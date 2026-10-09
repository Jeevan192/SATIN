"""Review Queue Builder for SAT-SA.

Constructs prioritized manual-review queues for regulatory examiners:
- 85% risk-ranked items diversified across detectors (preventing detector monopoly)
- 15% seeded random control slice for baseline verification
- Full explainability on why each item was selected
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Literal, Optional
import numpy as np
import pandas as pd

from satsa.detectors.base import Finding
from satsa.ingest import DataBundle
from satsa.scoring import compute_finding_score


SelectionBucket = Literal["risk_ranked", "random_control"]


@dataclass
class QueueItem:
    """A prioritized supervisory review item presented to human examiners."""
    item_id: str
    priority_rank: int
    entity_id: str
    selection_bucket: SelectionBucket
    finding_id: Optional[str]
    detector_id: Optional[str]
    category: Optional[str]
    scope: str
    priority_score: float
    selection_reason: str
    evidence_refs: List[str]
    target_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert queue item to standard JSON dictionary."""
        return asdict(self)


def determine_target_type(scope: str) -> str:
    """Extract primary resource type from scope string."""
    if ":" in scope:
        prefix = scope.split(":", 1)[0].lower()
        if prefix in ("alert", "case", "asset", "period", "entity", "category", "analyst"):
            return prefix
    return "alert"


def build_queue(
    entity_id: str,
    findings: List[Finding],
    bundle: DataBundle,
    budget: int = 50,
    seed: int = 42,
    entity_alerts: Optional[pd.DataFrame] = None,
) -> List[QueueItem]:
    """Construct prioritized review queue with 85% diversified risk items and 15% random control items."""
    rng = np.random.default_rng(seed)
    queue: List[QueueItem] = []

    # 1. Calculate quotas
    k_risk = max(1, int(round(0.85 * budget)))
    k_control = max(1, budget - k_risk)

    e_findings = [f for f in findings if f.entity_id == entity_id]

    # 2. Diversified Risk Selection (85%)
    # Group findings by detector to prevent one detector from monopolizing the queue
    findings_by_det: Dict[str, List[Finding]] = {}
    for f in e_findings:
        findings_by_det.setdefault(f.detector_id, []).append(f)

    # Sort each detector's findings by score descending
    for d_id in findings_by_det:
        findings_by_det[d_id].sort(key=compute_finding_score, reverse=True)

    selected_risk_findings: List[Finding] = []
    # Cap per detector: max 35% of risk quota unless fewer detectors exist
    max_per_detector = max(2, math.ceil(k_risk * 0.35))

    # Round-robin selection across detectors
    active_detectors = list(findings_by_det.keys())
    det_indices: Dict[str, int] = {d: 0 for d in active_detectors}
    det_counts: Dict[str, int] = {d: 0 for d in active_detectors}

    while len(selected_risk_findings) < k_risk and active_detectors:
        progress_made = False
        for d in list(active_detectors):
            idx = det_indices[d]
            f_list = findings_by_det[d]
            if idx < len(f_list) and det_counts[d] < max_per_detector:
                selected_risk_findings.append(f_list[idx])
                det_indices[d] += 1
                det_counts[d] += 1
                progress_made = True
                if len(selected_risk_findings) >= k_risk:
                    break
            else:
                active_detectors.remove(d)
        if not progress_made:
            break

    # If quota still not met, fill from remaining highest scoring findings
    if len(selected_risk_findings) < k_risk:
        already_picked = set(f.finding_id for f in selected_risk_findings)
        remaining = [f for f in e_findings if f.finding_id not in already_picked]
        remaining.sort(key=compute_finding_score, reverse=True)
        needed = k_risk - len(selected_risk_findings)
        selected_risk_findings.extend(remaining[:needed])

    # Convert selected risk findings to queue items
    rank = 1
    flagged_alert_ids = set()

    for f in selected_risk_findings:
        f_score = round(compute_finding_score(f), 2)
        ttype = determine_target_type(f.scope)
        # Track flagged alerts
        for ref in f.evidence_refs:
            if ref.startswith("alerts:"):
                flagged_alert_ids.add(ref.split(":")[-1])

        item = QueueItem(
            item_id=f"QI-{entity_id}-{rank:03d}",
            priority_rank=rank,
            entity_id=entity_id,
            selection_bucket="risk_ranked",
            finding_id=f.finding_id,
            detector_id=f.detector_id,
            category=f.category,
            scope=f.scope,
            priority_score=f_score,
            selection_reason=(
                f"Ranked high supervisory risk by {f.detector_id} ({f.category}): {f.reason_text}"
            ),
            evidence_refs=f.evidence_refs,
            target_type=ttype,
            metadata={"deviation": f.deviation, "confidence": f.confidence, "parameters": f.parameters},
        )
        queue.append(item)
        rank += 1

    # 3. Seeded Random Control Slice (15% base, plus any unfilled risk budget)
    needed_control = max(k_control, budget - len(selected_risk_findings))
    if entity_alerts is not None:
        e_alerts = entity_alerts
    else:
        e_alerts = bundle.alerts[bundle.alerts["entity_id"] == entity_id] if not bundle.alerts.empty else pd.DataFrame()
    if not e_alerts.empty:
        # Prefer alerts not flagged by risk detectors
        clean_alerts = e_alerts[~e_alerts["alert_id"].isin(flagged_alert_ids)]
        candidate_pool = clean_alerts if len(clean_alerts) >= needed_control else e_alerts

        n_sample = min(needed_control, len(candidate_pool))
        if n_sample > 0:
            sample_indices = rng.choice(len(candidate_pool), size=n_sample, replace=False)
            sampled_df = candidate_pool.iloc[sample_indices]

            for a_row in sampled_df.to_dict(orient="records"):
                aid = str(a_row["alert_id"])
                item = QueueItem(
                    item_id=f"QI-{entity_id}-{rank:03d}",
                    priority_rank=rank,
                    entity_id=entity_id,
                    selection_bucket="random_control",
                    finding_id=None,
                    detector_id="CONTROL",
                    category="CONTROL",
                    scope=f"alert:{aid}",
                    priority_score=1.0,
                    selection_reason=(
                        f"Selected via seeded 15% random control sampling (seed={seed}) "
                        f"for baseline supervisory verification and verification of true negative hygiene."
                    ),
                    evidence_refs=[f"alerts:{aid}"],
                    target_type="alert",
                    metadata={"severity": a_row.get("severity", "low"), "category": a_row.get("category", "")},
                )
                queue.append(item)
                rank += 1

    return queue


def build_portfolio_queues(
    findings: List[Finding],
    bundle: DataBundle,
    budget_per_entity: int = 50,
    seed: int = 42,
) -> Dict[str, List[QueueItem]]:
    """Generate review queues for all entities in the portfolio."""
    entities = bundle.entities["entity_id"].dropna().unique()
    # Pre-split alerts once so each entity queue doesn't re-scan the full table.
    alert_groups: Dict[str, pd.DataFrame] = (
        {eid: g for eid, g in bundle.alerts.groupby("entity_id")} if not bundle.alerts.empty else {}
    )
    return {
        eid: build_queue(
            eid, findings, bundle,
            budget=budget_per_entity, seed=seed,
            entity_alerts=alert_groups.get(eid, bundle.alerts.iloc[0:0]),
        )
        for eid in entities
    }

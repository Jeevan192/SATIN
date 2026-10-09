"""Claim-vs-Reality Index: self-reported supervisory KPIs vs evidence.

Critical Sector Entities periodically self-report headline KPIs (mean time to
close, monitoring coverage, false-positive rate, escalation rate). This module
derives the *evidence* equivalents from the audited alert/case/asset records
and scores how much each claim flatters (or understates) reality.

Scoring (per compared metric):
    exaggeration  = signed fraction by which the claim flatters the entity
                    (>0 means the claim looks better than the evidence)
    credibility   = 1 below a materiality DEADBAND, then linear decay to 0 at
                    FULL_PENALTY exaggeration; understatements are penalised
                    at half rate (a mismatch, but not a credibility problem)

    ClaimRealityIndex = 100 * mean(credibility over compared metrics)

Verdicts: ``substantiated`` (>= 85), ``partially_substantiated`` (>= 60),
``materially_exaggerated`` (< 60).

Everything is computed offline from the local DataBundle: no network, no
external APIs. Entities that submit no claims are simply omitted.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from satsa.features import alert_features, asset_features
from satsa.ingest import DataBundle

# Materiality deadband: claims within +/-5% of evidence are fully substantiated.
DEADBAND = 0.05
# Exaggeration at (or beyond) this fraction receives zero credibility.
FULL_PENALTY = 0.50
# Understating your own KPIs is a mismatch but only half as damning.
UNDERSTATE_RATE = 0.5

# metric key -> (entity claim column, label, unit, polarity)
# polarity "higher_better": claim above evidence flatters the entity.
# polarity "lower_better":  claim below evidence flatters the entity.
CLAIM_METRICS: Dict[str, tuple] = {
    "mttc_min": ("claimed_mttc_min", "Median close time (critical/high)", "minutes", "lower_better"),
    "coverage_pct": ("claimed_coverage_pct", "Monitored critical-asset coverage", "%", "higher_better"),
    "fp_rate_pct": ("claimed_fp_rate_pct", "False-positive disposition rate", "%", "lower_better"),
    "escalation_pct": ("claimed_escalation_pct", "Critical/high escalation rate", "%", "higher_better"),
}


@dataclass
class ClaimComparison:
    """One claimed metric vs its evidence-derived counterpart."""
    entity_id: str
    metric: str
    metric_label: str
    claimed: float
    observed: float
    unit: str
    exaggeration: float          # >0 = claim flatters the entity (fraction)
    credibility: float           # 0..1
    evidence_source: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClaimRealityScore:
    """Aggregate Claim-vs-Reality score for one entity."""
    entity_id: str
    index: float                                 # 0..100, 100 = fully substantiated
    verdict: str
    comparisons: List[ClaimComparison] = field(default_factory=list)

    @property
    def exaggerated_count(self) -> int:
        return sum(1 for c in self.comparisons if c.exaggeration > DEADBAND)

    @property
    def substantiated_count(self) -> int:
        return sum(1 for c in self.comparisons if c.credibility >= 0.999)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["exaggerated_count"] = self.exaggerated_count
        d["substantiated_count"] = self.substantiated_count
        d["n_claimed"] = len(self.comparisons)
        return d


def derive_evidence_metrics(bundle: DataBundle) -> Dict[str, Dict[str, Optional[float]]]:
    """Evidence-side KPI values per entity, derived from audited records.

    Mirrors the synthetic generator's claim basis exactly (see
    ``synth.generate._attach_kpi_claims``).
    """
    evidence: Dict[str, Dict[str, Optional[float]]] = {}
    if bundle.entities.empty:
        return evidence

    if bundle.alerts.empty:
        for eid in bundle.entities["entity_id"].dropna().unique():
            evidence[eid] = {"mttc_min": None, "coverage_pct": None, "fp_rate_pct": None, "escalation_pct": None}
        return evidence

    feats = alert_features(bundle)
    afeats = asset_features(bundle)

    # Monitored critical assets that actually produced telemetry.
    if afeats.empty or "is_silent" not in afeats.columns:
        mc = pd.DataFrame(columns=["entity_id", "active"])
    else:
        if "monitoring_expected" in afeats.columns:
            mc = afeats[(afeats["criticality"] == "critical") & (afeats["monitoring_expected"])]
        else:
            mc = afeats[afeats["criticality"] == "critical"]
        mc = mc.copy()
        mc["active"] = ~mc["is_silent"].astype(bool)

    for eid in bundle.entities["entity_id"].dropna().unique():
        e_alerts = feats[feats["entity_id"] == eid]
        ch = e_alerts[e_alerts["severity"].isin(["critical", "high"])]
        e_mc = mc[mc["entity_id"] == eid]

        mttc = float(ch["closure_duration_min"].median()) if not ch.empty else None
        cov = (100.0 * float(e_mc["active"].mean())) if not e_mc.empty else None
        fp = (100.0 * float((e_alerts["disposition"] == "false_positive").mean())) if not e_alerts.empty else None
        esc = (100.0 * float(ch["is_escalated"].mean())) if not ch.empty else None

        evidence[eid] = {
            "mttc_min": mttc,
            "coverage_pct": cov,
            "fp_rate_pct": fp,
            "escalation_pct": esc,
        }
    return evidence


def _credibility(exaggeration: float) -> float:
    """Map signed exaggeration to a 0..1 credibility score."""
    if exaggeration > 0:
        return float(np.clip(1.0 - (exaggeration - DEADBAND) / (FULL_PENALTY - DEADBAND), 0.0, 1.0))
    # Understatement: half penalty, same deadband.
    return float(np.clip(1.0 - UNDERSTATE_RATE * (-exaggeration - DEADBAND) / (FULL_PENALTY - DEADBAND), 0.0, 1.0))


def compute_claim_reality(bundle: DataBundle) -> Dict[str, ClaimRealityScore]:
    """Compute the Claim-vs-Reality Index for every entity that submitted claims.

    Returns a mapping of entity_id -> :class:`ClaimRealityScore`. Entities
    without any ``claimed_*`` values are omitted (``claim_reality`` handles
    legacy entity tables that lack the columns entirely).
    """
    entities = bundle.entities
    if entities.empty:
        return {}

    present_cols = [v[0] for v in CLAIM_METRICS.values() if v[0] in entities.columns]
    if not present_cols:
        return {}

    evidence = derive_evidence_metrics(bundle)
    results: Dict[str, ClaimRealityScore] = {}

    for rec in entities.to_dict(orient="records"):
        eid = rec.get("entity_id")
        if not eid:
            continue

        comparisons: List[ClaimComparison] = []
        for metric, (col, label, unit, polarity) in CLAIM_METRICS.items():
            if col not in rec:
                continue
            claimed = rec.get(col)
            if claimed is None or (isinstance(claimed, float) and np.isnan(claimed)):
                continue
            try:
                claimed = float(claimed)
            except (TypeError, ValueError):
                continue
            observed = evidence.get(eid, {}).get(metric)
            if observed is None or np.isnan(observed):
                continue  # no evidence basis -> cannot compare this metric

            # Signed exaggeration: positive = claim flatters the entity.
            denom = max(abs(observed), 1e-9)
            if polarity == "higher_better":
                exag = (claimed - observed) / denom
            else:
                exag = (observed - claimed) / denom

            comparisons.append(
                ClaimComparison(
                    entity_id=eid,
                    metric=metric,
                    metric_label=label,
                    claimed=round(claimed, 2),
                    observed=round(float(observed), 2),
                    unit=unit,
                    exaggeration=round(float(exag), 4),
                    credibility=round(_credibility(float(exag)), 4),
                    evidence_source="audited records (alerts/cases/assets)",
                )
            )

        if not comparisons:
            continue

        index = round(100.0 * float(np.mean([c.credibility for c in comparisons])), 1)
        if index >= 85.0:
            verdict = "substantiated"
        elif index >= 60.0:
            verdict = "partially_substantiated"
        else:
            verdict = "materially_exaggerated"

        results[eid] = ClaimRealityScore(entity_id=eid, index=index, verdict=verdict, comparisons=comparisons)

    return results


def summarize(scores: Dict[str, ClaimRealityScore]) -> Dict[str, Any]:
    """Portfolio-level summary of the Claim-vs-Reality results."""
    if not scores:
        return {
            "entities_with_claims": 0,
            "mean_index": None,
            "materially_exaggerated": [],
            "substantiated": 0,
        }
    return {
        "entities_with_claims": len(scores),
        "mean_index": round(float(np.mean([s.index for s in scores.values()])), 1),
        "materially_exaggerated": sorted(
            [s.entity_id for s in scores.values() if s.verdict == "materially_exaggerated"]
        ),
        "substantiated": sum(1 for s in scores.values() if s.verdict == "substantiated"),
    }

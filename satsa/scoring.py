"""Supervisory Risk Scoring Engine for SAT-SA.

Computes detector finding scores, aggregates into 8 SOC capability areas,
calculates the 0-100 Entity Supervisory Risk Index, peer percentile, and QoQ trend.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
import math
from typing import Any, Dict, List, Literal, Optional, Tuple
import numpy as np
import pandas as pd

from satsa.config import CAPABILITIES, THRESHOLDS
from satsa.detectors.base import Finding
from satsa.ingest import DataBundle
from satsa.peers import CohortManager, percentile


RiskTier = Literal["low", "moderate", "elevated", "high", "critical"]


@dataclass
class AreaScore:
    """Supervisory assessment score for a specific SOC capability area."""
    area: str
    weight: float
    score: float  # 0.0 to 100.0
    finding_count: int
    top_detectors: List[str] = field(default_factory=list)


@dataclass
class EntitySupervisoryScore:
    """Overall supervisory assessment result for a Critical Sector Entity."""
    entity_id: str
    overall_risk_index: float  # 0.0 to 100.0
    peer_percentile: float     # 0.0 to 1.0
    risk_tier: RiskTier
    qoq_trend: str             # "deteriorating", "stable", "improving"
    findings_count: int
    area_scores: Dict[str, float]
    area_details: List[AreaScore]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert score object to JSON-serializable dictionary."""
        d = asdict(self)
        d["area_details"] = [asdict(a) for a in self.area_details]
        return d


def compute_finding_score(f: Finding) -> float:
    """Calculate calibrated score for an individual finding.

    score = severity_weight * min(|deviation|, 5.0) * confidence
    """
    dev_mag = min(abs(float(f.deviation)), 5.0)
    return float(f.severity_weight * dev_mag * f.confidence)


def assign_risk_tier(score: float) -> RiskTier:
    """Assign human-readable supervisory risk tier based on index score."""
    if score >= 75.0:
        return "critical"
    elif score >= 55.0:
        return "high"
    elif score >= 35.0:
        return "elevated"
    elif score >= 20.0:
        return "moderate"
    else:
        return "low"


def compute_entity_score(
    entity_id: str,
    findings: List[Finding],
    bundle: DataBundle,
    cohort_mgr: CohortManager,
) -> EntitySupervisoryScore:
    """Calculate 8-capability area scores and overall risk index for a single entity."""
    e_findings = [f for f in findings if f.entity_id == entity_id]

    # Map findings to capability areas
    area_finding_scores: Dict[str, List[float]] = {a: [] for a in CAPABILITIES.areas}
    area_detectors: Dict[str, List[str]] = {a: [] for a in CAPABILITIES.areas}

    for f in e_findings:
        mapped_areas = CAPABILITIES.detector_capability_map.get(f.detector_id, ["security_operations"])
        f_score = compute_finding_score(f)
        for a in mapped_areas:
            if a in area_finding_scores:
                area_finding_scores[a].append(f_score)
                area_detectors[a].append(f.detector_id)

    # Compute area sub-scores (0-100) using smooth saturation function
    area_details: List[AreaScore] = []
    area_scores_dict: Dict[str, float] = {}
    weighted_total = 0.0

    for a in CAPABILITIES.areas:
        wt = CAPABILITIES.area_weights.get(a, 0.125)
        scores = area_finding_scores[a]
        sum_scores = sum(scores)

        # Smooth saturation: 0 at 0 findings, ~50 at score=35, ~90 at score=115, max 100
        if sum_scores <= 0.0:
            sub_score = 0.0
        else:
            sub_score = 100.0 * (1.0 - math.exp(-sum_scores / 45.0))

        sub_score = round(float(sub_score), 2)
        area_scores_dict[a] = sub_score
        weighted_total += wt * sub_score

        top_dets = sorted(set(area_detectors[a]))[:3]
        area_details.append(AreaScore(
            area=a,
            weight=wt,
            score=sub_score,
            finding_count=len(scores),
            top_detectors=top_dets,
        ))

    overall_risk = round(float(np.clip(weighted_total, 0.0, 100.0)), 2)

    # Compute Quarter-over-Quarter Trend (Q1 vs Q2)
    # Filter alert dates if available
    e_alerts = bundle.alerts[bundle.alerts["entity_id"] == entity_id] if not bundle.alerts.empty else pd.DataFrame()
    if not e_alerts.empty and "created_ts" in e_alerts.columns:
        ts = pd.to_datetime(e_alerts["created_ts"])
        min_t, max_t = ts.min(), ts.max()
        mid_t = min_t + (max_t - min_t) / 2

        # Check early vs late finding proxy (using finding timestamps or scope alerts)
        early_alerts = set(e_alerts[ts <= mid_t]["alert_id"])
        late_alerts = set(e_alerts[ts > mid_t]["alert_id"])

        early_score = sum(
            compute_finding_score(f) for f in e_findings
            if any(ref.split(":")[-1] in early_alerts for ref in f.evidence_refs)
        )
        late_score = sum(
            compute_finding_score(f) for f in e_findings
            if any(ref.split(":")[-1] in late_alerts for ref in f.evidence_refs)
        )

        diff = late_score - early_score
        if diff > 15.0:
            trend = "deteriorating"
        elif diff < -15.0:
            trend = "improving"
        else:
            trend = "stable"
    else:
        trend = "stable"

    return EntitySupervisoryScore(
        entity_id=entity_id,
        overall_risk_index=overall_risk,
        peer_percentile=0.50,  # Updated in portfolio pass
        risk_tier=assign_risk_tier(overall_risk),
        qoq_trend=trend,
        findings_count=len(e_findings),
        area_scores=area_scores_dict,
        area_details=area_details,
    )


def score_portfolio(
    findings: List[Finding],
    bundle: DataBundle,
    cohort_mgr: CohortManager,
) -> Dict[str, EntitySupervisoryScore]:
    """Score all entities across the portfolio and compute cohort-relative peer percentiles."""
    entities = bundle.entities["entity_id"].dropna().unique()
    scores: Dict[str, EntitySupervisoryScore] = {}

    for eid in entities:
        scores[eid] = compute_entity_score(eid, findings, bundle, cohort_mgr)

    # Compute peer percentiles
    all_overall_scores = {eid: s.overall_risk_index for eid, s in scores.items()}

    for eid, score_obj in scores.items():
        cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
        cohort_scores = [all_overall_scores[cid] for cid in cohort_ids if cid in all_overall_scores]

        if len(cohort_scores) < THRESHOLDS.min_cohort_size:
            cohort_scores = list(all_overall_scores.values())

        pct = percentile(score_obj.overall_risk_index, cohort_scores)
        score_obj.peer_percentile = round(float(pct), 4)
        score_obj.metadata["cohort_fallback"] = fallback_lvl
        score_obj.metadata["cohort_size"] = len(cohort_scores)

    return scores

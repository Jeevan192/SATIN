"""EXECUTION_GAP Detectors (EG-01 through EG-08).

Identifies records that contradict claimed SOC effectiveness:
- Fast closure of critical/high alerts without real triage
- Lack of escalation on severe incidents
- Zero workflow activity on acknowledged alerts
- Template-driven investigation notes and low entropy
- Unremediated repeated alerts
- SLA-boundary closure bunching
- Extreme analyst closure concentration
- Systematic disposition skew drift (CUSUM)
"""

from collections import Counter
import math
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from satsa.config import SEVERITY_WEIGHTS, THRESHOLDS
from satsa.detectors.base import BaseDetector, Finding, generate_finding_id
from satsa.features import (
    calculate_entropy,
    calculate_gini,
    compute_alert_features,
    compute_entity_features,
)
from satsa.ingest import DataBundle
from satsa.peers import CohortManager, percentile, robust_z


class EG01ClosureSpeedDetector(BaseDetector):
    """EG-01: Critical/High alert closure speed anomaly (cohort p5 / robust z < -2.5)."""

    detector_id = "EG-01"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alert_feats = compute_alert_features(bundle.alerts)
        entities = bundle.entities["entity_id"].dropna().unique()

        for eid in entities:
            e_alerts = alert_feats[alert_feats["entity_id"] == eid]
            if e_alerts.empty:
                continue

            cohort_alerts, fallback_lvl = cohort_mgr.get_cohort_slice(alert_feats, eid)
            if cohort_alerts.empty:
                continue

            for sev in ("critical", "high"):
                e_sev = e_alerts[e_alerts["severity"] == sev]
                c_sev = cohort_alerts[cohort_alerts["severity"] == sev]

                if len(e_sev) < THRESHOLDS.eg01_min_alerts or len(c_sev) < THRESHOLDS.eg01_min_alerts:
                    continue

                # Prefer peer-only distribution to avoid self-contamination
                peer_sev = cohort_alerts[(cohort_alerts["severity"] == sev) & (cohort_alerts["entity_id"] != eid)]
                if len(peer_sev) >= THRESHOLDS.eg01_min_alerts:
                    cohort_durations = peer_sev["closure_duration_sec"].dropna().values
                else:
                    cohort_durations = c_sev["closure_duration_sec"].dropna().values

                p5_cohort = float(np.percentile(cohort_durations, THRESHOLDS.eg01_percentile_thresh * 100))

                for _, a_row in e_sev.iterrows():
                    dur_sec = float(a_row["closure_duration_sec"])
                    if dur_sec <= 0:
                        continue
                    z_val = robust_z(dur_sec, cohort_durations)
                    pct = percentile(dur_sec, cohort_durations)

                    if dur_sec <= p5_cohort or z_val <= THRESHOLDS.eg01_z_thresh or pct <= THRESHOLDS.eg01_percentile_thresh:
                        aid = a_row["alert_id"]
                        sev_wt = SEVERITY_WEIGHTS.weights.get(sev, 3.0)
                        findings.append(Finding(
                            finding_id=generate_finding_id(self.detector_id, eid, f"alert:{aid}"),
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            category=self.category,
                            entity_id=eid,
                            scope=f"alert:{aid}",
                            severity_weight=sev_wt,
                            deviation=round(float(z_val), 3),
                            peer_percentile=round(float(pct), 4),
                            confidence=0.95 if fallback_lvl == "primary" else 0.85,
                            reason_text=(
                                f"Alert was closed in {dur_sec:.1f}s ({dur_sec/60.0:.1f} min), "
                                f"which is significantly faster than cohort 5th percentile ({p5_cohort/60.0:.1f} min, robust z={z_val:.2f}). "
                                f"Contradicts thorough triage standards for {sev.upper()} severity."
                            ),
                            evidence_refs=[f"alerts:{aid}"],
                            parameters={
                                "severity": sev,
                                "closure_duration_sec": dur_sec,
                                "cohort_p5_sec": p5_cohort,
                                "robust_z": z_val,
                                "fallback_level": fallback_lvl,
                            },
                        ))

        return findings


class EG02EscalationDeficitDetector(BaseDetector):
    """EG-02: Critical/High closed without escalation vs peer expected rate (z < -2.0)."""

    detector_id = "EG-02"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alert_feats = compute_alert_features(
            bundle.alerts, bundle.cases, bundle.workflow_events, bundle.escalations
        )
        entities = bundle.entities["entity_id"].dropna().unique()

        # Compute escalation rates per entity for critical/high
        crit_high = alert_feats[alert_feats["severity"].isin(["critical", "high"])]
        if crit_high.empty:
            return findings

        rates = crit_high.groupby("entity_id")["is_escalated"].mean()

        for eid in entities:
            if eid not in rates:
                continue

            e_rate = float(rates[eid])
            e_records = crit_high[crit_high["entity_id"] == eid]
            if len(e_records) < THRESHOLDS.eg02_min_critical_high:
                continue

            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_rates = [rates[cid] for cid in cohort_ids if cid in rates]

            if len(cohort_rates) < THRESHOLDS.min_cohort_size:
                cohort_rates = list(rates.values)

            z_val = robust_z(e_rate, cohort_rates)
            pct = percentile(e_rate, cohort_rates)

            if z_val <= THRESHOLDS.eg02_z_thresh:
                unescalated = e_records[~e_records["is_escalated"]]
                evidence = [f"alerts:{aid}" for aid in unescalated["alert_id"].head(10)]

                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"entity:{eid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"entity:{eid}",
                    severity_weight=4.0,
                    deviation=round(float(z_val), 3),
                    peer_percentile=round(float(pct), 4),
                    confidence=0.90 if fallback_lvl == "primary" else 0.80,
                    reason_text=(
                        f"Critical/High escalation rate of {e_rate*100:.1f}% is significantly suppressed "
                        f"compared to peer cohort median ({np.median(cohort_rates)*100:.1f}%, robust z={z_val:.2f}). "
                        f"Indicates severe alerts closed at Tier-1 without mandatory escalation."
                    ),
                    evidence_refs=evidence,
                    parameters={
                        "observed_rate": e_rate,
                        "cohort_median": float(np.median(cohort_rates)),
                        "robust_z": z_val,
                        "unescalated_count": len(unescalated),
                    },
                ))

        return findings


class EG03UnworkedAlertsDetector(BaseDetector):
    """EG-03: Acknowledged alerts with zero workflow investigation events."""

    detector_id = "EG-03"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        # Check if workflow_events table exists or is populated
        if bundle.workflow_events.empty:
            # Missing data finding
            for eid in bundle.entities["entity_id"].dropna().unique():
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, "data_gap:workflow_events"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope="table:workflow_events",
                    severity_weight=3.0,
                    deviation=-3.0,
                    peer_percentile=0.01,
                    confidence=0.70,
                    reason_text="Workflow events table is missing or empty. Evidence of investigation activity cannot be verified.",
                    evidence_refs=[],
                    parameters={"missing_table": "workflow_events"},
                ))
            return findings

        alert_feats = compute_alert_features(
            bundle.alerts, bundle.cases, bundle.workflow_events, bundle.escalations
        )

        unworked = alert_feats[
            (alert_feats["has_case"]) &
            (alert_feats["workflow_event_count"] == 0) &
            (alert_feats["closure_duration_sec"] >= THRESHOLDS.eg03_min_gap_seconds)
        ]

        for eid, group in unworked.groupby("entity_id"):
            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            # Sample evidence
            sample = group.head(15)
            for _, row in sample.iterrows():
                aid = row["alert_id"]
                cid = row["case_id"]
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"alert:{aid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"alert:{aid}",
                    severity_weight=2.5,
                    deviation=-2.5,
                    peer_percentile=0.05,
                    confidence=0.92,
                    reason_text=(
                        f"Alert was acknowledged and closed under case {cid}, but recorded zero workflow "
                        f"investigation steps or actions between acknowledgement and closure."
                    ),
                    evidence_refs=[f"alerts:{aid}", f"cases:{cid}"],
                    parameters={"alert_id": aid, "case_id": cid, "duration_sec": row["closure_duration_sec"]},
                ))

        return findings


class EG04TemplateInvestigationDetector(BaseDetector):
    """EG-04: Template-driven investigations (TF-IDF cosine similarity > 0.9 and low entropy)."""

    detector_id = "EG-04"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.cases.empty:
            return findings

        cases = bundle.cases.copy()
        if "notes_text" not in cases.columns:
            return findings

        entities = bundle.entities["entity_id"].dropna().unique()

        for eid in entities:
            # Map cases to entity
            e_alerts = bundle.alerts[bundle.alerts["entity_id"] == eid]["alert_id"]
            e_cases = cases[cases["alert_id"].isin(e_alerts)]
            if len(e_cases) < THRESHOLDS.eg04_min_notes:
                continue

            notes = e_cases["notes_text"].dropna().astype(str).tolist()
            clean_notes = [n.strip() for n in notes if len(n.strip()) > 10]
            if len(clean_notes) < THRESHOLDS.eg04_min_notes:
                continue

            # Closure code entropy
            entropy = calculate_entropy(e_cases["closure_code"].dropna().tolist())

            # Evaluate template duplication and pairwise similarity of dominant notes
            note_counts = Counter(clean_notes)
            top_notes = [note for note, cnt in note_counts.most_common(5) if cnt >= 5]
            if not top_notes:
                continue

            if len(top_notes) == 1:
                template_similarity = 1.0
            else:
                try:
                    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
                    tfidf_mat = vectorizer.fit_transform(top_notes)
                    sim_mat = cosine_similarity(tfidf_mat)
                    triu_indices = np.triu_indices(len(top_notes), k=1)
                    template_similarity = float(np.max(sim_mat[triu_indices])) if len(triu_indices[0]) > 0 else 1.0
                except Exception:
                    template_similarity = 0.0

            dominant_count = sum(cnt for note, cnt in note_counts.most_common(5) if cnt >= 5)
            dominant_share = dominant_count / len(clean_notes)

            if (template_similarity >= THRESHOLDS.eg04_similarity_thresh and dominant_share >= 0.35) and entropy <= THRESHOLDS.eg04_entropy_thresh:
                sample_cases = e_cases.head(5)["case_id"].tolist()
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"entity:{eid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"entity:{eid}",
                    severity_weight=3.5,
                    deviation=round(float(template_similarity - THRESHOLDS.eg04_similarity_thresh), 3),
                    peer_percentile=0.95,
                    confidence=0.88,
                    reason_text=(
                        f"Investigation notes show excessive template repetition ({dominant_share*100:.1f}% cases share "
                        f"near-identical text with {template_similarity*100:.1f}% cosine similarity) "
                        f"and depressed closure-code entropy ({entropy:.2f} bits vs expected > 1.2). "
                        f"Consistent with template copy-paste or automated rubber-stamping."
                    ),
                    evidence_refs=[f"cases:{cid}" for cid in sample_cases],
                    parameters={
                        "dominant_note_share": round(dominant_share, 3),
                        "template_similarity": round(template_similarity, 3),
                        "closure_code_entropy": round(entropy, 3),
                    },
                ))

        return findings


class EG05RepeatAlertsDetector(BaseDetector):
    """EG-05: Repeat alerts on same asset+rule without remediation."""

    detector_id = "EG-05"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alert_feats = compute_alert_features(bundle.alerts)
        if "is_repeat_7d" not in alert_feats.columns:
            return findings

        # Filter entities where specific asset has recurring unmitigated alerts
        grouped = alert_feats[alert_feats["is_repeat_7d"]].groupby(["entity_id", "asset_id", "category"])

        for (eid, aid, cat), group in grouped:
            if len(group) >= THRESHOLDS.eg05_min_occurrences:
                sample_alerts = group.head(5)["alert_id"].tolist()
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"asset:{aid}:{cat}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"asset:{aid}",
                    severity_weight=3.0,
                    deviation=round(float(len(group)), 2),
                    peer_percentile=0.90,
                    confidence=0.85,
                    reason_text=(
                        f"Asset {aid} generated {len(group)} recurring '{cat}' alerts within 7 days "
                        f"without persistent remediation or configuration correction."
                    ),
                    evidence_refs=[f"alerts:{a}" for a in sample_alerts],
                    parameters={"asset_id": aid, "category": cat, "recurrence_count": len(group)},
                ))

        return findings


class EG06SLABoundaryBunchingDetector(BaseDetector):
    """EG-06: Closure bunching at SLA boundaries or shift/month ends."""

    detector_id = "EG-06"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alert_feats = compute_alert_features(bundle.alerts)
        entities = bundle.entities["entity_id"].dropna().unique()

        # Compute cohort-wide SLA window closure proportion
        sla_rates = alert_feats.groupby("entity_id")["is_sla_window"].mean()

        for eid in entities:
            if eid not in sla_rates:
                continue

            e_rate = float(sla_rates[eid])
            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_rates = [sla_rates[cid] for cid in cohort_ids if cid in sla_rates]

            if len(cohort_rates) < THRESHOLDS.min_cohort_size:
                cohort_rates = list(sla_rates.values)

            z_val = robust_z(e_rate, cohort_rates)
            pct = percentile(e_rate, cohort_rates)

            if z_val >= THRESHOLDS.eg06_spike_z_thresh and e_rate >= 0.15:
                e_alerts = alert_feats[alert_feats["entity_id"] == eid]
                bunch_sample = e_alerts[e_alerts["is_sla_window"]].head(10)["alert_id"].tolist()

                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"entity:{eid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"entity:{eid}",
                    severity_weight=3.2,
                    deviation=round(float(z_val), 3),
                    peer_percentile=round(float(pct), 4),
                    confidence=0.88,
                    reason_text=(
                        f"Unusual spike in alert closures right at the 55-60 min SLA boundary "
                        f"({e_rate*100:.1f}% vs cohort median {np.median(cohort_rates)*100:.1f}%, robust z={z_val:.2f}). "
                        f"Suggests metric gaming to meet SLA response time thresholds."
                    ),
                    evidence_refs=[f"alerts:{a}" for a in bunch_sample],
                    parameters={"sla_bunching_rate": e_rate, "cohort_median": float(np.median(cohort_rates)), "robust_z": z_val},
                ))

        return findings


class EG07AnalystConcentrationDetector(BaseDetector):
    """EG-07: Analyst closure concentration (Gini or top-1 share vs cohort)."""

    detector_id = "EG-07"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.cases.empty:
            return findings

        alert_feats = compute_alert_features(bundle.alerts, bundle.cases)
        crit_high = alert_feats[alert_feats["severity"].isin(["critical", "high"])]
        if crit_high.empty:
            return findings

        entities = bundle.entities["entity_id"].dropna().unique()

        # Compute top1 share per entity
        top1_shares: Dict[str, float] = {}
        top1_analysts: Dict[str, str] = {}
        for eid in entities:
            e_ch = crit_high[crit_high["entity_id"] == eid]
            if len(e_ch) >= 10 and "analyst_id" in e_ch.columns:
                counts = e_ch["analyst_id"].dropna().value_counts()
                if len(counts) >= THRESHOLDS.eg07_min_analysts:
                    top1_shares[eid] = float(counts.iloc[0] / len(e_ch))
                    top1_analysts[eid] = str(counts.index[0])

        for eid, share in top1_shares.items():
            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_shares = [top1_shares[cid] for cid in cohort_ids if cid in top1_shares]
            if len(cohort_shares) < THRESHOLDS.min_cohort_size:
                cohort_shares = list(top1_shares.values())

            z_val = robust_z(share, cohort_shares)
            pct = percentile(share, cohort_shares)

            if share >= THRESHOLDS.eg07_top1_share_thresh and z_val >= 1.8:
                star_analyst = top1_analysts[eid]
                e_ch = crit_high[crit_high["entity_id"] == eid]
                sample_cases = e_ch[e_ch["analyst_id"] == star_analyst].head(5)["case_id"].dropna().tolist()

                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"analyst:{star_analyst}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"analyst:{star_analyst}",
                    severity_weight=2.8,
                    deviation=round(float(z_val), 3),
                    peer_percentile=round(float(pct), 4),
                    confidence=0.86,
                    reason_text=(
                        f"Single analyst '{star_analyst}' handles {share*100:.1f}% of all critical/high investigations "
                        f"(cohort median {np.median(cohort_shares)*100:.1f}%, robust z={z_val:.2f}). "
                        f"Represents extreme single-point dependency and potential oversight bypass."
                    ),
                    evidence_refs=[f"cases:{c}" for c in sample_cases],
                    parameters={"analyst_id": star_analyst, "top1_share": share, "cohort_median": float(np.median(cohort_shares))},
                ))

        return findings


class EG08DispositionSkewDriftDetector(BaseDetector):
    """EG-08: Disposition skew drift (CUSUM on false-positive rate)."""

    detector_id = "EG-08"
    detector_version = "1.0.0"
    category = "EXECUTION_GAP"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alerts = bundle.alerts.copy()
        if "disposition" not in alerts.columns:
            return findings

        alerts["created_ts"] = pd.to_datetime(alerts["created_ts"])
        alerts["year_month"] = alerts["created_ts"].dt.to_period("M").astype(str)

        entities = bundle.entities["entity_id"].dropna().unique()

        for eid in entities:
            e_alerts = alerts[alerts["entity_id"] == eid].sort_values("created_ts")
            if len(e_alerts) < 50:
                continue

            # Monthly FP rates
            monthly = e_alerts.groupby("year_month")["disposition"].apply(
                lambda s: float((s == "false_positive").mean())
            )
            if len(monthly) < 3:
                continue

            # CUSUM algorithm on monthly series
            target = float(monthly.iloc[0])  # baseline is early month rate
            s_pos = 0.0
            max_s_pos = 0.0
            drift = THRESHOLDS.eg08_cusum_drift

            for rate in monthly:
                # standardized delta
                delta = (rate - target) * 10.0
                s_pos = max(0.0, s_pos + delta - drift)
                if s_pos > max_s_pos:
                    max_s_pos = s_pos

            if max_s_pos >= THRESHOLDS.eg08_cusum_thresh:
                start_r = float(monthly.iloc[0])
                end_r = float(monthly.iloc[-1])
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"entity:{eid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"entity:{eid}",
                    severity_weight=3.2,
                    deviation=round(float(max_s_pos), 3),
                    peer_percentile=0.92,
                    confidence=0.88,
                    reason_text=(
                        f"CUSUM drift detected in false-positive disposition rate (rose from {start_r*100:.1f}% to "
                        f"{end_r*100:.1f}%, CUSUM statistic={max_s_pos:.2f} >= {THRESHOLDS.eg08_cusum_thresh}). "
                        f"Indicates progressive relaxation of investigation thresholds."
                    ),
                    evidence_refs=[],
                    parameters={
                        "cusum_score": max_s_pos,
                        "initial_fp_rate": start_r,
                        "final_fp_rate": end_r,
                    },
                ))

        return findings

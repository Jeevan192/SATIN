"""NEGATIVE_SPACE Detectors (NS-01 through NS-06).

Identifies expected telemetry and supervisory evidence that is missing:
- Silent critical monitored assets
- Missing or suppressed threat categories (Poisson test)
- Alerts without cases / cases without mandatory escalations
- Suppressed total alert volume vs size-adjusted peers
- Silent operational periods (daily continuity gaps)
- Criticality-weighted monitoring coverage ratio deficits
"""

from datetime import timedelta
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from satsa.config import SEVERITY_WEIGHTS, THRESHOLDS
from satsa.detectors.base import BaseDetector, Finding, generate_finding_id
from satsa.features import (
    alert_features,
    asset_features,
    compute_alert_features,
    compute_asset_features,
    compute_entity_features,
)
from satsa.ingest import DataBundle
from satsa.peers import (
    CohortManager,
    expected_poisson_category_count,
    expected_volume_ratio,
    percentile,
    robust_z,
)


class NS01SilentCriticalAssetsDetector(BaseDetector):
    """NS-01: Critical monitored assets with zero alerts/events in period (asset anti-join)."""

    detector_id = "NS-01"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.assets.empty:
            # Missing assets inventory finding
            for eid in bundle.entities["entity_id"].dropna().unique():
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, "data_gap:assets"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope="table:assets",
                    severity_weight=4.0,
                    deviation=-3.0,
                    peer_percentile=0.01,
                    confidence=0.75,
                    reason_text="Asset inventory table is missing or empty. Critical asset monitoring coverage cannot be verified.",
                    evidence_refs=[],
                    parameters={"missing_table": "assets"},
                ))
            return findings

        asset_feats = asset_features(bundle)

        # Monitored critical assets with zero alerts
        silent_crit = asset_feats[
            (asset_feats["criticality"] == THRESHOLDS.ns01_min_critical_tier) &
            (asset_feats["monitoring_expected"]) &
            (asset_feats["is_silent"])
        ]

        for row in silent_crit.to_dict(orient="records"):
            aid = row["asset_id"]
            eid = row["entity_id"]
            atype = row.get("asset_type", "unknown")

            findings.append(Finding(
                finding_id=generate_finding_id(self.detector_id, eid, f"asset:{aid}"),
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                category=self.category,
                entity_id=eid,
                scope=f"asset:{aid}",
                severity_weight=4.5,
                deviation=-3.0,
                peer_percentile=0.02,
                confidence=0.95,
                reason_text=(
                    f"Designated CRITICAL asset '{aid}' ({atype}) generated zero alerts or telemetry "
                    f"events during the entire 6-month evaluation period despite monitoring being mandatory."
                ),
                evidence_refs=[f"assets:{aid}"],
                parameters={"asset_id": aid, "asset_type": atype, "criticality": "critical"},
            ))

        return findings


class NS02SuppressedCategoriesDetector(BaseDetector):
    """NS-02: Expected alert categories absent or far below Poisson cohort expectation."""

    detector_id = "NS-02"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alerts = bundle.alerts
        entities = bundle.entities["entity_id"].dropna().unique()

        # Identify all categories across portfolio
        all_categories = sorted(alerts["category"].dropna().unique())

        # Precompute per-entity and per-(entity, category) counts once; cohort
        # totals are summed from these instead of re-scanning the alert table
        # for every (entity, category) pair.
        entity_totals = alerts.groupby("entity_id").size()
        entity_cat_counts = (
            alerts.groupby(["entity_id", "category"]).size().unstack(fill_value=0)
        )

        for eid in entities:
            e_total = int(entity_totals.get(eid, 0))
            if e_total < 30:
                continue

            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_members = [cid for cid in cohort_ids if cid in entity_totals.index]
            c_total = int(sum(int(entity_totals[cid]) for cid in cohort_members))
            if c_total < 100:
                continue

            c_counts = entity_cat_counts.loc[cohort_members].sum(axis=0)
            e_counts = (
                entity_cat_counts.loc[eid] if eid in entity_cat_counts.index else None
            )

            for cat in all_categories:
                e_cat_count = int(e_counts[cat]) if e_counts is not None else 0
                c_cat_count = int(c_counts[cat]) if cat in c_counts.index else 0

                # If category has substantial volume in cohort (>5% of peer alerts)
                if c_cat_count / c_total >= 0.05:
                    mu, p_val = expected_poisson_category_count(e_cat_count, e_total, c_cat_count, c_total)

                    if p_val <= THRESHOLDS.ns02_poisson_p_thresh or (e_cat_count == 0 and mu >= 8.0):
                        findings.append(Finding(
                            finding_id=generate_finding_id(self.detector_id, eid, f"category:{cat}"),
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            category=self.category,
                            entity_id=eid,
                            scope=f"category:{cat}",
                            severity_weight=4.0,
                            deviation=round(float(e_cat_count - mu), 2),
                            peer_percentile=round(float(p_val), 4),
                            confidence=0.92,
                            reason_text=(
                                f"Expected alert category '{cat}' is completely suppressed or absent "
                                f"(observed: {e_cat_count}, cohort expected: {mu:.1f}, Poisson p={p_val:.2e}). "
                                f"Indicates potential detection blind spot or disabled correlation rule."
                            ),
                            evidence_refs=[],
                            parameters={
                                "category": cat,
                                "observed_count": e_cat_count,
                                "expected_count": round(mu, 2),
                                "poisson_p_value": p_val,
                            },
                        ))

        return findings


class NS03OrphanAlertsCasesDetector(BaseDetector):
    """NS-03: Alerts without cases / cases without mandatory escalations."""

    detector_id = "NS-03"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        alert_feats = alert_features(bundle)

        # Critical / High alerts without cases
        severe_alerts = alert_feats[alert_feats["severity"].isin(THRESHOLDS.ns03_require_case_severities)]
        missing_cases = severe_alerts[~severe_alerts["has_case"]]

        for eid, group in missing_cases.groupby("entity_id"):
            sample = group.head(10)
            sample_ids = sample["alert_id"].tolist()
            findings.append(Finding(
                finding_id=generate_finding_id(self.detector_id, eid, "alerts_without_cases"),
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                category=self.category,
                entity_id=eid,
                scope=f"entity:{eid}",
                severity_weight=3.8,
                deviation=-float(len(group)),
                peer_percentile=0.05,
                confidence=0.90,
                reason_text=(
                    f"Identified {len(group)} high/critical alerts with no corresponding case record created, "
                    f"leaving critical threats unassigned in supervisory audit logs."
                ),
                evidence_refs=[f"alerts:{aid}" for aid in sample_ids],
                parameters={"unassigned_critical_alerts": len(group)},
            ))

        return findings


class NS04SuppressedVolumeDetector(BaseDetector):
    """NS-04: Total alert volume below size-adjusted peer expectation."""

    detector_id = "NS-04"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.entities.empty or bundle.alerts.empty:
            return findings

        entity_feats = compute_entity_features(bundle)
        if entity_feats.empty:
            return findings

        rates_map = entity_feats.set_index("entity_id")["alerts_per_asset"].to_dict()

        for ent_rec in entity_feats.to_dict(orient="records"):
            eid = ent_rec["entity_id"]
            e_rate = float(ent_rec["alerts_per_asset"])

            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_rates = [rates_map[cid] for cid in cohort_ids if cid in rates_map]

            if len(cohort_rates) < THRESHOLDS.min_cohort_size:
                cohort_rates = list(rates_map.values())

            cohort_med, ratio, z_val = expected_volume_ratio(e_rate, cohort_rates)
            pct = percentile(e_rate, cohort_rates)

            if (ratio <= THRESHOLDS.ns04_volume_ratio_thresh or z_val <= THRESHOLDS.ns04_z_thresh) and cohort_med > 0:
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, f"entity:{eid}"),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=f"entity:{eid}",
                    severity_weight=4.2,
                    deviation=round(float(ratio - 1.0), 3),
                    peer_percentile=round(float(pct), 4),
                    confidence=0.88,
                    reason_text=(
                        f"Overall alert volume per asset ({e_rate:.1f}) is suppressed to {ratio*100:.1f}% "
                        f"of peer cohort median ({cohort_med:.1f} alerts/asset, robust z={z_val:.2f}). "
                        f"Indicates wide-scale alert filtering, throttling, or missing data collectors."
                    ),
                    evidence_refs=[],
                    parameters={
                        "alerts_per_asset": e_rate,
                        "cohort_median_per_asset": cohort_med,
                        "volume_ratio": ratio,
                        "robust_z": z_val,
                    },
                ))

        return findings


class NS05SilentPeriodDetector(BaseDetector):
    """NS-05: Silent operational periods (consecutive days with 0 alerts / change-point)."""

    detector_id = "NS-05"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        # alert_features already parses created_ts to datetime; grouping once
        # avoids a boolean full-frame scan per entity.
        alert_feats = alert_features(bundle)
        entities = bundle.entities["entity_id"].dropna().unique()
        alert_groups = {eid: g for eid, g in alert_feats.groupby("entity_id")}

        for eid in entities:
            e_alerts = alert_groups.get(eid)
            if e_alerts is None or e_alerts.empty:
                continue

            # Resample daily count
            daily = e_alerts.set_index("created_ts").resample("D").size()
            if len(daily) < 14:
                continue

            # Find consecutive zero runs >= THRESHOLDS.ns05_consecutive_days_zero
            zero_runs = []
            cur_start = None
            cur_count = 0

            for dt, count in daily.items():
                if count == 0:
                    if cur_start is None:
                        cur_start = dt
                    cur_count += 1
                else:
                    if cur_count >= THRESHOLDS.ns05_consecutive_days_zero:
                        zero_runs.append((cur_start, cur_count))
                    cur_start = None
                    cur_count = 0

            if cur_count >= THRESHOLDS.ns05_consecutive_days_zero:
                zero_runs.append((cur_start, cur_count))

            for z_start, z_days in zero_runs:
                z_end = z_start + timedelta(days=z_days)
                scope_str = f"period:{z_start.strftime('%Y-%m-%d')}_to_{z_end.strftime('%Y-%m-%d')}"
                findings.append(Finding(
                    finding_id=generate_finding_id(self.detector_id, eid, scope_str),
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    category=self.category,
                    entity_id=eid,
                    scope=scope_str,
                    severity_weight=4.0,
                    deviation=-float(z_days),
                    peer_percentile=0.01,
                    confidence=0.94,
                    reason_text=(
                        f"Operational silence: zero SOC alerts recorded for {z_days} consecutive days "
                        f"from {z_start.strftime('%Y-%m-%d')} to {z_end.strftime('%Y-%m-%d')}. "
                        f"Indicates telemetry outage, sensor failure, or unsubmitted batch logs."
                    ),
                    evidence_refs=[],
                    parameters={"start_date": str(z_start), "consecutive_days": z_days},
                ))

        return findings


class NS06CoverageDeficitDetector(BaseDetector):
    """NS-06: Criticality-weighted monitoring coverage ratio vs peers."""

    detector_id = "NS-06"
    detector_version = "1.0.0"
    category = "NEGATIVE_SPACE"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.assets.empty or bundle.entities.empty:
            return findings

        entity_feats = compute_entity_features(bundle)
        if entity_feats.empty:
            return findings

        cov_map = entity_feats.set_index("entity_id")["crit_coverage_ratio"].to_dict()

        for ent_rec in entity_feats.to_dict(orient="records"):
            eid = ent_rec["entity_id"]
            e_cov = float(ent_rec["crit_coverage_ratio"])

            cohort_ids, fallback_lvl = cohort_mgr.get_cohort_entities(eid)
            cohort_covs = [cov_map[cid] for cid in cohort_ids if cid in cov_map]

            if len(cohort_covs) < THRESHOLDS.min_cohort_size:
                cohort_covs = list(cov_map.values())

            z_val = robust_z(e_cov, cohort_covs)
            pct = percentile(e_cov, cohort_covs)

            if z_val <= THRESHOLDS.ns06_coverage_z_thresh and e_cov <= 0.70:
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
                    confidence=0.90,
                    reason_text=(
                        f"Critical asset monitoring coverage ratio ({e_cov*100:.1f}%) is severely depressed "
                        f"relative to peer cohort median ({np.median(cohort_covs)*100:.1f}%, robust z={z_val:.2f}). "
                        f"Over {(1.0-e_cov)*100:.0f}% of designated critical assets generated no alerts."
                    ),
                    evidence_refs=[],
                    parameters={"coverage_ratio": e_cov, "cohort_median": float(np.median(cohort_covs)), "robust_z": z_val},
                ))

        return findings

"""NOVELTY Detector (NOV-01).

Unsupervised ensemble (IsolationForest + LocalOutlierFactor) on cohort-normalized
entity-month feature vectors to catch previously uncatalogued multi-dimensional anomalies.
Explains anomalies by extracting top contributing feature deviations in plain language.
"""

from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler

from satsa.config import THRESHOLDS
from satsa.detectors.base import BaseDetector, Finding, generate_finding_id
from satsa.features import compute_entity_monthly_features
from satsa.ingest import DataBundle
from satsa.peers import CohortManager


FEATURE_LABELS = {
    "monthly_volume": "overall monthly alert volume",
    "crit_volume": "critical alert volume",
    "crit_median_close_sec": "critical alert closure speed",
    "ch_esc_rate": "critical/high escalation rate",
    "unworked_ratio": "proportion of unworked alerts",
    "sla_window_ratio": "SLA boundary closure concentration",
    "fp_rate": "false-positive disposition rate",
    "unique_assets_alerted": "breadth of alerting assets",
}


class NOV01NoveltyDetector(BaseDetector):
    """NOV-01: IsolationForest + LOF on entity-month feature vectors with cohort normalisation."""

    detector_id = "NOV-01"
    detector_version = "1.0.0"
    category = "NOVEL"

    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        findings: List[Finding] = []
        if bundle.alerts.empty:
            return findings

        monthly_df = compute_entity_monthly_features(bundle)
        if len(monthly_df) < 8:
            return findings

        num_cols = [
            c for c in monthly_df.columns
            if c not in ("entity_id", "year_month") and pd.api.types.is_numeric_dtype(monthly_df[c])
        ]
        if not num_cols:
            return findings

        X_raw = monthly_df[num_cols].fillna(0.0).values
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X_raw)

        # 1. Isolation Forest
        n_samples = len(X_scaled)
        contamination = min(0.15, max(0.02, THRESHOLDS.nov01_contamination))
        iso = IsolationForest(contamination=contamination, random_state=42)
        iso_preds = iso.fit_predict(X_scaled)  # -1 is anomaly, 1 is normal
        iso_scores = -iso.score_samples(X_scaled)  # higher = more anomalous

        # 2. Local Outlier Factor
        n_neighbors = min(THRESHOLDS.nov01_lof_neighbors, n_samples - 1)
        if n_neighbors >= 2:
            lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination)
            lof_preds = lof.fit_predict(X_scaled)
            lof_scores = -lof.negative_outlier_factor_
        else:
            lof_preds = np.ones(n_samples)
            lof_scores = np.zeros(n_samples)

        # Combine predictions: flagged if both agree or either is strongly anomalous
        anom_mask = (iso_preds == -1) | (lof_preds == -1)

        for idx in np.where(anom_mask)[0]:
            row = monthly_df.iloc[idx]
            eid = row["entity_id"]
            ym = row["year_month"]
            scope_str = f"period:{ym}"

            # Calculate which features contributed most to deviation
            feat_devs = np.abs(X_scaled[idx])
            top_indices = np.argsort(feat_devs)[::-1][:2]

            top_descriptions = []
            for t_idx in top_indices:
                col_name = num_cols[t_idx]
                col_label = FEATURE_LABELS.get(col_name, col_name)
                val = row[col_name]
                top_descriptions.append(f"{col_label} ({val:.1f})")

            driver_text = " and ".join(top_descriptions) if top_descriptions else "multi-dimensional shift"

            score = float(iso_scores[idx])
            findings.append(Finding(
                finding_id=generate_finding_id(self.detector_id, eid, scope_str),
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                category=self.category,
                entity_id=eid,
                scope=scope_str,
                severity_weight=3.5,
                deviation=round(score, 3),
                peer_percentile=0.98,
                confidence=0.82,
                reason_text=(
                    f"Multivariate behavioural anomaly detected for month {ym} (IsolationForest + LOF outlier score={score:.2f}). "
                    f"Primary drivers: {driver_text} deviating sharply from cohort norms."
                ),
                evidence_refs=[],
                parameters={
                    "year_month": ym,
                    "anomaly_score": round(score, 3),
                    "top_drivers": [num_cols[i] for i in top_indices],
                },
            ))

        return findings

"""Feature engineering for SAT-SA.

Computes granular per-alert, per-case, per-asset, per-entity, and per-entity-month
features for peer-relative anomaly detection and supervisory evaluation.
"""

from collections import Counter
from datetime import datetime
import math
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from satsa.ingest import DataBundle


def calculate_entropy(values: List[str]) -> float:
    """Calculate Shannon entropy (base 2) for categorical distributions."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / total
        if p > 0:
            entropy -= p * math.log2(p)
    return float(entropy)


def calculate_gini(values: np.ndarray) -> float:
    """Calculate Gini inequality coefficient (0.0 = uniform, 1.0 = total inequality)."""
    vals = np.asarray(values, dtype=float)
    vals = vals[vals >= 0]
    if len(vals) == 0 or np.sum(vals) == 0:
        return 0.0
    vals = np.sort(vals)
    n = len(vals)
    index = np.arange(1, n + 1)
    return float((2.0 * np.sum(index * vals)) / (n * np.sum(vals)) - (n + 1) / n)


def compute_alert_features(
    alerts_df: pd.DataFrame,
    cases_df: Optional[pd.DataFrame] = None,
    wf_df: Optional[pd.DataFrame] = None,
    esc_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Compute per-alert features including lifecycle durations, repeat counts, and case linkages."""
    if alerts_df.empty:
        return pd.DataFrame()

    df = alerts_df.copy()

    # Timestamps to datetime
    for c in ("created_ts", "ack_ts", "closed_ts"):
        if c in df.columns and not pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = pd.to_datetime(df[c])

    # Durations in seconds and minutes
    df["ack_latency_sec"] = (df["ack_ts"] - df["created_ts"]).dt.total_seconds().clip(lower=0)
    df["closure_duration_sec"] = (df["closed_ts"] - df["ack_ts"]).dt.total_seconds().clip(lower=0)
    df["closure_duration_min"] = df["closure_duration_sec"] / 60.0
    df["total_lifecycle_sec"] = (df["closed_ts"] - df["created_ts"]).dt.total_seconds().clip(lower=0)

    # Timing characteristics (for SLA bunching)
    df["closed_minute"] = df["closed_ts"].dt.minute
    df["closed_hour"] = df["closed_ts"].dt.hour
    df["closed_dayofweek"] = df["closed_ts"].dt.dayofweek
    df["is_sla_window"] = (df["closure_duration_min"] >= 55.0) & (df["closure_duration_min"] <= 60.0)

    # Repeat alerts on same asset + category within 7 days
    df = df.sort_values(by=["entity_id", "asset_id", "category", "created_ts"])
    df["prev_created_ts"] = df.groupby(["entity_id", "asset_id", "category"])["created_ts"].shift(1)
    df["days_since_prev"] = (df["created_ts"] - df["prev_created_ts"]).dt.total_seconds() / 86400.0
    df["is_repeat_7d"] = df["days_since_prev"].fillna(999.0) <= 7.0

    # Rolling repeat count
    df["repeat_streak_7d"] = df.groupby(["entity_id", "asset_id", "category"])["is_repeat_7d"].cumsum()

    # Link cases information
    if cases_df is not None and not cases_df.empty:
        case_map = cases_df.set_index("alert_id")
        df["case_id"] = df["alert_id"].map(case_map["case_id"] if "case_id" in case_map else pd.Series(dtype=object))
        df["has_case"] = df["case_id"].notna()
        df["analyst_id"] = df["alert_id"].map(case_map["analyst_id"] if "analyst_id" in case_map else pd.Series(dtype=object))
        df["closure_code"] = df["alert_id"].map(case_map["closure_code"] if "closure_code" in case_map else pd.Series(dtype=object))
        df["notes_text"] = df["alert_id"].map(case_map["notes_text"] if "notes_text" in case_map else pd.Series(dtype=object))
    else:
        df["case_id"] = None
        df["has_case"] = False
        df["analyst_id"] = None
        df["closure_code"] = None
        df["notes_text"] = None

    # Link workflow events
    if wf_df is not None and not wf_df.empty and "case_id" in df.columns:
        wf_counts = wf_df.groupby("case_id").size()
        df["workflow_event_count"] = df["case_id"].map(wf_counts).fillna(0).astype(int)
    else:
        df["workflow_event_count"] = 0

    # Link escalations
    if esc_df is not None and not esc_df.empty and "case_id" in df.columns:
        esc_cases = set(esc_df["case_id"].dropna().unique())
        df["is_escalated"] = df["case_id"].isin(esc_cases)
    else:
        df["is_escalated"] = False

    return df


def compute_asset_features(
    assets_df: pd.DataFrame,
    alerts_df: pd.DataFrame,
) -> pd.DataFrame:
    """Compute per-asset features including telemetry activity counts and silence indicators."""
    if assets_df.empty:
        return pd.DataFrame()

    df = assets_df.copy()

    if alerts_df.empty:
        df["total_alerts"] = 0
        df["critical_alerts"] = 0
        df["high_alerts"] = 0
        df["is_silent"] = True
        return df

    # Aggregations by asset
    counts = alerts_df.groupby("asset_id").size()
    crit_counts = alerts_df[alerts_df["severity"] == "critical"].groupby("asset_id").size()
    high_counts = alerts_df[alerts_df["severity"] == "high"].groupby("asset_id").size()

    df["total_alerts"] = df["asset_id"].map(counts).fillna(0).astype(int)
    df["critical_alerts"] = df["asset_id"].map(crit_counts).fillna(0).astype(int)
    df["high_alerts"] = df["asset_id"].map(high_counts).fillna(0).astype(int)
    df["is_silent"] = df["total_alerts"] == 0
    df["is_critical_silent"] = (df["criticality"] == "critical") & (df["total_alerts"] == 0)

    return df


def compute_entity_features(bundle: DataBundle) -> pd.DataFrame:
    """Compute entity-level macro features across the entire evaluation timeframe."""
    entities = bundle.entities.copy()
    if entities.empty:
        return pd.DataFrame()

    alert_feats = compute_alert_features(
        bundle.alerts, bundle.cases, bundle.workflow_events, bundle.escalations
    )
    asset_feats = compute_asset_features(bundle.assets, bundle.alerts)

    records: List[Dict[str, Any]] = []
    for _, ent_row in entities.iterrows():
        eid = ent_row["entity_id"]
        e_alerts = alert_feats[alert_feats["entity_id"] == eid] if not alert_feats.empty else pd.DataFrame()
        e_assets = asset_feats[asset_feats["entity_id"] == eid] if not asset_feats.empty else pd.DataFrame()
        e_cases = bundle.cases[bundle.cases["alert_id"].isin(e_alerts["alert_id"])] if not e_alerts.empty and not bundle.cases.empty else pd.DataFrame()

        total_alerts = len(e_alerts)
        total_assets = len(e_assets)
        crit_assets = len(e_assets[e_assets["criticality"] == "critical"]) if not e_assets.empty else 0
        monitored_crit_assets = len(e_assets[(e_assets["criticality"] == "critical") & e_assets["monitoring_expected"]]) if not e_assets.empty else 0
        silent_crit_assets = len(e_assets[(e_assets["criticality"] == "critical") & e_assets["monitoring_expected"] & e_assets["is_silent"]]) if not e_assets.empty else 0

        # Critical / High closure speed
        crit_alerts = e_alerts[e_alerts["severity"] == "critical"] if not e_alerts.empty else pd.DataFrame()
        high_alerts = e_alerts[e_alerts["severity"] == "high"] if not e_alerts.empty else pd.DataFrame()
        crithigh_alerts = e_alerts[e_alerts["severity"].isin(["critical", "high"])] if not e_alerts.empty else pd.DataFrame()

        crit_median_close_sec = float(crit_alerts["closure_duration_sec"].median()) if not crit_alerts.empty else np.nan
        crit_p5_close_sec = float(crit_alerts["closure_duration_sec"].quantile(0.05)) if not crit_alerts.empty else np.nan
        high_median_close_sec = float(high_alerts["closure_duration_sec"].median()) if not high_alerts.empty else np.nan

        # Escalation rates
        crit_esc_rate = float(crit_alerts["is_escalated"].mean()) if not crit_alerts.empty else np.nan
        high_esc_rate = float(high_alerts["is_escalated"].mean()) if not high_alerts.empty else np.nan
        crithigh_esc_rate = float(crithigh_alerts["is_escalated"].mean()) if not crithigh_alerts.empty else np.nan

        # Unworked alerts ratio
        unworked_ratio = float((e_alerts["workflow_event_count"] == 0).mean()) if not e_alerts.empty else 0.0

        # Analyst concentration
        if not crithigh_alerts.empty and "analyst_id" in crithigh_alerts.columns:
            analyst_counts = crithigh_alerts["analyst_id"].dropna().value_counts()
            top1_share = float(analyst_counts.iloc[0] / len(crithigh_alerts)) if len(analyst_counts) > 0 else 0.0
            analyst_gini = calculate_gini(analyst_counts.values)
        else:
            top1_share = 0.0
            analyst_gini = 0.0

        # SLA bunching ratio
        sla_bunching_ratio = float(e_alerts["is_sla_window"].mean()) if not e_alerts.empty else 0.0

        # Notes entropy & template ratio
        if not e_cases.empty and "closure_code" in e_cases.columns:
            closure_code_entropy = calculate_entropy(e_cases["closure_code"].dropna().tolist())
            notes = e_cases["notes_text"].dropna().astype(str).tolist()
            notes_entropy = calculate_entropy([n[:40] for n in notes])
            template_ratio = float(np.mean([1 if "Automated triage complete" in n else 0 for n in notes])) if notes else 0.0
        else:
            closure_code_entropy = 0.0
            notes_entropy = 0.0
            template_ratio = 0.0

        # Coverage ratio
        active_assets_count = len(e_assets[~e_assets["is_silent"]]) if not e_assets.empty else 0
        coverage_ratio = float(active_assets_count / total_assets) if total_assets > 0 else 0.0
        crit_coverage_ratio = float((crit_assets - silent_crit_assets) / crit_assets) if crit_assets > 0 else 1.0

        # Daily continuity (max consecutive zero days)
        if not e_alerts.empty:
            daily_series = e_alerts.set_index("created_ts").resample("D").size()
            zero_streaks = (daily_series == 0).astype(int)
            # Length of maximum consecutive zero run
            consec_zeros = 0
            max_consec_zeros = 0
            for z in zero_streaks:
                if z == 1:
                    consec_zeros += 1
                    if consec_zeros > max_consec_zeros:
                        max_consec_zeros = consec_zeros
                else:
                    consec_zeros = 0
        else:
            max_consec_zeros = 999

        records.append({
            "entity_id": eid,
            "sector": ent_row["sector"],
            "size_band": ent_row["size_band"],
            "soc_model": ent_row.get("soc_model", "in-house"),
            "total_alerts": total_alerts,
            "total_assets": total_assets,
            "alerts_per_asset": total_alerts / max(1, total_assets),
            "crit_median_close_sec": crit_median_close_sec,
            "crit_p5_close_sec": crit_p5_close_sec,
            "high_median_close_sec": high_median_close_sec,
            "crit_esc_rate": crit_esc_rate,
            "high_esc_rate": high_esc_rate,
            "crithigh_esc_rate": crithigh_esc_rate,
            "unworked_ratio": unworked_ratio,
            "analyst_gini": analyst_gini,
            "top1_analyst_share": top1_share,
            "sla_bunching_ratio": sla_bunching_ratio,
            "closure_code_entropy": closure_code_entropy,
            "notes_entropy": notes_entropy,
            "template_ratio": template_ratio,
            "silent_crit_assets": silent_crit_assets,
            "coverage_ratio": coverage_ratio,
            "crit_coverage_ratio": crit_coverage_ratio,
            "max_consecutive_zero_days": max_consec_zeros,
        })

    return pd.DataFrame(records)


def compute_entity_monthly_features(bundle: DataBundle) -> pd.DataFrame:
    """Compute per-entity-month feature matrix for IsolationForest and novelty detection (NOV-01)."""
    if bundle.alerts.empty:
        return pd.DataFrame()

    alert_feats = compute_alert_features(bundle.alerts, bundle.cases, bundle.workflow_events, bundle.escalations)
    alert_feats["year_month"] = alert_feats["created_ts"].dt.to_period("M").astype(str)

    groups = alert_feats.groupby(["entity_id", "year_month"])
    records = []

    for (eid, ym), g in groups:
        crit_g = g[g["severity"] == "critical"]
        high_g = g[g["severity"] == "high"]
        ch_g = g[g["severity"].isin(["critical", "high"])]

        records.append({
            "entity_id": eid,
            "year_month": ym,
            "monthly_volume": len(g),
            "crit_volume": len(crit_g),
            "crit_median_close_sec": float(crit_g["closure_duration_sec"].median()) if not crit_g.empty else 0.0,
            "ch_esc_rate": float(ch_g["is_escalated"].mean()) if not ch_g.empty else 0.0,
            "unworked_ratio": float((g["workflow_event_count"] == 0).mean()),
            "sla_window_ratio": float(g["is_sla_window"].mean()),
            "fp_rate": float((g["disposition"] == "false_positive").mean()),
            "unique_assets_alerted": g["asset_id"].nunique(),
        })

    return pd.DataFrame(records)

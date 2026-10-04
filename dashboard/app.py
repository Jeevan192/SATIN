"""Streamlit Supervisory Review Interface for SAT-SA.

Offline examiner review interface for evaluating Critical Sector Entities (CSEs):
- Portfolio Overview: Ranked CSEs, 8-capability area radar, sector benchmarks
- Entity Detail: Capability profile vs peer cohort median, QoQ trend
- Finding Card: Neutral explainability, evidence drill-down, peer distribution chart
- Review Queue: Prioritized 85% risk diversified + 15% random control queue with CSV export
- Coverage Heatmap: Critical asset telemetry status and silence detection
- Audit & Validation: Cryptographic run manifest, hash-chain verification, ground truth metrics
"""

from datetime import datetime
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure repository root is on sys.path and remove package dir
PACKAGE_DIR = str(Path(__file__).resolve().parent)
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
while PACKAGE_DIR in sys.path:
    sys.path.remove(PACKAGE_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from satsa.audit import verify_audit_chain
from satsa.config import PATHS, CAPABILITIES


# --------------------------------------------------
# Configuration & Layout
# --------------------------------------------------
st.set_page_config(
    page_title="SAT-SA | SOC Supervisory Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = os.getenv("SATSA_API_URL", "http://127.0.0.1:8000")


# --------------------------------------------------
# Offline Data Access Helpers
# --------------------------------------------------
@st.cache_data(ttl=60)
def fetch_json_data(endpoint: str, fallback_file: str) -> Optional[Any]:
    """Fetch data from FastAPI if available, or fall back directly to offline data/output."""
    # 1. Try FastAPI endpoint
    try:
        import requests
        resp = requests.get(f"{API_URL}{endpoint}", timeout=1.5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    # 2. Direct offline filesystem fallback
    local_p = PATHS.output_dir / fallback_file
    if local_p.exists():
        try:
            with open(local_p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def get_all_entities_data() -> Dict[str, Any]:
    """Load entity scores dictionary."""
    return fetch_json_data("/trends", "entity_scores.json") or {}


def get_all_findings_data() -> List[Dict[str, Any]]:
    """Load all findings list."""
    res = fetch_json_data("/findings", "findings.json")
    if isinstance(res, dict) and "findings" in res:
        return res["findings"]
    elif isinstance(res, list):
        return res
    return []


def get_all_queues_data() -> Dict[str, List[Dict[str, Any]]]:
    """Load review queues dictionary."""
    return fetch_json_data("/queue", "review_queue.json") or {}


# --------------------------------------------------
# Header & Navigation
# --------------------------------------------------
st.sidebar.markdown(
    """
    <div style="text-align: center; padding: 10px 0;">
        <h2 style="margin: 0; color: #1E3A8A;">🛡️ SAT-SA</h2>
        <p style="margin: 0; font-size: 13px; color: #64748B;">Supervisory Analytics Tool for SOC Assessment</p>
        <span style="display: inline-block; margin-top: 5px; background: #E2E8F0; color: #334155; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">OFFLINE AIR-GAP MODE</span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.divider()

page = st.sidebar.radio(
    "Supervisory Workflow",
    [
        "🏛️ Portfolio Overview",
        "🏢 Entity Detail & Capability Radar",
        "🔍 Finding Card & Evidence Drill-Down",
        "📋 Examiner Review Queue (85/15)",
        "🗺️ Asset Telemetry Coverage Heatmap",
        "🛡️ Cryptographic Audit & Validation",
    ],
    index=0,
)

st.sidebar.divider()
st.sidebar.caption("SAT-SA v1.0.0 | Offline Analytical Engine")


# --------------------------------------------------
# Load Base Data
# --------------------------------------------------
scores_data = fetch_json_data("/trends", "entity_scores.json")
findings_data = get_all_findings_data()
queues_data = get_all_queues_data()

# Normalize scores data if fetched from /trends
if isinstance(scores_data, dict) and "area_averages" in scores_data:
    # Directly read entity_scores.json for entity mapping
    local_scores = PATHS.output_dir / "entity_scores.json"
    if local_scores.exists():
        with open(local_scores, "r", encoding="utf-8") as f:
            scores_data = json.load(f)
    else:
        scores_data = {}

if not scores_data:
    st.warning("⚠️ No supervisory data found in `data/output/`. Please run the pipeline first.")
    if st.button("🚀 Run Offline Supervisory Pipeline Now"):
        from satsa.pipeline import run_all
        with st.spinner("Executing end-to-end supervisory assessment pipeline..."):
            run_all(data_dir=PATHS.synthetic_dir, output_dir=PATHS.output_dir)
            st.rerun()
    st.stop()


# --------------------------------------------------
# PAGE 1: Portfolio Overview
# --------------------------------------------------
if page == "🏛️ Portfolio Overview":
    st.title("Portfolio Supervisory Overview")
    st.caption("Comparative peer evaluation across Critical Sector Entities (CSEs)")

    # Top KPI Metrics
    entities_count = len(scores_data)
    high_risk_count = sum(1 for s in scores_data.values() if s.get("risk_tier") in ("high", "critical"))
    total_findings = len(findings_data)
    audit_valid, _ = verify_audit_chain(PATHS.audit_log_file)

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("CSE Entities Assessed", f"{entities_count}", "100% evaluated")
    kpi2.metric("High/Critical Risk Entities", f"{high_risk_count}", f"{(high_risk_count/max(1, entities_count))*100:.0f}% of portfolio", delta_color="inverse")
    kpi3.metric("Total Supervisory Findings", f"{total_findings}", "Active detections")
    kpi4.metric("Audit Trail Integrity", "SEALED & INTACT" if audit_valid else "TAMPER DETECTED", "SHA-256 chain")

    st.divider()

    # Portfolio Radar & Risk Ranking
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.subheader("Ranked Critical Sector Entities")
        table_rows = []
        for eid, s in scores_data.items():
            table_rows.append({
                "Entity ID": eid,
                "Supervisory Risk Index": s.get("overall_risk_index", 0.0),
                "Risk Tier": s.get("risk_tier", "low").upper(),
                "Peer Percentile": f"{s.get('peer_percentile', 0.5)*100:.1f}%",
                "QoQ Trend": s.get("qoq_trend", "stable").capitalize(),
                "Findings": s.get("findings_count", 0),
            })
        df_ranked = pd.DataFrame(table_rows).sort_values("Supervisory Risk Index", ascending=False)
        st.dataframe(
            df_ranked,
            use_container_width=True,
            column_config={
                "Supervisory Risk Index": st.column_config.ProgressColumn(
                    "Risk Index (0-100)",
                    format="%.1f",
                    min_value=0,
                    max_value=100,
                ),
            },
            hide_index=True,
        )

    with col_right:
        st.subheader("Portfolio Capability Area Radar")
        # Compute portfolio average per area
        area_sums = {a: [] for a in CAPABILITIES.areas}
        for s in scores_data.values():
            for a, val in s.get("area_scores", {}).items():
                if a in area_sums:
                    area_sums[a].append(val)

        avg_areas = [np.mean(area_sums[a]) if area_sums[a] else 0.0 for a in CAPABILITIES.areas]
        labels = [a.replace("_", " ").title() for a in CAPABILITIES.areas]

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=avg_areas + [avg_areas[0]],
            theta=labels + [labels[0]],
            fill="toself",
            name="Portfolio Average",
            line=dict(color="#2563EB", width=2),
            fillcolor="rgba(37, 99, 235, 0.2)",
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=False,
            margin=dict(l=40, r=40, t=20, b=20),
            height=360,
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    st.divider()

    # Breakdown by Category & Concept
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Findings by Concept Lane")
        concept_counts = pd.Series([f.get("category", "") for f in findings_data]).value_counts().reset_index()
        concept_counts.columns = ["Concept", "Count"]
        fig_concept = px.bar(
            concept_counts,
            x="Concept",
            y="Count",
            color="Concept",
            color_discrete_map={
                "EXECUTION_GAP": "#DC2626",
                "NEGATIVE_SPACE": "#2563EB",
                "NOVEL": "#7C3AED",
            },
            text_auto=True,
        )
        fig_concept.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=10))
        st.plotly_chart(fig_concept, use_container_width=True)

    with c2:
        st.subheader("Risk Tier Distribution")
        tier_counts = df_ranked["Risk Tier"].value_counts().reset_index()
        tier_counts.columns = ["Tier", "Entities"]
        fig_tier = px.pie(
            tier_counts,
            names="Tier",
            values="Entities",
            color="Tier",
            color_discrete_map={
                "CRITICAL": "#991B1B",
                "HIGH": "#DC2626",
                "ELEVATED": "#D97706",
                "MODERATE": "#2563EB",
                "LOW": "#16A34A",
            },
            hole=0.4,
        )
        fig_tier.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=10))
        st.plotly_chart(fig_tier, use_container_width=True)


# --------------------------------------------------
# PAGE 2: Entity Detail & Capability Radar
# --------------------------------------------------
elif page == "🏢 Entity Detail & Capability Radar":
    st.title("Entity Assessment & Capability Radar")
    st.caption("Detailed supervisory assessment and peer cohort comparison")

    sorted_eids = sorted(scores_data.keys(), key=lambda e: scores_data[e].get("overall_risk_index", 0.0), reverse=True)
    selected_eid = st.selectbox("Select Critical Sector Entity (CSE)", sorted_eids, index=0)

    e_score = scores_data[selected_eid]
    overall_idx = e_score.get("overall_risk_index", 0.0)
    tier = e_score.get("risk_tier", "low").upper()
    pct = e_score.get("peer_percentile", 0.5) * 100.0
    trend = e_score.get("qoq_trend", "stable").capitalize()

    # KPI row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Supervisory Risk Index", f"{overall_idx:.1f} / 100", f"Tier: {tier}")
    m2.metric("Cohort Peer Percentile", f"{pct:.1f}%", "Relative to sector peers")
    m3.metric("Quarter-over-Quarter Trend", trend, "Supervisory posture trajectory")
    m4.metric("Active Findings", f"{e_score.get('findings_count', 0)}", "Requiring attention")

    st.divider()

    # Entity Radar vs Peer Cohort Median
    r_col1, r_col2 = st.columns([1, 1])

    with r_col1:
        st.subheader("8-Capability Area Comparison vs Cohort Median")
        area_scores = e_score.get("area_scores", {})
        entity_vals = [area_scores.get(a, 0.0) for a in CAPABILITIES.areas]

        # Calculate cohort median per area
        cohort_vals = []
        for a in CAPABILITIES.areas:
            vals = [s.get("area_scores", {}).get(a, 0.0) for s in scores_data.values()]
            cohort_vals.append(float(np.median(vals)) if vals else 0.0)

        labels = [a.replace("_", " ").title() for a in CAPABILITIES.areas]

        fig_e_radar = go.Figure()
        fig_e_radar.add_trace(go.Scatterpolar(
            r=entity_vals + [entity_vals[0]],
            theta=labels + [labels[0]],
            fill="toself",
            name=f"{selected_eid}",
            line=dict(color="#DC2626", width=2),
            fillcolor="rgba(220, 38, 38, 0.2)",
        ))
        fig_e_radar.add_trace(go.Scatterpolar(
            r=cohort_vals + [cohort_vals[0]],
            theta=labels + [labels[0]],
            fill="toself",
            name="Cohort Peer Median",
            line=dict(color="#64748B", width=2, dash="dash"),
            fillcolor="rgba(100, 116, 139, 0.1)",
        ))
        fig_e_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            margin=dict(l=40, r=40, t=20, b=20),
            height=380,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_e_radar, use_container_width=True)

    with r_col2:
        st.subheader("Capability Area Sub-Scores")
        area_df = pd.DataFrame([
            {
                "Capability Area": a.replace("_", " ").title(),
                "Score": area_scores.get(a, 0.0),
                "Cohort Median": cohort_vals[i],
            }
            for i, a in enumerate(CAPABILITIES.areas)
        ]).sort_values("Score", ascending=False)

        st.dataframe(
            area_df,
            use_container_width=True,
            column_config={
                "Score": st.column_config.ProgressColumn("Score (0-100)", format="%.1f", min_value=0, max_value=100),
                "Cohort Median": st.column_config.NumberColumn("Peer Median", format="%.1f"),
            },
            hide_index=True,
        )

    st.divider()

    # Entity Findings Table
    st.subheader(f"Supervisory Findings for {selected_eid}")
    e_findings = [f for f in findings_data if f.get("entity_id") == selected_eid]
    if e_findings:
        f_display = []
        for f in e_findings:
            f_display.append({
                "Finding ID": f.get("finding_id"),
                "Detector": f.get("detector_id"),
                "Concept": f.get("category"),
                "Scope": f.get("scope"),
                "Deviation": f.get("deviation"),
                "Severity Weight": f.get("severity_weight"),
                "Reason": f.get("reason_text"),
            })
        st.dataframe(pd.DataFrame(f_display), use_container_width=True, hide_index=True)
    else:
        st.success(f"No anomalous supervisory findings detected for {selected_eid} (Clean Control Entity).")


# --------------------------------------------------
# PAGE 3: Finding Card & Evidence Drill-Down
# --------------------------------------------------
elif page == "🔍 Finding Card & Evidence Drill-Down":
    st.title("Supervisory Finding Card")
    st.caption("Explainable evidence drill-down, parameters, and cohort deviation")

    if not findings_data:
        st.info("No findings available to display.")
        st.stop()

    finding_options = [
        f"{f.get('finding_id')} | {f.get('detector_id')} ({f.get('category')}) | {f.get('entity_id')} - {f.get('scope')}"
        for f in findings_data[:300]
    ]
    selected_option = st.selectbox("Select Finding to Inspect", finding_options, index=0)
    selected_fid = selected_option.split(" | ")[0]
    finding = next((f for f in findings_data if f.get("finding_id") == selected_fid), findings_data[0])

    # Finding Banner
    cat = finding.get("category", "")
    badge_color = "#DC2626" if cat == "EXECUTION_GAP" else ("#2563EB" if cat == "NEGATIVE_SPACE" else "#7C3AED")

    st.markdown(
        f"""
        <div style="background: #F8FAFC; border-left: 6px solid {badge_color}; padding: 16px 20px; border-radius: 6px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin: 0; color: #0F172A;">{finding.get('detector_id')} - {finding.get('scope')}</h3>
                <span style="background: {badge_color}; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px;">{cat}</span>
            </div>
            <p style="margin: 8px 0 0 0; color: #334155; font-size: 15px; line-height: 1.5;">{finding.get('reason_text')}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    fc1, fc2, fc3, fc4 = st.columns(4)
    fc1.metric("Entity ID", finding.get("entity_id", ""))
    fc2.metric("Severity Weight", f"{finding.get('severity_weight', 1.0):.1f}x")
    fc3.metric("Cohort Deviation", f"{finding.get('deviation', 0.0):.2f}")
    fc4.metric("Confidence Score", f"{finding.get('confidence', 0.9)*100:.0f}%")

    st.divider()

    # Evidence References & Underlying Records
    ed_col1, ed_col2 = st.columns([1, 1])

    with ed_col1:
        st.subheader("Underlying Evidence References")
        evidence_list = finding.get("evidence_refs", [])
        if evidence_list:
            ev_df = pd.DataFrame([
                {"Record Ref": r, "Table": r.split(":")[0], "ID": r.split(":")[-1]}
                for r in evidence_list
            ])
            st.dataframe(ev_df, use_container_width=True, hide_index=True)
        else:
            st.info("Finding is computed at entity-aggregate or time-series scope (no single alert row).")

    with ed_col2:
        st.subheader("Detector Parameters & Thresholds")
        params = finding.get("parameters", {})
        if params:
            param_df = pd.DataFrame([
                {"Parameter": k, "Value": str(v)}
                for k, v in params.items()
            ])
            st.dataframe(param_df, use_container_width=True, hide_index=True)
        else:
            st.write("Standard detector configuration applied.")


# --------------------------------------------------
# PAGE 4: Examiner Review Queue (85/15)
# --------------------------------------------------
elif page == "📋 Examiner Review Queue (85/15)":
    st.title("Examiner Prioritized Review Queue")
    st.caption("Budget-constrained manual review queue: 85% diversified risk items + 15% random control baseline")

    q_eids = sorted(queues_data.keys())
    if not q_eids:
        st.warning("No review queues loaded.")
        st.stop()

    sel_q_eid = st.selectbox("Select Critical Sector Entity Queue", q_eids, index=0)
    raw_queue = queues_data.get(sel_q_eid, [])

    budget = st.slider("Examiner Review Budget", min_value=10, max_value=min(200, max(10, len(raw_queue))), value=min(50, len(raw_queue)), step=5)
    queue = raw_queue[:budget]

    risk_count = sum(1 for q in queue if q.get("selection_bucket") == "risk_ranked")
    ctrl_count = sum(1 for q in queue if q.get("selection_bucket") == "random_control")

    qc1, qc2, qc3 = st.columns(3)
    qc1.metric("Examiner Review Budget", f"{len(queue)} items")
    qc2.metric("Risk-Ranked Items (85%)", f"{risk_count}", f"{(risk_count/max(1, len(queue)))*100:.1f}%")
    qc3.metric("Random Control Slice (15%)", f"{ctrl_count}", f"{(ctrl_count/max(1, len(queue)))*100:.1f}%")

    st.divider()

    # Queue Table
    table_items = []
    for item in queue:
        table_items.append({
            "Rank": item.get("priority_rank"),
            "Bucket": "🚨 RISK" if item.get("selection_bucket") == "risk_ranked" else "🎲 CONTROL",
            "Detector": item.get("detector_id"),
            "Scope": item.get("scope"),
            "Priority Score": item.get("priority_score"),
            "Examiner Selection Reason": item.get("selection_reason"),
            "Evidence Refs": ", ".join(item.get("evidence_refs", [])),
        })

    df_queue = pd.DataFrame(table_items)
    st.dataframe(df_queue, use_container_width=True, hide_index=True)

    # Export to CSV
    csv_bytes = df_queue.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Export Examiner Review Queue to CSV",
        data=csv_bytes,
        file_name=f"SAT_SA_Review_Queue_{sel_q_eid}.csv",
        mime="text/csv",
    )


# --------------------------------------------------
# PAGE 5: Asset Telemetry Coverage Heatmap
# --------------------------------------------------
elif page == "🗺️ Asset Telemetry Coverage Heatmap":
    st.title("Asset Telemetry & Monitoring Coverage Heatmap")
    st.caption("Verifies designated critical assets against active telemetry (NS-01 and NS-06 detection)")

    # Load assets and alerts
    assets_csv = PATHS.synthetic_dir / "assets.csv"
    alerts_csv = PATHS.synthetic_dir / "alerts.csv"

    if assets_csv.exists() and alerts_csv.exists():
        assets_df = pd.read_csv(assets_csv)
        alerts_df = pd.read_csv(alerts_csv)

        ent_list = sorted(assets_df["entity_id"].dropna().unique())
        heat_eid = st.selectbox("Select Entity to Inspect Coverage", ent_list, index=0)

        e_assets = assets_df[assets_df["entity_id"] == heat_eid]
        e_alerts = alerts_df[alerts_df["entity_id"] == heat_eid]

        alert_counts = e_alerts.groupby("asset_id").size().to_dict()
        e_assets = e_assets.copy()
        e_assets["alert_count"] = e_assets["asset_id"].map(alert_counts).fillna(0).astype(int)
        e_assets["status"] = "Normal Telemetry"
        e_assets.loc[e_assets["alert_count"] == 0, "status"] = "Silent Asset"
        e_assets.loc[~e_assets["monitoring_expected"], "status"] = "Unmonitored Deficit"

        # KPI row
        total_a = len(e_assets)
        crit_a = len(e_assets[e_assets["criticality"] == "critical"])
        silent_crit = len(e_assets[(e_assets["criticality"] == "critical") & (e_assets["status"] == "Silent Asset")])

        hc1, hc2, hc3 = st.columns(3)
        hc1.metric("Total Assets in Scope", f"{total_a}")
        hc2.metric("Critical Assets", f"{crit_a}")
        hc3.metric("Silent Critical Assets (NS-01)", f"{silent_crit}", delta_color="inverse")

        st.divider()

        # Telemetry Distribution Matrix
        fig_heat = px.treemap(
            e_assets,
            path=["criticality", "asset_type", "status"],
            values="alert_count",
            color="status",
            color_discrete_map={
                "Normal Telemetry": "#10B981",
                "Silent Asset": "#EF4444",
                "Unmonitored Deficit": "#F59E0B",
            },
            title=f"Asset Telemetry Distribution for {heat_eid}",
        )
        fig_heat.update_layout(height=450, margin=dict(l=10, r=10, t=40, b=10))
        st.plotly_chart(fig_heat, use_container_width=True)

        st.subheader("Asset Inventory Status Details")
        st.dataframe(
            e_assets[["asset_id", "criticality", "asset_type", "monitoring_expected", "alert_count", "status"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Synthetic asset and alert tables not found in data/synthetic/.")


# --------------------------------------------------
# PAGE 6: Cryptographic Audit & Validation
# --------------------------------------------------
elif page == "🛡️ Cryptographic Audit & Validation":
    st.title("Cryptographic Audit Trail & Validation Benchmark")
    st.caption("Immutable SHA-256 hash chains, sealed run manifests, and ground truth performance metrics")

    tab1, tab2, tab3 = st.tabs(["🔒 Cryptographic Audit Chain", "📜 Sealed Run Manifest", "📊 Ground Truth Benchmark Report"])

    with tab1:
        st.subheader("SHA-256 Hash-Chained Audit Log (`audit_log.jsonl`)")
        audit_file = PATHS.audit_log_file

        is_valid, errs = verify_audit_chain(audit_file)
        if is_valid:
            st.success("✅ Cryptographic Audit Chain is 100% INTACT. All block hashes and previous links verified.")
        else:
            st.error("🚨 CRITICAL: Cryptographic Audit Chain TAMPER DETECTED!")
            for err in errs:
                st.code(err)

        if audit_file.exists():
            with open(audit_file, "r", encoding="utf-8") as f:
                log_lines = [json.loads(l) for l in f if l.strip()]

            df_log = pd.DataFrame(log_lines)
            st.dataframe(df_log, use_container_width=True, hide_index=True)

    with tab2:
        st.subheader("Sealed Run Manifest (`run_manifest.json`)")
        manifest_file = PATHS.run_manifest_file
        if manifest_file.exists():
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            st.json(manifest_data)
        else:
            st.info("No run manifest found. Execute pipeline first.")

    with tab3:
        st.subheader("Ground Truth Benchmark Report")
        val_rep_file = PATHS.validation_report_file
        if val_rep_file.exists():
            with open(val_rep_file, "r", encoding="utf-8") as f:
                val_content = f.read()
            st.markdown(val_content)
        else:
            st.info("Validation report not found. Execute `python validation/run_validation.py` first.")
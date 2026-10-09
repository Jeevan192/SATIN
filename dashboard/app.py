"""Streamlit Supervisory Review Interface for SATIN.

Offline examiner review interface for evaluating Critical Sector Entities (CSEs):
- Portfolio Overview: ranked CSEs, executive summary, capability profile, priority findings
- Entity Workspace: capability profile vs peer cohort, finding drill-down, evidence lineage
- Finding Investigation: neutral explainability, evidence references, peer deviation
- Review Queue: budgeted 85% risk-diversified + 15% random control queue with CSV export
- Claim-vs-Reality: self-reported KPIs against audited evidence
- Coverage Heatmap: critical-asset telemetry status and silence detection
- Audit & Validation: hash-chain verification, sealed manifest, ground-truth benchmark

Frontend presentation only. No API contract, detector logic, or analytics is changed here.
"""

from datetime import datetime
import html
import json
import os
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from satsa.audit import verify_audit_chain
from satsa.auth import authenticate as authenticate_user, bootstrap as bootstrap_auth, has_permission
from satsa.config import PATHS, CAPABILITIES


# ==========================================================================
# Configuration
# ==========================================================================
st.set_page_config(
    page_title="SATIN | Supervisory Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = os.getenv("SATSA_API_URL", "http://127.0.0.1:8000")


# ==========================================================================
# Design tokens (single source of truth for the visual system)
# ==========================================================================
TONE = {
    "critical": "#D96A6A",
    "high": "#D9A441",
    "elevated": "#5B8FD9",
    "moderate": "#7A8CA8",
    "low": "#4CAF7D",
    "accent": "#5B8FD9",
    "cyan": "#5FB8D9",
    "ok": "#4CAF7D",
    "warn": "#D9A441",
    "bad": "#D96A6A",
    "muted": "#7A8CA8",
    "novel": "#9B87C4",
}

CONCEPT_TONE = {
    "EXECUTION_GAP": "critical",
    "NEGATIVE_SPACE": "elevated",
    "NOVEL": "novel",
}

CONCEPT_COLORS = {
    "EXECUTION_GAP": TONE["critical"],
    "NEGATIVE_SPACE": TONE["elevated"],
    "NOVEL": TONE["novel"],
}

VERDICT_TONE = {
    "substantiated": "low",
    "partially_substantiated": "high",
    "materially_exaggerated": "critical",
}

ASSET_TONE = {
    "Normal Telemetry": "low",
    "Silent Asset": "critical",
    "Unmonitored Deficit": "high",
}

TIER_ORDER = ["critical", "high", "elevated", "moderate", "low"]

TIER_PRIORITY = {
    "critical": "IMMEDIATE",
    "high": "PRIORITY",
    "elevated": "SCHEDULED",
    "moderate": "ROUTINE",
    "low": "MONITOR",
}

# Short, supervisory-framed descriptor for the "primary concern" column.
DETECTOR_LABELS = {
    "EG-01": "Rapid critical-alert closure",
    "EG-02": "Closure without escalation",
    "EG-03": "No investigation workflow",
    "EG-04": "Template investigation notes",
    "EG-05": "Repeat alerts, no remediation",
    "EG-06": "SLA-boundary closure bunching",
    "EG-07": "Analyst closure concentration",
    "EG-08": "Disposition skew drift",
    "NS-01": "Silent critical assets",
    "NS-02": "Missing alert categories",
    "NS-03": "Missing cases / escalations",
    "NS-04": "Suppressed alert volume",
    "NS-05": "Operational silence",
    "NS-06": "Low monitoring coverage",
    "NOV-01": "Novel behaviour anomaly",
}


_CSS = """
<style>
:root, .stApp, [data-testid="stAppViewContainer"] {
    --bg: #0A1120;
    --bg-2: #0D1626;
    --panel: #111B2D;
    --panel-2: #15213A;
    --line: #22314D;
    --line-soft: #1A2740;
    --text: #E6ECF5;
    --text-2: #A8B6CC;
    --text-3: #6F82A0;
    --accent: #5B8FD9;
    --radius: 10px;
    --radius-sm: 6px;

    /* Streamlit theme variables (re-skin built-in widgets) */
    --background-color: #0A1120;
    --secondary-background-color: #111B2D;
    --text-color: #E6ECF5;
    --primary-color: #5B8FD9;
    --font: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
}

html, body, [class*="css"], .stApp {
    font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
}
.stApp, [data-testid="stAppViewContainer"] { background: var(--bg); color: var(--text); }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.1rem; padding-bottom: 3rem; max-width: 1560px; }

h1, h2, h3, h4, h5 { color: var(--text) !important; letter-spacing: -0.01em; }
h1 { font-size: 1.85rem; font-weight: 650; }
[data-testid="stCaptionContainer"], .stCaption, small { color: var(--text-3) !important; }

/* ---- Sidebar ---- */
[data-testid="stSidebar"] {
    background: var(--bg-2);
    border-right: 1px solid var(--line);
}
[data-testid="stSidebar"] .block-container { padding-top: 1rem; }
.sat-brand { padding: 4px 2px 10px 2px; }
.sat-brand-mark {
    font-size: 26px; font-weight: 700; letter-spacing: 0.22em; color: var(--text);
}
.sat-brand-sub { color: var(--text-3); font-size: 12px; margin-top: 2px; }
.sat-brand-tag {
    display: inline-block; margin-top: 10px; padding: 2px 9px; border-radius: 999px;
    font-size: 10.5px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
    color: #9FB6D8; background: rgba(91,143,217,0.12);
    border: 1px solid rgba(91,143,217,0.30);
}

/* ---- Nav radio ---- */
[data-testid="stSidebar"] [role="radiogroup"] { gap: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] label {
    padding: 7px 10px; border-radius: var(--radius-sm); color: var(--text-2);
    border: 1px solid transparent; transition: background .12s ease, color .12s ease;
}
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: rgba(255,255,255,0.03); color: var(--text); }
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
    background: rgba(91,143,217,0.12); color: var(--text); border-color: rgba(91,143,217,0.32);
}
input { accent-color: var(--accent); }

/* ---- Buttons ---- */
.stButton > button, .stDownloadButton > button, [data-testid="stBaseButton-secondary"] {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--line);
    border-radius: var(--radius-sm); font-weight: 550;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--accent); color: #fff;
}
.stButton > button[kind="primary"], .stButton > button[data-testid="stBaseButton-primary"] {
    background: var(--accent); border-color: var(--accent); color: #06101F;
}

/* ---- Inputs / selects ---- */
.stTextInput input, .stTextInput input:focus,
[data-baseweb="select"] > div, [data-baseweb="select"] input {
    background: var(--panel) !important; color: var(--text) !important;
    border-color: var(--line) !important;
}
[data-baseweb="popover"], [data-baseweb="menu"] { background: var(--panel-2) !important; }
[data-baseweb="menu"] li { color: var(--text) !important; }
[data-baseweb="menu"] li:hover { background: rgba(91,143,217,0.16) !important; }

/* ---- Metric tiles ---- */
[data-testid="stMetric"] {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: var(--radius); padding: 14px 16px; height: 100%;
}
[data-testid="stMetricLabel"] {
    color: var(--text-3) !important; font-size: 11px !important; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.07em;
}
[data-testid="stMetricValue"] { color: var(--text) !important; font-size: 27px; font-weight: 650; }
[data-testid="stMetricDelta"] { color: var(--text-3) !important; font-size: 12px; }

/* ---- Tabs ---- */
.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid var(--line); }
.stTabs [data-baseweb="tab"] { color: var(--text-3); font-weight: 550; }
.stTabs [aria-selected="true"] { color: var(--text) !important; }

/* ---- Expander / code / json ---- */
[data-testid="stExpander"] {
    border: 1px solid var(--line) !important; border-radius: var(--radius); background: var(--panel);
}
[data-testid="stExpander"] summary { color: var(--text-2); }
.stCode, code, pre { background: var(--panel-2) !important; color: #C7D6EC !important; }

/* ---- Page header ---- */
.sat-kicker {
    color: var(--accent); font-size: 11.5px; font-weight: 650;
    letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 2px;
}
.sat-subtitle {
    color: var(--text-2); font-size: 14px; margin: -2px 0 16px 0;
    padding-bottom: 12px; border-bottom: 1px solid var(--line);
}

/* ---- Status strip ---- */
.sat-strip { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 2px 0 18px 0; }
.sat-meta { color: var(--text-3); font-size: 12.5px; margin-left: auto; }

/* ---- Chips / badges ---- */
.sat-chip {
    display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px;
    border-radius: 999px; font-size: 11.5px; font-weight: 600; letter-spacing: 0.02em;
    border: 1px solid var(--line); color: var(--text-2); background: var(--panel);
}
.sat-chip .sat-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-3); }
.sat-badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 10.5px; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase;
    border: 1px solid transparent;
}
.sat-accent { --t: #5B8FD9; }
.sat-critical { --t: #D96A6A; }
.sat-high{ --t: #D9A441; }
.sat-elevated { --t: #5B8FD9; }
.sat-moderate { --t: #7A8CA8; }
.sat-low { --t: #4CAF7D; }
.sat-ok { --t: #4CAF7D; }
.sat-warn { --t: #D9A441; }
.sat-bad { --t: #D96A6A; }
.sat-muted { --t: #7A8CA8; }
.sat-novel { --t: #9B87C4; }
.sat-info { --t: #5B8FD9; }
.sat-chip .sat-dot, .sat-chip.sat-ok .sat-dot, .sat-chip.sat-bad .sat-dot, .sat-chip.sat-info .sat-dot {
    background: var(--t, var(--text-3));
}
.sat-badge { color: var(--t, var(--text-2)); background: color-mix(in srgb, var(--t) 14%, transparent);
    border-color: color-mix(in srgb, var(--t) 35%, transparent); }

/* ---- Panels ---- */
.sat-panel {
    background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
    padding: 16px 18px; margin-bottom: 14px;
}
.sat-panel-title { color: var(--text-2); font-size: 12px; font-weight: 650;
    text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 10px; }
.sat-note { color: var(--text-3); font-size: 12.5px; margin-top: 8px; }
.sat-empty {
    border: 1px dashed var(--line); border-radius: var(--radius); background: rgba(255,255,255,0.015);
    padding: 34px 20px; text-align: center; color: var(--text-3);
}
.sat-empty .sat-empty-title { color: var(--text); font-weight: 600; font-size: 15px; margin-bottom: 4px; }

/* ---- Findings / accent blocks ---- */
.sat-finding {
    background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--t, var(--accent));
    border-radius: var(--radius); padding: 16px 20px; margin-bottom: 18px;
}
.sat-finding .sat-finding-top { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.sat-finding h3 { margin: 0; font-size: 1.12rem; }
.sat-finding p { margin: 10px 0 0 0; color: var(--text-2); font-size: 14.5px; line-height: 1.55; }
.sat-why { color: var(--text-2); font-size: 13.5px; line-height: 1.6; }
.sat-why b { color: var(--text); }
.sat-flow { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
.sat-step {
    border: 1px solid var(--line); background: var(--panel-2); border-radius: var(--radius-sm);
    padding: 6px 10px; font-size: 12px; color: var(--text-2);
}
.sat-step .sat-step-k { color: var(--text-3); font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.06em; display: block; }
.sat-arrow { color: var(--text-3); font-weight: 700; }

/* ---- Custom tables ---- */
.sat-table-wrap { border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; margin: 4px 0 6px; }
.sat-table-scroll { max-height: 560px; overflow-y: auto; }
table.sat-table { width: 100%; border-collapse: collapse; font-size: 13px; }
table.sat-table thead th {
    position: sticky; top: 0; z-index: 2; background: var(--panel-2); color: var(--text-3);
    text-align: left; font-weight: 650; font-size: 10.5px; letter-spacing: 0.06em;
    text-transform: uppercase; padding: 9px 12px; border-bottom: 1px solid var(--line); white-space: nowrap;
}
table.sat-table tbody td {
    padding: 9px 12px; border-bottom: 1px solid var(--line-soft); color: var(--text); vertical-align: middle;
}
table.sat-table tbody tr:last-child td { border-bottom: none; }
table.sat-table tbody tr:hover { background: rgba(91,143,217,0.055); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.sat-strong { color: var(--text); font-weight: 600; }
.sat-dim { color: var(--text-3); }

/* ---- Inline bar ---- */
.sat-meter { display: inline-flex; align-items: center; gap: 8px; justify-content: flex-end; }
.sat-bar { width: 66px; height: 6px; border-radius: 3px; background: rgba(255,255,255,0.08);
    overflow: hidden; }
.sat-bar-fill { height: 100%; border-radius: 3px; background: var(--t, var(--accent)); }
.sat-bar-val { color: var(--text-2); font-variant-numeric: tabular-nums; min-width: 34px; text-align: right; }

/* Scrollbars */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: #1F2E4A; border-radius: 6px; }
::-webkit-scrollbar-track { background: transparent; }
</style>
"""


def _inject_css() -> None:
    """Inject the design-system stylesheet once per run."""
    st.markdown(_CSS, unsafe_allow_html=True)


# ==========================================================================
# Presentation primitives (reusable components)
# ==========================================================================
def _esc(value: Any) -> str:
    """HTML-escape any value for safe interpolation."""
    return html.escape("" if value is None else str(value))


def _fmt(value: Any, nd: int = 1) -> str:
    """Format a numeric value; pass through safe escaped text otherwise."""
    if value is None:
        return '<span class="sat-dim">—</span>'
    try:
        return f"{float(value):.{nd}f}"
    except (TypeError, ValueError):
        return _esc(value)


def _chip(text: str, tone: str = "muted", dot: bool = False) -> str:
    dot_html = '<span class="sat-dot"></span>' if dot else ""
    return f'<span class="sat-chip sat-{tone}">{dot_html}{_esc(text)}</span>'


def _badge(text: str, tone: str = "muted") -> str:
    return f'<span class="sat-badge sat-{tone}">{_esc(text)}</span>'


def _meter(value: float, max_value: float = 100.0, tone: str = "accent", nd: int = 1) -> str:
    """Inline progress meter (bar + value) for table numeric cells."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0.0
    pct = 0.0 if max_value <= 0 else max(0.0, min(1.0, v / max_value)) * 100.0
    return (
        '<span class="sat-meter">'
        f'<span class="sat-bar"><span class="sat-bar-fill sat-{tone}" style="width:{pct:.1f}%"></span></span>'
        f'<span class="sat-bar-val">{v:.{nd}f}</span>'
        "</span>"
    )


def ui_header(title: str, subtitle: str = "", kicker: str = "") -> None:
    """Page header: optional kicker, a real st.title, and a subtitle rule."""
    if kicker:
        st.markdown(f'<div class="sat-kicker">{_esc(kicker)}</div>', unsafe_allow_html=True)
    st.title(title)
    sub = _esc(subtitle) if subtitle else ""
    st.markdown(f'<div class="sat-subtitle">{sub}</div>', unsafe_allow_html=True)


def ui_kpis(items: List[Dict[str, Any]]) -> None:
    """Render a row of metric tiles from {label, value, delta?} dicts."""
    if not items:
        return
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        col.metric(item["label"], item["value"], item.get("delta"), delta_color="off")


def ui_table(
    columns: List[str],
    rows: List[List[str]],
    numeric: Optional[List[int]] = None,
    max_height: Optional[int] = None,
) -> None:
    """Render an HTML table with sticky headers. Cells must be HTML-ready strings."""
    numeric = numeric or []
    scroll_cls = "sat-table-scroll" if max_height else ""
    style = f' style="max-height:{max_height}px"' if max_height else ""
    head = "".join(
        f'<th class="{"num" if i in numeric else ""}">{_esc(c)}</th>' for i, c in enumerate(columns)
    )
    body = "".join(
        "<tr>" + "".join(
            f'<td class="{"num" if i in numeric else ""}">{cell}</td>' for i, cell in enumerate(row)
        ) + "</tr>"
        for row in rows
    )
    st.markdown(
        '<div class="sat-table-wrap">'
        f'<div class="{scroll_cls}"{style}>'
        f'<table class="sat-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'
        "</div></div>",
        unsafe_allow_html=True,
    )


def ui_panel_open(title: str = "") -> None:
    title_html = f'<div class="sat-panel-title">{_esc(title)}</div>' if title else ""
    st.markdown(f'<div class="sat-panel">{title_html}', unsafe_allow_html=True)


def ui_panel_close(note: str = "") -> None:
    note_html = f'<div class="sat-note">{_esc(note)}</div>' if note else ""
    st.markdown(f"{note_html}</div>", unsafe_allow_html=True)


def ui_empty(title: str, message: str = "") -> None:
    st.markdown(
        f'<div class="sat-empty"><div class="sat-empty-title">{_esc(title)}</div>{_esc(message)}</div>',
        unsafe_allow_html=True,
    )


def _style_fig(fig: "go.Figure", height: Optional[int] = None, margin: Optional[Dict[str, int]] = None) -> "go.Figure":
    """Apply the dark analytical chart theme."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#C7D3E6", size=12, family="Segoe UI, system-ui, sans-serif"),
        margin=margin or dict(l=10, r=10, t=24, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)),
        colorway=[TONE["accent"], TONE["critical"], TONE["low"], TONE["high"], TONE["novel"]],
    )
    if height:
        fig.update_layout(height=height)
    fig.update_xaxes(gridcolor="#1A2740", zerolinecolor="#22314D", linecolor="#22314D")
    fig.update_yaxes(gridcolor="#1A2740", zerolinecolor="#22314D", linecolor="#22314D")
    return fig


# ==========================================================================
# Offline data access helpers
# ==========================================================================
@st.cache_data(ttl=60)
def fetch_json_data(endpoint: str, fallback_file: str) -> Optional[Any]:
    """Fetch data from FastAPI if available, or fall back directly to offline data/output."""
    try:
        import requests
        resp = requests.get(f"{API_URL}{endpoint}", timeout=1.5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

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


def record_examiner_feedback(finding: Dict[str, Any], decision: str, examiner: str, comment: str) -> Dict[str, Any]:
    """Persist a confirm/dismiss decision to the local feedback database (offline)."""
    from satsa.feedback import record_feedback

    return record_feedback(
        finding_id=str(finding.get("finding_id", "")),
        entity_id=str(finding.get("entity_id", "")),
        detector_id=str(finding.get("detector_id", "")),
        decision=decision,
        examiner=(examiner or "dashboard").strip(),
        comment=comment.strip() or None,
    )


def current_weight(entity_id: str, detector_id: str) -> Optional[Dict[str, Any]]:
    """Live (entity, detector) feedback weight from the local SQLite store."""
    from satsa.feedback import list_weights

    for w in list_weights():
        if w["entity_id"] == entity_id and w["detector_id"] == detector_id:
            return w
    return None


def load_feedback_status() -> Dict[str, str]:
    """Map finding_id -> latest examiner decision, for the queue status column. First-wins."""
    status: Dict[str, str] = {}
    try:
        from satsa.feedback import get_history
        for row in get_history(limit=2000):
            fid = str(row.get("finding_id", ""))
            if fid and fid not in status:
                status[fid] = str(row.get("decision", "")).strip().lower()
    except Exception:
        pass
    return status


# ==========================================================================
# Global state: audit chain, run manifest, status strip
# ==========================================================================
_AUDIT_OK, _AUDIT_ERRORS = verify_audit_chain(PATHS.audit_log_file)


def _load_manifest() -> Dict[str, Any]:
    p = PATHS.run_manifest_file
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


_MANIFEST = _load_manifest()


def _manifest_meta() -> str:
    es = _MANIFEST.get("execution_summary", {}) if isinstance(_MANIFEST, dict) else {}
    if not es:
        return ""
    ts = str(_MANIFEST.get("timestamp", "")).replace("T", " ").split(".")[0]
    return (
        f"{es.get('entity_count', 0)} entities · {es.get('total_alerts', 0):,} alerts · "
        f"{es.get('finding_count', 0):,} findings · last analysis {ts} UTC"
    )


def ui_status_strip() -> None:
    audit_chip = _chip("Audit sealed" if _AUDIT_OK else "Audit tamper detected", "ok" if _AUDIT_OK else "bad", dot=True)
    offline_chip = _chip("Offline · Air-Gapped", "info", dot=True)
    st.markdown(
        f'<div class="sat-strip">{audit_chip}{offline_chip}'
        f'<span class="sat-meta">{_esc(_manifest_meta())}</span></div>',
        unsafe_allow_html=True,
    )


# ==========================================================================
# Sidebar: brand, authentication & RBAC, navigation
# ==========================================================================
_inject_css()

st.sidebar.markdown(
    '<div class="sat-brand">'
    '<div class="sat-brand-mark">SATIN</div>'
    '<div class="sat-brand-sub">Supervisory Analytics for SOC Assessment</div>'
    '<span class="sat-brand-tag">Air-gap · Offline</span>'
    "</div>",
    unsafe_allow_html=True,
)

if "auth_bootstrapped" not in st.session_state:
    try:
        bootstrap_auth()
        st.session_state["auth_bootstrapped"] = True
    except Exception as e:  # pragma: no cover - defensive
        st.sidebar.error(f"Authentication vault initialization failed: {e}")
        st.stop()

if st.session_state.get("auth_user") is None:
    st.sidebar.markdown("**Sign in to SATIN**")
    with st.sidebar.form("satsa_login", clear_on_submit=False):
        login_user = st.text_input("Username", autocomplete="username")
        login_pass = st.text_input("Password", type="password", autocomplete="current-password")
        login_ok = st.form_submit_button("Sign In", width="stretch")
    if login_ok:
        auth_result = authenticate_user(login_user, login_pass)
        if auth_result:
            st.session_state["auth_user"] = auth_result
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials.")
    st.sidebar.caption("Default roles: administrator / supervisor / auditor (see README)")
else:
    _u = st.session_state["auth_user"]
    st.sidebar.markdown(_chip(f"{_u['username']} · {_u['role'].upper()}", "info", dot=True), unsafe_allow_html=True)
    if st.sidebar.button("Sign out", width="stretch"):
        st.session_state["auth_user"] = None
        st.rerun()

st.sidebar.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
st.sidebar.markdown('<div class="sat-panel-title">Supervisory Workflow</div>', unsafe_allow_html=True)

PAGE_PORTFOLIO = "Portfolio Overview"
PAGE_ENTITY = "Entity Detail & Capability Radar"
PAGE_FINDING = "Finding Card & Evidence Drill-Down"
PAGE_QUEUE = "Examiner Review Queue (85/15)"
PAGE_CLAIM = "Claim-vs-Reality Index"
PAGE_HEATMAP = "Asset Telemetry Coverage Heatmap"
PAGE_AUDIT = "Cryptographic Audit & Validation"

page = st.sidebar.radio(
    "Supervisory Workflow",
    [PAGE_PORTFOLIO, PAGE_ENTITY, PAGE_FINDING, PAGE_QUEUE, PAGE_CLAIM, PAGE_HEATMAP, PAGE_AUDIT],
    index=0,
    label_visibility="collapsed",
)

st.sidebar.caption("SATIN v1.0.0 · Offline Analytical Engine")


# ==========================================================================
# Load base data
# ==========================================================================
scores_data = fetch_json_data("/trends", "entity_scores.json")
findings_data = get_all_findings_data()
queues_data = get_all_queues_data()

# Normalize scores data if fetched from /trends
if isinstance(scores_data, dict) and "area_averages" in scores_data:
    local_scores = PATHS.output_dir / "entity_scores.json"
    if local_scores.exists():
        with open(local_scores, "r", encoding="utf-8") as f:
            scores_data = json.load(f)
    else:
        scores_data = {}

if not scores_data:
    ui_status_strip()
    ui_empty("No supervisory data found", "Run the offline pipeline to populate data/output/, then reload this page.")
    if has_permission(st.session_state.get("auth_user"), "run_pipeline"):
        if st.button("Run Offline Supervisory Pipeline"):
            from satsa.pipeline import run_all
            with st.spinner("Executing end-to-end supervisory assessment pipeline..."):
                run_all(data_dir=PATHS.synthetic_dir, output_dir=PATHS.output_dir)
                st.rerun()
    else:
        st.caption("Pipeline execution requires the administrator role.")
    st.stop()


def _area_detail(entity_id: str, area: str) -> Dict[str, Any]:
    """Look up a capability-area detail block for an entity."""
    for d in scores_data.get(entity_id, {}).get("area_details", []):
        if d.get("area") == area:
            return d
    return {}


def _top_concern(entity_id: str) -> str:
    """Short human label for an entity's dominant detector."""
    details = scores_data.get(entity_id, {}).get("area_details", [])
    ranked = sorted(details, key=lambda d: (d.get("finding_count", 0), d.get("score", 0.0)), reverse=True)
    for d in ranked:
        for det in d.get("top_detectors", []) or []:
            return DETECTOR_LABELS.get(det, det)
    return "No material concern"


ui_status_strip()


# ==========================================================================
# Shared analytical / presentation helpers
# ==========================================================================
def _severity_tone(weight: Any) -> str:
    """Map a finding severity weight to a semantic tone."""
    try:
        w = float(weight or 0)
    except (TypeError, ValueError):
        w = 0.0
    if w >= 5.0:
        return "critical"
    if w >= 4.0:
        return "high"
    if w >= 3.0:
        return "elevated"
    return "moderate"


def _pct(value: Any, nd: int = 1) -> str:
    try:
        return f"{float(value) * 100:.{nd}f}%"
    except (TypeError, ValueError):
        return '<span class="sat-dim">—</span>'


def _lineage_html(finding: Dict[str, Any]) -> str:
    """Render the Finding -> Metric -> Evidence lineage for one finding."""
    det = finding.get("detector_id", "")
    refs = finding.get("evidence_refs", []) or []
    if refs:
        ev = ", ".join(str(r) for r in refs[:3]) + (" …" if len(refs) > 3 else "")
    else:
        ev = "entity/aggregate scope (no single record)"
    bits = []
    if finding.get("deviation") is not None:
        bits.append(f"deviation {float(finding.get('deviation') or 0):+.2f}")
    if finding.get("peer_percentile") is not None:
        bits.append(f"peer p{float(finding.get('peer_percentile') or 0) * 100:.0f}")
    metric = " · ".join(bits) or "aggregate metric"
    return (
        '<div class="sat-flow">'
        f'<span class="sat-step"><span class="sat-step-k">Finding</span>{_esc(det)} · '
        f'{_esc(DETECTOR_LABELS.get(det, ""))}</span>'
        '<span class="sat-arrow">→</span>'
        f'<span class="sat-step"><span class="sat-step-k">Metric</span>{_esc(metric)}</span>'
        '<span class="sat-arrow">→</span>'
        f'<span class="sat-step"><span class="sat-step-k">Evidence</span>{_esc(ev)}</span>'
        "</div>"
    )


def _priority_findings(findings: List[Dict[str, Any]], n: int = 12) -> List[Dict[str, Any]]:
    """Top-N findings by severity, round-robin diversified across entities."""
    ordered = sorted(
        findings,
        key=lambda x: (float(x.get("severity_weight") or 0), float(x.get("peer_percentile") or 0)),
        reverse=True,
    )
    by_entity: Dict[str, List[Dict[str, Any]]] = {}
    for f in ordered:
        by_entity.setdefault(f.get("entity_id", "—"), []).append(f)
    buckets = list(by_entity.values())
    out: List[Dict[str, Any]] = []
    while len(out) < n and buckets:
        for q in buckets:
            if q:
                out.append(q.pop(0))
                if len(out) >= n:
                    break
        buckets = [q for q in buckets if q]
    return out


def _ranking() -> List[Dict[str, Any]]:
    """Entities ranked by supervisory risk index (descending)."""
    return sorted(
        (dict(s, entity_id=eid) for eid, s in scores_data.items()),
        key=lambda s: s.get("overall_risk_index", 0.0),
        reverse=True,
    )


# ==========================================================================
# PAGE 1: Portfolio Supervisory Overview
# ==========================================================================
if page == PAGE_PORTFOLIO:
    from collections import Counter

    ui_header(
        "Portfolio Supervisory Overview",
        "Comparative peer evaluation across Critical Sector Entities (CSEs).",
        kicker="Executive Summary",
    )

    entities_count = len(scores_data)
    attention = [e for e, s in scores_data.items() if s.get("risk_tier") in ("high", "critical")]
    high_priority = sum(1 for f in findings_data if float(f.get("peer_percentile") or 0) >= 0.90)
    critical_findings = sum(1 for f in findings_data if float(f.get("severity_weight") or 0) >= 5.0)

    ui_kpis([
        {"label": "Entities Assessed", "value": f"{entities_count}", "delta": "full portfolio"},
        {"label": "Entities Requiring Attention", "value": f"{len(attention)}", "delta": "high / critical tier"},
        {"label": "High-Priority Findings", "value": f"{high_priority:,}", "delta": "≥ 90th peer percentile"},
        {"label": "Critical Findings", "value": f"{critical_findings:,}", "delta": "critical severity weight"},
    ])

    # ---- Executive summary narrative (derived from artefacts, never hardcoded) ----
    ranking = _ranking()
    top_entity = ranking[0] if ranking else {}
    det_counter = Counter(f.get("detector_id") for f in findings_data)
    top_det = det_counter.most_common(1)[0][0] if det_counter else "—"
    dominant = DETECTOR_LABELS.get(top_det, top_det)
    concept_counts = pd.Series([f.get("category", "") for f in findings_data]).value_counts().to_dict()
    eg_n = int(concept_counts.get("EXECUTION_GAP", 0))
    ns_n = int(concept_counts.get("NEGATIVE_SPACE", 0))
    nov_n = int(concept_counts.get("NOVEL", 0))

    if top_entity:
        lead = (
            f"{entities_count} entities were assessed against peer cohorts. "
            f"<b>{len(attention)}</b> require supervisory attention (high or critical risk tier). "
            f"<b>{high_priority:,}</b> findings sit at or above the 90th peer percentile and "
            f"<b>{critical_findings:,}</b> carry critical severity weight. "
            f"The dominant portfolio concern is <b>{_esc(dominant)}</b>. "
            f"Investigate <b>{_esc(top_entity.get('entity_id'))}</b> first "
            f"(risk index {top_entity.get('overall_risk_index', 0):.1f}, tier "
            f"{str(top_entity.get('risk_tier', '')).upper()})."
        )
    else:
        lead = "No analytical results are available to summarise."

    st.markdown(
        '<div class="sat-panel"><div class="sat-panel-title">Executive Summary</div>'
        f'<div class="sat-why">{lead}</div>'
        '<div class="sat-strip" style="margin-top:12px;margin-bottom:0">'
        + _chip(f"Execution gap {eg_n:,}", "critical", dot=True)
        + _chip(f"Negative space {ns_n:,}", "elevated", dot=True)
        + _chip(f"Novel {nov_n:,}", "novel", dot=True)
        + "</div></div>",
        unsafe_allow_html=True,
    )

    # ---- Supervisory priority table ----
    st.markdown('<div class="sat-panel-title">Supervisory Priority — Ranked Entities</div>', unsafe_allow_html=True)
    rows = []
    for i, s in enumerate(ranking, start=1):
        tier = str(s.get("risk_tier", "low"))
        idx = float(s.get("overall_risk_index", 0.0))
        rows.append([
            _esc(i),
            f'<span class="sat-strong">{_esc(s.get("entity_id"))}</span>',
            _meter(idx, 100.0, tier),
            _badge(tier.upper(), tier),
            _pct(s.get("peer_percentile", 0.0)),
            _esc(str(s.get("qoq_trend", "stable")).capitalize()),
            _badge(TIER_PRIORITY.get(tier, "—"), tier),
            f'{int(s.get("findings_count", 0)):,}',
            _esc(_top_concern(s.get("entity_id", ""))),
        ])
    ui_table(
        ["Rank", "Entity", "Risk Index", "Risk Tier", "Peer %ile", "QoQ", "Priority", "Findings", "Primary Concern"],
        rows,
        numeric=[0, 2, 4, 7],
    )

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # ---- Key signals: concept lanes + risk tier distribution ----
    sig_left, sig_right = st.columns([3, 2])
    with sig_left:
        st.markdown('<div class="sat-panel-title">Findings by Concept Lane</div>', unsafe_allow_html=True)
        concept_df = pd.DataFrame(
            [{"Concept": k.replace("_", " ").title(), "Count": v, "Raw": k} for k, v in concept_counts.items()]
        ).sort_values("Count", ascending=True)
        fig_concept = go.Figure(go.Bar(
            x=concept_df["Count"], y=concept_df["Concept"], orientation="h",
            marker_color=[CONCEPT_COLORS.get(r, TONE["accent"]) for r in concept_df["Raw"]],
            text=[f"{int(v):,}" for v in concept_df["Count"]], textposition="outside",
        ))
        _style_fig(fig_concept, height=240)
        st.plotly_chart(fig_concept, width="stretch")

    with sig_right:
        st.markdown('<div class="sat-panel-title">Risk Tier Distribution</div>', unsafe_allow_html=True)
        tier_counts = pd.Series([str(s.get("risk_tier", "low")) for s in scores_data.values()]).value_counts()
        tier_total = max(1, int(tier_counts.sum()))
        tier_rows = []
        for tier in TIER_ORDER:
            n = int(tier_counts.get(tier, 0))
            tier_rows.append([
                _badge(tier.upper(), tier),
                _meter(n, max(1, int(tier_counts.max())), tier, nd=0),
                f"{n / tier_total * 100:.0f}%",
            ])
        ui_table(["Tier", "Entities", "Share"], tier_rows, numeric=[1, 2])

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # ---- Peer comparison: portfolio capability profile ----
    st.markdown('<div class="sat-panel-title">Portfolio Capability Profile (mean per area, weakest first)</div>', unsafe_allow_html=True)
    area_vals: Dict[str, List[float]] = {a: [] for a in CAPABILITIES.areas}
    for s in scores_data.values():
        for a, val in s.get("area_scores", {}).items():
            if a in area_vals:
                area_vals[a].append(float(val))
    avg_areas = {a: (float(np.mean(v)) if v else 0.0) for a, v in area_vals.items()}
    prof = sorted(CAPABILITIES.areas, key=lambda a: avg_areas[a])
    prof_labels = [a.replace("_", " ").title() for a in prof]
    fig_prof = go.Figure(go.Bar(
        x=[avg_areas[a] for a in prof], y=prof_labels, orientation="h",
        marker_color=[TONE["critical"] if avg_areas[a] >= 60 else TONE["accent"] for a in prof],
        text=[f"{avg_areas[a]:.0f}" for a in prof], textposition="outside",
    ))
    _style_fig(fig_prof, height=300)
    st.plotly_chart(fig_prof, width="stretch")

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # ---- Priority findings ----
    st.markdown('<div class="sat-panel-title">Priority Findings — Investigate First</div>', unsafe_allow_html=True)
    pf = _priority_findings(findings_data, 12)
    if pf:
        pf_rows = []
        for f in pf:
            cat = f.get("category", "")
            tone = CONCEPT_TONE.get(cat, "muted")
            sw = f.get("severity_weight", 0)
            pf_rows.append([
                f'<span class="sat-strong">{_esc(f.get("finding_id"))}</span>',
                _esc(f.get("entity_id")),
                _badge(cat.replace("_", " "), tone),
                _esc(f.get("detector_id")),
                _badge(str(sw), _severity_tone(sw)),
                _pct(f.get("peer_percentile", 0.0)),
                _esc(str(f.get("reason_text", ""))[:150]),
            ])
        ui_table(
            ["Finding", "Entity", "Concept", "Detector", "Severity", "Peer %ile", "Reason"],
            pf_rows,
            numeric=[5],
        )
    else:
        ui_empty("No priority findings", "The current run produced no findings to prioritise.")

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # ---- Report export ----
    with st.expander("Supervisory Assessment Report Export", expanded=False):
        st.caption(
            "Renders the audited artefacts (scores, findings, queue, claim-vs-reality, manifest) "
            "into a publication-grade report. PDF uses WeasyPrint when installed, otherwise a stdlib renderer."
        )
        if st.button("Build Report Package (HTML + PDF + CSV)"):
            from satsa.report import build_report, collect_report_data
            import io
            import csv
            with st.spinner("Rendering supervisory report..."):
                st.session_state["report_pkg"] = build_report()
                try:
                    data = collect_report_data()
                    # export CSV summary
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(["metric", "value"])
                    w.writerow(["run_id", data.get("run_id")])
                    w.writerow(["generated_at", data.get("generated_at")])
                    w.writerow(["entity_count", data.get("entity_count")])
                    w.writerow(["total_findings", data.get("total_findings")])
                    w.writerow(["total_alerts", data.get("total_alerts")])
                    w.writerow(["high_risk_count", data.get("high_risk_count")])
                    w.writerow(["queue_total", data.get("queue_total")])
                    for e in data.get("entities", [])[:25]:
                        w.writerow([f"entity::{e.get('entity_id')}", f"idx={e.get('risk_index'):.1f} tier={e.get('tier')} pct={e.get('percentile'):.1f}%"])
                    st.session_state["report_csv"] = buf.getvalue()
                except Exception as e:
                    st.session_state["report_csv"] = f"# error: {e}"
        pkg = st.session_state.get("report_pkg")
        csv_txt = st.session_state.get("report_csv")
        if pkg:
            cols = st.columns([1, 1, 1, 2]) if csv_txt else st.columns([1, 1, 2])
            cols[0].download_button(
                label="Download PDF Report",
                data=pkg["pdf"],
                file_name="SATIN_Supervisory_Report.pdf",
                mime="application/pdf",
            )
            cols[1].download_button(
                label="Download HTML Report",
                data=pkg["html"],
                file_name="SATIN_Supervisory_Report.html",
                mime="text/html",
            )
            if csv_txt:
                cols[2].download_button(
                    label="Download CSV Summary",
                    data=csv_txt,
                    file_name="SATIN_Supervisory_Report_Summary.csv",
                    mime="text/csv",
                )
            (cols[-1] if len(cols) > 1 else cols[0]).caption(
                f"PDF engine: {pkg['pdf_engine']} · run {pkg['data'].get('run_id')} · "
                f"audit {'INTACT' if pkg['data'].get('audit_valid') else 'TAMPERED'}"
            )


# ==========================================================================
# PAGE 2: Entity Workspace & Capability Profile
# ==========================================================================
elif page == PAGE_ENTITY:
    ui_header(
        "Entity Workspace",
        "Detailed supervisory assessment, capability profile, and evidence lineage.",
        kicker="Examiner Workspace",
    )

    ranked_eids = [s["entity_id"] for s in _ranking()]
    selected_eid = st.selectbox("Select Critical Sector Entity (CSE)", ranked_eids, index=0)

    e_score = scores_data[selected_eid]
    overall_idx = float(e_score.get("overall_risk_index", 0.0))
    tier = str(e_score.get("risk_tier", "low"))
    pct = float(e_score.get("peer_percentile", 0.5))
    trend = str(e_score.get("qoq_trend", "stable")).capitalize()
    e_findings = [f for f in findings_data if f.get("entity_id") == selected_eid]

    # Overview header + KPIs
    st.markdown(
        f'<div class="sat-strip">{_badge(tier.upper(), tier)}'
        + _chip(f"{len(e_findings):,} active findings", "muted")
        + _chip(TIER_PRIORITY.get(tier, "—"), tier)
        + "</div>",
        unsafe_allow_html=True,
    )
    ui_kpis([
        {"label": "Supervisory Risk Index", "value": f"{overall_idx:.1f}", "delta": "out of 100"},
        {"label": "Cohort Peer Percentile", "value": f"{pct * 100:.1f}%", "delta": "relative to peers"},
        {"label": "Quarter-over-Quarter Trend", "value": trend, "delta": "posture trajectory"},
        {"label": "Active Findings", "value": f"{len(e_findings):,}", "delta": "requiring attention"},
    ])

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # Capability profile vs cohort median
    area_scores = e_score.get("area_scores", {})
    entity_vals = [float(area_scores.get(a, 0.0)) for a in CAPABILITIES.areas]
    cohort_vals = []
    for a in CAPABILITIES.areas:
        vals = [float(s.get("area_scores", {}).get(a, 0.0)) for s in scores_data.values()]
        cohort_vals.append(float(np.median(vals)) if vals else 0.0)
    area_labels = [a.replace("_", " ").title() for a in CAPABILITIES.areas]

    prof_left, prof_right = st.columns([1, 1])
    with prof_left:
        st.markdown('<div class="sat-panel-title">Capability Profile vs Cohort Median</div>', unsafe_allow_html=True)
        fig_e_radar = go.Figure()
        fig_e_radar.add_trace(go.Scatterpolar(
            r=entity_vals + [entity_vals[0]],
            theta=area_labels + [area_labels[0]],
            fill="toself",
            name=selected_eid,
            line=dict(color=TONE["critical"], width=2),
            fillcolor="rgba(217,106,106,0.20)",
        ))
        fig_e_radar.add_trace(go.Scatterpolar(
            r=cohort_vals + [cohort_vals[0]],
            theta=area_labels + [area_labels[0]],
            fill="toself",
            name="Cohort median",
            line=dict(color="#7A8CA8", width=2, dash="dash"),
            fillcolor="rgba(122,140,168,0.10)",
        ))
        fig_e_radar.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 100], gridcolor="#1A2740", linecolor="#22314D"),
                angularaxis=dict(gridcolor="#1A2740", linecolor="#22314D"),
            ),
            margin=dict(l=30, r=30, t=20, b=20),
            height=380,
            legend=dict(orientation="h", yanchor="bottom", y=-0.18, xanchor="center", x=0.5),
        )
        _style_fig(fig_e_radar)
        st.plotly_chart(fig_e_radar, width="stretch")

    with prof_right:
        st.markdown('<div class="sat-panel-title">Capability Area Sub-Scores</div>', unsafe_allow_html=True)
        area_rows = []
        for i, a in enumerate(sorted(CAPABILITIES.areas, key=lambda x: area_scores.get(x, 0.0), reverse=True)):
            score = float(area_scores.get(a, 0.0))
            cohort = cohort_vals[CAPABILITIES.areas.index(a)]
            delta = score - cohort
            tone = "critical" if delta < -15 else ("high" if delta < -5 else "low")
            area_rows.append([
                _esc(a.replace("_", " ").title()),
                _meter(score, 100.0, tone),
                _fmt(cohort),
                _badge(f"{delta:+.1f}", tone),
            ])
        ui_table(["Capability Area", "Score", "Peer Median", "Delta"], area_rows, numeric=[1, 2, 3])

    st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)

    # Why this was flagged — evidence lineage
    st.markdown('<div class="sat-panel-title">Why This Entity Was Flagged — Finding → Metric → Evidence</div>', unsafe_allow_html=True)
    if e_findings:
        top_findings = sorted(
            e_findings,
            key=lambda x: (float(x.get("severity_weight") or 0), float(x.get("peer_percentile") or 0)),
            reverse=True,
        )[:6]
        for f in top_findings:
            cat = f.get("category", "")
            tone = CONCEPT_TONE.get(cat, "accent")
            st.markdown(
                f'<div class="sat-finding" style="--t:{CONCEPT_COLORS.get(cat, TONE["accent"])}">'
                '<div class="sat-finding-top">'
                f'<h3>{_esc(f.get("detector_id"))} · {_esc(f.get("scope"))}</h3>'
                + _badge(cat.replace("_", " "), tone)
                + "</div>"
                f'<p>{_esc(f.get("reason_text", ""))}</p>'
                + _lineage_html(f)
                + "</div>",
                unsafe_allow_html=True,
            )
    else:
        ui_empty("No anomalous findings", f"{selected_eid} is a clean control entity for the current period.")

    # Full findings table
    st.markdown('<div class="sat-panel-title">All Supervisory Findings</div>', unsafe_allow_html=True)
    if e_findings:
        f_rows = []
        for f in sorted(e_findings, key=lambda x: float(x.get("severity_weight") or 0), reverse=True):
            sw = f.get("severity_weight", 0)
            cat = f.get("category", "")
            f_rows.append([
                f'<span class="sat-strong">{_esc(f.get("finding_id"))}</span>',
                _esc(f.get("detector_id")),
                _badge(cat.replace("_", " "), CONCEPT_TONE.get(cat, "muted")),
                _esc(f.get("scope")),
                _badge(str(sw), _severity_tone(sw)),
                _pct(f.get("peer_percentile", 0.0)),
                _fmt(f.get("deviation"), 2),
                _esc(str(f.get("reason_text", ""))[:120]),
            ])
        ui_table(
            ["Finding", "Detector", "Concept", "Scope", "Severity", "Peer %ile", "Deviation", "Reason"],
            f_rows, numeric=[5, 6],
        )
        st.caption("Open the Finding Card page to inspect, trace evidence, and record examiner feedback for a specific finding.")
    else:
        ui_empty("No findings", "This entity has no recorded supervisory findings for the current period.")


# ==========================================================================
# PAGE 3: Finding Card & Evidence Drill-Down (investigation view)
# ==========================================================================
elif page == PAGE_FINDING:
    ui_header(
        "Finding Investigation",
        "Explainable evidence drill-down, detector parameters, and cohort deviation.",
        kicker="Investigation",
    )

    if not findings_data:
        ui_empty("No findings available", "Run the offline pipeline to generate findings.json.")
        st.stop()

    finding_options = [
        f"{f.get('finding_id')} | {f.get('detector_id')} ({f.get('category')}) | {f.get('entity_id')} - {f.get('scope')}"
        for f in findings_data[:300]
    ]
    selected_option = st.selectbox("Select Finding to Inspect", finding_options, index=0)
    selected_fid = selected_option.split(" | ")[0]
    finding = next((f for f in findings_data if f.get("finding_id") == selected_fid), findings_data[0])

    cat = finding.get("category", "")
    tone = CONCEPT_TONE.get(cat, "accent")
    accent = CONCEPT_COLORS.get(cat, TONE["accent"])

    st.markdown(
        f'<div class="sat-finding" style="--t:{accent}">'
        '<div class="sat-finding-top">'
        f'<h3>{_esc(finding.get("detector_id"))} — {_esc(finding.get("scope"))}</h3>'
        + _badge(cat.replace("_", " "), tone)
        + "</div>"
        f'<p>{_esc(finding.get("reason_text", ""))}</p>'
        "</div>",
        unsafe_allow_html=True,
    )

    ui_kpis([
        {"label": "Entity ID", "value": f'{finding.get("entity_id", "")}'},
        {"label": "Severity Weight", "value": f'{float(finding.get("severity_weight") or 1.0):.1f}×'},
        {"label": "Cohort Deviation", "value": f'{float(finding.get("deviation") or 0.0):+.2f}'},
        {"label": "Confidence", "value": f'{float(finding.get("confidence") or 0.9) * 100:.0f}%'},
    ])

    st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sat-panel-title">Why This Was Flagged — Finding → Metric → Evidence</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sat-panel"><div class="sat-why">'
        + _esc(finding.get("reason_text", ""))
        + "</div>" + _lineage_html(finding) + "</div>",
        unsafe_allow_html=True,
    )

    # ---- Examiner Feedback (confirm / dismiss -> versioned re-weight) ----
    st.subheader("Examiner Feedback")
    weight = current_weight(str(finding.get("entity_id", "")), str(finding.get("detector_id", "")))
    if weight:
        st.markdown(
            f"**Current weight factor:** `{weight['factor']:.2f}` (version {weight['version']}) — "
            "applies to future scoring of this (entity, detector) pair."
        )
    else:
        st.caption("No feedback recorded yet for this (entity, detector) pair — factor is neutral (1.00).")

    if has_permission(st.session_state.get("auth_user"), "feedback"):
        fb_a, fb_b, _fb_pad = st.columns([1, 1, 2])
        examiner_name = fb_a.text_input(
            "Examiner", value=st.session_state.get("examiner_name", "examiner"), key="examiner_name"
        )
        fb_comment = fb_b.text_input("Comment (optional)", max_chars=200)

        btn_cols = st.columns([1, 1, 3])
        if btn_cols[0].button("Confirm Finding", key=f"fb_confirm_{finding.get('finding_id')}"):
            try:
                w = record_examiner_feedback(finding, "confirm", examiner_name, fb_comment)
                st.success(f"Confirmed. Weight factor now {w['factor']:.2f} (v{w['version']}). Run the pipeline to apply it to scores.")
            except Exception as e:
                st.error(f"Feedback not recorded: {e}")
        if btn_cols[1].button("Dismiss Finding", key=f"fb_dismiss_{finding.get('finding_id')}"):
            try:
                w = record_examiner_feedback(finding, "dismiss", examiner_name, fb_comment)
                st.warning(f"Dismissed. Weight factor now {w['factor']:.2f} (v{w['version']}). Run the pipeline to apply it to scores.")
            except Exception as e:
                st.error(f"Feedback not recorded: {e}")
    else:
        st.info("Please sign in with a supervisor or administrator account to record feedback for this finding.")

    st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)

    # ---- Evidence references & detector parameters ----
    ed_col1, ed_col2 = st.columns([1, 1])
    with ed_col1:
        st.markdown('<div class="sat-panel-title">Underlying Evidence References</div>', unsafe_allow_html=True)
        evidence_list = finding.get("evidence_refs", []) or []
        if evidence_list:
            ev_rows = [[_esc(r), _badge(str(r).split(":")[0], "muted"), _esc(str(r).split(":")[-1])] for r in evidence_list]
            ui_table(["Record Ref", "Table", "ID"], ev_rows, max_height=280)
        else:
            ui_empty("Aggregate scope", "This finding is computed at entity-aggregate or time-series scope (no single alert row).")

    with ed_col2:
        st.markdown('<div class="sat-panel-title">Detector Parameters & Thresholds</div>', unsafe_allow_html=True)
        params = finding.get("parameters", {}) or {}
        if params:
            param_rows = [[_esc(k), _esc(v)] for k, v in params.items()]
            ui_table(["Parameter", "Value"], param_rows, max_height=280)
        else:
            ui_panel_open()
            st.markdown('<div class="sat-why">Standard detector configuration applied.</div>', unsafe_allow_html=True)
            ui_panel_close()

    st.caption(
        f"Detector version {finding.get('detector_version', 'n/a')} · "
        f"category {cat} · feedback factor {float(finding.get('feedback_factor') or 1.0):.2f}"
    )


# ==========================================================================
# PAGE 4: Examiner Review Queue (85/15)
# ==========================================================================
elif page == PAGE_QUEUE:
    ui_header(
        "Examiner Review Queue",
        "Budget-constrained manual review: 85% diversified risk items + 15% random control baseline.",
        kicker="Review Queue",
    )

    q_eids = sorted(queues_data.keys())
    if not q_eids:
        ui_empty("No review queues loaded", "Run the offline pipeline to generate review_queue.json.")
        st.stop()

    sel_q_eid = st.selectbox("Select Critical Sector Entity Queue", q_eids, index=0)
    raw_queue = queues_data.get(sel_q_eid, [])

    budget = st.slider(
        "Examiner Review Budget",
        min_value=10,
        max_value=min(200, max(10, len(raw_queue))),
        value=min(50, max(10, len(raw_queue))),
        step=5,
    )
    queue = raw_queue[:budget]

    risk_count = sum(1 for q in queue if q.get("selection_bucket") == "risk_ranked")
    ctrl_count = sum(1 for q in queue if q.get("selection_bucket") == "random_control")

    ui_kpis([
        {"label": "Review Budget", "value": f"{len(queue):,}", "delta": "items selected"},
        {"label": "Risk-Ranked (85%)", "value": f"{risk_count:,}", "delta": f"{(risk_count / max(1, len(queue))) * 100:.1f}%"},
        {"label": "Random Control (15%)", "value": f"{ctrl_count:,}", "delta": f"{(ctrl_count / max(1, len(queue))) * 100:.1f}%"},
    ])

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    feedback_status = load_feedback_status()
    status_map = {"confirm": ("Confirmed", "low"), "dismiss": ("Dismissed", "critical")}
    max_score = max([float(q.get("priority_score") or 0) for q in queue] + [1.0])

    q_rows = []
    for item in queue:
        bucket = item.get("selection_bucket")
        is_risk = bucket == "risk_ranked"
        fid = str(item.get("finding_id", ""))
        status_label, status_tone = status_map.get(feedback_status.get(fid, ""), ("Awaiting review", "muted"))
        q_rows.append([
            _esc(item.get("priority_rank")),
            _badge("RISK" if is_risk else "CONTROL", "high" if is_risk else "elevated"),
            _esc(item.get("detector_id")),
            _esc(item.get("scope")),
            _meter(item.get("priority_score", 0), max_score, "high" if is_risk else "elevated", nd=2),
            _badge(status_label, status_tone),
            _esc(str(item.get("selection_reason", ""))[:120]),
            _esc(", ".join(item.get("evidence_refs", []) or [])[:90] or "—"),
        ])
    ui_table(
        ["Rank", "Bucket", "Detector", "Scope", "Priority", "Status", "Selection Reason", "Evidence"],
        q_rows, numeric=[0, 4],
    )

    export_rows = [
        {
            "Rank": item.get("priority_rank"),
            "Bucket": item.get("selection_bucket"),
            "Finding ID": item.get("finding_id"),
            "Detector": item.get("detector_id"),
            "Scope": item.get("scope"),
            "Priority Score": item.get("priority_score"),
            "Status": status_map.get(feedback_status.get(str(item.get("finding_id", "")), ""), ("Awaiting review", ""))[0],
            "Selection Reason": item.get("selection_reason"),
            "Evidence Refs": ", ".join(item.get("evidence_refs", []) or []),
        }
        for item in queue
    ]
    df_queue = pd.DataFrame(export_rows)
    csv_bytes = df_queue.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Export Examiner Review Queue to CSV",
        data=csv_bytes,
        file_name=f"SATIN_Review_Queue_{sel_q_eid}.csv",
        mime="text/csv",
    )


# ==========================================================================
# PAGE 5: Claim-vs-Reality Index
# ==========================================================================
elif page == PAGE_CLAIM:
    ui_header(
        "Claim-vs-Reality Index",
        "Self-reported entity KPIs (close time, coverage, false-positive rate, escalation) against audited evidence.",
        kicker="Assurance",
    )

    claims_data = fetch_json_data("/claim-reality", "claim_reality.json")
    if not isinstance(claims_data, dict) or not claims_data.get("entities"):
        ui_empty("No claim data available", "Run the pipeline to generate claim_reality.json.")
        st.stop()

    claim_summary = claims_data.get("summary", {}) or {}
    exag_list = claim_summary.get("materially_exaggerated", []) or []
    mean_index = claim_summary.get("mean_index")
    ui_kpis([
        {"label": "Entities With Claims", "value": claim_summary.get("entities_with_claims", 0)},
        {"label": "Mean Claim Index", "value": f"{mean_index}" if mean_index is not None else "n/a"},
        {"label": "Substantiated", "value": claim_summary.get("substantiated", 0)},
        {"label": "Materially Exaggerated", "value": len(exag_list)},
    ])

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    claim_rows = [
        {
            "Entity": c.get("entity_id"),
            "Index": float(c.get("index", 0.0)),
            "Verdict": str(c.get("verdict", "")).replace("_", " ").title(),
            "Raw": str(c.get("verdict", "")),
        }
        for c in claims_data["entities"].values()
    ]
    df_claims = pd.DataFrame(claim_rows).sort_values("Index")
    verdict_order = ["Substantiated", "Partially Substantiated", "Materially Exaggerated"]
    verdict_colors = {
        "Substantiated": TONE["low"],
        "Partially Substantiated": TONE["high"],
        "Materially Exaggerated": TONE["critical"],
    }
    fig_claims = px.bar(
        df_claims, x="Entity", y="Index", color="Verdict",
        color_discrete_map=verdict_colors,
        category_orders={"Verdict": verdict_order},
        range_y=[0, 100], text_auto=".0f",
    )
    fig_claims.add_hline(y=85, line_dash="dash", line_color="#6F82A0",
                         annotation_text="Substantiated (85)", annotation_position="top left")
    fig_claims.add_hline(y=60, line_dash="dash", line_color="#6F82A0",
                         annotation_text="Exaggeration (60)", annotation_position="bottom left")
    fig_claims.update_layout(showlegend=True, legend=dict(orientation="h", y=1.12, x=0))
    _style_fig(fig_claims, height=420, margin=dict(l=10, r=10, t=40, b=10))
    st.plotly_chart(fig_claims, width="stretch")

    st.markdown('<div class="sat-panel-title">Claim Credibility by Entity</div>', unsafe_allow_html=True)
    cred_rows = []
    for c in sorted(claims_data["entities"].values(), key=lambda x: float(x.get("index", 0.0))):
        verdict = str(c.get("verdict", ""))
        cred_rows.append([
            f'<span class="sat-strong">{_esc(c.get("entity_id"))}</span>',
            _meter(c.get("index", 0.0), 100.0, VERDICT_TONE.get(verdict, "muted")),
            _badge(verdict.replace("_", " ").upper(), VERDICT_TONE.get(verdict, "muted")),
            _esc(c.get("n_claimed", 0)),
            _esc(c.get("exaggerated_count", 0)),
        ])
    ui_table(["Entity", "Claim Index", "Verdict", "Metrics Claimed", "Exaggerated"], cred_rows, numeric=[1, 3, 4])

    st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)

    st.markdown('<div class="sat-panel-title">Claim Breakdown by Entity</div>', unsafe_allow_html=True)
    claim_eids = sorted(claims_data["entities"].keys(), key=lambda e: claims_data["entities"][e].get("index", 0.0))
    sel_claim_eid = st.selectbox("Select Entity", claim_eids, index=0)
    sel_claim = claims_data["entities"][sel_claim_eid]
    verdict = str(sel_claim.get("verdict", ""))
    st.markdown(
        f'<div class="sat-strip"><span class="sat-strong">{_esc(sel_claim_eid)}</span>'
        + _badge(verdict.replace("_", " "), VERDICT_TONE.get(verdict, "muted"))
        + _chip(f"Claim index {sel_claim.get('index')}", "muted")
        + "</div>",
        unsafe_allow_html=True,
    )
    comps = sel_claim.get("comparisons", []) or []
    if comps:
        comp_rows = []
        for c in comps:
            exag = 100.0 * float(c.get("exaggeration", 0.0))
            comp_rows.append([
                _esc(c.get("metric_label")),
                _esc(f"{c.get('claimed')} {c.get('unit')}"),
                _esc(f"{c.get('observed')} {c.get('unit')}"),
                _badge(f"{exag:+.1f}%", "critical" if exag > 5 else ("high" if exag < -5 else "low")),
                _meter(float(c.get("credibility", 0.0)) * 100.0, 100.0, "low"),
                _esc(c.get("evidence_source")),
            ])
        ui_table(
            ["Metric", "Claimed", "Observed (Evidence)", "Exaggeration", "Credibility", "Evidence Source"],
            comp_rows, numeric=[3, 4],
        )
    else:
        ui_empty("No comparable claims", "This entity has no metrics that can be reconciled against evidence.")


# ==========================================================================
# PAGE 6: Asset Telemetry Coverage Heatmap
# ==========================================================================
elif page == PAGE_HEATMAP:
    ui_header(
        "Asset Telemetry & Monitoring Coverage",
        "Verifies designated critical assets against active telemetry (NS-01 and NS-06).",
        kicker="Coverage",
    )

    assets_csv = PATHS.synthetic_dir / "assets.csv"
    alerts_csv = PATHS.synthetic_dir / "alerts.csv"

    if not (assets_csv.exists() and alerts_csv.exists()):
        ui_empty("Synthetic asset and alert tables not found", "Expected data/synthetic/assets.csv and alerts.csv.")
        st.stop()

    assets_df = pd.read_csv(assets_csv)
    alerts_df = pd.read_csv(alerts_csv)

    ent_list = sorted(assets_df["entity_id"].dropna().unique())
    heat_eid = st.selectbox("Select Entity to Inspect Coverage", ent_list, index=0)

    e_assets = assets_df[assets_df["entity_id"] == heat_eid].copy()
    e_alerts = alerts_df[alerts_df["entity_id"] == heat_eid]
    alert_counts = e_alerts.groupby("asset_id").size().to_dict()
    e_assets["alert_count"] = e_assets["asset_id"].map(alert_counts).fillna(0).astype(int)
    e_assets["status"] = "Normal Telemetry"
    e_assets.loc[e_assets["alert_count"] == 0, "status"] = "Silent Asset"
    e_assets.loc[~e_assets["monitoring_expected"].astype(bool), "status"] = "Unmonitored Deficit"

    total_a = len(e_assets)
    crit_a = int((e_assets["criticality"] == "critical").sum())
    silent_crit = int(((e_assets["criticality"] == "critical") & (e_assets["status"] == "Silent Asset")).sum())

    ui_kpis([
        {"label": "Assets in Scope", "value": f"{total_a:,}"},
        {"label": "Critical Assets", "value": f"{crit_a:,}"},
        {"label": "Silent Critical Assets (NS-01)", "value": f"{silent_crit:,}"},
    ])

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    status_order = ["Normal Telemetry", "Silent Asset", "Unmonitored Deficit"]
    pivot = e_assets.groupby(["criticality", "status"]).size().reset_index(name="count")
    fig_heat = px.bar(
        pivot, x="criticality", y="count", color="status", barmode="stack",
        color_discrete_map={s: TONE[ASSET_TONE[s]] for s in status_order},
        category_orders={"status": status_order},
        labels={"criticality": "Criticality", "count": "Assets", "status": "Telemetry status"},
    )
    _style_fig(fig_heat, height=360, margin=dict(l=10, r=10, t=36, b=10))
    fig_heat.update_layout(legend=dict(orientation="h", y=1.14, x=0))
    st.plotly_chart(fig_heat, width="stretch")

    st.markdown('<div class="sat-panel-title">Asset Inventory Status Details</div>', unsafe_allow_html=True)
    inv_rows = []
    for _, a in e_assets.sort_values(["criticality", "asset_id"]).iterrows():
        status = str(a["status"])
        inv_rows.append([
            _esc(a["asset_id"]),
            _badge(str(a["criticality"]).upper(), "critical" if str(a["criticality"]) == "critical" else "muted"),
            _esc(a["asset_type"]),
            _badge("Expected" if bool(a["monitoring_expected"]) else "Not expected",
                   "low" if bool(a["monitoring_expected"]) else "high"),
            _esc(int(a["alert_count"])),
            _badge(status, ASSET_TONE.get(status, "muted")),
        ])
    ui_table(
        ["Asset ID", "Criticality", "Type", "Monitoring", "Alerts", "Status"],
        inv_rows, numeric=[4], max_height=460,
    )


# ==========================================================================
# PAGE 7: Cryptographic Audit & Validation
# ==========================================================================
elif page == PAGE_AUDIT:
    ui_header(
        "Cryptographic Audit & Validation",
        "Immutable SHA-256 hash chains, sealed run manifests, and ground-truth benchmark metrics.",
        kicker="Integrity",
    )

    st.markdown(
        '<div class="sat-strip">'
        + _chip("Audit sealed" if _AUDIT_OK else "Audit tamper detected", "ok" if _AUDIT_OK else "bad", dot=True)
        + _chip(f"{len(_AUDIT_ERRORS)} chain errors" if not _AUDIT_OK else "0 chain errors", "muted")
        + "</div>",
        unsafe_allow_html=True,
    )

    tab1, tab2, tab3 = st.tabs(["Cryptographic Audit Chain", "Sealed Run Manifest", "Ground-Truth Benchmark"])

    with tab1:
        if _AUDIT_OK:
            st.success("Cryptographic audit chain is intact. All block hashes and previous links verified.")
        else:
            st.error("Audit chain tamper detected.")
            for err in _AUDIT_ERRORS:
                st.code(err)

        audit_file = PATHS.audit_log_file
        if audit_file.exists():
            with open(audit_file, "r", encoding="utf-8") as f:
                log_lines = [json.loads(line) for line in f if line.strip()]
            log_rows = []
            for e in log_lines:
                log_rows.append([
                    _esc(e.get("entry_id")),
                    _badge(str(e.get("event_type", "")).replace("_", " "), "info"),
                    _esc(e.get("run_id")),
                    _esc(str(e.get("timestamp", "")).replace("T", " ").split(".")[0]),
                    f'<span class="sat-dim">{_esc(str(e.get("entry_hash", ""))[:14])}…</span>',
                    f'<span class="sat-dim">{_esc(str(e.get("prev_hash", ""))[:14])}…</span>',
                ])
            ui_table(["#", "Event", "Run ID", "Timestamp (UTC)", "Entry Hash", "Prev Hash"],
                     log_rows, numeric=[0], max_height=520)
        else:
            ui_empty("No audit log", "Execute the pipeline to create data/output/audit_log.jsonl.")

    with tab2:
        manifest_file = PATHS.run_manifest_file
        if manifest_file.exists():
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            st.json(manifest_data)
        else:
            ui_empty("No run manifest", "Execute the pipeline to create data/output/run_manifest.json.")

    with tab3:
        val_rep_file = PATHS.validation_report_file
        if val_rep_file.exists():
            with open(val_rep_file, "r", encoding="utf-8") as f:
                val_content = f.read()
            st.markdown(val_content)
        else:
            ui_empty("No validation report", "Execute python validation/run_validation.py to generate it.")

"""Manual-review sampling baselines and examiner-agreement metrics (PS 26157 §8).

Two Section 8 obligations are discharged here:

1. **"Comparable to or better than current manual sampling approaches."**
   Three reproducible simulations of how supervisors sample alert records
   today, evaluated at identical review budgets against the same seeded
   ground truth:

   * ``random``      -- simple random sampling of alert records (Monte Carlo).
   * ``stratified``  -- severity-first sampling (critical > high > medium >
                        low), the classic risk-based manual pull.
   * ``checklist``   -- an examiner's fixed-threshold checklist scored per
                        alert from one entity's records alone: critical/high
                        closed < 10 min (+4), critical/high un-escalated (+3),
                        alert without a case (+3), severe false positive
                        closed < 30 min (+2). Absolute thresholds, NO peer
                        statistics -- what a human can compute by hand.

   All three use *case-aware* matching: an examiner who opens an alert also
   reads its linked case, so a sampled alert counts as a hit when the seeded
   fault sits at ``alert:<id>`` or at ``case:<linked-case-id>``.

2. **"Validate against findings derived from expert manual review."**
   :func:`compute_expert_agreement` converts real examiner confirm/dismiss
   decisions (the feedback-loop ledger) into agreement metrics: confirmation
   rate, review coverage, per-detector endorsement, and mean confidence of
   confirmed vs dismissed findings.

Deterministic, offline, stdlib + numpy/pandas only.
"""

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

# Alert severity ranking used by the severity-stratified manual pull.
SEVERITY_RANK: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Fixed absolute thresholds for the hand-applied expert checklist (minutes).
CHECKLIST_FAST_MIN = 10.0
CHECKLIST_FP_MIN = 30.0
CHECKLIST_POINTS = {
    "fast": 4.0,
    "unescalated": 3.0,
    "orphan": 3.0,
    "false_positive": 2.0,
}

# Columns the manual-sampling baselines need (fast mode may read less).
_MANUAL_REQUIRED_COLS = {
    "alert_id", "entity_id", "created_ts", "severity", "ack_ts", "closed_ts", "disposition",
}


def build_case_lookup(cases_df: Optional[pd.DataFrame]) -> Dict[str, List[str]]:
    """Map ``alert_id -> [case_id, ...]`` from the cases table."""
    lookup: Dict[str, List[str]] = {}
    if cases_df is None or cases_df.empty or not {"alert_id", "case_id"} <= set(cases_df.columns):
        return lookup
    for aid, cid in zip(cases_df["alert_id"].astype(str), cases_df["case_id"].astype(str)):
        lookup.setdefault(aid, []).append(cid)
    return lookup


def case_aware_hits(
    alert_ids: Sequence[str],
    alert_to_cases: Mapping[str, Sequence[str]],
    gt_scopes: set,
) -> np.ndarray:
    """Boolean hit mask: alert matches seeded GT at alert scope or linked case scope."""
    hits = np.zeros(len(alert_ids), dtype=bool)
    for i, aid in enumerate(alert_ids):
        if f"alert:{aid}".lower() in gt_scopes:
            hits[i] = True
            continue
        for cid in alert_to_cases.get(str(aid), ()):
            if f"case:{cid}".lower() in gt_scopes:
                hits[i] = True
                break
    return hits


def stratified_order(e_alerts: pd.DataFrame) -> np.ndarray:
    """Positional order for severity-first manual sampling (criticals first)."""
    if e_alerts.empty:
        return np.empty(0, dtype=int)
    sev_rank = (
        e_alerts["severity"].astype(str).str.strip().str.lower()
        .map(SEVERITY_RANK).fillna(9).astype(int).to_numpy()
    )
    order = pd.DataFrame({
        "_sev": sev_rank,
        "_ts": e_alerts["created_ts"].to_numpy(),
        "_id": e_alerts["alert_id"].astype(str).to_numpy(),
        "_pos": np.arange(len(e_alerts)),
    })
    return order.sort_values(["_sev", "_ts", "_id"], kind="mergesort")["_pos"].to_numpy()


def expert_checklist_scores(
    e_alerts: pd.DataFrame,
    alert_to_cases: Mapping[str, Sequence[str]],
    escalated_cases: set,
) -> np.ndarray:
    """Absolute-threshold examiner score per alert (no peer information used)."""
    if e_alerts.empty:
        return np.empty(0, dtype=float)

    sev = e_alerts["severity"].astype(str).str.strip().str.lower()
    ack = pd.to_datetime(e_alerts["ack_ts"], errors="coerce")
    closed = pd.to_datetime(e_alerts["closed_ts"], errors="coerce")
    mttc_min = (closed - ack).dt.total_seconds() / 60.0

    linked = e_alerts["alert_id"].astype(str).map(lambda a: alert_to_cases.get(a, ()))
    has_case = linked.map(len).gt(0)
    is_escalated = linked.map(
        lambda cs: any(c in escalated_cases for c in cs)
    ).astype(bool)

    is_severe = sev.isin(["critical", "high"])
    fast = is_severe & mttc_min.lt(CHECKLIST_FAST_MIN)
    unesc = is_severe & has_case & ~is_escalated
    orphan = ~has_case
    fp = (
        is_severe
        & e_alerts["disposition"].astype(str).str.strip().str.lower().eq("false_positive")
        & mttc_min.lt(CHECKLIST_FP_MIN)
    )

    score = (
        sev.map({"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.0}).fillna(0.0)
        + fast.astype(float) * CHECKLIST_POINTS["fast"]
        + unesc.astype(float) * CHECKLIST_POINTS["unescalated"]
        + orphan.astype(float) * CHECKLIST_POINTS["orphan"]
        + fp.astype(float) * CHECKLIST_POINTS["false_positive"]
    )
    return score.to_numpy(dtype=float)


def expert_checklist_order(
    e_alerts: pd.DataFrame,
    alert_to_cases: Mapping[str, Sequence[str]],
    escalated_cases: set,
) -> np.ndarray:
    """Positional order for the expert checklist (highest score first)."""
    if e_alerts.empty:
        return np.empty(0, dtype=int)
    scores = expert_checklist_scores(e_alerts, alert_to_cases, escalated_cases)
    order = pd.DataFrame({
        "_s": scores,
        "_id": e_alerts["alert_id"].astype(str).to_numpy(),
        "_pos": np.arange(len(e_alerts)),
    })
    return order.sort_values(
        ["_s", "_id"], ascending=[False, True], kind="mergesort"
    )["_pos"].to_numpy()


def compute_manual_baselines(
    alerts_df: pd.DataFrame,
    cases_df: Optional[pd.DataFrame],
    escalations_df: Optional[pd.DataFrame],
    gt_df: pd.DataFrame,
    entity_ids: Sequence[str],
    budgets_pct: Sequence[float] = (0.05, 0.10, 0.20),
    seed: int = 42,
    trials: int = 200,
) -> Dict[float, Dict[str, float]]:
    """Overall precision of each manual-sampling approach at each review budget.

    Uses the same budget formula as the SAT-SA review queue
    (``k = max(5, round(n_alerts * pct))``) and the same entities, so the
    numbers are directly comparable with the queue benchmark. Returns
    ``{budget_pct: {"random": p, "stratified": p, "checklist": p, "examined": n}}``
    or ``{}`` when the inputs lack the columns the baselines need.
    """
    budgets = tuple(budgets_pct)
    if alerts_df is None or gt_df is None or gt_df.empty:
        return {}
    if not _MANUAL_REQUIRED_COLS <= set(alerts_df.columns):
        return {}

    alert_to_cases = build_case_lookup(cases_df)
    escalated_cases: set = set()
    if escalations_df is not None and not escalations_df.empty and "case_id" in escalations_df.columns:
        escalated_cases = set(escalations_df["case_id"].astype(str))

    rng = np.random.default_rng(seed)
    acc = {b: {"rand_tp": 0.0, "strat_tp": 0.0, "check_tp": 0.0, "examined": 0} for b in budgets}
    gt_grouped = {eid: g for eid, g in gt_df.groupby("entity_id")}

    for eid in entity_ids:
        e = alerts_df[alerts_df["entity_id"] == eid]
        if e.empty:
            continue
        e_gt = gt_grouped.get(eid)
        if e_gt is None:
            continue
        gt_scopes = {str(s).lower() for s in e_gt["scope"]}
        if not gt_scopes:
            continue

        e = e.sort_values(["created_ts", "alert_id"], kind="mergesort").reset_index(drop=True)
        alert_ids = e["alert_id"].astype(str).to_numpy()
        hits = case_aware_hits(alert_ids, alert_to_cases, gt_scopes)
        strat = stratified_order(e)
        check = expert_checklist_order(e, alert_to_cases, escalated_cases)
        n = len(e)

        for b in budgets:
            k = min(n, max(5, int(round(n * b))))
            if k <= 0:
                continue
            acc[b]["strat_tp"] += float(hits[strat[:k]].sum())
            acc[b]["check_tp"] += float(hits[check[:k]].sum())
            acc[b]["rand_tp"] += float(hits[rng.choice(n, size=k, replace=False)].sum())
            acc[b]["examined"] += k

    out: Dict[float, Dict[str, float]] = {}
    for b in budgets:
        examined = acc[b]["examined"]
        denom = max(1, examined)
        out[b] = {
            "random": acc[b]["rand_tp"] / denom,
            "stratified": acc[b]["strat_tp"] / denom,
            "checklist": acc[b]["check_tp"] / denom,
            "examined": float(examined),
        }
    return out


def load_expert_labels(db_path: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Examiner decision ledger rows (empty when no feedback database exists)."""
    from satsa import feedback  # lazy: keeps this module import-light

    try:
        return feedback.get_history(db_path=db_path, limit=100_000)
    except Exception:
        return []


def compute_expert_agreement(
    labels: Optional[Sequence[Mapping[str, Any]]],
    findings: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """PS §8 agreement metrics over the examiner confirm/dismiss ledger.

    Only the latest decision per ``finding_id`` counts (re-deciding a finding
    supersedes the earlier decision). ``findings`` (the ``findings.json``
    records) supply confidence for the confirmed-vs-dismissed separation and
    the labelling-coverage denominator.
    """
    findings = list(findings or [])
    out: Dict[str, Any] = {
        "n_labels": 0,
        "n_decisions_raw": len(labels or []),
        "n_confirm": 0,
        "n_dismiss": 0,
        "confirm_rate": None,
        "coverage": (0.0 if findings else None),
        "by_detector": {},
        "by_entity": {},
        "confidence_confirmed": None,
        "confidence_dismissed": None,
        "status": "awaiting_examiner_feedback",
    }
    if not labels:
        return out

    latest: Dict[str, Mapping[str, Any]] = {}
    for row in labels:
        fid = str(row.get("finding_id") or "")
        if not fid:
            continue
        prev = latest.get(fid)
        if prev is None or int(row.get("feedback_id") or 0) >= int(prev.get("feedback_id") or 0):
            latest[fid] = row
    if not latest:
        return out

    dec = list(latest.values())
    n = len(dec)

    def _is_confirm(row: Mapping[str, Any]) -> bool:
        return str(row.get("decision", "")).lower() == "confirm"

    n_conf = sum(1 for r in dec if _is_confirm(r))

    by_detector: Dict[str, List[Mapping[str, Any]]] = {}
    by_entity: Dict[str, List[Mapping[str, Any]]] = {}
    for r in dec:
        by_detector.setdefault(str(r.get("detector_id") or "?"), []).append(r)
        by_entity.setdefault(str(r.get("entity_id") or "?"), []).append(r)

    conf_by_id = {
        str(f.get("finding_id")): float(f.get("confidence", 0.0) or 0.0) for f in findings
    }
    confirmed_conf = [
        conf_by_id[str(r["finding_id"])]
        for r in dec if _is_confirm(r) and str(r.get("finding_id")) in conf_by_id
    ]
    dismissed_conf = [
        conf_by_id[str(r["finding_id"])]
        for r in dec if not _is_confirm(r) and str(r.get("finding_id")) in conf_by_id
    ]

    def _rate(rows: List[Mapping[str, Any]]) -> Dict[str, Any]:
        c = sum(1 for r in rows if _is_confirm(r))
        return {"n": len(rows), "confirm": c, "confirm_rate": c / len(rows)}

    out.update({
        "n_labels": n,
        "n_confirm": n_conf,
        "n_dismiss": n - n_conf,
        "confirm_rate": n_conf / n,
        "coverage": (n / len(findings)) if findings else None,
        "by_detector": {k: _rate(v) for k, v in sorted(by_detector.items())},
        "by_entity": {k: _rate(v) for k, v in sorted(by_entity.items())},
        "confidence_confirmed": float(np.mean(confirmed_conf)) if confirmed_conf else None,
        "confidence_dismissed": float(np.mean(dismissed_conf)) if dismissed_conf else None,
        "status": "examiner_review_active",
    })
    return out

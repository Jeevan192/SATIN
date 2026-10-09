"""Robustness benchmark for SAT-SA: messy data, adaptive adversaries, sparse cohorts.

PS Section 8 requires validation under realistic supervisory conditions. This
harness measures three robustness properties end-to-end and writes
``data/output/robustness_report.md`` (plus ``robustness_report.json``):

1. **Messy-data robustness** -- known corruption (bad severity, broken and
   out-of-order timestamps, dangling entity FKs, duplicate primary keys,
   missing severity) is injected into a copy of the dataset; the harness
   measures quarantine catch rate, false-quarantine count, pipeline
   completion, and entity risk-rank stability vs the clean run (Spearman rho).
2. **Adaptive adversary (anti-gaming)** -- the worst faulty CSE rewrites its
   records to game every headline metric: pads closure times to the peer
   median, round-robins analysts, randomizes notes and closure codes,
   fabricates escalations and investigation events, and floods filler alerts
   to close silence / category / coverage / volume gaps. The harness measures
   per-detector survival (which lanes still flag the entity) and its risk
   rank before/after.
3. **Sparse cohorts** -- the fleet runs on a 4-entity subset whose sector /
   size cohorts all have a single member, exercising the hierarchical cohort
   fallback chain.

Usage::

    python validation/run_robustness.py --seed 42

Offline, deterministic, CPU-only.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from satsa.config import PATHS
from satsa.detectors import ALL_DETECTORS
from satsa.detectors.base import Finding
from satsa.ingest import DataBundle, load_dataset
from satsa.peers import CohortManager
from satsa.scoring import score_portfolio
from validation.run_validation import load_ground_truth

logger = logging.getLogger(__name__)

N_PER_CORRUPTION = 25
SEVERE = ("critical", "high")

CANONICAL_TABLES = ("cases", "workflow_events", "escalations", "assets", "entities")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run_fleet(bundle: DataBundle) -> Tuple[List[Finding], Dict[str, Any]]:
    """Run every detector and score the portfolio; returns (findings, scores)."""
    cohort_mgr = CohortManager(bundle.entities)
    findings: List[Finding] = []
    for det_cls in ALL_DETECTORS:
        findings.extend(det_cls().run(bundle, cohort_mgr))
    scores = score_portfolio(findings, bundle, cohort_mgr)
    return findings, scores


def _risk_map(scores: Dict[str, Any]) -> Dict[str, float]:
    return {eid: float(sc.overall_risk_index) for eid, sc in scores.items()}


def _rank_of(scores: Dict[str, Any], entity_id: str) -> int:
    """1-based risk rank (highest risk = 1)."""
    ordered = sorted(
        scores.items(), key=lambda kv: float(kv[1].overall_risk_index), reverse=True
    )
    for i, (eid, _) in enumerate(ordered, start=1):
        if eid == entity_id:
            return i
    return len(ordered)


def _load_raw_tables(data_dir: Path) -> Dict[str, pd.DataFrame]:
    tables: Dict[str, pd.DataFrame] = {}
    alerts_p = Path(data_dir) / "alerts.csv"
    if alerts_p.exists():
        tables["alerts"] = pd.read_csv(alerts_p, dtype=str)
    for name in CANONICAL_TABLES:
        p = Path(data_dir) / f"{name}.csv"
        if p.exists():
            tables[name] = pd.read_csv(p, dtype=str)
    return tables


# ---------------------------------------------------------------------------
# Scenario 1: messy data
# ---------------------------------------------------------------------------

def _corruption_recipes() -> List[Tuple[str, str]]:
    """(corruption key, expected quarantine reason substring)."""
    return [
        ("bad_severity", "Invalid severity tier"),
        ("missing_severity", "Invalid severity tier"),
        ("bad_timestamp", "Unparseable timestamp in column 'ack_ts'"),
        ("reversed_timestamp", "Timestamp ordering violation: created_ts > ack_ts"),
        ("ghost_entity", "Referential integrity: entity_id not in entities"),
        ("duplicate_pk", "Duplicate primary key alert_id"),
    ]


def _inject_corruption(
    alerts_raw: pd.DataFrame, rng: np.random.Generator
) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """Corrupt disjoint row slices; returns (corrupted frame, injected counts)."""
    o = alerts_raw.copy()
    recipes = _corruption_recipes()
    per = min(N_PER_CORRUPTION, max(1, len(o) // (2 * (len(recipes) + 1))))
    perm = rng.permutation(len(o))
    anchors = perm[:per]          # untouched rows used as duplicate targets
    pool = perm[per:]

    def bad_severity(pos):
        o.loc[pos, "severity"] = "P1-URGENT"

    def missing_severity(pos):
        o.loc[pos, "severity"] = ""

    def bad_timestamp(pos):
        o.loc[pos, "ack_ts"] = "not-a-timestamp-99"

    def reversed_timestamp(pos):
        created = pd.to_datetime(o.loc[pos, "created_ts"], errors="coerce")
        o.loc[pos, "ack_ts"] = (created - pd.Timedelta(minutes=45)).dt.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

    def ghost_entity(pos):
        o.loc[pos, "entity_id"] = "CSE-GHOST-99"

    def duplicate_pk(pos):
        o.loc[pos, "alert_id"] = o["alert_id"].iloc[anchors].to_numpy()

    injectors = [
        bad_severity, missing_severity, bad_timestamp,
        reversed_timestamp, ghost_entity, duplicate_pk,
    ]

    counts: Dict[str, int] = {}
    for i, ((key, _reason), inject) in enumerate(zip(recipes, injectors)):
        pos = pool[i * per:(i + 1) * per]
        if len(pos) == 0:
            counts[key] = 0
            continue
        inject(pos)
        counts[key] = len(pos)
    return o, counts


def scenario_messy_data(
    data_dir: Path,
    clean_bundle: DataBundle,
    seed: int,
    clean_findings: List[Finding],
    clean_scores: Dict[str, Any],
) -> Dict[str, Any]:
    q_clean = len(clean_bundle.quarantine)

    tables = _load_raw_tables(data_dir)
    corrupted, injected = _inject_corruption(
        tables["alerts"], np.random.default_rng(seed)
    )
    tables["alerts"] = corrupted

    with tempfile.TemporaryDirectory(prefix="satsa_robust_") as tmp:
        dirty = load_dataset(tables, quarantine_output_path=Path(tmp) / "q.csv")

    q_dirty = len(dirty.quarantine)
    reasons = dirty.quarantine["quarantine_reason"].astype(str) if q_dirty else pd.Series(dtype=str)

    per_type: List[Dict[str, Any]] = []
    total_injected = 0
    for key, reason_sub in _corruption_recipes():
        n_inj = int(injected.get(key, 0))
        n_catch = int(reasons.str.contains(reason_sub, regex=False).sum())
        total_injected += n_inj
        per_type.append({
            "corruption": key,
            "injected": n_inj,
            "caught": n_catch,
            "reason": reason_sub,
        })

    caught_total = q_dirty - q_clean
    catch_rate = caught_total / total_injected if total_injected else 0.0

    dirty_findings, dirty_scores = _run_fleet(dirty)
    entities = sorted(set(clean_scores) & set(dirty_scores))
    clean_risk = [_risk_map(clean_scores)[e] for e in entities]
    dirty_risk = [_risk_map(dirty_scores)[e] for e in entities]
    if len(entities) >= 3:
        rho = float(stats.spearmanr(clean_risk, dirty_risk).statistic)
    else:
        rho = float("nan")

    clean_n = len(clean_findings)
    dirty_n = len(dirty_findings)
    delta_pct = (dirty_n - clean_n) / clean_n * 100.0 if clean_n else 0.0

    logger.info(
        "Messy data: %d injected, %d quarantined (%.1f%%), rank rho=%.4f",
        total_injected, caught_total, catch_rate * 100.0, rho,
    )
    return {
        "injected_total": total_injected,
        "quarantined_clean": q_clean,
        "quarantined_dirty": q_dirty,
        "caught_total": caught_total,
        "catch_rate": catch_rate,
        "per_type": per_type,
        "pipeline_completed": True,
        "findings_clean": clean_n,
        "findings_dirty": dirty_n,
        "findings_delta_pct": delta_pct,
        "risk_rank_spearman": rho,
        "alerts_valid_after": len(dirty.alerts),
    }


# ---------------------------------------------------------------------------
# Scenario 2: adaptive adversary (anti-gaming)
# ---------------------------------------------------------------------------

def _adversary_transform(
    bundle: DataBundle, target: str, rng: np.random.Generator
) -> Tuple[DataBundle, Dict[str, int]]:
    """Six-vector metric-gaming rewrite of the target entity's records."""
    alerts = bundle.alerts.copy()
    cases = bundle.cases.copy()
    workflow = bundle.workflow_events.copy()
    escalations = bundle.escalations.copy()
    altered: Dict[str, int] = {}

    sev = alerts["severity"].astype(str).str.lower()
    t_mask = alerts["entity_id"] == target
    ch_mask = t_mask & sev.isin(SEVERE) & alerts["ack_ts"].notna() & alerts["closed_ts"].notna()

    # (a) Pad severe closure times to the peer median +/-10% (defeats EG-01).
    peer = alerts[~t_mask & sev.isin(SEVERE) & alerts["ack_ts"].notna() & alerts["closed_ts"].notna()]
    peer_min = ((peer["closed_ts"] - peer["ack_ts"]).dt.total_seconds() / 60.0).median()
    if not np.isfinite(peer_min) or peer_min <= 0:
        peer_min = 120.0
    pad_idx = alerts.index[ch_mask]
    if len(pad_idx):
        pad_min = peer_min * (0.9 + 0.2 * rng.random(len(pad_idx)))
        alerts.loc[pad_idx, "closed_ts"] = (
            alerts.loc[pad_idx, "ack_ts"] + pd.to_timedelta(pad_min, unit="m")
        )
    altered["closure_times_padded"] = int(len(pad_idx))

    # Case-level view of the target.
    t_alert_ids = set(alerts.loc[t_mask, "alert_id"].astype(str))
    tcase_mask = cases["alert_id"].astype(str).isin(t_alert_ids)
    n_tc = int(tcase_mask.sum())

    # (b) Round-robin analysts (defeats EG-07 concentration).
    if n_tc:
        cases.loc[tcase_mask, "analyst_id"] = [
            f"AN-SPREAD-{i % 8:02d}" for i in range(n_tc)
        ]
    altered["cases_analyst_spread"] = n_tc

    # (c) Randomize notes and closure codes (defeats EG-04 templates/entropy).
    if n_tc:
        idx = cases.index[tcase_mask]
        toks = np.array([f"TZ-{i:05d}-{int(rng.integers(100000, 999999))}" for i in range(n_tc)])
        cases.loc[idx, "notes_text"] = (
            cases.loc[idx, "notes_text"].fillna("").astype(str) + " " + toks
        )
        cases.loc[idx, "closure_code"] = [f"CC-{i % 9:02d}" for i in range(n_tc)]
    altered["notes_randomized"] = n_tc

    # (d) Fabricate escalations for severe cases lacking them (defeats EG-02).
    esc_set = set(escalations["case_id"].astype(str)) if not escalations.empty else set()
    severe_alert_ids = set(
        alerts.loc[t_mask & sev.isin(SEVERE), "alert_id"].astype(str)
    )
    need_esc = (
        tcase_mask
        & cases["alert_id"].astype(str).isin(severe_alert_ids)
        & ~cases["case_id"].astype(str).isin(esc_set)
    )
    n_esc = int(need_esc.sum())
    if n_esc:
        esc_src = cases.loc[need_esc]
        new_esc = pd.DataFrame({
            "case_id": esc_src["case_id"].astype(str).to_numpy(),
            "from_tier": "tier1",
            "to_tier": "tier2",
            "ts": esc_src["opened_ts"] + pd.Timedelta(minutes=5),
            "outcome": "acknowledged",
        })
        escalations = pd.concat([escalations, new_esc], ignore_index=True)
    altered["escalations_fabricated"] = n_esc

    # (e) Fabricate investigation events for cases lacking them (defeats EG-03).
    we_set = set(workflow["case_id"].astype(str)) if not workflow.empty else set()
    need_we = tcase_mask & ~cases["case_id"].astype(str).isin(we_set)
    n_we = int(need_we.sum())
    if n_we:
        we_src = cases.loc[need_we]
        new_we = pd.DataFrame({
            "case_id": we_src["case_id"].astype(str).to_numpy(),
            "step": "investigation",
            "actor_role": "analyst",
            "ts": we_src["opened_ts"] + pd.Timedelta(minutes=10),
        })
        workflow = pd.concat([workflow, new_we], ignore_index=True)
    altered["workflow_events_fabricated"] = n_we

    # (f) Filler-alert flood across every target asset/category to close
    # silence (NS-05), coverage (NS-01/NS-06), category (NS-02) and volume
    # (NS-04) gaps. Pairs are spaced so no (asset, category) pair repeats
    # within 7 days, i.e. the flood itself is built to avoid tripping EG-05.
    tgt_alerts = alerts[t_mask]
    tgt_assets = sorted(tgt_alerts["asset_id"].dropna().astype(str).unique())
    all_cats = sorted(alerts["category"].dropna().astype(str).unique())
    n_fill = 0
    if len(tgt_assets) >= 1 and len(all_cats) >= 1 and len(tgt_alerts) >= 2:
        t0 = tgt_alerts["created_ts"].min()
        t1 = tgt_alerts["created_ts"].max()
        pair_space = len(tgt_assets) * len(all_cats)
        interval_h = max(6.0, 192.0 / pair_space)  # guarantees >= 8d pair spacing
        ticks = pd.date_range(t0, t1, freq=pd.Timedelta(hours=interval_h))
        fill_alerts, fill_cases, fill_we = [], [], []
        for i, ts in enumerate(ticks):
            pair = i % pair_space
            asset = tgt_assets[pair // len(all_cats)]
            cat = all_cats[pair % len(all_cats)]
            aid = f"ALT-GAME-{target}-{i:04d}"
            cid = f"CAS-GAME-{target}-{i:04d}"
            created = pd.Timestamp(ts)
            closed = created + pd.Timedelta(minutes=12)
            fill_alerts.append({
                "alert_id": aid, "entity_id": target, "asset_id": asset,
                "category": cat, "severity": "medium",
                "created_ts": created, "ack_ts": created + pd.Timedelta(minutes=1),
                "closed_ts": closed, "disposition": "true_positive",
            })
            fill_cases.append({
                "case_id": cid, "alert_id": aid, "analyst_id": "AN-FILL-00",
                "opened_ts": created, "closed_ts": closed, "status": "closed",
                "closure_code": f"GAME-{i % 9:02d}",
                "notes_text": (
                    f"Filler investigation {i:04d} covering the daily coverage "
                    f"window for {asset} / {cat} with a unique content token."
                ),
            })
            fill_we.append({
                "case_id": cid, "step": "investigation", "actor_role": "analyst",
                "ts": created + pd.Timedelta(minutes=5),
            })
        if fill_alerts:
            alerts = pd.concat([alerts, pd.DataFrame(fill_alerts)], ignore_index=True)
            cases = pd.concat([cases, pd.DataFrame(fill_cases)], ignore_index=True)
            workflow = pd.concat([workflow, pd.DataFrame(fill_we)], ignore_index=True)
        n_fill = len(fill_alerts)
    altered["filler_alerts"] = n_fill

    gamed = DataBundle(
        alerts=alerts,
        cases=cases,
        workflow_events=workflow,
        escalations=escalations,
        assets=bundle.assets.copy(),
        entities=bundle.entities.copy(),
    )
    return gamed, altered


def scenario_adversary(
    clean_bundle: DataBundle,
    gt_df: pd.DataFrame,
    seed: int,
    clean_findings: List[Finding],
    clean_scores: Dict[str, Any],
) -> Dict[str, Any]:
    target = str(gt_df.groupby("entity_id").size().idxmax())
    gamed, altered = _adversary_transform(
        clean_bundle, target, np.random.default_rng(seed + 1)
    )
    gamed_findings, gamed_scores = _run_fleet(gamed)

    before = Counter(f.detector_id for f in clean_findings if f.entity_id == target)
    after = Counter(f.detector_id for f in gamed_findings if f.entity_id == target)
    detectors = sorted(set(before) | set(after))

    rows: List[Dict[str, Any]] = []
    for d in detectors:
        b, a = before.get(d, 0), after.get(d, 0)
        if b > 0 and a > 0:
            status = "survived"
        elif b > 0:
            status = "evaded"
        else:
            status = "new"
        rows.append({"detector": d, "before": b, "after": a, "status": status})

    lanes_before = sum(1 for r in rows if r["before"] > 0)
    survived = [r["detector"] for r in rows if r["status"] == "survived"]
    evaded = [r["detector"] for r in rows if r["status"] == "evaded"]

    rank_before = _rank_of(clean_scores, target)
    rank_after = _rank_of(gamed_scores, target)

    logger.info(
        "Adversary target %s: %d lanes before, %d survived, %d evaded; risk rank #%d -> #%d",
        target, lanes_before, len(survived), len(evaded), rank_before, rank_after,
    )
    return {
        "target": target,
        "altered_records": altered,
        "altered_total": int(sum(altered.values())),
        "per_detector": rows,
        "lanes_before": lanes_before,
        "lanes_survived": len(survived),
        "survived": survived,
        "evaded": evaded,
        "risk_rank_before": rank_before,
        "risk_rank_after": rank_after,
        "n_entities": len(clean_scores),
        "findings_on_target_before": int(sum(before.values())),
        "findings_on_target_after": int(sum(after.values())),
        "total_findings_clean": len(clean_findings),
        "total_findings_gamed": len(gamed_findings),
    }


# ---------------------------------------------------------------------------
# Scenario 3: sparse cohorts
# ---------------------------------------------------------------------------

def scenario_sparse_cohorts(clean_bundle: DataBundle) -> Dict[str, Any]:
    ent = clean_bundle.entities.drop_duplicates(subset=["entity_id"])
    picks: List[str] = []
    for _, row in ent[["sector", "size_band"]].drop_duplicates().iterrows():
        members = ent[
            (ent["sector"] == row["sector"]) & (ent["size_band"] == row["size_band"])
        ]["entity_id"].tolist()
        if members and members[0] not in picks:
            picks.append(members[0])
        if len(picks) == 4:
            break
    for eid in ent["entity_id"]:
        if eid not in picks:
            picks.append(eid)
        if len(picks) == 4:
            break
    ids = set(picks)

    alert_ids = set(
        clean_bundle.alerts[clean_bundle.alerts["entity_id"].isin(ids)]["alert_id"].astype(str)
    )
    case_ids = set(
        clean_bundle.cases[clean_bundle.cases["alert_id"].astype(str).isin(alert_ids)]["case_id"].astype(str)
    )
    sub = DataBundle(
        alerts=clean_bundle.alerts[clean_bundle.alerts["entity_id"].isin(ids)],
        cases=clean_bundle.cases[clean_bundle.cases["alert_id"].astype(str).isin(alert_ids)],
        workflow_events=clean_bundle.workflow_events[
            clean_bundle.workflow_events["case_id"].astype(str).isin(case_ids)
        ],
        escalations=clean_bundle.escalations[
            clean_bundle.escalations["case_id"].astype(str).isin(case_ids)
        ],
        assets=clean_bundle.assets[clean_bundle.assets["entity_id"].isin(ids)],
        entities=ent[ent["entity_id"].isin(ids)],
    )

    findings, _scores = _run_fleet(sub)
    cm = CohortManager(sub.entities)
    levels = {eid: cm.get_cohort_entities(eid)[1] for eid in picks}
    primary = sum(1 for lvl in levels.values() if lvl == "primary")
    per_entity = dict(Counter(f.entity_id for f in findings))

    logger.info(
        "Sparse cohorts: 4 entities, primary=%d, findings=%d", primary, len(findings),
    )
    return {
        "entities": picks,
        "fallback_levels": levels,
        "primary_cohort_count": primary,
        "n_findings": len(findings),
        "findings_per_entity": per_entity,
        "completed_without_crash": True,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _write_report(
    out_md: Path,
    results: Dict[str, Any],
    seed: int,
    n_alerts: int,
    n_entities: int,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    messy = results["messy_data"]
    adv = results["adaptive_adversary"]
    sparse = results["sparse_cohorts"]

    lines = [
        "# SAT-SA Robustness Benchmark (PS Section 8)",
        "",
        f"**Generated:** {now}  ",
        f"**Seed:** {seed}  ",
        f"**Dataset:** {n_alerts} alerts across {n_entities} entities  ",
        "",
        "---",
        "",
        "## 1. Messy-Data Robustness (Quarantine Router)",
        "",
        f"{messy['injected_total']} corrupted rows injected across 6 corruption types; "
        f"**{messy['caught_total']} routed to quarantine ({messy['catch_rate']*100:.1f}% catch rate)**; "
        f"{messy['quarantined_clean']} rows quarantined on the clean dataset (false-quarantine baseline).",
        "",
        "| Corruption | Injected | Caught | Expected Quarantine Reason |",
        "|---|---|---|---|",
    ]
    for row in messy["per_type"]:
        lines.append(
            f"| {row['corruption']} | {row['injected']} | {row['caught']} | `{row['reason']}` |"
        )
    lines += [
        "",
        f"- Pipeline on corrupted data: **completed**, {messy['findings_dirty']} findings "
        f"({messy['findings_delta_pct']:+.1f}% vs {messy['findings_clean']} on clean data); "
        f"{messy['alerts_valid_after']} valid alerts retained.",
        f"- Entity risk-rank stability vs clean run: **Spearman rho = {messy['risk_rank_spearman']:.4f}**.",
        "",
        "---",
        "",
        "## 2. Adaptive-Adversary (Anti-Gaming) Survival",
        "",
        f"Target: **{adv['target']}** (most injected faults). Attack vectors: closure padding to peer median, "
        "analyst round-robin, note/closure-code randomization, fabricated escalations, fabricated "
        f"investigation events, filler-alert flood -- **{adv['altered_total']} records altered** "
        f"({adv['altered_records'].get('filler_alerts', 0)} of them filler alerts).",
        "",
        "| Detector Lane | Findings Before | After | Status |",
        "|---|---|---|---|",
    ]
    for row in adv["per_detector"]:
        marker = {"survived": "survived", "evaded": "evaded", "new": "new"}[row["status"]]
        lines.append(
            f"| {row['detector']} | {row['before']} | {row['after']} | {marker} |"
        )
    lines += [
        "",
        f"- Lanes firing on the target before the attack: **{adv['lanes_before']}**; "
        f"after the full six-vector attack: **{adv['lanes_survived']} survived, "
        f"{len(adv['evaded'])} evaded** ({', '.join(adv['survived']) or 'none'}).",
        f"- Target risk rank: **#{adv['risk_rank_before']} of {adv['n_entities']}** -> "
        f"**#{adv['risk_rank_after']} of {adv['n_entities']}**.",
        f"- Findings on target: {adv['findings_on_target_before']} -> {adv['findings_on_target_after']} "
        f"(fleet total {adv['total_findings_clean']} -> {adv['total_findings_gamed']}).",
        "",
        "---",
        "",
        "## 3. Sparse-Cohort Robustness",
        "",
        f"4 entities whose sector/size cohorts each hold a single member "
        f"(fallback levels: {', '.join(f'{e}={l}' for e, l in sparse['fallback_levels'].items())}).",
        "",
        f"- Fleet completed without crash: **{sparse['completed_without_crash']}**; "
        f"findings emitted: **{sparse['n_findings']}** "
        f"({sparse['findings_per_entity']}).",
        f"- Primary (same sector+size) cohorts resolved: {sparse['primary_cohort_count']} of 4 -- "
        "the rest used sector/global fallbacks.",
        "",
        "---",
        "",
        "## 4. Summary",
        "",
        f"- Quarantine router caught **{messy['catch_rate']*100:.1f}%** of injected corruption; "
        f"pipeline output stayed stable (risk-rank rho = {messy['risk_rank_spearman']:.4f}).",
        f"- Under a six-vector adaptive adversary, **{adv['lanes_survived']} of "
        f"{adv['lanes_before']}** detector lanes still flag the gaming entity and its risk rank "
        f"remains #{adv['risk_rank_after']} of {adv['n_entities']}.",
        f"- The fleet stays functional on sparse cohorts via the hierarchical fallback chain "
        f"({sparse['n_findings']} findings on 4 entities).",
        "",
        "> Run: `python validation/run_robustness.py --seed 42`. Deterministic and offline.",
    ]

    report = "\n".join(lines) + "\n"
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(report, encoding="utf-8")
    out_json = out_md.with_suffix(".json")
    out_json.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="SAT-SA robustness benchmark (PS Section 8).")
    parser.add_argument("--data-dir", type=str, default=str(PATHS.synthetic_dir))
    parser.add_argument("--gt-path", type=str, default=str(PATHS.ground_truth_file))
    parser.add_argument(
        "--out", type=str, default=str(PATHS.output_dir / "robustness_report.md"),
        help="Output markdown report (JSON written alongside)",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    data_dir = Path(args.data_dir)
    gt_df = load_ground_truth(args.gt_path)

    logger.info("Loading clean dataset...")
    with tempfile.TemporaryDirectory(prefix="satsa_robust_") as tmp:
        clean = load_dataset(data_dir, quarantine_output_path=Path(tmp) / "q.csv")

    logger.info("Running baseline detector fleet on clean data...")
    clean_findings, clean_scores = _run_fleet(clean)

    results: Dict[str, Any] = {"seed": args.seed}
    results["messy_data"] = scenario_messy_data(
        data_dir, clean, args.seed, clean_findings, clean_scores
    )
    results["adaptive_adversary"] = scenario_adversary(
        clean, gt_df, args.seed, clean_findings, clean_scores
    )
    results["sparse_cohorts"] = scenario_sparse_cohorts(clean)

    report = _write_report(
        Path(args.out), results, args.seed, len(clean.alerts), len(clean.entities)
    )
    logger.info("Robustness report written to: %s", args.out)
    print(report)


if __name__ == "__main__":
    main()

"""SAT-SA scale benchmark: full pipeline on 1M+ alert rows (CPU-only, offline).

Generates a canonical synthetic dataset *vectorised* (numpy -> parquet, no
per-row Python loop) at the requested scale, then runs the real end-to-end
pipeline (ingest -> parquet store -> 15 detectors -> scoring -> queue -> audit)
while capturing per-step wall time and peak process memory.

Usage:
    python scripts/scale_test.py                 # 1,000,000 alerts (default)
    python scripts/scale_test.py --rows 10000000 # 10M alert stress run
    python scripts/scale_test.py --keep          # keep generated data for re-runs
    python scripts/scale_test.py --data-dir DIR  # benchmark existing canonical dir
"""

import argparse
import logging
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # repo root for direct execution

import numpy as np
import pandas as pd

# ------------------------------------------------------------------
# Peak memory (Windows: PeakWorkingSetSize via ctypes; POSIX: ru_maxrss)
# ------------------------------------------------------------------
def peak_rss_mb() -> float:
    if sys.platform.startswith("win"):
        import ctypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p  # HANDLE is pointer-sized
        psapi = ctypes.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.c_uint,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        ok = psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        if not ok:
            return float("nan")
        return counters.PeakWorkingSetSize / (1024 * 1024)

    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 1024 if sys.platform == "darwin" else rss / 1024  # KB on Linux


# ------------------------------------------------------------------
# Vectorised canonical dataset generation
# ------------------------------------------------------------------
SECTORS = ["banking", "energy", "telecom", "healthcare"]
BANDS = ["Tier-1", "Tier-2"]
CATEGORIES = [
    "malware", "phishing", "credential_access", "network_anomaly",
    "data_exfiltration", "insider_threat", "ransomware", "vulnerability_exploit",
]
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_P = [0.08, 0.22, 0.40, 0.30]
DISPOSITIONS = ["true_positive", "false_positive", "benign_true_positive", "unresolved"]
DISPOSITION_P = [0.55, 0.25, 0.15, 0.05]
ASSET_TYPES = ["database_server", "domain_controller", "app_server", "scada_controller", "firewall"]
CRITICALITIES = ["critical", "high", "medium", "low"]
CRITICALITY_P = [0.15, 0.25, 0.40, 0.20]
STEPS = ["triage", "investigation", "containment", "closure"]


def generate_scale_dataset(out_dir: Path, rows: int, seed: int = 42, entities_n: int = 12,
                           assets_per_entity: int = 150, days: int = 180) -> Dict[str, int]:
    """Write canonical parquet tables totalling ``rows`` alerts. Returns row counts."""
    rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    entity_ids = [f"CSE-SC-{i:02d}" for i in range(1, entities_n + 1)]
    entities = pd.DataFrame({
        "entity_id": entity_ids,
        "sector": [SECTORS[i % len(SECTORS)] for i in range(entities_n)],
        "size_band": [BANDS[i % len(BANDS)] for i in range(entities_n)],
        "soc_model": ["in-house" if i % 2 == 0 else "hybrid" for i in range(entities_n)],
    })

    n_assets = entities_n * assets_per_entity
    asset_owner = np.repeat(np.arange(entities_n), assets_per_entity)
    assets = pd.DataFrame({
        "asset_id": [f"AST-SC-{i:06d}" for i in range(n_assets)],
        "entity_id": [entity_ids[o] for o in asset_owner],
        "criticality": rng.choice(CRITICALITIES, size=n_assets, p=CRITICALITY_P),
        "asset_type": rng.choice(ASSET_TYPES, size=n_assets),
        "monitoring_expected": rng.random(n_assets) > 0.08,
    })

    # --- alerts (vectorised) ---
    ent_idx = rng.integers(0, entities_n, size=rows)
    asset_idx = ent_idx * assets_per_entity + rng.integers(0, assets_per_entity, size=rows)
    created = (
        np.datetime64("2026-01-01T00:00:00")
        + rng.integers(0, days * 86400, size=rows).astype("timedelta64[s]")
    )
    ack = created + rng.integers(60, 900, size=rows).astype("timedelta64[s]")
    closed = ack + rng.integers(60, 7200, size=rows).astype("timedelta64[s]")

    alerts = pd.DataFrame({
        "alert_id": [f"ALERT-SC-{i:09d}" for i in range(rows)],
        "entity_id": np.asarray(entity_ids, dtype=object)[ent_idx],
        "asset_id": assets["asset_id"].to_numpy()[asset_idx],
        "category": rng.choice(CATEGORIES, size=rows),
        "severity": rng.choice(SEVERITIES, size=rows, p=SEVERITY_P),
        "created_ts": created,
        "ack_ts": ack,
        "closed_ts": closed,
        "disposition": rng.choice(DISPOSITIONS, size=rows, p=DISPOSITION_P),
    })

    # --- cases: 1:1 with alerts ---
    cases = pd.DataFrame({
        "case_id": [f"CASE-SC-{i:09d}" for i in range(rows)],
        "alert_id": alerts["alert_id"].to_numpy(),
        "analyst_id": [f"AN-{i % 48:02d}" for i in range(rows)],
        "opened_ts": ack,
        "closed_ts": closed,
        "status": np.where(rng.random(rows) < 0.97, "closed", "in_progress"),
        "closure_code": rng.choice(["remediated", "false_positive", "accepted_risk"], size=rows),
        "notes_text": rng.choice(
            ["Reviewed and triaged.", "Indicator matched known benign host.", "Contained per playbook."],
            size=rows,
        ),
    })

    # --- workflow events: 1:1 triage event per case (keeps memory bounded) ---
    workflow = pd.DataFrame({
        "case_id": cases["case_id"].to_numpy(),
        "step": rng.choice(STEPS, size=rows),
        "actor_role": rng.choice(["analyst", "senior_analyst", "lead"], size=rows),
        "ts": ack + np.full(rows, np.timedelta64(300, "s")),
    })

    # --- escalations: ~12.5% of cases ---
    esc_mask = (np.arange(rows) % 8) == 0
    escalations = pd.DataFrame({
        "case_id": cases["case_id"].to_numpy()[esc_mask],
        "from_tier": np.full(int(esc_mask.sum()), "tier1"),
        "to_tier": np.full(int(esc_mask.sum()), "tier2"),
        "ts": ack[esc_mask] + np.timedelta64(3600, "s"),
        "outcome": np.where(np.arange(int(esc_mask.sum())) % 3 == 0, "escalated_up", "acknowledged"),
    })

    counts = {
        "alerts": rows,
        "cases": rows,
        "workflow_events": len(workflow),
        "assets": n_assets,
        "escalations": int(esc_mask.sum()),
        "entities": entities_n,
    }
    try:
        import polars as pl

        def _write(frame: pd.DataFrame, path: Path) -> None:
            # polars engine: works even when pyarrow's parquet DLL is
            # blocked by host application-control policies.
            pl.from_pandas(frame).write_parquet(path)

    except Exception:  # pragma: no cover - defensive

        def _write(frame: pd.DataFrame, path: Path) -> None:
            frame.to_parquet(path, index=False)

    for name, frame in (
        ("alerts", alerts), ("cases", cases), ("workflow_events", workflow),
        ("escalations", escalations), ("assets", assets), ("entities", entities),
    ):
        _write(frame, out_dir / f"{name}.parquet")

    print(f"[generate] {rows:,} alerts + companions -> {out_dir} in {time.perf_counter() - t0:.1f}s")
    return counts


# ------------------------------------------------------------------
# Step-timing capture from pipeline logs
# ------------------------------------------------------------------
class StepLog(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.events: List[Tuple[float, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.events.append((time.perf_counter(), record.getMessage()))


def print_step_breakdown(handler: StepLog) -> None:
    marks = [(t, m) for t, m in handler.events if "Step " in m or "successfully completed" in m]
    if not marks:
        return
    print("\n[steps]")
    prev_t = marks[0][0]
    for t, msg in marks:
        print(f"  +{t - prev_t:7.2f}s  {msg}")
        prev_t = t


# ------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SAT-SA scale benchmark (1M+ alerts, CPU-only, offline)")
    ap.add_argument("--rows", type=int, default=1_000_000, help="alert rows to generate (default 1,000,000)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--data-dir", type=str, default=None, help="benchmark an existing canonical data dir (skips generation)")
    ap.add_argument("--keep", action="store_true", help="keep generated data instead of deleting it")
    args = ap.parse_args()

    tmp_root: Optional[Path] = None
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        tmp_root = Path(tempfile.mkdtemp(prefix="satsa_scale_"))
        data_dir = tmp_root / "data"
        generate_scale_dataset(data_dir, rows=args.rows, seed=args.seed)
    out_dir = (tmp_root or data_dir.parent) / "output"

    from satsa.pipeline import run_all

    handler = StepLog()
    root = logging.getLogger()
    root.addHandler(handler)
    prev_level = root.level
    root.setLevel(logging.INFO)

    t0 = time.perf_counter()
    try:
        result = run_all(data_dir=data_dir, output_dir=out_dir, seed=args.seed)
    finally:
        root.removeHandler(handler)
        root.setLevel(prev_level)

    wall = time.perf_counter() - t0
    n_alerts = len(result.bundle.alerts)
    print_step_breakdown(handler)
    print("\n[scale benchmark results]")
    print(f"  alert rows ingested : {n_alerts:,}")
    print(f"  pipeline runtime    : {result.runtime_seconds:.2f}s (pipeline measured) / {wall:.2f}s (wall)")
    print(f"  throughput          : {n_alerts / max(result.runtime_seconds, 1e-9):,.0f} alerts/s")
    print(f"  findings emitted    : {len(result.findings):,}")
    print(f"  quarantined rows    : {len(result.bundle.quarantine):,}")
    print(f"  entities scored     : {len(result.scores)}")
    print(f"  queued for review   : {sum(len(q) for q in result.queues.values()):,}")
    print(f"  store tables        : {len(list((out_dir / 'store').glob('*.parquet')))} parquet")
    print(f"  peak process memory : {peak_rss_mb():.0f} MB")

    if tmp_root and not args.keep:
        shutil.rmtree(tmp_root, ignore_errors=True)
    elif tmp_root:
        print(f"  kept data at        : {tmp_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

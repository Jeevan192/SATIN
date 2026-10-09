"""Data ingestion, validation, and quarantine routing for SAT-SA.

Loads canonical CSV/JSON tables or adapts legacy data formats.
Validates types, timestamp ordering, duplicate primary keys, and referential integrity.
Routes invalid rows to quarantine.csv without halting execution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from satsa.config import PATHS, DetectorThresholds
from satsa.schemas import REQUIRED_COLUMNS, VALID_SEVERITIES


@dataclass
class DataBundle:
    """Validated data tables ready for supervisory feature extraction and analytics."""
    alerts: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["alerts"]))
    cases: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["cases"]))
    workflow_events: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["workflow_events"]))
    escalations: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["escalations"]))
    assets: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["assets"]))
    entities: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=REQUIRED_COLUMNS["entities"]))
    quarantine: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(
        columns=["table_name", "record_id", "quarantine_reason", "row_data", "quarantined_at"]
    ))
    # Memoization slot for expensive derived frames (alert/entity/asset features).
    # Invalidation is explicit: call invalidate_cache() after mutating any table.
    feature_cache: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def cached(self, key: str, factory) -> Any:
        """Return a lazily computed, per-bundle memoized value."""
        if key not in self.feature_cache:
            self.feature_cache[key] = factory()
        return self.feature_cache[key]

    def invalidate_cache(self) -> None:
        """Drop memoized feature frames (call after in-place table mutation)."""
        self.feature_cache.clear()

    def summary(self) -> Dict[str, int]:
        """Return counts of valid records per table and quarantined records."""
        return {
            "alerts": len(self.alerts),
            "cases": len(self.cases),
            "workflow_events": len(self.workflow_events),
            "escalations": len(self.escalations),
            "assets": len(self.assets),
            "entities": len(self.entities),
            "quarantined": len(self.quarantine),
        }


PRIMARY_KEYS: Dict[str, str] = {
    "alerts": "alert_id",
    "cases": "case_id",
    "workflow_events": "",
    "escalations": "",
    "assets": "asset_id",
    "entities": "entity_id",
}


def _read_parquet(path: Path) -> pd.DataFrame:
    """Read a canonical Parquet table.

    Polars first: its Rust engine is unaffected by host application-control
    policies that may block pyarrow's ``_parquet`` native library (observed on
    hardened Windows images). Falls back to pandas/pyarrow elsewhere.
    """
    try:
        import polars as pl

        return pl.read_parquet(path).to_pandas()
    except Exception:
        return pd.read_parquet(path)


def quarantine_rows(
    table_name: str,
    df: pd.DataFrame,
    mask: pd.Series,
    reason: str,
    id_col: Optional[str] = None
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split dataframe by mask. Rows matching mask are sent to quarantine records."""
    if not mask.any():
        return df, pd.DataFrame(columns=["table_name", "record_id", "quarantine_reason", "row_data", "quarantined_at"])

    bad_df = df[mask].copy()
    good_df = df[~mask].copy()

    # Vectorized emission: materialize records once instead of DataFrame.iterrows()
    # (iterrows boxes every row into a Series, which dominates ingest time at scale).
    now = datetime.now(timezone.utc).isoformat()
    bad_records = bad_df.to_dict(orient="records")
    has_id_col = bool(id_col) and id_col in df.columns
    rec_ids = [str(r.get(id_col, "")) for r in bad_records] if has_id_col else [""] * len(bad_records)
    row_jsons = [
        json.dumps({k: (str(v) if pd.notna(v) else None) for k, v in r.items()}, default=str)
        for r in bad_records
    ]
    records = [
        {
            "table_name": table_name,
            "record_id": rec_id,
            "quarantine_reason": reason,
            "row_data": row_json,
            "quarantined_at": now,
        }
        for rec_id, row_json in zip(rec_ids, row_jsons)
    ]

    quarantine_df = pd.DataFrame(records)
    return good_df, quarantine_df


def adapt_legacy_sample_alerts(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Adapt old data/sample_alerts.csv schema to canonical alerts, cases, workflow_events, escalations."""
    df = df.copy()
    col_map = {
        "cse_id": "entity_id",
        "alert_type": "category",
        "alert_time": "created_ts",
        "ack_time": "ack_ts",
        "closure_time": "closed_ts",
    }
    df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})

    # Ensure required alert columns
    if "severity" in df.columns:
        df["severity"] = df["severity"].astype(str).str.lower()
    if "disposition" not in df.columns:
        df["disposition"] = "unresolved"

    alerts_cols = [c for c in REQUIRED_COLUMNS["alerts"] if c in df.columns]
    alerts_df = df[alerts_cols].copy()

    # Synthesize cases (records materialized once; avoids per-row Series boxing)
    cases_records = []
    workflow_records = []
    escalation_records = []

    for row in df.to_dict(orient="records"):
        a_id = str(row["alert_id"])
        c_id = f"CASE-{a_id}"
        inv_start = row.get("investigation_start", row.get("ack_ts", row.get("created_ts")))
        close_t = row.get("closed_ts", inv_start)
        notes = row.get("investigation_notes", "")
        cases_records.append({
            "case_id": c_id,
            "alert_id": a_id,
            "analyst_id": "analyst-01",
            "opened_ts": inv_start,
            "closed_ts": close_t,
            "status": "closed",
            "closure_code": "resolved" if str(row.get("root_cause_found", "")).lower() in ("yes", "true", "1") else "standard",
            "notes_text": str(notes) if pd.notna(notes) else "",
        })

        # Workflow event
        workflow_records.append({
            "case_id": c_id,
            "step": "investigation",
            "actor_role": "analyst",
            "ts": inv_start,
        })

        # Escalation if marked Yes
        if str(row.get("escalated", "")).lower() in ("yes", "true", "1"):
            escalation_records.append({
                "case_id": c_id,
                "from_tier": "Tier-1",
                "to_tier": "Tier-2",
                "ts": inv_start,
                "outcome": "escalated",
            })

    cases_df = pd.DataFrame(cases_records)
    wf_df = pd.DataFrame(workflow_records)
    esc_df = pd.DataFrame(escalation_records)
    return alerts_df, cases_df, wf_df, esc_df


def adapt_legacy_asset_inventory(df: pd.DataFrame) -> pd.DataFrame:
    """Adapt old data/asset_inventory.csv schema to canonical assets table."""
    df = df.copy()
    col_map = {
        "cse_id": "entity_id",
        "expected_monitoring": "monitoring_expected",
    }
    df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
    if "monitoring_expected" in df.columns:
        df["monitoring_expected"] = df["monitoring_expected"].astype(str).str.lower().isin(["yes", "true", "1"])
    if "criticality" in df.columns:
        df["criticality"] = df["criticality"].astype(str).str.lower()
    return df


def validate_table(table_name: str, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Vectorized validation of types, timestamps, categories, and duplicates."""
    quarantine_frames: List[pd.DataFrame] = []
    if df.empty:
        return df, pd.DataFrame(columns=["table_name", "record_id", "quarantine_reason", "row_data", "quarantined_at"])

    df = df.copy()
    req_cols = REQUIRED_COLUMNS[table_name]
    id_col = PRIMARY_KEYS.get(table_name, "")

    # Check required columns
    missing = [c for c in req_cols if c not in df.columns]
    if missing:
        # If mandatory columns are completely missing, quarantine all
        mask = pd.Series([True] * len(df), index=df.index)
        df, q = quarantine_rows(table_name, df, mask, f"Missing required columns: {missing}", id_col)
        return df, q

    # Check primary key null or duplicate
    if id_col and id_col in df.columns:
        null_id = df[id_col].isna() | (df[id_col].astype(str).str.strip() == "")
        df, q = quarantine_rows(table_name, df, null_id, f"Missing primary key {id_col}", id_col)
        quarantine_frames.append(q)

        dup_id = df.duplicated(subset=[id_col], keep="first")
        df, q = quarantine_rows(table_name, df, dup_id, f"Duplicate primary key {id_col}", id_col)
        quarantine_frames.append(q)

    # Validate timestamps
    ts_cols = [c for c in df.columns if c.endswith("_ts") or c == "ts"]
    for col in ts_cols:
        parsed = pd.to_datetime(df[col], errors="coerce")
        bad_ts = parsed.isna()
        df, q = quarantine_rows(table_name, df, bad_ts, f"Unparseable timestamp in column '{col}'", id_col)
        quarantine_frames.append(q)
        df[col] = pd.to_datetime(df[col])

    # Table-specific validations
    if table_name == "alerts":
        # Timestamp ordering: created_ts <= ack_ts <= closed_ts
        bad_order1 = df["created_ts"] > df["ack_ts"]
        df, q = quarantine_rows(table_name, df, bad_order1, "Timestamp ordering violation: created_ts > ack_ts", id_col)
        quarantine_frames.append(q)

        bad_order2 = df["ack_ts"] > df["closed_ts"]
        df, q = quarantine_rows(table_name, df, bad_order2, "Timestamp ordering violation: ack_ts > closed_ts", id_col)
        quarantine_frames.append(q)

        # Severity domain check
        df["severity"] = df["severity"].astype(str).str.strip().str.lower()
        bad_sev = ~df["severity"].isin(VALID_SEVERITIES)
        df, q = quarantine_rows(table_name, df, bad_sev, "Invalid severity tier", id_col)
        quarantine_frames.append(q)

    elif table_name == "cases":
        bad_case_order = df["opened_ts"] > df["closed_ts"]
        df, q = quarantine_rows(table_name, df, bad_case_order, "Timestamp ordering violation: opened_ts > closed_ts", id_col)
        quarantine_frames.append(q)

    elif table_name == "assets":
        df["criticality"] = df["criticality"].astype(str).str.strip().str.lower()
        bad_crit = ~df["criticality"].isin(VALID_SEVERITIES)
        df, q = quarantine_rows(table_name, df, bad_crit, "Invalid asset criticality tier", id_col)
        quarantine_frames.append(q)

        if "monitoring_expected" in df.columns:
            df["monitoring_expected"] = df["monitoring_expected"].astype(bool)

    combined_quarantine = (
        pd.concat(quarantine_frames, ignore_index=True)
        if quarantine_frames
        else pd.DataFrame(columns=["table_name", "record_id", "quarantine_reason", "row_data", "quarantined_at"])
    )
    return df, combined_quarantine


def enforce_referential_integrity(bundle: DataBundle) -> DataBundle:
    """Validate cross-table foreign key relationships and route orphan records to quarantine."""
    quarantines: List[pd.DataFrame] = [bundle.quarantine]

    # Ensure all entities present in entities table
    known_entities = set(bundle.entities["entity_id"].dropna().unique())

    # Alerts -> Entities & Assets
    if not bundle.alerts.empty and known_entities:
        bad_ent = ~bundle.alerts["entity_id"].isin(known_entities)
        bundle.alerts, q = quarantine_rows("alerts", bundle.alerts, bad_ent, "Referential integrity: entity_id not in entities", "alert_id")
        quarantines.append(q)

    # Cases -> Alerts
    if not bundle.cases.empty and not bundle.alerts.empty:
        valid_alerts = set(bundle.alerts["alert_id"].dropna().unique())
        bad_alert_fk = ~bundle.cases["alert_id"].isin(valid_alerts)
        bundle.cases, q = quarantine_rows("cases", bundle.cases, bad_alert_fk, "Referential integrity: alert_id not in alerts", "case_id")
        quarantines.append(q)

    # Workflow events -> Cases
    if not bundle.workflow_events.empty and not bundle.cases.empty:
        valid_cases = set(bundle.cases["case_id"].dropna().unique())
        bad_case_fk = ~bundle.workflow_events["case_id"].isin(valid_cases)
        bundle.workflow_events, q = quarantine_rows("workflow_events", bundle.workflow_events, bad_case_fk, "Referential integrity: case_id not in cases")
        quarantines.append(q)

    # Escalations -> Cases
    if not bundle.escalations.empty and not bundle.cases.empty:
        valid_cases = set(bundle.cases["case_id"].dropna().unique())
        bad_esc_fk = ~bundle.escalations["case_id"].isin(valid_cases)
        bundle.escalations, q = quarantine_rows("escalations", bundle.escalations, bad_esc_fk, "Referential integrity: case_id not in cases")
        quarantines.append(q)

    bundle.quarantine = pd.concat(quarantines, ignore_index=True) if quarantines else pd.DataFrame()
    return bundle


def load_dataset(
    data_source: Union[str, Path, Dict[str, pd.DataFrame]],
    quarantine_output_path: Optional[Union[str, Path]] = None,
) -> DataBundle:
    """Load, validate, adapt, and quarantine dataset tables.

    Accepts:
    - Path to directory containing canonical CSV/JSON or legacy CSV files.
    - Dict of raw DataFrames.

    Guarantees that corrupt rows are quarantined and the pipeline proceeds without crashing.
    """
    raw_tables: Dict[str, pd.DataFrame] = {}

    if isinstance(data_source, dict):
        raw_tables = {k: v.copy() for k, v in data_source.items()}
    else:
        src_dir = Path(data_source)
        if not src_dir.exists():
            raise FileNotFoundError(f"Input directory does not exist: {src_dir}")

        for name in REQUIRED_COLUMNS.keys():
            csv_path = src_dir / f"{name}.csv"
            json_path = src_dir / f"{name}.json"
            parquet_path = src_dir / f"{name}.parquet"
            if parquet_path.exists():
                # Canonical Parquet store (preferred: columnar, schema-stable,
                # and what the scale layer writes at 1M+ rows).
                raw_tables[name] = _read_parquet(parquet_path)
            elif csv_path.exists():
                raw_tables[name] = pd.read_csv(csv_path)
            elif json_path.exists():
                raw_tables[name] = pd.read_json(json_path)

        # Check for legacy formats if canonical tables not found
        legacy_alerts = src_dir / "sample_alerts.csv"
        legacy_assets = src_dir / "asset_inventory.csv"

        if "alerts" not in raw_tables and legacy_alerts.exists():
            legacy_df = pd.read_csv(legacy_alerts)
            a_df, c_df, wf_df, esc_df = adapt_legacy_sample_alerts(legacy_df)
            raw_tables["alerts"] = a_df
            raw_tables["cases"] = c_df
            raw_tables["workflow_events"] = wf_df
            raw_tables["escalations"] = esc_df

        if "assets" not in raw_tables and legacy_assets.exists():
            asset_df = pd.read_csv(legacy_assets)
            raw_tables["assets"] = adapt_legacy_asset_inventory(asset_df)

    # If entities table is missing, infer entities from alerts and assets
    if "entities" not in raw_tables or raw_tables["entities"].empty:
        known_ids = set()
        if "alerts" in raw_tables and "entity_id" in raw_tables["alerts"].columns:
            known_ids.update(raw_tables["alerts"]["entity_id"].dropna().unique())
        if "assets" in raw_tables and "entity_id" in raw_tables["assets"].columns:
            known_ids.update(raw_tables["assets"]["entity_id"].dropna().unique())

        ent_rows = [
            {"entity_id": eid, "sector": "financial", "size_band": "Tier-1", "soc_model": "in-house"}
            for eid in sorted(known_ids)
        ]
        raw_tables["entities"] = pd.DataFrame(ent_rows) if ent_rows else pd.DataFrame(columns=REQUIRED_COLUMNS["entities"])

    # Ensure all tables exist
    for tbl in REQUIRED_COLUMNS.keys():
        if tbl not in raw_tables:
            raw_tables[tbl] = pd.DataFrame(columns=REQUIRED_COLUMNS[tbl])

    # Validate each table individually
    validated_tables: Dict[str, pd.DataFrame] = {}
    quarantine_list: List[pd.DataFrame] = []

    for name, df in raw_tables.items():
        v_df, q_df = validate_table(name, df)
        validated_tables[name] = v_df
        if not q_df.empty:
            quarantine_list.append(q_df)

    initial_quarantine = (
        pd.concat(quarantine_list, ignore_index=True)
        if quarantine_list
        else pd.DataFrame(columns=["table_name", "record_id", "quarantine_reason", "row_data", "quarantined_at"])
    )

    bundle = DataBundle(
        alerts=validated_tables.get("alerts", pd.DataFrame()),
        cases=validated_tables.get("cases", pd.DataFrame()),
        workflow_events=validated_tables.get("workflow_events", pd.DataFrame()),
        escalations=validated_tables.get("escalations", pd.DataFrame()),
        assets=validated_tables.get("assets", pd.DataFrame()),
        entities=validated_tables.get("entities", pd.DataFrame()),
        quarantine=initial_quarantine,
    )

    # Referential integrity pass
    bundle = enforce_referential_integrity(bundle)

    # Persist quarantine output if specified or default
    out_q_path = Path(quarantine_output_path) if quarantine_output_path else PATHS.quarantine_file
    if not bundle.quarantine.empty:
        out_q_path.parent.mkdir(parents=True, exist_ok=True)
        bundle.quarantine.to_csv(out_q_path, index=False)

    return bundle

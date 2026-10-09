"""Canonical Parquet store and DuckDB query layer for SAT-SA.

Blueprint section 2: "CANONICAL STORE: Parquet + DuckDB (columnar, local, fast)".

The store is the columnar, air-gapped persistence layer for the six canonical
tables. It exists for two reasons:

1. **Scale** -- Parquet is compressed and column-chunked, so loading a 10M-row
   alerts table reads only the columns a detector needs, and Polars/DuckDB
   operate on Arrow buffers without Python-level row loops.
2. **Drill-down** -- examiners and validation scripts can run arbitrary offline
   SQL over the exact audited inputs (``query()``), with no database server.

Everything here is local-filesystem only: no network, no SaaS, no daemon.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union

import pandas as pd

from satsa.ingest import DataBundle
from satsa.schemas import REQUIRED_COLUMNS

try:  # Polars is a hard dependency (requirements.txt) but we degrade gracefully.
    import polars as pl

    _HAS_POLARS = True
except Exception:  # pragma: no cover - defensive
    pl = None
    _HAS_POLARS = False

try:  # DuckDB is a hard dependency for the SQL drill-down layer.
    import duckdb

    _HAS_DUCKDB = True
except Exception:  # pragma: no cover - defensive
    duckdb = None
    _HAS_DUCKDB = False


TABLE_NAMES: List[str] = list(REQUIRED_COLUMNS.keys())
STORE_SUFFIX = ".parquet"


def _to_pandas(df: "pl.DataFrame") -> pd.DataFrame:
    """Arrow-backed pandas conversion with a pandas-version-safe fallback."""
    try:
        return df.to_pandas()
    except TypeError:  # pragma: no cover - older/newer polars signature
        return df.to_pandas(use_pyarrow_extension_array=False)


def write_bundle(bundle: DataBundle, store_dir: Union[str, Path]) -> Dict[str, Path]:
    """Persist all canonical tables of a bundle as Parquet files.

    Returns a mapping of table name -> written file path. Empty tables are
    written too (schema-stable store layout).
    """
    store_p = Path(store_dir)
    store_p.mkdir(parents=True, exist_ok=True)

    tables = {
        "alerts": bundle.alerts,
        "cases": bundle.cases,
        "workflow_events": bundle.workflow_events,
        "escalations": bundle.escalations,
        "assets": bundle.assets,
        "entities": bundle.entities,
        "quarantine": bundle.quarantine,
    }

    written: Dict[str, Path] = {}
    for name, df in tables.items():
        out = store_p / f"{name}{STORE_SUFFIX}"
        frame = df if df is not None else pd.DataFrame()
        if _HAS_POLARS:
            try:
                pl.from_pandas(frame).write_parquet(out)
                written[name] = out
                continue
            except Exception:
                # All-object empty frames can be untyped for Arrow; fall through
                # to pyarrow's direct pandas writer which infers null columns.
                pass
        frame.to_parquet(out, index=False)
        written[name] = out
    return written


def read_table(store_dir: Union[str, Path], table: str, columns: Optional[List[str]] = None) -> pd.DataFrame:
    """Read one canonical table (optionally only selected columns) from the store."""
    path = Path(store_dir) / f"{table}{STORE_SUFFIX}"
    if not path.exists():
        return pd.DataFrame(columns=REQUIRED_COLUMNS.get(table, []))
    if _HAS_POLARS:
        try:
            return _to_pandas(pl.read_parquet(path, columns=columns))
        except Exception:
            pass
    return pd.read_parquet(path, columns=columns)


def list_tables(store_dir: Union[str, Path]) -> List[str]:
    """Return table names present in the store directory."""
    store_p = Path(store_dir)
    return sorted(p.stem for p in store_p.glob(f"*{STORE_SUFFIX}")) if store_p.exists() else []


def load_bundle(store_dir: Union[str, Path]) -> DataBundle:
    """Load a full DataBundle from the canonical Parquet store."""
    return DataBundle(
        alerts=read_table(store_dir, "alerts"),
        cases=read_table(store_dir, "cases"),
        workflow_events=read_table(store_dir, "workflow_events"),
        escalations=read_table(store_dir, "escalations"),
        assets=read_table(store_dir, "assets"),
        entities=read_table(store_dir, "entities"),
        quarantine=read_table(store_dir, "quarantine"),
    )


def query(store_dir: Union[str, Path], sql: str) -> pd.DataFrame:
    """Run offline SQL over the store's Parquet files via in-process DuckDB.

    Tables are exposed as relations named after the files (e.g. ``alerts``,
    ``cases``). Example::

        query(store, "SELECT entity_id, count(*) c FROM alerts GROUP BY 1 ORDER BY c DESC LIMIT 5")
    """
    if not _HAS_DUCKDB:
        raise RuntimeError(
            "DuckDB is unavailable in this environment; install duckdb to enable SQL drill-down."
        )
    store_p = Path(store_dir)
    con = duckdb.connect(database=":memory:")
    try:
        for name in list_tables(store_p):
            # Views over local parquet files: no copies, no server, no network.
            safe = name.replace('"', "")
            path_lit = str(store_p / f"{safe}{STORE_SUFFIX}").replace("'", "''")
            con.execute(
                f"CREATE VIEW \"{safe}\" AS SELECT * FROM read_parquet('{path_lit}')"
            )
        return con.execute(sql).fetch_df()
    finally:
        con.close()


def store_summary(store_dir: Union[str, Path]) -> Dict[str, int]:
    """Row counts per table (DuckDB metadata scan, cheap on large stores)."""
    store_p = Path(store_dir)
    summary: Dict[str, int] = {}
    for name in list_tables(store_p):
        path = store_p / f"{name}{STORE_SUFFIX}"
        if _HAS_DUCKDB:
            con = duckdb.connect(database=":memory:")
            try:
                summary[name] = int(
                    con.execute("SELECT count(*) FROM read_parquet(?)", [str(path)]).fetchone()[0]
                )
            finally:
                con.close()
        else:  # pragma: no cover - defensive
            summary[name] = int(len(pd.read_parquet(path)))
    return summary

"""Tests for the canonical Parquet store + DuckDB query layer (satsa.store)."""

import numpy as np
import pandas as pd
import pytest

from satsa.ingest import DataBundle
from satsa.store import (
    TABLE_NAMES,
    list_tables,
    load_bundle,
    query,
    read_table,
    store_summary,
    write_bundle,
)


@pytest.fixture
def bundle():
    alerts = pd.DataFrame({
        "alert_id": [f"A-{i}" for i in range(10)],
        "entity_id": ["E1"] * 6 + ["E2"] * 4,
        "asset_id": ["AST-1"] * 5 + ["AST-2"] * 5,
        "category": ["malware"] * 10,
        "severity": ["critical", "high", "medium", "low"] * 2 + ["high", "low"],
        "created_ts": pd.date_range("2026-01-01", periods=10, freq="D"),
        "ack_ts": pd.date_range("2026-01-01 00:05", periods=10, freq="D"),
        "closed_ts": pd.date_range("2026-01-01 01:00", periods=10, freq="D"),
        "disposition": ["false_positive"] * 3 + ["true_positive"] * 7,
    })
    entities = pd.DataFrame({
        "entity_id": ["E1", "E2"],
        "sector": ["banking", "energy"],
        "size_band": ["Tier-1", "Tier-2"],
        "soc_model": ["in-house", "hybrid"],
        "claimed_mttc_min": [60.0, np.nan],
    })
    return DataBundle(alerts=alerts, entities=entities)


def test_write_creates_all_tables(tmp_path, bundle):
    written = write_bundle(bundle, tmp_path)
    names = list_tables(tmp_path)
    assert set(TABLE_NAMES) <= set(names)  # all canonical tables present
    assert all(p.suffix == ".parquet" for p in written.values())
    assert all(p.exists() for p in written.values())


def test_roundtrip_preserves_data(tmp_path, bundle):
    write_bundle(bundle, tmp_path)
    loaded = load_bundle(tmp_path)
    assert len(loaded.alerts) == 10
    assert len(loaded.entities) == 2
    pd.testing.assert_frame_equal(
        loaded.alerts.reset_index(drop=True),
        bundle.alerts.reset_index(drop=True),
        check_dtype=False,
    )
    # optional claim column survives; NaN stays NaN
    assert "claimed_mttc_min" in loaded.entities.columns
    assert np.isnan(loaded.entities.loc[loaded.entities.entity_id == "E2", "claimed_mttc_min"].iloc[0])


def test_column_projection_read(tmp_path, bundle):
    write_bundle(bundle, tmp_path)
    cols = read_table(tmp_path, "alerts", columns=["alert_id", "severity"])
    assert list(cols.columns) == ["alert_id", "severity"]
    assert len(cols) == 10


def test_read_missing_table_returns_empty(tmp_path):
    df = read_table(tmp_path, "alerts")
    assert df.empty
    assert "alert_id" in df.columns


def test_duckdb_query(tmp_path, bundle):
    from satsa.store import _HAS_DUCKDB

    if not _HAS_DUCKDB:
        pytest.skip("DuckDB is not installed in this environment")
    write_bundle(bundle, tmp_path)
    df = query(tmp_path, "SELECT entity_id, count(*) AS n FROM alerts GROUP BY 1 ORDER BY entity_id")
    assert list(df["entity_id"]) == ["E1", "E2"]
    assert list(df["n"]) == [6, 4]
    # SQL error propagates
    with pytest.raises(Exception):
        query(tmp_path, "SELECT * FROM does_not_exist")


def test_store_summary_counts(tmp_path, bundle):
    write_bundle(bundle, tmp_path)
    summary = store_summary(tmp_path)
    assert summary["alerts"] == 10
    assert summary["entities"] == 2
    assert summary["cases"] == 0      # empty canonical table still materialised

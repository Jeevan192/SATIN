"""Unit tests for SAT-SA canonical schema and ingestion pipeline (Phase 1)."""

import pandas as pd
import pytest
from satsa.ingest import load_dataset, validate_table, DataBundle
from satsa.schemas import AlertRecord, CaseRecord, AssetRecord


def test_schema_alert_validation():
    """Test individual AlertRecord pydantic model."""
    valid_alert = {
        "alert_id": "ALT-001",
        "entity_id": "CSE-01",
        "asset_id": "SRV-100",
        "category": "Malware Detection",
        "severity": "Critical",
        "created_ts": "2026-09-01T10:00:00Z",
        "ack_ts": "2026-09-01T10:05:00Z",
        "closed_ts": "2026-09-01T10:30:00Z",
        "disposition": "true_positive",
    }
    rec = AlertRecord(**valid_alert)
    assert rec.alert_id == "ALT-001"
    assert rec.severity == "critical"

    # Test timestamp ordering failure
    invalid_alert = dict(valid_alert, ack_ts="2026-09-01T09:59:00Z")
    with pytest.raises(ValueError, match="Timestamp violation"):
        AlertRecord(**invalid_alert)


def test_ingest_quarantines_invalid_rows(tmp_path):
    """Test that malformed rows are quarantined without halting ingestion."""
    alerts_data = pd.DataFrame([
        {
            "alert_id": "A1",
            "entity_id": "E1",
            "asset_id": "S1",
            "category": "Malware",
            "severity": "critical",
            "created_ts": "2026-09-01 10:00:00",
            "ack_ts": "2026-09-01 10:05:00",
            "closed_ts": "2026-09-01 10:20:00",
            "disposition": "true_positive",
        },
        {
            # Bad timestamp order: created > ack
            "alert_id": "A2_BAD_ORDER",
            "entity_id": "E1",
            "asset_id": "S1",
            "category": "Malware",
            "severity": "critical",
            "created_ts": "2026-09-01 10:10:00",
            "ack_ts": "2026-09-01 10:05:00",
            "closed_ts": "2026-09-01 10:20:00",
            "disposition": "true_positive",
        },
        {
            # Duplicate ID
            "alert_id": "A1",
            "entity_id": "E1",
            "asset_id": "S1",
            "category": "Malware",
            "severity": "high",
            "created_ts": "2026-09-01 11:00:00",
            "ack_ts": "2026-09-01 11:05:00",
            "closed_ts": "2026-09-01 11:20:00",
            "disposition": "true_positive",
        },
        {
            # Invalid severity
            "alert_id": "A3_BAD_SEV",
            "entity_id": "E1",
            "asset_id": "S1",
            "category": "Malware",
            "severity": "catastrophic_invalid",
            "created_ts": "2026-09-01 12:00:00",
            "ack_ts": "2026-09-01 12:05:00",
            "closed_ts": "2026-09-01 12:20:00",
            "disposition": "true_positive",
        },
    ])

    entities_data = pd.DataFrame([
        {"entity_id": "E1", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"}
    ])

    q_file = tmp_path / "quarantine.csv"
    bundle = load_dataset({
        "alerts": alerts_data,
        "entities": entities_data,
    }, quarantine_output_path=q_file)

    # Only A1 should survive in alerts
    assert len(bundle.alerts) == 1
    assert bundle.alerts.iloc[0]["alert_id"] == "A1"

    # Three alerts should be quarantined
    assert len(bundle.quarantine) == 3
    reasons = set(bundle.quarantine["quarantine_reason"])
    assert any("Timestamp ordering violation" in r for r in reasons)
    assert any("Duplicate primary key" in r for r in reasons)
    assert any("Invalid severity" in r for r in reasons)


def test_referential_integrity_quarantine(tmp_path):
    """Test that orphan cases and orphan workflow events are quarantined."""
    alerts_data = pd.DataFrame([
        {
            "alert_id": "A1",
            "entity_id": "E1",
            "asset_id": "S1",
            "category": "Phishing",
            "severity": "medium",
            "created_ts": "2026-09-01 10:00:00",
            "ack_ts": "2026-09-01 10:05:00",
            "closed_ts": "2026-09-01 10:20:00",
            "disposition": "false_positive",
        }
    ])
    cases_data = pd.DataFrame([
        {
            "case_id": "C1",
            "alert_id": "A1",
            "analyst_id": "analyst-01",
            "opened_ts": "2026-09-01 10:05:00",
            "closed_ts": "2026-09-01 10:20:00",
            "status": "closed",
            "closure_code": "resolved",
            "notes_text": "Normal investigation",
        },
        {
            "case_id": "C2_ORPHAN",
            "alert_id": "NON_EXISTENT_ALERT",
            "analyst_id": "analyst-01",
            "opened_ts": "2026-09-01 10:05:00",
            "closed_ts": "2026-09-01 10:20:00",
            "status": "closed",
            "closure_code": "resolved",
            "notes_text": "Orphan case",
        },
    ])
    entities_data = pd.DataFrame([
        {"entity_id": "E1", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"}
    ])

    bundle = load_dataset({
        "alerts": alerts_data,
        "cases": cases_data,
        "entities": entities_data,
    }, quarantine_output_path=tmp_path / "quarantine.csv")

    assert len(bundle.cases) == 1
    assert bundle.cases.iloc[0]["case_id"] == "C1"
    assert any("Referential integrity: alert_id not in alerts" in r for r in bundle.quarantine["quarantine_reason"])


def test_legacy_sample_alerts_load():
    """Verify legacy data/sample_alerts.csv and data/asset_inventory.csv load cleanly via adapter."""
    bundle = load_dataset("data")
    assert len(bundle.alerts) == 12
    assert len(bundle.assets) == 13
    assert len(bundle.cases) == 12
    assert len(bundle.entities) >= 3
    assert "CSE-001" in set(bundle.entities["entity_id"])
    assert "severity" in bundle.alerts.columns
    assert "created_ts" in bundle.alerts.columns
    assert "ack_ts" in bundle.alerts.columns
    assert "closed_ts" in bundle.alerts.columns

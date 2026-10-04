"""Unit tests for Phase 6: SHA-256 run manifest, hash-chained audit log, and tamper detection."""

import json
from pathlib import Path
import pytest

from satsa.audit import (
    append_audit_log,
    create_run_manifest,
    hash_dict,
    hash_file,
    verify_audit_chain,
)
from satsa.pipeline import run_all


def test_manifest_creation_and_reproducibility(tmp_path):
    """Verify run manifest creates deterministic hashes and captures input/config state."""
    f1 = tmp_path / "test_input.csv"
    f1.write_text("alert_id,created_ts\nA1,2026-09-01\n")
    h1 = hash_file(f1)
    assert len(h1) == 64

    manifest = create_run_manifest(
        run_id="RUN-TEST-001",
        input_files={"alerts": f1},
        output_files={},
        detector_versions={"EG-01": "1.0.0"},
        execution_summary={"count": 1},
    )

    assert manifest.run_id == "RUN-TEST-001"
    assert manifest.input_hashes["alerts"] == h1
    assert len(manifest.manifest_hash) == 64
    assert len(manifest.config_hash) == 64


def test_audit_chain_tamper_detection(tmp_path):
    """Verify hash-chained audit log detects tampering, insertion, and modification."""
    log_file = tmp_path / "audit_log.jsonl"

    # 1. Append 3 valid entries
    e1 = append_audit_log(log_file, "RUN", "RUN-1", "hash-1")
    e2 = append_audit_log(log_file, "RUN", "RUN-2", "hash-2")
    e3 = append_audit_log(log_file, "RUN", "RUN-3", "hash-3")

    assert e1.entry_id == 1
    assert e2.entry_id == 2
    assert e3.entry_id == 3
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash

    # Verify untampered chain
    valid, errors = verify_audit_chain(log_file)
    assert valid is True
    assert len(errors) == 0

    # 2. Tamper test: modify content in line 2
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    tampered_entry = json.loads(lines[1])
    tampered_entry["data_hash"] = "TAMPERED_HASH"
    lines[1] = json.dumps(tampered_entry) + "\n"

    tampered_file = tmp_path / "tampered_audit.jsonl"
    with open(tampered_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    valid_tamper, errors_tamper = verify_audit_chain(tampered_file)
    assert valid_tamper is False
    assert any("tampered" in err.lower() or "broken" in err.lower() for err in errors_tamper)


def test_pipeline_end_to_end(tmp_path):
    """Verify full end-to-end pipeline execution and output artifacts."""
    out_dir = tmp_path / "out"
    result = run_all(data_dir="data/synthetic", output_dir=out_dir, budget_per_entity=10, seed=42)

    assert result.run_id.startswith("RUN-")
    assert result.runtime_seconds > 0.0
    assert len(result.findings) > 0
    assert len(result.scores) == 12

    # Check output files exist
    assert (out_dir / "findings.json").exists()
    assert (out_dir / "entity_scores.json").exists()
    assert (out_dir / "review_queue.json").exists()
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "audit_log.jsonl").exists()

    # Verify audit chain of the pipeline run
    is_valid, errors = verify_audit_chain(out_dir / "audit_log.jsonl")
    assert is_valid is True
    assert len(errors) == 0


def test_offline_airgap_sandbox():
    """Verify that offline sandbox check executes and enforces air-gap isolation."""
    from satsa.offline_check import verify_offline_environment, is_loopback
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("8.8.8.8") is False

    success, msg = verify_offline_environment()
    assert success is True
    assert "air-gap sandbox verified" in msg.lower()

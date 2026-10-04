"""Unit tests for synthetic dataset generator and ground truth injections (Phase 2)."""

from pathlib import Path
import pandas as pd
import pytest

from satsa.ingest import load_dataset
from synth.generate import generate_synthetic_dataset, ENTITIES_CONFIG


def test_synthetic_determinism(tmp_path):
    """Verify generator is strictly deterministic with fixed seed."""
    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"

    ds1, gt1 = generate_synthetic_dataset(seed=42, scale=0.05, out_dir=dir1, days=30)
    ds2, gt2 = generate_synthetic_dataset(seed=42, scale=0.05, out_dir=dir2, days=30)

    assert len(ds1["alerts"]) == len(ds2["alerts"])
    assert len(gt1) == len(gt2)
    pd.testing.assert_frame_equal(ds1["alerts"], ds2["alerts"])
    pd.testing.assert_frame_equal(gt1, gt2)


def test_synthetic_canonical_ingestion(tmp_path):
    """Verify synthetic output strictly complies with canonical schema and produces 0 quarantine rows."""
    gen_dir = tmp_path / "synth_data"
    ds, gt = generate_synthetic_dataset(seed=123, scale=0.05, out_dir=gen_dir, days=30)

    # Ingest using canonical loader
    bundle = load_dataset(gen_dir, quarantine_output_path=tmp_path / "quarantine.csv")

    assert len(bundle.quarantine) == 0, f"Quarantined rows found: {bundle.quarantine[['table_name', 'quarantine_reason']].to_dict()}"
    assert len(bundle.entities) == 12
    assert len(bundle.alerts) > 500
    assert len(bundle.cases) > 500


def test_ground_truth_fault_coverage():
    """Verify all expected fault detectors (EG-01..08, NS-01..06) are injected with subtle/strong mix."""
    gt_file = Path("data/synthetic/ground_truth.csv")
    assert gt_file.exists(), "Ground truth file data/synthetic/ground_truth.csv must exist"
    gt = pd.read_csv(gt_file)

    expected_detectors = {
        "EG-01", "EG-02", "EG-03", "EG-04", "EG-05", "EG-06", "EG-07", "EG-08",
        "NS-01", "NS-02", "NS-03", "NS-04", "NS-05", "NS-06",
    }
    present_detectors = set(gt["detector_expected"].dropna().unique())
    missing = expected_detectors - present_detectors
    assert not missing, f"Missing detector injections in ground truth: {missing}"

    # Verify subtle and strong intensities present
    intensities = set(gt["intensity"].dropna().unique())
    assert "subtle" in intensities
    assert "strong" in intensities

    # Verify at least 3 clean control entities
    clean_entities = [e["entity_id"] for e in ENTITIES_CONFIG if len(e["faults"]) == 0]
    assert len(clean_entities) >= 3
    injected_entities = set(gt["entity_id"].dropna().unique())
    for c_ent in clean_entities:
        assert c_ent not in injected_entities, f"Clean control entity {c_ent} has injected faults!"

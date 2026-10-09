"""Tests for the Claim-vs-Reality Index (satsa.claim_reality)."""

import numpy as np
import pandas as pd
import pytest

from satsa.claim_reality import (
    compute_claim_reality,
    derive_evidence_metrics,
    summarize,
)
from satsa.ingest import DataBundle, load_dataset
from synth.generate import ENTITIES_CONFIG, generate_synthetic_dataset


@pytest.fixture(scope="module")
def tiny_dataset(tmp_path_factory):
    """Small deterministic synthetic dataset with injected KPI claims."""
    out = tmp_path_factory.mktemp("claims_data")
    generate_synthetic_dataset(seed=42, scale=0.08, out_dir=out, days=90)
    return load_dataset(out)


def test_all_entities_submit_claims(tiny_dataset):
    scores = compute_claim_reality(tiny_dataset)
    assert len(scores) == 12
    for s in scores.values():
        assert 0.0 <= s.index <= 100.0
        assert s.verdict in ("substantiated", "partially_substantiated", "materially_exaggerated")
        assert s.comparisons, "each entity should have at least one compared metric"


def test_clean_controls_vs_faulty_entities(tiny_dataset):
    """Controls claim honestly; the 8 fault-injected CSEs exaggerate."""
    scores = compute_claim_reality(tiny_dataset)
    controls = {e["entity_id"] for e in ENTITIES_CONFIG if e["role"] == "clean_control"}
    faulty = {e["entity_id"] for e in ENTITIES_CONFIG if e["role"] != "clean_control"}

    for eid in controls:
        assert scores[eid].verdict == "substantiated", f"{eid} should be substantiated (index={scores[eid].index})"
        assert scores[eid].index >= 85.0
    for eid in faulty:
        assert scores[eid].index < 85.0, f"{eid} should not be substantiated (index={scores[eid].index})"

    # Clear separation: every control outranks every faulty entity.
    assert min(scores[e].index for e in controls) > max(scores[e].index for e in faulty)


def test_faulty_claims_flatter_reality(tiny_dataset):
    """Exaggeration is signed positive (claim looks better than evidence)."""
    scores = compute_claim_reality(tiny_dataset)
    faulty = [e["entity_id"] for e in ENTITIES_CONFIG if e["role"] != "clean_control"]
    inflated = [
        c for eid in faulty for c in scores[eid].comparisons
        if c.metric in ("mttc_min", "fp_rate_pct") and c.exaggeration > 0
    ]
    assert inflated, "faulty entities must claim faster closure / lower FP rates than observed"


def test_evidence_derivation_edge_cases():
    """No alerts / no assets -> evidence is None, never a crash."""
    entities = pd.DataFrame({
        "entity_id": ["E1"],
        "sector": ["banking"],
        "size_band": ["Tier-1"],
        "soc_model": ["in-house"],
        "claimed_mttc_min": [30.0],
        "claimed_coverage_pct": [100.0],
        "claimed_fp_rate_pct": [5.0],
        "claimed_escalation_pct": [80.0],
    })
    bundle = DataBundle(entities=entities)
    evidence = derive_evidence_metrics(bundle)
    assert evidence["E1"] == {"mttc_min": None, "coverage_pct": None, "fp_rate_pct": None, "escalation_pct": None}
    # No comparable metrics -> entity omitted entirely
    assert compute_claim_reality(bundle) == {}


def test_entities_without_claim_columns_are_skipped():
    entities = pd.DataFrame({
        "entity_id": ["E1"],
        "sector": ["banking"],
        "size_band": ["Tier-1"],
        "soc_model": ["in-house"],
    })
    bundle = DataBundle(entities=entities)
    assert compute_claim_reality(bundle) == {}


def test_nan_claims_ignored(tiny_dataset):
    entities = tiny_dataset.entities.copy()
    entities["claimed_mttc_min"] = np.nan
    entities["claimed_coverage_pct"] = np.nan
    entities["claimed_fp_rate_pct"] = np.nan
    entities["claimed_escalation_pct"] = np.nan
    bundle = DataBundle(
        alerts=tiny_dataset.alerts,
        cases=tiny_dataset.cases,
        workflow_events=tiny_dataset.workflow_events,
        escalations=tiny_dataset.escalations,
        assets=tiny_dataset.assets,
        entities=entities,
    )
    assert compute_claim_reality(bundle) == {}


def test_summarize_shape(tiny_dataset):
    scores = compute_claim_reality(tiny_dataset)
    s = summarize(scores)
    assert s["entities_with_claims"] == 12
    assert isinstance(s["mean_index"], float)
    assert set(s["materially_exaggerated"]) <= set(scores.keys())
    assert summarize({})["entities_with_claims"] == 0

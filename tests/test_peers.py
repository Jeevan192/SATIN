"""Unit tests for feature extraction and peer cohort statistics (Phase 3)."""

import numpy as np
import pandas as pd
import pytest

from satsa.features import (
    calculate_entropy,
    calculate_gini,
    compute_alert_features,
    compute_asset_features,
    compute_entity_features,
)
from satsa.peers import (
    CohortManager,
    robust_z,
    percentile,
    expected_poisson_category_count,
    expected_volume_ratio,
)
from satsa.ingest import DataBundle


def test_gini_and_entropy_calculations():
    """Verify Gini coefficient and Shannon entropy implementations."""
    # Uniform distribution Gini should be near 0
    uniform_arr = np.array([10, 10, 10, 10, 10])
    assert calculate_gini(uniform_arr) == pytest.approx(0.0, abs=1e-3)

    # Concentrated distribution Gini should be high
    concentrated_arr = np.array([100, 0, 0, 0, 0])
    assert calculate_gini(concentrated_arr) > 0.75

    # Zero entropy for identical items
    assert calculate_entropy(["standard", "standard", "standard"]) == 0.0

    # Higher entropy for diverse items
    assert calculate_entropy(["code_a", "code_b", "code_c", "code_d"]) > 1.5


def test_robust_z_and_mad_zero_guard():
    """Verify robust_z computation and graceful guard against MAD=0."""
    cohort = [100.0, 100.0, 100.0, 100.0, 100.0]
    # In identical array, median=100, MAD=0. Same value should return z=0
    assert robust_z(100.0, cohort) == 0.0
    # Different value should yield deviation without ZeroDivisionError
    z_diff = robust_z(200.0, cohort)
    assert z_diff > 0.0
    assert not np.isnan(z_diff)

    # Standard distribution
    normal_cohort = [10.0, 20.0, 30.0, 40.0, 50.0]
    z_val = robust_z(50.0, normal_cohort)
    assert z_val > 1.0


def test_percentile_computation():
    """Verify empirical percentile rank boundaries."""
    cohort = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert percentile(10.0, cohort) == pytest.approx(0.10, abs=0.05)
    assert percentile(30.0, cohort) == pytest.approx(0.50, abs=0.05)
    assert percentile(50.0, cohort) == pytest.approx(0.90, abs=0.05)


def test_poisson_category_suppression():
    """Verify Poisson test flags absent or suppressed category counts."""
    # Cohort has 200 exfiltration alerts out of 1000 total (20% rate)
    # Target entity has 500 alerts but 0 exfiltration alerts
    mu, p_val = expected_poisson_category_count(
        entity_category_count=0,
        entity_total_alerts=500,
        cohort_category_count=200,
        cohort_total_alerts=1000,
    )
    assert mu == pytest.approx(100.0, abs=1.0)
    assert p_val < 1e-10  # Highly significant absence!


def test_cohort_hierarchy_fallbacks():
    """Verify CohortManager primary, sector, and global fallback resolution."""
    entities = pd.DataFrame([
        {"entity_id": "E1", "sector": "banking", "size_band": "Tier-1"},
        {"entity_id": "E2", "sector": "banking", "size_band": "Tier-1"},
        {"entity_id": "E3", "sector": "banking", "size_band": "Tier-1"},
        {"entity_id": "E4", "sector": "banking", "size_band": "Tier-2"},
        {"entity_id": "E5", "sector": "energy", "size_band": "Tier-3"},
    ])

    mgr = CohortManager(entities, min_cohort_size=3)

    # E1 has 3 banking Tier-1 peers -> primary
    c1, lvl1 = mgr.get_cohort_entities("E1")
    assert lvl1 == "primary"
    assert len(c1) == 3

    # E4 has only 1 banking Tier-2 peer -> falls back to sector (4 banking entities)
    c4, lvl4 = mgr.get_cohort_entities("E4")
    assert lvl4 == "sector_fallback"
    assert len(c4) == 4

    # E5 has only 1 energy entity -> falls back to global (5 entities)
    c5, lvl5 = mgr.get_cohort_entities("E5")
    assert lvl5 == "global_fallback"
    assert len(c5) == 5

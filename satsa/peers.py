"""Peer cohort partitioning and robust statistical baselines for SAT-SA.

Partitions entities into cohorts (same sector & size band, with hierarchical fallbacks).
Provides robust MAD-based Z-scores, empirical percentiles, and expected count models
(Poisson for category suppression, quantile/median ratios for volume suppression).
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from scipy import stats

from satsa.config import THRESHOLDS


class CohortManager:
    """Manages peer cohort resolution and hierarchical cohort fallbacks."""

    def __init__(self, entities_df: pd.DataFrame, min_cohort_size: Optional[int] = None):
        self.entities_df = entities_df.copy()
        self.min_cohort_size = min_cohort_size or THRESHOLDS.min_cohort_size
        self._entity_map = {
            row["entity_id"]: row.to_dict()
            for _, row in self.entities_df.iterrows()
        }

    def get_cohort_entities(self, entity_id: str) -> Tuple[List[str], str]:
        """Resolve peer cohort entity IDs for a target entity.

        Returns:
            (cohort_entity_ids, fallback_level)
            fallback_level in ('primary', 'sector_fallback', 'global_fallback')
        """
        if entity_id not in self._entity_map:
            # If entity not found, fallback to all known entities
            all_ids = list(self._entity_map.keys())
            return all_ids, "global_fallback"

        target = self._entity_map[entity_id]
        sector = target.get("sector")
        size_band = target.get("size_band")

        # 1. Primary: Same sector and same size band
        primary = self.entities_df[
            (self.entities_df["sector"] == sector) &
            (self.entities_df["size_band"] == size_band)
        ]["entity_id"].tolist()

        if len(primary) >= self.min_cohort_size:
            return primary, "primary"

        # 2. Fallback 1: Same sector across all size bands
        sector_cohort = self.entities_df[
            self.entities_df["sector"] == sector
        ]["entity_id"].tolist()

        if len(sector_cohort) >= self.min_cohort_size:
            return sector_cohort, "sector_fallback"

        # 3. Fallback 2: Global portfolio across all entities
        global_cohort = self.entities_df["entity_id"].tolist()
        return global_cohort, "global_fallback"

    def get_cohort_slice(
        self,
        df: pd.DataFrame,
        entity_id: str,
        id_col: str = "entity_id"
    ) -> Tuple[pd.DataFrame, str]:
        """Return subset of dataframe corresponding to target entity's cohort peers."""
        if df.empty or id_col not in df.columns:
            return pd.DataFrame(), "empty"

        cohort_ids, fallback_level = self.get_cohort_entities(entity_id)
        sliced = df[df[id_col].isin(cohort_ids)].copy()
        return sliced, fallback_level


def robust_z(
    val: float,
    cohort_values: Union[List[float], np.ndarray, pd.Series],
    guard_mad: float = 1e-6
) -> float:
    """Calculate Modified Z-score using Median and Median Absolute Deviation (MAD).

    Z_robust = (x - median) / (1.4826 * MAD)
    Guards against MAD=0 when cohort values are largely identical.
    """
    arr = np.asarray(cohort_values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0 or np.isnan(val):
        return 0.0

    med = float(np.median(arr))
    abs_dev = np.abs(arr - med)
    mad = float(np.median(abs_dev))
    effective_scale = 1.4826 * mad

    if effective_scale < guard_mad:
        # Fallback to mean absolute deviation or std
        std = float(np.std(arr))
        if std >= guard_mad:
            effective_scale = std
        else:
            # If all values identical, non-zero difference indicates deviation
            diff = val - med
            if abs(diff) < guard_mad:
                return 0.0
            return float(np.sign(diff) * 3.0)

    z = (val - med) / effective_scale
    return float(np.clip(z, -10.0, 10.0))


def percentile(
    val: float,
    cohort_values: Union[List[float], np.ndarray, pd.Series]
) -> float:
    """Calculate empirical percentile rank of val within cohort (0.0 to 1.0)."""
    arr = np.asarray(cohort_values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0 or np.isnan(val):
        return 0.50

    pct = stats.percentileofscore(arr, val, kind="mean") / 100.0
    return float(np.clip(pct, 0.0, 1.0))


def expected_poisson_category_count(
    entity_category_count: int,
    entity_total_alerts: int,
    cohort_category_count: int,
    cohort_total_alerts: int
) -> Tuple[float, float]:
    """Model expected category count using Poisson distribution against peer cohort rate.

    Returns:
        (expected_count, p_value)
    """
    if entity_total_alerts <= 0 or cohort_total_alerts <= 0:
        return 0.0, 1.0

    cohort_rate = cohort_category_count / max(1, cohort_total_alerts)
    mu = float(cohort_rate * entity_total_alerts)

    if mu <= 0:
        return 0.0, 1.0

    # Cumulative probability of observing <= entity_category_count given expected mu
    p_val = float(stats.poisson.cdf(entity_category_count, mu))
    return mu, p_val


def expected_volume_ratio(
    entity_alerts_per_asset: float,
    cohort_alerts_per_asset: Union[List[float], np.ndarray, pd.Series]
) -> Tuple[float, float, float]:
    """Compute peer-relative alert volume ratio and robust Z-score.

    Returns:
        (cohort_median_per_asset, ratio_to_median, robust_z_score)
    """
    arr = np.asarray(cohort_alerts_per_asset, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return 0.0, 1.0, 0.0

    cohort_med = float(np.median(arr))
    ratio = float(entity_alerts_per_asset / cohort_med) if cohort_med > 0 else 1.0
    z = robust_z(entity_alerts_per_asset, arr)
    return cohort_med, ratio, z

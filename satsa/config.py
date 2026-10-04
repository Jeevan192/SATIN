"""Configuration module for SAT-SA.

Single source of truth for thresholds, weights, capability mappings, and paths.
No detector or module should hardcode thresholds.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal


@dataclass(frozen=True)
class PathConfig:
    """Paths used across SAT-SA offline pipelines."""
    data_dir: Path = Path("data")
    output_dir: Path = Path("data/output")
    synthetic_dir: Path = Path("data/synthetic")
    quarantine_file: Path = Path("data/output/quarantine.csv")
    ground_truth_file: Path = Path("data/synthetic/ground_truth.csv")
    run_manifest_file: Path = Path("data/output/run_manifest.json")
    audit_log_file: Path = Path("data/output/audit_log.jsonl")
    findings_file: Path = Path("data/output/findings.json")
    scores_file: Path = Path("data/output/entity_scores.json")
    queue_file: Path = Path("data/output/review_queue.json")
    validation_report_file: Path = Path("data/output/validation_report.md")


@dataclass(frozen=True)
class DetectorThresholds:
    """Statistical and heuristic thresholds for all detectors."""
    # Minimum cohort size for robust peer comparison (fallback to wider cohort if smaller)
    min_cohort_size: int = 3

    # EG-01: Closure speed anomaly
    eg01_z_thresh: float = -2.5
    eg01_percentile_thresh: float = 0.05
    eg01_min_alerts: int = 5

    # EG-02: Critical/High closed without escalation vs cohort expected rate
    eg02_z_thresh: float = -2.0
    eg02_min_critical_high: int = 5

    # EG-03: Acknowledged alerts with zero workflow events
    eg03_min_gap_seconds: int = 60

    # EG-04: Template-driven notes & entropy
    eg04_similarity_thresh: float = 0.90
    eg04_entropy_thresh: float = 1.0
    eg04_min_notes: int = 5

    # EG-05: Repeat alerts without remediation
    eg05_window_days: int = 7
    eg05_min_occurrences: int = 3

    # EG-06: Closure bunching at SLA boundaries / month ends
    eg06_spike_z_thresh: float = 2.5
    eg06_bimodality_p_thresh: float = 0.05

    # EG-07: Analyst closure concentration
    eg07_gini_thresh: float = 0.70
    eg07_top1_share_thresh: float = 0.50
    eg07_min_analysts: int = 3

    # EG-08: Disposition skew drift (CUSUM on false positive rate)
    eg08_cusum_thresh: float = 4.0
    eg08_cusum_drift: float = 0.5

    # NS-01: Monitored critical assets silent in period
    ns01_min_critical_tier: str = "critical"

    # NS-02: Expected alert categories absent or far below Poisson expectation
    ns02_poisson_p_thresh: float = 0.01

    # NS-03: Alerts without cases / cases without mandatory escalations
    ns03_require_case_severities: tuple = ("critical", "high")

    # NS-04: Alert volume below size-adjusted peer expectation
    ns04_volume_ratio_thresh: float = 0.45
    ns04_z_thresh: float = -1.5

    # NS-05: Silent operational periods (consecutive days with 0 alerts)
    ns05_consecutive_days_zero: int = 3

    # NS-06: Criticality-weighted monitoring coverage ratio vs peers
    ns06_coverage_z_thresh: float = -1.8

    # NOV-01: IsolationForest / LOF anomaly detection
    nov01_contamination: float = 0.08
    nov01_lof_neighbors: int = 5


@dataclass(frozen=True)
class CapabilityConfig:
    """Weights and detector associations for 8 SOC capability areas."""
    areas: List[str] = field(default_factory=lambda: [
        "detection",
        "investigation",
        "escalation",
        "response",
        "security_operations",
        "governance",
        "operational_discipline",
        "resilience",
    ])

    area_weights: Dict[str, float] = field(default_factory=lambda: {
        "detection": 0.18,
        "investigation": 0.16,
        "escalation": 0.14,
        "response": 0.12,
        "security_operations": 0.12,
        "governance": 0.10,
        "operational_discipline": 0.10,
        "resilience": 0.08,
    })

    detector_capability_map: Dict[str, List[str]] = field(default_factory=lambda: {
        "EG-01": ["investigation", "operational_discipline"],
        "EG-02": ["escalation", "governance"],
        "EG-03": ["investigation", "operational_discipline"],
        "EG-04": ["investigation", "governance"],
        "EG-05": ["response", "resilience"],
        "EG-06": ["operational_discipline", "governance"],
        "EG-07": ["security_operations", "governance"],
        "EG-08": ["detection", "governance"],
        "NS-01": ["detection", "security_operations"],
        "NS-02": ["detection", "operational_discipline"],
        "NS-03": ["escalation", "governance"],
        "NS-04": ["detection", "security_operations"],
        "NS-05": ["operational_discipline", "resilience"],
        "NS-06": ["security_operations", "resilience"],
        "NOV-01": ["security_operations", "detection"],
    })


@dataclass(frozen=True)
class SeverityWeights:
    """Multipliers applied to findings based on alert/entity severity context."""
    weights: Dict[str, float] = field(default_factory=lambda: {
        "low": 1.0,
        "medium": 2.0,
        "high": 3.0,
        "critical": 5.0,
    })


# Global immutable default instances
PATHS = PathConfig()
THRESHOLDS = DetectorThresholds()
CAPABILITIES = CapabilityConfig()
SEVERITY_WEIGHTS = SeverityWeights()

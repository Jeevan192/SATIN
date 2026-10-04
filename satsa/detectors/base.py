"""Base classes and data models for SAT-SA detectors."""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Dict, List, Literal, Optional
import pandas as pd

from satsa.ingest import DataBundle
from satsa.peers import CohortManager


FindingCategory = Literal["EXECUTION_GAP", "NEGATIVE_SPACE", "NOVEL"]


@dataclass
class Finding:
    """Structured supervisory finding produced by SAT-SA detectors."""
    finding_id: str
    detector_id: str
    detector_version: str
    category: FindingCategory
    entity_id: str
    scope: str
    severity_weight: float
    deviation: float
    peer_percentile: float
    confidence: float
    reason_text: str
    evidence_refs: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard JSON-serializable dictionary."""
        return asdict(self)


def generate_finding_id(detector_id: str, entity_id: str, scope: str) -> str:
    """Deterministically generate unique finding ID based on content hash."""
    seed_str = f"{detector_id}:{entity_id}:{scope}"
    h = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:12]
    return f"FND-{detector_id}-{h}"


class BaseDetector(ABC):
    """Abstract base class for all supervisory detectors."""

    detector_id: str = "BASE"
    detector_version: str = "1.0.0"
    category: FindingCategory = "EXECUTION_GAP"

    @abstractmethod
    def run(self, bundle: DataBundle, cohort_mgr: CohortManager) -> List[Finding]:
        """Execute detection across all entities in the bundle and return structured findings."""
        pass

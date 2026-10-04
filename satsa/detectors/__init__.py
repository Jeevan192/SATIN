"""SAT-SA Detectors package.

Modular detectors covering EXECUTION_GAP, NEGATIVE_SPACE, and NOVEL anomaly lanes.
"""

from satsa.detectors.base import Finding, BaseDetector
from satsa.detectors.execution_gaps import (
    EG01ClosureSpeedDetector,
    EG02EscalationDeficitDetector,
    EG03UnworkedAlertsDetector,
    EG04TemplateInvestigationDetector,
    EG05RepeatAlertsDetector,
    EG06SLABoundaryBunchingDetector,
    EG07AnalystConcentrationDetector,
    EG08DispositionSkewDriftDetector,
)
from satsa.detectors.negative_space import (
    NS01SilentCriticalAssetsDetector,
    NS02SuppressedCategoriesDetector,
    NS03OrphanAlertsCasesDetector,
    NS04SuppressedVolumeDetector,
    NS05SilentPeriodDetector,
    NS06CoverageDeficitDetector,
)
from satsa.detectors.anomaly import NOV01NoveltyDetector

ALL_DETECTORS = [
    EG01ClosureSpeedDetector,
    EG02EscalationDeficitDetector,
    EG03UnworkedAlertsDetector,
    EG04TemplateInvestigationDetector,
    EG05RepeatAlertsDetector,
    EG06SLABoundaryBunchingDetector,
    EG07AnalystConcentrationDetector,
    EG08DispositionSkewDriftDetector,
    NS01SilentCriticalAssetsDetector,
    NS02SuppressedCategoriesDetector,
    NS03OrphanAlertsCasesDetector,
    NS04SuppressedVolumeDetector,
    NS05SilentPeriodDetector,
    NS06CoverageDeficitDetector,
    NOV01NoveltyDetector,
]

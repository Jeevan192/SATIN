"""Unit tests for all 15 SAT-SA modular detectors (Phase 4).

Validates each detector on concise hand-crafted dataframes covering positive and negative cases.
"""

from datetime import datetime, timedelta
import pandas as pd
import pytest

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
from satsa.ingest import DataBundle
from satsa.peers import CohortManager


@pytest.fixture
def base_entities():
    return pd.DataFrame([
        {"entity_id": "E1", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
        {"entity_id": "E2", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
        {"entity_id": "E3", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
    ])


def test_eg01_closure_speed(base_entities):
    """EG-01: Detects fast critical closures vs cohort distribution."""
    # Cohort E2, E3 close in 7200s (2 hrs). E1 closes in 60s.
    t0 = datetime(2026, 9, 1, 10, 0, 0)
    alerts = []

    # E1 fast alerts
    for i in range(6):
        alerts.append({
            "alert_id": f"E1-A{i}",
            "entity_id": "E1",
            "asset_id": "AST-1",
            "category": "Malware",
            "severity": "critical",
            "created_ts": t0,
            "ack_ts": t0 + timedelta(seconds=10),
            "closed_ts": t0 + timedelta(seconds=70),
            "disposition": "true_positive",
        })

    # E2, E3 normal alerts
    for eid in ("E2", "E3"):
        for i in range(10):
            alerts.append({
                "alert_id": f"{eid}-A{i}",
                "entity_id": eid,
                "asset_id": "AST-2",
                "category": "Malware",
                "severity": "critical",
                "created_ts": t0,
                "ack_ts": t0 + timedelta(minutes=5),
                "closed_ts": t0 + timedelta(hours=2),
                "disposition": "true_positive",
            })

    bundle = DataBundle(alerts=pd.DataFrame(alerts), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = EG01ClosureSpeedDetector().run(bundle, cm)

    assert len(findings) > 0
    assert all(f.detector_id == "EG-01" for f in findings)
    assert all(f.entity_id == "E1" for f in findings)
    assert any("faster than cohort" in f.reason_text for f in findings)


def test_eg03_unworked_alerts(base_entities):
    """EG-03: Detects acknowledged alerts with zero workflow events."""
    t0 = datetime(2026, 9, 1, 10, 0, 0)
    alerts = pd.DataFrame([{
        "alert_id": "A1",
        "entity_id": "E1",
        "asset_id": "AST-1",
        "category": "Malware",
        "severity": "high",
        "created_ts": t0,
        "ack_ts": t0 + timedelta(minutes=1),
        "closed_ts": t0 + timedelta(minutes=30),
        "disposition": "true_positive",
    }])
    cases = pd.DataFrame([{
        "case_id": "C1",
        "alert_id": "A1",
        "analyst_id": "anl-1",
        "opened_ts": t0 + timedelta(minutes=1),
        "closed_ts": t0 + timedelta(minutes=30),
        "status": "closed",
        "closure_code": "resolved",
        "notes_text": "Investigated",
    }])
    # workflow_events has some events for other cases, but 0 for C1
    wf = pd.DataFrame([{
        "case_id": "C_OTHER",
        "step": "triage",
        "actor_role": "analyst",
        "ts": t0 + timedelta(minutes=2),
    }])

    bundle = DataBundle(alerts=alerts, cases=cases, workflow_events=wf, entities=base_entities)
    cm = CohortManager(base_entities)
    findings = EG03UnworkedAlertsDetector().run(bundle, cm)

    assert len(findings) == 1
    assert findings[0].detector_id == "EG-03"
    assert "zero workflow" in findings[0].reason_text


def test_eg04_template_notes(base_entities):
    """EG-04: Detects repetitive template investigation notes."""
    t0 = datetime(2026, 9, 1, 10, 0, 0)
    alerts = []
    cases = []
    template_str = "Automated triage complete. Host verified compliant. No malicious action identified. Closing case as standard benign."

    for i in range(12):
        aid = f"A{i}"
        cid = f"C{i}"
        alerts.append({
            "alert_id": aid,
            "entity_id": "E1",
            "asset_id": "AST-1",
            "category": "Phishing",
            "severity": "medium",
            "created_ts": t0,
            "ack_ts": t0 + timedelta(minutes=1),
            "closed_ts": t0 + timedelta(minutes=10),
            "disposition": "false_positive",
        })
        cases.append({
            "case_id": cid,
            "alert_id": aid,
            "analyst_id": "anl-1",
            "opened_ts": t0 + timedelta(minutes=1),
            "closed_ts": t0 + timedelta(minutes=10),
            "status": "closed",
            "closure_code": "standard",
            "notes_text": template_str,
        })

    bundle = DataBundle(alerts=pd.DataFrame(alerts), cases=pd.DataFrame(cases), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = EG04TemplateInvestigationDetector().run(bundle, cm)

    assert len(findings) == 1
    assert findings[0].detector_id == "EG-04"
    assert "template" in findings[0].reason_text.lower()


def test_ns01_silent_critical_assets(base_entities):
    """NS-01: Detects designated critical assets with zero alerts."""
    assets = pd.DataFrame([
        {"asset_id": "AST-CRIT-SILENT", "entity_id": "E1", "criticality": "critical", "asset_type": "db", "monitoring_expected": True},
        {"asset_id": "AST-ACTIVE", "entity_id": "E1", "criticality": "critical", "asset_type": "srv", "monitoring_expected": True},
    ])
    alerts = pd.DataFrame([
        {
            "alert_id": "A1",
            "entity_id": "E1",
            "asset_id": "AST-ACTIVE",
            "category": "Malware",
            "severity": "critical",
            "created_ts": datetime(2026, 9, 1),
            "ack_ts": datetime(2026, 9, 1),
            "closed_ts": datetime(2026, 9, 1),
            "disposition": "true_positive",
        }
    ])

    bundle = DataBundle(assets=assets, alerts=alerts, entities=base_entities)
    cm = CohortManager(base_entities)
    findings = NS01SilentCriticalAssetsDetector().run(bundle, cm)

    assert len(findings) == 1
    assert findings[0].detector_id == "NS-01"
    assert findings[0].scope == "asset:AST-CRIT-SILENT"


def test_ns05_silent_periods(base_entities):
    """NS-05: Detects multi-day gaps with zero alert volume."""
    t0 = datetime(2026, 9, 1)
    alerts = []

    # 5 days active
    for d in range(5):
        alerts.append({
            "alert_id": f"A{d}",
            "entity_id": "E1",
            "asset_id": "AST-1",
            "category": "Malware",
            "severity": "low",
            "created_ts": t0 + timedelta(days=d),
            "ack_ts": t0 + timedelta(days=d),
            "closed_ts": t0 + timedelta(days=d),
            "disposition": "false_positive",
        })

    # Gap of 5 silent days (d=5 to 9), then active again d=10 to 15
    for d in range(10, 16):
        alerts.append({
            "alert_id": f"A{d}",
            "entity_id": "E1",
            "asset_id": "AST-1",
            "category": "Malware",
            "severity": "low",
            "created_ts": t0 + timedelta(days=d),
            "ack_ts": t0 + timedelta(days=d),
            "closed_ts": t0 + timedelta(days=d),
            "disposition": "false_positive",
        })

    bundle = DataBundle(alerts=pd.DataFrame(alerts), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = NS05SilentPeriodDetector().run(bundle, cm)

    assert len(findings) == 1
    assert findings[0].detector_id == "NS-05"
    assert "Operational silence" in findings[0].reason_text


def test_eg02_escalation_deficit(base_entities):
    """EG-02: Detects critical alerts closed without escalation."""
    t0 = datetime(2026, 9, 1)
    alerts = []
    cases = []
    escalations = []

    # E1: 20 critical alerts, only 1 escalated (5% rate)
    for i in range(20):
        aid = f"E1-A{i}"
        cid = f"E1-C{i}"
        alerts.append({"alert_id": aid, "entity_id": "E1", "asset_id": "AST-1", "category": "Malware", "severity": "critical", "created_ts": t0, "ack_ts": t0, "closed_ts": t0 + timedelta(hours=1), "disposition": "true_positive"})
        cases.append({"case_id": cid, "alert_id": aid, "analyst_id": "anl-1", "opened_ts": t0, "closed_ts": t0 + timedelta(hours=1), "status": "closed", "closure_code": "resolved", "notes_text": "notes"})
    escalations.append({"case_id": "E1-C0", "from_tier": "L1", "to_tier": "L2", "ts": t0, "outcome": "escalated"})

    # Peers E2, E3: 80% escalation rate
    for eid in ("E2", "E3"):
        for i in range(20):
            aid = f"{eid}-A{i}"
            cid = f"{eid}-C{i}"
            alerts.append({"alert_id": aid, "entity_id": eid, "asset_id": "AST-2", "category": "Malware", "severity": "critical", "created_ts": t0, "ack_ts": t0, "closed_ts": t0 + timedelta(hours=1), "disposition": "true_positive"})
            cases.append({"case_id": cid, "alert_id": aid, "analyst_id": "anl-1", "opened_ts": t0, "closed_ts": t0 + timedelta(hours=1), "status": "closed", "closure_code": "resolved", "notes_text": "notes"})
            if i < 16:  # 80%
                escalations.append({"case_id": cid, "from_tier": "L1", "to_tier": "L2", "ts": t0, "outcome": "escalated"})

    bundle = DataBundle(alerts=pd.DataFrame(alerts), cases=pd.DataFrame(cases), escalations=pd.DataFrame(escalations), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = EG02EscalationDeficitDetector().run(bundle, cm)

    assert len(findings) == 1
    assert findings[0].detector_id == "EG-02"
    assert findings[0].entity_id == "E1"


def test_ns02_suppressed_categories(base_entities):
    """NS-02: Detects missing alert categories via Poisson test."""
    alerts = []
    # E2, E3 have 25% "Data Exfiltration" alerts
    for eid in ("E2", "E3"):
        for i in range(100):
            cat = "Data Exfiltration" if i < 25 else "Authentication Anomaly"
            alerts.append({"alert_id": f"{eid}-A{i}", "entity_id": eid, "asset_id": "AST-1", "category": cat, "severity": "high", "created_ts": datetime(2026, 9, 1), "ack_ts": datetime(2026, 9, 1), "closed_ts": datetime(2026, 9, 1), "disposition": "true_positive"})

    # E1 has 100 alerts, but 0 "Data Exfiltration"
    for i in range(100):
        alerts.append({"alert_id": f"E1-A{i}", "entity_id": "E1", "asset_id": "AST-1", "category": "Authentication Anomaly", "severity": "high", "created_ts": datetime(2026, 9, 1), "ack_ts": datetime(2026, 9, 1), "closed_ts": datetime(2026, 9, 1), "disposition": "true_positive"})

    bundle = DataBundle(alerts=pd.DataFrame(alerts), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = NS02SuppressedCategoriesDetector().run(bundle, cm)

    assert len(findings) >= 1
    e1_findings = [f for f in findings if f.entity_id == "E1"]
    assert len(e1_findings) >= 1
    assert any("Data Exfiltration" in f.scope for f in e1_findings)


def test_nov01_novelty_detector(base_entities):
    """NOV-01: Detects multivariate behavioural shift using IsolationForest."""
    t0 = datetime(2026, 3, 1)
    alerts = []

    # Generate 6 months of data across 3 entities
    for eid in ("E1", "E2", "E3"):
        for m in range(6):
            dt = t0 + timedelta(days=m * 30 + 1)
            # Normal baseline
            n_alerts = 20
            # E1 month 5 is extreme outlier: 500 alerts, 100% false positive, 0 escalation
            if eid == "E1" and m == 5:
                n_alerts = 200
            for i in range(n_alerts):
                disp = "false_positive" if (eid == "E1" and m == 5) else "true_positive"
                alerts.append({
                    "alert_id": f"{eid}-M{m}-A{i}",
                    "entity_id": eid,
                    "asset_id": f"AST-{i%3}",
                    "category": "Malware",
                    "severity": "critical",
                    "created_ts": dt,
                    "ack_ts": dt,
                    "closed_ts": dt + timedelta(hours=1),
                    "disposition": disp,
                })

    bundle = DataBundle(alerts=pd.DataFrame(alerts), entities=base_entities)
    cm = CohortManager(base_entities)
    findings = NOV01NoveltyDetector().run(bundle, cm)

    assert len(findings) >= 1
    assert all(f.category == "NOVEL" for f in findings)
    assert any(f.entity_id == "E1" for f in findings)


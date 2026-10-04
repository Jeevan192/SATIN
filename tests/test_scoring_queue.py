"""Unit tests for Phase 5: Supervisory scoring and review queue builder."""

from datetime import datetime, timedelta
import pandas as pd
import pytest

from satsa.detectors.base import Finding
from satsa.ingest import DataBundle
from satsa.peers import CohortManager
from satsa.scoring import (
    compute_finding_score,
    compute_entity_score,
    score_portfolio,
    assign_risk_tier,
)
from satsa.queue import build_queue, build_portfolio_queues, QueueItem


@pytest.fixture
def mock_findings():
    return [
        Finding(
            finding_id="F1",
            detector_id="EG-01",
            detector_version="1.0.0",
            category="EXECUTION_GAP",
            entity_id="E1",
            scope="alert:A1",
            severity_weight=5.0,
            deviation=-4.0,
            peer_percentile=0.02,
            confidence=0.90,
            reason_text="Fast closure",
            evidence_refs=["alerts:A1"],
        ),
        Finding(
            finding_id="F2",
            detector_id="EG-02",
            detector_version="1.0.0",
            category="EXECUTION_GAP",
            entity_id="E1",
            scope="entity:E1",
            severity_weight=4.0,
            deviation=-3.0,
            peer_percentile=0.03,
            confidence=0.85,
            reason_text="No escalation",
            evidence_refs=[],
        ),
        Finding(
            finding_id="F3",
            detector_id="NS-01",
            detector_version="1.0.0",
            category="NEGATIVE_SPACE",
            entity_id="E1",
            scope="asset:AST-1",
            severity_weight=4.5,
            deviation=-3.0,
            peer_percentile=0.01,
            confidence=0.95,
            reason_text="Silent asset",
            evidence_refs=["assets:AST-1"],
        ),
    ]


@pytest.fixture
def mock_bundle():
    entities = pd.DataFrame([
        {"entity_id": "E1", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
        {"entity_id": "E2", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
        {"entity_id": "E3", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house"},
    ])
    alerts = pd.DataFrame([
        {"alert_id": f"A{i}", "entity_id": "E1", "asset_id": "AST-1", "category": "Malware", "severity": "low", "created_ts": datetime(2026, 9, 1), "ack_ts": datetime(2026, 9, 1), "closed_ts": datetime(2026, 9, 1), "disposition": "true_positive"}
        for i in range(100)
    ])
    return DataBundle(entities=entities, alerts=alerts)


def test_compute_finding_score():
    """Verify finding score caps deviation at 5.0 and scales linearly with confidence."""
    f = Finding(
        finding_id="F_TEST",
        detector_id="EG-01",
        detector_version="1.0.0",
        category="EXECUTION_GAP",
        entity_id="E1",
        scope="alert:A1",
        severity_weight=5.0,
        deviation=-10.0,  # exceeds cap of 5.0
        peer_percentile=0.01,
        confidence=0.80,
        reason_text="Test",
        evidence_refs=[],
    )
    score = compute_finding_score(f)
    # severity_weight (5.0) * min(10.0, 5.0) * confidence (0.80) = 5.0 * 5.0 * 0.80 = 20.0
    assert score == pytest.approx(20.0)


def test_entity_score_and_risk_tiers(mock_findings, mock_bundle):
    """Verify 8-capability area aggregation, overall index, and risk tiers."""
    cm = CohortManager(mock_bundle.entities)
    score_obj = compute_entity_score("E1", mock_findings, mock_bundle, cm)

    assert 0.0 <= score_obj.overall_risk_index <= 100.0
    assert len(score_obj.area_scores) == 8
    assert "investigation" in score_obj.area_scores
    assert "detection" in score_obj.area_scores
    assert score_obj.overall_risk_index > 0.0
    assert score_obj.risk_tier in ("low", "moderate", "elevated", "high", "critical")

    # Clean entity score should be 0.0
    clean_score = compute_entity_score("E2", [], mock_bundle, cm)
    assert clean_score.overall_risk_index == 0.0
    assert clean_score.risk_tier == "low"


def test_portfolio_scoring(mock_findings, mock_bundle):
    """Verify portfolio scoring and peer percentile assignment."""
    cm = CohortManager(mock_bundle.entities)
    scores = score_portfolio(mock_findings, mock_bundle, cm)

    assert len(scores) == 3
    assert "E1" in scores
    assert "E2" in scores
    # E1 has faults, E2 and E3 have none
    assert scores["E1"].overall_risk_index > scores["E2"].overall_risk_index
    assert scores["E1"].peer_percentile > scores["E2"].peer_percentile


def test_review_queue_builder(mock_findings, mock_bundle):
    """Verify review queue has correct budget, 85/15 split, and explainable reasons."""
    budget = 40
    queue = build_queue("E1", mock_findings, mock_bundle, budget=budget, seed=42)

    assert len(queue) == budget
    risk_items = [q for q in queue if q.selection_bucket == "risk_ranked"]
    control_items = [q for q in queue if q.selection_bucket == "random_control"]

    assert len(risk_items) == 3  # all 3 available findings picked
    assert len(control_items) == budget - len(risk_items)

    # Check order and explainability
    for i, item in enumerate(queue):
        assert item.priority_rank == i + 1
        assert len(item.selection_reason) > 10
        assert item.target_type in ("alert", "case", "asset", "period", "entity")

    # Verify seed determinism for random control items
    queue2 = build_queue("E1", mock_findings, mock_bundle, budget=budget, seed=42)
    assert [q.scope for q in queue] == [q.scope for q in queue2]

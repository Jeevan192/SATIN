"""Tests for the examiner feedback loop (satsa.feedback)."""

import pytest

from satsa.detectors.base import Finding
from satsa.feedback import (
    FACTOR_FLOOR,
    apply_feedback,
    get_history,
    list_weights,
    record_feedback,
)
from satsa.scoring import compute_finding_score


def make_finding(fid="F-1", eid="E1", det="EG-01", dev=2.0, sev=2.0, conf=0.9):
    return Finding(
        finding_id=fid,
        detector_id=det,
        detector_version="1.0.0",
        category="EXECUTION_GAP",
        entity_id=eid,
        scope="asset:AST-1",
        severity_weight=sev,
        deviation=dev,
        peer_percentile=0.99,
        confidence=conf,
        reason_text="test",
        evidence_refs=["alert:A-1"],
    )


@pytest.fixture
def db(tmp_path):
    return tmp_path / "feedback.db"


def test_fresh_install_is_noop(db):
    f = make_finding()
    assert apply_feedback([f], db) == 0            # no database yet
    assert f.feedback_factor == 1.0
    assert list_weights(db) == []
    assert get_history(db_path=db) == []


def test_dismiss_downweights_with_floor(db):
    factors = []
    for _ in range(4):
        w = record_feedback("F-1", "E1", "EG-01", "dismiss", examiner="alice", db_path=db)
        factors.append(w["factor"])
    assert factors == [0.6, 0.36, pytest.approx(0.3, abs=1e-9), FACTOR_FLOOR]
    weights = list_weights(db)
    assert len(weights) == 1
    assert weights[0]["version"] == 4
    assert weights[0]["factor"] == FACTOR_FLOOR


def test_confirm_restores_weight(db):
    record_feedback("F-1", "E1", "EG-01", "dismiss", db_path=db)   # 0.6
    record_feedback("F-1", "E1", "EG-01", "dismiss", db_path=db)   # 0.36
    w = record_feedback("F-1", "E1", "EG-01", "confirm", db_path=db)
    assert w["factor"] == pytest.approx(0.6)      # one confirm reverses one dismiss
    assert w["version"] == 3
    # and it can never exceed neutral
    record_feedback("F-2", "E1", "EG-01", "confirm", db_path=db)
    w2 = record_feedback("F-2", "E1", "EG-01", "confirm", db_path=db)
    assert w2["factor"] == 1.0


def test_apply_scopes_to_entity_and_detector_pair(db):
    record_feedback("F-1", "E1", "EG-01", "dismiss", db_path=db)   # factor 0.6
    same_pair = make_finding(fid="F-2", eid="E1", det="EG-01")
    other_entity = make_finding(fid="F-3", eid="E2", det="EG-01")
    other_detector = make_finding(fid="F-4", eid="E1", det="NS-05")

    n = apply_feedback([same_pair, other_entity, other_detector], db)
    assert n == 1
    assert same_pair.feedback_factor == 0.6
    assert other_entity.feedback_factor == 1.0
    assert other_detector.feedback_factor == 1.0


def test_score_uses_feedback_factor(db):
    f = make_finding()
    baseline = compute_finding_score(f)                      # 2.0 * 2.0 * 0.9 = 3.6
    assert baseline == pytest.approx(3.6)
    record_feedback("F-1", "E1", "EG-01", "dismiss", db_path=db)
    apply_feedback([f], db)
    assert compute_finding_score(f) == pytest.approx(3.6 * 0.6)


def test_invalid_inputs_rejected(db):
    with pytest.raises(ValueError):
        record_feedback("F-1", "E1", "EG-01", "banana", db_path=db)
    with pytest.raises(ValueError):
        record_feedback("", "E1", "EG-01", "confirm", db_path=db)


def test_history_is_filtered_and_newest_first(db):
    record_feedback("F-1", "E1", "EG-01", "dismiss", examiner="a", db_path=db)
    record_feedback("F-1", "E1", "EG-01", "confirm", examiner="b", db_path=db)
    record_feedback("F-9", "E2", "NS-01", "dismiss", examiner="a", db_path=db)

    all_rows = get_history(db_path=db)
    assert len(all_rows) == 3
    assert all_rows[0]["feedback_id"] > all_rows[1]["feedback_id"]  # newest first

    assert len(get_history(finding_id="F-1", db_path=db)) == 2
    assert len(get_history(entity_id="E2", db_path=db)) == 1
    assert len(get_history(finding_id="F-1", entity_id="E2", db_path=db)) == 0

"""Tests for the new Phase-2/4 API surfaces: feedback, claim-reality, report."""

import pytest
from fastapi.testclient import TestClient

import satsa.feedback as feedback_mod
from backend.app import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def isolated_feedback_db(tmp_path, monkeypatch):
    """Never write examiner feedback into the repo's data/output/."""
    monkeypatch.setattr(feedback_mod, "DEFAULT_DB_PATH", tmp_path / "feedback.db")
    return tmp_path / "feedback.db"


def test_claim_reality_endpoint(client):
    res = client.get("/claim-reality")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data and "entities" in data
    if data["entities"]:
        first = next(iter(data["entities"].values()))
        assert "index" in first
        assert "verdict" in first
        assert "comparisons" in first


def test_report_html_endpoint(client):
    res = client.get("/report/html")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "<!DOCTYPE html" in res.text or "<!doctype html" in res.text.lower()
    assert "SAT-SA" in res.text


def test_report_pdf_endpoint(client):
    res = client.get("/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.headers["x-pdf-engine"] in ("weasyprint", "minipdf")
    assert res.content[:5] == b"%PDF-"
    assert res.content.rstrip().endswith(b"%%EOF")


def test_feedback_post_and_weight_lifecycle(client):
    res = client.post("/feedback", json={
        "finding_id": "F-1", "entity_id": "CSE-BANK-02", "detector_id": "EG-01",
        "decision": "dismiss", "examiner": "tester", "comment": "looks benign",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["factor"] == pytest.approx(0.6)
    assert body["version"] == 1
    assert body["decision"] == "dismiss"

    res = client.post("/feedback", json={
        "finding_id": "F-1", "entity_id": "CSE-BANK-02", "detector_id": "EG-01",
        "decision": "confirm", "examiner": "tester",
    })
    assert res.status_code == 200
    assert res.json()["factor"] == pytest.approx(1.0)
    assert res.json()["version"] == 2

    res = client.get("/feedback/weights")
    assert res.status_code == 200
    weights = res.json()["weights"]
    assert len(weights) == 1
    assert weights[0]["entity_id"] == "CSE-BANK-02"

    res = client.get("/feedback/history", params={"entity_id": "CSE-BANK-02"})
    assert res.status_code == 200
    history = res.json()["history"]
    assert len(history) == 2
    assert history[0]["feedback_id"] > history[1]["feedback_id"]


def test_feedback_validation_errors(client):
    # pydantic rejects unknown decisions
    res = client.post("/feedback", json={
        "finding_id": "F", "entity_id": "E", "detector_id": "D", "decision": "banana",
    })
    assert res.status_code == 422
    # missing fields
    res = client.post("/feedback", json={"finding_id": "F"})
    assert res.status_code == 422


def test_feedback_history_empty_is_200(client):
    res = client.get("/feedback/history")
    assert res.status_code == 200
    assert res.json() == {"history": []}

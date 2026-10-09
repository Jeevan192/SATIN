"""Tests for SAT-SA Offline FastAPI Backend."""

import pytest
from fastapi.testclient import TestClient

from backend.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["tool"] == "SAT-SA"
    assert data["mode"] == "offline"
    assert data["status"] == "operational"


def test_entities_endpoint(client):
    response = client.get("/entities")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "entities" in data
    assert data["count"] > 0
    first = data["entities"][0]
    assert "entity_id" in first
    assert "overall_risk_index" in first
    assert "risk_tier" in first


def test_entity_detail_endpoint(client):
    response = client.get("/entities/CSE-BANK-01")
    assert response.status_code == 200
    data = response.json()
    assert data["entity_id"] == "CSE-BANK-01"
    assert "area_scores" in data
    assert "overall_risk_index" in data

    # Test not found
    err_res = client.get("/entities/NONEXISTENT-ENTITY")
    assert err_res.status_code == 404


def test_entity_findings_endpoint(client):
    response = client.get("/entities/CSE-BANK-01/findings")
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_review_queue_endpoint(client):
    response = client.get("/queue/CSE-BANK-01?budget=10")
    assert response.status_code == 200
    data = response.json()
    assert data["entity_id"] == "CSE-BANK-01"
    assert data["budget"] == 10
    assert len(data["items"]) <= 10


def test_trends_endpoint(client):
    response = client.get("/trends")
    assert response.status_code == 200
    data = response.json()
    assert "total_entities" in data
    assert "area_averages" in data
    assert "risk_tier_distribution" in data


def test_audit_verify_endpoint(client):
    response = client.get("/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert "audit_chain_verified" in data
    assert data["audit_chain_verified"] is True
    assert data["error_count"] == 0


def test_validation_endpoint(client):
    response = client.get("/validation")
    assert response.status_code == 200
    data = response.json()
    assert "report_markdown" in data
    assert len(data["report_markdown"]) > 0

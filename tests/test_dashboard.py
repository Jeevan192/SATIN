"""Integration tests for the Streamlit dashboard (RBAC, pages, feedback gating)."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


@pytest.fixture
def at():
    test_at = AppTest.from_file(APP_PATH, default_timeout=180)
    test_at.run()
    assert not test_at.exception, f"dashboard failed to boot: {test_at.exception}"
    return test_at


def _login(test_at, username, password):
    """Submit the sidebar login form with the given credentials."""
    assert any(t.label == "Username" for t in test_at.text_input), "login form not rendered"
    test_at.text_input[0].set_value(username)
    test_at.text_input[1].set_value(password)
    sign_in = [b for b in test_at.button if b.label == "Sign In"]
    assert sign_in, "sign-in button missing"
    sign_in[0].set_value(True)
    test_at.run()
    assert not test_at.exception, f"exception after login: {test_at.exception}"


def _select_page(test_at, fragment):
    options = test_at.radio[0].options
    match = [p for p in options if fragment in p]
    assert match, f"page containing {fragment!r} not in nav: {options}"
    test_at.radio[0].set_value(match[0])
    test_at.run()
    assert not test_at.exception, f"exception on page {fragment}: {test_at.exception}"


def _button_labels(test_at):
    return [b.label for b in test_at.button]


def test_dashboard_boots_to_portfolio(at):
    assert at.title[0].value == "Portfolio Supervisory Overview"
    # unauthenticated: sign-in form visible, sign-out not
    assert any(t.label == "Username" for t in at.text_input)
    assert not any(b.label == "Sign out" for b in at.button)
    # KPI metrics rendered
    assert any("Entities" in m.label for m in at.metric)


def test_login_rejects_bad_credentials(at):
    _login(at, "supervisor", "definitely-wrong")
    assert any("Invalid credentials" in e.value for e in at.sidebar.error)
    # still signed out
    assert not any(s.value for s in at.sidebar.success)


def test_feedback_requires_supervisor_role(at):
    # 1) unauthenticated -> finding page has no confirm/dismiss buttons
    _select_page(at, "Finding Card")
    assert not any("Confirm Finding" in l for l in _button_labels(at))
    assert any("feedback" in i.value.lower() and "sign in" in i.value.lower() for i in at.info)

    # 2) supervisor -> buttons appear
    _login(at, "supervisor", "satsa2026")
    _select_page(at, "Finding Card")
    labels = _button_labels(at)
    assert any("Confirm Finding" in l for l in labels)
    assert any("Dismiss Finding" in l for l in labels)

    # 3) sign out, sign in as auditor -> read-only, no feedback buttons
    [b for b in at.button if b.label == "Sign out"][0].set_value(True)
    at.run()
    _login(at, "auditor", "satsa2026")
    _select_page(at, "Finding Card")
    labels = _button_labels(at)
    assert not any("Confirm Finding" in l for l in labels)
    assert not any("Dismiss Finding" in l for l in labels)
    assert any("feedback" in i.value.lower() for i in at.info)
    # auditor still sees the finding card itself (view permission)
    assert any("Examiner Feedback" in s.value for s in at.subheader)


def test_claim_reality_page_renders(at):
    _select_page(at, "Claim-vs-Reality")
    assert at.title[0].value == "Claim-vs-Reality Index"
    # 12 entities with claims in the committed synthetic dataset
    assert any("Entities With Claims" in m.label for m in at.metric)

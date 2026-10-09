"""Tests for local RBAC authentication (satsa.auth)."""

import pytest

import satsa.auth as auth_mod
from satsa.auth import (
    DEFAULT_PASSWORD,
    authenticate,
    bootstrap,
    change_password,
    has_permission,
    list_users,
)


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path, monkeypatch):
    """Route the auth vault + master key into tmp (never touch data/output)."""
    key = b"\x11" * 32
    monkeypatch.setattr(auth_mod, "load_or_create_key", lambda *a, **k: key)
    return tmp_path / "users.db"


def test_bootstrap_creates_default_users(isolated_vault):
    bootstrap(db_path=isolated_vault)
    users = list_users(db_path=isolated_vault)
    by_name = {u["username"]: u for u in users}
    assert set(by_name) == {"admin", "supervisor", "auditor"}
    assert by_name["admin"]["role"] == "administrator"
    assert by_name["supervisor"]["role"] == "supervisor"
    assert by_name["auditor"]["role"] == "auditor"
    # never leak hashes
    assert all("password_hash" not in u for u in users)
    # idempotent
    bootstrap(db_path=isolated_vault)
    assert len(list_users(db_path=isolated_vault)) == 3


def test_authentication_success_and_failure(isolated_vault):
    bootstrap(db_path=isolated_vault)
    user = authenticate("admin", DEFAULT_PASSWORD, db_path=isolated_vault)
    assert user == {"username": "admin", "role": "administrator"}
    # wrong password / unknown user / empty creds
    assert authenticate("admin", "nope", db_path=isolated_vault) is None
    assert authenticate("ghost", DEFAULT_PASSWORD, db_path=isolated_vault) is None
    assert authenticate("", "", db_path=isolated_vault) is None
    assert authenticate("admin", "", db_path=isolated_vault) is None


def test_permission_matrix():
    admin = {"username": "admin", "role": "administrator"}
    sup = {"username": "supervisor", "role": "supervisor"}
    aud = {"username": "auditor", "role": "auditor"}

    for who in (admin, sup, aud):
        assert has_permission(who, "view")
        assert has_permission(who, "export")

    assert has_permission(sup, "feedback") and has_permission(admin, "feedback")
    assert not has_permission(aud, "feedback")

    assert has_permission(admin, "run_pipeline")
    assert not has_permission(sup, "run_pipeline")
    assert not has_permission(aud, "run_pipeline")

    assert has_permission(admin, "manage_users")
    assert not has_permission(sup, "manage_users")

    # unauthenticated
    assert not has_permission(None, "view")
    assert not has_permission({}, "feedback")
    # unknown permission is deny-by-default
    assert not has_permission(admin, "nonexistent_permission")


def test_password_rotation(isolated_vault):
    bootstrap(db_path=isolated_vault)
    assert change_password("admin", DEFAULT_PASSWORD, "brand-new-secret", db_path=isolated_vault)
    assert authenticate("admin", "brand-new-secret", db_path=isolated_vault) is not None
    assert authenticate("admin", DEFAULT_PASSWORD, db_path=isolated_vault) is None
    # wrong old password
    assert not change_password("admin", "wrong-old", "another-secret-1", db_path=isolated_vault)
    # policy
    with pytest.raises(ValueError):
        change_password("admin", "brand-new-secret", "short", db_path=isolated_vault)


def test_authenticate_before_bootstrap_fails_cleanly(isolated_vault):
    """No vault yet -> authentication returns None (and bootstraps schema safely)."""
    assert authenticate("admin", DEFAULT_PASSWORD, db_path=isolated_vault) is None


def test_user_store_is_encrypted_at_rest(isolated_vault, monkeypatch):
    bootstrap(db_path=isolated_vault)
    raw = isolated_vault.read_bytes()
    assert not raw.startswith(b"SQLite format 3")
    assert DEFAULT_PASSWORD.encode() not in raw      # obviously not stored
    assert b"admin" not in raw                       # usernames encrypted too

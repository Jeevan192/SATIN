"""Local role-based access control (RBAC) for the SAT-SA dashboard/API.

Fully offline: users live in an **encrypted SQLite vault**
(:func:`satsa.secure_store.encrypted_sqlite`, key file ``keys/vault.key``);
passwords are stored as salted PBKDF2-HMAC-SHA256 hashes (stdlib ``hashlib``).
No directory service, no network auth, no third-party crypto.

Bootstrap users (created on first use, documented in README + docs/ENCRYPTION.md):

===========  ==============  =================================================
Username     Role            Default password
===========  ==============  =================================================
admin        administrator   satsa2026
supervisor   supervisor      satsa2026
auditor      auditor         satsa2026
===========  ==============  =================================================

Change these before any real deployment (``change_password``).
"""

from datetime import datetime, timezone
from hashlib import pbkdf2_hmac
import hmac
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional, Union

from satsa.config import PATHS
from satsa.secure_store import load_or_create_key, encrypted_sqlite

PBKDF2_ITERATIONS = 200_000
DEFAULT_PASSWORD = "satsa2026"
MIN_PASSWORD_LEN = 8

ROLES = ("administrator", "supervisor", "auditor")

# permission -> roles allowed
PERMISSIONS: Dict[str, set] = {
    "view": {"administrator", "supervisor", "auditor"},
    "export": {"administrator", "supervisor", "auditor"},
    "feedback": {"administrator", "supervisor"},     # confirm/dismiss findings
    "run_pipeline": {"administrator"},               # regenerate audited outputs
    "manage_users": {"administrator"},
}

DEFAULT_USERS: List[tuple] = [
    ("admin", "administrator"),
    ("supervisor", "supervisor"),
    ("auditor", "auditor"),
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('administrator', 'supervisor', 'auditor')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    password_changed_at TEXT
);
"""


def default_db_path() -> Path:
    return PATHS.output_dir / "users.db"


def _hash_password(password: str, salt: Optional[bytes] = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


def _vault(master: Optional[bytes] = None, db_path: Optional[Union[str, Path]] = None):
    """Encrypted SQLite context manager for the user store."""
    key = master if master is not None else load_or_create_key()
    path = Path(db_path) if db_path else default_db_path()
    return encrypted_sqlite(path, key)


def bootstrap(db_path: Optional[Union[str, Path]] = None) -> None:
    """Create the vault and default users on first use (idempotent).

    Password hashes are only computed when the store is actually empty, so
    repeated calls (every dashboard rerun) cost a single file round-trip.
    """
    with _vault(db_path=db_path) as con:
        con.executescript(_SCHEMA)
        n = con.execute("SELECT count(*) FROM users").fetchone()[0]
        if n:
            return
        now = datetime.now(timezone.utc).isoformat()
        for username, role in DEFAULT_USERS:
            con.execute(
                "INSERT OR IGNORE INTO users (username, role, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, role, _hash_password(DEFAULT_PASSWORD), now),
            )
        con.commit()


def authenticate(username: str, password: str, db_path: Optional[Union[str, Path]] = None) -> Optional[Dict[str, Any]]:
    """Validate credentials; returns ``{"username", "role"}`` or None."""
    username = (username or "").strip()
    if not username or not password:
        return None
    with _vault(db_path=db_path) as con:
        con.executescript(_SCHEMA)
        row = con.execute(
            "SELECT username, role, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        # Constant-ish work even for unknown users (timing hygiene, offline).
        _verify_password(password, _hash_password("decoy"))
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    return {"username": row["username"], "role": row["role"]}


def list_users(db_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    """All users (never returns hashes)."""
    with _vault(db_path=db_path) as con:
        con.executescript(_SCHEMA)
        rows = con.execute(
            "SELECT username, role, created_at, password_changed_at FROM users ORDER BY username"
        ).fetchall()
    return [dict(r) for r in rows]


def change_password(
    username: str,
    old_password: str,
    new_password: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Rotate a password after verifying the old one (>= 8 characters)."""
    if not new_password or len(new_password) < MIN_PASSWORD_LEN:
        raise ValueError(f"New password must be at least {MIN_PASSWORD_LEN} characters")
    with _vault(db_path=db_path) as con:
        con.executescript(_SCHEMA)
        row = con.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or not _verify_password(old_password, row["password_hash"]):
            return False
        con.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ? WHERE username = ?",
            (_hash_password(new_password), datetime.now(timezone.utc).isoformat(), username),
        )
        con.commit()
    return True


def role_of(user: Optional[Dict[str, Any]]) -> Optional[str]:
    """Role string for a user dict (None when unauthenticated)."""
    return (user or {}).get("role")


def has_permission(user: Optional[Dict[str, Any]], permission: str) -> bool:
    """Check whether an authenticated user may perform ``permission``."""
    role = role_of(user)
    if role is None:
        return False
    return role in PERMISSIONS.get(permission, set())

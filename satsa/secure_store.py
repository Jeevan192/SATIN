"""Encryption-at-rest utilities (stdlib-only, offline).

Design goal: demonstrate a complete key-management + encrypted-vault flow with
zero third-party crypto dependencies and zero network access, while being
honest about its limits. ``docs/ENCRYPTION.md`` specifies the production
hardening path (LUKS2 full-disk encryption, SQLCipher for SQLite).

Scheme (simulated, not production cryptography):

* Master key: 32 random bytes from a local key file (``keys/vault.key``) or a
  passphrase stretched with PBKDF2-HMAC-SHA256 (``hashlib.pbkdf2_hmac``).
* Subkeys: ``enc = HMAC-SHA256(master, b"enc")``, ``mac = HMAC-SHA256(master, b"mac")``.
* Keystream: HMAC-SHA256(enc_key, nonce || counter) blocks in counter mode,
  XORed with the plaintext (stream-cipher construction).
* Integrity: encrypt-then-MAC -- HMAC-SHA256 over header+ciphertext, verified
  with ``hmac.compare_digest`` *before* any decryption (tamper-evident).
* Random 16-byte salt + 16-byte nonce per encryption (no two blobs share a
  keystream).

``encrypted_sqlite`` provides a context-managed SQLite database whose bytes
are only ever persisted encrypted (plaintext working copy lives in a private
temp file for the duration of the session and is deleted on close).
"""

from contextlib import contextmanager
from hashlib import pbkdf2_hmac
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
from typing import Iterator, Optional, Union

MAGIC = b"STSv"          # SAT-SA vault
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 16
MAC_LEN = 32
KEY_LEN = 32
PBKDF2_ITERATIONS = 200_000
_HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN  # magic | version | salt | nonce

DEFAULT_KEY_PATH = Path("keys") / "vault.key"


# --------------------------------------------------
# Key handling
# --------------------------------------------------
def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Stretch a passphrase into a 32-byte master key (PBKDF2-HMAC-SHA256)."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    if len(salt) < 8:
        raise ValueError("salt too short (>= 8 bytes required)")
    return pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_LEN)


def load_or_create_key(key_path: Union[str, Path] = DEFAULT_KEY_PATH) -> bytes:
    """Load the local vault key file, creating it (0600) on first use."""
    p = Path(key_path)
    if p.exists():
        key = bytes.fromhex(p.read_text(encoding="utf-8").strip())
        if len(key) != KEY_LEN:
            raise ValueError(f"Key file {p} is malformed (expected {KEY_LEN} bytes hex)")
        return key
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_LEN)
    p.write_text(key.hex() + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # best-effort on Windows; documented in ENCRYPTION.md
    except OSError:
        pass
    return key


def _subkeys(master: bytes) -> tuple:
    enc = hmac.new(master, b"enc", "sha256").digest()
    mac = hmac.new(master, b"mac", "sha256").digest()
    return enc, mac


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 counter-mode keystream block generation."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), "sha256").digest()
        counter += 1
    return bytes(out[:length])


# --------------------------------------------------
# Encrypt / decrypt primitives
# --------------------------------------------------
def encrypt_bytes(data: bytes, master: bytes) -> bytes:
    """Encrypt-then-MAC: ``MAGIC | version | salt | nonce | ciphertext | tag``."""
    if not master or len(master) != KEY_LEN:
        raise ValueError(f"master key must be {KEY_LEN} bytes")
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    enc_key, mac_key = _subkeys(master)

    keystream = _keystream(enc_key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    header = MAGIC + bytes([VERSION]) + salt + nonce
    tag = hmac.new(mac_key, header + ciphertext, "sha256").digest()
    return header + ciphertext + tag


def decrypt_bytes(blob: bytes, master: bytes) -> bytes:
    """Verify MAC first (fail-closed), then decrypt."""
    if len(master) != KEY_LEN:
        raise ValueError(f"master key must be {KEY_LEN} bytes")
    if len(blob) < _HEADER_LEN + MAC_LEN:
        raise ValueError("ciphertext too short")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("not a SAT-SA vault blob (bad magic)")
    if blob[len(MAGIC)] != VERSION:
        raise ValueError(f"unsupported vault version {blob[len(MAGIC)]}")

    header = blob[:_HEADER_LEN]
    ciphertext = blob[_HEADER_LEN:-MAC_LEN]
    tag = blob[-MAC_LEN:]

    enc_key, mac_key = _subkeys(master)
    expected = hmac.new(mac_key, header + ciphertext, "sha256").digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("MAC verification failed: blob was tampered with or key is wrong")

    nonce = header[len(MAGIC) + 1 + SALT_LEN:]
    keystream = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


def encrypt_file(path: Union[str, Path], master: bytes, out_path: Optional[Union[str, Path]] = None) -> Path:
    """Encrypt a file in place (or to ``out_path``) and return the target path."""
    p = Path(path)
    target = Path(out_path) if out_path else p
    target.write_bytes(encrypt_bytes(p.read_bytes(), master))
    return target


def decrypt_file(path: Union[str, Path], master: bytes, out_path: Optional[Union[str, Path]] = None) -> Path:
    """Decrypt a vault file to ``out_path`` (default: strip ``.enc`` / in place)."""
    p = Path(path)
    target = Path(out_path) if out_path else p
    target.write_bytes(decrypt_bytes(p.read_bytes(), master))
    return target


# --------------------------------------------------
# Encrypted SQLite vault
# --------------------------------------------------
@contextmanager
def encrypted_sqlite(
    db_path: Union[str, Path],
    master: bytes,
) -> Iterator[sqlite3.Connection]:
    """Context-managed SQLite database persisted only in encrypted form.

    On entry the stored blob (if any) is decrypted into a private temporary
    file; on exit the database is flushed, re-encrypted, and the plaintext
    working copy is deleted. Production deployments should use SQLCipher
    instead so no plaintext temp file ever exists (see docs/ENCRYPTION.md).
    """
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(prefix="satsa_vault_", suffix=".db")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        if p.exists() and p.stat().st_size > 0:
            tmp.write_bytes(decrypt_bytes(p.read_bytes(), master))

        con = sqlite3.connect(tmp)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
            con.execute("PRAGMA journal_mode=DELETE")  # drop plaintext -journal sidecar
            con.close()

            data = tmp.read_bytes()
            if data:
                p.write_bytes(encrypt_bytes(data, master))
        finally:
            con.close()  # must happen before the temp file is removed (Windows)
    finally:
        tmp.unlink(missing_ok=True)
        Path(str(tmp) + "-journal").unlink(missing_ok=True)

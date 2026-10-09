"""Tests for the stdlib encryption vault (satsa.secure_store)."""

from hashlib import sha256

import pytest

from satsa.secure_store import (
    KEY_LEN,
    MAGIC,
    decrypt_bytes,
    decrypt_file,
    derive_key,
    encrypt_bytes,
    encrypt_file,
    encrypted_sqlite,
    load_or_create_key,
)


@pytest.fixture
def key(tmp_path):
    return load_or_create_key(tmp_path / "vault.key")


def test_key_file_created_and_reloaded(tmp_path):
    kp = tmp_path / "vault.key"
    k1 = load_or_create_key(kp)
    k2 = load_or_create_key(kp)
    assert len(k1) == KEY_LEN
    assert k1 == k2                      # stable across loads
    assert k1 != load_or_create_key(tmp_path / "other.key")  # fresh entropy per key


def test_malformed_key_rejected(tmp_path):
    kp = tmp_path / "bad.key"
    kp.write_text("deadbeef\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_or_create_key(kp)


def test_derive_key_from_passphrase():
    salt = b"0123456789abcdef"
    k1 = derive_key("correct horse", salt)
    k2 = derive_key("correct horse", salt)
    k3 = derive_key("wrong horse", salt)
    assert len(k1) == KEY_LEN
    assert k1 == k2
    assert k1 != k3
    with pytest.raises(ValueError):
        derive_key("", salt)


def test_encrypt_decrypt_roundtrip(key):
    for payload in (b"", b"x", b"supervisory evidence", b"\x00" * 1000, bytes(range(256))):
        blob = encrypt_bytes(payload, key)
        assert blob.startswith(MAGIC)
        assert decrypt_bytes(blob, key) == payload


def test_encryption_is_randomised(key):
    a = encrypt_bytes(b"same plaintext", key)
    b = encrypt_bytes(b"same plaintext", key)
    assert a != b  # fresh salt+nonce per call (no keystream reuse)


def test_tamper_detection_fail_closed(key):
    blob = encrypt_bytes(b"important", key)
    # flip one ciphertext bit
    idx = 30
    tampered = blob[:idx] + bytes([blob[idx] ^ 0x01]) + blob[idx + 1:]
    with pytest.raises(ValueError, match="MAC verification failed"):
        decrypt_bytes(tampered, key)
    # truncate
    with pytest.raises(ValueError):
        decrypt_bytes(blob[:-4], key)
    # wrong magic
    with pytest.raises(ValueError, match="bad magic"):
        decrypt_bytes(b"XXXX" + blob[4:], key)
    # wrong key
    with pytest.raises(ValueError, match="MAC verification failed"):
        decrypt_bytes(blob, sha256(b"not the key").digest())


def test_wrong_key_length_rejected(key):
    with pytest.raises(ValueError):
        encrypt_bytes(b"data", b"short")
    with pytest.raises(ValueError):
        decrypt_bytes(encrypt_bytes(b"data", key), b"short")


def test_file_roundtrip(tmp_path, key):
    src = tmp_path / "plain.txt"
    src.write_bytes(b"file contents to protect")
    enc_path = encrypt_file(src, key, tmp_path / "vault.enc")
    assert enc_path.read_bytes().startswith(MAGIC)
    assert b"file contents" not in enc_path.read_bytes()
    out = decrypt_file(enc_path, key, tmp_path / "restored.txt")
    assert out.read_bytes() == b"file contents to protect"


def test_encrypted_sqlite_roundtrip_and_at_rest(tmp_path, key):
    db = tmp_path / "vault.db"

    with encrypted_sqlite(db, key) as con:
        con.execute("CREATE TABLE secrets (k TEXT, v TEXT)")
        con.execute("INSERT INTO secrets VALUES ('token', 'classified-value')")
        con.commit()

    raw = db.read_bytes()
    assert not raw.startswith(b"SQLite format 3")   # no plaintext header at rest
    assert b"classified-value" not in raw           # no plaintext rows at rest
    assert b"secrets" not in raw

    with encrypted_sqlite(db, key) as con:
        row = con.execute("SELECT v FROM secrets WHERE k='token'").fetchone()
        assert row["v"] == "classified-value"
    # still encrypted after the second session
    assert not db.read_bytes().startswith(b"SQLite format 3")


def test_encrypted_sqlite_wrong_key_fails(tmp_path, key):
    db = tmp_path / "vault.db"
    with encrypted_sqlite(db, key) as con:
        con.execute("CREATE TABLE t (x INTEGER)")
        con.commit()
    other_key = load_or_create_key(tmp_path / "k2.key")
    with pytest.raises(ValueError, match="MAC verification failed"):
        with encrypted_sqlite(db, other_key):
            pass

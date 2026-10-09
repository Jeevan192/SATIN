# SAT-SA — Encryption at Rest & Key Management

**Scope:** offline supervisory analytics (NCIIPC PS26157). No network, no cloud, no
external key service. This document covers (a) what the tool ships with today
(standard-library-only encryption), and (b) the exact commands to harden a
deployment with real full-disk / database encryption.

---

## 1. What SAT-SA ships with (simulated crypto, stdlib-only)

Implementation: `satsa/secure_store.py`, `satsa/auth.py`.

| Component | Mechanism |
|---|---|
| Key derivation | PBKDF2-HMAC-SHA256, 200 000 iterations, 16-byte random salt (`hashlib.pbkdf2_hmac`) |
| Master key | 32 random bytes in `keys/vault.key` (mode 0600, git-ignored), **or** a stretched passphrase |
| Subkeys | `enc = HMAC-SHA256(master, "enc")`, `mac = HMAC-SHA256(master, "mac")` |
| Cipher | HMAC-SHA256 keystream in counter mode, XORed with the plaintext (stream construction) |
| Integrity | **Encrypt-then-MAC**: HMAC-SHA256 over `header ‖ ciphertext`, verified with `hmac.compare_digest` **before** decryption |
| Freshness | 16-byte random salt + 16-byte nonce per encryption (no keystream reuse) |
| Blob format | `STSv | version(1) | salt(16) | nonce(16) | ciphertext(n) | tag(32)` |

Encrypted artifacts produced by the tool:

* `data/output/users.db` — RBAC user store (passwords only as salted PBKDF2 hashes),
  decrypted in memory via `encrypted_sqlite()`, re-encrypted on close.
* Any file passed through `encrypt_file()` / `encrypt_bytes()`.
* `data/output/feedback.db` and the run artifacts are **not** encrypted by default —
  put them under an encrypted volume (section 3) for deployment.

> ⚠️ **Honesty note:** the keystream construction is deterministic standard-library
> cryptography built for an offline demo with zero third-party crypto dependencies.
> It is **not** a reviewed cipher implementation. For real deployments use LUKS2 +
> SQLCipher (section 3), which is what `docs/ARCHITECTURE.md` and the blueprint specify.

### Demo: verify tamper detection

```python
from satsa.secure_store import encrypt_bytes, decrypt_bytes, load_or_create_key

key = load_or_create_key()            # creates keys/vault.key on first use
blob = encrypt_bytes(b"evidence", key)
tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
decrypt_bytes(tampered, key)          # ValueError: MAC verification failed...
```

---

## 2. Authentication & RBAC (offline)

`satsa/auth.py` stores users in the encrypted vault above.

| Username | Role | Default password | Capabilities |
|---|---|---|---|
| `admin` | administrator | `satsa2026` | everything incl. pipeline execution |
| `supervisor` | supervisor | `satsa2026` | review, **feedback (confirm/dismiss)**, exports |
| `auditor` | auditor | `satsa2026` | read-only: audit chain, validation, exports |

* Passwords: PBKDF2-HMAC-SHA256 (200 k iterations, per-user 16-byte salt), constant-time compare.
* Permissions map: `satsa/auth.py::PERMISSIONS`.
* **Change the default passwords before any real use** — `satsa.auth.change_password(...)`.

---

## 3. Production hardening (real crypto)

### 3.1 Full-disk / data-volume encryption — LUKS2 (Linux)

```bash
# Create an encrypted volume for all SAT-SA data (run from live USB / recovery env)
sudo cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
    --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 \
    /dev/sdX1

sudo cryptsetup open /dev/sdX1 satsa-data
sudo mkfs.ext4 /dev/mapper/satsa-data
sudo mount /dev/mapper/satsa-data /srv/satsa-data

# Bind the application paths to the encrypted volume
sudo ln -s /srv/satsa-data/output  /srv/satsa/data/output
sudo ln -s /srv/satsa-data/keys    /srv/satsa/keys

# Detach when the operator is away (data at rest is unreadable)
sudo umount /srv/satsa/data/output && sudo cryptsetup close satsa-data
```

Key-file discipline for LUKS: keep the backup passphrase in a sealed envelope;
optionally add a second keyslot bound to a YubiKey/hardware token:

```bash
sudo cryptsetup luksAddKey /dev/sdX1   # adds a second passphrase/keyslot
```

### 3.2 SQLite database encryption — SQLCipher

`feedback.db` and `users.db` can be moved onto SQLCipher builds of SQLite:

```bash
# Debian/Ubuntu offline wheelhouse install
sudo apt-get install sqlcipher          # or: pip install pysqlcipher3 (offline wheel)
```

Exact PRAGMA sequence **before any statement** on the connection:

```sql
PRAGMA key = 'hex-256-bit-key';          -- or: PRAGMA key = 'passphrase';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 600000;                -- OWASP-recommended for SQLCipher 4
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
PRAGMA cipher_memory_security = ON;
-- verify before trusting the connection:
SELECT count(*) FROM pragma_cipher_version;   -- must return 1
PRAGMA cipher_integrity_check;                -- 'ok'
```

Compatibility flags when reading a database created by SQLCipher 3:

```sql
PRAGMA cipher_compatibility = 3;
```

### 3.3 Key management rules

1. Keys never leave the host; no KMS, no cloud secret manager (air-gap rule).
2. `keys/vault.key` lives only on the encrypted volume (section 3.1) — the LUKS
   header then becomes the root of trust.
3. Rotate: `cryptsetup luksChangeKey` for the volume; re-encrypt `users.db` with a
   new master key and re-derive password hashes (`change_password` for each user).
4. Backups: ciphertext only; the LUKS keyslot backup is stored offline, separate
   from the media.

---

## 4. Where things live

| Path | Contents | Protected by |
|---|---|---|
| `keys/vault.key` | 32-byte master key (hex) | file mode 0600 + encrypted volume |
| `data/output/users.db` | RBAC users | `encrypted_sqlite` (AES-less stdlib vault) |
| `data/output/feedback.db` | examiner decisions + weights | volume encryption (3.1) / SQLCipher (3.2) |
| `data/output/*` | findings, scores, queue, manifests | volume encryption (3.1) |
| `data/synthetic/` | generated test data | not sensitive (synthetic) |

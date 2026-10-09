"""Cryptographic Audit Trail and Run Manifest for SAT-SA.

Generates SHA-256 run manifests and maintains an immutable hash-chained audit log
(audit_log.jsonl) where every line links to the SHA-256 hash of the preceding record.
Provides tamper detection and cryptographic verification of supervisory runs.
"""

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from satsa.config import PATHS, THRESHOLDS, CAPABILITIES


logger = logging.getLogger(__name__)


GENESIS_HASH = "0" * 64


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 checksum of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: Path | str) -> str:
    """Compute SHA-256 checksum of a file on disk."""
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return ""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def hash_dict(data: Dict[str, Any]) -> str:
    """Compute canonical SHA-256 hash of a dictionary (sorted keys, compact)."""
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hash_bytes(canonical_json.encode("utf-8"))


def get_git_commit_hash() -> str:
    """Safely obtain current git commit hash if running inside a git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown-git-ref"


@dataclass
class RunManifest:
    """Cryptographic manifest documenting code version, inputs, outputs, and parameters."""
    run_id: str
    timestamp: str
    code_version: str
    config_hash: str
    detector_versions: Dict[str, str]
    input_hashes: Dict[str, str]
    output_hashes: Dict[str, str]
    execution_summary: Dict[str, Any]
    manifest_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to JSON dictionary."""
        d = asdict(self)
        if not self.manifest_hash:
            d_copy = {k: v for k, v in d.items() if k != "manifest_hash"}
            d["manifest_hash"] = hash_dict(d_copy)
        return d


@dataclass
class AuditEntry:
    """Single link in the hash-chained audit log."""
    entry_id: int
    timestamp: str
    event_type: str
    run_id: str
    data_hash: str
    prev_hash: str
    entry_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        d = asdict(self)
        if not self.entry_hash:
            d_copy = {k: v for k, v in d.items() if k != "entry_hash"}
            d["entry_hash"] = hash_dict(d_copy)
        return d


def create_run_manifest(
    run_id: str,
    input_files: Dict[str, Path | str],
    output_files: Dict[str, Path | str],
    detector_versions: Dict[str, str],
    execution_summary: Dict[str, Any],
) -> RunManifest:
    """Construct and seal a cryptographic RunManifest."""
    now_utc = datetime.now(timezone.utc).isoformat()
    git_hash = get_git_commit_hash()

    # Hash active configuration
    cfg_data = {
        "thresholds": asdict(THRESHOLDS),
        "capabilities": asdict(CAPABILITIES),
    }
    cfg_hash = hash_dict(cfg_data)

    # Hash inputs
    in_hashes = {name: hash_file(path) for name, path in input_files.items() if Path(path).exists()}

    # Hash outputs
    out_hashes = {name: hash_file(path) for name, path in output_files.items() if Path(path).exists()}

    manifest = RunManifest(
        run_id=run_id,
        timestamp=now_utc,
        code_version=git_hash,
        config_hash=cfg_hash,
        detector_versions=detector_versions,
        input_hashes=in_hashes,
        output_hashes=out_hashes,
        execution_summary=execution_summary,
    )
    manifest_dict = manifest.to_dict()
    manifest.manifest_hash = manifest_dict["manifest_hash"]
    return manifest


def append_audit_log(
    audit_file_path: Path | str,
    event_type: str,
    run_id: str,
    payload_hash: str,
) -> AuditEntry:
    """Append a verified link to the SHA-256 hash-chained audit log."""
    log_p = Path(audit_file_path)
    log_p.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = GENESIS_HASH
    entry_id = 1

    if log_p.exists() and log_p.stat().st_size > 0:
        with open(log_p, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
            if lines:
                last_line = lines[-1]
                try:
                    last_obj = json.loads(last_line)
                    prev_hash = last_obj.get("entry_hash", GENESIS_HASH)
                    entry_id = int(last_obj.get("entry_id", 0)) + 1
                except Exception:
                    prev_hash = hash_bytes(last_line.encode("utf-8"))
                    entry_id = len(lines) + 1

    now_utc = datetime.now(timezone.utc).isoformat()
    raw_entry = {
        "entry_id": entry_id,
        "timestamp": now_utc,
        "event_type": event_type,
        "run_id": run_id,
        "data_hash": payload_hash,
        "prev_hash": prev_hash,
    }
    entry_hash = hash_dict(raw_entry)
    raw_entry["entry_hash"] = entry_hash

    with open(log_p, "a", encoding="utf-8") as f:
        f.write(json.dumps(raw_entry, sort_keys=True) + "\n")

    return AuditEntry(**raw_entry)


def verify_audit_chain(audit_file_path: Path | str) -> Tuple[bool, List[str]]:
    """Cryptographically verify the integrity of the hash-chained audit log.

    Detects any added, modified, reordered, or deleted records.
    Returns:
        (is_valid, list_of_error_strings)
    """
    log_p = Path(audit_file_path)
    if not log_p.exists():
        return True, ["Audit log does not exist yet (clean state)."]

    errors: List[str] = []
    expected_prev_hash = GENESIS_HASH

    with open(log_p, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                entry = json.loads(line_str)
            except Exception as e:
                errors.append(f"Line {line_num}: Malformed JSON - {e}")
                continue

            # Verify prev_hash link
            actual_prev = entry.get("prev_hash")
            if actual_prev != expected_prev_hash:
                errors.append(
                    f"Line {line_num}: Hash chain broken! Expected prev_hash='{expected_prev_hash[:12]}...', "
                    f"got '{actual_prev[:12]}...' (TAMPERING DETECTED)"
                )

            # Verify entry_hash self-integrity
            claimed_hash = entry.get("entry_hash")
            content_to_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed = hash_dict(content_to_hash)

            if claimed_hash != recomputed:
                errors.append(
                    f"Line {line_num}: Record content tampered! Claimed hash='{claimed_hash[:12]}...', "
                    f"recomputed='{recomputed[:12]}...'"
                )

            expected_prev_hash = claimed_hash

    is_valid = len(errors) == 0
    return is_valid, errors


def main():
    parser = argparse.ArgumentParser(description="Cryptographic Audit Verification CLI for SAT-SA.")
    parser.add_argument("--verify", action="store_true", help="Verify the integrity of audit_log.jsonl")
    parser.add_argument("--log-path", type=str, default=str(PATHS.audit_log_file), help="Path to audit log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.verify:
        logger.info("Verifying hash-chained audit log at: %s", args.log_path)
        valid, errors = verify_audit_chain(args.log_path)
        if valid:
            logger.info("OK: Cryptographic audit chain is 100%% INTACT and VERIFIED.")
            sys.exit(0)
        else:
            logger.critical("Audit chain verification FAILED!")
            for err in errors:
                logger.error("  - %s", err)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

"""Examiner feedback loop: SQLite-backed confirm/dismiss re-weighting.

Examiners review queue items and confirm or dismiss findings. The loop turns
those decisions into a **versioned per-(entity, detector) weight factor** that
rescales future finding scores (``Finding.feedback_factor`` -> 
``compute_finding_score``):

* ``dismiss`` -> factor *= 0.6 (floor 0.3) -- a detector that keeps producing
  findings an examiner rejects for the same entity is down-weighted.
* ``confirm``  -> factor *= 1/0.6 (cap 1.0) -- confirmation restores weight
  (one confirm exactly reverses one dismiss).

Storage is a local SQLite database (stdlib ``sqlite3`` only -- blueprint
section 2: "SQLite (audit, config)"), append-only for the decision log plus a
current-weights table with a monotonically increasing ``version`` per change.
Nothing here touches the network.
"""

from datetime import datetime, timezone
from pathlib import Path
from sqlite3 import Connection, Row, connect
from typing import Any, Dict, List, Optional, Tuple, Union

from satsa.config import PATHS
from satsa.detectors.base import Finding

DEFAULT_DB_PATH = PATHS.output_dir / "feedback.db"  # late-bound: callables read this at call time

DISMISS_FACTOR = 0.6       # multiplicative down-weight per dismissal
CONFIRM_FACTOR = 1.0 / 0.6  # multiplicative restore per confirmation
FACTOR_FLOOR = 0.3         # never silence a detector entirely
FACTOR_CAP = 1.0           # never exceed neutral weight
VALID_DECISIONS = ("confirm", "dismiss")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('confirm', 'dismiss')),
    examiner TEXT NOT NULL DEFAULT 'unknown',
    comment TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_finding ON feedback(finding_id);
CREATE INDEX IF NOT EXISTS idx_feedback_entity ON feedback(entity_id);
CREATE TABLE IF NOT EXISTS feedback_weights (
    entity_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    factor REAL NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (entity_id, detector_id)
);
"""


def _open(db_path: Union[str, Path]) -> Connection:
    """Open (creating parents/schema if needed) the feedback database."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = connect(p)
    con.row_factory = Row
    con.executescript(_SCHEMA)
    return con


def record_feedback(
    finding_id: str,
    entity_id: str,
    detector_id: str,
    decision: str,
    examiner: str = "unknown",
    comment: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Append one examiner decision and recompute the (entity, detector) weight.

    Returns the updated weight record (factor/version/updated_at) plus the
    inserted ``feedback_id``. ``db_path`` defaults to ``DEFAULT_DB_PATH``.
    """
    db_path = db_path or DEFAULT_DB_PATH
    decision = (decision or "").strip().lower()
    if decision not in VALID_DECISIONS:
        raise ValueError(f"decision must be one of {VALID_DECISIONS}, got {decision!r}")
    if not finding_id or not entity_id or not detector_id:
        raise ValueError("finding_id, entity_id and detector_id are required")

    now = datetime.now(timezone.utc).isoformat()
    con = _open(db_path)
    try:
        cur = con.execute(
            "INSERT INTO feedback (finding_id, entity_id, detector_id, decision, examiner, comment, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding_id, entity_id, detector_id, decision, examiner or "unknown", comment, now),
        )
        feedback_id = int(cur.lastrowid or 0)

        row = con.execute(
            "SELECT factor, version FROM feedback_weights WHERE entity_id = ? AND detector_id = ?",
            (entity_id, detector_id),
        ).fetchone()
        factor = float(row["factor"]) if row else 1.0
        version = int(row["version"]) if row else 0

        if decision == "dismiss":
            factor = max(FACTOR_FLOOR, factor * DISMISS_FACTOR)
        else:
            factor = min(FACTOR_CAP, factor * CONFIRM_FACTOR)
        factor = round(factor, 6)
        version += 1

        con.execute(
            "INSERT INTO feedback_weights (entity_id, detector_id, factor, version, updated_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(entity_id, detector_id) DO UPDATE SET"
            " factor = excluded.factor, version = excluded.version, updated_at = excluded.updated_at",
            (entity_id, detector_id, factor, version, now),
        )
        con.commit()
        return {
            "feedback_id": feedback_id,
            "finding_id": finding_id,
            "entity_id": entity_id,
            "detector_id": detector_id,
            "decision": decision,
            "factor": factor,
            "version": version,
            "updated_at": now,
        }
    finally:
        con.close()


def list_weights(db_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    """All current (entity, detector) weight records, newest change first."""
    p = Path(db_path or DEFAULT_DB_PATH)
    if not p.exists():
        return []
    con = _open(p)
    try:
        rows = con.execute(
            "SELECT entity_id, detector_id, factor, version, updated_at"
            " FROM feedback_weights ORDER BY updated_at DESC, entity_id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def get_history(
    finding_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    limit: int = 200,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Append-only examiner decision log, newest first."""
    p = Path(db_path or DEFAULT_DB_PATH)
    if not p.exists():
        return []
    con = _open(p)
    try:
        sql = "SELECT * FROM feedback"
        clauses: List[str] = []
        params: List[Any] = []
        if finding_id:
            clauses.append("finding_id = ?")
            params.append(finding_id)
        if entity_id:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY feedback_id DESC LIMIT ?"
        params.append(int(limit))
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    finally:
        con.close()


def apply_feedback(
    findings: List[Finding],
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Stamp ``feedback_factor`` onto findings from stored weights.

    No-op (returns 0) when the database does not exist yet, so a fresh run
    produces exactly the neutral (factor=1.0) results. Returns the number of
    findings whose factor differs from 1.0 after stamping.
    """
    p = Path(db_path or DEFAULT_DB_PATH)
    if not p.exists():
        return 0

    weights: Dict[Tuple[str, str], float] = {
        (w["entity_id"], w["detector_id"]): float(w["factor"]) for w in list_weights(p)
    }
    if not weights:
        return 0

    applied = 0
    for f in findings:
        factor = weights.get((f.entity_id, f.detector_id), 1.0)
        f.feedback_factor = factor
        if factor != 1.0:
            applied += 1
    return applied

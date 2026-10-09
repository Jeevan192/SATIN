"""Canonical Pydantic schemas for SAT-SA input tables.

Enforces column types, timestamp ordering, and standardized categorical values
across the 6 canonical input tables.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def normalize_str(v: Any) -> str:
    """Normalize string input by stripping whitespace."""
    if v is None:
        return ""
    return str(v).strip()


def parse_timestamp(v: Any) -> datetime:
    """Robustly parse timestamps from strings, ints, or datetimes."""
    if isinstance(v, datetime):
        return v
    if v is None or (isinstance(v, float) and v != v):
        raise ValueError("Timestamp cannot be null")
    s = str(v).strip()
    if not s or s.lower() in ("nat", "nan", "none", "null"):
        raise ValueError("Timestamp string is empty or invalid")
    try:
        # Standard ISO format or pandas-compatible date
        import pandas as pd
        ts = pd.to_datetime(s)
        return ts.to_pydatetime()
    except Exception as e:
        raise ValueError(f"Cannot parse timestamp '{s}': {e}")


class AlertRecord(BaseModel):
    """Canonical alert record."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    alert_id: str = Field(..., min_length=1)
    entity_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    created_ts: datetime
    ack_ts: datetime
    closed_ts: datetime
    disposition: str = Field(default="unresolved")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        s = str(v).strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of {sorted(VALID_SEVERITIES)}")
        return s

    @field_validator("created_ts", "ack_ts", "closed_ts", mode="before")
    @classmethod
    def validate_timestamps(cls, v: Any) -> datetime:
        return parse_timestamp(v)

    @field_validator("disposition", mode="before")
    @classmethod
    def normalize_disp(cls, v: Any) -> str:
        return normalize_str(v) or "unresolved"

    @model_validator(mode="after")
    def validate_timestamp_order(self) -> "AlertRecord":
        if self.created_ts > self.ack_ts:
            raise ValueError(
                f"Timestamp violation: created_ts ({self.created_ts}) > ack_ts ({self.ack_ts})"
            )
        if self.ack_ts > self.closed_ts:
            raise ValueError(
                f"Timestamp violation: ack_ts ({self.ack_ts}) > closed_ts ({self.closed_ts})"
            )
        return self


class CaseRecord(BaseModel):
    """Canonical case record."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    case_id: str = Field(..., min_length=1)
    alert_id: str = Field(..., min_length=1)
    analyst_id: str = Field(..., min_length=1)
    opened_ts: datetime
    closed_ts: datetime
    status: str = Field(default="closed")
    closure_code: str = Field(default="standard")
    notes_text: Optional[str] = Field(default="")

    @field_validator("opened_ts", "closed_ts", mode="before")
    @classmethod
    def validate_timestamps(cls, v: Any) -> datetime:
        return parse_timestamp(v)

    @model_validator(mode="after")
    def validate_order(self) -> "CaseRecord":
        if self.opened_ts > self.closed_ts:
            raise ValueError(
                f"Timestamp violation: opened_ts ({self.opened_ts}) > closed_ts ({self.closed_ts})"
            )
        return self


class WorkflowEventRecord(BaseModel):
    """Canonical workflow event record."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    case_id: str = Field(..., min_length=1)
    step: str = Field(..., min_length=1)
    actor_role: str = Field(default="analyst")
    ts: datetime

    @field_validator("ts", mode="before")
    @classmethod
    def validate_timestamps(cls, v: Any) -> datetime:
        return parse_timestamp(v)


class EscalationRecord(BaseModel):
    """Canonical escalation record."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    case_id: str = Field(..., min_length=1)
    from_tier: str = Field(..., min_length=1)
    to_tier: str = Field(..., min_length=1)
    ts: datetime
    outcome: str = Field(default="pending")

    @field_validator("ts", mode="before")
    @classmethod
    def validate_timestamps(cls, v: Any) -> datetime:
        return parse_timestamp(v)


class AssetRecord(BaseModel):
    """Canonical asset inventory record."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    asset_id: str = Field(..., min_length=1)
    entity_id: str = Field(..., min_length=1)
    criticality: Literal["low", "medium", "high", "critical"]
    asset_type: str = Field(default="server")
    monitoring_expected: bool = Field(default=True)

    @field_validator("criticality", mode="before")
    @classmethod
    def validate_criticality(cls, v: Any) -> str:
        s = str(v).strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid criticality '{v}'. Must be one of {sorted(VALID_SEVERITIES)}")
        return s

    @field_validator("monitoring_expected", mode="before")
    @classmethod
    def validate_bool(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("1", "true", "yes", "y", "t")


class EntityRecord(BaseModel):
    """Canonical entity metadata record.

    The ``claimed_*`` columns are optional self-reported supervisory KPIs
    submitted by the CSE (used by the Claim-vs-Reality Index); entities that
    do not submit claims simply leave them empty.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    entity_id: str = Field(..., min_length=1)
    sector: str = Field(..., min_length=1)
    size_band: str = Field(..., min_length=1)
    soc_model: str = Field(default="in-house")

    # Self-reported KPIs (Claim-vs-Reality)
    claimed_mttc_min: Optional[float] = None       # claimed median close time, critical/high alerts (minutes)
    claimed_coverage_pct: Optional[float] = None   # claimed monitored critical-asset coverage (%)
    claimed_fp_rate_pct: Optional[float] = None    # claimed false-positive disposition rate (%)
    claimed_escalation_pct: Optional[float] = None # claimed critical/high escalation rate (%)

    @field_validator(
        "claimed_mttc_min", "claimed_coverage_pct",
        "claimed_fp_rate_pct", "claimed_escalation_pct",
        mode="before",
    )
    @classmethod
    def parse_claim(cls, v: Any) -> Optional[float]:
        """Coerce claim values to float; empty/NaN sentinels become None (no claim)."""
        if v is None:
            return None
        if isinstance(v, float) and v != v:  # NaN
            return None
        s = str(v).strip()
        if not s or s.lower() in ("nan", "none", "null", "nat"):
            return None
        try:
            return float(s)
        except ValueError:
            raise ValueError(f"Claim value '{v}' is not numeric")


# Table name to Schema mapping
SCHEMA_MAP = {
    "alerts": AlertRecord,
    "cases": CaseRecord,
    "workflow_events": WorkflowEventRecord,
    "escalations": EscalationRecord,
    "assets": AssetRecord,
    "entities": EntityRecord,
}

# Required columns per canonical table
REQUIRED_COLUMNS: Dict[str, List[str]] = {
    "alerts": [
        "alert_id", "entity_id", "asset_id", "category", "severity",
        "created_ts", "ack_ts", "closed_ts", "disposition"
    ],
    "cases": [
        "case_id", "alert_id", "analyst_id", "opened_ts", "closed_ts",
        "status", "closure_code", "notes_text"
    ],
    "workflow_events": ["case_id", "step", "actor_role", "ts"],
    "escalations": ["case_id", "from_tier", "to_tier", "ts", "outcome"],
    "assets": ["asset_id", "entity_id", "criticality", "asset_type", "monitoring_expected"],
    "entities": ["entity_id", "sector", "size_band", "soc_model"],
}


def validate_row(table_name: str, row_dict: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate a single row against its canonical schema.

    Returns:
        (validated_dict, None) on success
        (None, error_message) on failure
    """
    model_cls = SCHEMA_MAP.get(table_name)
    if not model_cls:
        return None, f"Unknown table '{table_name}'"
    try:
        instance = model_cls.model_validate(row_dict)
        return instance.model_dump(), None
    except Exception as e:
        return None, str(e)

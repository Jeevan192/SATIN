"""FastAPI Backend Service for SAT-SA.

Serves supervisory findings, entity capability assessments, review queues,
cryptographic audit trails, and validation benchmarks from offline data/output/ artifacts.
Supports on-demand pipeline execution via POST /run.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure repository root is on sys.path and remove package dir
PACKAGE_DIR = str(Path(__file__).resolve().parent)
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
while PACKAGE_DIR in sys.path:
    sys.path.remove(PACKAGE_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from satsa.audit import verify_audit_chain, hash_file
from satsa.config import PATHS
from satsa.pipeline import run_all


app = FastAPI(
    title="SAT-SA Supervisory API",
    description="Offline Supervisory Analytics Tool for Critical Sector Entity SOC Assessment (NCIIPC)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_output_path(filename: str) -> Path:
    """Resolve file inside data/output directory."""
    return PATHS.output_dir / filename


def load_json_file(filename: str) -> Any:
    """Load JSON artifact from data/output."""
    p = get_output_path(filename)
    if not p.exists():
        # Attempt to run pipeline on synthetic data if output missing
        synth_dir = PATHS.synthetic_dir
        if (synth_dir / "alerts.csv").exists():
            run_all(data_dir=synth_dir, output_dir=PATHS.output_dir)
        else:
            raise HTTPException(status_code=404, detail=f"Artifact '{filename}' not found. Please run pipeline first.")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


class RunRequest(BaseModel):
    data_dir: str = Field(default="data/synthetic", description="Path to input data directory")
    out_dir: str = Field(default="data/output", description="Path to output directory")
    budget: int = Field(default=50, description="Review queue budget per entity")
    seed: int = Field(default=42, description="Random seed")


@app.get("/")
def get_root():
    """Health check and API overview."""
    return {
        "tool": "SAT-SA",
        "description": "Supervisory Analytics Tool for SOC Assessment",
        "version": "1.0.0",
        "mode": "offline",
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/entities")
def get_entities():
    """List all assessed Critical Sector Entities with risk scores, tiers, and trends."""
    scores_data = load_json_file("entity_scores.json")
    entities_list = []
    for eid, score_dict in scores_data.items():
        entities_list.append({
            "entity_id": eid,
            "overall_risk_index": score_dict.get("overall_risk_index", 0.0),
            "risk_tier": score_dict.get("risk_tier", "low"),
            "peer_percentile": score_dict.get("peer_percentile", 0.5),
            "qoq_trend": score_dict.get("qoq_trend", "stable"),
            "findings_count": score_dict.get("findings_count", 0),
        })
    entities_list.sort(key=lambda x: x["overall_risk_index"], reverse=True)
    return {"count": len(entities_list), "entities": entities_list}


@app.get("/entities/{entity_id}")
def get_entity_detail(entity_id: str):
    """Retrieve full capability breakdown and supervisory risk metrics for a specific entity."""
    scores_data = load_json_file("entity_scores.json")
    eid_upper = entity_id.upper()
    matched = None
    for k, v in scores_data.items():
        if k.upper() == eid_upper:
            matched = v
            break

    if not matched:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found.")
    return matched


@app.get("/entities/{entity_id}/findings")
def get_entity_findings(
    entity_id: str,
    category: Optional[str] = Query(None, description="EXECUTION_GAP, NEGATIVE_SPACE, or NOVEL"),
    detector_id: Optional[str] = Query(None, description="Filter by detector ID (e.g. EG-01)"),
):
    """List all supervisory findings for a specific entity with optional filters."""
    findings_data = load_json_file("findings.json")
    eid_upper = entity_id.upper()
    filtered = [
        f for f in findings_data
        if f.get("entity_id", "").upper() == eid_upper
    ]
    if category:
        filtered = [f for f in filtered if f.get("category", "").upper() == category.upper()]
    if detector_id:
        filtered = [f for f in filtered if f.get("detector_id", "").upper() == detector_id.upper()]

    return {
        "entity_id": entity_id,
        "count": len(filtered),
        "findings": filtered,
    }


@app.get("/findings/{finding_id}")
def get_finding_detail(finding_id: str):
    """Retrieve detailed finding card including parameters and evidence references."""
    findings_data = load_json_file("findings.json")
    f_matched = next((f for f in findings_data if f.get("finding_id") == finding_id), None)
    if not f_matched:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return f_matched


@app.get("/queue/{entity_id}")
def get_review_queue(entity_id: str, budget: int = Query(50, ge=1, le=500)):
    """Retrieve prioritized examiner review queue (85% diversified risk + 15% random control)."""
    queue_data = load_json_file("review_queue.json")
    eid_upper = entity_id.upper()
    matched_q = None
    for k, v in queue_data.items():
        if k.upper() == eid_upper:
            matched_q = v
            break

    if not matched_q:
        raise HTTPException(status_code=404, detail=f"Review queue for entity '{entity_id}' not found.")

    return {
        "entity_id": entity_id,
        "budget": budget,
        "items": matched_q[:budget],
    }


@app.get("/trends")
def get_trends():
    """Retrieve portfolio-wide trend indicators and average capability area scores."""
    scores_data = load_json_file("entity_scores.json")
    area_totals: Dict[str, float] = {}
    tier_counts: Dict[str, int] = {}
    trend_counts: Dict[str, int] = {}

    for s in scores_data.values():
        tier = s.get("risk_tier", "low")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        trend = s.get("qoq_trend", "stable")
        trend_counts[trend] = trend_counts.get(trend, 0) + 1

        for a, val in s.get("area_scores", {}).items():
            area_totals[a] = area_totals.get(a, 0.0) + val

    n_ent = max(1, len(scores_data))
    area_averages = {a: round(tot / n_ent, 2) for a, tot in area_totals.items()}

    return {
        "total_entities": n_ent,
        "area_averages": area_averages,
        "risk_tier_distribution": tier_counts,
        "trend_distribution": trend_counts,
    }


@app.get("/audit/verify")
def get_audit_verification():
    """Verify cryptographic integrity of the hash-chained audit log and return status."""
    audit_file = get_output_path("audit_log.jsonl")
    manifest_file = get_output_path("run_manifest.json")

    is_valid, errors = verify_audit_chain(audit_file)
    manifest_data = {}
    if manifest_file.exists():
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

    return {
        "audit_chain_verified": is_valid,
        "error_count": len(errors),
        "errors": errors,
        "audit_file": str(audit_file),
        "manifest": manifest_data,
    }


@app.get("/validation")
def get_validation_report():
    """Retrieve ground-truth validation benchmark report."""
    rep_file = get_output_path("validation_report.md")
    if not rep_file.exists():
        raise HTTPException(status_code=404, detail="Validation report not found. Run validation script first.")

    with open(rep_file, "r", encoding="utf-8") as f:
        content = f.read()

    return {"report_markdown": content}


@app.post("/run")
def run_pipeline_endpoint(req: RunRequest):
    """Trigger offline supervisory assessment pipeline on a specified data directory."""
    try:
        res = run_all(
            data_dir=req.data_dir,
            output_dir=req.out_dir,
            budget_per_entity=req.budget,
            seed=req.seed,
        )
        return {
            "status": "success",
            "run_id": res.run_id,
            "runtime_seconds": res.runtime_seconds,
            "findings_count": len(res.findings),
            "manifest_hash": res.manifest.manifest_hash,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")
"""FastAPI Backend Service for SAT-SA.

Serves supervisory findings, entity capability assessments, review queues,
cryptographic audit trails, and validation benchmarks from offline data/output/ artifacts.
Supports on-demand pipeline execution via POST /run.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from satsa.audit import verify_audit_chain, hash_file
from satsa.config import PATHS
from satsa.feedback import get_history as get_feedback_history, list_weights, record_feedback
from satsa.pipeline import run_all
from satsa.report import build_report


logger = logging.getLogger(__name__)


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
    """Retrieve ground-truth validation benchmark report.

    If ``validation_report.md`` is absent, the report is regenerated dynamically
    from existing audited pipeline artifacts (findings, queue, scores + ground
    truth) without re-running the detector fleet.
    """
    rep_file = get_output_path("validation_report.md")
    if rep_file.exists():
        with open(rep_file, "r", encoding="utf-8") as f:
            content = f.read()
        if content.strip():
            return {"report_markdown": content, "generated": "static"}

    # Dynamic generation from audited outputs (fast mode, no detector re-run)
    try:
        from validation.run_validation import build_report_from_outputs

        content = build_report_from_outputs(output_report_path=rep_file)
        return {"report_markdown": content, "generated": "dynamic"}
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=404,
            detail=f"Validation report not found and could not be generated: {e}",
        )
    except Exception as e:  # pragma: no cover - defensive
        logger.exception("Dynamic validation report generation failed")
        raise HTTPException(status_code=500, detail=f"Validation generation error: {e}")


@app.get("/claim-reality")
def get_claim_reality():
    """Claim-vs-Reality Index: self-reported entity KPIs vs audited evidence."""
    return load_json_file("claim_reality.json")


class FeedbackIn(BaseModel):
    """Examiner confirm/dismiss decision for a finding."""
    finding_id: str = Field(..., min_length=1, description="Finding identifier")
    entity_id: str = Field(..., min_length=1, description="Entity the finding belongs to")
    detector_id: str = Field(..., min_length=1, description="Detector that produced the finding")
    decision: Literal["confirm", "dismiss"] = Field(..., description="Examiner decision")
    examiner: str = Field(default="unknown", min_length=1, description="Examiner identifier")
    comment: Optional[str] = Field(default=None, max_length=2000, description="Optional rationale")


@app.post("/feedback")
def post_feedback(req: FeedbackIn):
    """Record an examiner decision and return the updated (entity, detector) weight."""
    try:
        return record_feedback(
            finding_id=req.finding_id,
            entity_id=req.entity_id,
            detector_id=req.detector_id,
            decision=req.decision,
            examiner=req.examiner,
            comment=req.comment,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/feedback/weights")
def get_feedback_weights():
    """Current versioned per-(entity, detector) feedback weight factors."""
    return {"weights": list_weights()}


@app.get("/feedback/history")
def get_feedback_log(
    finding_id: Optional[str] = Query(None, description="Filter by finding"),
    entity_id: Optional[str] = Query(None, description="Filter by entity"),
    limit: int = Query(200, ge=1, le=1000),
):
    """Append-only examiner decision log (newest first)."""
    return {"history": get_feedback_history(finding_id=finding_id, entity_id=entity_id, limit=limit)}


@app.get("/report/html", response_class=HTMLResponse)
def get_report_html():
    """Styled HTML supervisory assessment report (offline-rendered)."""
    return build_report()["html"]


@app.get("/report/pdf")
def get_report_pdf():
    """Supervisory assessment report as PDF (WeasyPrint, or stdlib fallback)."""
    rep = build_report()
    return Response(
        content=rep["pdf"],
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="SAT-SA_Supervisory_Report.pdf"',
            "X-PDF-Engine": rep["pdf_engine"],
        },
    )


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
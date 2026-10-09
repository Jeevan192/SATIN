"""End-to-End Execution Pipeline for SAT-SA.

Coordinates the complete offline supervisory analytics workflow:
1. Ingests and validates canonical/legacy data tables
2. Computes cohort-relative peer baselines
3. Executes all 15 EXECUTION_GAP, NEGATIVE_SPACE, and NOVEL detectors
4. Calculates 8-capability area sub-scores and overall Entity Risk Index
5. Generates examiner review queues (85% diversified risk + 15% random control)
6. Emits cryptographic RunManifest and appends to hash-chained audit_log.jsonl
"""

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import uuid

from satsa.audit import append_audit_log, create_run_manifest, RunManifest
from satsa.claim_reality import ClaimRealityScore, compute_claim_reality, summarize as summarize_claims
from satsa.config import PATHS
from satsa.detectors import ALL_DETECTORS
from satsa.detectors.base import Finding
from satsa.feedback import apply_feedback
from satsa.ingest import DataBundle, load_dataset
from satsa.peers import CohortManager
from satsa.queue import QueueItem, build_portfolio_queues
from satsa.scoring import EntitySupervisoryScore, score_portfolio
from satsa.store import write_bundle as write_store_bundle

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Full execution output bundle from an end-to-end supervisory assessment run."""
    run_id: str
    runtime_seconds: float
    bundle: DataBundle
    findings: List[Finding]
    scores: Dict[str, EntitySupervisoryScore]
    queues: Dict[str, List[QueueItem]]
    manifest: RunManifest
    claim_reality: Dict[str, ClaimRealityScore] = field(default_factory=dict)


def run_all(
    data_dir: Path | str,
    output_dir: Optional[Path | str] = None,
    budget_per_entity: int = 50,
    seed: int = 42,
) -> PipelineResult:
    """Execute complete SAT-SA supervisory assessment pipeline.

    Returns:
        PipelineResult with findings, entity scores, review queues, and cryptographic manifest.
    """
    start_time = time.time()
    run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
    src_p = Path(data_dir)
    out_p = Path(output_dir) if output_dir else PATHS.output_dir
    out_p.mkdir(parents=True, exist_ok=True)

    logger.info("[%s] Step 1/6: Ingesting dataset from %s...", run_id, src_p)
    quarantine_p = out_p / "quarantine.csv"
    bundle = load_dataset(src_p, quarantine_output_path=quarantine_p)

    # Canonical Parquet store (blueprint section 2): columnar copy of the
    # validated inputs, used for offline SQL drill-down and fast reloads.
    store_dir = out_p / "store"
    store_t = time.time()
    write_store_bundle(bundle, store_dir)
    logger.info(
        "[%s] Canonical Parquet store written to %s (%d tables, %.2fs)",
        run_id, store_dir, len(list(store_dir.glob('*.parquet'))), time.time() - store_t,
    )

    summary = bundle.summary()
    logger.info(
        "[%s] Valid records: %d alerts, %d cases, %d assets, %d entities.",
        run_id, summary["alerts"], summary["cases"], summary["assets"], summary["entities"],
    )
    if summary["quarantined"] > 0:
        logger.info("[%s] Quarantined %d corrupted rows to %s", run_id, summary["quarantined"], quarantine_p)

    logger.info("[%s] Step 2/6: Initializing peer cohort manager...", run_id)
    cohort_mgr = CohortManager(bundle.entities)

    logger.info("[%s] Step 3/6: Executing %d supervisory detectors...", run_id, len(ALL_DETECTORS))
    detector_versions: Dict[str, str] = {}
    all_findings: List[Finding] = []

    for det_cls in ALL_DETECTORS:
        det = det_cls()
        detector_versions[det.detector_id] = det.detector_version
        det_findings = det.run(bundle, cohort_mgr)
        all_findings.extend(det_findings)

    logger.info("[%s] Generated %d supervisory findings across portfolio.", run_id, len(all_findings))

    # Examiner feedback loop: down-weight findings the examiner previously
    # dismissed for the same (entity, detector) pair; no-op on fresh installs.
    reweighted = apply_feedback(all_findings)
    if reweighted:
        logger.info("[%s] Examiner feedback: re-weighted %d findings from feedback.db", run_id, reweighted)

    logger.info("[%s] Step 4/6: Computing capability sub-scores and Entity Risk Index...", run_id)
    scores = score_portfolio(all_findings, bundle, cohort_mgr)

    logger.info("[%s] Step 5/6: Building prioritized review queues (budget=%d)...", run_id, budget_per_entity)
    queues = build_portfolio_queues(all_findings, bundle, budget_per_entity=budget_per_entity, seed=seed)

    logger.info("[%s] Step 6/6: Persisting outputs and generating cryptographic manifest...", run_id)
    findings_file = out_p / "findings.json"
    scores_file = out_p / "entity_scores.json"
    queue_file = out_p / "review_queue.json"
    manifest_file = out_p / "run_manifest.json"
    audit_file = out_p / "audit_log.jsonl"

    # Persist core outputs
    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump([f.to_dict() for f in all_findings], f, indent=2, default=str)

    with open(scores_file, "w", encoding="utf-8") as f:
        json.dump({eid: s.to_dict() for eid, s in scores.items()}, f, indent=2, default=str)

    with open(queue_file, "w", encoding="utf-8") as f:
        json.dump({eid: [item.to_dict() for item in q] for eid, q in queues.items()}, f, indent=2, default=str)

    # Claim-vs-Reality Index (self-reported KPIs vs audited evidence)
    claims = compute_claim_reality(bundle)
    claims_file = out_p / "claim_reality.json"
    with open(claims_file, "w", encoding="utf-8") as f:
        json.dump(
            {"summary": summarize_claims(claims),
             "entities": {eid: s.to_dict() for eid, s in claims.items()}},
            f, indent=2, default=str,
        )
    if claims:
        n_exag = sum(1 for s in claims.values() if s.verdict == "materially_exaggerated")
        logger.info("[%s] Claim-vs-Reality: %d entities claimed, %d materially exaggerated.", run_id, len(claims), n_exag)

    runtime = round(time.time() - start_time, 3)

    # Input files map
    input_files = {
        name: src_p / f"{name}.csv" for name in ("alerts", "cases", "workflow_events", "escalations", "assets", "entities")
    }
    output_files = {
        "findings": findings_file,
        "entity_scores": scores_file,
        "review_queue": queue_file,
        "claim_reality": claims_file,
    }
    if quarantine_p.exists():
        output_files["quarantine"] = quarantine_p

    exec_summary = {
        "entity_count": len(bundle.entities),
        "total_alerts": len(bundle.alerts),
        "finding_count": len(all_findings),
        "runtime_seconds": runtime,
    }

    manifest = create_run_manifest(
        run_id=run_id,
        input_files=input_files,
        output_files=output_files,
        detector_versions=detector_versions,
        execution_summary=exec_summary,
    )

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2)

    # Append to hash-chained audit log
    append_audit_log(
        audit_file_path=audit_file,
        event_type="SUPERVISORY_PIPELINE_RUN",
        run_id=run_id,
        payload_hash=manifest.manifest_hash,
    )

    logger.info(
        "[%s] Run successfully completed in %.2fs. Manifest sealed: %s...",
        run_id, runtime, manifest.manifest_hash[:12],
    )
    return PipelineResult(
        run_id=run_id,
        runtime_seconds=runtime,
        bundle=bundle,
        findings=all_findings,
        scores=scores,
        queues=queues,
        manifest=manifest,
        claim_reality=claims,
    )


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="SAT-SA Offline Supervisory Analytics Pipeline.")
    parser.add_argument("--data-dir", type=str, default="data/synthetic", help="Path to input data directory")
    parser.add_argument("--out-dir", type=str, default="data/output", help="Path to output data directory")
    parser.add_argument("--budget", type=int, default=50, help="Review queue budget per entity")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    result = run_all(data_dir=args.data_dir, output_dir=args.out_dir, budget_per_entity=args.budget, seed=args.seed)
    logger.info("--- TOP RANKED SUPERVISORY ENTITIES ---")
    sorted_entities = sorted(result.scores.values(), key=lambda s: s.overall_risk_index, reverse=True)
    for s in sorted_entities[:5]:
        logger.info(
            "Entity: %-15s | Risk Index: %5.1f | Tier: %-10s | Findings: %4d",
            s.entity_id, s.overall_risk_index, s.risk_tier, s.findings_count,
        )


if __name__ == "__main__":
    main()

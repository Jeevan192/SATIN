"""Supervisory assessment report export: Jinja2 HTML + PDF.

Renders a publication-grade supervisory report from the audited artifacts in
``data/output/`` (findings, scores, queue, claim-reality, manifest, audit log):

* **HTML** -- styled Jinja2 template (``satsa/templates/report.html.j2``).
* **PDF**  -- WeasyPrint when the optional ``pdf`` extra is installed and its
  system libraries are present; otherwise a stdlib-only fallback
  (:mod:`satsa.minipdf`) renders the same content as paginated plain text.

Fully offline: no CDN assets, no external fonts, no network calls.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader, select_autoescape

from satsa.audit import verify_audit_chain
from satsa.config import PATHS

VERSION = "1.0.0"
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TOP_FINDINGS = 25
_TOP_DETECTORS = 15
_REASON_MAX = 180


def _load_json(path: Path) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def collect_report_data(output_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Assemble the report context from audited pipeline artifacts."""
    out_p = Path(output_dir) if output_dir else PATHS.output_dir
    scores: Dict[str, Any] = _load_json(out_p / "entity_scores.json") or {}
    findings: List[Dict[str, Any]] = _load_json(out_p / "findings.json") or []
    queues: Dict[str, Any] = _load_json(out_p / "review_queue.json") or {}
    claims: Dict[str, Any] = _load_json(out_p / "claim_reality.json") or {}
    manifest: Dict[str, Any] = _load_json(out_p / "run_manifest.json") or {}

    audit_file = out_p / "audit_log.jsonl"
    audit_valid = False
    if audit_file.exists():
        audit_valid, _ = verify_audit_chain(audit_file)

    # Portfolio ranking (risk index descending)
    ranked = sorted(
        scores.items(),
        key=lambda kv: kv[1].get("overall_risk_index", 0.0),
        reverse=True,
    )
    entities = [
        {
            "entity_id": eid,
            "risk_index": s.get("overall_risk_index", 0.0),
            "tier": s.get("risk_tier", "low"),
            "percentile": 100.0 * s.get("peer_percentile", 0.5),
            "trend": s.get("qoq_trend", "stable"),
            "findings_count": s.get("findings_count", 0),
        }
        for eid, s in ranked
    ]

    concept_counter = Counter(f.get("category", "UNKNOWN") for f in findings)
    total = max(1, len(findings))
    concept_rows = [
        {"concept": c, "count": n, "share": 100.0 * n / total}
        for c, n in concept_counter.most_common()
    ]

    detector_rows = [
        {"detector_id": d, "count": n}
        for d, n in Counter(f.get("detector_id", "?") for f in findings).most_common(_TOP_DETECTORS)
    ]

    # Highest-priority findings: score-equivalent ranking, truncated reasons.
    def _prio(f: Dict[str, Any]) -> float:
        return float(f.get("severity_weight", 1.0)) * min(abs(float(f.get("deviation", 0.0))), 5.0) * float(f.get("confidence", 0.9))

    top_findings = []
    for f in sorted(findings, key=_prio, reverse=True)[:_TOP_FINDINGS]:
        reason = " ".join(str(f.get("reason_text", "")).split())
        top_findings.append({
            "finding_id": f.get("finding_id", ""),
            "entity_id": f.get("entity_id", ""),
            "detector_id": f.get("detector_id", ""),
            "scope": f.get("scope", ""),
            "severity_weight": float(f.get("severity_weight", 1.0)),
            "reason_text": reason[:_REASON_MAX] + ("..." if len(reason) > _REASON_MAX else ""),
        })

    claim_entities = []
    for eid, c in (claims.get("entities") or {}).items():
        claim_entities.append({
            "entity_id": eid,
            "index": float(c.get("index", 0.0)),
            "verdict": c.get("verdict", "unknown"),
            "n_claimed": int(c.get("n_claimed", len(c.get("comparisons", [])))),
            "exaggerated_count": int(c.get("exaggerated_count", 0)),
        })
    claim_entities.sort(key=lambda c: c["index"])

    exec_summary = manifest.get("execution_summary") or {}
    return {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "run_id": manifest.get("run_id", "n/a"),
        "manifest_hash": str(manifest.get("manifest_hash", "n/a")),
        "audit_valid": bool(audit_valid),
        "entity_count": len(scores),
        "total_findings": len(findings),
        "total_alerts": int(exec_summary.get("total_alerts", 0)),
        "high_risk_count": sum(1 for e in entities if e["tier"] in ("high", "critical")),
        "queue_total": sum(len(q) for q in queues.values()) if isinstance(queues, dict) else 0,
        "entities": entities,
        "concept_rows": concept_rows,
        "detector_counts": detector_rows,
        "claim_summary": claims.get("summary") or {
            "entities_with_claims": 0,
            "mean_index": None,
            "materially_exaggerated": [],
            "substantiated": 0,
        },
        "claim_entities": claim_entities,
        "top_findings": top_findings,
    }


def render_html(data: Dict[str, Any]) -> str:
    """Render the styled HTML supervisory report."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    return env.get_template("report.html.j2").render(report=data)


def _weasyprint_available() -> bool:
    """Detect whether WeasyPrint's GTK/Pango system libraries are loadable.

    WeasyPrint prints a help banner straight to fd 2 (bypassing
    ``redirect_stderr``) when its native libs are missing, so we probe with
    ctypes first and skip the import entirely when the runtime is absent.
    Result is cached -- the environment does not change mid-process.
    """
    if getattr(_weasyprint_available, "_cached", None) is not None:
        return _weasyprint_available._cached  # type: ignore[attr-defined]

    import ctypes
    import ctypes.util
    import sys

    ok = False
    try:
        if sys.platform.startswith("win"):
            groups = [
                ("libgobject-2.0-0", "gobject-2.0-0"),
                ("libpango-1.0-0", "pango-1.0-0"),
                ("libcairo-2", "cairo-2"),
            ]
            ok = all(
                any(_try_cdll(name) for name in group)
                for group in groups
            )
        else:
            ok = all(
                (p := ctypes.util.find_library(name)) and _try_cdll(p)
                for name in ("gobject-2.0", "pango-1.0", "cairo")
            )
    except Exception:
        ok = False

    _weasyprint_available._cached = ok  # type: ignore[attr-defined]
    return ok


def _try_cdll(name: str) -> bool:
    import ctypes

    try:
        ctypes.CDLL(name)
        return True
    except OSError:
        return False


def html_to_pdf(html: str) -> Optional[bytes]:
    """Convert HTML to PDF with WeasyPrint; None when unavailable (no GTK etc.)."""
    if not _weasyprint_available():
        return None
    try:
        from weasyprint import HTML  # type: ignore

        return HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf()
    except Exception:
        return None


def render_text(data: Dict[str, Any]) -> List[str]:
    """Plain-text rendering of the same content (fallback PDF + quick preview)."""
    w = 90
    rule = "=" * w
    lines: List[str] = [
        "SAT-SA SUPERVISORY ASSESSMENT REPORT",
        f"Run {data['run_id']}  |  {data['generated_at']}  |  version {data['version']}",
        f"Manifest {data['manifest_hash']}",
        f"Audit chain: {'INTACT' if data['audit_valid'] else 'TAMPER DETECTED'}",
        rule,
        "PORTFOLIO SUMMARY",
        f"  Entities assessed: {data['entity_count']}"
        f"   Findings: {data['total_findings']}"
        f"   High/Critical: {data['high_risk_count']}"
        f"   Queued for review: {data['queue_total']}",
        f"  Alerts analysed: {data['total_alerts']}",
        "",
        "PORTFOLIO RISK RANKING",
        f"  {'#':>3}  {'ENTITY':<15} {'RISK':>5}  {'TIER':<10} {'PEER%':>6}  {'QOQ':<14} {'FIND':>5}",
    ]
    for i, e in enumerate(data["entities"], start=1):
        lines.append(
            f"  {i:>3}  {e['entity_id']:<15} {e['risk_index']:>5.1f}  {e['tier']:<10}"
            f" {e['percentile']:>6.1f}  {e['trend']:<14} {e['findings_count']:>5}"
        )

    lines += ["", "FINDINGS BY CONCEPT LANE"]
    for c in data["concept_rows"]:
        lines.append(f"  {c['concept']:<20} {c['count']:>6}  ({c['share']:.1f}%)")

    lines += ["", "CLAIM-VS-REALITY INDEX"]
    if data["claim_entities"]:
        mean_idx = data["claim_summary"].get("mean_index")
        lines.append(f"  Mean index: {mean_idx}   Entities with claims: {data['claim_summary'].get('entities_with_claims')}")
        for c in data["claim_entities"]:
            lines.append(
                f"  {c['entity_id']:<15} {c['index']:>5.1f}  {c['verdict']:<26}"
                f" claimed={c['n_claimed']} exaggerated={c['exaggerated_count']}"
            )
        exag = data["claim_summary"].get("materially_exaggerated") or []
        if exag:
            lines.append(f"  Materially exaggerated: {', '.join(exag)}")
    else:
        lines.append("  No self-reported KPI claims submitted.")

    lines += ["", f"HIGHEST-PRIORITY FINDINGS (top {len(data['top_findings'])})"]
    for f in data["top_findings"]:
        lines.append(f"  {f['finding_id']}  {f['entity_id']}  {f['detector_id']}  sev={f['severity_weight']:.1f}")
        lines.append(f"      scope: {f['scope']}")
        lines.append(f"      {f['reason_text']}")

    lines += [
        "",
        rule,
        f"SAT-SA v{data['version']} - generated entirely offline (no network calls)",
    ]
    return lines


def build_report(output_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Build the full report package.

    Returns ``{"html": str, "pdf": bytes, "pdf_engine": "weasyprint"|"minipdf",
    "data": dict}``. The PDF engine is recorded so the UI can disclose which
    renderer produced the file.
    """
    data = collect_report_data(output_dir)
    html = render_html(data)
    pdf = html_to_pdf(html)
    engine = "weasyprint"
    if pdf is None:
        from satsa.minipdf import text_to_pdf

        pdf = text_to_pdf(render_text(data))
        engine = "minipdf"
    return {"html": html, "pdf": pdf, "pdf_engine": engine, "data": data}

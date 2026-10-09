"""Tests for report export (satsa.report, satsa.minipdf)."""

import pytest

from satsa.minipdf import MAX_COLS, text_to_pdf
from satsa.report import (
    build_report,
    collect_report_data,
    html_to_pdf,
    render_html,
    render_text,
)


def test_collect_report_data_shape():
    data = collect_report_data()
    for key in (
        "run_id", "manifest_hash", "audit_valid", "entity_count", "total_findings",
        "entities", "concept_rows", "detector_counts", "claim_summary",
        "claim_entities", "top_findings", "queue_total",
    ):
        assert key in data
    assert data["version"]
    if data["entities"]:
        # sorted by risk index descending
        idx = [e["risk_index"] for e in data["entities"]]
        assert idx == sorted(idx, reverse=True)
    assert len(data["top_findings"]) <= 25
    assert len(data["detector_counts"]) <= 15


def test_render_html_is_styled_document():
    data = collect_report_data()
    html = render_html(data)
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "<table" in html
    assert "SAT-SA Supervisory Assessment Report" in html
    if data["entities"]:
        assert data["entities"][0]["entity_id"] in html
    if data["claim_entities"]:
        assert "Claim-vs-Reality" in html


def test_render_text_has_sections():
    data = collect_report_data()
    lines = render_text(data)
    text = "\n".join(lines)
    assert "PORTFOLIO RISK RANKING" in text
    assert "CLAIM-VS-REALITY INDEX" in text
    assert "generated entirely offline" in text
    # Longest lines are the truncated finding reasons (pre-wrapped by minipdf)
    assert all(len(l) <= 300 for l in lines)


def test_minipdf_structure():
    pdf = text_to_pdf(["Hello SAT-SA", "line two", "", "x" * (MAX_COLS * 3)])
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    # xref offsets must point at their objects
    tail = pdf.rsplit(b"startxref", 1)[1]
    xref_pos = int(tail.split(b"%%EOF")[0].strip())
    assert pdf[xref_pos:xref_pos + 4] == b"xref"
    rows = pdf[xref_pos:].split(b"\n")
    size = int(rows[1].split()[1])
    for i in range(1, size):
        off = int(rows[2 + i].split()[0])
        expect = str(i).encode() + b" 0 obj"
        assert pdf[off:off + len(expect)] == expect


def test_minipdf_escapes_and_paginates():
    # 5000 lines force multiple pages; special chars must not break the file
    lines = [f"row {i} (paren) \\ slash" for i in range(5000)]
    pdf = text_to_pdf(lines)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.count(b"/Type /Page ") >= 5  # >1 page
    assert b"row 4999" in pdf


def test_build_report_package():
    rep = build_report()
    assert rep["pdf_engine"] in ("weasyprint", "minipdf")
    assert rep["pdf"][:5] == b"%PDF-"
    assert len(rep["pdf"]) > 1000
    assert rep["html"] and rep["data"]["run_id"]
    # On hosts without GTK, the stdlib fallback must engage silently
    if html_to_pdf("<p>x</p>") is None:
        assert rep["pdf_engine"] == "minipdf"

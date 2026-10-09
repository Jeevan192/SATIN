"""Minimal stdlib-only PDF writer (fallback when WeasyPrint/GTK is unavailable).

Produces simple paginated monospaced-text PDFs (A4, Courier) with a correct
cross-reference table. No third-party dependencies, no network access -- used
by :mod:`satsa.report` when the optional ``weasyprint`` extra cannot load
(e.g. air-gapped Windows hosts missing GTK libraries).

This is intentionally *not* a general HTML renderer: it renders plain text
lines. The primary report path renders styled HTML via Jinja2 and converts it
with WeasyPrint when that is available.
"""

from typing import List, Sequence

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 48
FONT_SIZE = 9
LINE_HEIGHT = 12.0
# Courier is a fixed-width font: advance = 0.6 * font size.
CHAR_W = FONT_SIZE * 0.6
MAX_COLS = int((PAGE_W - 2 * MARGIN) / CHAR_W)


def _escape(text: str) -> str:
    """Escape a string for a PDF literal string token (and strip control chars)."""
    out = []
    for ch in text:
        if ch in ("\\", "(", ")"):
            out.append("\\" + ch)
        elif ord(ch) < 32 or ord(ch) > 126:
            out.append("?")  # Courier/WinAnsi: keep it simple and deterministic
        else:
            out.append(ch)
    return "".join(out)


def _paginate(lines: Sequence[str], max_lines: int) -> List[List[str]]:
    per_page = int((PAGE_H - 2 * MARGIN) / LINE_HEIGHT)
    return [list(lines[i:i + per_page]) for i in range(0, len(lines), per_page)] or [[]]


def text_to_pdf(lines: Sequence[str]) -> bytes:
    """Render plain text lines into a minimal, spec-valid PDF document."""
    # Hard-wrap to the printable width so no glyph is clipped.
    wrapped: List[str] = []
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            wrapped.append("")
        else:
            while len(line) > MAX_COLS:
                wrapped.append(line[:MAX_COLS])
                line = line[MAX_COLS:]
            wrapped.append(line)

    pages = _paginate(wrapped, 0)

    # Object layout: 1 catalog, 2 pages, 3 font, then (page, content) pairs.
    objects: List[bytes] = []
    kids = []
    first_page_obj = 4
    for i in range(len(pages)):
        page_obj_num = first_page_obj + i * 2
        content_obj_num = page_obj_num + 1
        kids.append(f"{page_obj_num} 0 R")

        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_num} 0 R >>"
        )
        content_stream = [f"BT /F1 {FONT_SIZE} Tf {MARGIN} {PAGE_H - MARGIN} Td {LINE_HEIGHT:g} TL"]
        for line in pages[i]:
            content_stream.append(f"({_escape(line)}) Tj T*")
        content_stream.append("ET")
        stream_bytes = "\n".join(content_stream).encode("latin-1", errors="replace")
        content_dict = f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1") + stream_bytes + b"\nendstream"

        objects.append(page_dict.encode("latin-1"))
        objects.append(content_dict)

    catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
    pages_dict = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode("latin-1")
    font_dict = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"

    ordered = [catalog, pages_dict, font_dict] + objects

    out = bytearray(b"%PDF-1.4\n")
    offsets: List[int] = []
    for i, body in enumerate(ordered, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode("latin-1") + body + b"\nendobj\n"

    xref_pos = len(out)
    n = len(ordered) + 1
    out += f"xref\n0 {n}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode("latin-1")
    out += f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1")
    return bytes(out)

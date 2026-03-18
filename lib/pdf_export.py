from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def export_pdf(findings: list[Any], session_id: str) -> dict[str, Any]:
    """Export findings to a PDF file.

    Args:
        findings: List of finding dicts to render into the report.
        session_id: Unique session identifier used to name the output file.

    Returns:
        dict with keys:
            pdf_path  (str): Absolute path to the generated PDF.
            page_count (int): Number of pages in the generated PDF.

    Raises:
        ValueError: If session_id is empty or findings is not a list.
        RuntimeError: If PDF generation fails.
    """
    if not isinstance(findings, list):
        raise ValueError(f"findings must be a list, got {type(findings).__name__}")
    if not session_id or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")

    try:
        from reportlab.lib import colors  # type: ignore[import]
        from reportlab.lib.pagesizes import A4  # type: ignore[import]
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[import]
        from reportlab.lib.units import cm  # type: ignore[import]
        from reportlab.platypus import (  # type: ignore[import]
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("reportlab is required for PDF export. Install it with: pip install reportlab") from exc

    output_dir = Path(tempfile.gettempdir()) / "donjon_pdf_exports"
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_session = "".join(c if c.isalnum() or c in "-_" else "_" for c in session_id)
    pdf_path = output_dir / f"report_{safe_session}.pdf"

    styles = getSampleStyleSheet()
    story: list[Any] = []

    # Title
    title_style = styles["Title"]
    story.append(Paragraph("Security Findings Report", title_style))
    story.append(Paragraph(f"Session: {session_id}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    if not findings:
        story.append(Paragraph("No findings recorded for this session.", styles["Normal"]))
    else:
        # Collect all unique field names across findings to build table headers
        headers: list[str] = _collect_headers(findings)
        table_data: list[list[str]] = [headers]

        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                logger.warning("Skipping non-dict finding at index %d: %r", idx, finding)
                row = [str(finding)] + [""] * (len(headers) - 1)
            else:
                row = [str(finding.get(h, "")) for h in headers]
            table_data.append(row)

        col_count = len(headers)
        page_width = A4[0] - 4 * cm  # usable width
        col_width = page_width / col_count

        table = Table(table_data, colWidths=[col_width] * col_count, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(table)

    # Build the document and capture page count
    page_counter = _PageCounter()
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    try:
        doc.build(story, onLaterPages=page_counter.count, onFirstPage=page_counter.count)
    except Exception as exc:
        raise RuntimeError(f"PDF generation failed for session {session_id!r}: {exc}") from exc

    if not pdf_path.exists():
        raise RuntimeError(f"PDF file was not created at {pdf_path}")

    page_count = max(page_counter.pages, 1)
    logger.info("PDF exported: path=%s pages=%d session=%s", pdf_path, page_count, session_id)

    return {
        "pdf_path": str(pdf_path),
        "page_count": page_count,
    }


def _collect_headers(findings: list[Any]) -> list[str]:
    """Return a stable, ordered list of column headers from all finding dicts."""
    seen: dict[str, None] = {}
    for finding in findings:
        if isinstance(finding, dict):
            for key in finding:
                seen[str(key)] = None
    headers = list(seen.keys())
    # Promote common severity/title fields to front for readability
    priority = ["id", "title", "severity", "description", "status"]
    front: list[str] = [h for h in priority if h in seen]
    rest: list[str] = [h for h in headers if h not in seen or h not in front]
    return front + rest if front else (headers or ["finding"])


class _PageCounter:
    """Callback object that counts pages as reportlab builds the document."""

    pages: int

    def __init__(self) -> None:
        self.pages = 0

    def count(self, canvas: Any, doc: Any) -> None:  # noqa: ARG002
        self.pages += 1

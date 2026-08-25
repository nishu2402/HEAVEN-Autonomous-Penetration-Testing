"""HEAVEN — shared PDF renderer for coverage / compliance matrices.

Both the methodology coverage report (:mod:`heaven.methodology`) and the
compliance control-coverage report (:mod:`heaven.devsecops.compliance_frameworks`)
render the *same shape* of deliverable: a titled cover line, a KPI strip, then a
sequence of tables (one per category / control group). This module is the single
Platypus/reportlab renderer they share, so the two PDFs look identical and there
is one place to maintain the styling.

Kept import-light: ``reportlab`` is imported lazily inside :func:`render_matrix_pdf`
so importing this module never forces the dependency. Callers that want a graceful
degradation should check ``reportlab`` themselves (the API already does) — this
function raises ``RuntimeError`` with an actionable message when it is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class MatrixSection:
    """One table in the report — a category (methodology) or a control group."""
    heading: str
    columns: list[str]
    rows: list[list[str]] = field(default_factory=list)
    # Index of each row's "exercised/present" flag drives light highlighting; a
    # truthy entry shades that data row. Same length as ``rows`` (or empty).
    highlight: list[bool] = field(default_factory=list)
    note: str = ""                       # shown when the section has no rows
    col_ratios: Optional[list[float]] = None  # relative widths; defaults to equal


# Brand palette (echoes the HTML report).
_INK = "#1a1f29"
_ACCENT = "#4f46e5"
_MUTED = "#5b6472"
_HDR_BG = "#f0f3f8"
_HIT_BG = "#eef4ff"
_LINE = "#e3e7ee"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")


def render_matrix_pdf(
    *,
    title: str,
    subtitle: str = "",
    meta_lines: Optional[list[str]] = None,
    intro: str = "",
    kpis: Optional[list[tuple[str, str]]] = None,
    sections: Optional[list[MatrixSection]] = None,
    footer: str = "",
) -> bytes:
    """Render a coverage/compliance matrix to PDF bytes.

    ``kpis`` is a list of ``(value, label)`` shown as a KPI strip. ``sections``
    is the body. Raises ``RuntimeError`` if reportlab is unavailable.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as exc:  # pragma: no cover - exercised via API 503 path
        raise RuntimeError(
            "PDF export needs reportlab. Run `pip install reportlab`."
        ) from exc

    import io

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("cov_h1", parent=styles["Heading1"], fontSize=18,
                        textColor=colors.HexColor(_INK), spaceAfter=2)
    sub = ParagraphStyle("cov_sub", parent=styles["Normal"], fontSize=9,
                         textColor=colors.HexColor(_MUTED), spaceAfter=2)
    body = ParagraphStyle("cov_body", parent=styles["Normal"], fontSize=9.5,
                          textColor=colors.HexColor(_INK), spaceAfter=6, leading=13)
    h3 = ParagraphStyle("cov_h3", parent=styles["Heading3"], fontSize=11.5,
                        textColor=colors.HexColor("#33405a"), spaceBefore=12, spaceAfter=4)
    cell = ParagraphStyle("cov_cell", parent=styles["Normal"], fontSize=8,
                          textColor=colors.HexColor(_INK), leading=10.5, alignment=TA_LEFT)
    cell_hdr = ParagraphStyle("cov_cell_hdr", parent=cell, fontSize=8,
                              textColor=colors.HexColor("#33405a"),
                              fontName="Helvetica-Bold")
    kpi_num = ParagraphStyle("cov_kpi_n", parent=styles["Normal"], fontSize=17,
                             textColor=colors.HexColor(_INK), fontName="Helvetica-Bold",
                             alignment=1)
    kpi_lbl = ParagraphStyle("cov_kpi_l", parent=styles["Normal"], fontSize=7,
                             textColor=colors.HexColor(_MUTED), alignment=1)
    foot = ParagraphStyle("cov_foot", parent=sub, fontSize=7.5, spaceBefore=16)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm, title=title)
    story: list = [Paragraph(_esc(title), h1)]
    if subtitle:
        story.append(Paragraph(_esc(subtitle), sub))
    for ml in (meta_lines or []):
        story.append(Paragraph(_esc(ml), sub))
    story.append(Spacer(1, 6))
    if intro:
        story.append(Paragraph(_esc(intro), body))

    # KPI strip.
    if kpis:
        kcells = [[Paragraph(_esc(str(v)), kpi_num) for v, _ in kpis],
                  [Paragraph(_esc(str(lbl)), kpi_lbl) for _, lbl in kpis]]
        avail = doc.width
        kt = Table(kcells, colWidths=[avail / len(kpis)] * len(kpis))
        kt.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(_LINE)),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor(_LINE)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fcfdff")),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(Spacer(1, 4))
        story.append(kt)

    for sec in (sections or []):
        story.append(Paragraph(_esc(sec.heading), h3))
        if not sec.rows:
            story.append(Paragraph("<i>%s</i>" % _esc(
                sec.note or "No automated tests in this category."), sub))
            continue
        ncol = len(sec.columns)
        header = [Paragraph(_esc(c), cell_hdr) for c in sec.columns]
        data = [header]
        for r in sec.rows:
            data.append([Paragraph(_esc(str(c)), cell) for c in r])
        ratios = sec.col_ratios or [1.0] * ncol
        tot = sum(ratios) or 1.0
        widths = [doc.width * (x / tot) for x in ratios]
        t = Table(data, colWidths=widths, repeatRows=1)
        ts = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_HDR_BG)),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(_LINE)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        for ri, hl in enumerate(sec.highlight or [], start=1):
            if hl:
                ts.append(("BACKGROUND", (0, ri), (-1, ri), colors.HexColor(_HIT_BG)))
        t.setStyle(TableStyle(ts))
        story.append(t)

    if footer:
        story.append(Paragraph(_esc(footer), foot))

    doc.build(story)
    return buf.getvalue()


def _esc(s: str) -> str:
    """Escape text for a Platypus Paragraph (which parses a mini-HTML)."""
    return (str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

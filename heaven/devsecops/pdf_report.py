"""
HEAVEN — Professional Penetration-Test Report Generator (PDF)

Produces a client-ready PDF deliverable using **reportlab** (pure Python — no
system libraries, installs cleanly on macOS/Linux/Windows). The structure mirrors
the HTML report (:mod:`heaven.devsecops.compliance_report`) exactly, and the two
share the same severity palette, OWASP mapping and knowledge-base enrichment so a
finding looks identical whether exported as HTML or PDF:

  1. Cover page (classification, engagement, overall-risk badge, metadata)
  2. Confidentiality notice
  3. Document control + revision history
  4. Table of contents (real page numbers, two-pass build)
  5. Executive summary (narrative + severity KPIs + distribution + key findings)
  6. Scope & methodology (targets, phases, standards)
  7. Risk-rating methodology (severity scale + remediation SLAs)
  8. Findings summary table
  9. Detailed findings (metadata, description, impact, evidence/PoC, remediation, refs)
 10. OWASP Top 10 coverage
 11. Remediation roadmap (prioritised)
 12. Appendix (tooling, glossary, disclaimer)

If reportlab is not installed, :meth:`PDFReportGenerator.generate` degrades
gracefully by writing the professional HTML report to a ``.html`` file instead.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Optional
from xml.sax.saxutils import escape as _xml_escape  # nosec B406 -- escape() is OUTPUT encoding (a security control), not XML parsing

from heaven.devsecops.compliance_report import SEVERITY_META, ComplianceReportGenerator
from heaven.utils.logger import get_logger

logger = get_logger("devsecops.pdf")

_SEV_ORDER = {k: v["order"] for k, v in SEVERITY_META.items()}
_OWASP = ComplianceReportGenerator()  # reuse OWASP_MAP / _owasp_for — keeps reports in sync

# CVSS v3.1 vectors per vuln class (illustrative; shown when known)
_CVSS_VECTORS = {
    "sqli": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "sql_injection": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "xss": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssrf": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "idor": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "ssti": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "command_injection": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "default_credentials": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}


def _logo_drawing(size_pt: float = 46.0):
    """The 'Ascendant Aegis' mark as a ReportLab vector Drawing.

    Redrawn (not rasterised) so the PDF cover carries a crisp brand icon that
    matches the web/CLI mark: a faceted hexagonal aegis enclosing an "H" whose
    crossbar ascends to a glowing apex node. Colours are solid (ReportLab shapes
    have no gradients) but echo the emerald/cyan brand ramp.
    """
    from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon
    from reportlab.lib import colors

    s = size_pt / 128.0

    def pt(x: float, y: float) -> tuple[float, float]:
        # map 128-unit design space (y-down) → Drawing space (y-up)
        return (x * s, (128 - y) * s)

    edge = colors.HexColor("#34E5A3")   # emerald
    mono = colors.HexColor("#22D3EE")   # cyan
    d = Drawing(size_pt, size_pt)

    hex_flat: list[float] = []
    for x, y in [(64, 10), (110, 37), (110, 91), (64, 118), (18, 91), (18, 37)]:
        px, py = pt(x, y)
        hex_flat += [px, py]
    d.add(Polygon(hex_flat, strokeColor=edge, strokeWidth=5 * s,
                  fillColor=colors.HexColor("#0B1220"), strokeLineJoin=1))

    def seg(x0: float, y0: float, x1: float, y1: float) -> None:
        a, b = pt(x0, y0), pt(x1, y1)
        d.add(Line(a[0], a[1], b[0], b[1], strokeColor=mono,
                   strokeWidth=8 * s, strokeLineCap=1))

    seg(48, 50, 48, 88)          # left bar
    seg(80, 50, 80, 88)          # right bar
    seg(48, 72, 64, 54)          # chevron ↑
    seg(64, 54, 80, 72)          # chevron ↓
    nx, ny = pt(64, 45)
    d.add(Circle(nx, ny, 4.6 * s, fillColor=colors.HexColor("#EAFBF4"), strokeColor=None))
    return d


def _sev_of(f: dict) -> str:
    s = (f.get("severity") or "info").lower()
    return s if s in SEVERITY_META else "info"


def _esc(value: Any) -> str:
    return _xml_escape("" if value is None else str(value))


class PDFReportGenerator:
    """Generate professional PDF penetration-test reports via reportlab."""

    def __init__(self) -> None:
        try:
            import reportlab  # noqa: F401
            self.available = True
        except ImportError:
            self.available = False
            logger.warning("reportlab not installed — PDF export will fall back to HTML "
                           "(pip install reportlab)")

    # ── public API ──────────────────────────────────────────────────

    def generate(self, data: dict[str, Any], output_path: str) -> bool:
        """Render the report to ``output_path`` (.pdf). Returns True on success.

        Without reportlab, writes the professional HTML report to a sibling
        ``.html`` file (same content, different container) and returns True.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        if not self.available:
            return self._html_fallback(data, output_path)
        try:
            self._build_pdf(data, output_path)
            logger.info(f"PDF report written to {output_path}")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error(f"PDF generation failed ({exc}); falling back to HTML")
            return self._html_fallback(data, output_path)

    def _html_fallback(self, data: dict[str, Any], output_path: str) -> bool:
        try:
            from pathlib import Path
            html_path = (output_path[:-4] + ".html") if output_path.endswith(".pdf") \
                else output_path + ".html"
            findings = self._findings(data)
            html = ComplianceReportGenerator().generate_html_report(
                findings, engagement_name=self._engagement(data),
                assets=data.get("assets"))
            Path(html_path).write_text(html, encoding="utf-8")
            logger.info(f"HTML report written to {html_path} (install reportlab for PDF)")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Report generation failed: {exc}")
            return False

    # ── data prep (shared shape with the HTML report) ───────────────

    @staticmethod
    def _engagement(data: dict) -> str:
        return (data.get("engagement") or data.get("client_name")
                or data.get("target") or "HEAVEN Engagement")

    @staticmethod
    def _findings(data: dict) -> list[dict]:
        from heaven.devsecops.vuln_kb import enrich_finding
        raw = data.get("findings") or data.get("vulnerabilities") or []
        enriched = [enrich_finding(dict(f)) for f in raw]
        return sorted(enriched, key=lambda f: (_SEV_ORDER.get(_sev_of(f), 4),
                                               -float(f.get("risk_score") or 0)))

    # ── PDF construction ────────────────────────────────────────────

    def _build_pdf(self, data: dict[str, Any], output_path: str) -> None:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
        from reportlab.platypus import (
            PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
        from reportlab.platypus.tableofcontents import TableOfContents

        eng = self._engagement(data)
        findings = self._findings(data)
        counts = {k: 0 for k in SEVERITY_META}
        for f in findings:
            counts[_sev_of(f)] += 1
        overall = self._overall(counts)
        scope = data.get("scope") or sorted({str(f.get("target")) for f in findings if f.get("target")})
        from heaven.devsecops.inventory import inventory_totals, normalize_assets
        inventory = normalize_assets(data.get("assets"))
        inv_totals = inventory_totals(inventory)
        now = datetime.datetime.now(datetime.UTC)
        gen_date = now.strftime("%d %B %Y, %H:%M UTC")
        version = str(data.get("version") or "1.0")

        ink = colors.HexColor("#1a1f29")
        muted = colors.HexColor("#5b6472")
        line = colors.HexColor("#d7dde7")

        ss = getSampleStyleSheet()
        styles = {
            "body": ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica",
                                   fontSize=9.5, leading=14, textColor=ink, spaceAfter=6),
            "small": ParagraphStyle("small", parent=ss["BodyText"], fontName="Helvetica",
                                    fontSize=8, leading=11, textColor=muted),
            "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                                 fontSize=15, textColor=ink, spaceBefore=4, spaceAfter=10),
            "h3": ParagraphStyle("h3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                                 fontSize=11, textColor=ink, spaceBefore=8, spaceAfter=4),
            "label": ParagraphStyle("label", parent=ss["BodyText"], fontName="Helvetica-Bold",
                                    fontSize=7.5, textColor=muted, spaceBefore=8, spaceAfter=2),
            "cell": ParagraphStyle("cell", parent=ss["BodyText"], fontName="Helvetica",
                                   fontSize=8.5, leading=12, textColor=ink),
            "cellb": ParagraphStyle("cellb", parent=ss["BodyText"], fontName="Helvetica-Bold",
                                    fontSize=8.5, leading=12, textColor=ink),
            "th": ParagraphStyle("th", parent=ss["BodyText"], fontName="Helvetica-Bold",
                                 fontSize=8.5, leading=12, textColor=colors.HexColor("#33405a")),
            "pre": ParagraphStyle("pre", parent=ss["Code"], fontName="Courier",
                                  fontSize=7.5, leading=10, textColor=colors.HexColor("#d6deeb"),
                                  wordWrap="CJK"),
        }
        cw = A4[0] - 28 * mm  # content width

        def heading(num: str, text: str) -> Paragraph:
            p = Paragraph(f"{num}&nbsp;&nbsp;{_esc(text)}", styles["h2"])
            p._toc_text = f"{num}  {text}"  # picked up by afterFlowable
            return p

        def pill(sev: str) -> Table:
            m = SEVERITY_META[sev]
            # 20mm — must stay narrower than its host cell (Severity column is
            # 26mm and carries 12pt of left+right padding); a 26mm pill overflowed
            # into the adjacent CVSS column. 20mm leaves clear margin in both the
            # summary (26mm) and key-findings (30mm) tables.
            t = Table([[Paragraph(f'<font color="white"><b>{m["label"]}</b></font>',
                                  styles["cell"])]], colWidths=[20 * mm], rowHeights=[6 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(m["color"])),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]))
            return t

        def table(rows, col_widths, header=True, zebra=True, font=8.5):
            t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
            cmds = [
                ("GRID", (0, 0), (-1, -1), 0.5, line),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), font),
                ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
            if header:
                cmds += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f8")),
                         ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
            if zebra:
                cmds.append(("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1),
                             [colors.white, colors.HexColor("#f7f9fc")]))
            t.setStyle(TableStyle(cmds))
            return t

        story: list[Any] = []

        # ── 1. Cover ──
        story.append(Spacer(1, 22 * mm))
        band = Table([[_logo_drawing(46),
                       Paragraph('<font color="white"><b>HEAVEN</b></font>',
                                 ParagraphStyle("brand", fontName="Helvetica-Bold",
                                                fontSize=30, textColor=colors.white, leading=34))]],
                     colWidths=[20 * mm, cw - 20 * mm], rowHeights=[20 * mm])
        band.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1b2a")),
                                  ("LEFTPADDING", (0, 0), (0, 0), 14),
                                  ("LEFTPADDING", (1, 0), (1, 0), 6),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(band)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("Autonomous Penetration-Testing Platform", styles["small"]))
        story.append(Spacer(1, 18 * mm))
        story.append(Paragraph("Penetration Test Report",
                               ParagraphStyle("ctitle", fontName="Helvetica-Bold", fontSize=30,
                                              textColor=ink, leading=34)))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(_esc(eng), ParagraphStyle("csub", fontName="Helvetica",
                     fontSize=14, textColor=muted)))
        story.append(Spacer(1, 10 * mm))
        ocol = colors.HexColor(self._overall_color(overall))
        badge = Table([[Paragraph(f'<font color="white"><b>Overall Risk: {_esc(overall)}</b></font>',
                                  ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=13,
                                                 textColor=colors.white, alignment=TA_CENTER))]],
                      colWidths=[70 * mm], rowHeights=[11 * mm])
        badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ocol),
                                   ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(badge)
        story.append(Spacer(1, 14 * mm))
        meta = [
            ["Findings", f"{len(findings)}  ({counts['critical']} critical, {counts['high']} high, "
                         f"{counts['medium']} medium, {counts['low']} low)"],
            ["Targets in scope", str(len(scope))],
            ["Report date", gen_date],
            ["Version", version],
            ["Classification", "CONFIDENTIAL"],
            ["Prepared by", "HEAVEN Autonomous Penetration-Testing Platform"],
        ]
        mt = Table([[Paragraph(k, styles["cellb"]), Paragraph(_esc(v), styles["cell"])]
                    for k, v in meta], colWidths=[45 * mm, cw - 45 * mm])
        mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 2),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        story.append(mt)
        story.append(PageBreak())

        # ── 2. Confidentiality ──
        story.append(heading("", "Confidentiality Notice"))
        note = Table([[Paragraph(
            f"This document contains confidential and proprietary information about the security "
            f"posture of <b>{_esc(eng)}</b>. It is intended solely for the named recipient and "
            f"authorised stakeholders. It details vulnerabilities that could be exploited to "
            f"compromise systems and data; unauthorised disclosure, copying, or distribution is "
            f"strictly prohibited.", styles["body"])]], colWidths=[cw])
        note.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff8e6")),
                                  ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#f0d98c")),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 12),
                                  ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                                  ("TOPPADDING", (0, 0), (-1, -1), 10),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
        story.append(note)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Distribute on a strict need-to-know basis and store per your "
                               "organisation's data-classification policy.", styles["small"]))

        # ── 3. Document control ──
        story.append(Spacer(1, 8))
        story.append(heading("", "Document Control"))
        dc = [[Paragraph("Field", styles["th"]), Paragraph("Detail", styles["th"])]]
        for k, v in [("Engagement", eng), ("Assessor", "HEAVEN Autonomous Penetration-Testing Platform"),
                     ("Report version", version), ("Date generated", gen_date),
                     ("Targets in scope", str(len(scope))), ("Total findings", str(len(findings))),
                     ("Overall risk rating", overall), ("Classification", "CONFIDENTIAL")]:
            dc.append([Paragraph(_esc(k), styles["cell"]), Paragraph(_esc(v), styles["cell"])])
        story.append(table(dc, [50 * mm, cw - 50 * mm]))
        story.append(Paragraph("Revision History", styles["h3"]))
        rev = [[Paragraph(h, styles["th"]) for h in ("Version", "Date", "Author", "Description")],
               [Paragraph(version, styles["cell"]), Paragraph(gen_date, styles["cell"]),
                Paragraph("HEAVEN", styles["cell"]),
                Paragraph("Automated assessment report generated from engagement findings.",
                          styles["cell"])]]
        story.append(table(rev, [22 * mm, 45 * mm, 25 * mm, cw - 92 * mm]))
        story.append(PageBreak())

        # ── 4. Table of Contents ──
        story.append(Paragraph("Table of Contents", styles["h2"]))
        toc = TableOfContents()
        toc.levelStyles = [ParagraphStyle("toc1", fontName="Helvetica", fontSize=10,
                                          leading=18, textColor=ink)]
        story.append(toc)
        story.append(PageBreak())

        # ── 5. Executive Summary ──
        story.append(heading("1.", "Executive Summary"))
        story.append(Paragraph(self._posture(eng, counts, len(findings), overall, len(scope)),
                               styles["body"]))
        # KPI row
        kpi_cells = []
        for sev in ("critical", "high", "medium", "low", "info"):
            m = SEVERITY_META[sev]
            kpi_cells.append(Paragraph(
                f'<para align="center"><font size="20" color="{m["color"]}"><b>{counts[sev]}</b>'
                f'</font><br/><font size="7" color="#5b6472">{m["label"].upper()}</font></para>',
                styles["cell"]))
        kpit = Table([kpi_cells], colWidths=[cw / 5.0] * 5)
        kpit.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, line),
                                  ("INNERGRID", (0, 0), (-1, -1), 0.5, line),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 10),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
        story.append(Spacer(1, 4))
        story.append(kpit)
        # Severity distribution bar
        story.append(Paragraph("Severity Distribution", styles["h3"]))
        story.append(self._sev_bar(findings, counts, cw, styles))
        # Key findings
        story.append(Paragraph("Key Findings", styles["h3"]))
        kf = [[Paragraph("Severity", styles["th"]), Paragraph("Finding", styles["th"]),
               Paragraph("Target", styles["th"])]]
        for f in findings[:5]:
            kf.append([pill(_sev_of(f)),
                       Paragraph(_esc(f.get("title") or f.get("vuln_type") or "Finding"), styles["cell"]),
                       Paragraph(_esc(f.get("target") or "—"), styles["small"])])
        if len(kf) == 1:
            kf.append([Paragraph("—", styles["cell"]), Paragraph("No findings.", styles["cell"]),
                       Paragraph("", styles["cell"])])
        story.append(table(kf, [30 * mm, cw - 90 * mm, 60 * mm]))
        story.append(PageBreak())

        # ── 6. Scope & Methodology ──
        story.append(heading("2.", "Scope & Methodology"))
        story.append(Paragraph("In-Scope Targets", styles["h3"]))
        if scope:
            srows = [[Paragraph("#", styles["th"]), Paragraph("Target", styles["th"])]]
            for i, t in enumerate(scope, 1):
                srows.append([Paragraph(str(i), styles["cell"]), Paragraph(_esc(t), styles["cell"])])
            story.append(table(srows, [12 * mm, cw - 12 * mm]))
        else:
            story.append(Paragraph("No explicit scope recorded; findings list their own targets.",
                                   styles["small"]))
        story.append(Paragraph("Testing Approach", styles["h3"]))
        story.append(Paragraph(
            "Testing followed a structured methodology aligned with industry standards, progressing "
            "through reconnaissance, enumeration, vulnerability identification, exploitation (where "
            "safe and authorised), and impact analysis. Each finding was validated to reduce false "
            "positives and rated using the CVSS-based scale in the next section.", styles["body"]))
        story.append(Paragraph("Standards & Frameworks Referenced", styles["h3"]))
        std = [[Paragraph("Framework", styles["th"]), Paragraph("Use", styles["th"])]]
        for fw, use in [("OWASP Top 10 (2021)", "Web application risk categorisation"),
                        ("PTES", "Penetration Testing Execution Standard phases"),
                        ("NIST SP 800-115", "Technical assessment methodology"),
                        ("MITRE ATT&CK", "Adversary technique mapping (where applicable)"),
                        ("CVSS v3.1 / EPSS / CISA KEV",
                         "Severity, exploit-likelihood & known-exploited enrichment")]:
            std.append([Paragraph(_esc(fw), styles["cell"]), Paragraph(_esc(use), styles["cell"])])
        story.append(table(std, [55 * mm, cw - 55 * mm]))
        story.append(PageBreak())

        # ── Host & Service Inventory (only when a network scan ran) ──
        if inventory:
            story.append(heading("", "Host & Service Inventory"))
            story.append(Paragraph(
                f"The network scan mapped <b>{inv_totals['hosts']}</b> host(s) exposing "
                f"<b>{inv_totals['open_ports']}</b> open port(s) across "
                f"<b>{inv_totals['distinct_services']}</b> distinct service(s). Ports, service "
                "versions and operating systems are reported exactly as observed by the scanner. "
                "An OS marked <i>(heuristic — unconfirmed)</i> was inferred from a TTL value, not a "
                "full stack fingerprint, and should be treated as indicative only.", styles["body"]))
            for h in inventory:
                os_txt = h.get("os_label") or "OS not determined"
                story.append(Paragraph(f'{_esc(h.get("host"))} — {_esc(os_txt)}', styles["h3"]))
                ports = h.get("ports") or []
                if not ports:
                    story.append(Paragraph("No open ports observed.", styles["small"]))
                    continue
                prows = [[Paragraph(c, styles["th"]) for c in
                          ("Port", "Proto", "Service", "Version", "CPE")]]
                for p in ports:
                    prows.append([
                        Paragraph(_esc(p.get("port")), styles["cell"]),
                        Paragraph(_esc(p.get("protocol") or "tcp"), styles["cell"]),
                        Paragraph(_esc(p.get("service") or "—"), styles["cell"]),
                        Paragraph(_esc(p.get("service_version") or "—"), styles["cell"]),
                        Paragraph(_esc(p.get("cpe") or "—"), styles["cell"]),
                    ])
                story.append(table(prows,
                                   [16 * mm, 14 * mm, 26 * mm, cw - 116 * mm, 60 * mm]))
            story.append(PageBreak())

        # ── 7. Risk methodology ──
        story.append(heading("3.", "Risk Rating Methodology"))
        story.append(Paragraph(
            "Each finding's severity derives from its CVSS v3.1 base score, adjusted for real-world "
            "exploitability (EPSS) and presence on the CISA Known Exploited Vulnerabilities catalog. "
            "Remediation SLAs are guidance and should be tailored to the organisation's risk appetite.",
            styles["body"]))
        rm = [[Paragraph("Severity", styles["th"]), Paragraph("CVSS range", styles["th"]),
               Paragraph("Recommended remediation SLA", styles["th"])]]
        for sev, m in SEVERITY_META.items():
            rm.append([pill(sev), Paragraph(m["cvss"], styles["cell"]),
                       Paragraph(m["sla"], styles["cell"])])
        story.append(table(rm, [30 * mm, 40 * mm, cw - 70 * mm]))
        story.append(PageBreak())

        # ── 8. Findings summary ──
        story.append(heading("4.", "Findings Summary"))
        if findings:
            fs = [[Paragraph(h, styles["th"]) for h in
                   ("#", "Finding", "Severity", "CVSS", "Target", "Status")]]
            for i, f in enumerate(findings, 1):
                cvss = f.get("predicted_cvss_score") or f.get("typical_cvss") or "—"
                fs.append([Paragraph(str(i), styles["cell"]),
                           Paragraph(_esc(f.get("title") or f.get("vuln_type") or "Finding"), styles["cell"]),
                           pill(_sev_of(f)), Paragraph(_esc(cvss), styles["small"]),
                           Paragraph(_esc(f.get("target") or "—"), styles["small"]),
                           Paragraph(_esc((f.get("status") or "open").title()), styles["small"])])
            story.append(table(fs, [9 * mm, cw - 119 * mm, 26 * mm, 14 * mm, 50 * mm, 20 * mm]))
        else:
            story.append(Paragraph("No findings recorded.", styles["small"]))
        story.append(PageBreak())

        # ── 9. Detailed findings ──
        story.append(heading("5.", "Detailed Findings"))
        if not findings:
            story.append(Paragraph("No findings recorded.", styles["small"]))
        for i, f in enumerate(findings, 1):
            story.extend(self._finding_block(i, f, cw, styles, pill))
        story.append(PageBreak())

        # ── 10. OWASP coverage ──
        story.append(heading("6.", "OWASP Top 10 (2021) Coverage"))
        story.append(self._owasp_table(findings, cw, styles, table))
        story.append(PageBreak())

        # ── 11. Roadmap ──
        story.append(heading("7.", "Remediation Roadmap"))
        story.append(Paragraph("Recommended remediation order, prioritised by severity. Address "
                               "higher-severity items first; SLAs are guidance.", styles["body"]))
        actionable = [f for f in findings if _sev_of(f) in ("critical", "high", "medium")] or findings[:10]
        if actionable:
            rr = [[Paragraph(h, styles["th"]) for h in
                   ("#", "Severity", "Finding", "Recommended action", "SLA")]]
            for i, f in enumerate(actionable[:25], 1):
                ev = f.get("evidence") or {}
                action = str(ev.get("remediation") or f.get("remediation")
                             or "Review and remediate per finding detail.")
                if len(action) > 160:
                    action = action[:160] + "…"
                rr.append([Paragraph(str(i), styles["cell"]), pill(_sev_of(f)),
                           Paragraph(_esc(f.get("title") or f.get("vuln_type") or "Finding"), styles["cell"]),
                           Paragraph(_esc(action), styles["small"]),
                           Paragraph(SEVERITY_META[_sev_of(f)]["sla"], styles["small"])])
            story.append(table(rr, [8 * mm, 24 * mm, 48 * mm, cw - 110 * mm, 30 * mm]))
        story.append(PageBreak())

        # ── 12. Appendix ──
        story.append(heading("8.", "Appendix"))
        story.append(Paragraph("Tooling", styles["h3"]))
        story.append(Paragraph(
            "Assessment performed with the HEAVEN Autonomous Penetration-Testing Platform, which "
            "orchestrates reconnaissance, vulnerability scanning, NVD/EPSS/KEV enrichment, and "
            "ML-assisted risk scoring.", styles["body"]))
        story.append(Paragraph("Glossary", styles["h3"]))
        gloss = [["CVSS", "Common Vulnerability Scoring System — a 0–10 severity score."],
                 ["EPSS", "Exploit Prediction Scoring System — probability a vuln will be exploited."],
                 ["CISA KEV", "Catalog of vulnerabilities known to be actively exploited."],
                 ["CWE", "Common Weakness Enumeration — category of the underlying weakness."],
                 ["OWASP Top 10", "The ten most critical web application security risks."]]
        gt = [[Paragraph(t, styles["cellb"]), Paragraph(d, styles["cell"])] for t, d in gloss]
        story.append(table(gt, [32 * mm, cw - 32 * mm], header=False))
        story.append(Paragraph("Disclaimer", styles["h3"]))
        story.append(Paragraph(
            "This assessment reflects the security posture observed at the time of testing within the "
            "agreed scope. It does not guarantee the absence of other vulnerabilities. Re-testing is "
            "recommended after remediation and following significant environment changes.", styles["small"]))

        # ── Build (two-pass for the ToC) with footer canvas ──
        title_str = f"CONFIDENTIAL — HEAVEN Penetration Test Report — {eng}"

        class _NumberedCanvas(canvas.Canvas):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self._saved: list[dict] = []

            def showPage(self):
                self._saved.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total = len(self._saved)
                for st in self._saved:
                    self.__dict__.update(st)
                    if self._pageNumber > 1:  # skip cover
                        self.setFont("Helvetica", 7)
                        self.setFillColor(colors.HexColor("#9aa3b2"))
                        self.drawString(14 * mm, 10 * mm, title_str[:90])
                        self.drawRightString(A4[0] - 14 * mm, 10 * mm,
                                             f"Page {self._pageNumber} of {total}")
                    super().showPage()
                super().save()

        class _Doc(SimpleDocTemplate):
            def afterFlowable(self, flowable):
                toc_text = getattr(flowable, "_toc_text", None)
                if toc_text:
                    self.notify("TOCEntry", (0, toc_text, self.page))

        doc = _Doc(output_path, pagesize=A4, topMargin=16 * mm, bottomMargin=18 * mm,
                   leftMargin=14 * mm, rightMargin=14 * mm, title=f"Penetration Test Report — {eng}",
                   author="HEAVEN")
        doc.multiBuild(story, canvasmaker=_NumberedCanvas)

    # ── section helpers ─────────────────────────────────────────────

    @staticmethod
    def _overall(counts: dict[str, int]) -> str:
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev):
                return SEVERITY_META[sev]["label"]
        return "Informational"

    @staticmethod
    def _overall_color(overall: str) -> str:
        for m in SEVERITY_META.values():
            if m["label"] == overall:
                return m["color"]
        return "#1f6feb"

    @staticmethod
    def _posture(eng, counts, total, overall, scope_n) -> str:
        crit, high = counts["critical"], counts["high"]
        if crit or high:
            tail = (f"The assessment identified <b>{crit} critical</b> and <b>{high} high</b>-severity "
                    "issues that require prompt remediation; exploitation could lead to unauthorised "
                    "access, data exposure, or full system compromise.")
        elif counts["medium"]:
            tail = ("No critical or high-severity issues were identified. The medium-severity findings "
                    "should be remediated to reduce residual risk.")
        else:
            tail = ("No significant vulnerabilities were identified; the environment demonstrated a "
                    "strong security posture.")
        return (f"This report presents the results of a penetration test of <b>{_esc(eng)}</b>, "
                f"covering <b>{scope_n}</b> in-scope target(s). A total of <b>{total}</b> finding(s) "
                f"were identified, yielding an overall risk rating of <b>{_esc(overall)}</b>. {tail}")

    @staticmethod
    def _sev_bar(findings, counts, cw, styles):
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
        total = len(findings) or 1
        cells, widths, cmds = [], [], []
        col = 0
        for sev, m in SEVERITY_META.items():
            n = counts[sev]
            if not n:
                continue
            widths.append(max(cw * (n / total), 10))
            cells.append(Paragraph(f'<font color="white" size="7"><b>{n}</b></font>', styles["cell"]))
            cmds.append(("BACKGROUND", (col, 0), (col, 0), colors.HexColor(m["color"])))
            col += 1
        if not cells:
            return Spacer(1, 1)
        t = Table([cells], colWidths=widths, rowHeights=[7 * mm])
        cmds += [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                 ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]
        t.setStyle(TableStyle(cmds))
        return t

    def _finding_block(self, idx, f, cw, styles, pill) -> list:
        """Return the flowables for one finding. The header+metadata are kept
        together; the (possibly long) narrative/evidence is allowed to flow."""
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import KeepTogether, Paragraph, Spacer, Table, TableStyle
        line = colors.HexColor("#d7dde7")
        sev = _sev_of(f)
        m = SEVERITY_META[sev]
        ev = f.get("evidence") or {}
        title = f.get("title") or f.get("vuln_type") or "Finding"
        cvss = f.get("predicted_cvss_score") or f.get("typical_cvss") or "—"
        owasp = f.get("owasp") or _OWASP._owasp_for(f.get("vuln_type", "")) or "—"

        hdr = Table([[Paragraph(f'<font color="white" size="10"><b>{m["label"]} &nbsp; '
                                f'#{idx} &nbsp; {_esc(title)}</b></font>', styles["cell"])]],
                    colWidths=[cw], rowHeights=[8 * mm])
        hdr.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(m["color"])),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 10),
                                 ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))

        meta_pairs = [
            ("Target", f.get("target") or "—"), ("Severity", m["label"]),
            ("CVSS (predicted)", cvss),
            ("Risk score", f.get("risk_score") if f.get("risk_score") is not None else "—"),
            ("Confidence", f"{float(f.get('confidence', 0)):.0%}" if f.get("confidence") is not None else "—"),
            ("CWE", f.get("cwe") or "—"), ("OWASP", owasp),
            ("CVE", f.get("cve_id") or f.get("cve") or "—"),
            ("MITRE ATT&CK", f.get("mitre_technique") or "—"),
            ("CVSS vector", f.get("cvss_vector")
             or _CVSS_VECTORS.get((f.get("vuln_type") or "").lower(), "—")),
            ("Status", (f.get("status") or "open").title()),
        ]
        mt = Table([[Paragraph(_esc(k), styles["cellb"]), Paragraph(_esc(v), styles["cell"])]
                    for k, v in meta_pairs], colWidths=[38 * mm, cw - 38 * mm])
        mt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, line),
                                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fafbfd")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))

        out: list = [KeepTogether([hdr, Spacer(1, 3), mt])]

        def section(label, text):
            if text:
                out.append(Paragraph(label, styles["label"]))
                out.append(Paragraph(_esc(text), styles["body"]))

        section("DESCRIPTION", ev.get("description") or f.get("description"))
        section("IMPACT", ev.get("impact"))

        for key, label in (("payload", "PAYLOAD"), ("request", "HTTP REQUEST"),
                           ("response", "HTTP RESPONSE"), ("curl", "REPRODUCTION (CURL)"),
                           ("proof", "PROOF"), ("poc", "PROOF OF CONCEPT")):
            val = ev.get(key)
            if not val:
                continue
            snippet = str(val)
            if len(snippet) > 2500:
                snippet = snippet[:2500] + "\n… (truncated)"
            # Paragraph with wordWrap=CJK (set on the 'pre' style) wraps long
            # unbroken tokens safely; <br/> preserves line breaks.
            pre = Paragraph(_esc(snippet).replace("\n", "<br/>"), styles["pre"])
            box = Table([[pre]], colWidths=[cw])
            box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1117")),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                     ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                     ("TOPPADDING", (0, 0), (-1, -1), 6),
                                     ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
            out.append(Paragraph(label, styles["label"]))
            out.append(box)

        section("REMEDIATION", ev.get("remediation") or f.get("remediation"))

        refs = ev.get("references") or f.get("references") or []
        if refs:
            out.append(Paragraph("REFERENCES", styles["label"]))
            for r in refs:
                out.append(Paragraph(f'• <link href="{_esc(r)}"><font color="#1f6feb">{_esc(r)}'
                                     f'</font></link>', styles["small"]))
        section("ASSESSOR NOTES", f.get("operator_notes"))
        out.append(Spacer(1, 12))
        return out

    def _owasp_table(self, findings, cw, styles, table):
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph
        coverage: dict[str, dict] = {}
        for f in findings:
            vt = (f.get("vuln_type") or "").lower()
            for key, (cid, cn) in _OWASP.OWASP_MAP.items():
                if key in vt:
                    coverage.setdefault(cid, {"name": cn, "n": 0})
                    coverage[cid]["n"] += 1
        rows = [[Paragraph(h, styles["th"]) for h in ("Control", "Category", "Status", "Findings")]]
        seen = set()
        for _k, (cid, cn) in _OWASP.OWASP_MAP.items():
            if cid in seen:
                continue
            seen.add(cid)
            hit = cid in coverage
            n = coverage.get(cid, {}).get("n", 0)
            status = "Findings present" if hit else "No findings"
            color = "#b00020" if hit else "#1a7f37"
            rows.append([Paragraph(cid, styles["cell"]), Paragraph(_esc(cn), styles["cell"]),
                         Paragraph(f'<font color="{color}"><b>{status}</b></font>', styles["cell"]),
                         Paragraph(str(n), styles["cell"])])
        return table(rows, [28 * mm, cw - 86 * mm, 38 * mm, 20 * mm])


def generate_report(data: dict[str, Any], output_path: str,
                    client_name: Optional[str] = None) -> bool:
    """Convenience wrapper used by the CLI."""
    if client_name:
        data = {**data, "engagement": client_name}
    return PDFReportGenerator().generate(data, output_path)

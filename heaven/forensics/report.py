"""HEAVEN — render an offline-artifact analysis result to a downloadable report.

Takes the dict returned by :func:`heaven.forensics.dispatch.analyze_artifact`
(``{kind, report, findings, summary, ...}``) and renders a self-contained
Markdown or HTML report. The renderer is generic: it turns every section of the
analyzer's ``report`` into readable tables/lists, so new analyzer fields appear
automatically without changing this file. Used by both the CLI (``heaven analyze
--report``) and the web API download button.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Severity → (fill, text) for the PDF badges; mirrors the web/HTML palette.
_SEV_COLORS = {
    "critical": ("#b3261e", "#ffffff"),
    "high": ("#d1443c", "#ffffff"),
    "medium": ("#b7791f", "#ffffff"),
    "low": ("#2f6feb", "#ffffff"),
    "info": ("#5b6472", "#ffffff"),
}

# Human titles for known report sections (anything not listed is title-cased).
_SECTION_TITLES = {
    "protocol_breakdown": "Protocol breakdown",
    "application_protocols": "Application protocols",
    "top_talkers": "Top talkers",
    "conversations": "Conversations (top by bytes)",
    "dns_queries": "DNS queries",
    "dns_answers": "DNS answers",
    "tls_sessions": "TLS sessions",
    "http_transactions": "HTTP transactions",
    "cleartext_credentials": "Cleartext credentials",
    "ntlm_hashes": "Captured NTLM hashes",
    "snmp_communities": "SNMP community strings",
    "arp_table": "ARP table",
    "cleartext_protocols": "Cleartext protocols",
    "payload_secrets": "Secrets seen on the wire",
    "software_versions": "Software / version inventory",
    "embedded_accounts": "Embedded accounts",
    "interesting_strings": "Strings of interest",
    "imports_flagged": "Dangerous imports",
    "decodings": "Decodings",
    "dangerous_permissions": "Dangerous permissions",
    "native_libraries": "Native libraries (ABIs)",
    # Shared per-file enrichment
    "file_overview": "File overview (hashes · entropy · type)",
    # Documents
    "active_content": "Active content markers",
    "javascript_snippets": "JavaScript snippets",
    "embedded_files": "Embedded files",
    "embedded_secrets": "Embedded secrets",
    "document_metadata": "Document metadata",
    "external_relationships": "External relationships",
    "dde_fields": "DDE fields",
    "embedded_objects": "Embedded OLE objects",
    "object_classes": "OLE object classes",
    "remote_templates": "Remote templates",
    "vba_modules": "VBA modules",
    "macro_keywords": "Suspicious macro calls",
    "macro_source_excerpt": "Macro source (excerpt)",
    "streams": "Compound-file streams",
    # Archives
    "executables": "Executable / script members",
    "unsafe_paths": "Path-traversal members",
    "inner_type": "Inner content type",
    # Binary depth
    "sections": "Sections",
    "imported_libraries": "Imported libraries",
    "rpath": "RPATH / RUNPATH",
}


def _title(key: str) -> str:
    return _SECTION_TITLES.get(key, key.replace("_", " ").capitalize())


def _fmt_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".")
    return str(v)


# ── Markdown ──────────────────────────────────────────────────────────────────
def _md_value(key: str, val: Any) -> list[str]:
    out: list[str] = [f"### {_title(key)}", ""]
    if isinstance(val, list):
        if not val:
            return []
        if all(isinstance(x, dict) for x in val):
            cols: list[str] = []
            for row in val[:200]:
                for k in row:
                    if k not in cols and not k.startswith("_"):
                        cols.append(k)
            cols = cols[:8]
            out.append("| " + " | ".join(cols) + " |")
            out.append("| " + " | ".join("---" for _ in cols) + " |")
            for row in val[:200]:
                out.append("| " + " | ".join(
                    _md_cell(row.get(c, "")) for c in cols) + " |")
        else:
            for x in val[:200]:
                out.append(f"- {_md_cell(x)}")
    elif isinstance(val, dict):
        out.append("| Key | Value |")
        out.append("| --- | --- |")
        for k, v in list(val.items())[:200]:
            out.append(f"| {_md_cell(k)} | {_md_cell(v)} |")
    else:
        out.append(_fmt_scalar(val))
    out.append("")
    return out


def _md_cell(v: Any) -> str:
    if isinstance(v, (dict, list)):
        s = json.dumps(v, default=str)
    else:
        s = _fmt_scalar(v)
    return s.replace("|", "\\|").replace("\n", " ")[:300]


def render_markdown(result: dict[str, Any]) -> str:
    kind = result.get("kind") or result.get("detected_kind") or "artifact"
    fname = result.get("filename", "")
    findings = sorted(result.get("findings", []),
                      key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [f"# HEAVEN Offline Artifact Analysis: {kind}", ""]
    if fname:
        lines.append(f"**File:** `{fname}`  ")
    lines.append(f"**Type:** {kind}  ")
    if result.get("summary"):
        lines.append(f"**Summary:** {result['summary']}  ")
    lines.append(f"**Generated:** {ts}")
    lines.append("")

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    if counts:
        badge = " · ".join(f"{counts[s]} {s}" for s in
                           ["critical", "high", "medium", "low", "info"] if s in counts)
        lines += [f"## Findings ({len(findings)}): {badge}", ""]
    else:
        lines += ["## Findings (0)", "", "No findings.", ""]

    for f in findings:
        lines.append(f"### [{f.get('severity', 'info').upper()}] {f.get('title', '')}")
        meta = []
        if f.get("cwe"):
            meta.append(f.get("cwe"))
        if f.get("confidence") is not None:
            meta.append(f"confidence {int(float(f['confidence']) * 100)}%")
        if f.get("owasp_mobile"):
            meta.append(f["owasp_mobile"])
        if meta:
            lines.append("*" + " · ".join(meta) + "*")
        lines.append("")
        if f.get("description"):
            lines.append(f.get("description"))
            lines.append("")
        if f.get("remediation"):
            lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")
        ev = f.get("evidence")
        if ev:
            lines.append("<details><summary>Evidence</summary>")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(ev, indent=2, default=str)[:4000])
            lines.append("```")
            lines.append("</details>")
            lines.append("")

    report = result.get("report", {})
    if isinstance(report, dict) and report:
        lines += ["## Detailed report", ""]
        for key, val in report.items():
            if key in ("input",) or val in (None, [], {}, ""):
                continue
            lines += _md_value(key, val)

    lines += ["---", "", "*Generated by HEAVEN · offline artifact analysis. Every "
              "finding reflects real bytes read from the file.*"]
    return "\n".join(lines)


# ── HTML ──────────────────────────────────────────────────────────────────────
_HTML_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;
--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--info:#8b949e;--accent:#7ee787}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:32px}
.wrap{max-width:1000px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;border-bottom:1px solid var(--border);padding-bottom:6px;margin:28px 0 12px}
h3{font-size:14px;margin:18px 0 6px}.meta{color:var(--dim);font-size:13px;margin-bottom:18px}
.finding{background:var(--card);border:1px solid var(--border);border-left-width:4px;
border-radius:8px;padding:12px 14px;margin:10px 0}.pill{display:inline-block;font-size:11px;
font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;margin-right:8px}
.sev-critical{border-left-color:var(--crit)}.p-critical{background:var(--crit);color:#fff}
.sev-high{border-left-color:var(--high)}.p-high{background:var(--high);color:#000}
.sev-medium{border-left-color:var(--med)}.p-medium{background:var(--med);color:#000}
.sev-low{border-left-color:var(--low)}.p-low{background:var(--low);color:#000}
.sev-info{border-left-color:var(--info)}.p-info{background:var(--info);color:#000}
.fmeta{color:var(--dim);font-size:12px;margin:4px 0}.rem{color:var(--accent);font-size:13px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--border);padding:5px 9px;text-align:left;vertical-align:top}
th{background:var(--card);color:var(--dim)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#0b0f14;border:1px solid var(--border);border-radius:6px;padding:10px;
overflow-x:auto;font-size:11.5px;max-height:340px}details summary{cursor:pointer;color:var(--dim)}
.badge{color:var(--dim)}.foot{color:var(--dim);font-size:12px;margin-top:30px;border-top:1px solid var(--border);padding-top:12px}
"""


def _h(v: Any) -> str:
    return html.escape(_fmt_scalar(v) if not isinstance(v, (dict, list))
                       else json.dumps(v, default=str))[:600]


def _html_section(key: str, val: Any) -> str:
    parts = [f"<h3>{html.escape(_title(key))}</h3>"]
    if isinstance(val, list):
        if not val:
            return ""
        if all(isinstance(x, dict) for x in val):
            cols: list[str] = []
            for row in val[:300]:
                for k in row:
                    if k not in cols and not k.startswith("_"):
                        cols.append(k)
            cols = cols[:9]
            head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
            rows = ""
            for row in val[:300]:
                rows += "<tr>" + "".join(
                    f"<td>{_h(row.get(c, ''))}</td>" for c in cols) + "</tr>"
            parts.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
        else:
            items = "".join(f"<li>{_h(x)}</li>" for x in val[:300])
            parts.append(f"<ul>{items}</ul>")
    elif isinstance(val, dict):
        rows = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{_h(v)}</td></tr>"
                       for k, v in list(val.items())[:300])
        parts.append(f"<table><thead><tr><th>Key</th><th>Value</th></tr></thead>"
                     f"<tbody>{rows}</tbody></table>")
    else:
        parts.append(f"<p>{_h(val)}</p>")
    return "".join(parts)


def render_html(result: dict[str, Any]) -> str:
    kind = result.get("kind") or result.get("detected_kind") or "artifact"
    fname = result.get("filename", "")
    findings = sorted(result.get("findings", []),
                      key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    body = ["<h1>HEAVEN Offline Artifact Analysis</h1>",
            "<div class='meta'>"
            + (f"File <code>{html.escape(fname)}</code> · " if fname else "")
            + f"Type <b>{html.escape(kind)}</b> · "
            + (html.escape(result.get("summary", "")) + " · " if result.get("summary") else "")
            + f"{ts}</div>"]

    body.append(f"<h2>Findings ({len(findings)})</h2>")
    if not findings:
        body.append("<p>No findings.</p>")
    for f in findings:
        sev = f.get("severity", "info")
        meta = []
        if f.get("cwe"):
            meta.append(html.escape(f["cwe"]))
        if f.get("confidence") is not None:
            meta.append(f"confidence {int(float(f['confidence']) * 100)}%")
        if f.get("owasp_mobile"):
            meta.append(html.escape(f["owasp_mobile"]))
        block = [f"<div class='finding sev-{sev}'>",
                 f"<span class='pill p-{sev}'>{sev}</span>"
                 f"<b>{html.escape(f.get('title', ''))}</b>"]
        if meta:
            block.append(f"<div class='fmeta'>{' · '.join(meta)}</div>")
        if f.get("description"):
            block.append(f"<div>{html.escape(f['description'])}</div>")
        if f.get("remediation"):
            block.append(f"<div class='rem'>Remediation: {html.escape(f['remediation'])}</div>")
        ev = f.get("evidence")
        if ev:
            block.append("<details><summary>Evidence</summary><pre>"
                         + html.escape(json.dumps(ev, indent=2, default=str)[:6000])
                         + "</pre></details>")
        block.append("</div>")
        body.append("".join(block))

    report = result.get("report", {})
    if isinstance(report, dict) and report:
        body.append("<h2>Detailed report</h2>")
        for key, val in report.items():
            if key in ("input",) or val in (None, [], {}, ""):
                continue
            section = _html_section(key, val)
            if section:
                body.append(section)

    body.append("<div class='foot'>Generated by HEAVEN · offline artifact analysis. "
                "Every finding reflects real bytes read from the file.</div>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>HEAVEN artifact report — {html.escape(kind)}</title>"
            f"<style>{_HTML_CSS}</style></head><body><div class='wrap'>"
            + "".join(body) + "</div></body></html>")


# ── PDF ─────────────────────────────────────────────────────────────────────
def _pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def render_pdf(result: dict[str, Any]) -> bytes:
    """Render ``result`` to a self-contained PDF (bytes) via reportlab.

    Mirrors the Markdown/HTML report: a header, a findings section (each finding
    with a severity badge, metadata, description, remediation and truncated
    evidence) and the analyzer's detailed ``report`` sections rendered as tables.
    Every value is passed through reportlab's own XML escaping, and each finding
    and section renders inside its own try/except so one malformed entry can never
    abort the whole document. Raises ``RuntimeError`` if reportlab is unavailable.
    """
    if not _pdf_available():
        raise RuntimeError(
            "reportlab is not installed, so PDF export is unavailable "
            "(pip install reportlab).")

    import io
    from xml.sax.saxutils import escape as _xesc  # nosec B406 -- escape() is OUTPUT encoding (a security control), not XML parsing

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
        TableStyle,
    )

    kind = str(result.get("kind") or result.get("detected_kind") or "artifact")
    fname = str(result.get("filename") or "")
    summary = str(result.get("summary") or "")
    findings = sorted(result.get("findings", []),
                      key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ink = colors.HexColor("#1a1f29")
    muted = colors.HexColor("#5b6472")
    line = colors.HexColor("#d7dde7")
    ss = getSampleStyleSheet()
    S = {
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                             fontSize=18, textColor=ink, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, textColor=ink, spaceBefore=12, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                             fontSize=10.5, textColor=ink, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica",
                               fontSize=9.5, leading=13.5, textColor=ink, spaceAfter=4),
        "small": ParagraphStyle("small", parent=ss["BodyText"], fontName="Helvetica",
                                fontSize=8, leading=11, textColor=muted),
        "cell": ParagraphStyle("cell", parent=ss["BodyText"], fontName="Helvetica",
                               fontSize=8, leading=11, textColor=ink),
        "th": ParagraphStyle("th", parent=ss["BodyText"], fontName="Helvetica-Bold",
                             fontSize=8, leading=11, textColor=colors.HexColor("#33405a")),
        "rem": ParagraphStyle("rem", parent=ss["BodyText"], fontName="Helvetica",
                              fontSize=9, leading=12.5, textColor=colors.HexColor("#1a7f37")),
        "pre": ParagraphStyle("pre", parent=ss["Code"], fontName="Courier", fontSize=7,
                              leading=9, textColor=colors.HexColor("#c9d1d9"), wordWrap="CJK"),
    }
    A4W = A4[0]
    cw = A4W - 28 * mm

    def esc(v: Any) -> str:
        return _xesc("" if v is None else str(v))

    def cell(v: Any) -> str:
        if isinstance(v, (dict, list)):
            s = json.dumps(v, default=str)
        else:
            s = _fmt_scalar(v)
        return esc(s[:300])

    story: list[Any] = []

    # ── Header ──
    story.append(Paragraph("HEAVEN &nbsp;·&nbsp; Offline Artifact Analysis", S["h1"]))
    metabits = []
    if fname:
        metabits.append(f"File <b>{esc(fname)}</b>")
    metabits.append(f"Type <b>{esc(kind)}</b>")
    if summary:
        metabits.append(esc(summary))
    metabits.append(f"Generated {ts}")
    story.append(Paragraph(" &nbsp;·&nbsp; ".join(metabits), S["small"]))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=0.6, color=line))

    # ── Severity summary ──
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    kpi_cells, kpi_widths, kpi_cmds = [], [], []
    col = 0
    for sev in ("critical", "high", "medium", "low", "info"):
        fill, txt = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
        n = counts.get(sev, 0)
        kpi_cells.append(Paragraph(
            f'<para align="center"><font color="{txt}" size="14"><b>{n}</b></font><br/>'
            f'<font color="{txt}" size="6">{sev.upper()}</font></para>', S["cell"]))
        kpi_widths.append(cw / 5.0)
        kpi_cmds.append(("BACKGROUND", (col, 0), (col, 0), colors.HexColor(fill)))
        col += 1
    kpi = Table([kpi_cells], colWidths=kpi_widths, rowHeights=[11 * mm])
    kpi_cmds += [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                 ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    kpi.setStyle(TableStyle(kpi_cmds))
    story.append(Spacer(1, 8))
    story.append(kpi)

    # ── Findings ──
    story.append(Paragraph(f"Findings ({len(findings)})", S["h2"]))
    if not findings:
        story.append(Paragraph("No security findings.", S["body"]))
    for f in findings:
        try:
            sev = f.get("severity", "info")
            fill, txt = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
            meta = []
            if f.get("cwe"):
                meta.append(esc(f["cwe"]))
            if f.get("confidence") is not None:
                meta.append(f"confidence {int(float(f['confidence']) * 100)}%")
            if f.get("owasp_mobile"):
                meta.append(esc(f["owasp_mobile"]))
            hdr = Table([[Paragraph(
                f'<font color="{txt}" size="9"><b>{sev.upper()} &nbsp; '
                f'{esc(f.get("title", ""))}</b></font>', S["cell"])]],
                colWidths=[cw], rowHeights=[7 * mm])
            hdr.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(fill)),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                     ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            block: list[Any] = [hdr]
            if meta:
                block.append(Paragraph(" · ".join(meta), S["small"]))
            if f.get("description"):
                block.append(Paragraph(esc(f["description"]), S["body"]))
            if f.get("remediation"):
                block.append(Paragraph("Remediation: " + esc(f["remediation"]), S["rem"]))
            ev = f.get("evidence")
            if ev:
                snippet = json.dumps(ev, indent=2, default=str)[:2600]
                pre = Paragraph(esc(snippet).replace("\n", "<br/>"), S["pre"])
                box = Table([[pre]], colWidths=[cw])
                box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1117")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
                block.append(box)
            block.append(Spacer(1, 8))
            # Keep the header with at least its first lines together.
            story.append(KeepTogether(block[:2]))
            story.extend(block[2:])
        except Exception:  # noqa: BLE001
            story.append(Paragraph(esc(f.get("title", "finding")) + " (render error)", S["small"]))

    # ── Detailed report sections ──
    report = result.get("report", {})
    if isinstance(report, dict) and report:
        story.append(Paragraph("Detailed report", S["h2"]))
        for key, val in report.items():
            if key in ("input",) or val in (None, [], {}, ""):
                continue
            try:
                story.extend(_pdf_section(key, val, cw, S, cell, esc, Paragraph, Table, TableStyle, line, colors))
            except Exception:  # noqa: BLE001
                story.append(Paragraph(_title(key) + " (render error)", S["small"]))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.6, color=line))
    story.append(Paragraph(
        "Generated by HEAVEN · offline artifact analysis. Every finding reflects "
        "real bytes read from the file.", S["small"]))

    buf = io.BytesIO()

    def _footer(cnv: Any, doc: Any) -> None:
        cnv.setFont("Helvetica", 7)
        cnv.setFillColor(colors.HexColor("#9aa3b2"))
        cnv.drawString(14 * mm, 10 * mm, f"HEAVEN artifact report · {kind}"[:90])
        cnv.drawRightString(A4W - 14 * mm, 10 * mm, f"Page {doc.page}")

    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
                            leftMargin=14 * mm, rightMargin=14 * mm,
                            title=f"HEAVEN artifact report · {kind}", author="HEAVEN")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _pdf_section(key, val, cw, S, cell, esc, Paragraph, Table, TableStyle, line, colors) -> list:
    """Render one report section to reportlab flowables (table / bullets / kv)."""
    out = [Paragraph(esc(_title(key)), S["h3"])]

    def _table(rows, col_widths):
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, line),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
        return t

    if isinstance(val, list):
        if not val:
            return []
        if all(isinstance(x, dict) for x in val):
            cols: list[str] = []
            for row in val[:250]:
                for k in row:
                    if k not in cols and not str(k).startswith("_"):
                        cols.append(k)
            cols = cols[:7]
            head = [Paragraph(esc(c), S["th"]) for c in cols]
            rows = [head]
            for row in val[:250]:
                rows.append([Paragraph(cell(row.get(c, "")), S["cell"]) for c in cols])
            out.append(_table(rows, [cw / len(cols)] * len(cols)))
        else:
            for x in val[:250]:
                out.append(Paragraph("• " + cell(x), S["cell"]))
    elif isinstance(val, dict):
        rows = [[Paragraph("Key", S["th"]), Paragraph("Value", S["th"])]]
        for k, v in list(val.items())[:250]:
            rows.append([Paragraph(esc(str(k)), S["cell"]), Paragraph(cell(v), S["cell"])])
        out.append(_table(rows, [cw * 0.34, cw * 0.66]))
    else:
        out.append(Paragraph(cell(val), S["body"]))
    return out


def render_report(result: dict[str, Any], fmt: str = "md") -> tuple[str, str, str]:
    """Render ``result`` in ``fmt`` (md|html|json). Returns (content, mimetype, ext).

    PDF is binary, so it is not returned here; callers that need PDF use
    :func:`render_pdf`, which returns raw bytes.
    """
    if fmt == "html":
        return render_html(result), "text/html", "html"
    if fmt == "json":
        return json.dumps(result, indent=2, default=str), "application/json", "json"
    return render_markdown(result), "text/markdown", "md"

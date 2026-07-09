"""
HEAVEN — Professional Penetration-Test Report Generator

Produces a single self-contained, **print-ready** HTML report that doubles as a
PDF: open it in any browser and use "Print → Save as PDF" (a button is built
in). The layout follows the structure clients expect from a professional
penetration-testing deliverable:

  1. Cover page (classification, engagement, overall risk)
  2. Confidentiality notice
  3. Document control + table of contents
  4. Executive summary (narrative + severity distribution)
  5. Scope & methodology (targets, standards, tools)
  6. Risk-rating methodology (severity scale + remediation SLAs)
  7. Findings summary table
  8. Detailed findings (description, impact, evidence/PoC, remediation, refs)
  9. OWASP Top 10 coverage
 10. Remediation roadmap (prioritised)
 11. Appendix (standards, glossary, disclaimer)

All scan-controlled text is HTML-escaped, so a finding title/target/evidence can
never break the layout or inject markup into the deliverable.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

# Severity → presentation. Colours are chosen to print cleanly on white paper.
SEVERITY_META: dict[str, dict[str, Any]] = {
    "critical": {"label": "Critical", "color": "#b00020", "cvss": "9.0 – 10.0",
                 "sla": "24–48 hours", "order": 0},
    "high":     {"label": "High",     "color": "#e8590c", "cvss": "7.0 – 8.9",
                 "sla": "1 week",      "order": 1},
    "medium":   {"label": "Medium",   "color": "#b8860b", "cvss": "4.0 – 6.9",
                 "sla": "1 month",     "order": 2},
    "low":      {"label": "Low",      "color": "#2563eb", "cvss": "0.1 – 3.9",
                 "sla": "90 days",     "order": 3},
    "info":     {"label": "Info",     "color": "#6b7280", "cvss": "0.0",
                 "sla": "Best effort", "order": 4},
}

_BRAND = "#1f6feb"


def _esc(value: Any) -> str:
    """HTML-escape any value (scan output is untrusted)."""
    return html.escape("" if value is None else str(value), quote=True)


def _sev_of(f: dict) -> str:
    s = (f.get("severity") or "info").lower()
    return s if s in SEVERITY_META else "info"


class ComplianceReportGenerator:

    # vuln_type substring → (OWASP 2021 control id, name)
    OWASP_MAP = {
        "sqli": ("A03:2021", "Injection"),
        "sql_injection": ("A03:2021", "Injection"),
        "xss": ("A03:2021", "Injection"),
        "command_injection": ("A03:2021", "Injection"),
        "code_injection": ("A03:2021", "Injection"),
        "broken_auth": ("A07:2021", "Identification and Authentication Failures"),
        "auth": ("A07:2021", "Identification and Authentication Failures"),
        "sensitive_data": ("A02:2021", "Cryptographic Failures"),
        "crypto": ("A02:2021", "Cryptographic Failures"),
        "xxe": ("A05:2021", "Security Misconfiguration"),
        "misconfig": ("A05:2021", "Security Misconfiguration"),
        "access_control": ("A01:2021", "Broken Access Control"),
        "idor": ("A01:2021", "Broken Access Control"),
        "ssrf": ("A10:2021", "Server-Side Request Forgery"),
        "insecure_design": ("A04:2021", "Insecure Design"),
        "vulnerable_component": ("A06:2021", "Vulnerable and Outdated Components"),
        "outdated": ("A06:2021", "Vulnerable and Outdated Components"),
        "logging": ("A09:2021", "Security Logging and Monitoring Failures"),
        "lfi": ("A01:2021", "Broken Access Control"),
        "rfi": ("A03:2021", "Injection"),
    }

    SEV_ORDER = {k: v["order"] for k, v in SEVERITY_META.items()}

    # ── public entry point ──────────────────────────────────────────────

    def generate_html_report(self, findings: list[dict],
                             engagement_name: str = "",
                             output_path: Optional[Path] = None,
                             meta: Optional[dict] = None) -> str:
        """Render the full professional report as one HTML string.

        `meta` (all optional) may carry: client, assessor, period, version,
        scope (list of targets). Anything absent is derived from the findings.
        """
        meta = meta or {}
        findings = findings or []
        eng = engagement_name or meta.get("client") or "HEAVEN Engagement"

        ordered = sorted(findings, key=lambda f: (
            self.SEV_ORDER.get(_sev_of(f), 4),
            -float(f.get("risk_score") or 0),
        ))
        counts = {k: 0 for k in SEVERITY_META}
        for f in findings:
            counts[_sev_of(f)] += 1

        overall = self._overall_risk(counts)
        scope = meta.get("scope") or sorted(
            {str(f.get("target")) for f in findings if f.get("target")}
        )
        generated = datetime.now(UTC).strftime("%d %B %Y, %H:%M UTC")
        version = meta.get("version") or "1.0"
        assessor = meta.get("assessor") or "HEAVEN Autonomous Penetration-Testing Platform"

        sections = [
            self._styles(),
            self._toolbar(),
            self._cover(eng, overall, counts, len(findings), len(scope), generated, version),
            self._confidentiality(eng),
            self._doc_control(eng, assessor, version, generated, len(scope), len(findings), overall),
            self._toc(),
            self._exec_summary(eng, counts, len(findings), overall, ordered, len(scope)),
            self._scope_methodology(scope),
            self._risk_methodology(),
            self._findings_summary(ordered),
            self._detailed_findings(ordered),
            self._owasp_coverage(findings),
            self._roadmap(ordered),
            self._appendix(),
            self._footer(),
        ]
        html_doc = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>Penetration Test Report — {_esc(eng)}</title>"
            + sections[0]
            + "</head><body>"
            + "".join(sections[1:])
            + "</body></html>"
        )
        if output_path:
            Path(output_path).write_text(html_doc, encoding="utf-8")
        return html_doc

    # ── helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _overall_risk(counts: dict[str, int]) -> str:
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev):
                return SEVERITY_META[sev]["label"]
        return "Informational"

    @staticmethod
    def _styles() -> str:
        return """<style>
        :root{--brand:#1f6feb;--ink:#1a1f29;--muted:#5b6472;--line:#e3e7ee;--bg:#fff;}
        *{box-sizing:border-box;}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
             color:var(--ink);background:#f4f6f9;margin:0;line-height:1.55;font-size:14px;}
        .page{background:var(--bg);max-width:850px;margin:24px auto;padding:48px 56px;
              box-shadow:0 1px 4px rgba(0,0,0,.08);}
        h1,h2,h3{color:var(--ink);font-weight:700;line-height:1.25;}
        h2{font-size:20px;margin:0 0 16px;padding-bottom:8px;border-bottom:2px solid var(--brand);}
        h3{font-size:15px;margin:22px 0 6px;}
        p{margin:0 0 12px;} a{color:var(--brand);}
        table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 4px;}
        th{background:#f0f3f8;text-align:left;padding:8px 10px;border:1px solid var(--line);
           font-weight:600;color:#33405a;}
        td{padding:8px 10px;border:1px solid var(--line);vertical-align:top;}
        .muted{color:var(--muted);} .small{font-size:12px;}
        .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;
              font-weight:700;color:#fff;letter-spacing:.02em;}
        .kpis{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0;}
        .kpi{flex:1;min-width:110px;border:1px solid var(--line);border-radius:10px;
             padding:14px;text-align:center;background:#fcfdff;}
        .kpi .n{font-size:30px;font-weight:800;line-height:1;} .kpi .l{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
        .bar{height:14px;border-radius:7px;overflow:hidden;display:flex;border:1px solid var(--line);background:#fff;}
        .bar span{display:block;height:100%;}
        .legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;margin-top:8px;}
        .legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle;}
        .finding{border:1px solid var(--line);border-radius:10px;margin:16px 0;overflow:hidden;}
        .finding-head{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#fafbfd;border-bottom:1px solid var(--line);}
        .finding-head .id{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);}
        .finding-head .ttl{font-weight:700;font-size:15px;}
        .finding-body{padding:8px 16px 16px;}
        .meta{width:100%;font-size:12.5px;margin:6px 0 12px;}
        .meta td:first-child{width:150px;color:var(--muted);background:#fafbfd;font-weight:600;}
        pre{background:#0d1117;color:#d6deeb;padding:12px 14px;border-radius:8px;overflow-x:auto;
            font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;}
        .block-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;margin:14px 0 4px;}
        .cover{min-height:78vh;display:flex;flex-direction:column;justify-content:center;}
        .classif{display:inline-block;border:1.5px solid #b00020;color:#b00020;font-weight:800;
                  font-size:12px;letter-spacing:.18em;padding:4px 12px;border-radius:4px;}
        .cover h1{font-size:40px;margin:24px 0 6px;letter-spacing:-.5px;}
        .cover .sub{font-size:17px;color:var(--muted);}
        .riskbadge{display:inline-block;margin-top:28px;padding:14px 26px;border-radius:12px;
                   color:#fff;font-weight:800;font-size:18px;letter-spacing:.04em;}
        .toc ol{margin:0;padding-left:22px;} .toc li{margin:5px 0;}
        .toc a{text-decoration:none;color:var(--ink);} .toc a:hover{color:var(--brand);}
        .note{background:#fff8e6;border:1px solid #f0d98c;border-radius:8px;padding:14px 16px;font-size:13px;}
        .toolbar{position:fixed;top:16px;right:16px;z-index:99;}
        .btn{background:var(--brand);color:#fff;border:0;border-radius:8px;padding:10px 16px;
             font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(31,111,235,.35);}
        @media print{
          body{background:#fff;} .page{box-shadow:none;margin:0;max-width:none;padding:0;}
          .no-print{display:none!important;}
          .section{page-break-before:always;} .cover{page-break-after:always;min-height:90vh;}
          .finding,tr{page-break-inside:avoid;}
          @page{size:A4;margin:16mm 14mm;}
        }
        </style>"""

    @staticmethod
    def _toolbar() -> str:
        return ("<div class=\"toolbar no-print\">"
                "<button class=\"btn\" onclick=\"window.print()\">🖨 Print / Save as PDF</button>"
                "</div>")

    def _cover(self, eng: str, overall: str, counts: dict, total: int,
               scope_n: int, generated: str, version: str) -> str:
        col = next((m["color"] for m in SEVERITY_META.values()
                    if m["label"] == overall), _BRAND)
        return f"""<div class="page"><div class="cover">
          <div><span class="classif">CONFIDENTIAL</span></div>
          <h1>Penetration Test Report</h1>
          <div class="sub">{_esc(eng)}</div>
          <div class="riskbadge" style="background:{col}">Overall Risk: {_esc(overall)}</div>
          <div style="margin-top:40px;color:var(--muted);font-size:13px;line-height:2">
            <div><strong style="color:var(--ink)">Findings:</strong> {total}
               &nbsp;·&nbsp; {counts['critical']} critical, {counts['high']} high,
               {counts['medium']} medium, {counts['low']} low</div>
            <div><strong style="color:var(--ink)">Targets in scope:</strong> {scope_n}</div>
            <div><strong style="color:var(--ink)">Report date:</strong> {_esc(generated)}</div>
            <div><strong style="color:var(--ink)">Version:</strong> {_esc(version)}</div>
            <div><strong style="color:var(--ink)">Prepared by:</strong> HEAVEN Autonomous Penetration-Testing Platform</div>
          </div>
        </div></div>"""

    def _confidentiality(self, eng: str) -> str:
        return f"""<div class="page section"><h2>Confidentiality Notice</h2>
          <p class="note">This document contains confidential and proprietary information about the
          security posture of <strong>{_esc(eng)}</strong>. It is intended solely for the named
          recipient and authorised stakeholders. It details vulnerabilities that could be exploited
          to compromise systems and data; unauthorised disclosure, copying, or distribution is
          strictly prohibited and may expose the organisation to significant risk.</p>
          <p class="small muted">Distribute on a strict need-to-know basis and store in accordance with
          your organisation's data-classification policy. Destroy securely when no longer required.</p>
        </div>"""

    def _doc_control(self, eng, assessor, version, generated, scope_n, total, overall) -> str:
        return f"""<div class="page section"><h2>Document Control</h2>
          <table>
            <tr><th style="width:200px">Field</th><th>Detail</th></tr>
            <tr><td>Engagement</td><td>{_esc(eng)}</td></tr>
            <tr><td>Assessor</td><td>{_esc(assessor)}</td></tr>
            <tr><td>Report version</td><td>{_esc(version)}</td></tr>
            <tr><td>Date generated</td><td>{_esc(generated)}</td></tr>
            <tr><td>Targets in scope</td><td>{scope_n}</td></tr>
            <tr><td>Total findings</td><td>{total}</td></tr>
            <tr><td>Overall risk rating</td><td><strong>{_esc(overall)}</strong></td></tr>
            <tr><td>Classification</td><td>CONFIDENTIAL</td></tr>
          </table>
          <h3>Revision History</h3>
          <table>
            <tr><th>Version</th><th>Date</th><th>Author</th><th>Description</th></tr>
            <tr><td>{_esc(version)}</td><td>{_esc(generated)}</td><td>HEAVEN</td>
                <td>Automated assessment report generated from engagement findings.</td></tr>
          </table>
        </div>"""

    @staticmethod
    def _toc() -> str:
        items = [
            ("exec", "Executive Summary"),
            ("scope", "Scope & Methodology"),
            ("risk", "Risk Rating Methodology"),
            ("summary", "Findings Summary"),
            ("details", "Detailed Findings"),
            ("owasp", "OWASP Top 10 Coverage"),
            ("roadmap", "Remediation Roadmap"),
            ("appendix", "Appendix"),
        ]
        lis = "".join(f'<li><a href="#{i}">{_esc(t)}</a></li>' for i, t in items)
        return f'<div class="page section"><h2>Table of Contents</h2><div class="toc"><ol>{lis}</ol></div></div>'

    def _exec_summary(self, eng, counts, total, overall, ordered, scope_n) -> str:
        crit, high = counts["critical"], counts["high"]
        if crit or high:
            posture = (f"The assessment identified <strong>{crit} critical</strong> and "
                       f"<strong>{high} high</strong>-severity issues that require prompt "
                       "remediation. Exploitation of these could lead to unauthorised access, "
                       "data exposure, or full system compromise.")
        elif counts["medium"]:
            posture = ("No critical or high-severity issues were identified. The medium-severity "
                       "findings below should be remediated to reduce residual risk.")
        else:
            posture = ("No significant vulnerabilities were identified during this assessment. "
                       "The environment demonstrated a strong security posture.")

        # severity distribution bar
        bar = ""
        legend = ""
        for sev, m in SEVERITY_META.items():
            n = counts[sev]
            if total:
                bar += f'<span style="background:{m["color"]};width:{(n/total)*100:.1f}%"></span>'
            legend += (f'<span><i style="background:{m["color"]}"></i>'
                       f'{m["label"]}: <strong>{n}</strong></span>')

        top = ordered[:5]
        top_rows = "".join(
            f'<tr><td><span class="pill" style="background:{SEVERITY_META[_sev_of(f)]["color"]}">'
            f'{SEVERITY_META[_sev_of(f)]["label"]}</span></td>'
            f'<td>{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</td>'
            f'<td class="small">{_esc(f.get("target") or "—")}</td></tr>'
            for f in top
        ) or '<tr><td colspan="3" class="muted">No findings.</td></tr>'

        return f"""<div class="page section" id="exec"><h2>Executive Summary</h2>
          <p>This report presents the results of a penetration test of <strong>{_esc(eng)}</strong>,
          covering <strong>{scope_n}</strong> in-scope target(s). A total of <strong>{total}</strong>
          finding(s) were identified, yielding an overall risk rating of
          <strong>{_esc(overall)}</strong>. {posture}</p>
          <div class="kpis">
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['critical']['color']}">{counts['critical']}</div><div class="l">Critical</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['high']['color']}">{counts['high']}</div><div class="l">High</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['medium']['color']}">{counts['medium']}</div><div class="l">Medium</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['low']['color']}">{counts['low']}</div><div class="l">Low</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['info']['color']}">{counts['info']}</div><div class="l">Info</div></div>
          </div>
          <h3>Severity Distribution</h3>
          <div class="bar">{bar}</div>
          <div class="legend">{legend}</div>
          <h3>Key Findings</h3>
          <table><tr><th style="width:90px">Severity</th><th>Finding</th><th>Target</th></tr>{top_rows}</table>
        </div>"""

    def _scope_methodology(self, scope: list[str]) -> str:
        if scope:
            rows = "".join(f'<tr><td class="small">{i+1}</td><td>{_esc(t)}</td></tr>'
                           for i, t in enumerate(scope))
            scope_tbl = f'<table><tr><th style="width:50px">#</th><th>Target</th></tr>{rows}</table>'
        else:
            scope_tbl = '<p class="muted">No explicit scope recorded; findings list their own targets.</p>'
        return f"""<div class="page section" id="scope"><h2>Scope &amp; Methodology</h2>
          <h3>In-Scope Targets</h3>
          {scope_tbl}
          <h3>Testing Approach</h3>
          <p>Testing followed a structured methodology aligned with industry standards. Activities
          progressed through reconnaissance, enumeration, vulnerability identification, exploitation
          (where safe and authorised), and impact analysis. Each finding was validated to reduce false
          positives and rated using the CVSS-based scale described in the next section.</p>
          <h3>Standards &amp; Frameworks Referenced</h3>
          <table>
            <tr><th style="width:230px">Framework</th><th>Use</th></tr>
            <tr><td>OWASP Top 10 (2021)</td><td>Web application risk categorisation</td></tr>
            <tr><td>PTES</td><td>Penetration Testing Execution Standard phases</td></tr>
            <tr><td>NIST SP 800-115</td><td>Technical assessment methodology</td></tr>
            <tr><td>MITRE ATT&amp;CK</td><td>Adversary technique mapping (where applicable)</td></tr>
            <tr><td>CVSS v3.1 / EPSS / CISA KEV</td><td>Severity, exploit-likelihood &amp; known-exploited enrichment</td></tr>
          </table>
        </div>"""

    @staticmethod
    def _risk_methodology() -> str:
        rows = ""
        for sev, m in SEVERITY_META.items():
            rows += (f'<tr><td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td>{m["cvss"]}</td><td>{m["sla"]}</td></tr>')
        return f"""<div class="page section" id="risk"><h2>Risk Rating Methodology</h2>
          <p>Each finding is assigned a severity derived from its CVSS v3.1 base score and adjusted for
          real-world exploitability (EPSS) and whether the issue is on the CISA Known Exploited
          Vulnerabilities catalog. Recommended remediation timeframes (SLAs) are guidance and should be
          tailored to the organisation's risk appetite.</p>
          <table>
            <tr><th style="width:130px">Severity</th><th>CVSS range</th><th>Recommended remediation SLA</th></tr>
            {rows}
          </table>
        </div>"""

    def _findings_summary(self, ordered: list[dict]) -> str:
        if not ordered:
            return '<div class="page section" id="summary"><h2>Findings Summary</h2><p class="muted">No findings recorded.</p></div>'
        rows = ""
        for i, f in enumerate(ordered, 1):
            sev = _sev_of(f)
            m = SEVERITY_META[sev]
            cvss = f.get("predicted_cvss_score") or f.get("typical_cvss") or "—"
            rows += (f'<tr><td class="small">{i}</td>'
                     f'<td><a href="#f{i}">{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</a></td>'
                     f'<td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td class="small">{_esc(cvss)}</td>'
                     f'<td class="small">{_esc(f.get("target") or "—")}</td>'
                     f'<td class="small">{_esc((f.get("status") or "open").title())}</td></tr>')
        return f"""<div class="page section" id="summary"><h2>Findings Summary</h2>
          <table>
            <tr><th style="width:40px">#</th><th>Finding</th><th style="width:90px">Severity</th>
                <th style="width:60px">CVSS</th><th>Target</th><th style="width:80px">Status</th></tr>
            {rows}
          </table>
        </div>"""

    def _detailed_findings(self, ordered: list[dict]) -> str:
        if not ordered:
            return '<div class="page section" id="details"><h2>Detailed Findings</h2><p class="muted">No findings recorded.</p></div>'
        cards = ""
        for i, f in enumerate(ordered, 1):
            cards += self._finding_card(i, f)
        return f'<div class="page section" id="details"><h2>Detailed Findings</h2>{cards}</div>'

    def _finding_card(self, idx: int, f: dict) -> str:
        sev = _sev_of(f)
        m = SEVERITY_META[sev]
        ev = f.get("evidence") or {}
        title = f.get("title") or f.get("vuln_type") or "Finding"
        cvss = f.get("predicted_cvss_score") or f.get("typical_cvss") or "—"

        # OWASP from finding or map
        owasp = f.get("owasp") or self._owasp_for(f.get("vuln_type", ""))
        meta_rows = [
            ("Target", f.get("target") or "—"),
            ("Severity", m["label"]),
            ("CVSS (predicted)", cvss),
            ("Risk score", f.get("risk_score") if f.get("risk_score") is not None else "—"),
            ("Confidence", f"{float(f.get('confidence', 0)):.0%}" if f.get("confidence") is not None else "—"),
            ("CWE", f.get("cwe") or "—"),
            ("OWASP", owasp or "—"),
            ("CVE", f.get("cve_id") or f.get("cve") or "—"),
            ("MITRE ATT&CK", f.get("mitre_technique") or "—"),
            ("CVSS vector", f.get("cvss_vector") or "—"),
            ("Status", (f.get("status") or "open").title()),
        ]
        meta_html = "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in meta_rows)

        def block(label: str, text: Any) -> str:
            if not text:
                return ""
            return f'<div class="block-label">{_esc(label)}</div><p>{_esc(text)}</p>'

        description = ev.get("description") or f.get("description") or ""
        impact = ev.get("impact") or ""
        remediation = ev.get("remediation") or f.get("remediation") or ""

        # Evidence / PoC — show whichever technical artefacts exist
        poc_parts = []
        for key, label in (("payload", "Payload"), ("request", "HTTP Request"),
                           ("response", "HTTP Response"), ("curl", "Reproduction (curl)"),
                           ("proof", "Proof"), ("poc", "Proof of Concept")):
            val = ev.get(key)
            if val:
                snippet = str(val)
                if len(snippet) > 4000:
                    snippet = snippet[:4000] + "\n… (truncated)"
                poc_parts.append(f'<div class="block-label">{_esc(label)}</div><pre>{_esc(snippet)}</pre>')
        poc_html = "".join(poc_parts)

        # References
        refs = ev.get("references") or f.get("references") or []
        refs_html = ""
        if refs:
            lis = "".join(f'<li><a href="{_esc(r)}">{_esc(r)}</a></li>' for r in refs)
            refs_html = f'<div class="block-label">References</div><ul class="small">{lis}</ul>'

        notes = f.get("operator_notes") or ""

        return f"""<div class="finding" id="f{idx}">
          <div class="finding-head">
            <span class="pill" style="background:{m['color']}">{m['label']}</span>
            <span class="id">#{idx}</span>
            <span class="ttl">{_esc(title)}</span>
          </div>
          <div class="finding-body">
            <table class="meta">{meta_html}</table>
            {block("Description", description)}
            {block("Impact", impact)}
            {poc_html}
            {block("Remediation", remediation)}
            {refs_html}
            {block("Assessor Notes", notes)}
          </div>
        </div>"""

    def _owasp_for(self, vuln_type: str) -> str:
        vt = (vuln_type or "").lower()
        for key, (cid, cn) in self.OWASP_MAP.items():
            if key in vt:
                return f"{cid} {cn}"
        return ""

    def _owasp_coverage(self, findings: list[dict]) -> str:
        coverage: dict[str, dict[str, Any]] = {}
        for f in findings:
            vt = (f.get("vuln_type") or "").lower()
            for key, (cid, cn) in self.OWASP_MAP.items():
                if key in vt:
                    coverage.setdefault(cid, {"name": cn, "n": 0})
                    coverage[cid]["n"] += 1
        rows = ""
        seen = set()
        for _key, (cid, cn) in self.OWASP_MAP.items():
            if cid in seen:
                continue
            seen.add(cid)
            hit = cid in coverage
            n = coverage.get(cid, {}).get("n", 0)
            status = "Findings present" if hit else "No findings"
            color = "#b00020" if hit else "#1a7f37"
            rows += (f'<tr><td class="small">{_esc(cid)}</td><td>{_esc(cn)}</td>'
                     f'<td style="color:{color};font-weight:600">{status}</td>'
                     f'<td class="small">{n}</td></tr>')
        return f"""<div class="page section" id="owasp"><h2>OWASP Top 10 (2021) Coverage</h2>
          <p class="small muted">Mapping of identified findings to the OWASP Top 10 risk categories.</p>
          <table>
            <tr><th style="width:110px">Control</th><th>Category</th><th style="width:160px">Status</th><th style="width:80px">Findings</th></tr>
            {rows}
          </table>
        </div>"""

    def _roadmap(self, ordered: list[dict]) -> str:
        actionable = [f for f in ordered if _sev_of(f) in ("critical", "high", "medium")]
        if not actionable:
            actionable = ordered[:10]
        rows = ""
        for i, f in enumerate(actionable[:25], 1):
            sev = _sev_of(f)
            m = SEVERITY_META[sev]
            ev = f.get("evidence") or {}
            action = ev.get("remediation") or f.get("remediation") or "Review and remediate per finding detail."
            action = str(action)
            if len(action) > 180:
                action = action[:180] + "…"
            rows += (f'<tr><td class="small">{i}</td>'
                     f'<td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td>{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</td>'
                     f'<td class="small">{_esc(action)}</td>'
                     f'<td class="small">{m["sla"]}</td></tr>')
        return f"""<div class="page section" id="roadmap"><h2>Remediation Roadmap</h2>
          <p>Recommended remediation order, prioritised by severity. Address higher-severity items
          first; SLAs are guidance and should be adapted to your risk appetite.</p>
          <table>
            <tr><th style="width:40px">#</th><th style="width:90px">Severity</th><th>Finding</th>
                <th>Recommended action</th><th style="width:100px">Target SLA</th></tr>
            {rows}
          </table>
        </div>"""

    @staticmethod
    def _appendix() -> str:
        gloss = [
            ("CVSS", "Common Vulnerability Scoring System — a 0–10 severity score."),
            ("EPSS", "Exploit Prediction Scoring System — probability a vuln will be exploited."),
            ("CISA KEV", "Catalog of vulnerabilities known to be actively exploited."),
            ("CWE", "Common Weakness Enumeration — category of the underlying weakness."),
            ("OWASP Top 10", "The ten most critical web application security risks."),
            ("False positive", "A reported issue that is not actually exploitable."),
        ]
        grows = "".join(f"<tr><td style='width:150px'><strong>{_esc(t)}</strong></td><td>{_esc(d)}</td></tr>"
                        for t, d in gloss)
        return f"""<div class="page section" id="appendix"><h2>Appendix</h2>
          <h3>Tooling</h3>
          <p class="small">Assessment performed with the HEAVEN Autonomous Penetration-Testing Platform,
          which orchestrates reconnaissance, vulnerability scanning, NVD/EPSS/KEV enrichment, and
          ML-assisted risk scoring.</p>
          <h3>Glossary</h3>
          <table>{grows}</table>
          <h3>Disclaimer</h3>
          <p class="small muted">This assessment reflects the security posture observed at the time of
          testing within the agreed scope. It does not guarantee the absence of other vulnerabilities.
          Security is an ongoing process; re-testing is recommended after remediation and following
          significant changes to the environment.</p>
        </div>"""

    @staticmethod
    def _footer() -> str:
        year = datetime.now(UTC).year
        return (f'<div class="page" style="text-align:center;color:var(--muted);font-size:12px">'
                f'Generated by HEAVEN · {year} · CONFIDENTIAL</div>')

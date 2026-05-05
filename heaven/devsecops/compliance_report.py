"""
HEAVEN — Compliance Report Generator
Generates HTML security assessment reports with OWASP Top 10 mapping.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class ComplianceReportGenerator:

    OWASP_MAP = {
        "sqli": ("A03:2021", "Injection"),
        "xss": ("A03:2021", "Injection"),
        "broken_auth": ("A07:2021", "Identification and Authentication Failures"),
        "sensitive_data": ("A02:2021", "Cryptographic Failures"),
        "xxe": ("A05:2021", "Security Misconfiguration"),
        "access_control": ("A01:2021", "Broken Access Control"),
        "ssrf": ("A10:2021", "SSRF"),
        "insecure_design": ("A04:2021", "Insecure Design"),
        "vulnerable_component": ("A06:2021", "Vulnerable and Outdated Components"),
        "logging": ("A09:2021", "Security Logging and Monitoring Failures"),
    }

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def generate_html_report(self, findings: list[dict],
                              engagement_name: str = "",
                              output_path: Optional[Path] = None) -> str:

        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEV_ORDER.get(f.get("severity", "info").lower(), 4)
        )

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        overall = ("Critical" if sev_counts["critical"] > 0 else
                   "High" if sev_counts["high"] > 0 else
                   "Medium" if sev_counts["medium"] > 0 else "Low")

        owasp_coverage = {}
        for f in findings:
            vt = (f.get("vuln_type") or "").lower()
            for key, (ctrl_id, ctrl_name) in self.OWASP_MAP.items():
                if key in vt:
                    if ctrl_id not in owasp_coverage:
                        owasp_coverage[ctrl_id] = {"name": ctrl_name, "findings": []}
                    owasp_coverage[ctrl_id]["findings"].append(f)

        sev_color = {"Critical": "#FF003C", "High": "#FF6B00",
                     "Medium": "#FFB800", "Low": "#00D4FF"}

        findings_html = ""
        for f in sorted_findings:
            sev = f.get("severity", "info").lower()
            col = {"critical": "#FF003C", "high": "#FF6B00",
                   "medium": "#FFB800", "low": "#00D4FF"}.get(sev, "#888")
            vt = (f.get("vuln_type") or "").lower()
            mapped = next(
                (f"{cid} — {cn}" for k, (cid, cn) in self.OWASP_MAP.items() if k in vt),
                "Uncategorized"
            )
            findings_html += f"""
            <div style="border:1px solid #333;padding:16px;margin:8px 0;background:#0a0a0a">
              <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <span style="background:{col};color:#000;padding:2px 8px;font-size:11px;font-weight:700">
                  {sev.upper()}
                </span>
                <span style="font-size:14px;font-weight:500">{f.get('title') or f.get('vuln_type','')}</span>
              </div>
              <table style="font-size:12px;color:#888;width:100%;border-collapse:collapse">
                <tr><td style="width:140px;padding:2px 0">Target</td>
                    <td style="color:#ccc">{f.get('target','')}</td></tr>
                <tr><td>Confidence</td>
                    <td style="color:#ccc">{f.get('confidence',0):.2f}</td></tr>
                <tr><td>Predicted CVSS</td>
                    <td style="color:#ccc">{f.get('predicted_cvss_score','N/A')}</td></tr>
                <tr><td>Priority Score</td>
                    <td style="color:#ccc">{f.get('priority_score','N/A')}</td></tr>
                <tr><td>OWASP Control</td>
                    <td style="color:#ccc">{mapped}</td></tr>
              </table>
            </div>"""

        owasp_rows = ""
        seen_ctrl_ids = set()
        for key, (ctrl_id, ctrl_name) in self.OWASP_MAP.items():
            if ctrl_id in seen_ctrl_ids:
                continue
            seen_ctrl_ids.add(ctrl_id)
            status = "FAILED" if ctrl_id in owasp_coverage else "NO FINDINGS"
            color = "#FF003C" if ctrl_id in owasp_coverage else "#1a4a1a"
            count = len(owasp_coverage.get(ctrl_id, {}).get("findings", []))
            owasp_rows += f"""
            <tr>
              <td style="padding:6px 8px;color:#888">{ctrl_id}</td>
              <td style="padding:6px 8px;color:#ccc">{ctrl_name}</td>
              <td style="padding:6px 8px"><span style="color:{color}">{status}</span></td>
              <td style="padding:6px 8px;color:#888">{count}</td>
            </tr>"""

        exec_tiles = "".join(
            f'<div style="flex:1;border:1px solid #333;padding:12px;text-align:center">'
            f'<div style="font-size:10px;color:#666;margin-bottom:4px">{k.upper()}</div>'
            f'<div style="font-size:28px;color:{sev_color.get(k.capitalize(), "#ccc")};font-weight:700">{v}</div></div>'
            for k, v in sev_counts.items() if k != "info"
        )

        html = f"""<!DOCTYPE html><html><head>
        <meta charset="utf-8">
        <title>HEAVEN Security Assessment — {engagement_name}</title>
        <style>
          body{{font-family:'JetBrains Mono',monospace;background:#000;color:#ccc;
               font-size:13px;padding:32px;max-width:1100px;margin:0 auto}}
          h1{{color:#00FF41;letter-spacing:0.15em;font-size:18px;margin-bottom:4px}}
          h2{{color:#00D4FF;font-size:13px;letter-spacing:0.1em;
              text-transform:uppercase;margin:28px 0 12px;
              border-bottom:1px solid #1a4a1a;padding-bottom:6px}}
          table{{width:100%;border-collapse:collapse;font-size:12px}}
          th{{text-align:left;padding:6px 8px;color:#00D4FF;
              border-bottom:1px solid #1a4a1a;font-weight:500}}
        </style></head><body>
        <h1>HEAVEN // SECURITY ASSESSMENT REPORT</h1>
        <div style="color:#666;font-size:11px;margin-bottom:24px">
          {engagement_name} &nbsp;|&nbsp;
          Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
          Overall Risk: <span style="color:{sev_color.get(overall,'#ccc')}">{overall}</span>
        </div>

        <h2>Executive Summary</h2>
        <div style="display:flex;gap:12px;margin-bottom:16px">
          {exec_tiles}
        </div>

        <h2>OWASP Top 10 Coverage</h2>
        <table>
          <tr><th>Control</th><th>Name</th><th>Status</th><th>Findings</th></tr>
          {owasp_rows}
        </table>

        <h2>Findings Detail ({len(findings)} total)</h2>
        {findings_html}
        </body></html>"""

        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
        return html

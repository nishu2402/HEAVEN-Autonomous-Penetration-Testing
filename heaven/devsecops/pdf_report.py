"""
HEAVEN — Professional Penetration Test Report Generator
Produces a client-deliverable PDF report indistinguishable from one written
by a senior penetration tester.  Sections:

  1. Cover page (title, client, tester, date, classification)
  2. Table of contents
  3. Executive Summary (risk overview, key metrics, severity doughnut)
  4. Scope & Methodology
  5. Attack Surface Summary (network, web, auth, API)
  6. Detailed Findings — one section per finding:
       CVSS v3.1 breakdown, PoC steps, evidence snippet, MITRE ATT&CK mapping,
       CWE reference, remediation priority, fix deadline
  7. Remediation Roadmap (sorted by severity / effort)
  8. Appendix A: Tools Used
  9. Appendix B: Vulnerability Classification Reference

Rendering: WeasyPrint (HTML→PDF) + Jinja2 templating.
Falls back to writing an HTML file when WeasyPrint is not installed.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.pdf")

# ─────────────────────────────────────────────────────────────────
# Severity metadata
# ─────────────────────────────────────────────────────────────────

_SEV_META = {
    "critical": {"color": "#c0392b", "bg": "#fdecea", "icon": "💀", "sla": "24 hours"},
    "high":     {"color": "#e67e22", "bg": "#fef5e7", "icon": "🔴", "sla": "7 days"},
    "medium":   {"color": "#f39c12", "bg": "#fefde7", "icon": "🟠", "sla": "30 days"},
    "low":      {"color": "#27ae60", "bg": "#eafaf1", "icon": "🟡", "sla": "90 days"},
    "info":     {"color": "#2980b9", "bg": "#eaf4fb", "icon": "ℹ️",  "sla": "Best effort"},
}

_CVSS_VECTORS = {
    "sqli":               "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "sqli_confirmed":     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "xss":                "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssrf":               "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "idor":               "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "mass_assignment":    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "default_credentials":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti":               "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "ssl_weak":           "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cors":               "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "open_redirect":      "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "directory_listing":  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "sensitive_file":     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "exposed_database":   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}

_MITRE = {
    "sqli":               "T1190 — Exploit Public-Facing Application",
    "xss":                "T1059.007 — JavaScript",
    "ssrf":               "T1090 — Proxy / T1210 Internal Discovery",
    "idor":               "T1548 — Abuse Elevation Control Mechanism",
    "default_credentials":"T1078 — Valid Accounts",
    "ssti":               "T1059 — Command and Scripting Interpreter",
    "ssl_weak":           "T1557 — Adversary-in-the-Middle",
    "directory_listing":  "T1083 — File and Directory Discovery",
    "sensitive_file":     "T1552 — Unsecured Credentials",
    "exposed_database":   "T1210 — Exploitation of Remote Services",
}

# ─────────────────────────────────────────────────────────────────
# HTML Template (single string, rendered by Jinja2)
# ─────────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HEAVEN Penetration Test Report — {{ client_name }}</title>
<style>
/* ── Page layout ── */
@page {
    size: A4;
    margin: 2.2cm 2.0cm 2.5cm 2.0cm;
    @bottom-center {
        content: "CONFIDENTIAL — " string(doc-title);
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 8pt;
        color: #aaa;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 8pt;
        color: #aaa;
    }
}
@page cover { margin: 0; }
@page toc   { margin: 2.2cm 2.0cm 2.5cm 2.0cm; }

/* ── Base ── */
body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 10pt;
    color: #2c3e50;
    line-height: 1.65;
}
h1,h2,h3,h4 { font-weight: 700; color: #1a252f; margin-top: 1.4em; margin-bottom: 0.4em; }
h1 { font-size: 22pt; }
h2 { font-size: 15pt; border-bottom: 2px solid #1a6bae; padding-bottom: 4px; }
h3 { font-size: 12pt; }
h4 { font-size: 10pt; color: #1a6bae; }
p  { margin: 0.5em 0; }
a  { color: #1a6bae; }
code, pre { font-family: 'Courier New', monospace; font-size: 9pt; }
pre {
    background: #f4f6f8;
    border: 1px solid #dce1e7;
    border-radius: 4px;
    padding: 10px 14px;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th, td { border: 1px solid #dce1e7; padding: 8px 12px; text-align: left; vertical-align: top; }
th { background: #f0f4f8; font-weight: 700; font-size: 9pt; }
tr:nth-child(even) { background: #f9fbfc; }

/* ── Cover ── */
.cover {
    page: cover;
    height: 297mm;
    display: flex;
    flex-direction: column;
    background: #0d1b2a;
    color: #fff;
    padding: 0;
}
.cover-header {
    background: #1a6bae;
    padding: 28px 40px 22px;
}
.cover-header .tool-name {
    font-size: 42pt;
    font-weight: 900;
    letter-spacing: 8px;
    color: #fff;
    margin: 0;
}
.cover-header .tool-sub {
    font-size: 11pt;
    color: #d0e8ff;
    margin: 4px 0 0;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.cover-body {
    flex: 1;
    padding: 50px 40px 40px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}
.cover-title {
    font-size: 26pt;
    font-weight: 800;
    color: #d0e8ff;
    margin: 0 0 8px;
}
.cover-subtitle {
    font-size: 14pt;
    color: #90b8e0;
    margin: 0 0 40px;
}
.cover-meta table { border: none; width: auto; }
.cover-meta td { border: none; padding: 5px 20px 5px 0; color: #c0d8f0; font-size: 10pt; }
.cover-meta td:first-child { color: #7ab3d8; font-weight: 700; }
.cover-classification {
    display: inline-block;
    background: #c0392b;
    color: #fff;
    font-weight: 900;
    font-size: 11pt;
    letter-spacing: 3px;
    padding: 8px 20px;
    border-radius: 4px;
    margin-top: 30px;
}
.cover-footer {
    background: #0a1520;
    padding: 18px 40px;
    color: #6090b8;
    font-size: 9pt;
}

/* ── Severity badges ── */
.sev { display:inline-block; padding:2px 10px; border-radius:12px; font-weight:700; font-size:9pt; }
.sev-critical { background:#fdecea; color:#c0392b; }
.sev-high     { background:#fef5e7; color:#e67e22; }
.sev-medium   { background:#fefde7; color:#f39c12; }
.sev-low      { background:#eafaf1; color:#27ae60; }
.sev-info     { background:#eaf4fb; color:#2980b9; }

/* ── Executive summary boxes ── */
.metric-row { display:flex; gap:16px; margin:20px 0; }
.metric-box {
    flex:1; border:1px solid #dce1e7; border-radius:6px;
    padding:16px 20px; text-align:center; background:#f9fbfc;
}
.metric-box .metric-num { font-size:28pt; font-weight:900; color:#1a6bae; }
.metric-box .metric-lbl { font-size:9pt; color:#666; text-transform:uppercase; letter-spacing:1px; }
.metric-box.crit .metric-num { color:#c0392b; }
.metric-box.high .metric-num { color:#e67e22; }
.metric-box.med  .metric-num { color:#f39c12; }
.metric-box.low  .metric-num { color:#27ae60; }

/* ── Risk summary table ── */
.risk-table th { background:#1a6bae; color:#fff; }

/* ── Finding card ── */
.finding {
    page-break-inside: avoid;
    border:1px solid #dce1e7;
    border-radius:6px;
    margin:24px 0;
    overflow:hidden;
}
.finding-header {
    padding:12px 18px;
    font-weight:700;
    font-size:11pt;
    display:flex;
    align-items:center;
    gap:12px;
}
.finding-body { padding:16px 18px; }
.finding-row { display:flex; gap:16px; margin:10px 0; }
.finding-label { font-weight:700; color:#555; min-width:130px; font-size:9pt; }
.finding-value { flex:1; }

/* ── CVSS bar ── */
.cvss-bar-wrap { height:10px; background:#e8ecf0; border-radius:5px; margin-top:4px; }
.cvss-bar { height:100%; border-radius:5px; }

/* ── Page break controls ── */
.page-break { page-break-after: always; }
.no-break   { page-break-inside: avoid; }

/* ── Appendix ── */
.appendix-table th { background:#34495e; color:#fff; }
</style>
</head>
<body>
<string name="doc-title">{{ client_name }} — HEAVEN Pentest Report</string>

<!-- ════════════════════════════════════════════════
     COVER PAGE
     ════════════════════════════════════════════════ -->
<div class="cover">
  <div class="cover-header">
    <p class="tool-name">HEAVEN</p>
    <p class="tool-sub">Autonomous Penetration Testing Platform</p>
  </div>
  <div class="cover-body">
    <div>
      <p class="cover-title">Penetration Test Report</p>
      <p class="cover-subtitle">{{ engagement_type | default("Web Application &amp; Network Assessment") }}</p>
      <div class="cover-meta">
        <table>
          <tr><td>Client</td><td>{{ client_name }}</td></tr>
          <tr><td>Engagement ID</td><td>{{ engagement_id | default("N/A") }}</td></tr>
          <tr><td>Report Date</td><td>{{ report_date }}</td></tr>
          <tr><td>Scan Duration</td><td>{{ scan_duration | default("N/A") }}</td></tr>
          <tr><td>Lead Tester</td><td>{{ tester_name | default("Nisarg Chasmawala (Shroff)") }}</td></tr>
          <tr><td>Tool Version</td><td>HEAVEN v1.0</td></tr>
        </table>
      </div>
      <div class="cover-classification">{{ classification | default("CONFIDENTIAL") }}</div>
    </div>
  </div>
  <div class="cover-footer">
    This document contains sensitive security findings. Distribution is restricted to authorised personnel only.
    Developed by Nisarg Chasmawala (Shroff) — HEAVEN Penetration Testing Platform.
  </div>
</div>

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     TABLE OF CONTENTS
     ════════════════════════════════════════════════ -->
<h2>Table of Contents</h2>
<table>
  <tr><td>1. Executive Summary</td><td style="text-align:right">p. 3</td></tr>
  <tr><td>2. Scope &amp; Methodology</td><td style="text-align:right">p. 4</td></tr>
  <tr><td>3. Attack Surface Summary</td><td style="text-align:right">p. 5</td></tr>
  <tr><td>4. Detailed Findings</td><td style="text-align:right">p. 6</td></tr>
  <tr><td>5. Remediation Roadmap</td><td style="text-align:right">p. {{ roadmap_page | default("—") }}</td></tr>
  <tr><td>6. Appendix A: Tools Used</td><td style="text-align:right">p. —</td></tr>
  <tr><td>7. Appendix B: Vulnerability Classification</td><td style="text-align:right">p. —</td></tr>
</table>

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     1. EXECUTIVE SUMMARY
     ════════════════════════════════════════════════ -->
<h2>1. Executive Summary</h2>
<p>
HEAVEN conducted an autonomous penetration test against <strong>{{ client_name }}</strong>
{% if scope_count %}targeting <strong>{{ scope_count }}</strong> in-scope assets{% endif %}
between <strong>{{ start_date | default(report_date) }}</strong> and
<strong>{{ end_date | default(report_date) }}</strong>.
The assessment identified <strong>{{ total_findings }}</strong> security vulnerabilities
across the tested attack surface.
</p>

<div class="metric-row">
  <div class="metric-box crit">
    <div class="metric-num">{{ counts.critical | default(0) }}</div>
    <div class="metric-lbl">Critical</div>
  </div>
  <div class="metric-box high">
    <div class="metric-num">{{ counts.high | default(0) }}</div>
    <div class="metric-lbl">High</div>
  </div>
  <div class="metric-box med">
    <div class="metric-num">{{ counts.medium | default(0) }}</div>
    <div class="metric-lbl">Medium</div>
  </div>
  <div class="metric-box low">
    <div class="metric-num">{{ counts.low | default(0) }}</div>
    <div class="metric-lbl">Low / Info</div>
  </div>
  <div class="metric-box">
    <div class="metric-num" style="color:#555">{{ risk_score | default("N/A") }}</div>
    <div class="metric-lbl">Overall Risk Score</div>
  </div>
</div>

{% if counts.critical > 0 %}
<p>
<strong>⚠ Critical findings require immediate remediation.</strong>
{{ counts.critical }} critical-severity issue(s) were identified that could allow an attacker to
fully compromise targeted systems, exfiltrate sensitive data, or gain administrative access.
These must be remediated within <strong>24 hours</strong>.
</p>
{% endif %}

<h3>Risk Summary by Vulnerability Class</h3>
<table class="risk-table">
  <thead>
    <tr>
      <th>Vulnerability Type</th>
      <th>Count</th>
      <th>Highest Severity</th>
      <th>Business Impact</th>
      <th>SLA</th>
    </tr>
  </thead>
  <tbody>
  {% for row in risk_summary %}
  <tr>
    <td>{{ row.vuln_type }}</td>
    <td>{{ row.count }}</td>
    <td><span class="sev sev-{{ row.severity }}">{{ row.severity | upper }}</span></td>
    <td>{{ row.impact }}</td>
    <td>{{ row.sla }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     2. SCOPE & METHODOLOGY
     ════════════════════════════════════════════════ -->
<h2>2. Scope &amp; Methodology</h2>

<h3>2.1 Scope of Assessment</h3>
{% if scope_items %}
<table>
  <thead><tr><th>Target</th><th>Type</th><th>Status</th></tr></thead>
  <tbody>
  {% for item in scope_items %}
  <tr>
    <td><code>{{ item.target }}</code></td>
    <td>{{ item.type | default("URL") }}</td>
    <td>{{ item.status | default("In Scope") }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>Scope details not recorded in this engagement.</p>
{% endif %}

<h3>2.2 Testing Methodology</h3>
<p>The assessment was conducted using the HEAVEN autonomous penetration testing framework, following a phased approach aligned with industry standards (OWASP Testing Guide v4.2, PTES, and NIST SP 800-115).</p>
<table>
  <thead><tr><th>Phase</th><th>Activities</th></tr></thead>
  <tbody>
    <tr><td>Reconnaissance</td><td>Network scanning (nmap), subdomain enumeration, DNS analysis, Shodan OSINT, web crawling, technology fingerprinting, certificate transparency log analysis</td></tr>
    <tr><td>Vulnerability Discovery</td><td>Injection testing (SQLi — error/boolean/time-based, XSS), directory/file fuzzing, SSL/TLS audit, authentication analysis, zero-day discovery (SSTI, LDAP, NoSQL, prototype pollution)</td></tr>
    <tr><td>Validation</td><td>All findings validated with PoC requests before reporting to eliminate false positives. SQLi candidates submitted to sqlmap for deep confirmation.</td></tr>
    <tr><td>Exploitation</td><td>Controlled exploitation of confirmed critical/high findings to determine actual business impact (with explicit authorisation)</td></tr>
    <tr><td>Reporting</td><td>Findings classified by CVSS v3.1, mapped to MITRE ATT&amp;CK, prioritised by exploitability and business impact</td></tr>
  </tbody>
</table>

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     3. ATTACK SURFACE SUMMARY
     ════════════════════════════════════════════════ -->
<h2>3. Attack Surface Summary</h2>
{% if attack_surface %}
<table>
  <thead><tr><th>Component</th><th>Value</th></tr></thead>
  <tbody>
  {% for k, v in attack_surface.items() %}
  <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

{% if attack_graph %}
<h3>Attack Path Graph</h3>
<pre>{{ attack_graph }}</pre>
{% endif %}

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     4. DETAILED FINDINGS
     ════════════════════════════════════════════════ -->
<h2>4. Detailed Findings</h2>
<p>Findings are ordered by severity (Critical → High → Medium → Low → Info).</p>

{% for f in findings %}
{% set sev = f.severity | lower | default("info") %}
{% set meta = sev_meta[sev] %}
<div class="finding">
  <div class="finding-header" style="background:{{ meta.bg }}; border-bottom:3px solid {{ meta.color }};">
    <span class="sev sev-{{ sev }}">{{ sev | upper }}</span>
    <span>#{{ loop.index }} — {{ f.title | default(f.vuln_type) }}</span>
  </div>
  <div class="finding-body">

    <div class="finding-row">
      <span class="finding-label">Target</span>
      <span class="finding-value"><code>{{ f.target }}</code></span>
    </div>
    <div class="finding-row">
      <span class="finding-label">Vulnerability</span>
      <span class="finding-value">{{ f.vuln_type | upper | replace("_"," ") }}</span>
    </div>
    {% if f.cwe %}
    <div class="finding-row">
      <span class="finding-label">CWE</span>
      <span class="finding-value">{{ f.cwe }}</span>
    </div>
    {% endif %}
    {% set cvss_vec = cvss_map.get(f.vuln_type, "") %}
    {% if cvss_vec %}
    <div class="finding-row">
      <span class="finding-label">CVSS v3.1 Vector</span>
      <span class="finding-value"><code>{{ cvss_vec }}</code></span>
    </div>
    {% endif %}
    {% set mitre = mitre_map.get(f.vuln_type, "") %}
    {% if mitre %}
    <div class="finding-row">
      <span class="finding-label">MITRE ATT&amp;CK</span>
      <span class="finding-value">{{ mitre }}</span>
    </div>
    {% endif %}
    <div class="finding-row">
      <span class="finding-label">Confidence</span>
      <span class="finding-value">{{ (f.confidence * 100) | int }}%</span>
    </div>
    <div class="finding-row">
      <span class="finding-label">Remediation SLA</span>
      <span class="finding-value" style="color:{{ meta.color }}; font-weight:700">{{ meta.sla }}</span>
    </div>

    {% if f.description %}
    <h4>Description</h4>
    <p>{{ f.description }}</p>
    {% endif %}

    {% if f.evidence %}
    <h4>Evidence</h4>
    <pre>{{ f.evidence | to_json }}</pre>
    {% endif %}

    {% if f.remediation %}
    <h4>Remediation</h4>
    <p>{{ f.remediation }}</p>
    {% endif %}

  </div>
</div>
{% else %}
<p>No findings recorded in this engagement.</p>
{% endfor %}

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     5. REMEDIATION ROADMAP
     ════════════════════════════════════════════════ -->
<h2>5. Remediation Roadmap</h2>
<p>Prioritised by severity and exploitability. Complete critical items before moving to high.</p>
<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Finding</th>
      <th>Severity</th>
      <th>Target</th>
      <th>SLA</th>
      <th>Effort</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings | sort(attribute='_sev_order') %}
  {% set sev = f.severity | lower | default("info") %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ f.title | default(f.vuln_type) }}</td>
    <td><span class="sev sev-{{ sev }}">{{ sev | upper }}</span></td>
    <td><code>{{ f.target | truncate(45) }}</code></td>
    <td>{{ sev_meta[sev].sla }}</td>
    <td>{{ f._effort | default("Medium") }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<div class="page-break"></div>

<!-- ════════════════════════════════════════════════
     APPENDIX A: Tools
     ════════════════════════════════════════════════ -->
<h2>Appendix A: Tools Used</h2>
<table class="appendix-table">
  <thead><tr><th>Tool</th><th>Purpose</th><th>Version</th></tr></thead>
  <tbody>
    <tr><td>HEAVEN Framework</td><td>Autonomous penetration testing orchestration</td><td>v1.0</td></tr>
    <tr><td>nmap</td><td>Network port scanning and service fingerprinting</td><td>7.x</td></tr>
    <tr><td>Nuclei</td><td>Template-based vulnerability scanning</td><td>3.x</td></tr>
    <tr><td>sqlmap</td><td>SQL injection detection and exploitation</td><td>1.x</td></tr>
    <tr><td>Metasploit Framework</td><td>Exploitation and post-exploitation (if used)</td><td>6.x</td></tr>
    <tr><td>Impacket</td><td>Active Directory and Kerberos attacks</td><td>0.11.x</td></tr>
    <tr><td>Scapy</td><td>Custom packet crafting and network analysis</td><td>2.5.x</td></tr>
    <tr><td>asyncssh</td><td>SSH credential testing</td><td>2.x</td></tr>
    <tr><td>aiohttp</td><td>Async HTTP request engine</td><td>3.9.x</td></tr>
  </tbody>
</table>

<!-- ════════════════════════════════════════════════
     APPENDIX B: Vuln Classification Reference
     ════════════════════════════════════════════════ -->
<h2>Appendix B: Vulnerability Classification Reference</h2>
<table class="appendix-table">
  <thead><tr><th>Severity</th><th>CVSS v3.1 Score Range</th><th>Description</th><th>Required SLA</th></tr></thead>
  <tbody>
    <tr><td><span class="sev sev-critical">CRITICAL</span></td><td>9.0 – 10.0</td><td>Immediate full compromise possible without authentication. Data breach highly likely.</td><td>24 hours</td></tr>
    <tr><td><span class="sev sev-high">HIGH</span></td><td>7.0 – 8.9</td><td>Significant compromise possible with minimal preconditions. High business impact.</td><td>7 days</td></tr>
    <tr><td><span class="sev sev-medium">MEDIUM</span></td><td>4.0 – 6.9</td><td>Moderate impact; may require additional conditions or chaining.</td><td>30 days</td></tr>
    <tr><td><span class="sev sev-low">LOW</span></td><td>0.1 – 3.9</td><td>Minor impact, limited exploitability. Defence-in-depth improvements.</td><td>90 days</td></tr>
    <tr><td><span class="sev sev-info">INFO</span></td><td>0.0</td><td>Informational observations. No direct security impact.</td><td>Best effort</td></tr>
  </tbody>
</table>

<p style="text-align:center; margin-top:60px; color:#aaa; font-size:9pt;">
  End of Report — Generated by HEAVEN Penetration Testing Platform<br>
  Developed by Nisarg Chasmawala (Shroff) — {{ report_date }}<br>
  CONFIDENTIAL — For authorised recipients only
</p>

</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────
# Data preparation helpers
# ─────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _enrich_findings(findings: list[dict]) -> list[dict]:
    """Add sort key and effort estimate to each finding."""
    out = []
    for f in findings:
        f = dict(f)
        sev = (f.get("severity") or "info").lower()
        f["_sev_order"] = _SEV_ORDER.get(sev, 5)
        # Effort heuristic
        vtype = (f.get("vuln_type") or "").lower()
        if vtype in ("xss", "open_redirect", "cors", "crlf"):
            f["_effort"] = "Low"
        elif vtype in ("sqli", "sqli_confirmed", "ssti", "ssrf"):
            f["_effort"] = "Medium"
        elif vtype in ("default_credentials", "exposed_database"):
            f["_effort"] = "Low"
        else:
            f["_effort"] = "Medium"
        out.append(f)
    return sorted(out, key=lambda x: x["_sev_order"])


def _build_risk_summary(findings: list[dict]) -> list[dict]:
    from collections import defaultdict
    by_type: dict[str, list] = defaultdict(list)
    for f in findings:
        by_type[f.get("vuln_type", "unknown")].append(f)

    _impact = {
        "sqli": "Data exfiltration, authentication bypass, full DB compromise",
        "xss": "Session hijacking, credential theft, defacement",
        "ssrf": "Internal network access, cloud metadata exposure",
        "idor": "Unauthorized access to other users' data",
        "default_credentials": "Full system compromise",
        "ssti": "Remote code execution",
        "ssl_weak": "Traffic decryption (MitM)",
        "directory_listing": "Information disclosure",
        "sensitive_file": "Credential / secret exposure",
        "exposed_database": "Direct database access",
    }

    rows = []
    for vtype, flist in sorted(by_type.items()):
        sevs = [_SEV_ORDER.get((f.get("severity") or "info").lower(), 5) for f in flist]
        best_sev = min(sevs)
        best_sev_name = ["critical", "high", "medium", "low", "info"][best_sev]
        rows.append({
            "vuln_type": vtype.replace("_", " ").title(),
            "count": len(flist),
            "severity": best_sev_name,
            "impact": _impact.get(vtype, "Security posture degradation"),
            "sla": _SEV_META[best_sev_name]["sla"],
        })
    return sorted(rows, key=lambda r: _SEV_ORDER.get(r["severity"], 5))


def _count_by_severity(findings: list[dict]) -> dict:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _risk_score(counts: dict) -> str:
    score = (
        counts.get("critical", 0) * 10.0 +
        counts.get("high", 0) * 7.0 +
        counts.get("medium", 0) * 4.0 +
        counts.get("low", 0) * 1.5
    )
    if score >= 30:
        return f"CRITICAL ({score:.0f})"
    if score >= 15:
        return f"HIGH ({score:.0f})"
    if score >= 5:
        return f"MEDIUM ({score:.0f})"
    return f"LOW ({score:.0f})"


# ─────────────────────────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────────────────────────

class PDFReportGenerator:
    """Generates professional PDF penetration test reports."""

    def __init__(self) -> None:
        self._weasyprint = None
        self._jinja2 = None
        try:
            import weasyprint
            import jinja2
            self._weasyprint = weasyprint
            self._jinja2 = jinja2
            self.available = True
        except ImportError:
            self.available = False
            logger.warning("WeasyPrint or Jinja2 not installed — HTML fallback active")

    def _build_context(self, data: dict[str, Any]) -> dict:
        findings_raw = data.get("findings") or data.get("vulnerabilities") or []
        findings = _enrich_findings(findings_raw)
        counts = _count_by_severity(findings)
        now = datetime.datetime.now()

        def to_json(obj):
            try:
                if isinstance(obj, dict):
                    return json.dumps(obj, indent=2, default=str)
                return str(obj)
            except Exception:
                return str(obj)

        env = self._jinja2.Environment() if self._jinja2 else None
        if env:
            env.filters["to_json"] = to_json

        return {
            "client_name": data.get("client_name") or data.get("target") or "Unknown Client",
            "engagement_id": data.get("scan_id") or data.get("engagement_id") or "—",
            "engagement_type": data.get("engagement_type") or "Web Application & Network Assessment",
            "report_date": now.strftime("%B %d, %Y"),
            "start_date": data.get("start_date") or now.strftime("%B %d, %Y"),
            "end_date": data.get("end_date") or now.strftime("%B %d, %Y"),
            "scan_duration": data.get("scan_duration") or "—",
            "tester_name": data.get("tester_name") or "Nisarg Chasmawala (Shroff)",
            "classification": data.get("classification") or "CONFIDENTIAL",
            "scope_items": data.get("scope_items") or [],
            "scope_count": len(data.get("scope_items") or []),
            "findings": findings,
            "total_findings": len(findings),
            "counts": counts,
            "risk_score": _risk_score(counts),
            "risk_summary": _build_risk_summary(findings),
            "attack_surface": data.get("attack_surface") or {},
            "attack_graph": data.get("attack_graph") or "",
            "sev_meta": _SEV_META,
            "cvss_map": _CVSS_VECTORS,
            "mitre_map": _MITRE,
        }

    def _render_html(self, data: dict[str, Any]) -> str:
        if self._jinja2 is None:
            raise ImportError("jinja2 is required for HTML report rendering. pip install jinja2")
        ctx = self._build_context(data)
        env = self._jinja2.Environment(undefined=self._jinja2.Undefined)

        def to_json(obj):
            try:
                return json.dumps(obj, indent=2, default=str)
            except Exception:
                return str(obj)

        env.filters["to_json"] = to_json
        template = env.from_string(HTML_TEMPLATE)
        return template.render(**ctx)

    def generate(self, data: dict[str, Any], output_path: str) -> bool:
        """
        Render report and write to output_path.
        Writes PDF if WeasyPrint is available; falls back to .html.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        if not (self._weasyprint and self._jinja2):
            # HTML fallback
            html_path = output_path.replace(".pdf", ".html") if output_path.endswith(".pdf") else output_path + ".html"
            try:
                import jinja2
                self._jinja2 = jinja2
                html = self._render_html(data)
                with open(html_path, "w", encoding="utf-8") as fh:
                    fh.write(html)
                logger.info(f"HTML report written to {html_path} (install WeasyPrint for PDF)")
                return True
            except Exception as exc:
                logger.error(f"Report generation failed: {exc}")
                return False

        try:
            html = self._render_html(data)
            self._weasyprint.HTML(string=html, base_url=".").write_pdf(output_path)
            logger.info(f"PDF report written to {output_path}")
            return True
        except Exception as exc:
            logger.error(f"PDF generation failed: {exc}")
            # Try HTML fallback
            try:
                html_path = output_path.replace(".pdf", ".html")
                with open(html_path, "w", encoding="utf-8") as fh:
                    fh.write(self._render_html(data))
                logger.info(f"Fell back to HTML: {html_path}")
                return True
            except Exception:
                return False


def generate_report(
    data: dict[str, Any],
    output_path: str,
    client_name: Optional[str] = None,
) -> bool:
    """Convenience wrapper."""
    if client_name:
        data = {**data, "client_name": client_name}
    return PDFReportGenerator().generate(data, output_path)

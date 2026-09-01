"""Regression: Confirmed vs Potential confirmation status + confirmed-only risk.

A professional pentest separates what was *proven present* (Confirmed) from what
is only *inferred* from a service version banner (Potential). Unauthenticated,
version-based CVE matches must be labelled Potential and must NOT inflate the
Overall Risk headline — yet must still appear in full. See
``heaven.utils.cvss.confirmation_status`` and the report generators.
"""
from __future__ import annotations

import pytest

from heaven.utils.cvss import (
    confirmation_status,
    is_confirmed_finding,
)


# ── The canonical resolver ──────────────────────────────────────────────────

@pytest.mark.parametrize("finding,expected", [
    # Version-based network CVE matches → Potential, regardless of confidence /
    # severity. The banner doesn't prove the flaw is present (backport problem).
    ({"vuln_type": "vulnerable_service", "cve": "CVE-2021-41773",
      "severity": "critical", "source": "inline_db", "confidence": 0.9}, "Potential"),
    ({"vuln_type": "potential_vulnerable_service", "severity": "low",
      "source": "inline_db", "confidence": 0.3}, "Potential"),
    # live-feed "version_confirmed" is still a banner inference, not a proof.
    ({"vuln_type": "vulnerable_service", "cve": "CVE-2023-1", "severity": "high",
      "source": "live:nvd", "version_confirmed": True, "confidence": 0.85}, "Potential"),
    ({"type": "zero_day_heuristic", "cve": "HEAVEN-HEURISTIC", "severity": "medium",
      "source": "heuristic", "confidence": 0.5}, "Potential"),
    ({"cve": "CVE-2021-1", "severity": "critical", "source": "nvd"}, "Potential"),
    # Heuristic / indicator language → Potential.
    ({"vuln_type": "sql_injection", "title": "Possible boolean-based SQLi indicator",
      "severity": "high", "confidence": 0.4}, "Potential"),
    # SCA / dependency (authoritative version from a manifest) → Confirmed.
    ({"vuln_type": "vulnerable_dependency", "cve": "CVE-2022-1", "severity": "high",
      "source": "osv", "confidence": 0.95}, "Confirmed"),
    # Directly-observed posture / config / exposure → Confirmed.
    ({"vuln_type": "missing_security_header", "severity": "medium", "confidence": 0.9}, "Confirmed"),
    ({"vuln_type": "spf_missing", "severity": "low"}, "Confirmed"),
    ({"vuln_type": "cleartext_protocol", "severity": "medium"}, "Confirmed"),
    ({"vuln_type": "server_version_disclosure", "severity": "low", "confidence": 0.98}, "Confirmed"),
    # Actively validated / exploited → Confirmed even with an "indicator" title.
    ({"vuln_type": "xss", "title": "Possible XSS", "severity": "high", "validated": True}, "Confirmed"),
    ({"vuln_type": "sql_injection", "severity": "critical",
      "evidence": {"result": "confirmed"}}, "Confirmed"),
    # Active-exploitation engine proof signals → Confirmed. The ``confirmed``
    # flag lives on the fresh in-memory finding; ``evidence.proof_output`` is the
    # one that survives the DB round-trip, so a *persisted* RCE still reads as
    # Confirmed (its top-level flag is gone by then).
    ({"vuln_type": "samba_usermap_script", "severity": "critical",
      "cve": "CVE-2007-2447", "confidence": 1.0, "confirmed": True,
      "evidence": {"proof_output": "uid=0(root) gid=0(root)"}}, "Confirmed"),
    ({"vuln_type": "samba_usermap_script", "severity": "critical",
      "cve": "CVE-2007-2447",
      "evidence": {"proof_output": "uid=0(root) gid=0(root)"}}, "Confirmed"),
])
def test_confirmation_status_classification(finding, expected):
    assert confirmation_status(finding) == expected
    assert is_confirmed_finding(finding) is (expected == "Confirmed")


def test_version_confirmed_is_not_active_validation():
    """A live-feed ``version_confirmed`` flag means a version fell in a CVE's
    affected range — it must NOT be treated as active validation (still Potential)."""
    f = {"vuln_type": "vulnerable_service", "cve": "CVE-9", "severity": "high",
         "source": "live:circl", "version_confirmed": True}
    assert confirmation_status(f) == "Potential"


# ── Report: Overall Risk from confirmed findings only ───────────────────────

def _cert_hacker_findings():
    """A hardened, certifiedhacker-style target: a version-based Critical CVE
    (Potential) plus directly-observed medium/low posture findings (Confirmed)."""
    return [
        {"vuln_type": "vulnerable_service", "cve": "CVE-2021-41773",
         "title": "Apache path traversal", "severity": "critical",
         "source": "inline_db", "confidence": 0.9, "cvss_base": 9.8, "target": "1.2.3.4:80"},
        {"vuln_type": "potential_vulnerable_service", "severity": "low",
         "title": "Potential vulnerable service: Dovecot (version undetermined)",
         "source": "inline_db", "confidence": 0.3, "target": "1.2.3.4",
         "evidence": {"candidate_cve_count": 3}},
        {"vuln_type": "missing_security_header", "title": "Missing CSP",
         "severity": "medium", "confidence": 0.9, "target": "https://1.2.3.4"},
        {"vuln_type": "cleartext_protocol", "title": "Cleartext FTP exposed",
         "severity": "medium", "target": "1.2.3.4:21"},
        {"vuln_type": "spf_missing", "title": "SPF record missing",
         "severity": "low", "target": "example.com"},
    ]


def test_html_report_overall_risk_is_confirmed_only():
    """The version-based Critical must NOT drive the Overall Risk headline; the
    worst *confirmed* finding (Medium) does. But the Critical still appears."""
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    html = ComplianceReportGenerator().generate_html_report(
        _cert_hacker_findings(), engagement_name="certified_hacker")
    import re
    m = re.search(r"Overall Risk: ([A-Za-z]+)", html)
    assert m and m.group(1) == "Medium", "confirmed-only risk should be Medium, not Critical"
    # Nothing is hidden: the Potential critical CVE is still in the report.
    assert "CVE-2021-41773" in html or "Apache path traversal" in html
    # Confirmation pills render for both classes.
    assert "conf-confirmed" in html and "conf-potential" in html
    # The confirmed/potential split is disclosed.
    assert "confirmed" in html.lower() and "potential" in html.lower()


def test_html_report_all_confirmed_keeps_headline():
    """With only confirmed findings, the headline reflects their worst severity."""
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    findings = [{"vuln_type": "missing_security_header", "title": "Missing CSP",
                 "severity": "high", "confidence": 0.9, "target": "h"}]
    html = ComplianceReportGenerator().generate_html_report(findings, engagement_name="e")
    import re
    m = re.search(r"Overall Risk: ([A-Za-z]+)", html)
    assert m and m.group(1) == "High"


def test_pdf_report_renders_with_confirmation():
    """The PDF generator must still build with the confirmation column."""
    pytest.importorskip("reportlab")
    import os
    import tempfile
    from heaven.devsecops.pdf_report import PDFReportGenerator
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "r.pdf")
        ok = PDFReportGenerator().generate(
            {"findings": _cert_hacker_findings(), "engagement": "certified_hacker",
             "scope": ["1.2.3.4", "example.com"]}, out)
        assert ok and os.path.getsize(out) > 0


# ── P2: header findings from a cross-site redirect are not the target's ──────

def test_same_site_redirect_gate():
    from heaven.vulnscan.auth_scanner import _same_site
    # On-site hops stay attributable.
    assert _same_site("http://certifiedhacker.com", "https://certifiedhacker.com/home")
    assert _same_site("http://certifiedhacker.com", "https://www.certifiedhacker.com/")
    assert _same_site("http://10.0.0.5", "http://10.0.0.5/app")
    # Cross-registered-domain redirects (CDN / parking / SSO) are NOT the target.
    assert not _same_site("http://certifiedhacker.com", "https://parking.bluehost-cdn.net/x")
    assert not _same_site("http://certifiedhacker.com", "https://login.microsoftonline.com/")


@pytest.mark.asyncio
async def test_security_headers_skip_offsite_redirect():
    """A "Server: nginx/…" header seen only after an off-site redirect must not be
    attributed to the in-scope target (the wrong-target FP the user hit)."""
    from heaven.vulnscan import auth_scanner

    class _Resp:
        def __init__(self, url, headers):
            self.url = url
            self.headers = headers
            self.status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def __init__(self, final_url, headers):
            self._final_url = final_url
            self._headers = headers

        def get(self, url, **kw):
            return _Resp(self._final_url, self._headers)

    offsite = _Session("https://parking.other-cdn.net/",
                       {"Server": "nginx/1.29.8"})
    out = await auth_scanner._audit_security_headers(offsite, "http://certifiedhacker.com")
    assert not any(f.get("vuln_type") == "server_version_disclosure" for f in out), \
        "off-site nginx header must not be attributed to the target"

    onsite = _Session("https://certifiedhacker.com/",
                      {"Server": "nginx/1.29.8"})
    out2 = await auth_scanner._audit_security_headers(onsite, "http://certifiedhacker.com")
    assert any(f.get("vuln_type") == "server_version_disclosure" for f in out2), \
        "a genuine on-site version banner is still reported"

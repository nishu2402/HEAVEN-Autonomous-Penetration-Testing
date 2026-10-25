"""Phase 5 — submission-ready per-finding bug-bounty report exporter."""

from __future__ import annotations

from heaven.devsecops.evidence import export_findings_bugbounty

_FINDINGS = [
    {"id": "f1", "target": "https://api.example.com/fetch?url=1", "vuln_type": "ssrf",
     "severity": "high", "confidence": 0.95,
     "title": "Server-Side Request Forgery via 'url'", "cwe": "CWE-918",
     "description": "The server resolved an attacker-controlled hostname.",
     "remediation": "Allow-list outbound hosts.",
     "evidence": {"parameter": "url", "callback_channel": "dns", "channels": ["dns"],
                  "token": "oobdeadbeef", "dns_hostname": "oobdeadbeef.oast.example.com",
                  "callback_from": "203.0.113.9", "callback_count": 2,
                  "validation_result": "confirmed"}},
    {"id": "f2", "target": "https://app.example.com/api/item/2", "vuln_type": "bola",
     "severity": "critical", "confidence": 0.96, "title": "BOLA: cross-identity read",
     "cwe": "CWE-639",
     "evidence": {"probe_type": "cross_identity_bola", "own_id": "1", "other_id": "2",
                  "proof": "A read object 2 as B", "validation_result": "confirmed"}},
    {"id": "f3", "target": "https://shop.example.com/buy?qty=2",
     "vuln_type": "numeric_tampering", "severity": "medium", "confidence": 0.7,
     "title": "Numeric/quantity tampering accepted in 'qty'", "cwe": "CWE-20",
     "evidence": {"parameter": "qty", "tampered": "-1", "status": 200}},
]


def test_bugbounty_export_is_severity_ordered_and_self_contained():
    md = export_findings_bugbounty(_FINDINGS, engagement_name="acme-bbp",
                                   platform="hackerone")
    # Severity ordering: critical before high before medium.
    assert md.index("BOLA") < md.index("Server-Side Request Forgery") < md.index("Numeric/quantity")
    # Every finding gets the full submission scaffold.
    assert md.count("## Summary") == 3
    assert md.count("## Steps To Reproduce") == 3  # hackerone wording
    assert md.count("## Impact") == 3
    assert md.count("## Remediation") == 3


def test_bugbounty_export_includes_cvss_cwe_and_oast_proof():
    md = export_findings_bugbounty(_FINDINGS, platform="generic")
    assert "CVSS 3.1:" in md and "CVSS 4.0:" in md
    assert "CWE-918" in md and "CWE-639" in md
    # The OAST callback is rendered as proof for the blind SSRF.
    assert "Out-of-band proof" in md
    assert "oobdeadbeef.oast.example.com" in md
    assert "Channel(s): dns" in md


def test_bugbounty_export_marks_confirmed_vs_potential():
    potential = [{"id": "p1", "target": "https://x.example/y", "vuln_type": "oauth_pkce_not_advertised",
                  "severity": "medium", "confidence": 0.45,  # conditional → Potential
                  "title": "PKCE not advertised", "cwe": "CWE-287",
                  "evidence": {"discovery": "https://x.example/.well-known/openid-configuration"}}]
    md = export_findings_bugbounty(potential)
    # A metadata-only weakness is honestly labelled, not claimed as reproduced.
    assert "Potential" in md


def test_bugbounty_platform_wording_switches():
    h1 = export_findings_bugbounty(_FINDINGS, platform="hackerone")
    intg = export_findings_bugbounty(_FINDINGS, platform="intigriti")
    assert "## Steps To Reproduce" in h1
    assert "## Proof of Concept" in intg

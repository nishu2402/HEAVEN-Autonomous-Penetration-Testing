"""Dynamic, faithful reproduction per finding (the "Reproduce / curl" gap).

The reported gap: ``evidence.build_curl`` always returned a curl, so a DNS / DB /
TLS / host finding that made *no* HTTP request got a bogus
``curl -i http://host:3306`` — and there was no raw-HTTP "Paste as request"
block despite the label promising one.

The fix makes reproduction dynamic per finding:
  * an HTTP finding gets a **faithful** curl (real method, param+payload folded
    into the exact URL/body) **and** a raw HTTP/1.1 request for Burp,
  * a non-HTTP finding gets a class-appropriate read-only command
    (``openssl s_client`` / ``dig`` / ``nmap`` / ``redis-cli`` …) or an honest
    "observed via …" note — **never** a fabricated curl.
"""
from __future__ import annotations

from heaven.devsecops.evidence import (
    build_curl,
    build_raw_http_request,
    build_repro_command,
    package_finding,
)


# ── HTTP findings: faithful curl + raw request built from the SAME txn ────────

def test_http_sqli_curl_folds_payload_into_query():
    finding = {
        "vuln_type": "sql_injection",
        "target": "http://192.168.0.162/vuln.php",
        "severity": "high",
        "confidence": 0.9,
        "param": "id",
        "method": "GET",
        "evidence": {
            "url": "http://192.168.0.162/vuln.php",
            "payload": "1' OR '1'='1",
            "status": 200,
            "response_excerpt": "You have an error in your SQL syntax",
        },
    }
    pkg = package_finding(finding)
    assert pkg.is_http is True
    # Faithful: the proof payload is folded into the query string.
    assert pkg.curl_command.startswith("curl")
    assert "id=1" in pkg.curl_command
    assert "vuln.php" in pkg.curl_command
    # A raw HTTP request exists for Burp "Paste as request".
    assert pkg.raw_http_request.startswith("GET /vuln.php?id=1")
    assert "Host: 192.168.0.162" in pkg.raw_http_request
    assert "HTTP/1.1" in pkg.raw_http_request
    # No non-HTTP repro command competes with the curl.
    assert pkg.repro_command == ""


def test_http_post_curl_and_raw_carry_body():
    curl = build_curl("POST", "http://t/login", headers={"Cookie": "x=1"},
                      body="", payload_param="user", payload_value="admin' --")
    assert "-X POST" in curl and "--data" in curl and "user=admin" in curl
    raw = build_raw_http_request("POST", "http://t/login", headers={"Cookie": "x=1"},
                                 body="", payload_param="user", payload_value="admin' --")
    assert raw.startswith("POST /login HTTP/1.1")
    assert "Content-Length:" in raw
    assert "user=admin" in raw


def test_raw_http_request_empty_for_non_http_url():
    assert build_raw_http_request("GET", "mysql://10.0.0.1:3306") == ""
    assert build_raw_http_request("GET", "10.0.0.1") == ""


# ── Non-HTTP findings: class-appropriate command, NEVER a bogus curl ──────────

def test_database_finding_gets_nmap_not_curl():
    finding = {
        "vuln_type": "database_exposed",
        "target": "10.0.0.1",
        "severity": "high",
        "evidence": {"port": 3306, "service": "mysql", "source": "network_scan"},
    }
    pkg = package_finding(finding)
    assert pkg.is_http is False
    assert not pkg.curl_command                      # no fabricated curl
    assert not pkg.raw_http_request
    assert pkg.repro_command                          # a real command instead
    assert pkg.repro_command.startswith("nmap")
    assert "3306" in pkg.repro_command and "10.0.0.1" in pkg.repro_command


def test_tls_finding_gets_openssl_s_client():
    cmd, note = build_repro_command("ssl_weak_cipher", "example.com",
                                    {"port": 443})
    assert cmd.startswith("openssl s_client -connect example.com:443")
    assert "-servername example.com" in cmd
    assert note == ""


def test_dns_spf_finding_gets_dig():
    cmd, _ = build_repro_command("spf_missing", "example.com")
    assert cmd.startswith("dig") and "example.com" in cmd


def test_redis_finding_gets_redis_cli():
    cmd, _ = build_repro_command("redis_exposed", "10.0.0.9", {"port": 6379})
    assert cmd.startswith("redis-cli") and "6379" in cmd


def test_eol_finding_gets_service_scan():
    cmd, _ = build_repro_command("unsupported_software", "10.0.0.1")
    assert cmd.startswith("nmap -sV") and "10.0.0.1" in cmd


def test_unreproducible_finding_gets_honest_note_not_curl():
    cmd, note = build_repro_command("some_passive_osint_only", "example.com",
                                    {"source": "passive_intel"})
    assert cmd == ""
    assert "no single-command reproduction" in note.lower()
    assert "passive_intel" in note


def test_non_http_package_has_no_curl_but_a_note_when_unmatched():
    finding = {
        "vuln_type": "passive_only_class_zzz",
        "target": "example.com",
        "severity": "info",
        "evidence": {"source": "shodan_internetdb"},
    }
    pkg = package_finding(finding)
    assert pkg.is_http is False
    assert not pkg.curl_command
    assert pkg.repro_command == ""
    assert pkg.repro_note and "shodan_internetdb" in pkg.repro_note


# ── to_markdown renders the right block per finding class ─────────────────────

def test_markdown_http_finding_shows_curl_and_raw():
    finding = {
        "vuln_type": "reflected_xss",
        "target": "http://t/search",
        "severity": "medium",
        "param": "q",
        "method": "GET",
        "evidence": {"url": "http://t/search", "payload": "<script>alert(1)</script>",
                     "status": 200, "response_excerpt": "<script>alert(1)</script>"},
    }
    md = package_finding(finding).to_markdown()
    assert "curl" in md
    assert "Paste as request" in md or "Raw HTTP request" in md


def test_markdown_non_http_finding_shows_command_not_curl():
    finding = {
        "vuln_type": "database_exposed",
        "target": "10.0.0.1",
        "severity": "high",
        "evidence": {"port": 5432, "service": "postgres"},
    }
    md = package_finding(finding).to_markdown()
    assert "nmap" in md
    # The bogus "curl -i http://10.0.0.1:5432" must not appear.
    assert "curl -i http://10.0.0.1:5432" not in md


# ── Internal scoring fields must never leak into the "Observed" proof block ───
# Regression: the FindingDetail "Proof of Issue" panel dumps evidence_data. When
# the ML predictor's raw fields (predicted_cvss_score / priority_score /
# risk_band) were copied into evidence for the header, they also surfaced here
# unreconciled and contradicted the reconciled header (e.g. "risk_band: high"
# beside a Medium severity badge). They are engine-internal, not observations.

def test_observed_block_excludes_internal_ml_scoring_fields():
    finding = {
        "vuln_type": "vulnerable_service",
        "target": "192.168.0.162:139",
        "severity": "medium",
        "evidence": {
            "product": "samba", "version": "3.X - 4.X", "exploit_available": True,
            "predicted_cvss_score": 7.6, "priority_score": 3.8, "risk_band": "high",
            "epss": 0.0, "in_kev": False, "criticality": "high",
        },
    }
    observed = package_finding(finding).to_dict()["evidence_data"]
    for leaked in ("predicted_cvss_score", "priority_score", "risk_band",
                   "epss", "in_kev", "criticality"):
        assert leaked not in observed, f"{leaked} must not surface as observed evidence"
    # The genuine observations survive.
    assert observed.get("product") == "samba"
    assert observed.get("exploit_available") is True


def test_enrich_finding_pins_risk_band_to_reconciled_severity():
    # A banner-inferred finding: published base 6.0 -> reconciled Medium, while
    # the ML risk_band says "high". enrich_finding must not leave them disagreeing.
    from heaven.devsecops.vuln_kb import enrich_finding
    out = enrich_finding({
        "vuln_type": "vulnerable_service",
        "title": "Samba username map script command execution (RCE)",
        "severity": "medium", "confidence": 0.90, "cve_id": "CVE-2007-2447",
        "evidence": {"cvss_base": 6.0, "risk_band": "high", "product": "samba"},
    })
    assert out["severity"] == "medium"
    assert out["evidence"]["risk_band"] == "medium"

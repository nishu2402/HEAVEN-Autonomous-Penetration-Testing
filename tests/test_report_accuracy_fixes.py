"""Regression tests for the accuracy / evidence-quality fixes prompted by a live
`certifiedhacker.com` report vs its public Shodan record.

Each test pins one concrete defect the report exposed:

Evidence rendering (`heaven/devsecops/evidence.py`)
  * A DNS / mail / network finding no longer fabricates a bogus HTTP request,
    a ``Response: HTTP 0 (0 bytes)`` line, or a meaningless ``curl`` command.
  * A security-header finding now shows the *real* HTTP 200 + response headers.

Taxonomy (`heaven/devsecops/vuln_kb.py`)
  * ``xml_accepted`` (an "accepts XML" surface note) is NOT inflated into the
    High XXE class; the *confirmed* ``xxe_entity_expansion`` still is.

Detectors
  * ``dangerous_http_method`` only fires on a genuine success, not a 404.
  * ``http_smuggling_indicator`` ignores 4xx/5xx WAF answers and no longer
    attaches the unrelated CVE-2019-16278.
  * ``race_condition`` no longer fires on mere status-code variance / on GET.

Coverage (vs Shodan)
  * Internet-exposed databases are flagged (public host only — no internal FP).
  * PostgreSQL and BIND end-of-life versions are detected.
  * cPanel / WHM / webmail ports are fingerprinted.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.devsecops.evidence import package_finding
from heaven.devsecops.vuln_kb import enrich_finding
from heaven.utils.cvss import reconcile_severity


# ── minimal fake aiohttp session ──────────────────────────────────────────────

class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._text


class _FnSession:
    """Every verb is dispatched to a single ``handler(method, url, **kw)`` that
    returns a ``_Resp`` — so the real detector code path runs unchanged."""

    def __init__(self, handler):
        self._h = handler

    def request(self, method, url, **kw):
        return self._h(method, url, **kw)

    def get(self, url, **kw):
        return self._h("GET", url, **kw)

    def post(self, url, **kw):
        return self._h("POST", url, **kw)

    def put(self, url, **kw):
        return self._h("PUT", url, **kw)

    def options(self, url, **kw):
        return self._h("OPTIONS", url, **kw)


# ── 1. Evidence rendering ─────────────────────────────────────────────────────

def test_dns_finding_has_no_fabricated_http_proof():
    spf = {
        "id": "a1", "target": "certifiedhacker.com", "vuln_type": "spf_analysis",
        "severity": "medium", "confidence": 0.95,
        "description": "SPF uses '?all' (neutral) — provides no protection",
        "evidence": {"spf_record": "v=spf1 a mx ptr include:bluehost.com ?all"},
    }
    md = package_finding(spf).to_markdown()
    assert "HTTP 0 (0 bytes)" not in md          # no fabricated empty response
    assert "Reproduce with curl" not in md       # no meaningless curl repro
    assert "curl -i" not in md
    assert "**Request:**" not in md              # no fake HTTP request block
    assert "?all" in md                          # the real record IS shown
    assert "Observed" in md


def test_header_finding_shows_real_status_and_headers():
    csp = {
        "id": "b2", "target": "https://www.certifiedhacker.com",
        "vuln_type": "csp_missing", "severity": "medium", "confidence": 0.98,
        "evidence": {"missing_header": "Content-Security-Policy", "status": 200,
                     "response_headers": {"Server": "Apache", "Set-Cookie": "<redacted>"}},
    }
    md = package_finding(csp).to_markdown()
    assert "HTTP 200" in md                       # real status, not HTTP 0
    assert "HTTP 0 (0 bytes)" not in md
    assert "Server: Apache" in md                 # headers are the proof


def test_cleartext_port_finding_not_rendered_as_http():
    # port-21 FTP finding: target is host:port, not a URL → no HTTP/curl block
    f = {"id": "c3", "target": "www.certifiedhacker.com:21",
         "vuln_type": "cleartext_service", "severity": "high", "confidence": 0.85,
         "evidence": {"port": 21, "protocol": "FTP"}}
    md = package_finding(f).to_markdown()
    assert "HTTP 0 (0 bytes)" not in md
    assert "curl -i" not in md


# ── 2. XXE taxonomy inflation ─────────────────────────────────────────────────

def test_xml_accepted_not_inflated_to_high_xxe():
    f = enrich_finding({"target": "https://x", "vuln_type": "xml_accepted",
                        "severity": "low", "confidence": 0.55, "evidence": {"status": 200}})
    f = reconcile_severity(f)
    assert f.get("severity") == "low", f"xml_accepted inflated to {f.get('severity')}"


def test_confirmed_xxe_stays_high():
    g = enrich_finding({"target": "https://x", "vuln_type": "xxe_entity_expansion",
                        "severity": "critical", "confidence": 0.9, "evidence": {}})
    g = reconcile_severity(g)
    assert g.get("cwe") == "CWE-611"
    assert g.get("severity") in ("high", "critical")


# ── 3. dangerous_http_method ──────────────────────────────────────────────────

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.asyncio
async def test_dangerous_method_404_not_flagged():
    from heaven.vulnscan.web_fuzzer import _fuzz_verb_tampering

    def handler(method, url, **kw):
        return _Resp(status=404, text="not found", headers={})  # DELETE/PUT → 404

    findings = await _fuzz_verb_tampering(_FnSession(handler), "https://t/")
    assert not [f for f in findings if f["vuln_type"] == "dangerous_http_method"], \
        "a 404 to DELETE/PUT must NOT be reported as a dangerous method"


@pytest.mark.asyncio
async def test_dangerous_method_webdav_success_is_flagged():
    from heaven.vulnscan.web_fuzzer import _fuzz_verb_tampering

    def handler(method, url, **kw):
        if method in ("PUT", "DELETE"):
            return _Resp(status=201, text="")   # genuine WebDAV success (Created)
        return _Resp(status=404, text="")

    findings = await _fuzz_verb_tampering(_FnSession(handler), "https://t/")
    assert [f for f in findings if f["vuln_type"] == "dangerous_http_method"], \
        "a 201/204 WebDAV success to DELETE/PUT SHOULD be reported"


@pytest.mark.asyncio
async def test_dangerous_method_200_page_served_is_not_flagged():
    # A plain 200 that returns the page is the app IGNORING the method (Apache
    # serves any verb PHP doesn't handle) — not a dangerous-method finding.
    # This was a real FP on DVWA, where DELETE /login.php returns 200 HTML.
    from heaven.vulnscan.web_fuzzer import _fuzz_verb_tampering

    def handler(method, url, **kw):
        return _Resp(status=200, text="<html>the page</html>")

    findings = await _fuzz_verb_tampering(_FnSession(handler), "https://t/")
    assert not [f for f in findings if f["vuln_type"] == "dangerous_http_method"], \
        "a 200 (page served) to DELETE/PUT must NOT be flagged"


# ── 4. http_smuggling_indicator ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_smuggling_4xx_answer_is_not_an_indicator():
    from heaven.vulnscan.web_fuzzer import _fuzz_request_smuggling

    def handler(method, url, **kw):
        # baseline POST → 200; the ambiguous CL+TE / TE-obfuscation → 406 (WAF)
        headers = kw.get("headers") or {}
        if headers.get("Transfer-Encoding"):
            return _Resp(status=406, text="not acceptable")
        return _Resp(status=200, text="ok")

    findings = await _fuzz_request_smuggling(_FnSession(handler), "https://t/")
    assert findings == [], "a 4xx rejection of a malformed request is not smuggling"


@pytest.mark.asyncio
async def test_smuggling_never_attaches_wrong_cve():
    from heaven.vulnscan.web_fuzzer import _fuzz_request_smuggling

    def handler(method, url, **kw):
        headers = kw.get("headers") or {}
        if headers.get("Transfer-Encoding"):
            return _Resp(status=301, text="")   # normal, differs from baseline → fires
        return _Resp(status=200, text="ok")

    findings = await _fuzz_request_smuggling(_FnSession(handler), "https://t/")
    # It may fire as a weak indicator, but must NOT carry the nostromo RCE CVE.
    blob = repr(findings)
    assert "CVE-2019-16278" not in blob


# ── 5. race_condition ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_race_status_variance_not_flagged():
    from heaven.vulnscan.advanced_attacks import RaceConditionDetector

    calls = {"n": 0}

    def handler(method, url, **kw):
        calls["n"] += 1
        # A spread of 200/403 with an identical success body — the classic admin
        # panel that merely answers inconsistently. Must NOT be a race finding.
        return _Resp(status=200 if calls["n"] % 2 else 403, text="same-body")

    r = await RaceConditionDetector.test_race(_FnSession(handler), "https://t/cpanel",
                                              method="POST", concurrent_requests=20)
    assert r is None


@pytest.mark.asyncio
async def test_race_get_never_flagged():
    from heaven.vulnscan.advanced_attacks import RaceConditionDetector

    def handler(method, url, **kw):
        return _Resp(status=200, text="x")

    r = await RaceConditionDetector.test_race(_FnSession(handler), "https://t/",
                                              method="GET", concurrent_requests=20)
    assert r is None


@pytest.mark.asyncio
async def test_race_divergent_successes_is_a_low_lead():
    from heaven.vulnscan.advanced_attacks import RaceConditionDetector

    calls = {"n": 0}
    concurrent = 20

    def handler(method, url, **kw):
        calls["n"] += 1
        # The genuine (weak) race signal: the CONCURRENT burst diverges (the
        # state raced), but once serialised the endpoint is deterministic. The
        # detector confirms that stability with two sequential probes AFTER the
        # burst, so a merely-dynamic page (which diverges every time, even
        # serially) is rejected — see test_race_dynamic_page_not_flagged.
        if calls["n"] <= concurrent:
            return _Resp(status=200, text=f"balance-{calls['n']}")
        return _Resp(status=200, text="balance-final")   # stable when serialised

    r = await RaceConditionDetector.test_race(_FnSession(handler), "https://t/redeem",
                                              method="POST", concurrent_requests=concurrent)
    assert r is not None
    assert r.severity == "low" and r.vuln_type == "race_condition"


@pytest.mark.asyncio
async def test_race_dynamic_page_not_flagged():
    """A page whose body varies on EVERY request (phpinfo, CSRF tokens,
    timestamps) is dynamic, not racing — its divergence appears under a serial
    probe too, so it must never be flagged."""
    from heaven.vulnscan.advanced_attacks import RaceConditionDetector

    calls = {"n": 0}

    def handler(method, url, **kw):
        calls["n"] += 1
        return _Resp(status=200, text=f"nonce-{calls['n']}")   # differs every call

    r = await RaceConditionDetector.test_race(_FnSession(handler), "https://t/phpinfo.php",
                                              method="POST", concurrent_requests=20)
    assert r is None


# ── 6. Exposed databases (coverage vs Shodan) ─────────────────────────────────

@pytest.mark.asyncio
async def test_exposed_database_public_flagged_private_skipped():
    from heaven.recon.network_exposure import analyze_network_exposure

    net = {"hosts": [
        {"ip": "162.241.216.11", "open_ports": [
            {"port": 3306, "service": "mysql"}, {"port": 5432, "service": "postgresql"}]},
        {"ip": "192.168.1.50", "open_ports": [{"port": 3306, "service": "mysql"}]},
    ]}
    res = await analyze_network_exposure(net, active_snmp=False, active_probes=False)
    db = {f["target"] for f in res["findings"] if f["vuln_type"] == "database_exposed"}
    assert "162.241.216.11:3306" in db and "162.241.216.11:5432" in db
    assert not any(t.startswith("192.168") for t in db), "internal DB must not be flagged"


# ── 7. EOL coverage ───────────────────────────────────────────────────────────

def test_eol_postgres_and_bind_flagged():
    from heaven.vulnscan.eol_scanner import _product_findings
    assert _product_findings("h:5432", "PostgreSQL", "9.6.0", "PostgreSQL 9.6.0")
    assert _product_findings("h:53", "ISC BIND", "9.16.23", "ISC BIND 9.16.23 (RedHat)")
    # A supported version must NOT be flagged.
    assert not _product_findings("h:3306", "MySQL", "8.0.36", "MySQL 8.0.36")


# ── 8. Port fingerprint coverage ──────────────────────────────────────────────

def test_cpanel_ports_are_fingerprinted():
    from heaven.recon.network_scanner import SERVICE_FINGERPRINTS, _LIVENESS_PROBE_PORTS
    for p in (2082, 2083, 2086, 2087, 2095, 2096, 2222):
        assert p in SERVICE_FINGERPRINTS, f"port {p} not fingerprinted"
    assert 2083 in _LIVENESS_PROBE_PORTS and 2087 in _LIVENESS_PROBE_PORTS

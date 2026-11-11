"""network_exposure: a cPanel/WHM/Webmail login panel served over cleartext HTTP
must be reported (CWE-319).

Live recall gap found on certifiedhacker.com: ``http://host:2082/`` (cPanel),
``:2086`` (WHM) and ``:2095`` (Webmail) each serve a 200 login page with a real
password field over plaintext HTTP. nmap fingerprints those non-standard
cleartext ports as a random non-HTTP service (infowave / gnunet / nbx-ser), so
the web/auth crawlers — which key off an HTTP service or the standard 80/8080 —
never reach them, and the cleartext admin login slipped through with ZERO
findings. The ``_cleartext_http_login_panel`` probe closes that gap.

FP-safety is the whole design: the probe fires ONLY on a 200 login form served
over http://. A port that 301/302-redirects to its HTTPS twin (the common cPanel
"always redirect to SSL" config), or that serves no password field, yields
nothing — so a seeded port guess can never become a false positive. Generic
HTTP (80/8080) is deliberately left to the web scanners so this module neither
double-reports nor fetches every site's homepage.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import network_exposure as nx
from heaven.devsecops.vuln_kb import enrich_finding

pytest.importorskip("aiohttp")


def _run(coro):
    return asyncio.run(coro)


def _net(ip, *ports):
    return {"hosts": [{"ip": ip, "open_ports":
            [{"port": p, "service": s} for p, s in ports]}]}


# ── dispatch: the recall win ──────────────────────────────────────────────────

def test_cleartext_cpanel_panel_flagged(monkeypatch):
    seen = []

    async def _fake(host, port, timeout=6.0):
        seen.append(port)
        return {"url": f"http://{host}:{port}/", "status": 200,
                "title": "cPanel Login", "known_panel": True,
                "form_action_scheme": "relative"}

    monkeypatch.setattr(nx, "_cleartext_http_login_panel", _fake)
    # nmap mislabels 2082 as "infowave" (NOT http); the port seed must still
    # reach it — that is exactly the gap this detector exists to close.
    res = _run(nx.analyze_network_exposure(
        _net("203.0.113.9", (2082, "infowave"), (2083, "ssl/radsec")),
        active_snmp=False, active_probes=True))
    cl = [f for f in res["findings"] if f["vuln_type"] == "cleartext_service"]
    assert len(cl) == 1, cl
    f = cl[0]
    assert f["severity"] == "high"
    assert "cPanel" in f["title"] and "2082" in f["title"]
    assert f["evidence"]["port"] == 2082 and f["evidence"]["scheme"] == "http"
    assert f["evidence"]["proven"] is True
    assert enrich_finding(f).get("cwe")        # taxonomy parity with other findings
    # the SSL twin on 2083 is never probed → no FP, and the seed truly drove it
    assert seen == [2082]


def test_ssl_panel_twins_are_not_probed(monkeypatch):
    seen = []

    async def _fake(host, port, timeout=6.0):
        seen.append(port)
        return None

    monkeypatch.setattr(nx, "_cleartext_http_login_panel", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("203.0.113.9", (2083, "ssl/radsec"), (2087, "ssl/eli"),
             (443, "ssl/http")),
        active_snmp=False, active_probes=True))
    assert seen == []
    assert not any(f["vuln_type"] == "cleartext_service" for f in res["findings"])


def test_generic_http_is_left_to_the_web_scanners(monkeypatch):
    # Plain :80 / :8080 must NOT be probed here — the web/auth crawlers own those.
    seen = []

    async def _fake(host, port, timeout=6.0):
        seen.append(port)
        return None

    monkeypatch.setattr(nx, "_cleartext_http_login_panel", _fake)
    _run(nx.analyze_network_exposure(
        _net("203.0.113.9", (80, "http"), (8080, "http-proxy")),
        active_snmp=False, active_probes=True))
    assert seen == []


def test_panel_probe_never_runs_in_passive_mode(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("cleartext panel probe ran in passive mode")

    monkeypatch.setattr(nx, "_cleartext_http_login_panel", _boom)
    res = _run(nx.analyze_network_exposure(
        _net("203.0.113.9", (2082, "infowave")), active_snmp=False))
    assert not any(f["vuln_type"] == "cleartext_service" for f in res["findings"])


# ── probe gate: FP-safety on the real wire shapes ─────────────────────────────

def _patch_aiohttp(monkeypatch, status, body=b"", ctype="text/html"):
    import aiohttp

    class _Resp:
        def __init__(self):
            self.status = status
            self.headers = {"Content-Type": ctype}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def read(self):
            return body

    class _Sess:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, **kw):
            return _Resp()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: _Sess())


def test_probe_fires_on_200_cleartext_login_form(monkeypatch):
    body = (b'<html><head><title>cPanel Login</title></head><body>'
            b'<form action="/login/"><input type="password" name="pass">'
            b'</form></body></html>')
    _patch_aiohttp(monkeypatch, 200, body)
    out = _run(nx._cleartext_http_login_panel("h", 2082))
    assert out is not None
    assert out["status"] == 200 and out["known_panel"] is True
    assert out["form_action_scheme"] == "relative"


def test_probe_silent_on_redirect_to_https(monkeypatch):
    # cPanel "always redirect to SSL": http://:2082 → 301 https://:2083 — the
    # login form is NOT delivered in cleartext, so this is not a finding.
    _patch_aiohttp(monkeypatch, 301, b"")
    assert _run(nx._cleartext_http_login_panel("h", 2082)) is None


def test_probe_silent_without_a_password_field(monkeypatch):
    # A 200 that is not a login form (no password input) must never fire.
    _patch_aiohttp(monkeypatch, 200,
                   b"<html><title>cPanel</title><p>redirecting...</p></html>")
    assert _run(nx._cleartext_http_login_panel("h", 2082)) is None

"""Detection tests for the in-house OOB + misconfiguration scanners.

Every positive case is proven against the native vulnerable app
(``tests/benchmarks/native/vuln_app.py``); every class also has a negative case
proving HEAVEN does not false-positive on well-configured behaviour. SSRF and XXE
are confirmed out-of-band via the in-house OAST collaborator — a finding only
appears if the target actually calls us back.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json

import pytest

from heaven.vulnscan.misconfig_scanner import (
    _collapse_catch_all_hygiene,
    _crack_jwt_secret,
    _jwt_findings,
    _parse_jwt,
    scan_misconfig,
)
from heaven.vulnscan.oast import OASTListener
from heaven.vulnscan.oob_scanner import scan_oob

pytest.importorskip("aiohttp")
pytest.importorskip("flask")

from tests.benchmarks.native.vuln_app import serve  # noqa: E402


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _types(findings: list[dict]) -> set[str]:
    return {f.get("vuln_type") for f in findings}


# ── OAST collaborator ─────────────────────────────────────────────────────────

def test_oast_records_and_isolates_tokens():
    import urllib.request
    with OASTListener() as oast:
        t = oast.new_token()
        urllib.request.urlopen(oast.url_for(t), timeout=2).read()
        assert oast.poll(t, timeout=2) is True
        hits = oast.interactions(t)
        assert len(hits) == 1 and hits[0].method == "GET"
        assert oast.hit("oob_never_fired") is False  # token isolation


# ── JWT primitives ────────────────────────────────────────────────────────────

def test_jwt_weak_secret_is_cracked():
    import hashlib
    import hmac
    header, payload = _b64url({"alg": "HS256", "typ": "JWT"}), _b64url({"sub": "admin"})
    signing_input = f"{header}.{payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert _crack_jwt_secret(signing_input, sig, "HS256") == "secret"


def test_jwt_strong_secret_not_cracked():
    import hashlib
    import hmac
    header, payload = _b64url({"alg": "HS256"}), _b64url({"sub": "x"})
    signing_input = f"{header}.{payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(b"a-genuinely-strong-unguessable-key-8f3b", signing_input.encode(),
                 hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert _crack_jwt_secret(signing_input, sig, "HS256") is None


def test_jwt_alg_none_flagged():
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'admin'})}."
    out = _jwt_findings("http://h/", token, source="test")
    assert len(out) == 1 and out[0]["vuln_type"] == "jwt_alg_none"
    assert out[0]["severity"] == "critical"


def test_non_jwt_is_ignored():
    assert _parse_jwt("not.a.jwt") is None
    assert _jwt_findings("http://h/", "just-a-plain-cookie-value", source="c") == []


# ── misconfiguration scanner against the native app ───────────────────────────

async def test_misconfig_detects_all_classes_on_native_app():
    with serve() as base:
        urls = [
            f"{base}/api/data",
            f"{base}/login",
            f"{base}/vulnerabilities/redirect/?url=x",
        ]
        res = await scan_misconfig(urls)
    types = _types(res["findings"])
    assert "cors_misconfig" in types
    assert "insecure_cookie" in types
    assert "jwt_weak_secret" in types
    assert "open_redirect" in types
    # the CORS+credentials case is the dangerous one — verify severity
    cors = next(f for f in res["findings"] if f["vuln_type"] == "cors_misconfig")
    assert cors["severity"] == "high"
    jwt = next(f for f in res["findings"] if f["vuln_type"] == "jwt_weak_secret")
    assert jwt["evidence"]["recovered_secret"] == "secret"


async def test_misconfig_no_false_positive_on_clean_endpoint():
    # the escaped-echo endpoint sets no cookies, reflects no Origin, issues no
    # redirect → none of the session/CORS/redirect classes should fire.
    with serve() as base:
        res = await scan_misconfig([f"{base}/vulnerabilities/xss_d/?default=1"])
    types = _types(res["findings"])
    assert "cors_misconfig" not in types
    assert "insecure_cookie" not in types
    assert "jwt_weak_secret" not in types
    assert "open_redirect" not in types


async def test_open_redirect_requires_canary_host_match():
    # An endpoint that only ever redirects to itself (same-site) must not be
    # reported, even though it *is* a redirect.
    class _SelfRedirect:
        async def __aenter__(self):
            self._s = await asyncio.start_server(self._h, "127.0.0.1", 0)
            self.port = self._s.sockets[0].getsockname()[1]
            return self

        async def __aexit__(self, *e):
            self._s.close()
            with contextlib.suppress(Exception):
                await self._s.wait_closed()

        async def _h(self, reader, writer):
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader.read(4096), timeout=0.5)
                writer.write(b"HTTP/1.1 302 Found\r\nLocation: /home\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()

    async with _SelfRedirect() as srv:
        res = await scan_misconfig([f"http://127.0.0.1:{srv.port}/go?url=x"])
    assert "open_redirect" not in _types(res["findings"])


# ── out-of-band SSRF / XXE ────────────────────────────────────────────────────

async def test_ssrf_proven_out_of_band():
    with serve() as base, OASTListener() as oast:
        res = await scan_oob([f"{base}/vulnerabilities/ssrf/?url=x"], oast=oast)
    ssrf = [f for f in res["findings"] if f["vuln_type"] == "ssrf"]
    assert ssrf, "SSRF should be proven via an OAST callback"
    assert ssrf[0]["evidence"]["proof"] == "out-of-band callback received"
    assert ssrf[0]["evidence"]["callback_count"] >= 1


async def test_xxe_proven_out_of_band():
    with serve() as base, OASTListener() as oast:
        res = await scan_oob([f"{base}/vulnerabilities/xxe/"], oast=oast)
    assert "xxe" in _types(res["findings"])


async def test_oob_no_false_positive_on_non_fetching_endpoint():
    # The reflected-XSS endpoint never fetches a URL and never parses XML → no
    # callback → no SSRF/XXE finding.
    with serve() as base, OASTListener() as oast:
        res = await scan_oob([f"{base}/vulnerabilities/xss_r/?name=x"], oast=oast)
    assert _types(res["findings"]) == set()


def test_catch_all_hygiene_collapse():
    """On a soft-404 / catch-all host (every path returns the same page), per-URL
    page-hygiene findings collapse to ONE per host, so dozens of speculative probe
    URLs (/graphql, /swagger, /api/v1 …) don't flood a report with identical
    login-form nags. A non-catch-all host and other finding types are untouched."""
    base = "https://catchall.example"
    findings = []
    for p in ("", "/graphql", "/swagger", "/api/v1", "/xmlrpc"):
        findings.append({"target": base + p,
                         "vuln_type": "password_autocomplete_enabled", "severity": "low"})
        findings.append({"target": base + p,
                         "vuln_type": "sensitive_cache_control", "severity": "low"})
    findings.append({"target": "https://real.example/login",
                     "vuln_type": "password_autocomplete_enabled", "severity": "low"})
    findings.append({"target": base + "/graphql",
                     "vuln_type": "graphql_introspection", "severity": "medium"})

    out = _collapse_catch_all_hygiene(findings, {base})
    pw = [f for f in out if f["vuln_type"] == "password_autocomplete_enabled"
          and f["target"].startswith(base)]
    cc = [f for f in out if f["vuln_type"] == "sensitive_cache_control"]
    assert len(pw) == 1
    assert pw[0]["target"] == base                      # representative = site root
    assert pw[0]["evidence"]["catch_all_host"] is True
    assert pw[0]["evidence"]["duplicate_probe_urls"] == 4
    assert len(cc) == 1
    # a genuinely distinct (non-catch-all) host and non-hygiene finding are kept
    assert any(f["target"] == "https://real.example/login" for f in out)
    assert any(f["vuln_type"] == "graphql_introspection" for f in out)
    # a host NOT confirmed catch-all is never collapsed
    out2 = _collapse_catch_all_hygiene(findings, set())
    assert sum(1 for f in out2
               if f["vuln_type"] == "password_autocomplete_enabled") == 6


# ── cookie-flag parsing: attribute-scoped, deletion-aware ──────────────────────
# The flag checks must read the Set-Cookie ATTRIBUTE section only. The old
# ``"secure" in raw.lower()`` substring test over the whole header let a cookie
# whose VALUE contained the flag word mask a genuine missing-flag finding, and it
# warned about logout cookies the server is actively deleting.

class _CookieHdrs:
    def __init__(self, set_cookies):
        self._sc = list(set_cookies)

    def getall(self, key, default=None):
        if key.lower() == "set-cookie":
            return list(self._sc)
        return list(default) if default is not None else []


class _CookieResp:
    def __init__(self, set_cookies, content_type="text/html", body=""):
        self.headers = _CookieHdrs(set_cookies)
        self.content_type = content_type
        self._body = body

    async def text(self, *a, **k):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _CookieSession:
    def __init__(self, set_cookies):
        self._sc = set_cookies

    def get(self, url, **kw):
        return _CookieResp(self._sc)


async def _cookie_findings(set_cookies, url="https://h/login"):
    from heaven.vulnscan.misconfig_scanner import _check_cookies_and_jwt
    out = await _check_cookies_and_jwt(_CookieSession(set_cookies), url)
    return [f for f in out if f["vuln_type"] == "insecure_cookie"]


async def test_cookie_value_flag_words_do_not_mask_missing_attributes():
    out = await _cookie_findings(
        ["sessionid=secure_httponly_samesite_tok_abcdef; Path=/"])
    assert len(out) == 1
    assert set(out[0]["evidence"]["missing_flags"]) == {"HttpOnly", "Secure", "SameSite"}


async def test_cookie_logout_deletion_not_flagged():
    out = await _cookie_findings(
        ["PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:00 GMT; Path=/"])
    assert out == []


async def test_cookie_max_age_zero_clear_not_flagged():
    out = await _cookie_findings(["sessionid=; Max-Age=0; Path=/"])
    assert out == []


async def test_cookie_fully_secured_not_flagged():
    out = await _cookie_findings(
        ["sessionid=abcdef0123456789; Secure; HttpOnly; SameSite=Strict; Path=/"])
    assert out == []

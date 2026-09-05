"""Docker-free unit tests for the spec-driven API discovery + excessive-data
detector added to ``heaven/vulnscan/api_scanner.py``.

These drive the REAL detectors through a fake GET session (no live server, no
Docker), so the precision guards are locked in in normal CI. The live proof that
the same detectors fire against a genuinely-vulnerable third-party API (VAmPI)
lives in ``tests/benchmarks/test_domain_labs.py::test_vampi_lab_detects_api_flaws``.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("aiohttp")

from heaven.vulnscan.api_scanner import RESTAPIScanner, _is_placeholder_value


class _Resp:
    def __init__(self, body, status: int = 200, ctype: str = "application/json"):
        self._body = body if isinstance(body, str) else json.dumps(body)
        self.status = status
        self.headers = {"Content-Type": ctype}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def text(self):
        return self._body


class _GetSession:
    """Maps a URL path to a fixed response; any unmapped path 404s. Models a
    GET-only REST surface, mirroring aiohttp's ``session.get(...)`` context
    manager well enough for the detectors under test."""

    def __init__(self, routes: dict):
        self._routes = routes

    def get(self, endpoint, timeout=None, headers=None):
        from urllib.parse import urlsplit
        path = urlsplit(endpoint).path
        resp = self._routes.get(path)
        if resp is None:
            return _Resp({"error": "not found"}, status=404)
        return resp


def _run(coro):
    return asyncio.run(coro)


# ── the placeholder guard ────────────────────────────────────────────────────
def test_is_placeholder_value_guards() -> None:
    for empty in ("", "   ", "string", "password", "secret", "token"):
        assert _is_placeholder_value(empty) is True
    for sample in ("your-api-key", "changeme", "example-secret", "<redacted>"):
        assert _is_placeholder_value(sample) is True
    # A real (even short) secret is NOT a placeholder.
    for real in ("pass1", "hunter2", "S3cr3t!"):
        assert _is_placeholder_value(real) is False


# ── excessive-data-exposure detector ─────────────────────────────────────────
def test_excessive_data_fires_on_record_password_leak() -> None:
    routes = {"/users/v1/_debug": _Resp({"users": [
        {"username": "name1", "email": "a@b.c", "password": "pass1"},
        {"username": "admin", "email": "x@y.z", "password": "pass2"},
    ]})}
    out = _run(RESTAPIScanner.test_excessive_data_exposure(
        _GetSession(routes), "http://t", ["/users/v1/_debug"]))
    assert len(out) == 1
    f = out[0]
    assert f.vuln_type == "excessive_data_exposure"
    assert f.severity == "high"
    assert f.evidence["leaked_field"] == "password"
    assert f.evidence["records_with_credential"] == 2
    assert f.owasp_api.startswith("API3")
    assert f.cwe == "CWE-359"


def test_excessive_data_ignores_placeholder_password() -> None:
    # A documented sample value must not be reported as a live leak.
    routes = {"/u": _Resp({"users": [{"username": "a", "password": "string"}]})}
    out = _run(RESTAPIScanner.test_excessive_data_exposure(
        _GetSession(routes), "http://t", ["/u"]))
    assert out == []


def test_excessive_data_requires_identity_key() -> None:
    # A lone credential with no subject (a config value) is not a record leak;
    # api_key_leakage covers that surface, not this one.
    routes = {"/c": _Resp({"client_secret": "abc123def456ghi789"})}
    out = _run(RESTAPIScanner.test_excessive_data_exposure(
        _GetSession(routes), "http://t", ["/c"]))
    assert out == []


def test_excessive_data_key_match_is_exact() -> None:
    # "password_required" is a policy flag, NOT a credential key: must not match.
    routes = {"/s": _Resp({"id": 1, "username": "a", "password_required": True})}
    out = _run(RESTAPIScanner.test_excessive_data_exposure(
        _GetSession(routes), "http://t", ["/s"]))
    assert out == []


def test_excessive_data_skips_non_json() -> None:
    routes = {"/h": _Resp("<html>password: hunter2</html>", ctype="text/html")}
    out = _run(RESTAPIScanner.test_excessive_data_exposure(
        _GetSession(routes), "http://t", ["/h"]))
    assert out == []


# ── spec-driven endpoint discovery ───────────────────────────────────────────
def test_discover_spec_endpoints_parses_openapi() -> None:
    spec = {"openapi": "3.0.1", "info": {"title": "t", "version": "1"},
            "paths": {
                "/users/v1": {"get": {}},
                "/users/v1/_debug": {"get": {}},
                "/users/v1/{username}": {"get": {}, "delete": {}},
                "/books/v1": {"get": {}, "post": {}},
                "/login": {"post": {}},
            }}
    paths = _run(RESTAPIScanner.discover_spec_endpoints(
        _GetSession({"/openapi.json": _Resp(spec)}), "http://t"))
    assert "/users/v1" in paths
    assert "/users/v1/_debug" in paths
    assert "/books/v1" in paths                    # GET present -> kept
    assert "/users/v1/{username}" not in paths     # path param -> excluded
    assert "/login" not in paths                   # POST-only -> excluded


def test_discover_spec_endpoints_empty_without_spec() -> None:
    paths = _run(RESTAPIScanner.discover_spec_endpoints(
        _GetSession({}), "http://t"))
    assert paths == []


def test_broken_auth_probes_spec_discovered_path() -> None:
    # /users/v1 is NOT in the hard-coded _PROTECTED_COLLECTIONS: it is only
    # reachable because spec discovery passes it as extra_paths.
    routes = {"/users/v1": _Resp({"users": [
        {"username": "a", "email": "a@b.c"},
        {"username": "b", "email": "b@c.d"},
        {"username": "c", "email": "c@d.e"}]})}
    session = _GetSession(routes)
    without = _run(RESTAPIScanner.test_broken_authentication(session, "http://t"))
    assert without == []  # conventional paths all 404
    withspec = _run(RESTAPIScanner.test_broken_authentication(
        session, "http://t", extra_paths=["/users/v1"]))
    assert len(withspec) == 1
    assert withspec[0].vuln_type == "api_broken_auth"

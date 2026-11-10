"""Authenticated-scan depth for SPAs/APIs: bearer tokens + JSON/API login.

All tests avoid the network (and local binding) with a fake aiohttp
ClientSession, so they run in the Claude sandbox as well as on CI.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("aiohttp")

from heaven.recon import auth_session as A  # noqa: E402


# ── spec parsing ────────────────────────────────────────────────────────────

def test_parse_token_spec_needs_no_url_or_creds():
    spec = A.parse_auth_string("token=abc.def.ghi")
    assert spec["token"] == "abc.def.ghi"
    assert spec["token_scheme"] == "Bearer"


def test_parse_header_spec():
    spec = A.parse_auth_string("header=X-API-Key: secret123")
    assert spec["header"] == "X-API-Key: secret123"


def test_parse_json_login_spec():
    spec = A.parse_auth_string(
        "login_json=1,url=/api/login,user=admin,pass=pw,token_json=data.access_token")
    assert spec["login_json"] == "1"
    assert spec["token_json"] == "data.access_token"
    assert spec["username_field"] == "username"


def test_parse_form_spec_still_requires_url_and_creds():
    with pytest.raises(ValueError):
        A.parse_auth_string("user=admin,pass=pw")  # no url, no token
    with pytest.raises(ValueError):
        A.parse_auth_string("url=/login,user=admin")  # no pass


# ── token / header sessions (no network) ────────────────────────────────────

def test_build_token_session_sets_bearer_header():
    sess = A.build_token_session(A.parse_auth_string("token=JWT123"))
    assert sess.headers["Authorization"] == "Bearer JWT123"
    assert sess.label.startswith("token:")


def test_build_token_session_custom_scheme():
    sess = A.build_token_session(A.parse_auth_string("token=T,token_scheme=Token"))
    assert sess.headers["Authorization"] == "Token T"


def test_build_token_session_api_key_header_and_cookies():
    sess = A.build_token_session(
        A.parse_auth_string("header=X-API-Key: k9,cookies=security=low"))
    assert sess.headers["X-API-Key"] == "k9"
    assert sess.cookies["security"] == "low"


def test_build_token_session_requires_something():
    with pytest.raises(ValueError):
        A.build_token_session({"token_scheme": "Bearer"})


def test_token_session_flows_into_aiohttp_kwargs():
    """A token session must put the Authorization header on every request."""
    A.set_active_session(A.build_token_session(A.parse_auth_string("token=XYZ")))
    try:
        kw = A.aiohttp_session_kwargs()
        assert kw.get("headers", {}).get("Authorization") == "Bearer XYZ"
    finally:
        A.clear_active_session()


# ── JSON path extraction ────────────────────────────────────────────────────

def test_extract_json_path_nested_and_flat():
    assert A._extract_json_path({"access_token": "a"}, "access_token") == "a"
    assert A._extract_json_path({"data": {"token": "b"}}, "data.token") == "b"
    assert A._extract_json_path({"data": {}}, "data.token") == ""
    assert A._extract_json_path({"n": 7}, "n") == "7"
    assert A._extract_json_path(["x"], "0") == ""  # lists not walked


# ── fake aiohttp for JSON login ─────────────────────────────────────────────

class _FakeJsonResp:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeClientSession:
    def __init__(self, status, payload, captured):
        self._resp = _FakeJsonResp(status, payload)
        self._captured = captured

    def post(self, url, json=None, allow_redirects=True, timeout=None):
        self._captured["url"] = url
        self._captured["json"] = json
        return self._resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _patch_session(monkeypatch, status, payload, captured):
    monkeypatch.setattr(A.aiohttp, "ClientSession",
                        lambda *a, **k: _FakeClientSession(status, payload, captured))


def test_json_login_extracts_default_token(monkeypatch):
    captured: dict = {}
    _patch_session(monkeypatch, 200, {"access_token": "TOK42"}, captured)
    spec = A.parse_auth_string("login_json=1,url=/api/login,user=admin,pass=pw")
    sess = asyncio.run(A.perform_json_login("http://api.example.com", spec))
    assert sess.headers["Authorization"] == "Bearer TOK42"
    # Login URL resolved against the base; creds posted as JSON.
    assert captured["url"] == "http://api.example.com/api/login"
    assert captured["json"] == {"username": "admin", "password": "pw"}


def test_json_login_honours_token_json_path(monkeypatch):
    captured: dict = {}
    _patch_session(monkeypatch, 200, {"data": {"jwt": "NESTED"}}, captured)
    spec = A.parse_auth_string(
        "login_json=1,url=/login,user=u,pass=p,token_json=data.jwt")
    sess = asyncio.run(A.perform_json_login("http://api.example.com", spec))
    assert sess.headers["Authorization"] == "Bearer NESTED"


def test_json_login_raises_when_no_token(monkeypatch):
    captured: dict = {}
    _patch_session(monkeypatch, 200, {"nope": 1}, captured)
    spec = A.parse_auth_string("login_json=1,url=/login,user=u,pass=p")
    with pytest.raises(RuntimeError):
        asyncio.run(A.perform_json_login("http://api.example.com", spec))


def test_json_login_raises_on_http_error(monkeypatch):
    captured: dict = {}
    _patch_session(monkeypatch, 401, {"error": "bad creds"}, captured)
    spec = A.parse_auth_string("login_json=1,url=/login,user=u,pass=p")
    with pytest.raises(RuntimeError):
        asyncio.run(A.perform_json_login("http://api.example.com", spec))


# ── dispatch + refresh ──────────────────────────────────────────────────────

def test_establish_dispatches_token_without_network():
    spec = A.parse_auth_string("token=QQQ")
    sess = asyncio.run(A.establish_auth_session("http://x", spec))
    assert sess.headers["Authorization"] == "Bearer QQQ"


def test_establish_dispatches_json(monkeypatch):
    captured: dict = {}
    _patch_session(monkeypatch, 200, {"token": "J"}, captured)
    spec = A.parse_auth_string("login_json=1,url=/l,user=u,pass=p")
    sess = asyncio.run(A.establish_auth_session("http://x", spec))
    assert sess.headers["Authorization"] == "Bearer J"


def test_refresh_redispatches_json_for_fresh_token(monkeypatch):
    """A remembered JSON login refreshes to a NEW token mid-scan."""
    captured: dict = {}
    _patch_session(monkeypatch, 200, {"token": "FRESH"}, captured)
    spec = A.parse_auth_string("login_json=1,url=/l,user=u,pass=p")
    A.remember_login("http://x", spec)
    try:
        ok = asyncio.run(A.refresh_active_session())
        assert ok is True
        assert A.get_active_session().headers["Authorization"] == "Bearer FRESH"
    finally:
        A.clear_active_session()


def test_session_looks_expired_recognises_api_token_failures():
    assert A.session_looks_expired('{"detail":"Token expired"}') is True
    assert A.session_looks_expired('{"detail":"Invalid token"}') is True
    assert A.session_looks_expired(
        '{"detail":"Authentication credentials were not provided."}') is True
    assert A.session_looks_expired("just some html", status=200) is False
    assert A.session_looks_expired("", status=401) is True

"""advanced_attacks: JWT alg=none and default-credential redirect precision.

Two false-positive classes closed here:

1. ``JWTAttacker.test_jwt_vulnerabilities`` used to flag a critical
   ``jwt_none_algorithm`` purely because the alg=none forgery returned 200. A
   public (or token-agnostic) endpoint returns 200 for *any* token, so that
   fabricated a critical. The check now requires an asymmetry: a
   broken-signature token is REJECTED while the alg=none forgery is ACCEPTED.

2. ``CredentialSprayer.spray_web_login`` compared the full ``Location`` string
   against the known-bad-credential baseline, so a failed login bouncing to
   ``/home?error=1`` vs a (still failed) attempt landing on ``/home?locked=1``
   looked "different" and was flagged as a default-credential hit. It now
   compares the landing PATH, not the query string.
"""
from __future__ import annotations

import asyncio
import base64
import json

from heaven.vulnscan.advanced_attacks import CredentialSprayer, JWTAttacker


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


_TOKEN = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': '1', 'role': 'user'})}.origsig"


# ── JWT alg=none fake session ────────────────────────────────────────────────

class _JwtResp:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body


class _JwtSession:
    """Responds to a bearer token via a handler(token_sig) -> (status, body)."""

    def __init__(self, handler):
        self._h = handler

    def get(self, url, headers=None, timeout=None):
        auth = (headers or {}).get("Authorization", "")
        tok = auth.split(" ", 1)[1] if " " in auth else auth
        sig = tok.split(".")[2] if tok.count(".") == 2 else "?"
        status, body = self._h(sig)
        return _JwtResp(status, body)


def _run(coro):
    return asyncio.run(coro)


def test_jwt_none_flagged_only_when_tampered_is_rejected():
    # alg=none forgery has an EMPTY signature; the tampered baseline has a
    # random one. Server rejects the random signature but accepts alg=none.
    def handler(sig: str):
        return (200, "welcome admin") if sig == "" else (401, "invalid signature")

    out = _run(JWTAttacker.test_jwt_vulnerabilities(_JwtSession(handler), "https://t/api", _TOKEN))
    assert any(f.vuln_type == "jwt_none_algorithm" for f in out), out


def test_jwt_none_suppressed_when_endpoint_accepts_any_token():
    # Public / token-agnostic endpoint: 200 for EVERYTHING, including the
    # broken-signature baseline -> the 200 to alg=none proves nothing.
    out = _run(JWTAttacker.test_jwt_vulnerabilities(
        _JwtSession(lambda sig: (200, "ok")), "https://t/api", _TOKEN))
    assert [f for f in out if f.vuln_type == "jwt_none_algorithm"] == []


def test_jwt_none_suppressed_when_none_is_rejected():
    def handler(sig: str):
        return (401, "nope") if sig == "" else (401, "nope")

    out = _run(JWTAttacker.test_jwt_vulnerabilities(_JwtSession(handler), "https://t/api", _TOKEN))
    assert [f for f in out if f.vuln_type == "jwt_none_algorithm"] == []


def test_jwt_none_suppressed_when_200_body_signals_rejection():
    # 200 but the body says the token was invalid (soft rejection).
    def handler(sig: str):
        return (200, "invalid token") if sig == "" else (401, "nope")

    out = _run(JWTAttacker.test_jwt_vulnerabilities(_JwtSession(handler), "https://t/api", _TOKEN))
    assert [f for f in out if f.vuln_type == "jwt_none_algorithm"] == []


# ── Credential-spray redirect fake session ───────────────────────────────────

class _PostResp:
    def __init__(self, status: int, location: str, body: str):
        self.status = status
        self.headers = {"Location": location} if location else {}
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body


class _PostSession:
    def __init__(self, handler):
        self._h = handler

    def post(self, url, data=None, timeout=None, allow_redirects=True):
        status, location, body = self._h(data or {})
        return _PostResp(status, location, body)


def test_spray_suppresses_same_path_different_query_redirect():
    # Baseline (bad cred) -> /home?error=1. A still-failed attempt that merely
    # lands on /home?locked=1 differs only by query string and must NOT be a hit.
    def handler(data: dict):
        user = data.get("username", "")
        if user == "admin":
            return (302, "/home?locked=1", "")
        return (302, "/home?error=1", "")

    out = _run(CredentialSprayer.spray_web_login(_PostSession(handler), "https://t/login"))
    assert out == [], out


def test_spray_still_flags_distinct_authed_landing_path():
    # A genuine login lands on a DIFFERENT path (/dashboard) than the baseline.
    def handler(data: dict):
        user = data.get("username", "")
        if user == "tomcat":
            return (302, "/dashboard", "")
        return (302, "/login?error=1", "")

    out = _run(CredentialSprayer.spray_web_login(_PostSession(handler), "https://t/login"))
    assert len(out) == 1 and out[0].vuln_type == "default_credentials", out

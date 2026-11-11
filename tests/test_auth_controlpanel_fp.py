"""auth_scanner: a control-panel login must not become a bogus critical.

Live regression (engagement real-world audit, certifiedhacker.com cPanel/WHM/
Webmail on :2083/:2087/:2096): the credential-spray read a **401 Unauthorized**
as a successful login and stored three CRITICAL ``weak_login_credentials``
findings titled "Login successful with credentials admin:Password1" — on a 401.
cPanel answers every bad credential with ``401`` + its login page, whose body
carries "account"/"welcome" (so the keyword heuristic fired) and a per-request
token that jitters the length by >300 bytes (so the length baseline fired too).

Two gaps, both closed here:

1. An auth-challenge status (401/403) is a FAILED login and can never be a
   success, and a response that still renders a password field is still a login
   form — neither is "logged in".
2. ``no_account_lockout`` must not be asserted when every attempt returned an
   auth-challenge (we never saw the endpoint process a login normally, so its
   throttling behaviour is unobserved): that is inconclusive, not "no lockout".

A genuine weak credential (a 200/redirect to an authenticated page with no
password field) still fires, and a genuinely unthrottled normal login form still
yields ``no_account_lockout`` — recall is preserved.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import auth_scanner

pytest.importorskip("aiohttp")

_LOGIN_FORM = [{"action": "https://cp.example.com/login/",
                "fields": [{"name": "user"}, {"name": "pass"}]}]


class _Resp:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body
        self.headers: dict = {}
        self.url = "https://cp.example.com/login/"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body


class _Session:
    """Minimal aiohttp-style session driven by a responder(method, data)->_Resp."""

    def __init__(self, responder):
        self._responder = responder

    def get(self, url, **kw):
        return self._responder("GET", {})

    def post(self, url, data=None, **kw):
        return self._responder("POST", data or {})


def _run(responder) -> list[dict]:
    return asyncio.run(
        auth_scanner._brute_login_form(_Session(responder),
                                       "https://cp.example.com/login/", _LOGIN_FORM))


# ── the FP: a cPanel-style blanket 401 ───────────────────────────────────────

def test_cpanel_style_401_is_not_a_successful_login():
    calls = {"n": 0}

    def responder(method, data):
        calls["n"] += 1
        # cPanel login page: the success keywords AND a password field are present,
        # plus a per-request nonce so the length jitters >300 bytes between probes
        # (exactly what used to defeat the length baseline).
        nonce = "x" * (320 + calls["n"] * 9)
        body = ('<!DOCTYPE html><title>cPanel Login</title>'
                '<input type="password" name="pass">'
                f'<span>welcome · account</span><!-- {nonce} -->')
        return _Resp(401, body)

    out = _run(responder)
    types = [f["vuln_type"] for f in out]
    assert "weak_login_credentials" not in types, (
        "a 401 is a FAILED login and must never be reported as weak credentials; "
        f"got {types}")
    # Uniform 401s mean the throttling behaviour was never observed → inconclusive,
    # not a confident "no account lockout".
    assert "no_account_lockout" not in types, types
    assert "lockout_inconclusive" in types, types


# ── recall: a genuine weak credential still fires ────────────────────────────

def test_real_weak_credential_still_detected():
    def responder(method, data):
        pw = '<input type="password" name="pass">'
        if method == "GET":
            return _Resp(200, "login " + pw)
        if str(data.get("user", "")).startswith("nosuchu"):   # bad-cred baseline
            return _Resp(200, "<form>please sign in " + pw + "</form>")
        # any guessed credential "works" → authenticated dashboard, no password field
        body = "<h1>Dashboard</h1> welcome — logout — my account " + "d" * 2000
        return _Resp(200, body)

    out = _run(responder)
    assert any(f["vuln_type"] == "weak_login_credentials" for f in out), (
        "a real authenticated response (200, no login form) must still be caught")


# ── recall: a genuinely unthrottled normal login still flags no-lockout ───────

def test_unthrottled_normal_login_still_flags_no_lockout():
    def responder(method, data):
        pw = '<input type="password" name="pass">'
        # Every attempt re-renders the SAME 200 login form with no success markers:
        # a normal, unthrottled login the detector should still flag.
        return _Resp(200, "<form>please sign in " + pw + "</form>")

    out = _run(responder)
    types = [f["vuln_type"] for f in out]
    assert "no_account_lockout" in types, types
    assert "weak_login_credentials" not in types, types

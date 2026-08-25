"""GET-based CSRF detection (heaven/vulnscan/auth_scanner._audit_csrf).

A GET form that changes server state (the classic "password change over GET",
DVWA's low-difficulty CSRF, trivially forgeable via a bare <img src>) is a real
CSRF hole. The auditor used to skip every GET form and so missed it. These tests
pin the new behaviour AND the false-positive guard: an ordinary search GET form
must never be flagged.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import auth_scanner


class _FakeResp:
    """Minimal aiohttp-response stand-in for the no-token meta/header re-check."""

    def __init__(self, body="<html><body>no csrf here</body></html>", headers=None):
        self._body = body
        self.headers = headers or {}

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, resp=None):
        self._resp = resp or _FakeResp()

    def get(self, *a, **k):
        return self._resp


def _csrf(forms, session=None):
    return asyncio.run(
        auth_scanner._audit_csrf(session or _FakeSession(), "http://t/", forms)
    )


def _dvwa_get_password_form():
    # DVWA low CSRF: password change accepted over GET, no anti-CSRF token.
    return {
        "action": "http://t/vulnerabilities/csrf/",
        "method": "GET",
        "fields": [
            {"name": "password_new", "type": "password"},
            {"name": "password_conf", "type": "password"},
            {"name": "Change", "type": "submit"},
        ],
    }


def test_get_password_change_form_is_flagged():
    findings = _csrf([_dvwa_get_password_form()])
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "csrf_missing_token"
    assert "GET" in f["title"]
    assert f["severity"] == "high"


def test_ordinary_search_get_form_is_not_flagged():
    # The false-positive guard: a search box is a GET form with no state change.
    search = {
        "action": "http://t/search",
        "method": "GET",
        "fields": [
            {"name": "q", "type": "text"},
            {"name": "sort", "type": "text"},
            {"name": "page", "type": "text"},
        ],
    }
    assert _csrf([search]) == []


def test_get_form_with_csrf_token_is_not_flagged():
    form = _dvwa_get_password_form()
    form["fields"].append({"name": "user_token", "type": "hidden"})
    assert _csrf([form]) == []


def test_post_state_changing_form_still_flagged():
    # Regression: the original POST behaviour is unchanged.
    post = {
        "action": "http://t/account/update",
        "method": "POST",
        "fields": [{"name": "email", "type": "text"}],
    }
    findings = _csrf([post])
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "csrf_missing_token"


def test_state_changing_helper_is_conservative():
    # Direct unit check on the gate: password type and mutation names in, plain
    # search/navigation fields out.
    scg = auth_scanner._get_form_is_state_changing
    assert scg([{"name": "password_new", "type": "password"}], "/x")
    assert scg([{"name": "delete_id", "type": "text"}], "/x")
    assert scg([{"name": "new_email", "type": "text"}], "/x")
    assert not scg([{"name": "q", "type": "text"}], "/search")
    assert not scg([{"name": "sort", "type": "text"}], "/list")
    assert not scg([], "/anything")


def test_login_form_is_not_flagged_as_csrf():
    # A GET login form (user identifier + password) is authentication, not a
    # CSRF state change — flagging it would be a false positive (login CSRF is a
    # separate, lower class). This is DVWA's /vulnerabilities/brute/ shape.
    login = {
        "action": "http://t/vulnerabilities/brute/",
        "method": "GET",
        "fields": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
            {"name": "Login", "type": "submit"},
        ],
    }
    assert _csrf([login]) == []
    assert not auth_scanner._get_form_is_state_changing(login["fields"], login["action"])


def test_audit_csrf_accepts_inputs_key():
    # Crawler-produced forms carry their fields under "inputs"; the auditor must
    # read them too (this was the wiring gap that silently dropped every form).
    form = {
        "action": "http://t/vulnerabilities/csrf/",
        "method": "GET",
        "inputs": [
            {"name": "password_new", "type": "password"},
            {"name": "password_conf", "type": "password"},
        ],
    }
    findings = _csrf([form])
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "csrf_missing_token"

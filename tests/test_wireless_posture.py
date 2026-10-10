"""Tests for the wireless-infrastructure posture review (heaven.recon.wireless_posture).

No live HTTP: a fake aiohttp-style session feeds crafted responses into
``_probe_host`` so the vendor fingerprint and the login-form vs no-login
severity split are exercised deterministically.
"""
from __future__ import annotations

import asyncio

from heaven.recon import wireless_posture as wp


class _FakeResp:
    def __init__(self, status: int, headers: dict, body: str):
        self.status = status
        self.headers = headers
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="ignore"):
        return self._body


class _FakeSession:
    """Returns one response for every GET (the first probed port matches, so
    ``_probe_host`` stops after it)."""

    def __init__(self, resp: _FakeResp):
        self._resp = resp

    def get(self, url, **kwargs):
        return self._resp


def _probe(resp: _FakeResp):
    return asyncio.run(wp._probe_host(_FakeSession(resp), "10.0.0.5"))


def test_login_form_at_200_is_exposure_not_unauthenticated():
    # A vendor-fingerprinted panel that serves a login form at 200 enforces
    # authentication: it is an exposure (medium), never an unauthenticated-admin
    # high. Routers almost all return their login page with a 200.
    body = ("<html><head><title>TP-Link Wireless Router</title></head>"
            "<body><form action='/login'>"
            "<input type='password' name='pwd'></form></body></html>")
    findings = _probe(_FakeResp(200, {"Server": "GoAhead"}, body))
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "wireless_mgmt_exposed"
    assert findings[0]["severity"] == "medium"


def test_no_login_admin_landing_at_200_is_unauthenticated_high():
    # The management UI landing page with no login form is the genuine
    # unauthenticated-admin case (matches the live RouterOS webfig lab decoy).
    body = ("<html><head><title>RouterOS router configuration page</title></head>"
            "<body><h1>MikroTik RouterOS</h1>"
            "<p>Welcome to RouterOS webfig management interface.</p></body></html>")
    findings = _probe(_FakeResp(200, {"Server": "nginx"}, body))
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "wireless_mgmt_unauthenticated"
    assert findings[0]["severity"] == "high"


def test_401_with_vendor_is_exposure_medium():
    body = "<html><title>UniFi Network</title></html>"
    findings = _probe(_FakeResp(401, {"WWW-Authenticate": "Basic realm=UniFi"}, body))
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "wireless_mgmt_exposed"
    assert findings[0]["severity"] == "medium"


def test_non_wireless_200_is_not_flagged():
    body = "<html><title>Welcome to nginx</title><form><input type='password'></form></html>"
    findings = _probe(_FakeResp(200, {"Server": "nginx"}, body))
    assert findings == []


def test_serves_login_form_helper():
    assert wp._serves_login_form('<input type="password">')
    assert wp._serves_login_form("<form>login here</form>")
    assert not wp._serves_login_form("<h1>welcome to the dashboard</h1>")

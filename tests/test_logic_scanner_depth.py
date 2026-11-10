"""Business-logic depth: mass assignment + password-reset host poisoning.

Two layers:
  * direct-call unit tests with a tiny fake aiohttp session (no local bind, so
    they run everywhere, including the Claude sandbox), driving the audit
    functions deterministically; and
  * real-server integration tests through ``scan_business_logic`` (need local
    binding; they pass on CI / a normal machine).
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("aiohttp")

from aiohttp import web  # noqa: E402

from heaven.vulnscan import logic_scanner as ls  # noqa: E402
from heaven.vulnscan.logic_scanner import scan_business_logic  # noqa: E402


# ── fake session (no network, no bind) ──────────────────────────────────────

class _FakeResp:
    def __init__(self, status: int, body: str, headers: dict | None = None):
        self.status = status
        self._body = body.encode("utf-8")
        self.headers = headers or {}
        self.content = self

    async def read(self, _n: int = -1) -> bytes:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


class _FakeSession:
    """Drives the audit via a handler(method, url, data, headers) -> (status, body)."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[dict] = []

    def post(self, url, data=None, headers=None, allow_redirects=False, timeout=None):
        self.calls.append({"method": "POST", "url": url, "data": data, "headers": headers})
        status, body = self.handler("POST", url, data, headers)
        return _FakeResp(status, body)

    def get(self, url, allow_redirects=False, timeout=None, headers=None):
        self.calls.append({"method": "GET", "url": url, "headers": headers})
        status, body = self.handler("GET", url, None, headers)
        return _FakeResp(status, body)


def _form(action: str, *names: str) -> dict:
    return {"action": action, "fields": [{"name": n, "value": "x"} for n in names]}


# ── mass assignment ─────────────────────────────────────────────────────────

def test_mass_assignment_fires_on_bound_privileged_field():
    """Server echoes values of KNOWN field names (incl. privileged) but not an
    unknown control field → the differential proves binding."""
    def handler(method, url, data, headers):
        data = data or {}
        # Reflect values for known fields + privileged names; drop unknown ones
        # (the garbage control field name starts with heaven_ctl_).
        echoed = [v for k, v in data.items()
                  if not k.startswith("heaven_ctl_")]
        return 200, "RERENDER " + " ".join(echoed)
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_mass_assignment(sess, "http://t/acct", _form("/acct", "name")))
    assert out, "expected a mass-assignment finding"
    assert all(f["vuln_type"] == "mass_assignment" for f in out)
    assert any(f["evidence"]["parameter"] in ls._MASS_ASSIGN_FIELDS for f in out)
    assert out[0]["cwe"] == "CWE-915"


def test_mass_assignment_suppressed_when_server_echoes_everything():
    """A form that re-echoes EVERY input (control included) is not mass assignment."""
    def handler(method, url, data, headers):
        data = data or {}
        return 200, "RERENDER " + " ".join(str(v) for v in data.values())
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_mass_assignment(sess, "http://t/acct", _form("/acct", "name")))
    assert out == []


def test_mass_assignment_silent_when_nothing_reflected():
    def handler(method, url, data, headers):
        return 200, "<html>thanks</html>"
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_mass_assignment(sess, "http://t/acct", _form("/acct", "name")))
    assert out == []


def test_mass_assignment_skips_fields_form_already_has():
    """A privileged field the form already exposes is not mass assignment."""
    def handler(method, url, data, headers):
        return 200, "RERENDER " + " ".join(str(v) for v in (data or {}).values())
    sess = _FakeSession(handler)
    # Form already carries every privileged probe → nothing left to inject.
    out = asyncio.run(ls._audit_mass_assignment(
        sess, "http://t/acct", _form("/acct", *ls._MASS_ASSIGN_FIELDS)))
    assert out == []


# ── password-reset host poisoning ───────────────────────────────────────────

def test_reset_host_poisoning_fires_on_reflected_host():
    captured = {}

    def handler(method, url, data, headers):
        captured["data"] = data
        captured["headers"] = headers
        host = (headers or {}).get("X-Forwarded-Host", "")
        return 200, f"<p>If the account exists we emailed a reset link via {host}</p>"
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_reset_host_poisoning(
        sess, "http://t/forgot-password", _form("/forgot-password", "email")))
    assert out, "expected a host-poisoning finding"
    assert out[0]["vuln_type"] == "password_reset_host_poisoning"
    assert out[0]["cwe"] == "CWE-640"
    # The probe account is non-existent / non-routable — no real user emailed.
    assert captured["data"]["email"].endswith("@example.invalid")
    assert "heaven-noexist-" in captured["data"]["email"]


def test_reset_host_poisoning_silent_without_reflection():
    def handler(method, url, data, headers):
        return 200, "<p>If the account exists, we sent an email.</p>"
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_reset_host_poisoning(
        sess, "http://t/forgot-password", _form("/forgot-password", "email")))
    assert out == []


def test_reset_host_poisoning_skips_non_reset_form():
    def handler(method, url, data, headers):
        host = (headers or {}).get("X-Forwarded-Host", "")
        return 200, f"reflected {host}"  # would reflect, but form is not a reset
    sess = _FakeSession(handler)
    out = asyncio.run(ls._audit_reset_host_poisoning(
        sess, "http://t/contact", _form("/contact", "message")))
    assert out == []


def test_reset_host_poisoning_requires_email_field():
    def handler(method, url, data, headers):
        host = (headers or {}).get("X-Forwarded-Host", "")
        return 200, f"reflected {host}"
    sess = _FakeSession(handler)
    # Reset action but no email/user field to carry a safe probe account.
    out = asyncio.run(ls._audit_reset_host_poisoning(
        sess, "http://t/reset-password", _form("/reset-password", "csrf")))
    assert out == []


# ── real-server integration (needs local binding; passes on CI) ─────────────

async def _serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


@pytest.mark.asyncio
async def test_mass_assignment_end_to_end():
    async def profile(request):
        posted = await request.post()
        # A framework that binds every field onto the model and re-renders known
        # attributes, but silently drops field names it does not recognise.
        known = {"name", *ls._MASS_ASSIGN_FIELDS}
        echoed = " ".join(str(v) for k, v in posted.items() if k in known)
        return web.Response(text=f"<html>profile {echoed}</html>")

    app = web.Application()
    app.router.add_post("/profile", profile)
    runner, base = await _serve(app)
    try:
        forms = {base + "/profile": [_form(base + "/profile", "name")]}
        res = await scan_business_logic([base + "/profile"], forms_by_url=forms)
        types = {f["vuln_type"] for f in res["findings"]}
        assert "mass_assignment" in types
    finally:
        await runner.cleanup()

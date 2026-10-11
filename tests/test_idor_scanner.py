"""Tests for the IDOR scanner's dual-session horizontal-privesc precision.

The dual-session check must only fire on an access-controlled resource: two
authenticated users seeing the same object is IDOR only when an anonymous client
is denied. A public/shared ID-bearing endpoint (a catalog item) is served
identically to everyone and must NOT raise a critical false positive.

Responses are scripted per Authorization header via a fake aiohttp-style session,
so no live HTTP is needed.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan.idor_scanner import IDORScanner


class _Resp:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="replace"):
        return self._body


class _Session:
    """Returns a scripted (status, body) keyed by the Authorization header
    ('A', 'B', or '' for anonymous)."""

    def __init__(self, by_auth: dict):
        self._by_auth = by_auth

    def get(self, url, headers=None, **kwargs):
        auth = (headers or {}).get("Authorization", "")
        status, body = self._by_auth.get(auth, self._by_auth[""])
        return _Resp(status, body)


_URL = "http://target.example/account/123/statement"


def _scan(by_auth: dict):
    s = IDORScanner(auth_headers={"Authorization": "A"},
                    alt_auth_headers={"Authorization": "B"})
    asyncio.run(s._test_horizontal_privesc(_Session(by_auth), _URL))
    return s._findings


def test_horizontal_privesc_public_resource_is_not_flagged():
    # Every identity — including anonymous — sees the same body: a public/shared
    # object, not a broken-authorization finding.
    page = "<html>Public catalog item #123 — price $49.99 in stock</html>"
    findings = _scan({"A": (200, page), "B": (200, page), "": (200, page)})
    assert findings == []


def test_horizontal_privesc_access_controlled_resource_is_critical():
    # A and B (two users) see the same private statement, but anonymous is denied:
    # user B is reading user A's object → a genuine horizontal-privesc IDOR.
    private = "<html>Account 123 statement — balance $12,430.55, owner Jane Roe</html>"
    findings = _scan({
        "A": (200, private),
        "B": (200, private),
        "": (401, "<html>401 Unauthorized</html>"),
    })
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["vuln_type"] == "idor"
    assert findings[0]["evidence"]["anonymous_status"] == 401


def test_horizontal_privesc_requires_alt_token():
    s = IDORScanner(auth_headers={"Authorization": "A"})  # no alt token
    asyncio.run(s._test_horizontal_privesc(_Session({"": (200, "x" * 80)}), _URL))
    assert s._findings == []


# ── Unauthenticated-access check: structured-record gate, not a footer email ──

def _scan_unauth(by_auth: dict):
    s = IDORScanner(auth_headers={"Authorization": "A"})
    asyncio.run(s._test_unauth_access(_Session(by_auth), _URL))
    return s._findings


def test_unauth_access_public_page_with_footer_email_not_flagged():
    # A public id'd page returns the same body with or without auth (auth is
    # irrelevant to it) and carries only a site-wide contact email in its footer.
    # A bare email is page furniture, not a protected record: no critical finding.
    page = ("<html><body>Public catalog item #123 — in stock."
            "<footer>Contact us: hello@shop.example</footer></body></html>")
    findings = _scan_unauth({"A": (200, page), "": (200, page)})
    assert findings == [], findings


def test_unauth_access_protected_record_still_flagged():
    # The same body with and without auth, but it is a structured data record
    # (a JSON user object) — a genuine broken-authentication exposure.
    record = ('{"account":123,"first_name":"Jane","last_name":"Roe",'
              '"balance":"12430.55"}')
    findings = _scan_unauth({"A": (200, record), "": (200, record)})
    assert len(findings) == 1, findings
    assert findings[0]["severity"] == "critical"
    assert findings[0]["vuln_type"] == "idor"
    assert findings[0]["evidence"]["probe_type"] == "unauth_access"

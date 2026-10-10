"""auth_scanner WSTG surrogates must not attribute an external IdP to the target.

``_audit_wstg_surrogates`` probes /register, /reset and /api/login style paths
and reports open-registration / security-question-reset / alternate-auth
findings against the in-scope origin. ``_get`` follows redirects, so a path that
30x-redirects to an external identity provider would get that provider's
registration/reset/auth posture mis-attributed to the target. The shared ``_get``
helper now returns the error sentinel on an off-site hop; a same-registered-
domain hop (apex -> www) stays in scope.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan.auth_scanner import _audit_wstg_surrogates

_REG_HTML = ('<html><form><input type="password" name="pw"> Register / '
             'create account</form></html>')


class _Resp:
    def __init__(self, url: str, body: str, status: int = 200, headers=None):
        self.url = url
        self._body = body
        self.status = status
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="replace"):
        return self._body


class _Session:
    def __init__(self, final_url: str, body: str):
        self._url = final_url
        self._body = body

    def get(self, u, **kw):
        return _Resp(self._url, self._body)


def _run(coro):
    return asyncio.run(coro)


def test_surrogates_suppressed_on_offsite_redirect():
    sess = _Session("https://signup.auth0.com/u/signup", _REG_HTML)
    out = _run(_audit_wstg_surrogates(sess, "https://target.example/"))
    assert out == [], out


def test_surrogates_same_site_still_flagged():
    sess = _Session("https://target.example/register", _REG_HTML)
    out = _run(_audit_wstg_surrogates(sess, "https://target.example/"))
    assert any(f["vuln_type"] == "open_registration" for f in out), out

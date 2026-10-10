"""Cookie-flag audit must not attribute another host's cookies to the target.

``_audit_cookies`` follows redirects and reads ``Set-Cookie`` from the FINAL
response. When the target 302s to an off-site SSO/CDN/parking host, those cookies
belong to that other server, so flagging their missing flags against the in-scope
target is a wrong-target false positive. The header audit already guards this with
``_same_site``; the cookie audit must apply the same guard. (A same-registered-
domain hop — apex↔www, http→https — is still the target and stays in scope.)
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import auth_scanner


class _Hdrs:
    def __init__(self, set_cookies):
        self._sc = list(set_cookies)

    def getall(self, key, default=None):
        if key.lower() == "set-cookie":
            return list(self._sc)
        return list(default) if default is not None else []


class _Resp:
    def __init__(self, url, set_cookies):
        self.url = url
        self.headers = _Hdrs(set_cookies)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return ""


class _Session:
    def __init__(self, resp):
        self._resp = resp

    def get(self, url, **kwargs):
        return self._resp


def _audit(final_url, cookies, requested):
    resp = _Resp(final_url, cookies)
    return asyncio.run(auth_scanner._audit_cookies(_Session(resp), requested))


def test_offsite_redirect_cookies_not_attributed_to_target():
    # app.example.com -> Microsoft SSO: the ESTSAUTH cookie is Microsoft's.
    out = _audit(
        "https://login.microsoftonline.com/common/oauth2/authorize",
        ["ESTSAUTH=xyz; Path=/"],  # no Secure / HttpOnly / SameSite
        "https://app.example.com/",
    )
    assert out == [], [f["vuln_type"] for f in out]


def test_same_registered_domain_hop_still_flagged():
    # example.com -> www.example.com is the SAME site: still audited.
    out = _audit(
        "https://www.example.com/home",
        ["sessionid=abcdef0123456789; Path=/"],  # missing all three flags
        "https://example.com/",
    )
    types = {f["vuln_type"] for f in out}
    assert "cookie_no_secure" in types
    assert "cookie_no_httponly" in types
    assert "cookie_no_samesite" in types

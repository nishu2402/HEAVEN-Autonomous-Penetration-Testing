"""misconfig_scanner header-derived checks must not describe another host.

``_check_security_headers`` / ``_check_server_banner`` / ``_check_clickjacking``
read the FINAL response's headers but anchor the finding to the requested origin.
When the target redirects to an off-site host (CDN / SSO / parking), those
headers belong to that host — attributing "missing CSP" or "Server: nginx/1.29"
to the target is a wrong-target false positive. These checks now apply the shared
``same_site`` guard (the same one auth_scanner uses). A same-registered-domain
hop (apex↔www) stays in scope.
"""
from __future__ import annotations

import asyncio

from multidict import CIMultiDict

from heaven.vulnscan import misconfig_scanner as MS


class _Resp:
    def __init__(self, url, headers, status=200, content_type="text/html"):
        self.url = url
        self.status = status
        self.content_type = content_type
        self.headers = CIMultiDict(headers)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, final_url, headers, status=200, content_type="text/html"):
        self._r = _Resp(final_url, headers, status, content_type)

    def get(self, *a, **k):
        return self._r


def _run(coro):
    return asyncio.run(coro)


# All three header-derived checks: off-site redirect → no finding.

def test_security_headers_skipped_on_offsite_redirect():
    sess = _Session("https://cdn.vendor-cdn.net/landing", {})  # zero sec headers
    out = _run(MS._check_security_headers(sess, "https://target.example/"))
    assert out == [], out


def test_server_banner_skipped_on_offsite_redirect():
    sess = _Session("https://parking.bluehost-cdn.net/x", {"Server": "nginx/1.29.1"})
    out = _run(MS._check_server_banner(sess, "https://target.example/"))
    assert out == [], out


def test_clickjacking_skipped_on_offsite_redirect():
    sess = _Session("https://login.microsoftonline.com/common", {})  # framable, but off-site
    out = _run(MS._check_clickjacking(sess, "https://target.example/"))
    assert out == [], out


# Same registered domain (apex→www) stays in scope and is still assessed.

def test_security_headers_same_registered_domain_still_flagged():
    sess = _Session("https://www.target.example/home", {})
    out = _run(MS._check_security_headers(sess, "https://target.example/"))
    assert any(f["vuln_type"] == "missing_security_headers" for f in out), out


def test_server_banner_same_registered_domain_still_flagged():
    sess = _Session("https://www.target.example/home", {"Server": "nginx/1.29.1"})
    out = _run(MS._check_server_banner(sess, "https://target.example/"))
    assert any(f["vuln_type"] == "server_version_disclosure" for f in out), out


# ── _check_login_form: a target whose /login redirects to an external IdP ──────
# (Okta / Azure AD / Auth0) must not get the IdP's autocomplete / cache posture.

class _BodyResp:
    def __init__(self, url, body, headers=None, status=200, content_type="text/html"):
        self.url = url
        self._body = body
        self.status = status
        self.content_type = content_type
        self.headers = CIMultiDict(headers or {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="replace"):
        return self._body


class _BodySession:
    def __init__(self, resp):
        self._r = resp

    def get(self, *a, **k):
        return self._r


_LOGIN_HTML = '<html><form><input type="password" name="pw"></form></html>'


def test_login_form_skipped_on_offsite_idp_redirect():
    # /login 302s to an external identity provider → not our posture to report.
    sess = _BodySession(_BodyResp("https://login.microsoftonline.com/common", _LOGIN_HTML))
    out = _run(MS._check_login_form(sess, "https://target.example/login"))
    assert out == [], out


def test_login_form_same_site_still_flagged():
    sess = _BodySession(_BodyResp("https://target.example/login", _LOGIN_HTML))
    out = _run(MS._check_login_form(sess, "https://target.example/login"))
    assert any(f["vuln_type"] == "password_autocomplete_enabled" for f in out), out

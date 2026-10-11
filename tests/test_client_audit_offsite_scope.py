"""client_audit must not attribute off-site content to the requested target.

``audit_url`` reads the delivered HTML/JS and anchors every finding (secrets in
comments, DOM-XSS sinks, Flash, XSSI) to the requested URL, but ``_fetch`` uses
``allow_redirects=True``. When the target 30x-redirects off its registered
domain (a CDN / SSO / parking host), the content belongs to that host, so
flagging a leaked AWS key against the in-scope target is a wrong-target false
positive. The fetch now applies the shared ``same_site`` guard; a
same-registered-domain hop (apex -> www) stays in scope.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import client_audit as C

_LEAKY = ('<html><!-- TODO remove hardcoded admin password="Sup3rSecret123" '
          'AKIAABCDEFGHIJKLMNOP --></html>')


class _Resp:
    def __init__(self, url: str, body: str, status: int = 200, ctype: str = "text/html"):
        self.url = url
        self._body = body
        self.status = status
        self.headers = {"Content-Type": ctype}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="replace"):
        return self._body


class _Session:
    def __init__(self, final_url: str, body: str):
        self._r = _Resp(final_url, body)

    def get(self, url, **kw):
        return self._r


class _NoUrlResp(_Resp):
    """A fake with no .url attribute (must fall back to the requested URL)."""

    def __init__(self, body: str):
        super().__init__("", body)
        del self.url


class _NoUrlSession:
    def __init__(self, body: str):
        self._r = _NoUrlResp(body)

    def get(self, url, **kw):
        return self._r


def _run(coro):
    return asyncio.run(coro)


def test_offsite_redirect_source_review_suppressed():
    sess = _Session("https://cdn.vendor-cdn.net/landing", _LEAKY)
    out = _run(C.audit_url(sess, "https://target.example/"))
    assert out == [], out


def test_same_registered_domain_still_reviewed():
    sess = _Session("https://www.target.example/home", _LEAKY)
    out = _run(C.audit_url(sess, "https://target.example/"))
    assert any(f["vuln_type"] == "source_comment_disclosure" for f in out), out


def test_missing_response_url_treated_as_same_site():
    # A fake/odd response with no .url must not suppress (falls back to request).
    out = _run(C.audit_url(_NoUrlSession(_LEAKY), "https://target.example/"))
    assert any(f["vuln_type"] == "source_comment_disclosure" for f in out), out


# ── password_assignment placeholder screening ─────────────────────────────────
# The value-bearing password/key pattern is the one secret rule loose enough to
# fire on a commented-out config *example*. A templated placeholder value must
# NOT raise a high-severity disclosure, while a real credential still does.

def test_templated_placeholder_credential_not_disclosed():
    # A commented-out example config with placeholder values is not a leak.
    for placeholder in (
        '<!-- api_key: "YOUR_API_KEY_HERE" -->',
        '<!-- password = "<your-password>" -->',
        '<!-- secret: "{{SESSION_SECRET}}" -->',
        '<!-- pwd = "xxxxxxxx" -->',
        '<!-- api-key="example-key-value" -->',
    ):
        out = C._review_source("https://target.example/", f"<html>{placeholder}</html>")
        assert out == [], (placeholder, out)


def test_real_weak_default_credential_still_disclosed():
    # Real shipped credentials, including weak defaults, must still fire high.
    for real in (
        '<!-- password = "Sup3rSecret123" -->',
        '<!-- password: "changeme" -->',
        '<!-- admin pwd="admin" -->',
    ):
        out = C._review_source("https://target.example/", f"<html>{real}</html>")
        assert any(f["vuln_type"] == "source_comment_disclosure"
                   and f["severity"] == "high" for f in out), (real, out)


def test_real_secret_next_to_placeholder_in_same_comment_still_caught():
    # A placeholder sitting beside a genuine credential must not mask it.
    html = ('<html><!-- sample: api_key="YOUR_KEY_HERE" ; '
            'live password="R3alP@ssw0rd!" --></html>')
    out = C._review_source("https://target.example/", html)
    assert any(f["vuln_type"] == "source_comment_disclosure"
               and f["severity"] == "high" for f in out), out

"""web_tech must not map an off-site redirect's headers to the target origin.

``_default_header_fetch`` follows redirects and returns the final response's
headers, which feed the EOL + CVE pipeline keyed on the requested origin. If the
target bounces off its registered domain (to a CDN / parking host), that host's
``Server`` / ``X-Powered-By`` version must not become the target's EOL/CVE
posture. A same-registered-domain hop (apex -> www) stays in scope.
"""
from __future__ import annotations

import asyncio

from heaven.recon.web_tech import _default_header_fetch


class _Resp:
    def __init__(self, url: str, headers: dict, status: int = 200):
        self.url = url
        self.status = status
        self._headers = headers

    @property
    def headers(self):
        return self._headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, resp: _Resp):
        self._r = resp

    def get(self, url, **kw):
        return self._r


def _run(coro):
    return asyncio.run(coro)


def test_offsite_redirect_headers_dropped():
    sess = _Session(_Resp("https://cdn.vendor-cdn.net/x", {"Server": "nginx/1.18.0"}))
    out = _run(_default_header_fetch(sess, "http://target.example/", 5.0))
    assert out is None, out


def test_same_registered_domain_headers_kept():
    sess = _Session(_Resp("http://www.target.example/", {"Server": "nginx/1.18.0"}))
    out = _run(_default_header_fetch(sess, "http://target.example/", 5.0))
    assert out is not None and out.get("Server") == "nginx/1.18.0", out

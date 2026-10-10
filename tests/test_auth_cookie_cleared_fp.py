"""Cookie-flag audit must not score a cookie that is being DELETED, and must read
the flags from the attribute section rather than from the cookie value.

``_audit_cookies`` used to:

* flag a session cookie whose value is under 16 chars as a HIGH "Short Session ID
  (brute-forceable)". But a logout response deletes the cookie with a sentinel
  value, not a live id: PHP emits ``Set-Cookie: PHPSESSID=deleted; expires=Thu,
  01-Jan-1970 …`` (``deleted`` is 7 chars), and other stacks use an empty value
  with ``Max-Age=0``. Scoring that produced a HIGH false positive on every logout.
* decide the Secure / HttpOnly / SameSite flags with ``"secure" not in raw.lower()``
  over the WHOLE header, so a cookie whose value merely contained one of those
  words was mistaken for having the flag set, silently dropping a real finding.

Both are pinned here with a positive control (a genuinely short, insecure live
session cookie still fires every finding). Nothing here touches the network: the
HTTP surface is a tiny in-process fake, same host in and out so the off-site guard
stays satisfied.
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


def _audit(cookies):
    # Same host in and out so the off-site redirect guard is satisfied.
    resp = _Resp("http://t/login", cookies)
    return asyncio.run(auth_scanner._audit_cookies(_Session(resp), "http://t/login"))


def test_php_logout_deleted_cookie_not_scored():
    out = _audit(["PHPSESSID=deleted; path=/; expires=Thu, 01-Jan-1970 00:00:00 GMT"])
    assert out == [], [f["vuln_type"] for f in out]


def test_max_age_zero_clear_not_scored():
    out = _audit(["sessionid=; Max-Age=0; path=/"])
    assert out == [], [f["vuln_type"] for f in out]


def test_short_live_session_cookie_still_fires():
    # A genuinely short, insecure, live session id (not a deletion): every finding
    # must still fire — recall preserved.
    out = _audit(["sessionid=abc123; path=/"])
    types = {f["vuln_type"] for f in out}
    assert "weak_session_id" in types
    assert "cookie_no_secure" in types
    assert "cookie_no_httponly" in types
    assert "cookie_no_samesite" in types


def test_flag_in_value_does_not_mask_missing_attribute():
    # The value contains the words secure/httponly/samesite but NONE is an actual
    # attribute; the loose substring check used to treat the flags as present and
    # emit nothing. The attribute-scoped check now fires all three.
    out = _audit(["auth=secure_httponly_samesite_tok_abcdefghij; path=/"])
    types = {f["vuln_type"] for f in out}
    assert "cookie_no_secure" in types
    assert "cookie_no_httponly" in types
    assert "cookie_no_samesite" in types


def test_fully_secured_cookie_not_flagged():
    out = _audit([
        "sessionid=longenoughvalue1234567890; Secure; HttpOnly; SameSite=Strict; path=/"
    ])
    assert out == [], [f["vuln_type"] for f in out]

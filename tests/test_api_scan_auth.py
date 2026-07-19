"""HEAVEN — web/API authenticated-scan session wiring.

The CLI has long accepted ``--cookie-file``/``--auth`` (+ the ``--low-priv-*``
pair) so authenticated crawls, IDOR and the multi-role Broken Access Control
audit work. These tests prove the *web* path now sets up the same sessions from
a ``ScanRequest``: raw cookie header, form login, the low-privilege second
identity, the empty no-op, bad input, and — critically — that sessions are
cleared afterwards so one scan's credentials never leak into the next in the
long-lived server process.

Isolation note: ``auth_session`` state lives in *module globals*, and some other
test in the suite (``test_advanced.py``) nukes every ``heaven*`` entry from
``sys.modules`` and re-imports. If this file bound the module at import time it
would end up pointing at an orphaned copy while ``server.py``'s lazy imports use
the fresh one — the two ``_active`` globals would diverge. So we resolve the
module at *call time* via ``_A()``, exactly as ``server.py`` does.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("aiohttp")


def _A():
    """Resolve the CURRENT auth_session module (robust to sys.modules resets)."""
    import heaven.recon.auth_session as m
    return m


def _server():
    """Resolve the CURRENT api.server module for the same reason."""
    import heaven.api.server as m
    return m


class _LoginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)   # drain body → keep-alive stays healthy
        self.send_response(302)
        self.send_header("Set-Cookie", "session=web-fresh; Path=/")
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 — post-login redirect lands here
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        return


class _LoginServer:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


@pytest.fixture(autouse=True)
def _clean():
    _server()._clear_scan_auth()
    _A()._login_memo = None
    yield
    _server()._clear_scan_auth()
    _A()._login_memo = None


def test_parse_cookie_header_splits_pairs():
    parse = _server()._parse_cookie_header
    assert parse("session=abc; role=admin") == {"session": "abc", "role": "admin"}
    assert parse("  a=1 ;; b=2 ") == {"a": "1", "b": "2"}
    assert parse("") == {}


def test_auth_base_url_prefers_http_target():
    srv = _server()
    SR = srv.ScanRequest
    assert srv._auth_base_url(SR(urls=["https://app.example.com/x"])) == "https://app.example.com/x"
    assert srv._auth_base_url(SR(targets=["10.0.0.1"])) == "http://10.0.0.1"
    assert srv._auth_base_url(SR()) == "http://localhost"


def test_cookie_string_activates_primary_session():
    srv = _server()
    req = srv.ScanRequest(urls=["http://t.example"], cookie="session=abc; role=admin")
    notes = asyncio.run(srv._setup_scan_auth(req))
    sess = _A().get_active_session()
    assert sess is not None
    assert sess.cookies == {"session": "abc", "role": "admin"}
    assert any("primary session via cookie" in n for n in notes)
    assert _A().get_low_priv_session() is None


def test_low_priv_cookie_sets_second_identity():
    srv = _server()
    req = srv.ScanRequest(
        urls=["http://t.example"],
        cookie="session=admin",
        low_priv_cookie="session=user",
    )
    asyncio.run(srv._setup_scan_auth(req))
    assert _A().get_active_session().cookies == {"session": "admin"}
    assert _A().get_low_priv_session().cookies == {"session": "user"}


def test_form_login_activates_session_and_remembers_it():
    srv = _server()
    with _LoginServer() as base:
        req = srv.ScanRequest(urls=[base], auth="url=/login,user=admin,pass=pw")
        notes = asyncio.run(srv._setup_scan_auth(req))
    sess = _A().get_active_session()
    assert sess is not None and sess.cookies.get("session") == "web-fresh"
    assert any("form login" in n for n in notes)
    # remember_login was called → a mid-scan renewal is possible
    assert _A()._login_memo is not None


def test_empty_request_is_noop():
    srv = _server()
    notes = asyncio.run(srv._setup_scan_auth(srv.ScanRequest(urls=["http://t.example"])))
    assert notes == []
    assert _A().get_active_session() is None
    assert _A().get_low_priv_session() is None


def test_bad_cookie_raises():
    srv = _server()
    with pytest.raises(ValueError):
        asyncio.run(srv._setup_scan_auth(srv.ScanRequest(cookie="not-a-cookie")))


def test_clear_scan_auth_drops_both_sessions():
    A = _A()
    A.set_active_session(A.AuthSession(cookies={"a": "1"}, label="x"))
    A.set_low_priv_session(A.AuthSession(cookies={"b": "2"}, label="y"))
    _server()._clear_scan_auth()
    assert A.get_active_session() is None
    assert A.get_low_priv_session() is None

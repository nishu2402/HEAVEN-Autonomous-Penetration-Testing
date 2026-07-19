"""HEAVEN — mid-scan session renewal tests.

A long authenticated scan can outlive its session. The auth layer remembers a
form login so it can transparently re-authenticate. These tests prove the
primitives: expiry detection, remember→refresh, and the safe no-op when there is
nothing to renew.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("aiohttp")

from heaven.recon import auth_session as A


class _LoginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    token = "tok123"

    def do_POST(self):  # noqa: N802
        # Drain the request body so the keep-alive connection isn't corrupted for
        # the redirect GET that aiohttp sends next.
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self.send_response(302)
        self.send_header("Set-Cookie", f"session={type(self).token}; Path=/")
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 — the post-login redirect lands here
        body = b"<html><body>logged in</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        return


class _LoginServer:
    def __init__(self, token="tok123"):
        self.token = token

    def __enter__(self):
        cls = type("_H", (_LoginHandler,), {"token": self.token})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


@pytest.fixture(autouse=True)
def _clean_session():
    A.clear_active_session()
    A._login_memo = None
    yield
    A.clear_active_session()
    A._login_memo = None


def test_session_looks_expired_detects_login_wall():
    assert A.session_looks_expired('<form><input name="password"></form>')
    assert A.session_looks_expired("", status=401)
    assert A.session_looks_expired("Your session has expired, please log in")
    assert not A.session_looks_expired("<html><body>dashboard widgets</body></html>")


def test_refresh_is_noop_without_remembered_login():
    assert asyncio.run(A.refresh_active_session()) is False


def test_remember_then_refresh_restores_active_session():
    with _LoginServer(token="fresh999") as base:
        spec = A.parse_auth_string("url=/login,user=admin,pass=pw")
        A.remember_login(base, spec)
        ok = asyncio.run(A.refresh_active_session())
    assert ok is True
    sess = A.get_active_session()
    assert sess is not None
    assert sess.cookies.get("session") == "fresh999"


def test_low_priv_session_is_independent_of_primary():
    primary = A.AuthSession(cookies={"role": "admin"}, label="admin")
    low = A.AuthSession(cookies={"role": "user"}, label="user")
    A.set_active_session(primary)
    A.set_low_priv_session(low)
    try:
        assert A.get_active_session().cookies == {"role": "admin"}
        assert A.get_low_priv_session().cookies == {"role": "user"}
    finally:
        A.set_low_priv_session(None)

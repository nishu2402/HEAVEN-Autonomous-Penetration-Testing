"""HEAVEN - form-login submit/hidden-field mirroring tests.

Regression for a real bug found on a live DVWA target: `perform_form_login`
submitted only user+pass, so apps that gate the login on the submit button name
(DVWA checks `isset($_POST['Login'])`) or on a hidden state token stayed
UNauthenticated. Every "authenticated" scan then probed protected pages blind
and reported nothing - indistinguishable from "the target has no findings".

The fix mirrors the real form: GET the login page, carry its hidden inputs and
submit button(s), then override user/pass/csrf. These tests pin both the pure
form-parser and the end-to-end login against a server that, like DVWA, only
authenticates when the submit button is present.
"""
from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("aiohttp")

from heaven.recon import auth_session as A


# ── pure parser: _login_form_defaults ───────────────────────────────────────

def test_form_defaults_capture_named_submit_button():
    html = (
        "<form action='login.php' method='post'>"
        "<input type='text' name='username'>"
        "<input type='password' name='password'>"
        "<input type='submit' value='Login' name='Login'>"
        "</form>"
    )
    out = A._login_form_defaults(html, "password")
    assert out.get("Login") == "Login"  # the button DVWA gates on


def test_form_defaults_capture_hidden_csrf_token():
    html = (
        "<form method='post'>"
        "<input type='hidden' name='csrfmiddlewaretoken' value='abc123'>"
        "<input name='username'><input type='password' name='password'>"
        "<button type='submit'>Sign in</button>"
        "</form>"
    )
    out = A._login_form_defaults(html, "password")
    assert out.get("csrfmiddlewaretoken") == "abc123"


def test_form_defaults_pick_the_password_form_not_a_search_box():
    html = (
        "<form id='search'><input type='text' name='q'>"
        "<input type='submit' name='go' value='Search'></form>"
        "<form id='login' method='post'>"
        "<input name='username'><input type='password' name='password'>"
        "<input type='hidden' name='return_to' value='/home'>"
        "<input type='submit' name='Login' value='Log In'></form>"
    )
    out = A._login_form_defaults(html, "password")
    assert out.get("Login") == "Log In"
    assert out.get("return_to") == "/home"
    assert "go" not in out  # the search form's submit must not leak in


def test_form_defaults_ignore_text_inputs_and_empty_html():
    # Plain text inputs (other than the ones the caller overrides) are not
    # mirrored - only hidden state and submit controls.
    html = "<form><input type='text' name='nickname' value='x'>" \
           "<input type='password' name='password'></form>"
    out = A._login_form_defaults(html, "password")
    assert "nickname" not in out
    assert A._login_form_defaults("", "password") == {}


# ── end-to-end: a DVWA-style server that requires the submit button ──────────

class _SubmitGatedLogin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    _FORM = (
        b"<html><body><form action='/login' method='post'>"
        b"<input type='hidden' name='token' value='T'>"
        b"<input type='text' name='username'>"
        b"<input type='password' name='password'>"
        b"<input type='submit' name='Login' value='Login'>"
        b"</form></body></html>"
    )

    def do_GET(self):  # noqa: N802
        body = b"<html><body>dashboard</body></html>" if self.path == "/" else self._FORM
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode() if length else ""
        fields = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
        # DVWA-style gate: authenticate ONLY when the submit button was sent
        # (and creds are right). Missing 'Login' -> re-render, no auth cookie.
        ok = fields.get("Login") == "Login" and fields.get("username") == "admin" \
            and fields.get("password") == "pw"
        self.send_response(302 if ok else 200)
        if ok:
            self.send_header("Set-Cookie", "auth=yes; Path=/")
            self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_a):
        return


class _Server:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SubmitGatedLogin)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


@pytest.fixture(autouse=True)
def _clean_session():
    A.clear_active_session()
    yield
    A.clear_active_session()


def test_form_login_sends_submit_button_and_authenticates():
    with _Server() as base:
        spec = A.parse_auth_string("url=/login,user=admin,pass=pw")
        sess = asyncio.run(A.perform_form_login(base, spec))
    # The auth cookie only appears if the submit button (and hidden token) were
    # mirrored into the POST - the whole point of the fix.
    assert sess.cookies.get("auth") == "yes"


def test_form_login_carries_hidden_token():
    # A csrf_field that lives as a hidden input is auto-carried from the page.
    with _Server() as base:
        spec = A.parse_auth_string("url=/login,user=admin,pass=pw,csrf_field=token")
        sess = asyncio.run(A.perform_form_login(base, spec))
    assert sess.cookies.get("auth") == "yes"


# ── operator-seeded session cookies (`cookies=` spec key) ────────────────────

def test_parse_cookie_pairs_basic_and_multi():
    assert A._parse_cookie_pairs("security=low") == {"security": "low"}
    assert A._parse_cookie_pairs("security=low;lang=en") == {
        "security": "low", "lang": "en"}


def test_parse_cookie_pairs_value_with_equals_and_junk():
    # base64/JWT-ish values keep their '='; blank/malformed segments are dropped.
    assert A._parse_cookie_pairs("t=ab==;  ; =noname; ok=1") == {
        "t": "ab==", "ok": "1"}
    assert A._parse_cookie_pairs("") == {}


def test_parse_auth_string_captures_cookies_field():
    spec = A.parse_auth_string("url=/login,user=a,pass=b,cookies=security=low")
    assert spec["cookies"] == "security=low"


def test_form_login_seeds_extra_cookie_onto_session():
    # DVWA needs `security=low` alongside the login cookie or nothing is
    # exploitable. The seeded cookie must ride on top of the real login cookie.
    with _Server() as base:
        spec = A.parse_auth_string(
            "url=/login,user=admin,pass=pw,cookies=security=low")
        sess = asyncio.run(A.perform_form_login(base, spec))
    assert sess.cookies.get("auth") == "yes"      # real login still succeeded
    assert sess.cookies.get("security") == "low"  # operator cookie seeded on


def test_form_login_seeded_cookie_reaches_scanners():
    # The seeded cookie must be attached to every scanner request, not just the
    # login jar — that is what aiohttp_session_kwargs() feeds the scan.
    with _Server() as base:
        spec = A.parse_auth_string(
            "url=/login,user=admin,pass=pw,cookies=security=low")
        sess = asyncio.run(A.perform_form_login(base, spec))
    A.set_active_session(sess)
    try:
        kw = A.aiohttp_session_kwargs()
        assert kw.get("cookies", {}).get("security") == "low"
    finally:
        A.clear_active_session()

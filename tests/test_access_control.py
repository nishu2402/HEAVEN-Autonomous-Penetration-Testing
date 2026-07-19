"""HEAVEN — multi-role Broken Access Control audit tests.

A local server models three identities via a ``role`` cookie (admin / user /
anon) across four routes that exercise every branch:

  /admin/panel  — admin+user get the protected content, anon is DENIED  → the
                  proven bug (low-priv reaches gated content).
  /admin/stats  — everyone (incl. anon) gets identical content on a privileged
                  path                                                   → the
                  heuristic medium "verify" finding (missing auth).
  /private/data — admin granted, user 403, anon 401 (correct enforcement) → NONE.
  /public/page  — everyone gets the same public content                  → NONE.

The last two are the false-positive traps this design must not fall into.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from heaven.recon.auth_session import AuthSession
from heaven.vulnscan.access_control import scan_access_control

_ADMIN = "<html><body>SECRET ADMIN PANEL — user management console " + ("a" * 160) + "</body></html>"
_STATS = "<html><body>ADMIN STATISTICS dashboard totals " + ("b" * 160) + "</body></html>"
_PRIV = "<html><body>PRIVATE customer record dossier " + ("c" * 160) + "</body></html>"
_PUB = "<html><body>Welcome to our public marketing homepage " + ("d" * 160) + "</body></html>"
_DENY = "<html><body>401 Unauthorized — please log in to continue</body></html>"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _role(self) -> str:
        cookie = self.headers.get("Cookie", "")
        if "role=admin" in cookie:
            return "admin"
        if "role=user" in cookie:
            return "user"
        return "anon"

    def _send(self, status: int, body: str) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        role = self._role()
        path = self.path.split("?", 1)[0]
        if path.startswith("/admin/panel"):
            # authn enforced (anon denied) but NOT authz (user gets admin content)
            if role in ("admin", "user"):
                self._send(200, _ADMIN)
            else:
                self._send(401, _DENY)
        elif path.startswith("/admin/stats"):
            # privileged path served to everyone incl. anon → missing auth
            self._send(200, _STATS)
        elif path.startswith("/private/data"):
            # correct enforcement — only admin
            if role == "admin":
                self._send(200, _PRIV)
            elif role == "user":
                self._send(403, _DENY)
            else:
                self._send(401, _DENY)
        elif path.startswith("/public/page"):
            self._send(200, _PUB)
        else:
            self._send(404, "not found")

    def log_message(self, *_a):
        return


class _Server:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def _run(base: str):
    urls = [f"{base}/admin/panel", f"{base}/admin/stats",
            f"{base}/private/data", f"{base}/public/page"]
    admin = AuthSession(cookies={"role": "admin"}, label="admin")
    user = AuthSession(cookies={"role": "user"}, label="user")
    return asyncio.run(scan_access_control(
        urls, privileged=admin, low_priv=user, stealth_level="aggressive"))


def test_proven_bac_when_low_priv_reaches_gated_content():
    with _Server() as base:
        res = _run(base)
    panel = [f for f in res["findings"] if f["target"].endswith("/admin/panel")]
    assert len(panel) == 1, res["findings"]
    f = panel[0]
    assert f["vuln_type"] == "broken_access_control"
    assert f["severity"] == "high"
    assert f["proved"] is True


def test_missing_auth_on_privileged_path_is_medium_verify():
    with _Server() as base:
        res = _run(base)
    stats = [f for f in res["findings"] if f["target"].endswith("/admin/stats")]
    assert len(stats) == 1, res["findings"]
    f = stats[0]
    assert f["severity"] == "medium"
    assert f["proved"] is False
    assert "verify" in f["evidence"]["verification"].lower()


def test_correctly_enforced_resource_is_not_flagged():
    with _Server() as base:
        res = _run(base)
    priv = [f for f in res["findings"] if f["target"].endswith("/private/data")]
    assert priv == [], f"correctly-enforced resource flagged: {priv}"


def test_public_page_is_not_flagged():
    with _Server() as base:
        res = _run(base)
    pub = [f for f in res["findings"] if f["target"].endswith("/public/page")]
    assert pub == [], f"public page mistaken for BAC: {pub}"


def test_no_privileged_session_skips_audit():
    with _Server() as base:
        res = asyncio.run(scan_access_control(
            [f"{base}/admin/panel"], privileged=None, low_priv=None))
    assert res["findings"] == []
    assert "skipped" in res


def test_findings_carry_owasp_and_cwe_taxonomy():
    with _Server() as base:
        res = _run(base)
    for f in res["findings"]:
        assert f["cwe"] == "CWE-284"
        assert f["owasp"].startswith("A01")

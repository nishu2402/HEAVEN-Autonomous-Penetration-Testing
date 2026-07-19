"""HEAVEN — blind OS command injection (OOB) + reachable-collaborator tests.

The blind-cmdi prober injects a shell command that fetches HEAVEN's collaborator;
a callback proves code execution. We model a vulnerable target whose "shell"
actually runs the injected ``curl`` (fetches the URL it finds in the value), and
a benign one that never does — proving the finding fires only on a real callback.
"""

from __future__ import annotations

import asyncio
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("aiohttp")

from heaven.vulnscan.oast import OASTListener
from heaven.vulnscan.oob_scanner import scan_oob

_URL_RE = re.compile(r"https?://[^\s;|&$(){}`\"'<>]+")


class _CmdiHandler(BaseHTTPRequestHandler):
    """A target whose shell executes an injected curl/wget (fetches the URL)."""
    protocol_version = "HTTP/1.1"
    execute = True  # toggled to False for the benign target

    def do_GET(self):  # noqa: N802
        qs = parse_qs(urlparse(self.path).query)
        if type(self).execute:
            for vals in qs.values():
                for v in vals:
                    if "curl" in v or "wget" in v or "certutil" in v:
                        m = _URL_RE.search(v)
                        if m:
                            try:
                                urllib.request.urlopen(m.group(0), timeout=2)  # noqa: S310
                            except Exception:
                                pass
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        return


class _Target:
    def __init__(self, execute: bool):
        self._execute = execute

    def __enter__(self):
        cls = type("_H", (_CmdiHandler,), {"execute": self._execute})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/run?cmd=1"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def test_blind_cmdi_proven_via_callback():
    with _Target(execute=True) as url, OASTListener() as oast:
        res = asyncio.run(scan_oob([url], oast=oast, xxe=False))
    cmdi = [f for f in res["findings"] if f["vuln_type"] == "command_injection"]
    assert cmdi, f"blind cmdi not proven: {res['findings']}"
    f = cmdi[0]
    assert f["severity"] == "critical"
    assert f["evidence"]["proof"] == "out-of-band callback received"


def test_benign_target_yields_no_cmdi_finding():
    # The target never executes the command → no callback → no finding (zero FP).
    with _Target(execute=False) as url, OASTListener() as oast:
        res = asyncio.run(scan_oob([url], oast=oast, xxe=False))
    cmdi = [f for f in res["findings"] if f["vuln_type"] == "command_injection"]
    assert cmdi == [], f"false positive without a callback: {cmdi}"


# ── reachable collaborator (HEAVEN_OAST_HOST / _BIND / _PORT) ────────────────

def test_from_env_advertises_routable_host(monkeypatch):
    monkeypatch.setenv("HEAVEN_OAST_HOST", "10.11.12.13")
    monkeypatch.setenv("HEAVEN_OAST_BIND", "127.0.0.1")  # bind loopback for the test
    listener = OASTListener.from_env()
    assert listener.advertised_host == "10.11.12.13"
    listener.start()
    try:
        assert listener.base_url.startswith("http://10.11.12.13:")
        assert listener.url_for("tok").startswith("http://10.11.12.13:")
        assert listener.url_for("tok").endswith("/tok")
    finally:
        listener.stop()


def test_from_env_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("HEAVEN_OAST_HOST", raising=False)
    monkeypatch.delenv("HEAVEN_OAST_BIND", raising=False)
    listener = OASTListener.from_env()
    assert listener.advertised_host == "127.0.0.1"

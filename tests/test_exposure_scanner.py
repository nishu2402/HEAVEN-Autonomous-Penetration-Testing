"""HEAVEN — exposed-file & secret discovery tests.

A local server exposes real artefacts (.git, .env, .DS_Store, a JS source map, a
.bak source file); a second "soft-404" mode returns the SPA shell for every path.
The scanner must find every genuine artefact and, critically, find NOTHING on the
soft-404 server — content verification is what separates the two.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("aiohttp")

from heaven.vulnscan.exposure_scanner import scan_exposures

_SHELL = "<html><body>Single Page App shell " + ("x" * 120) + "</body></html>"
_GIT_HEAD = "ref: refs/heads/main\n"
_GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
_DOTENV = "APP_KEY=base64:abcd1234\nDB_PASSWORD=s3cr3t\nSTRIPE_SECRET=sk_live_x\n"
_DSSTORE = "\x00\x00\x00\x01Bud1\x00\x00\x00\x00directory listing here"
_PHP_BAK = "<?php $conn = mysqli_connect('db','root','p@ss'); ?>"
_MAP = json.dumps({"version": 3, "sources": ["src/app.tsx"],
                   "sourcesContent": ["export const x = 1"], "mappings": "AAAA"})


def _make_handler(expose: bool):
    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body: str, ctype: str = "text/html", status: int = 200):
            raw = body.encode("utf-8", "replace")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            if expose:
                if path == "/.git/HEAD":
                    return self._send(_GIT_HEAD, "text/plain")
                if path == "/.git/config":
                    return self._send(_GIT_CONFIG, "text/plain")
                if path == "/.env":
                    return self._send(_DOTENV, "text/plain")
                if path == "/.DS_Store":
                    return self._send(_DSSTORE, "application/octet-stream")
                if path == "/app.js.map":
                    return self._send(_MAP, "application/json")
                if path == "/index.php.bak":
                    return self._send(_PHP_BAK, "text/plain")
            # Everything else (and all paths when expose=False) → SPA shell.
            return self._send(_SHELL)

        def log_message(self, *_a):
            return
    return _H


class _Server:
    def __init__(self, expose: bool):
        self.expose = expose

    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self.expose))
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def _scan(base: str):
    return asyncio.run(scan_exposures(
        [base], js_files=[f"{base}/app.js"], page_urls=[f"{base}/index.php"],
        stealth_level="aggressive"))


def _types(res):
    return {(f["title"]) for f in res["findings"]}


def test_finds_exposed_git():
    with _Server(expose=True) as base:
        res = _scan(base)
    assert any(f["title"] == "Exposed .git repository" and f["severity"] == "high"
               for f in res["findings"]), res["findings"]


def test_finds_exposed_dotenv_as_secret():
    with _Server(expose=True) as base:
        res = _scan(base)
    env = [f for f in res["findings"] if f["title"] == "Exposed .env file"]
    assert env and env[0]["vuln_type"] == "secret_exposure", res["findings"]


def test_finds_source_map():
    with _Server(expose=True) as base:
        res = _scan(base)
    assert any(f["title"] == "JavaScript source map exposed" for f in res["findings"]), res["findings"]


def test_finds_ds_store_and_backup():
    with _Server(expose=True) as base:
        res = _scan(base)
    titles = _types(res)
    assert "Exposed .DS_Store" in titles, titles
    assert "Exposed backup / source file" in titles, titles


def test_soft404_server_yields_no_findings():
    # Every path returns the SPA shell → content verification must reject all.
    with _Server(expose=False) as base:
        res = _scan(base)
    assert res["findings"] == [], f"false positives on soft-404 server: {res['findings']}"


def test_all_findings_content_verified_and_proved():
    with _Server(expose=True) as base:
        res = _scan(base)
    assert res["findings"]
    for f in res["findings"]:
        assert f["proved"] is True
        assert f["evidence"]["verification"] == "content-verified"

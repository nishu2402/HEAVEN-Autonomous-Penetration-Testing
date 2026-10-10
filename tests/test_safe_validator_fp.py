"""Regression: safe_validator must confirm CRLF and XXE from positive evidence
only, never from an incidental substring in a reflected value or a generic word.

Two report-facing false positives are pinned here:

* ``validate_crlf`` used to confirm when the unique canary appeared anywhere in
  the stringified response headers. A server that merely echoes the parameter
  verbatim into a reflecting header value (e.g. a Location/redirect header)
  contains the canary text but never split a header, so that was a false
  positive. Confirmation now requires the canary to appear as a real response
  *header name*.

* ``validate_xxe`` carried ``"localhost"`` in its confirmation indicators. That
  generic word appears in countless normal response bodies, so any XML endpoint
  whose body merely mentioned localhost was reported as a confirmed (critical)
  XXE. The indicator was removed; only the unique canary and /etc/passwd markers
  confirm now.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

aiohttp = pytest.importorskip("aiohttp")


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# ── CRLF ────────────────────────────────────────────────────────────────────

class _ReflectsParamIntoLocation(BaseHTTPRequestHandler):
    """Echoes the ``next`` parameter verbatim into a Location header without ever
    splitting a header. The CRLF canary text is therefore present in the response
    headers as a substring, but no injected header exists."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = urlparse(self.path)
        nxt = (parse_qs(q.query).get("next") or [""])[0]
        self.send_response(302)
        # The param (percent-decoded by parse_qs) is placed into a header VALUE.
        # aiohttp will not treat an embedded value as a separate header key.
        self.send_header("Location", "/go?to=" + nxt.replace("\r", "").replace("\n", ""))
        self.end_headers()


class _TrueCRLF(BaseHTTPRequestHandler):
    """Actually splits the response: whatever name:value the param carries becomes
    a genuine extra response header (a real CRLF header injection)."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = urlparse(self.path)
        raw = (parse_qs(q.query, keep_blank_values=True).get("next") or [""])[0]
        self.send_response(200)
        # Emulate a vulnerable server that folds the decoded CRLF into real
        # headers: split on newline and emit each "k: v" as its own header.
        for line in raw.replace("\r\n", "\n").split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip():
                    self.send_header(k.strip(), v.strip())
        self.end_headers()


def _run_crlf(port):
    from heaven.vulnscan.safe_validator import validate_crlf

    async def _r():
        async with aiohttp.ClientSession() as s:
            return await validate_crlf(s, f"http://127.0.0.1:{port}/", "next", timeout=5.0)
    return asyncio.run(_r())


def test_crlf_reflection_into_header_value_is_not_confirmed():
    srv, port = _serve(_ReflectsParamIntoLocation)
    try:
        res = _run_crlf(port)
    finally:
        srv.shutdown()
    assert res.result != "confirmed", res.evidence


def test_crlf_real_header_split_is_confirmed():
    srv, port = _serve(_TrueCRLF)
    try:
        res = _run_crlf(port)
    finally:
        srv.shutdown()
    assert res.result == "confirmed", res.evidence
    assert res.evidence.get("injected_header")


# ── XXE ───────────────────────────────────────────────────────────────────────

class _MentionsLocalhost(BaseHTTPRequestHandler):
    """A benign XML endpoint whose body merely contains the word 'localhost'
    (as a real app's error/help text might). It never expands any entity."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        body = b"<error>Could not connect to database at localhost:5432</error>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ExpandsEntity(BaseHTTPRequestHandler):
    """A genuinely XXE-vulnerable endpoint: it reflects the expanded internal
    entity (the unique canary) back in the response."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        import re
        length = int(self.headers.get("Content-Length", 0) or 0)
        payload = self.rfile.read(length).decode("utf-8", "ignore")
        m = re.search(r'<!ENTITY xxe "([0-9a-f]+)"', payload)
        echo = m.group(1) if m else ""
        body = ("<root>" + echo + "</root>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _run_xxe(port):
    from heaven.vulnscan.safe_validator import validate_xxe

    async def _r():
        async with aiohttp.ClientSession() as s:
            return await validate_xxe(s, f"http://127.0.0.1:{port}/", timeout=5.0)
    return asyncio.run(_r())


def test_xxe_body_mentioning_localhost_is_not_confirmed():
    srv, port = _serve(_MentionsLocalhost)
    try:
        res = _run_xxe(port)
    finally:
        srv.shutdown()
    assert res.result != "confirmed", res.evidence


def test_xxe_entity_expansion_is_confirmed():
    srv, port = _serve(_ExpandsEntity)
    try:
        res = _run_xxe(port)
    finally:
        srv.shutdown()
    assert res.result == "confirmed", res.evidence

"""Regression: SSRF validation must actually probe the cloud-metadata endpoints.

The localhost-obfuscation variants numbered exactly 12 and used to fill the whole
probe budget (``all_urls[:12]``), so ``validate_ssrf`` never sent the AWS/GCP/
Azure metadata URLs — a silent false negative on the most severe SSRF outcome
(credential exfiltration via the instance-metadata service). This test drives the
validator against a tiny in-process HTTP server that mimics a reflecting SSRF and
asserts a metadata probe both reaches the target and is what confirms the finding.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

aiohttp = pytest.importorskip("aiohttp")


class _ReflectingSSRF(BaseHTTPRequestHandler):
    """/fetch?url=... echoes recognisable EC2 metadata only for the IMDS host,
    exactly as a server-side fetch of a real IMDS would — nothing else reflects,
    so a confirmation can ONLY come from a metadata probe actually being sent."""

    seen_urls: list[str] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = urlparse(self.path)
        url = (parse_qs(q.query).get("url") or [""])[0]
        type(self).seen_urls.append(url)
        if "169.254.169.254" in url and "meta-data" in url:
            body = b"ami-id\niam/\ninstance-id\n"
        else:
            body = b"nothing to see here"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_validate_ssrf_probes_and_confirms_via_metadata():
    from heaven.vulnscan.safe_validator import validate_ssrf

    _ReflectingSSRF.seen_urls = []
    srv = HTTPServer(("127.0.0.1", 0), _ReflectingSSRF)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        async def _run():
            async with aiohttp.ClientSession() as s:
                return await validate_ssrf(
                    s, f"http://127.0.0.1:{port}/fetch", "url", timeout=5.0)

        res = asyncio.run(_run())
    finally:
        srv.shutdown()

    # A cloud-metadata URL must have actually been sent (the old truncation bug
    # meant it never was).
    assert any("169.254.169.254" in u and "meta-data" in u
               for u in _ReflectingSSRF.seen_urls), _ReflectingSSRF.seen_urls
    # ...and it must be what confirms the finding.
    assert res.result == "confirmed", res.result
    assert "169.254.169.254" in res.evidence.get("probe_url", ""), res.evidence

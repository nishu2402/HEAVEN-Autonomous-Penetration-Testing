"""``deep_recon.fuzz_endpoints`` phantom-endpoint suppression on a catch-all host.

Shared hosting, parked domains and SPA origins answer EVERY path with the same
200 HTML shell. Before the guard, ``fuzz_endpoints`` "discovered" the whole
``COMMON_API_PATHS`` list (/api, /graphql, /v1 …) as real endpoints and fed them
forward to the API/web scanners, which then ran their full battery against dozens
of nonexistent paths — observed live on a cPanel host, driving the API task into
its 600s timeout and firing a ``no_rate_limit`` false positive on every path.

The guard probes a random path that cannot exist: if the origin answers it with a
200 HTML page it is a catch-all, and any speculative path returning the same shell
is dropped. A well-behaved origin (404 for the random path) is unaffected.
"""

from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from typing import Callable

import pytest

aiohttp = pytest.importorskip("aiohttp")

# A representative slice of the real COMMON_API_PATHS — enough to prove the guard
# without probing the full list on every run.
_API_PATHS = ["/api", "/api/v1", "/graphql", "/graphiql", "/v1", "/rest"]


def _make_server(handler_fn: Callable[[str], tuple[int, str, bytes]]):
    """Serve ``handler_fn(path) -> (status, content_type, body_bytes)``."""

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status, ctype, body = handler_fn(self.path)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    return socketserver.TCPServer(("127.0.0.1", 0), _H)


def _run(handler_fn, paths):
    srv = _make_server(handler_fn)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    async def _go():
        from heaven.recon.deep_recon import fuzz_endpoints
        async with aiohttp.ClientSession() as session:
            return await fuzz_endpoints(
                session, f"http://127.0.0.1:{port}", paths=paths)

    try:
        return asyncio.run(_go())
    finally:
        srv.shutdown()


_SHELL = b"<!doctype html><html><body>welcome home</body></html>"


def test_total_catch_all_discovers_no_phantom_endpoints() -> None:
    # Every path (including the random baseline) returns the same 200 HTML shell.
    found = _run(lambda path: (200, "text/html", _SHELL), _API_PATHS)
    assert found == [], (
        "a total catch-all origin must not yield phantom API endpoints; got "
        f"{[a.value for a in found]}")


def test_real_distinct_endpoint_survives_catch_all() -> None:
    # Catch-all HTML shell for unknown paths, but /api is a real DISTINCT JSON API.
    def handler(path):
        if path == "/api":
            return 200, "application/json", b'{"name":"svc","version":"1.0","routes":[]}'
        return 200, "text/html", _SHELL

    found = _run(handler, _API_PATHS)
    assert len(found) == 1 and found[0].value.endswith("/api"), (
        "a genuinely distinct JSON endpoint must survive the catch-all guard; got "
        f"{[a.value for a in found]}")


def test_normal_host_discovery_unchanged() -> None:
    # Random baseline → 404 (well-behaved), so the guard is inert: only the real
    # 200 endpoints are discovered, the 404s are not.
    def handler(path):
        if path in ("/api", "/graphql"):
            return 200, "application/json", b'{"ok":true}'
        return 404, "text/html", b"not found"

    found = _run(handler, _API_PATHS)
    vals = [a.value for a in found]
    assert len(found) == 2, f"expected exactly the two real 200s; got {vals}"
    assert any(v.endswith("/api") for v in vals)
    assert any(v.endswith("/graphql") for v in vals)


def test_blanket_403_origin_discovers_no_phantom_endpoints() -> None:
    # Live regression (www.ashirwadsweets.com): a WAF/CDN in block mode returns 403
    # for EVERY path, so the random baseline is also 403. Every COMMON_API_PATHS
    # entry would otherwise be "discovered" as a protected endpoint and fed to the
    # API/web scanners. The baseline deny-match guard drops them all.
    found = _run(lambda path: (403, "text/html", b"<html>403 Forbidden</html>"),
                 _API_PATHS)
    assert found == [], (
        "a blanket-403 origin must not yield phantom endpoints; got "
        f"{[a.value for a in found]}")


def test_real_protected_endpoint_survives_blanket_404() -> None:
    # Honest 404 for unknown paths (baseline is 404, not a deny-all), but /api is a
    # real endpoint that 403s. It is genuine discovery and must survive.
    def handler(path):
        if path == "/api":
            return 403, "application/json", b'{"error":"forbidden"}'
        return 404, "text/html", b"not found"

    found = _run(handler, _API_PATHS)
    vals = [a.value for a in found]
    assert len(found) == 1 and vals[0].endswith("/api"), (
        f"a genuinely protected endpoint on a well-behaved origin must survive; got {vals}")

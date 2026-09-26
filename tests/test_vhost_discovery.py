"""Virtual-host discovery: honest detection + false-positive containment + wiring.

``deep_recon.discover_vhosts`` probes one origin (127.0.0.1:PORT here) while
varying only the ``Host`` header, so the test server routes purely on ``Host``.
The false-positive guard is the important one: a target whose body changes
between two identical requests (nonces / timestamps / ads) must NOT flag every
candidate as a vhost.
"""

from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from pathlib import Path

import pytest

aiohttp = pytest.importorskip("aiohttp")


def _make_server(valid: dict, *, baseline=(404, b"nope"), dynamic_baseline=False):
    """Serve responses keyed by the request's ``Host`` header.

    ``valid`` maps a lowercased host (no port) to ``(status, body_bytes)``.
    Unknown hosts get ``baseline``; with ``dynamic_baseline`` they instead get
    a 200 whose body length grows every request, i.e. a deliberately unstable
    target that must defeat the length heuristic.
    """
    counter = {"n": 0}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            host = (self.headers.get("Host") or "").split(":", 1)[0].lower()
            if host in valid:
                status, body = valid[host]
            elif dynamic_baseline:
                counter["n"] += 1
                status, body = 200, b"x" * (counter["n"] * 1000)
            else:
                status, body = baseline
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    return socketserver.TCPServer(("127.0.0.1", 0), _H)


def _run(valid, words, *, baseline=(404, b"nope"), dynamic_baseline=False):
    srv = _make_server(valid, baseline=baseline, dynamic_baseline=dynamic_baseline)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    async def _go():
        from heaven.recon.deep_recon import discover_vhosts
        async with aiohttp.ClientSession() as session:
            return await discover_vhosts(
                session, "127.0.0.1", "example.com", wordlist=words, port=port)

    try:
        return asyncio.run(_go())
    finally:
        srv.shutdown()


def test_detects_vhost_by_distinct_status() -> None:
    # Baseline (random + www/mail) → 404; admin → 200 is a strong routing signal.
    found = _run(
        {"admin.example.com": (200, b"<html>admin</html>")},
        ["admin", "www", "mail"],
    )
    names = {a.value for a in found}
    assert "admin.example.com" in names
    assert "www.example.com" not in names and "mail.example.com" not in names
    admin = next(a for a in found if a.value == "admin.example.com")
    assert admin.asset_type == "vhost"
    assert admin.metadata["signal"] == "status"
    assert admin.confidence == pytest.approx(0.9)


def test_detects_vhost_by_length_on_stable_baseline() -> None:
    # Baseline is a stable 200 small page; a much larger 200 page is the signal.
    found = _run(
        {"bigapp.example.com": (200, b"X" * 5000)},
        ["bigapp", "www"],
        baseline=(200, b"<html>default</html>"),
    )
    names = {a.value for a in found}
    assert "bigapp.example.com" in names
    assert "www.example.com" not in names
    big = next(a for a in found if a.value == "bigapp.example.com")
    assert big.metadata["signal"] == "length"


def test_no_false_positives_on_unstable_target() -> None:
    # Every response is a 200 of a different size (dynamic content). No candidate
    # may be reported, because the two baselines disagree → length is untrusted
    # and the status never differs.
    found = _run({}, ["admin", "www", "api", "dev", "staging"],
                 dynamic_baseline=True)
    assert found == []


def test_candidates_are_same_scope_only() -> None:
    words = ["admin", "internal", "www"]
    found = _run(
        {"admin.example.com": (200, b"a"), "internal.example.com": (500, b"b")},
        words,
    )
    for a in found:
        assert a.value.endswith(".example.com")
        assert a.value.split(".", 1)[0] in words


def test_discover_vhosts_is_wired_into_orchestrator() -> None:
    # Guard against silently un-wiring the capability: the deep-recon phase must
    # import and call discover_vhosts.
    src = Path("heaven/orchestrator.py").read_text(encoding="utf-8")
    assert "discover_vhosts" in src
    assert 'results["vhosts"]' in src

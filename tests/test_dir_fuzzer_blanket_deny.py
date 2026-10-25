"""dir_fuzzer: a server that denies every path must not flood 'sensitive file'.

Live regression (engagement "Ashirwad Sweets", www.ashirwadsweets.com): a WAF/CDN
in block mode returned HTTP 403 for EVERY path the fuzzer probed, including the
guessed wordlist names that do not exist. The fuzzer reads a 403 as "this path
exists but is protected", so it stored 96 ``sensitive_file`` findings plus a
``directory_listing``, all 403, whose bodies collapsed to two deny pages. None of
the "discovered" links could actually be opened.

Two gaps let it through and both are closed here:

1. The native engine's 403 suppression was size-band gated, so a deny edge serving
   two page sizes (a 10-byte stub and a 5768-byte challenge) leaked. It now drops a
   401/403 whenever the known-nonexistent wildcard probe got that SAME status
   (ground truth that the server denies everything), size notwithstanding.
2. The ffuf backend has no server-side catch-all model and its ``-ac`` calibration
   could not model two deny-page sizes. A shared post-filter
   (``_collapse_blanket_deny``) now runs on BOTH backends' merged findings: many
   access-controlled hits on one host whose sizes collapse to a tiny set are a
   blanket policy and are dropped.

A handful of genuinely protected paths, or many that each render distinctly, stay:
that is honest discovery.
"""
from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from typing import Callable

import pytest

from heaven.vulnscan import dir_fuzzer as DF
from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer

aiohttp = pytest.importorskip("aiohttp")


# ── helper: _blanket_denies (native ground-truth suppression) ────────────────

def test_blanket_denies_matches_access_controlled_catchall():
    # The wildcard probe got a uniform 403 → the server denies everything, so a
    # probed path's identical 403 is the policy, not a discovery.
    assert DF._blanket_denies({"status": 403}, 403) is True
    assert DF._blanket_denies({"status": 401}, 401) is True
    # Different status, a non-access-controlled catch-all, or no catch-all → inert.
    assert DF._blanket_denies({"status": 403}, 401) is False
    assert DF._blanket_denies({"status": 200}, 403) is False
    assert DF._blanket_denies({"status": None}, 403) is False
    assert DF._blanket_denies(None, 403) is False
    # 405 (wrong method) is not an access-controlled deny; handled elsewhere.
    assert DF._blanket_denies({"status": 405}, 405) is False


# ── _collapse_blanket_deny (shared cross-backend backstop) ───────────────────

def _ac(path: str, size: int, status: int = 403, host: str = "h") -> dict:
    return {"target": f"https://{host}{path}", "vuln_type": "sensitive_file",
            "evidence": {"status_code": status, "response_size": size, "path": path}}


def test_collapse_drops_blanket_deny_flood():
    # 12 access-controlled hits on one host, two deny-page sizes → blanket policy.
    findings = [_ac(f"/p{i}", 10 if i % 4 else 5768) for i in range(12)]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert out == [], f"a blanket-deny flood must be dropped entirely; kept {len(out)}"


def test_collapse_keeps_a_few_protected_paths():
    # Below _DENY_MIN: a couple of genuinely protected paths are honest discovery.
    findings = [_ac("/admin", 120), _ac("/config.php", 340)]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert out is findings or len(out) == 2
    assert {f["evidence"]["path"] for f in out} == {"/admin", "/config.php"}


def test_collapse_keeps_many_distinct_sized_protected_paths():
    # Many access-controlled hits that each render at a DISTINCT size are distinct
    # resources, not one blanket deny, so they are kept.
    findings = [_ac(f"/svc{i}", 200 + i * 400) for i in range(14)]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert len(out) == 14, "distinctly-sized protected paths are real discovery"


def test_collapse_never_touches_served_200():
    # A real served file (200) is never swept by the deny collapse.
    served = [{"target": f"https://h/f{i}.sql", "vuln_type": "sensitive_file",
               "evidence": {"status_code": 200, "response_size": 50 + i,
                            "path": f"/f{i}.sql"}} for i in range(12)]
    out = DirectoryFuzzer._collapse_blanket_deny(served)
    assert len(out) == 12


def test_collapse_scopes_per_host():
    # A blanket-deny host collapses; a different host with a couple of 403s does not.
    flood = [_ac(f"/p{i}", 10, host="deny.example") for i in range(11)]
    real = [_ac("/admin", 90, host="real.example"),
            _ac("/backup.zip", 410, host="real.example")]
    out = DirectoryFuzzer._collapse_blanket_deny(flood + real)
    hosts = {f["target"].split("/")[2] for f in out}
    assert hosts == {"real.example"}, f"only the blanket-deny host is swept; got {hosts}"


# ── live end-to-end: native engine on a blanket-403 origin ───────────────────

def _make_server(handler_fn: Callable[[str], tuple[int, bytes]]):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status, body = handler_fn(self.path)
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    # Threaded: the native engine fans out ~510 probes concurrently, which would
    # overflow a single-threaded server's tiny accept backlog and silently drop
    # connections (masking the test). ThreadingTCPServer serves every probe.
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _H)
    srv.daemon_threads = True
    return srv


def _run_fuzz(monkeypatch, handler_fn):
    # Force the native engine so the test is deterministic regardless of a locally
    # installed ffuf binary.
    monkeypatch.setattr(DF.shutil, "which", lambda _b: None)
    srv = _make_server(handler_fn)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    async def _go():
        fz = DirectoryFuzzer(concurrency=40, recursive=False)
        return await fz.fuzz([f"http://127.0.0.1:{port}"])

    try:
        return asyncio.run(_go())
    finally:
        srv.shutdown()


_STUB = b"Forbidden\n"                       # 10 bytes, like the live stub
_CHALLENGE = b"<!doctype html><title>403</title>" + b"x" * 5700  # bigger deny page


def test_blanket_403_origin_yields_no_sensitive_files(monkeypatch):
    # Every path (including the wildcard probes) → 403, alternating two deny-page
    # sizes to mimic the live CDN that defeated size-band calibration.
    def handler(path):
        return 403, (_STUB if (hash(path) & 1) else _CHALLENGE)

    result = _run_fuzz(monkeypatch, handler)
    assert result["error"] is None
    assert result["findings"] == [], (
        "a blanket-403 origin must not yield sensitive-file findings; got "
        f"{[f.get('target') for f in result['findings']]}")


def test_genuinely_protected_paths_survive(monkeypatch):
    # Honest 404 for unknown paths (no catch-all), but two real protected paths
    # 403 with distinct bodies → they are kept (real discovery).
    def handler(path):
        if path.rstrip("/") in ("/admin", "/config.php"):
            return 403, (b"admin area" if "admin" in path else b"config denied xyz")
        return 404, b"nope"

    result = _run_fuzz(monkeypatch, handler)
    paths = {(f.get("evidence") or {}).get("path") for f in result["findings"]}
    assert "/admin" in paths and "/config.php" in paths, (
        f"genuinely protected paths must survive; got {sorted(paths)}")


# ── ffuf path: the shared backstop collapses an ffuf flood ───────────────────

@pytest.mark.asyncio
async def test_ffuf_blanket_deny_flood_is_collapsed(monkeypatch):
    """ffuf (no catch-all model of its own) reports a 403 for every wordlist name
    on a blanket-deny host; the shared collapse in ``fuzz`` drops them."""
    monkeypatch.setattr(DF.shutil, "which", lambda _b: "/usr/bin/ffuf")
    fz = DirectoryFuzzer()

    flood = [
        {"target": f"http://t/p{i}", "vuln_type": "sensitive_file",
         "title": f"p{i}", "severity": "low", "confidence": 0.4,
         "evidence": {"status_code": 403, "response_size": 10 if i % 3 else 5768,
                      "path": f"/p{i}", "words": 1}}
        for i in range(20)
    ]

    async def flood_ffuf(url, timeout=300):
        return flood

    async def no_capture(_findings):
        return None

    monkeypatch.setattr(fz, "_run_ffuf", flood_ffuf)
    monkeypatch.setattr(fz, "_capture_responses", no_capture)

    result = await fz.fuzz(["http://t/"])
    assert result["error"] is None
    assert result["findings"] == [], (
        f"ffuf's blanket-deny flood must be collapsed; kept {len(result['findings'])}")

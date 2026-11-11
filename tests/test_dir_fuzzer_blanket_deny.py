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


def test_collapse_drops_byte_uniform_deny_below_min():
    # cPanel :2078 regression: a control-panel port answers every guessed path with
    # the SAME 36-byte 401. Only ~6 wordlist names matched — below _DENY_MIN (10) —
    # yet the byte-for-byte uniformity across DISTINCT names is itself proof of a
    # blanket policy (the ffuf backend has no per-base wildcard probe to catch it).
    findings = [_ac(p, 36, status=401, host="certifiedhacker.com:2078")
                for p in ("/phpMyAdmin", "/pma", "/admin-panel",
                          "/admin.asp", "/admin.aspx", "/admin_panel")]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert out == [], f"a byte-uniform blanket-401 run must be dropped; kept {len(out)}"


def test_collapse_keeps_two_uniform_protected_paths():
    # Below _DENY_UNIFORM_MIN (3): two same-size protected paths are too few to call
    # a blanket policy and remain honest discovery.
    findings = [_ac("/admin", 120, status=401), _ac("/secret", 120, status=401)]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert len(out) == 2, "two protected paths are honest discovery, not a blanket deny"


def test_collapse_keeps_uniform_run_of_unknown_sizes():
    # The uniformity rule must key on a REAL size bucket, never the -1 "size unknown"
    # sentinel — three findings with no captured size are not a proven blanket deny.
    findings = [{"target": f"https://h/p{i}", "vuln_type": "sensitive_file",
                 "evidence": {"status_code": 401, "path": f"/p{i}"}} for i in range(5)]
    out = DirectoryFuzzer._collapse_blanket_deny(findings)
    assert len(out) == 5, "missing-size hits are not collapsed on uniformity alone"


# ── control-panel surfaces + Apache .ht* deny (residual catch-all FPs) ───────

def _ff(path: str, status: int = 200, body: str = "", host: str = "h") -> dict:
    return {"target": f"https://{host}{path}", "vuln_type": "sensitive_file",
            "evidence": {"status_code": status, "response_body": body, "path": path}}


def test_drop_apache_dotht_deny():
    # Apache's universal <Files ~ "^\.ht"> rule 403s every .ht* path whether or not
    # it exists, so a 401/403 there is the global deny, never a disclosure — but a
    # 200 (a real leaked .htaccess carrying its bytes) survives.
    findings = [_ff("/.htaccess", 403, "<title>403 Forbidden</title>"),
                _ff("/.htpasswd", 403, "<title>403 Forbidden</title>"),
                _ff("/.htaccess", 200, "RewriteEngine On\nAuthUserFile /etc/x")]
    out = DirectoryFuzzer._drop_control_panel_and_dotht(findings)
    kept = [(f["evidence"]["path"], f["evidence"]["status_code"]) for f in out]
    assert kept == [("/.htaccess", 200)], f"only the served .htaccess survives; got {kept}"


def test_drop_control_panel_surface():
    # cPanel/WHM/Webmail own login/landing pages served for a probed path are the
    # panel UI, not a discovered sensitive file (regression: /img, /whm).
    findings = [_ff("/img", 200, '<html><head><title>cPanel Login</title></head>'),
                _ff("/whm", 200, '<!DOCTYPE html><title>cPanel Redirect</title>'),
                _ff("/mail", 200, '<title>Webmail :: Welcome</title>')]
    out = DirectoryFuzzer._drop_control_panel_and_dotht(findings)
    assert out == [], f"panel surfaces must be dropped; kept {[f['evidence']['path'] for f in out]}"


def test_keep_real_disclosure_through_panel_guard():
    # A genuine sensitive file / directory listing carries no control-panel title and
    # is not a .ht* deny → kept, so recall is preserved.
    findings = [_ff("/.env", 200, "DB_PASSWORD=s3cr3t\nAPI_KEY=abc"),
                _ff("/backup/", 200, "<title>Index of /backup</title>"),
                _ff("/config.php.bak", 200, "<?php $db_pass='x'; ?>")]
    out = DirectoryFuzzer._drop_control_panel_and_dotht(findings)
    assert len(out) == 3, "real disclosures must survive the control-panel/.ht* guard"


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
    # connections (masking the test). ThreadingTCPServer serves every accepted
    # probe on its own thread — but the OS-level accept backlog
    # (``request_queue_size``, default 5) is the real bottleneck: under that burst
    # of concurrent connects the listen queue overflows and the kernel drops SYNs,
    # silently losing a probe. In isolation the accept loop keeps up, but under
    # full-suite CPU contention it falls behind and a probe (e.g. /config.php) is
    # lost — a load-dependent flake. Defer activation so the backlog is raised
    # before listen().
    srv = socketserver.ThreadingTCPServer(
        ("127.0.0.1", 0), _H, bind_and_activate=False)
    srv.request_queue_size = 256
    srv.daemon_threads = True
    srv.server_bind()
    srv.server_activate()
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

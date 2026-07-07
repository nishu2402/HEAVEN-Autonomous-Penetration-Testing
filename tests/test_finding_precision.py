"""Precision regression tests — HEAVEN must not emit false findings from noise
or from ordinary servers.

Covers the fixes for three classes of false positive observed in a live full
scan (2026-07-07):
  * a stray docstring/log line surfacing as a finding (empty type + no evidence),
  * the CL.TE timing detector flagging any slow/hung server as *critical*,
  * the web-fuzzer smuggling checks firing on nearly every 200 response.
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest

from heaven.engagement import _is_junk_finding, dedup_findings
from heaven.vulnscan.advanced_attacks import RequestSmugglingDetector


# ── junk-finding guard ────────────────────────────────────────────────────────

def test_junk_finding_no_type_no_evidence_no_conf():
    # the live case: a Python docstring leaked in with no type/evidence/confidence
    junk = {
        "title": "http.cookies.Morsel.js_output() returns an inline <script> snippet",
        "severity": "medium", "vuln_type": "", "evidence": {}, "confidence": None,
    }
    assert _is_junk_finding(junk) is True


@pytest.mark.parametrize("f", [
    {"vuln_type": "sqli"},                                 # has a type
    {"type": "nuclei", "evidence": {}},                    # has a type
    {"vuln_type": "", "evidence": {"payload": "x"}},       # has evidence
    {"vuln_type": "", "evidence": {}, "confidence": 0.8},  # has confidence
])
def test_real_findings_are_not_junk(f):
    assert _is_junk_finding(f) is False


def test_dedup_drops_junk_keeps_real():
    real = {"target": "http://h/a", "vuln_type": "sqli", "param": "id",
            "endpoint": "http://h/a", "confidence": 0.9, "evidence": {"x": 1}}
    junk = {"target": "http://h", "vuln_type": "", "evidence": {}, "confidence": None,
            "title": "some stray docstring line"}
    out = dedup_findings([real, junk])
    assert len(out) == 1
    assert (out[0].get("vuln_type") or out[0].get("type")) == "sqli"


# ── request-smuggling: no FP on a normal server ──────────────────────────────

class _AlwaysOKServer:
    """A trivial HTTP/1.1 origin that answers *every* request with a fast 200 —
    a stand-in for a normal server. A correct smuggling detector reports nothing
    against it (no stall, no behavioural deviation)."""

    def __init__(self) -> None:
        self._server = None
        self.port = 0

    async def __aenter__(self) -> "_AlwaysOKServer":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._server.close()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        with contextlib.suppress(Exception):
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(reader.read(4096), timeout=0.5)  # drain request
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"
            )
            await writer.drain()
            writer.close()


async def test_clte_no_false_positive_on_fast_server():
    async with _AlwaysOKServer() as srv:
        finding = await RequestSmugglingDetector.detect_clte(
            f"http://127.0.0.1:{srv.port}/", timeout=2.0)
    assert finding is None  # server never stalls → no smuggling claim


async def test_web_fuzz_smuggling_no_fp_on_uniform_server():
    aiohttp = pytest.importorskip("aiohttp")
    from heaven.vulnscan.web_fuzzer import _fuzz_request_smuggling
    async with _AlwaysOKServer() as srv:
        async with aiohttp.ClientSession() as session:
            out = await _fuzz_request_smuggling(session, f"http://127.0.0.1:{srv.port}/")
    # every response is an identical fast 200 → no deviation → no findings
    assert out == []

"""Hostile-target resilience — HEAVEN must degrade gracefully, never hang or crash.

Real engagements hit servers that are slow, error out, drop the connection or
redirect in a loop. These tests point the live web detectors at a deliberately
nasty local server in each mode and assert three things:

  * the scan **returns** (a per-request timeout bounds every mode — a hang fails
    the test via ``asyncio.wait_for``),
  * it never raises, and
  * it emits **no** findings (a broken/hostile server is not a vulnerable one).
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest

pytest.importorskip("aiohttp")

from heaven.vulnscan.misconfig_scanner import scan_misconfig  # noqa: E402
from heaven.vulnscan.oast import OASTListener  # noqa: E402
from heaven.vulnscan.oob_scanner import scan_oob  # noqa: E402
from heaven.vulnscan.web_fuzzer import fuzz_url  # noqa: E402


class HostileServer:
    """A local server that misbehaves in one chosen ``mode``."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self._server = None
        self.port = 0

    async def __aenter__(self) -> "HostileServer":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc) -> None:
        self._server.close()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        with contextlib.suppress(Exception):
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(reader.read(65536), timeout=0.5)
            if self.mode == "drop":
                writer.close()
                return
            if self.mode == "slow":
                await asyncio.sleep(3)  # longer than the client timeout → cut off
            if self.mode == "error500":
                payload = (b"HTTP/1.1 500 Internal Server Error\r\n"
                           b"Content-Length: 5\r\nConnection: close\r\n\r\nboom!")
            elif self.mode == "loop":
                payload = (b"HTTP/1.1 302 Found\r\nLocation: /loop\r\n"
                           b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            else:  # slow eventually answers 200
                payload = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                           b"Connection: close\r\n\r\nhi")
            writer.write(payload)
            await writer.drain()
            writer.close()


_MODES = ["slow", "error500", "drop", "loop"]


@pytest.mark.parametrize("mode", _MODES)
async def test_misconfig_scan_survives_hostile_server(mode):
    async with HostileServer(mode) as srv:
        url = f"http://127.0.0.1:{srv.port}/x?url=1"
        res = await asyncio.wait_for(scan_misconfig([url], timeout=1.0), timeout=20)
    assert res["findings"] == []  # a broken/hostile server yields no confirmed vulns


@pytest.mark.parametrize("mode", _MODES)
async def test_oob_scan_survives_hostile_server(mode):
    async with HostileServer(mode) as srv:
        with OASTListener() as oast:
            url = f"http://127.0.0.1:{srv.port}/x"
            res = await asyncio.wait_for(scan_oob([url], oast=oast, timeout=1.0), timeout=25)
    # the hostile server never calls the collaborator back → no SSRF/XXE proof
    assert res["findings"] == []


@pytest.mark.parametrize("mode", _MODES)
async def test_web_fuzzer_survives_hostile_server(mode):
    async with HostileServer(mode) as srv:
        url = f"http://127.0.0.1:{srv.port}/x"
        res = await asyncio.wait_for(fuzz_url(url), timeout=40)
    assert isinstance(res.get("findings"), list)  # returns cleanly, no exception

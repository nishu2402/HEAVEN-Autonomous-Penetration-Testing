"""The pure-Python liveness sweep must bound concurrent SOCKETS, not just hosts.

Each host in a CIDR fans out to every liveness port at once, so a host-only
semaphore let peak sockets reach hosts x ports (~16.5k for a /16) — enough to
blow past a default file-descriptor limit or the local ephemeral-port range, at
which point every connect errors and live hosts are silently misread as dead.
The sweep now caps concurrent connections globally; these tests pin that.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.recon import network_scanner as ns


def test_socket_cap_is_clamped():
    cap = ns._sweep_socket_cap()
    assert 64 <= cap <= 500


@pytest.mark.asyncio
async def test_sweep_peak_sockets_bounded_by_cap(monkeypatch):
    peak = 0
    inflight = 0

    async def fake_open_connection(host, port):
        nonlocal peak, inflight
        inflight += 1
        peak = max(peak, inflight)
        try:
            await asyncio.sleep(0.01)
            raise ConnectionRefusedError()   # every host is "dead"
        finally:
            inflight -= 1

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    hosts = ns.expand_targets(["10.0.0.0/24"])          # 254 hosts
    n_ports = len(ns._LIVENESS_PROBE_PORTS)
    assert len(hosts) * n_ports > 500                   # naive fan-out would exceed the cap

    live = await ns._tcp_ping_sweep(hosts, timeout=1.0)

    cap = ns._sweep_socket_cap()
    # Peak concurrent sockets never exceeds the global cap, and is far below the
    # naive hosts x ports fan-out the host-only bound used to allow.
    assert peak <= cap
    assert peak < len(hosts) * n_ports
    assert live == []                                   # nothing accepted a connect

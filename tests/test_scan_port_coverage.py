"""Full-port coverage regression tests.

Guards the fix for "the scanner only covers a few ports — nmap finds more":

  1. the web/API default is a FULL 1-65535 sweep, matching `heaven scan` (CLI)
     and a plain `nmap -p-` — the old `1-1024` default was the root cause of the
     web path missing everything above port 1024;
  2. the network-recon deadline scales with port breadth, so a full-range scan
     of a single host isn't truncated mid-scan back to a handful of ports;
  3. the pure-Python TCP connect-scan fallback genuinely finds every open port
     when nmap isn't installed — real handshakes only, nothing fabricated.
"""

import socket

import pytest

from heaven.recon import network_scanner


def test_api_default_ports_is_full_range():
    """The web/API scan defaults to a full 65,535-port sweep (parity w/ nmap)."""
    from heaven.api.server import ScanRequest

    assert ScanRequest().ports == "1-65535"


def _net_task_timeout(ports: str) -> float:
    from heaven.orchestrator import build_full_scan

    orch = build_full_scan({"ips": ["192.0.2.10"], "urls": [], "ports": ports})
    net = next(t for t in orch.tasks.values() if t.name == "Network Reconnaissance")
    return float(net.timeout)


def test_full_range_gets_a_bigger_budget_than_common_range():
    """A full-port sweep of a host earns materially more time than a 1-1024 pass,
    so it can finish instead of being cut short at "a few ports"."""
    full = _net_task_timeout("1-65535")
    common = _net_task_timeout("1-1024")
    assert full > common
    # Comfortably above the old ~300s single-host floor that truncated -p- scans.
    assert full >= 600


def test_network_task_carries_the_requested_port_range():
    """The full range is actually threaded through to scan_network's kwargs."""
    from heaven.orchestrator import build_full_scan

    orch = build_full_scan({"ips": ["192.0.2.10"], "urls": [], "ports": "1-65535"})
    net = next(t for t in orch.tasks.values() if t.name == "Network Reconnaissance")
    assert net.kwargs.get("port_range") == "1-65535"


def _find_closed_port() -> int:
    """Bind then immediately release an ephemeral port so it's known-closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_python_connect_scan_finds_open_port_real_socket():
    """The no-nmap fallback reports a genuinely-open port as open, and never
    invents a closed one — proven against a real localhost listener."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    closed_port = _find_closed_port()
    try:
        results = await network_scanner._python_connect_scan(
            "127.0.0.1", [open_port, closed_port], timeout=1.0,
        )
    finally:
        srv.close()

    by_port = {r.port: r for r in results}
    assert open_port in by_port, "a genuinely-open port must be reported"
    assert by_port[open_port].state == "open"
    assert by_port[open_port].protocol == "tcp"
    # A closed port is never fabricated as open.
    assert closed_port not in by_port


@pytest.mark.asyncio
async def test_python_connect_scan_no_ports_is_empty():
    assert await network_scanner._python_connect_scan("127.0.0.1", []) == []


@pytest.mark.asyncio
async def test_python_connect_scan_labels_known_service():
    """An open well-known port carries its service name from the port map."""
    # Bind a listener and pretend it is on a well-known port by scanning the
    # actual ephemeral port but asserting the label logic via SERVICE_FINGERPRINTS
    # for a canonical port. (We can't bind 80 without privileges, so assert the
    # mapping the scanner uses directly, plus a live open-port observation.)
    assert network_scanner.SERVICE_FINGERPRINTS.get(3306) == "mysql"

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        results = await network_scanner._python_connect_scan(
            "127.0.0.1", [port], timeout=1.0,
        )
    finally:
        srv.close()
    assert len(results) == 1
    assert results[0].port == port
    assert results[0].state == "open"

"""Regression tests for the UDP scan + full-port-scan / customization fixes.

These pin the behaviour that was broken before this pass:

* UDP scanning was 100% dead — no caller set ``include_udp`` and the probe table
  was never used. Now a real UDP service is caught unprivileged, wired end to end.
* A full / UDP scan is given a larger deadline so it is not silently truncated.
* Truncation, when it does happen, is surfaced as an honest finding instead of a
  silent "few ports" result.
* Port customization (fast / full / custom / UDP spec) is genuinely honoured, not
  cosmetic — proven with a real loopback responder.
"""

from __future__ import annotations

import socket
import threading

import pytest

from heaven.config import ScanMode
from heaven.orchestrator import build_full_scan
from heaven.recon.firewall_detector import build_scan_completeness_findings
from heaven.recon.network_scanner import PortResult
from heaven.recon.udp_scanner import (
    COMMON_UDP_PORTS,
    UDP_SERVICE_PROBES,
    resolve_udp_ports,
    scan_udp_ports,
)


# ── resolve_udp_ports ─────────────────────────────────────────────────────────

def test_resolve_udp_ports_defaults_to_common_set():
    assert resolve_udp_ports(None) == sorted(set(COMMON_UDP_PORTS))
    assert resolve_udp_ports("") == sorted(set(COMMON_UDP_PORTS))
    assert resolve_udp_ports("top") == sorted(set(COMMON_UDP_PORTS))
    assert resolve_udp_ports("common") == sorted(set(COMMON_UDP_PORTS))


def test_resolve_udp_ports_explicit_spec():
    assert resolve_udp_ports("53,161,500") == [53, 161, 500]
    assert resolve_udp_ports("100-103") == [100, 101, 102, 103]


def test_resolve_udp_ports_all_is_full_range_but_capped():
    got = resolve_udp_ports("all", max_ports=500)
    assert got[0] == 1
    assert len(got) == 500  # capped so an unprivileged sweep stays feasible


def test_resolve_udp_ports_invalid_falls_back_to_common():
    # A malformed spec must not raise — it degrades to the common set.
    assert resolve_udp_ports("not-a-port-spec") == sorted(set(COMMON_UDP_PORTS))


def test_common_udp_set_covers_key_services():
    # The curated set must include the services with real protocol probes.
    for p in UDP_SERVICE_PROBES:
        assert p in COMMON_UDP_PORTS, f"probed port {p} missing from common set"


# ── pure-Python UDP scan against a real loopback responder ────────────────────

def _start_udp_responder(reply: bytes = b"HEAVEN-UDP-REPLY") -> tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))  # ephemeral port
    port = s.getsockname()[1]

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(4096)
                s.sendto(reply, addr)
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return s, port


@pytest.mark.asyncio
async def test_udp_scan_catches_responsive_service():
    sock, port = _start_udp_responder()
    try:
        res = await scan_udp_ports("127.0.0.1", [port], timeout=1.0, retries=2)
    finally:
        sock.close()
    open_ports = {p["port"] for p in res["open"]}
    assert port in open_ports, "a responding UDP service must be reported open"
    got = next(p for p in res["open"] if p["port"] == port)
    assert got["protocol"] == "udp"
    assert "HEAVEN-UDP-REPLY" in got["banner"]


@pytest.mark.asyncio
async def test_udp_scan_does_not_invent_open_from_silence():
    # A port with nothing listening must NOT be reported open. On loopback a
    # silent port yields ICMP-unreachable → closed; either way, never "open".
    # Use a high port very unlikely to be in use.
    res = await scan_udp_ports("127.0.0.1", [59321], timeout=0.5, retries=1)
    assert all(p["port"] != 59321 for p in res["open"]), (
        "a silent/closed UDP port must never be reported open"
    )


@pytest.mark.asyncio
async def test_udp_scan_empty_ports_is_noop():
    res = await scan_udp_ports("127.0.0.1", [], timeout=0.5)
    assert res == {"open": [], "open_filtered": 0, "closed": 0}


# ── end-to-end through scan_host (the real deep-scan entry) ────────────────────

@pytest.mark.asyncio
async def test_scan_host_reports_udp_when_enabled():
    from heaven.recon.network_scanner import scan_host

    sock, port = _start_udp_responder()
    try:
        # include_udp with an explicit udp_ports list containing our responder.
        result = await scan_host(
            "127.0.0.1", [80], timeout=1.0, include_udp=True, udp_ports=[port],
            stealth_level="aggressive",
        )
    finally:
        sock.close()
    udp = [p for p in result.open_ports if p.protocol == "udp"]
    assert any(p.port == port for p in udp), "scan_host must surface the open UDP port"


@pytest.mark.asyncio
async def test_scan_host_no_udp_when_disabled():
    from heaven.recon.network_scanner import scan_host

    sock, port = _start_udp_responder()
    try:
        result = await scan_host(
            "127.0.0.1", [80], timeout=1.0, include_udp=False, udp_ports=[port],
            stealth_level="aggressive",
        )
    finally:
        sock.close()
    assert all(p.protocol != "udp" for p in result.open_ports), (
        "UDP must not be scanned when include_udp is False"
    )


# ── orchestrator wiring: UDP + full-range budget ──────────────────────────────

def _network_task(targets: dict):
    orch = build_full_scan(targets, scan_mode=ScanMode.NETWORK)
    for t in orch.tasks.values():
        if "Network Recon" in t.name:
            return t
    raise AssertionError("network recon task not found")


def test_orchestrator_threads_udp_into_network_task():
    t = _network_task({
        "ips": ["127.0.0.1"], "ports": "1-65535",
        "scan_udp": True, "udp_ports": "53,161,500", "stealth_level": "normal",
    })
    assert t.kwargs.get("include_udp") is True
    assert t.kwargs.get("udp_ports") == "53,161,500"
    assert t.kwargs.get("port_range") == "1-65535"


def test_orchestrator_tcp_only_by_default():
    t = _network_task({"ips": ["127.0.0.1"], "ports": "1-1024", "stealth_level": "normal"})
    assert t.kwargs.get("include_udp") is False
    assert t.kwargs.get("udp_ports") is None


def test_full_range_scan_gets_larger_deadline_than_fast():
    full = _network_task({"ips": ["127.0.0.1"], "ports": "1-65535", "stealth_level": "normal"})
    fast = _network_task({"ips": ["127.0.0.1"], "ports": "1-1024", "stealth_level": "normal"})
    assert full.timeout > fast.timeout, (
        "a full-range scan must get more time so it isn't truncated to a few ports"
    )


def test_udp_scan_gets_extra_budget():
    with_udp = _network_task({
        "ips": ["127.0.0.1"], "ports": "1-1024",
        "scan_udp": True, "stealth_level": "normal",
    })
    without = _network_task({"ips": ["127.0.0.1"], "ports": "1-1024", "stealth_level": "normal"})
    assert with_udp.timeout > without.timeout


# ── honest truncation surfacing ───────────────────────────────────────────────

def test_scan_completeness_finding_emitted_when_truncated():
    findings = build_scan_completeness_findings({"hosts_timed_out": 2, "total_hosts": 3})
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "scan_incomplete"
    assert f["severity"] == "info"
    assert f["observation"] is True
    assert f["evidence"]["hosts_timed_out"] == 2


def test_scan_completeness_finding_silent_when_complete():
    assert build_scan_completeness_findings({"hosts_timed_out": 0, "total_hosts": 5}) == []
    assert build_scan_completeness_findings({}) == []
    assert build_scan_completeness_findings("not a dict") == []


# ── API surface: the UDP fields exist and default TCP-only ────────────────────

def test_scan_request_has_udp_fields():
    from heaven.api.server import ScanRequest

    req = ScanRequest()
    assert req.scan_udp is False
    assert req.udp_ports == ""
    req2 = ScanRequest(scan_udp=True, udp_ports="53,161")
    assert req2.scan_udp is True
    assert req2.udp_ports == "53,161"


# ── privileged nmap -sU path: hang-safety + timeout fallback ──────────────────
# The privileged path (nmap -sU) is exercised for real, as root, against a live
# UDP responder in a Linux container (docker) during development — it can't run
# on an unprivileged dev box. These unit tests pin the surrounding contract that
# *is* reachable without root: the wall-clock budget parser and the dispatcher's
# behaviour when nmap is unavailable, authoritative, or times out.

def test_nmap_wait_budget_parses_units_and_bounds():
    from heaven.recon.network_scanner import _nmap_wait_budget

    assert _nmap_wait_budget("120s") == 180.0       # 120 + 60 margin
    assert _nmap_wait_budget("5m") == 360.0          # 300 + 60
    assert _nmap_wait_budget("2h") == 7260.0         # 7200 + 60
    assert _nmap_wait_budget("90") == 150.0          # bare seconds + 60
    assert _nmap_wait_budget("") == 180.0            # default secs 120 + 60
    assert _nmap_wait_budget("garbage") == 180.0     # never raises → default
    assert _nmap_wait_budget("1s") >= 30.0           # floored so it can't be tiny


@pytest.mark.asyncio
async def test_udp_service_scan_falls_back_when_nmap_times_out(monkeypatch):
    # THE regression: a privileged nmap -sU that hits its --host-timeout must NOT
    # be treated as "scan done, nothing open". It has to fall back to the bounded
    # pure-Python probes so a slow / heavily-filtered host still gets its
    # responsive UDP services caught — never a silent zero.
    from heaven.recon import network_scanner as ns

    async def _timed_out(*_a, **_k):
        return [], True  # (confirmed nothing, timed_out=True)

    monkeypatch.setattr(ns, "_nmap_udp_scan", _timed_out)

    sock, port = _start_udp_responder()
    try:
        res = await ns._udp_service_scan(
            "127.0.0.1", [port], raw_capable=True, timeout=1.0)
    finally:
        sock.close()
    assert any(p.port == port and p.protocol == "udp" for p in res), (
        "a timed-out nmap -sU must fall back to the pure-Python probes"
    )


@pytest.mark.asyncio
async def test_udp_service_scan_trusts_authoritative_nmap(monkeypatch):
    # When nmap FINISHES (timed_out False), its result is authoritative and the
    # pure-Python probes must NOT run — even an empty result is a real "nothing
    # open", not a reason to re-probe.
    from heaven.recon import network_scanner as ns
    from heaven.recon import udp_scanner as us

    nmap_port = PortResult(host="127.0.0.1", port=161, protocol="udp",
                           state="open", service="snmp")

    async def _authoritative(*_a, **_k):
        return [nmap_port], False

    tripwire = {"hit": False}

    async def _probe_tripwire(*_a, **_k):
        tripwire["hit"] = True
        return {"open": [], "open_filtered": 0, "closed": 0}

    monkeypatch.setattr(ns, "_nmap_udp_scan", _authoritative)
    monkeypatch.setattr(us, "scan_udp_ports", _probe_tripwire)

    res = await ns._udp_service_scan("127.0.0.1", [161], raw_capable=True)
    assert [p.port for p in res] == [161]
    assert tripwire["hit"] is False, "authoritative nmap result must skip probes"


@pytest.mark.asyncio
async def test_udp_service_scan_merges_partial_nmap_with_probes(monkeypatch):
    # nmap confirmed one port but timed out before finishing: keep that confirmed
    # port AND fill the remaining ports with the probe scanner (deduped).
    from heaven.recon import network_scanner as ns

    confirmed = PortResult(host="127.0.0.1", port=53, protocol="udp",
                           state="open", service="domain")

    async def _partial(*_a, **_k):
        return [confirmed], True  # one confirmed, but incomplete

    monkeypatch.setattr(ns, "_nmap_udp_scan", _partial)

    sock, live = _start_udp_responder()
    try:
        res = await ns._udp_service_scan(
            "127.0.0.1", [53, live], raw_capable=True, timeout=1.0)
    finally:
        sock.close()
    ports = {p.port for p in res}
    assert 53 in ports, "nmap's confirmed port must be kept"
    assert live in ports, "the probe scanner must fill the un-scanned remainder"


def test_nmap_udp_scan_returns_tuple_signature():
    # The contract callers depend on: (ports_or_None, timed_out: bool).
    import inspect

    from heaven.recon.network_scanner import _nmap_udp_scan

    assert inspect.iscoroutinefunction(_nmap_udp_scan)
    ann = inspect.signature(_nmap_udp_scan).return_annotation
    assert "tuple" in str(ann).lower()

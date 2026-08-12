"""Regression tests for the "scan returns 0 findings" + stealth non-determinism
root causes.

The real defect: nmap's default-script engine (``-sC`` / NSE) ABORTS on some nmap
builds — notably the 7.9x Lua/nsock ``lua_status(L) == LUA_YIELD`` SIGABRT — and
emits only a truncated XML document. HEAVEN always passed ``-sC``, so nmap crashed,
zero ports were parsed, and a scan of a live, service-rich host (Metasploitable,
certifiedhacker.com, …) came back with an empty inventory and 0 findings. On a
remote host the crash is timing-dependent, so it fired intermittently — the same
target produced *different* results run-to-run and across stealth levels.

These tests pin the fixes:
  1. a truncated/crash XML document is distinguished from a clean "nothing open"
     result (``_parse_nmap_xml`` returns None vs a dict with an empty port list);
  2. ``scan_host`` retries WITHOUT ``-sC`` when the first attempt crashes, so the
     full port + service-version inventory is still captured;
  3. a genuinely-empty clean result is NOT retried (no wasted second scan);
  4. when every nmap attempt is unusable, the pure-Python connect scan is the
     final fallback so a live host is never reported as 0 ports;
  5. the stealth timing profiles are bounded (no pathologically-low packet-rate
     floor that can't finish in budget) and retry >= 2 (no single-retry port loss),
     and the network task's time budget scales up for the slower stealth levels so
     the same target converges on the same inventory at every stealth level.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import network_scanner as ns
from heaven.recon.network_scanner import _parse_nmap_xml, scan_host

# A valid nmap document with one open port (ftp / vsftpd 2.3.4).
GOOD_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap">
 <host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="21">
    <state state="open"/>
    <service name="ftp" product="vsftpd" version="2.3.4"/>
   </port>
  </ports>
 </host>
</nmaprun>"""

# What a crashed nmap actually leaves on stdout: the header + an open <nmaprun>
# tag and nothing else (no </nmaprun>) — an unparseable, truncated document.
CRASH_XML = (
    b'<?xml version="1.0"?>\n'
    b'<!-- Nmap 7.99 scan initiated -->\n'
    b'<nmaprun scanner="nmap" args="nmap -sV -sC ..." start="1">'
)
CRASH_STDERR = b"Assertion failed: (lua_status(L) == LUA_YIELD), function callback, file nse_nsock.cc, line 381."

# A clean run that simply found no open ports (valid XML, ports empty).
EMPTY_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="user-set"/><ports></ports></host></nmaprun>"""


def _fake_exec(behavior):
    """Return a create_subprocess_exec stand-in.

    ``behavior(argv) -> (stdout, stderr, returncode)`` decides what each nmap
    invocation returns, so a test can make the first (``-sC``) attempt crash and
    the second (no ``-sC``) attempt succeed.
    """
    class _Proc:
        def __init__(self, out, err, rc):
            self._out, self._err, self.returncode = out, err, rc

        async def communicate(self):
            return (self._out, self._err)

    async def _exec(*args, **kwargs):
        out, err, rc = behavior(list(args))
        return _Proc(out, err, rc)

    return _exec


# ── 1. crash output is told apart from a clean empty result ────────────────────

def test_parse_returns_none_on_truncated_crash_document():
    assert _parse_nmap_xml(CRASH_XML, "10.0.0.1") is None


def test_parse_returns_ports_on_valid_document():
    parsed = _parse_nmap_xml(GOOD_XML, "10.0.0.1")
    assert parsed is not None
    assert [p.port for p in parsed["ports"]] == [21]
    assert parsed["ports"][0].product == "vsftpd"
    assert parsed["probe_confirmed"] is True  # reason="syn-ack" is a real probe


def test_parse_returns_empty_ports_on_clean_no_open_result():
    parsed = _parse_nmap_xml(EMPTY_XML, "10.0.0.1")
    assert parsed is not None and parsed["ports"] == []


# ── 2. scan_host retries without -sC when nmap's NSE crashes ───────────────────

def test_scan_host_retries_without_sc_on_nse_crash(monkeypatch):
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        if "-sC" in argv:  # the crashing default-script attempt
            return (CRASH_XML, CRASH_STDERR, 134)
        return (GOOD_XML, b"", 0)  # service-detection-only retry succeeds

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))
    res = asyncio.run(scan_host("10.0.0.1", [21]))

    assert len(calls) == 2, "expected a retry after the -sC crash"
    assert "-sC" in calls[0] and "-sC" not in calls[1]
    assert [p.port for p in res.open_ports] == [21]
    assert res.open_ports[0].product == "vsftpd"
    assert res.is_alive


# ── 3. a clean empty result is accepted, not retried ───────────────────────────

def test_scan_host_does_not_retry_a_clean_empty_result(monkeypatch):
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        return (EMPTY_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))
    res = asyncio.run(scan_host("10.0.0.1", [21]))

    assert len(calls) == 1, "a clean 'nothing open' result must not trigger a retry"
    assert res.open_ports == []


# ── 4. total nmap failure falls back to the pure-Python connect scan ───────────

def test_scan_host_falls_back_to_connect_scan_when_nmap_unusable(monkeypatch):
    def behavior(argv):
        return (b"", CRASH_STDERR, 134)  # crash on every attempt, empty stdout

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        return [ns.PortResult(host=host, port=ports[0], state="open", service="ftp")]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [21]))

    assert [p.port for p in res.open_ports] == [21]
    assert res.is_alive


# ── 5. stealth timing is bounded + reliable, and budget scales with stealth ────

@pytest.mark.parametrize("level", ["paranoid", "stealth", "normal", "aggressive"])
def test_timing_profiles_are_bounded_and_reliable(level):
    args = ns._nmap_timing_args(level)
    min_rate = int(args[args.index("--min-rate") + 1])
    retries = int(args[args.index("--max-retries") + 1])
    # No pathologically-low floor (the old paranoid --min-rate 10 could never
    # finish a real range in budget -> host cancelled -> 0 ports).
    assert min_rate >= 100
    # No single-retry port loss (that made the same target flap run-to-run).
    assert retries >= 2


def test_network_budget_scales_with_stealth():
    from heaven.config import ScanMode
    from heaven.orchestrator import build_full_scan

    def net_timeout(stealth: str) -> float:
        orch = build_full_scan(
            {"ips": ["10.0.0.1"], "ports": "1-65535", "stealth_level": stealth},
            scan_mode=ScanMode.NETWORK,
        )
        return orch.tasks[orch.net_task_id].timeout

    # A quieter profile sends far fewer packets/sec, so it needs proportionally
    # more time to converge on the SAME inventory instead of being truncated.
    assert net_timeout("paranoid") > net_timeout("normal") > net_timeout("aggressive")

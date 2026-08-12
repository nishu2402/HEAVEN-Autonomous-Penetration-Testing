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

# A clean, well-formed run that reports the host ALIVE (it refused 11 ports — the
# bulk <extraports state="closed">) yet finds NOTHING open. This is the field
# false-negative that produced "0 findings on a box I know is wide open": the XML
# parses, so the crash fallback never fires, and the empty inventory flows through
# every downstream stage (CVE mapping / exposure / EOL) as zero findings.
ANSWERED_BUT_NO_OPEN_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="user-set"/>
 <ports><extraports state="closed" count="11"/></ports></host></nmaprun>"""

# A clean, well-formed run that nmap CUT SHORT at its --host-timeout: the <host>
# carries timedout="true" and, because a full-range -sV -sC sweep of a slow /
# heavily-filtered / emulated host never gets to scan the open ports, it reports
# state="up" reason="user-set" (from -Pn) with ZERO ports and ZERO closed. This is
# the exact "scan sits for minutes then reports 0 findings on a box I know is wide
# open" case seen live against Metasploitable under UTM/QEMU.
TIMED_OUT_EMPTY_XML = b"""<?xml version="1.0"?>
<nmaprun><host timedout="true"><status state="up" reason="user-set"/>
 <ports></ports></host></nmaprun>"""

# nmap timed out AFTER finding one open port but before it could reach the rest —
# the result is INCOMPLETE, so the connect scan must complete it, not accept it.
TIMED_OUT_PARTIAL_XML = b"""<?xml version="1.0"?>
<nmaprun><host timedout="true"><status state="up" reason="user-set"/>
 <ports><port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache" version="2.2.8"/></port></ports></host></nmaprun>"""


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


# ── 4b. nmap says "all closed" on a live host → connect scan cross-checks ──────

def test_scan_host_cross_checks_connect_when_nmap_reports_0_open_on_live_host(monkeypatch):
    """nmap returns a *clean* XML (so no crash fallback) that reports the host
    alive but ZERO open ports, when the ports are in fact open. The connect-scan
    cross-check must recover them, or the whole scan yields 0 findings."""
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        return (ANSWERED_BUT_NO_OPEN_XML, b"", 0)  # valid, alive, nothing open

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    xchecked: list[bool] = []

    async def fake_connect(host, ports, **kw):
        xchecked.append(True)
        return [ns.PortResult(host=host, port=80, state="open", service="http")]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [80, 443]))

    # A clean result is not retried, so nmap ran once; the cross-check then fired.
    assert len(calls) == 1
    assert xchecked == [True], "expected a connect-scan cross-check after 0 open ports"
    assert [p.port for p in res.open_ports] == [80]
    assert res.is_alive


def test_scan_host_dead_host_probes_common_ports_only_not_full_range(monkeypatch):
    """A clean 'nothing open' result must be verified — under -Pn a firewalled but
    plainly-alive host reports reason="user-set" with 0 closed ports, so the old
    "did it answer?" gate wrongly skipped recovery and returned 0 findings. Now the
    recovery ALWAYS runs, but cheaply: it probes only the high-value service ports
    first, and when NONE answer it stops — so a genuinely dead / silent host never
    triggers a full-range connect sweep of every dead address in a /24, and no port
    is invented."""
    def behavior(argv):
        return (EMPTY_XML, b"", 0)  # up (user-set), but 0 open / 0 closed

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    probed_counts: list[int] = []

    async def fake_connect(host, ports, **kw):
        probed_counts.append(len(ports))
        return []  # nothing answers → dead / empty host

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    full_range = list(range(1, 1001))  # a broad request incl. common service ports
    res = asyncio.run(scan_host("10.0.0.1", full_range))

    # Exactly one probe — the cheap high-value set — and NOT the full range.
    assert len(probed_counts) == 1, "must not sweep the full range on a dead host"
    assert probed_counts[0] < len(full_range)
    assert res.open_ports == []


# ── 4c. nmap host-timeout (incomplete scan) → connect scan recovers/completes ──

def test_parse_flags_host_timeout():
    """A host nmap cut short at its --host-timeout is INCOMPLETE, not clean-empty:
    the parse must surface it so the caller falls back instead of accepting 0."""
    parsed = _parse_nmap_xml(TIMED_OUT_EMPTY_XML, "10.0.0.1")
    assert parsed is not None
    assert parsed["host_timed_out"] is True
    assert parsed["ports"] == []
    # A clean (non-timed-out) result must NOT be flagged.
    clean = _parse_nmap_xml(EMPTY_XML, "10.0.0.1")
    assert clean is not None and clean["host_timed_out"] is False


def test_scan_host_recovers_when_nmap_times_out_with_zero_ports(monkeypatch):
    """The headline fix: a full-range -sV -sC sweep that never finishes (host
    timed out, 0 ports, valid XML, rc 0) must NOT be accepted as '0 findings' —
    the built-in connect scanner recovers the live host's real services."""
    def behavior(argv):
        return (TIMED_OUT_EMPTY_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        # Only the high-value service ports the caller actually asked for answer.
        want = {21, 22, 80, 3306}
        return [ns.PortResult(host=host, port=p, state="open")
                for p in ports if p in want]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [21, 22, 80, 3306, 443]))

    assert [p.port for p in res.open_ports] == [21, 22, 80, 3306]
    assert res.is_alive


def test_scan_host_completes_a_partial_timed_out_nmap(monkeypatch):
    """nmap timed out after finding SOME ports: the connect scan unions in the
    ports it missed while keeping nmap's version-rich entry for the one it found."""
    def behavior(argv):
        return (TIMED_OUT_PARTIAL_XML, b"", 0)  # found :80 (Apache), then timed out

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        return [ns.PortResult(host=host, port=p, state="open")
                for p in ports if p in {80, 22, 3306}]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [22, 80, 3306]))

    by_port = {p.port: p for p in res.open_ports}
    assert set(by_port) == {22, 80, 3306}          # 22 + 3306 recovered, 80 kept
    assert by_port[80].product == "Apache"          # nmap's richer entry preserved
    assert res.is_alive


def test_connect_scan_fallback_is_common_first_and_bails_on_dead_host():
    """_connect_scan_fallback probes the high-value ports first and only sweeps the
    rest once the host proves itself alive — so a dead host is ruled out cheaply."""
    async def _run():
        seen: list[list[int]] = []

        async def fake_connect(host, ports, **kw):
            seen.append(list(ports))
            return []  # nothing answers anywhere

        import heaven.recon.network_scanner as _ns
        orig = _ns._python_connect_scan
        _ns._python_connect_scan = fake_connect
        try:
            out = await _ns._connect_scan_fallback(
                "10.0.0.1", list(range(1, 2001)), timeout=0.4)
        finally:
            _ns._python_connect_scan = orig
        return out, seen

    out, seen = asyncio.run(_run())
    assert out == []
    # Exactly one probe (the high-value set); the ~2000-port range was NOT swept.
    assert len(seen) == 1 and len(seen[0]) < 2000


def test_scan_network_bounds_nmap_host_timeout_under_budget(monkeypatch):
    """scan_network must cap nmap's per-host --host-timeout well below the deep-scan
    time_budget, so a stuck full-range nmap can't run until the orchestrator
    cancels the whole coroutine and DISCARDS the result (the '0 findings' bug)."""
    captured: dict[str, str] = {}

    async def fake_scan_host(host, ports, **kw):
        captured["host_timeout"] = kw.get("host_timeout", "")
        return ns.HostResult(host=host)

    monkeypatch.setattr(ns, "scan_host", fake_scan_host)
    asyncio.run(ns.scan_network(
        ["10.0.0.1"], port_range="1-65535", time_budget=600.0,
        passive_enrich=False,
    ))
    secs = int(captured["host_timeout"].rstrip("s"))
    assert 60 <= secs < 600, f"nmap host-timeout {secs}s must be bounded under the budget"


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

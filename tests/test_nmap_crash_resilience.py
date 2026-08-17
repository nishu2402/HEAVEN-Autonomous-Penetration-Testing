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
     the same target converges on the same inventory at every stealth level;
  6. connect-scan-recovered ports (which have NO -sV version data) are enriched by
     a targeted `-sV` on just those short ports, so the Service/Version/CPE columns
     and CVE mapping are no longer blank on a slow / heavily-filtered / emulated
     host — while a clean completed scan is NOT re-scanned (no wasted work);
  7. the enrichment happens in two ordered passes — the service band is -sV'd BEFORE
     the ephemeral/high-band completion sweep (so the flood can't starve it), and
     the freshly-swept ephemeral ports get their OWN scoped -sV only AFTER a settle
     lets the flood drain — so even dynamic RPC/OS high ports are fingerprinted.
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

# The result of the TARGETED -sV enrichment scan on the (short) recovered open-port
# list: nmap finishes instantly on a small explicit port set and returns full
# service/version detail for each — the data the connect scanner alone can't get,
# and which the inventory columns + CVE mapping need.
ENRICH_SV_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/>
 <ports>
  <port protocol="tcp" portid="21"><state state="open"/>
   <service name="ftp" product="vsftpd" version="2.3.4"/></port>
  <port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="4.7p1"/></port>
  <port protocol="tcp" portid="139"><state state="open"/>
   <service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/></port>
  <port protocol="tcp" portid="3306"><state state="open"/>
   <service name="mysql" product="MySQL" version="5.0.51a"/></port>
 </ports></host></nmaprun>"""

# A clean, COMPLETED scan (not timed out) that found an open port nmap's -sV
# couldn't identify. This is the happy path: nmap already ran -sV, so re-scanning
# it would be pure waste — the enrichment must NOT fire here.
VERSIONLESS_CLEAN_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/>
 <ports><port protocol="tcp" portid="9999"><state state="open"/></port></ports>
</host></nmaprun>"""

# Targeted -sV enrichment result for a single recovered HTTP port (:80).
ENRICH_HTTP_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/>
 <ports><port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.2.8"/></port></ports>
</host></nmaprun>"""

# The SECOND targeted -sV — over the freshly-swept ephemeral/high band — identifies
# a dynamic RPC service (the kind rpcbind hands out on a high port). This is what
# turns the previously-blank ephemeral ports into named services.
ENRICH_EPHEMERAL_XML = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/>
 <ports><port protocol="tcp" portid="50000"><state state="open"/>
  <service name="status" product="RPC status" version="1"/></port></ports>
</host></nmaprun>"""


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
    cross-check must recover them (or the whole scan yields 0 findings), and the
    version-less recovered port is then enriched by a targeted -sV."""
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        # 1st nmap = the full-range primary (clean, alive, 0 open). Any later nmap
        # = the targeted -sV enrichment of the recovered port.
        if len(calls) == 1:
            return (ANSWERED_BUT_NO_OPEN_XML, b"", 0)  # valid, alive, nothing open
        return (ENRICH_HTTP_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    xchecked: list[bool] = []

    async def fake_connect(host, ports, **kw):
        xchecked.append(True)
        return [ns.PortResult(host=host, port=80, state="open", service="http")]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [80, 443]))

    # The primary ran once (no -sC crash retry) and the cross-check then fired.
    assert calls[0][calls[0].index("-p") + 1] == "80,443"  # the full-range primary
    assert xchecked == [True], "expected a connect-scan cross-check after 0 open ports"
    assert [p.port for p in res.open_ports] == [80]
    # …and the recovered, version-less port was enriched by the targeted -sV.
    assert res.open_ports[0].product == "Apache httpd"
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


# ── 4d. targeted -sV enrichment of version-less recovered ports ────────────────
# The connect-scan recovery proves ports OPEN but does no version detection, so
# the recovered ports come back with blank product/version/CPE — which empties the
# inventory columns and starves CVE mapping. A targeted `-sV` on just those (short)
# ports finishes fast and restores the detail. These pin that behaviour.

def test_nmap_service_scan_parses_targeted_sv(monkeypatch):
    """The enrichment helper runs nmap -sV on a short port list and returns a
    {port: PortResult} map carrying the real product/version detail."""
    def behavior(argv):
        assert "-sV" in argv and "-p" in argv  # a real service scan of explicit ports
        return (ENRICH_SV_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))
    out = asyncio.run(ns._nmap_service_scan("10.0.0.1", [21, 22, 139, 3306]))

    assert set(out) == {21, 22, 139, 3306}
    assert out[21].product == "vsftpd" and out[21].version == "2.3.4"
    assert out[3306].product == "MySQL" and out[3306].version == "5.0.51a"


def test_nmap_service_scan_empty_on_no_ports():
    assert asyncio.run(ns._nmap_service_scan("10.0.0.1", [])) == {}


def test_scan_host_enriches_versionless_recovered_ports(monkeypatch):
    """The headline fix for THIS issue: a full-range sweep times out (0 ports),
    the connect scanner recovers the open ports version-less, and the targeted -sV
    enrichment then fills in product/version/CPE — so the inventory columns and CVE
    mapping are no longer blank on a slow / heavily-filtered host."""
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        # 1st nmap = the full-range primary sweep → times out with zero ports.
        # Any later nmap = the targeted -sV enrichment on the recovered ports.
        if len(calls) == 1:
            return (TIMED_OUT_EMPTY_XML, b"", 0)
        return (ENRICH_SV_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        # Connect scan proves the ports open, but WITHOUT any version data.
        want = {21, 22, 139, 3306}
        return [ns.PortResult(host=host, port=p, state="open")
                for p in ports if p in want]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [21, 22, 139, 3306, 443]))

    by_port = {p.port: p for p in res.open_ports}
    assert set(by_port) == {21, 22, 139, 3306}
    # Every recovered port now carries the -sV detail — no more blank columns.
    assert by_port[21].product == "vsftpd" and by_port[21].version == "2.3.4"
    assert by_port[22].product == "OpenSSH"
    assert by_port[139].product == "Samba smbd"
    assert by_port[3306].product == "MySQL" and by_port[3306].version == "5.0.51a"
    assert len(calls) >= 2, "expected a targeted -sV enrichment scan after recovery"
    assert res.is_alive


def test_scan_host_skips_enrichment_on_clean_completed_scan(monkeypatch):
    """No wasted re-scan on the happy path: a clean COMPLETED nmap already ran -sV,
    so even a version-less open port must NOT trigger a second targeted scan."""
    calls: list[list] = []

    def behavior(argv):
        calls.append(argv)
        return (VERSIONLESS_CLEAN_XML, b"", 0)  # clean, one open port, no version

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):  # pragma: no cover - must not fire
        raise AssertionError("connect scan / enrichment must not run on a clean scan")

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)
    res = asyncio.run(scan_host("10.0.0.1", [9999]))

    assert len(calls) == 1, "a clean completed scan must not trigger an enrichment scan"
    assert [p.port for p in res.open_ports] == [9999]


def test_scan_host_enriches_service_band_first_then_ephemeral_after_settle(monkeypatch):
    """Both bands get fingerprinted, in a load-bearing order:

      1. the service-band -sV runs BEFORE the full-range completion sweep — on a
         fragile / slow / emulated host the flood (tens of thousands of connections)
         leaves it (and the scanner's local port pool) unresponsive, starving any
         -sV that runs during it (the live "ports show but Service/Version/CVE are
         blank" bug);
      2. the freshly-swept ephemeral/high ports then get their OWN -sV — but only
         after a settle so the flood has drained, otherwise it would be starved too.
    """
    events: list[str] = []
    ephemeral_argv: list[list] = []

    def behavior(argv):
        joined = " ".join(str(a) for a in argv)
        if "nmap:primary" not in events:
            events.append("nmap:primary")           # full-range sweep → times out
            return (TIMED_OUT_EMPTY_XML, b"", 0)
        if "50000" in joined:
            events.append("nmap:enrich-ephemeral")  # 2nd -sV, scoped to the high band
            ephemeral_argv.append(argv)
            return (ENRICH_EPHEMERAL_XML, b"", 0)
        events.append("nmap:enrich-service")        # 1st -sV, the service band
        return (ENRICH_SV_XML, b"", 0)

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        if ports and all(p > ns._SERVICE_PORT_CEILING for p in ports):
            events.append("connect:ephemeral")      # the flood band
            return [ns.PortResult(host=host, port=50000, state="open")]
        events.append("connect:service")
        return [ns.PortResult(host=host, port=p, state="open")
                for p in ports if p in {21, 22, 139, 3306}]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)

    # Record the inter-pass settle without actually waiting (keeps the test fast).
    async def recording_sleep(secs):
        events.append(f"settle:{secs}")

    monkeypatch.setattr(ns.asyncio, "sleep", recording_sleep)
    res = asyncio.run(scan_host("10.0.0.1", ns.parse_port_range("1-65535"),
                                enrich_host_timeout="30s",
                                ephemeral_enrich_host_timeout="20s"))

    # (1) service-band -sV precedes the ephemeral flood
    assert events.index("nmap:enrich-service") < events.index("connect:ephemeral"), \
        "the service-band -sV must precede the ephemeral flood"
    # (2) a settle of exactly _ENRICH_SETTLE_SECONDS sits between the flood and the
    #     ephemeral -sV — so the flood can't starve it
    settle_marker = f"settle:{ns._ENRICH_SETTLE_SECONDS}"
    assert settle_marker in events, "the inter-pass settle must be honored"
    assert (events.index("connect:ephemeral")
            < events.index(settle_marker)
            < events.index("nmap:enrich-ephemeral")), \
        "the ephemeral -sV must run AFTER the flood settles"
    by_port = {p.port: p for p in res.open_ports}
    assert by_port[21].product == "vsftpd"           # service band enriched
    assert by_port[3306].product == "MySQL"
    assert by_port[50000].product == "RPC status"    # ephemeral port NOW enriched too
    # (3) the ephemeral pass forces a CONNECT scan (-sT): these ports answer a full
    #     handshake but not a bare SYN on a filtered/emulated host, so a SYN-based
    #     enrichment (when HEAVEN runs nmap privileged) would see them filtered.
    assert ephemeral_argv, "the ephemeral -sV pass must have run"
    assert "-sT" in ephemeral_argv[0], "the ephemeral pass must force a connect scan"


def test_scan_host_ephemeral_pass_includes_rpcbind_context(monkeypatch):
    """The dynamic RPC high ports only resolve when nmap is given the rpcbind port
    (111) in the same scan — without it a dynamically-assigned RPC port stays
    `unknown`. The ephemeral enrichment must therefore include any open rpcbind
    port as CONTEXT (scanned, but not merged over)."""
    ephemeral_argv: list[list] = []

    def behavior(argv):
        joined = " ".join(str(a) for a in argv)
        if "50000" in joined:                        # the ephemeral enrichment pass
            ephemeral_argv.append(argv)
            return (ENRICH_EPHEMERAL_XML, b"", 0)
        return (TIMED_OUT_EMPTY_XML, b"", 0)          # primary sweep → times out

    monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec(behavior))

    async def fake_connect(host, ports, **kw):
        if ports and all(p > ns._SERVICE_PORT_CEILING for p in ports):
            return [ns.PortResult(host=host, port=50000, state="open")]
        # service band: an open rpcbind on 111 (already service-labelled)
        return [ns.PortResult(host=host, port=111, state="open", service="rpcbind")]

    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)

    async def instant_sleep(_secs):
        return None

    monkeypatch.setattr(ns.asyncio, "sleep", instant_sleep)
    res = asyncio.run(scan_host("10.0.0.1", ns.parse_port_range("1-65535"),
                                ephemeral_enrich_host_timeout="20s"))

    assert ephemeral_argv, "the ephemeral -sV pass must have run"
    argv = ephemeral_argv[0]
    # rpcbind (111) is scanned as CONTEXT alongside the ephemeral target…
    port_spec = argv[argv.index("-p") + 1]
    assert "111" in port_spec.split(","), "rpcbind must be scanned as RPC context"
    assert "50000" in port_spec.split(","), "the ephemeral target must be scanned"
    # …but the context port is never overwritten by the enrichment merge.
    by_port = {p.port: p for p in res.open_ports}
    assert by_port[111].service == "rpcbind"         # context port left intact
    assert by_port[50000].product == "RPC status"    # ephemeral target enriched


def test_scan_network_bounds_enrich_host_timeout_under_budget(monkeypatch):
    """scan_network must reserve a bounded slice of the deep-scan budget for the
    targeted enrichment, so primary nmap + connect scan + enrichment all finish
    inside time_budget (and the host result is kept, not cancelled-and-discarded)."""
    captured: dict[str, str] = {}

    async def fake_scan_host(host, ports, **kw):
        captured["enrich"] = kw.get("enrich_host_timeout", "")
        captured["primary"] = kw.get("host_timeout", "")
        return ns.HostResult(host=host)

    monkeypatch.setattr(ns, "scan_host", fake_scan_host)
    asyncio.run(ns.scan_network(
        ["10.0.0.1"], port_range="1-65535", time_budget=600.0,
        passive_enrich=False,
    ))
    enrich = int(captured["enrich"].rstrip("s"))
    primary = int(captured["primary"].rstrip("s"))
    assert 30 <= enrich <= 180, f"enrich host-timeout {enrich}s must be small + bounded"
    assert primary + enrich < 600, "primary + enrichment must both fit under the budget"


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

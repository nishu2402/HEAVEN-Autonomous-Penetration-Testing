"""Regression tests for the Metasploitable-2 network-scan accuracy audit.

These lock in the fixes for the "many findings before, few now" regression found
by scanning a live Metasploitable-2 host whose emulated (QEMU-TCG) CPU is too slow
for a bulk ``nmap -sV`` to finish, so version detection fell back to a banner path
that (a) omitted the signature services and (b) let a NetBIOS reply mislabel the
Linux host as Windows.

Everything here is deterministic — it feeds the REAL banners Metasploitable-2
presents into the pure fingerprint / mapping / OS-hint functions, so it needs no
live host and no nmap.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from heaven.recon.network_scanner import (
    HostResult,
    PortResult,
    _BANNER_READ_PORTS,
    _ENRICH_PRIORITY_PORTS,
    _IRC_PORTS,
    _os_hint_from_banners,
)
from heaven.vulnscan.cve_mapper import (
    _fingerprint_from_banner,
    map_vulnerabilities,
)


# ── Banner fingerprinting: the signature MSF2 services ──────────────────────

@pytest.mark.parametrize("banner,product,version", [
    ("220 (vsFTPd 2.3.4)", "vsftpd", "2.3.4"),
    ("500 OOPS: vsftpd: refusing to run with writable root", "vsftpd", ""),
    ("SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1", "openssh", "4.7p1"),
    ("Samba smbd 3.0.20-Debian", "samba", "3.0.20"),
    ("Unreal3.2.8.1", "unrealircd", "3.2.8.1"),
    (":irc.Metasploitable.LAN 351 Unreal3.2.8.1. irc.X", "unrealircd", "3.2.8.1"),
    ("distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))", "distccd", "4.2.4"),
    ("220 ProFTPD 1.3.1 Server (Debian)", "proftpd", "1.3.1"),
])
def test_banner_fingerprints_resolve_signature_products(banner, product, version):
    fp = _fingerprint_from_banner(banner)
    assert fp is not None, f"no fingerprint for {banner!r}"
    assert fp[0] == product
    assert fp[1] == version


def test_ssh_version_is_product_not_protocol():
    # Must extract the OpenSSH build (4.7p1), never the "2.0" SSH-protocol token.
    _, ver = _fingerprint_from_banner("SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1")
    assert ver == "4.7p1"


# ── CVE mapping: given the banners, the signature RCEs must fire ────────────

async def _map(open_ports):
    host = {"host": "10.0.0.5", "ip": "10.0.0.5", "open_ports": open_ports}
    return await map_vulnerabilities([host], live_feed=None)


@pytest.mark.asyncio
async def test_signature_rces_fire_from_banners_alone():
    vulns = await _map([
        {"port": 21, "service": "ftp", "banner": "220 (vsFTPd 2.3.4)"},
        {"port": 139, "service": "netbios-ssn", "banner": "Samba smbd 3.0.20-Debian"},
        {"port": 6667, "service": "irc", "banner": "Unreal3.2.8.1"},
        {"port": 3632, "service": "distccd", "banner": "distccd v1 ((GNU) 4.2.4)"},
    ])
    cves = {v.get("cve") for v in vulns}
    assert "CVE-2011-2523" in cves   # vsftpd 2.3.4 backdoor
    assert "CVE-2007-2447" in cves   # Samba usermap RCE
    assert "CVE-2010-2075" in cves   # UnrealIRCd 3.2.8.1 backdoor
    assert "CVE-2004-2687" in cves   # distccd RCE


@pytest.mark.asyncio
async def test_distccd_fires_confirmed_even_without_a_version():
    # distccd's affected range is unconditional ("all") — a bare product match
    # is enough. It must be a CONFIRMED vulnerable_service, not demoted to a
    # low "potential_vulnerable_service".
    vulns = await _map([
        {"port": 3632, "service": "distccd", "banner": "distccd"},
    ])
    distcc = [v for v in vulns if v.get("cve") == "CVE-2004-2687"]
    assert distcc, "distccd CVE-2004-2687 should fire version-less"
    assert distcc[0]["vuln_type"] == "vulnerable_service"
    assert distcc[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_unrealircd_stays_potential_without_the_exact_build():
    # The backdoor is pinned to the trojaned 3.2.8.1 tarball, so a version-less
    # UnrealIRCd must NOT be asserted as the confirmed backdoor.
    vulns = await _map([
        {"port": 6667, "service": "irc", "banner": "UnrealIRCd"},
    ])
    confirmed = [v for v in vulns
                 if v.get("cve") == "CVE-2010-2075"
                 and v.get("vuln_type") == "vulnerable_service"]
    assert not confirmed, "version-less UnrealIRCd must not assert the backdoor"


@pytest.mark.asyncio
async def test_irc_probe_registers_before_asking_for_version(monkeypatch):
    """UnrealIRCd only emits the build-bearing 002/004/351 numerics once the
    client has registered, so a bare ``VERSION`` (the old probe) never captured
    "Unreal3.2.8.1" and the backdoor CVE could not be confirmed live. Stand up a
    fake ircd that withholds the version until it sees NICK+USER, and assert the
    probe now registers first and comes back with the exact build (which the
    version-aware mapper turns into the confirmed CVE-2010-2075 critical).
    """
    # Resolve the module at RUN time: sibling tests (e.g. test_advanced) nuke
    # ``sys.modules['heaven*']``, so a name imported at collection can point at a
    # stale module object while monkeypatch patches the live one. Patching and
    # calling through the same live object keeps them in lock-step.
    import importlib
    ns = importlib.import_module("heaven.recon.network_scanner")
    cve = importlib.import_module("heaven.vulnscan.cve_mapper")

    async def handle(reader, writer):
        # Greet with a hostname-lookup NOTICE only: no version pre-registration.
        writer.write(b":irc.fake NOTICE AUTH :*** Looking up your hostname...\r\n")
        with contextlib.suppress(Exception):
            await writer.drain()
        buf = b""
        registered = False
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(256), timeout=2.0)
                if not chunk:
                    break
                buf += chunk
                if not registered and b"NICK" in buf and b"USER" in buf:
                    registered = True
                    writer.write(
                        b":irc.fake 001 hvnscan :Welcome\r\n"
                        b":irc.fake 002 hvnscan :Your host is irc.fake, "
                        b"running version Unreal3.2.8.1\r\n"
                        b":irc.fake 004 hvnscan irc.fake Unreal3.2.8.1 abc\r\n"
                    )
                    await writer.drain()
                if registered and b"VERSION" in buf:
                    writer.write(
                        b":irc.fake 351 hvnscan Unreal3.2.8.1. irc.fake :FhiXOoE\r\n")
                    await writer.drain()
                    break
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    # Treat this ephemeral port as an IRC port so the probe takes the IRC path.
    # Patch a SUPERSET (keep the real IRC ports) so this never removes 6667 for a
    # sibling test, and wrap the probe in a hard timeout so a stuck socket can
    # never hang the run.
    monkeypatch.setattr(ns, "_IRC_PORTS", frozenset(ns._IRC_PORTS | {port}))
    try:
        async with server:
            banner = await asyncio.wait_for(
                ns._grab_banner("127.0.0.1", port, 3.0), timeout=10.0)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()

    assert "Unreal3.2.8.1" in banner, (
        f"IRC probe must register then read the version; got {banner!r}")
    assert cve._fingerprint_from_banner(banner) == ("unrealircd", "3.2.8.1")


def _irc_host(product="UnrealIRCd", version=""):
    hr = HostResult(host="10.0.0.9")
    hr.open_ports = [PortResult(host="10.0.0.9", port=6667, protocol="tcp",
                                state="open", service="irc",
                                product=product, version=version)]
    return hr


@pytest.mark.asyncio
async def test_enrich_irc_fills_version_and_enables_confirmed_backdoor(monkeypatch):
    # nmap reports the product but no version, so the finding would stay a
    # version-less "potential". The IRC VERSION probe recovers the exact build,
    # which is what lets the mapper confirm the backdoor. Real capture only.
    import importlib
    ns = importlib.import_module("heaven.recon.network_scanner")
    monkeypatch.setattr(ns, "_IRC_PORTS", frozenset({6667}))
    async def fake_grab(host, port, timeout):
        return ":irc 002 x :running version Unreal3.2.8.1"
    monkeypatch.setattr(ns, "_grab_banner", fake_grab)
    hr = _irc_host()
    await ns._enrich_irc_versions(hr, "10.0.0.9", 3.0)
    assert hr.open_ports[0].version == "3.2.8.1"
    # And that version now yields the CONFIRMED critical (not a low potential).
    vulns = await _map([
        {"port": 6667, "service": "irc", "product": "UnrealIRCd",
         "version": hr.open_ports[0].version, "banner": hr.open_ports[0].banner},
    ])
    assert any(v.get("cve") == "CVE-2010-2075" and v.get("severity") == "critical"
               for v in vulns), "3.2.8.1 must confirm the backdoor as critical"


@pytest.mark.asyncio
async def test_enrich_irc_probes_each_port_once_no_throttle_retry(monkeypatch):
    # UnrealIRCd extends its reconnect-throttle on every reconnect, so retrying is
    # useless AND needless load on the target: the enrichment must probe each port
    # exactly once (never a retry storm).
    import importlib
    ns = importlib.import_module("heaven.recon.network_scanner")
    monkeypatch.setattr(ns, "_IRC_PORTS", frozenset({6667}))
    calls = {"n": 0}
    async def throttled(host, port, timeout):
        calls["n"] += 1
        return "ERROR :Closing Link: [x] (Throttled: Reconnecting too fast)"
    monkeypatch.setattr(ns, "_grab_banner", throttled)
    hr = _irc_host()  # one open IRC port
    await ns._enrich_irc_versions(hr, "10.0.0.9", 3.0)
    assert calls["n"] == 1, "one probe per port: retrying only prolongs the throttle"
    # A throttled daemon leaves the port version-less, so it stays an HONEST low
    # "potential" carrying the CVE candidate and is never asserted as the backdoor.
    assert hr.open_ports[0].version == ""


# ── OS false positive: Samba-on-Linux must never read as Windows ────────────

def _ports(*specs):
    out = []
    for port, banner in specs:
        out.append(PortResult(host="h", port=port, protocol="tcp",
                              state="open", banner=banner))
    return out


def test_os_hint_calls_samba_linux_host_linux_not_windows():
    # SSH advertises Debian; SMB is present. The Linux banner must win.
    ports = _ports(
        (22, "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"),
        (445, ""),   # microsoft-ds, binary, no banner
    )
    assert _os_hint_from_banners(ports) == "Linux"


def test_os_hint_does_not_infer_windows_from_smb_alone():
    # A bare SMB port with no OS banner must NOT be called Windows — that is the
    # Samba-on-Unix false positive. Empty hint lets a real Windows signal (or the
    # legitimate NBSTAT path on a host with NOTHING else) decide.
    assert _os_hint_from_banners(_ports((445, ""), (139, ""))) == ""


def test_os_hint_detects_genuine_windows_banner():
    ports = _ports((80, "Microsoft-IIS/7.5"), (445, ""))
    assert _os_hint_from_banners(ports) == "Windows"


def test_os_hint_empty_for_no_banners():
    assert _os_hint_from_banners([]) == ""
    assert _os_hint_from_banners(_ports((3632, ""))) == ""


# ── Banner-capture coverage: the ports the regression missed ────────────────

def test_banner_read_set_covers_the_previously_missed_services():
    # UnrealIRCd (6667), VNC (5900), ProFTPD (2121) were open on MSF2 but never
    # banner-grabbed, so their versions — and CVEs — vanished.
    for port in (6667, 5900, 2121):
        assert port in _BANNER_READ_PORTS, f"port {port} must be banner-grabbed"
    assert 6667 in _IRC_PORTS


def test_enrich_priority_covers_cve_bearing_services():
    for port in (139, 445, 3632, 6667, 5900, 3306, 5432):
        assert port in _ENRICH_PRIORITY_PORTS

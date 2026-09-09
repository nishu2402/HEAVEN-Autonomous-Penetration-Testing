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

import pytest

from heaven.recon.network_scanner import (
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

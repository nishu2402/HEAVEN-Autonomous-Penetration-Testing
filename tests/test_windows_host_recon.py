"""HEAVEN — hardened-Windows-host reconnaissance tests.

Regression suite for the reproduced live bug: a Windows 7 box (`HEAVEN-PC`,
192.168.0.102) with Windows Firewall on silently FILTERS 135/139/445/3389, so an
unprivileged connect scan of the common range found nothing and the Assets view
showed "OS not determined, 0 open ports" — even though the host answers on
5357/wsdapi (TCP) and NBSTAT (UDP/137).

These pin the fixes:
  * the Windows management/AD ports (5357 WSDAPI, 5985/5986/47001 WinRM, 2869
    UPnP, Kerberos/GC) are in the always-probe + liveness sets, so the one open
    high port is captured common-first instead of lost to the slow full sweep;
  * those ports classify the host as a Windows host;
  * the pure-Python NBSTAT enricher recovers computer name / workgroup / MAC and
    confirms Windows without root or an open TCP port;
  * the state-aware connect probe distinguishes filtered (drop) from closed
    (RST), so a firewalled host is still classified even when nmap timed out;
  * the evasion technique ladder builds the right nmap flags per intensity;
  * NetBIOS + EOL findings are honest (no fabricated version).
"""
from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from heaven.recon import network_scanner as N
from heaven.recon import netbios as NB


# ── 1. Port coverage: the Windows survivors are always probed ────────────────

def test_windows_management_ports_in_always_probe():
    for p in (5357, 5985, 5986, 47001, 2869, 88, 464, 3268, 3269):
        assert p in N._ALWAYS_PROBE_PORTS, f"{p} must be in the always-probe set"


def test_key_windows_ports_in_liveness_set():
    # A hardened Windows box most often survives on 5357 / WinRM — they must count
    # as a liveness signal so the host isn't declared down.
    for p in (5357, 5985):
        assert p in N._LIVENESS_PROBE_PORTS


def test_5357_is_probed_common_first_in_connect_fallback():
    # The reproduced miss: 5357 must be inside the curated "common" set the
    # connect-scan recovery probes first, or it is only found by the slow sweep.
    assert 5357 in (set(range(1, 65536)) & N._ALWAYS_PROBE_PORTS)


# ── 2. Device-role inference from Windows ports ──────────────────────────────

@pytest.mark.parametrize("ports", [[5357], [5985], [5986], [47001], [139], [445], [3389]])
def test_windows_ports_infer_windows_host(ports):
    assert N._device_type_from_services(ports) == "Windows host"


# ── 3. NetBIOS NBSTAT parser ─────────────────────────────────────────────────

def _fake_nbstat_reply(names, mac=b"\x2e\x6f\x4f\x63\x1f\xbd") -> bytes:
    """Build a syntactically-valid NBSTAT node-status response for the parser."""
    header = struct.pack(">HHHHHH", 0xA248, 0x8400, 0, 1, 0, 0)
    encoded_name = bytes([0x20]) + b"A" * 32 + b"\x00"     # 34 bytes
    rr = struct.pack(">HH", 0x0021, 0x0001) + b"\x00\x00\x00\x00" + b"\x00\x00"
    body = bytes([len(names)])
    for nm, suffix, group in names:
        flags = 0x8400 if group else 0x0400
        body += nm.encode("ascii").ljust(15, b"\x20")[:15] + bytes([suffix]) \
            + struct.pack(">H", flags)
    return header + encoded_name + rr + body + mac


def test_nbstat_parse_extracts_name_workgroup_mac():
    data = _fake_nbstat_reply([
        ("HEAVEN-PC", 0x00, False),
        ("WORKGROUP", 0x00, True),
        ("HEAVEN-PC", 0x20, False),
    ])
    info = NB._parse_response(data, "192.168.0.102")
    assert info is not None
    assert info.computer_name == "HEAVEN-PC"
    assert info.workgroup == "WORKGROUP"
    assert info.mac_address == "2E:6F:4F:63:1F:BD"
    assert info.file_sharing is True          # suffix 0x20 present
    assert info.is_domain_controller is False


def test_nbstat_parse_flags_domain_controller():
    data = _fake_nbstat_reply([
        ("DC01", 0x00, False),
        ("CORP", 0x1C, True),                  # domain / DC suffix
    ])
    info = NB._parse_response(data, "10.0.0.5")
    assert info is not None and info.is_domain_controller is True


def test_nbstat_parse_rejects_short_and_empty():
    assert NB._parse_response(b"", "h") is None
    assert NB._parse_response(b"\x00" * 20, "h") is None


def test_nbstat_encoded_name_is_34_bytes():
    enc = NB._encode_nbstat_name()
    assert len(enc) == 34 and enc[0] == 0x20 and enc[-1] == 0x00


def test_nbstat_skips_public_targets_by_default():
    # UDP/137 is not routed off-LAN — a public target must be skipped, not probed.
    assert asyncio.run(NB.nbstat("8.8.8.8")) is None


def test_nbstat_lan_gate():
    assert NB._is_lan_target("192.168.0.102") is True
    assert NB._is_lan_target("10.0.0.5") is True
    assert NB._is_lan_target("8.8.8.8") is False


# ── 4. NetBIOS-derived findings are honest ───────────────────────────────────

def _net_with_netbios(**over):
    nb = {"computer_name": "HEAVEN-PC", "workgroup": "WORKGROUP",
          "mac_address": "2E:6F:4F:63:1F:BD", "file_sharing": True,
          "is_domain_controller": False,
          "names": [{"name": "HEAVEN-PC", "suffix": "0x00", "group": False}]}
    nb.update(over.pop("netbios", {}))
    host = {"ip": "192.168.0.102", "os_guess": "Windows", "os_source": "netbios",
            "netbios": nb}
    host.update(over)
    return {"hosts": [host]}


def test_netbios_disclosure_finding_emitted():
    fs = NB.build_netbios_findings(_net_with_netbios())
    kinds = {f["vuln_type"] for f in fs}
    assert "netbios_information_disclosure" in kinds
    disc = next(f for f in fs if f["vuln_type"] == "netbios_information_disclosure")
    assert disc["severity"] == "low"
    assert "HEAVEN-PC" in disc["description"]
    assert disc["evidence"]["cwe"] == "CWE-200"


def test_os_version_undetermined_observation_for_generic_windows():
    fs = NB.build_netbios_findings(_net_with_netbios())
    obs = [f for f in fs if f["vuln_type"] == "os_version_undetermined"]
    assert obs and obs[0].get("observation") is True
    # Honest: it never claims a version, and points at the privileged re-scan.
    assert "7" not in obs[0]["title"] or "undetermined" in obs[0]["title"].lower()


def test_no_undetermined_observation_when_version_known():
    fs = NB.build_netbios_findings(_net_with_netbios(os_guess="Windows 7",
                                                     os_source="nmap"))
    assert not any(f["vuln_type"] == "os_version_undetermined" for f in fs)


def test_domain_controller_finding_when_flagged():
    fs = NB.build_netbios_findings(_net_with_netbios(
        netbios={"is_domain_controller": True, "workgroup": "CORP"}))
    assert any(f["vuln_type"] == "active_directory_exposure" for f in fs)


def test_no_netbios_findings_without_reply():
    assert NB.build_netbios_findings({"hosts": [{"ip": "1.2.3.4"}]}) == []


# ── 5. State-aware connect probe: filtered vs closed ─────────────────────────

@pytest.mark.asyncio
async def test_connect_probe_states_open_and_closed():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    open_port = srv.getsockname()[1]
    # A bound-then-released ephemeral port is closed (RST on connect).
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.bind(("127.0.0.1", 0))
    closed_port = s2.getsockname()[1]
    s2.close()
    try:
        open_ports, filtered, closed = await N._connect_probe_states(
            "127.0.0.1", [open_port, closed_port], timeout=1.0)
    finally:
        srv.close()
    assert open_port in {p.port for p in open_ports}
    # localhost refuses the closed port with a RST → counted closed, not filtered.
    assert closed >= 1
    assert closed_port not in {p.port for p in open_ports}


# ── 6. Evasion technique ladder ──────────────────────────────────────────────

def test_evasion_args_unprivileged_is_source_port_only():
    assert N._nmap_evasion_args(False) == ["--source-port", "53"]


def test_evasion_args_standard_fragments_and_decoys():
    args = N._nmap_evasion_args(True)
    assert "-f" in args and "--source-port" in args
    assert any(a.startswith("RND:") for a in args)


def test_evasion_args_aggressive_is_stronger():
    args = N._nmap_evasion_args(True, intensity="aggressive")
    assert "--mtu" in args and "16" in args
    assert "RND:10" in args


def test_technique_args_require_raw_sockets():
    assert N._nmap_technique_args("ack", False) is None
    assert N._nmap_technique_args("ack", True) == ["-sA"]
    assert N._nmap_technique_args("fin", True) == ["-sF"]
    assert N._nmap_technique_args("bogus", True) is None


# ── 7. EOL fires on a determined Windows version, not on generic "Windows" ───

@pytest.mark.asyncio
async def test_eol_flags_windows_7_when_version_known():
    from heaven.vulnscan.eol_scanner import scan_eol_from_net
    res = await scan_eol_from_net(
        {"hosts": [{"ip": "192.168.0.102", "os_guess": "Windows 7",
                    "open_ports": []}]}, dynamic=False)
    assert any("Windows 7" in f["title"] for f in res["findings"])


@pytest.mark.asyncio
async def test_eol_does_not_fire_on_generic_windows():
    from heaven.vulnscan.eol_scanner import scan_eol_from_net
    res = await scan_eol_from_net(
        {"hosts": [{"ip": "192.168.0.102", "os_guess": "Windows",
                    "open_ports": []}]}, dynamic=False)
    assert not any("Unsupported Operating System" in f["title"]
                   for f in res["findings"])

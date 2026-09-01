"""Tests for the sniffing / internal-MITM susceptibility probe
(heaven.recon.mitm_probe). Packet builders and the NBSTAT parser are exercised
against a synthetic response so the logic is verified without live traffic.
"""
from __future__ import annotations

import asyncio
import struct

from heaven.recon import mitm_probe as m


def _make_nbstat_response(names: list[tuple[str, int]]) -> bytes:
    """Build a minimal NBSTAT response (QDCOUNT=0, one answer RR) for parsing."""
    header = b"\x92\xe2\x84\x00" + struct.pack(">HHHH", 0, 1, 0, 0)
    # Answer name: the encoded wildcard '*' (0x20 + 32 bytes + null) mirrors a real
    # reply; the parser only needs to walk past it.
    enc = bytearray([0x20])
    star = b"*" + b"\x00" * 15
    for byte in star:
        enc.append(0x41 + (byte >> 4))
        enc.append(0x41 + (byte & 0x0F))
    enc.append(0x00)
    rr_fixed = struct.pack(">HH", 0x21, 0x01) + b"\x00\x00\x00\x00"  # type, class, ttl
    rdata = bytes([len(names)])
    for name, suffix in names:
        rdata += name.ljust(15)[:15].encode("ascii") + bytes([suffix]) + b"\x00\x00"
    rr = bytes(enc) + rr_fixed + struct.pack(">H", len(rdata)) + rdata
    return header + rr


def test_nbstat_parser_decodes_name_table():
    resp = _make_nbstat_response([("METASPLOITABLE", 0x00), ("WORKGROUP", 0x1D)])
    names = m._parse_nbstat_names(resp)
    assert ("METASPLOITABLE", 0x00) in names
    assert ("WORKGROUP", 0x1D) in names


def test_host_name_from_nbt_prefers_workstation_suffix():
    names = [("WORKGROUP", 0x00), ("SRV01", 0x00), ("SRV01", 0x20)]
    # First <00> UNIQUE workstation name wins.
    assert m._host_name_from_nbt(names) == "WORKGROUP"


def test_nbstat_parser_ignores_empty_or_short():
    assert m._parse_nbstat_names(b"") == []
    assert m._parse_nbstat_names(b"\x00" * 8) == []


def test_llmnr_query_is_wellformed_dns():
    pkt = m._llmnr_query("SRV01")
    # QDCOUNT=1, first label length matches "SRV01"
    assert struct.unpack(">H", pkt[4:6])[0] == 1
    assert pkt[12] == len("SRV01")
    assert pkt.endswith(struct.pack(">HH", 1, 1))  # A, IN


def test_mdns_query_targets_service_enumeration():
    pkt = m._mdns_query()
    assert b"_services" in pkt and b"_dns-sd" in pkt and b"local" in pkt
    assert pkt.endswith(struct.pack(">HH", 12, 1))  # PTR, IN


def test_skip_dns_name_handles_pointer_and_labels():
    # label sequence "ab" then root
    seq = b"\x02ab\x00rest"
    assert m._skip_dns_name(seq, 0) == 4
    # compression pointer
    ptr = b"\xc0\x0crest"
    assert m._skip_dns_name(ptr, 0) == 2


def test_nbtns_finding_shape():
    f = m._nbtns_finding("10.0.0.5", [("SRV01", 0x00), ("DOMAIN", 0x1C)])
    assert f["vuln_type"] == "nbtns_poisoning"
    assert f["severity"] == "high"
    assert f["evidence"]["cwe"] == "CWE-290"
    assert f["evidence"]["mitre"].startswith("T1557")
    assert "Responder" in f["evidence"]["attack_tools"]


def test_mitm6_finding_only_when_dual_stack():
    f = m._mitm6_finding("10.0.0.5", "fe80::1")
    assert f["vuln_type"] == "ipv6_mitm6"
    assert f["evidence"]["ipv6_address"] == "fe80::1"


def test_hosts_from_net_data_extracts_ipv6():
    net = {"hosts": [{"ip": "10.0.0.5", "addresses": ["10.0.0.5", "fe80::1"]}]}
    assert m._hosts_from_net_data(net) == [("10.0.0.5", "fe80::1")]


def test_scan_mitm_empty_is_safe():
    out = asyncio.run(m.scan_mitm_targets(net_data={}, targets=[]))
    assert out["findings"] == []


def test_mitm_vuln_types_have_kb_and_methodology():
    from heaven.devsecops.vuln_kb import lookup
    from heaven.methodology import modules_for_vuln

    for vt in ("nbtns_poisoning", "llmnr_poisoning", "mdns_exposure", "ipv6_mitm6"):
        assert lookup(vt).get("cwe"), vt
        assert "mitm_probe" in modules_for_vuln(vt), vt

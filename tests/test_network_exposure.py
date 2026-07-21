"""Network service exposure analyzer — turns a router/switch/host inventory into
findings (the fix for "scan a Cisco device → No findings recorded"), without
false positives on a hardened host. SNMP default-community probing is disabled
in these tests so nothing touches the network."""
from __future__ import annotations

import asyncio

from heaven.recon import network_exposure as nx
from heaven.devsecops.vuln_kb import enrich_finding


def _run(coro):
    return asyncio.run(coro)


def test_cisco_like_device_produces_findings():
    net = {"hosts": [{"ip": "192.168.1.1", "open_ports": [
        {"port": 23, "service": "telnet"},
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"},
        {"port": 161, "service": "snmp"},
        {"port": 4786, "service": "cisco-smi"},
        {"port": 22, "service": "ssh"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    types = {f["vuln_type"] for f in res["findings"]}
    assert "cleartext_service" in types          # telnet
    assert "snmp_exposed" in types               # snmp (probe off → exposed, not proven)
    assert "cisco_smart_install" in types        # SMI
    # every finding carries taxonomy after enrichment
    for f in res["findings"]:
        e = enrich_finding(f)
        assert e.get("cwe") and e.get("cvss_vector")


def test_hardened_host_has_no_false_positives():
    # Only SSH + HTTPS — no cleartext, no SNMP, no SMI.
    net = {"hosts": [{"ip": "10.0.0.5", "open_ports": [
        {"port": 22, "service": "ssh"},
        {"port": 443, "service": "https"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert res["findings"] == []


def test_ambiguous_service_name_does_not_trigger_cleartext():
    # A random service literally named "shell"/"login" on an unrelated port must
    # NOT be flagged (exact-token match only, never substring).
    net = {"hosts": [{"ip": "10.0.0.9", "open_ports": [
        {"port": 9999, "service": "someshell-thing"},
        {"port": 8443, "service": "https-alt"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert res["findings"] == []


def test_telnet_on_nonstandard_port_matched_by_service_name():
    net = {"hosts": [{"ip": "10.0.0.7", "open_ports": [
        {"port": 2323, "service": "telnet"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert any(f["vuln_type"] == "cleartext_service" for f in res["findings"])


def test_snmp_packet_is_well_formed_ber():
    pkt = nx._snmp_get_packet("public", 0x3039, nx.SYS_DESCR_OID)
    assert pkt[0] == 0x30            # outer SEQUENCE
    assert b"public" in pkt          # community string
    assert 0xA0 in pkt               # GetRequest-PDU tag
    # sysDescr OID bytes present in the varbind
    assert nx.SYS_DESCR_OID in pkt


def test_extract_sysdescr_requires_getresponse():
    # A packet without a GetResponse (0xA2) PDU is not a valid SNMP answer.
    assert nx._extract_sysdescr(b"\x30\x05not-snmp", nx.SYS_DESCR_OID) is None

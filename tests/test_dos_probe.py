"""Tests for the DoS/DDoS susceptibility probe (heaven.vulnscan.dos_probe).

These verify the *logic* (packet builders, the amplification floor that keeps a
non-amplifying reply from being reported, finding shape, severity) without
sending any real traffic — the network I/O is exercised live in the audit runs,
not in CI.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import dos_probe as d


def test_all_reflector_builders_emit_nonempty_bytes():
    for r in d._REFLECTORS:
        pkt = r.build()
        assert isinstance(pkt, bytes) and len(pkt) > 0, r.name


def test_ntp_monlist_is_the_classic_amplifier_request():
    # mode 7 (private), impl 3 (XNTPD), request code 42 (MON_GETLIST_1)
    pkt = d._ntp_monlist_request()
    assert pkt[0] == 0x17 and pkt[3] == 0x2A


def test_usable_reflector_floor_rejects_non_amplifying_reply():
    # A DNS server that REFUSES echoes ~the request back (BAF < 1) — never a finding.
    dns = next(r for r in d._REFLECTORS if r.name.startswith("DNS"))
    assert d._is_usable_reflector(dns, 0.9) is False
    assert d._is_usable_reflector(dns, 1.0) is False
    # A generic vector needs BAF >= 2 to count as a usable weapon.
    assert d._is_usable_reflector(dns, 1.9) is False
    assert d._is_usable_reflector(dns, 2.0) is True


def test_named_cve_vectors_report_on_any_real_amplification():
    ntp = next(r for r in d._REFLECTORS if r.name == "NTP monlist")
    memc = next(r for r in d._REFLECTORS if r.name == "memcached")
    assert ntp.always_high and memc.always_high
    # Above 1x they qualify immediately (known massive real-world BAF + CVE)…
    assert d._is_usable_reflector(ntp, 1.1) is True
    assert d._is_usable_reflector(memc, 1.5) is True
    # …but an echo/error (<=1x) is still never reported.
    assert d._is_usable_reflector(ntp, 1.0) is False


@pytest.mark.parametrize("factor,expected", [(4.6, "medium"), (25.0, "high")])
def test_reflector_finding_severity_scales_with_baf(factor, expected):
    refl = next(r for r in d._REFLECTORS if r.name == "SSDP / UPnP")
    f = d._reflector_finding("10.0.0.5", refl, 94, int(94 * factor), factor)
    assert f["severity"] == expected
    assert f["vuln_type"] == "dos_amplification"
    assert f["evidence"]["amplification_factor"] == round(factor, 2)
    assert f["evidence"]["cwe"] == "CWE-406"
    assert "reflect" in f["description"].lower()


def test_named_cve_vector_is_always_at_least_high():
    ntp = next(r for r in d._REFLECTORS if r.name == "NTP monlist")
    # Even a modest single-datagram BAF is high for a monlist reflector.
    f = d._reflector_finding("10.0.0.5", ntp, 8, 40, 5.0)
    assert f["severity"] == "high"
    assert "CVE-2013-5211" in f["title"]


def test_slow_http_finding_shape():
    f = d._slow_http_finding("10.0.0.5", 80, False, 8.0)
    assert f["vuln_type"] == "slow_http_dos"
    assert f["severity"] == "medium"
    assert f["evidence"]["cwe"] == "CWE-400"
    assert f["target"] == "http://10.0.0.5:80"


def test_web_targets_dedup_and_scheme_inference():
    net = {"hosts": [{"ip": "10.0.0.5", "open_ports": [{"port": 80}, {"port": 443}]}]}
    web = d._web_targets(net, ["https://app.example.com", "app.example.com"])
    # https URL → tls; the bare host defaults to http; both host:80 and :443 picked up
    assert ("app.example.com", 443, True) in web
    assert ("10.0.0.5", 80, False) in web
    assert ("10.0.0.5", 443, True) in web
    # No duplicate (host, port, tls) tuples
    assert len(web) == len(set(web))


def test_hosts_from_net_data_parses_ports():
    net = {"hosts": [{"ip": "10.0.0.5", "open_ports": [{"port": 123}, {"port": "137"}]}]}
    hp = d._hosts_from_net_data(net)
    assert hp == [("10.0.0.5", {123, 137})]


def test_scan_dos_targets_empty_is_safe():
    out = asyncio.run(d.scan_dos_targets(net_data={}, urls=[], targets=[]))
    assert out["findings"] == []
    assert "NTP monlist" in out["reflectors_tested"]


def test_dos_vuln_types_have_kb_taxonomy():
    from heaven.devsecops.vuln_kb import lookup

    for vt in ("dos_amplification", "slow_http_dos"):
        entry = lookup(vt)
        assert entry and entry.get("cwe"), vt
        assert entry.get("remediation")


def test_dos_vuln_types_mapped_in_methodology():
    from heaven.methodology import modules_for_vuln

    assert "dos_probe" in modules_for_vuln("dos_amplification")
    assert "dos_probe" in modules_for_vuln("slow_http_dos")

"""End-to-end proof that ONE passive-OSINT enrichment of the recon blob feeds
EVERY downstream stage — the "single chokepoint" design.

Models the exact certifiedhacker miss: an active scan that returned only SSH,
while the public Shodan/InternetDB record shows 80/443 + MySQL 5.7.44. After
enrichment the same host dict drives:

  * the Host & Service Inventory (3306 present, honestly labelled passive),
  * the exposed-database finding (public host, service-driven),
  * the End-of-Life audit (MySQL 5.7 < 8.0),
  * the CVE mapper (the CVE the public record ties to the host).

Plus the CVE mapper's own passive-CVE surfacing + dedup contract.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import passive_intel as pi
from heaven.recon.network_exposure import analyze_network_exposure
from heaven.vulnscan.cve_mapper import map_vulnerabilities
from heaven.vulnscan.eol_scanner import scan_eol_from_net
from heaven.devsecops.inventory import normalize_assets


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    pi._CACHE.clear()
    # Re-enable passive OSINT (conftest disables it suite-wide); the lookup +
    # re-probe are mocked below, so this stays deterministic and offline.
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")
    yield
    pi._CACHE.clear()


def _enrich_certifiedhacker(monkeypatch):
    """Return a single host dict enriched from a mocked public record."""
    async def fake_lookup(ip, **kw):
        return {
            "ports": [22, 80, 443, 3306],
            "cpes": ["cpe:2.3:a:mysql:mysql:5.7.44"],
            "vulns": ["CVE-2016-6662"],
        }

    async def unreachable(host, ports, stealth):
        return {}  # our vantage can't reach the newly-found ports

    monkeypatch.setattr(pi, "lookup", fake_lookup)
    monkeypatch.setattr(pi, "_reprobe_ports", unreachable)

    host = {"host": "45.33.32.156", "ip": "45.33.32.156", "is_alive": True,
            "os_guess": "", "open_ports": [
                {"port": 22, "service": "ssh", "state": "open",
                 "service_version": "OpenSSH 8.9"}]}
    _run(pi.enrich_hosts([host], stealth_level="normal"))
    return host


def test_chokepoint_inventory(monkeypatch):
    host = _enrich_certifiedhacker(monkeypatch)
    inv = normalize_assets([host])
    ports = {p["port"]: p for p in inv[0]["ports"]}
    assert set(ports) >= {22, 80, 443, 3306}
    assert ports[3306]["source"] == "passive:internetdb"
    assert ports[3306]["state"] == "passive-observed"


def test_chokepoint_exposed_database(monkeypatch):
    host = _enrich_certifiedhacker(monkeypatch)
    res = _run(analyze_network_exposure({"hosts": [host]},
                                        active_snmp=False, active_probes=False))
    db = [f for f in res["findings"] if f["vuln_type"] == "database_exposed"]
    assert any("3306" in f["target"] for f in db)


def test_chokepoint_eol(monkeypatch):
    host = _enrich_certifiedhacker(monkeypatch)
    # Static table alone covers MySQL < 8.0 — no live feed needed here.
    res = _run(scan_eol_from_net({"hosts": [host]}, dynamic=False))
    assert any("MySQL" in f["title"] for f in res["findings"])


def test_chokepoint_cve_mapping(monkeypatch):
    host = _enrich_certifiedhacker(monkeypatch)
    vulns = _run(map_vulnerabilities([host]))
    passive = [v for v in vulns if v.get("source") == "passive:internetdb"]
    assert any(v["cve"] == "CVE-2016-6662" for v in passive)
    for v in passive:
        assert v["target"] == "45.33.32.156"
        assert v["vuln_type"] == "vulnerable_service"


def test_passive_cves_dedupe_within_host():
    host = {"host": "1.2.3.4", "open_ports": [],
            "passive_cves": ["CVE-2020-1111", "CVE-2020-1111", "CVE-2020-2222",
                             "not-a-cve"]}
    vulns = _run(map_vulnerabilities([host]))
    passive = [v for v in vulns if v.get("source") == "passive:internetdb"]
    cves = sorted(v["cve"] for v in passive)
    assert cves == ["CVE-2020-1111", "CVE-2020-2222"]

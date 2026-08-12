"""Field-completeness regression tests for the Host & Service Inventory.

Guards the fix for "the inventory shows blank Service / Version / CPE cells that a
side-by-side nmap fills". Every value asserted here is derived from data nmap (or
Shodan's public record) actually reported — nothing is fabricated:

  1. a well-known port nmap leaves unnamed still gets its conventional service
     label (e.g. 2077 -> cpanel-webdav), while a port with no conventional
     assignment (e.g. 26) honestly stays blank;
  2. when nmap omits the <cpe> element (common for newer versions) HEAVEN derives
     a CPE from the product+version nmap DID report, for well-established vendors
     only -- an unknown product yields no CPE (never a guessed vendor);
  3. nmap's own service name and CPE always win over the fallbacks;
  4. passive OSINT carries Shodan's real CPE onto a passive port and backfills a
     blank field on an actively-found port (never overwriting active data).
"""
from __future__ import annotations

import asyncio

from heaven.recon import passive_intel as pi
from heaven.recon.network_scanner import (
    HostResult,
    PortResult,
    _generate_cpe,
    _host_to_dict,
)


# ── 1+2. deterministic CPE derivation from nmap's own product/version ──────────

def test_generate_cpe_for_well_established_products():
    assert _generate_cpe("nginx", "1.29.8") == "cpe:2.3:a:nginx:nginx:1.29.8:*:*:*:*:*:*:*"
    assert _generate_cpe("OpenSSH", "9.9") == "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*"
    # nmap's cPanel/MariaDB-style build suffix is kept verbatim (real observation).
    assert _generate_cpe("MySQL", "5.7.44-48") == "cpe:2.3:a:mysql:mysql:5.7.44-48:*:*:*:*:*:*:*"
    assert _generate_cpe("Apache httpd", "2.4.62") == "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*"
    # A product with no version still yields a useful, honest wildcard-version CPE.
    assert _generate_cpe("Pure-FTPd", "") == "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*"


def test_generate_cpe_never_guesses_an_unknown_vendor():
    # Unknown product -> no CPE (we do not invent a vendor).
    assert _generate_cpe("some-bespoke-daemon", "1.0") == ""
    # A bare service name with no product -> no CPE either.
    assert _generate_cpe("", "1.0") == ""


# ── 3. serialization chokepoint fills blanks without overriding nmap ───────────

def test_host_to_dict_fills_known_service_and_derived_cpe_honestly():
    host = HostResult(host="192.0.2.10", is_alive=True)
    host.open_ports = [
        # known port nmap couldn't name (blank service) -> conventional label
        PortResult(host="192.0.2.10", port=2077, state="open", service=""),
        # unrecognised port with no standard service -> honestly stays blank
        PortResult(host="192.0.2.10", port=26, state="open", service=""),
        # product+version but nmap emitted no CPE -> derive one
        PortResult(host="192.0.2.10", port=80, state="open", service="http",
                   product="nginx", version="1.29.8", cpe=""),
        # nmap's OWN service + CPE must always win over the fallbacks
        PortResult(host="192.0.2.10", port=22, state="open", service="ssh",
                   product="OpenSSH", version="9.9",
                   cpe="cpe:/a:openbsd:openssh:9.9"),
        # product only (no version) -> wildcard-version CPE, still honest
        PortResult(host="192.0.2.10", port=21, state="open", service="ftp",
                   product="pure-ftpd", version="", cpe=""),
    ]
    by_port = {p["port"]: p for p in _host_to_dict(host)["open_ports"]}

    # 1. conventional label for a known-but-unnamed port; blank stays blank.
    assert by_port[2077]["service"] == "cpanel-webdav"
    assert by_port[26]["service"] == ""

    # 2. derived CPE where nmap omitted it.
    assert by_port[80]["cpe"] == "cpe:2.3:a:nginx:nginx:1.29.8:*:*:*:*:*:*:*"
    assert by_port[80]["service"] == "http"  # nmap's own name untouched
    assert by_port[21]["cpe"] == "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*"

    # 3. nmap's own CPE (and service) preserved verbatim.
    assert by_port[22]["cpe"] == "cpe:/a:openbsd:openssh:9.9"
    assert by_port[22]["service"] == "ssh"


# ── 4. passive OSINT carries real Shodan CPEs / backfills blanks ──────────────

def test_cpe_strings_by_port_maps_full_cpe_to_conventional_ports():
    m = pi._cpe_strings_by_port([
        "cpe:2.3:a:mysql:mysql:5.7.44",
        "cpe:2.3:a:apache:http_server:2.4.6",
    ])
    assert m[3306] == "cpe:2.3:a:mysql:mysql:5.7.44"
    assert m[80] == "cpe:2.3:a:apache:http_server:2.4.6"
    assert m[443] == "cpe:2.3:a:apache:http_server:2.4.6"


def test_passive_port_carries_shodan_cpe():
    pd = pi._passive_port(3306, "mysql", "5.7.44", "cpe:2.3:a:mysql:mysql:5.7.44")
    assert pd["cpe"] == "cpe:2.3:a:mysql:mysql:5.7.44"
    assert pd["state"] == "passive-observed"


def test_enrich_backfills_blank_fields_on_active_port(monkeypatch):
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")
    pi._CACHE.clear()

    async def fake_lookup(ip, **kw):
        return {"ports": [3306], "cpes": ["cpe:2.3:a:mysql:mysql:5.7.44"], "vulns": []}

    async def no_confirm(host, ports, stealth):
        return {}

    monkeypatch.setattr(pi, "lookup", fake_lookup)
    monkeypatch.setattr(pi, "_reprobe_ports", no_confirm)

    hosts = [{
        "host": "45.33.32.156", "ip": "45.33.32.156", "is_alive": True,
        "open_ports": [
            {"port": 3306, "service": "mysql", "state": "open",
             "product": "", "version": "", "cpe": ""},
        ],
    }]
    asyncio.run(pi.enrich_hosts(hosts, stealth_level="normal"))
    p = {x["port"]: x for x in hosts[0]["open_ports"]}[3306]

    # Still an actively-proven port -- never downgraded to passive.
    assert p["state"] == "open"
    assert p.get("source", "active") in ("active", None)
    assert p["corroborated_by"] == "internetdb"
    # Blank fields backfilled from Shodan's real, observed CPE.
    assert p["product"] == "mysql"
    assert p["version"] == "5.7.44"
    assert p["cpe"] == "cpe:2.3:a:mysql:mysql:5.7.44"
    assert p["service_version"] == "mysql 5.7.44"


def test_enrich_never_overwrites_richer_active_data(monkeypatch):
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")
    pi._CACHE.clear()

    async def fake_lookup(ip, **kw):
        # Shodan has a coarser version than the active scan already captured.
        return {"ports": [3306], "cpes": ["cpe:2.3:a:mysql:mysql:5.7"], "vulns": []}

    async def no_confirm(host, ports, stealth):
        return {}

    monkeypatch.setattr(pi, "lookup", fake_lookup)
    monkeypatch.setattr(pi, "_reprobe_ports", no_confirm)

    hosts = [{
        "host": "45.33.32.156", "ip": "45.33.32.156", "is_alive": True,
        "open_ports": [
            {"port": 3306, "service": "mysql", "state": "open",
             "product": "MySQL", "version": "5.7.44-48",
             "cpe": "cpe:2.3:a:mysql:mysql:5.7.44-48", "service_version": "MySQL 5.7.44-48"},
        ],
    }]
    asyncio.run(pi.enrich_hosts(hosts, stealth_level="normal"))
    p = {x["port"]: x for x in hosts[0]["open_ports"]}[3306]

    # Active (richer) data is preserved; only corroboration is stamped.
    assert p["version"] == "5.7.44-48"
    assert p["cpe"] == "cpe:2.3:a:mysql:mysql:5.7.44-48"
    assert p["corroborated_by"] == "internetdb"

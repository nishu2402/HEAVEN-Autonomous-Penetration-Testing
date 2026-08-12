"""Tests for passive OSINT enrichment (`heaven/recon/passive_intel.py`).

The feature exists so HEAVEN never misses a port / service / CVE that is already
publicly visible on the target — the exact class of miss where an authenticated
Shodan record shows 80/443 + MySQL/PostgreSQL but a single flaky active scan
came back without them. These tests pin the honesty contract:

* public-IP-only, private/loopback short-circuits, kill-switch respected;
* a passively-discovered port is labelled ``passive-observed`` unless a read-only
  re-probe confirms it (then ``passive+active`` / ``open``);
* an actively-proven port always outranks a passive one in the inventory;
* the inventory markdown shows provenance so the two are never confused;
* CPEs from the public record carry a real product+version into EOL/CVE stages.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import passive_intel as pi
from heaven.devsecops.inventory import (
    normalize_assets,
    port_source_label,
    render_markdown,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _clear_cache(monkeypatch):
    pi._CACHE.clear()
    # Re-enable passive OSINT (conftest disables it suite-wide); every test here
    # mocks the network, so this stays deterministic and offline.
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")
    yield
    pi._CACHE.clear()


# ── public-IP gate + parsing ──────────────────────────────────────────────────

def test_public_ip_gate():
    assert pi._is_public_ip("45.33.32.156") is True
    assert pi._is_public_ip("10.0.0.1") is False
    assert pi._is_public_ip("127.0.0.1") is False
    assert pi._is_public_ip("192.168.1.10") is False
    assert pi._is_public_ip("not-an-ip") is False


def test_cpe_parse():
    assert pi._parse_cpe("cpe:2.3:a:mysql:mysql:5.7.44:*:*:*:*:*:*:*") == ("mysql", "5.7.44")
    assert pi._parse_cpe("cpe:/a:postgresql:postgresql:9.6") == ("postgresql", "9.6")
    # version wildcard collapses to empty
    assert pi._parse_cpe("cpe:2.3:a:nginx:nginx:*") == ("nginx", "")


def test_cpe_port_map_associates_products_with_conventional_ports():
    m = pi._cpe_port_map([
        "cpe:2.3:a:mysql:mysql:5.7.44",
        "cpe:2.3:a:postgresql:postgresql:9.6",
        "cpe:2.3:a:apache:http_server:2.4.6",
    ])
    assert m[3306] == ("mysql", "5.7.44")
    assert m[5432] == ("postgresql", "9.6")
    assert m[80][0] == "http server" and m[80][1] == "2.4.6"


# ── lookup gating ─────────────────────────────────────────────────────────────

def test_lookup_private_ip_shortcircuits():
    # No network touched: a private IP has nothing in InternetDB by definition.
    assert _run(pi.lookup("10.0.0.5")) == {}


def test_kill_switch_disables_lookup(monkeypatch):
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "1")
    assert pi.passive_intel_enabled() is False
    assert _run(pi.lookup("45.33.32.156")) == {}


def test_lookup_parses_internetdb_json(monkeypatch):
    body = {
        "ip": "45.33.32.156",
        "ports": [22, 80, 443, 3306],
        "cpes": ["cpe:2.3:a:mysql:mysql:5.7.44"],
        "hostnames": ["scanme.example"],
        "tags": ["database"],
        "vulns": ["CVE-2021-1234", "not-a-cve"],
    }

    class _Resp:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def json(self, *a, **k):
            return body

    class _Session:
        def get(self, url, **kw):
            return _Resp()

        async def close(self):
            return None

    out = _run(pi.lookup("45.33.32.156", session=_Session()))
    assert out["ports"] == [22, 80, 443, 3306]
    assert out["vulns"] == ["CVE-2021-1234", "not-a-cve"]
    assert out["cpes"] == ["cpe:2.3:a:mysql:mysql:5.7.44"]


def test_lookup_offline_returns_empty():
    class _Boom:
        def get(self, url, **kw):
            raise OSError("network unreachable")

        async def close(self):
            return None

    assert _run(pi.lookup("45.33.32.156", session=_Boom())) == {}


# ── enrichment merge honesty ──────────────────────────────────────────────────

def _mock_lookup(monkeypatch, data):
    async def fake(ip, **kw):
        return data
    monkeypatch.setattr(pi, "lookup", fake)


def test_enrich_merges_passive_ports_labeled_honestly(monkeypatch):
    _mock_lookup(monkeypatch, {
        "ports": [22, 80, 3306, 5432],
        "cpes": ["cpe:2.3:a:mysql:mysql:5.7.44", "cpe:2.3:a:postgresql:postgresql:9.6"],
        "vulns": ["CVE-2020-9999"],
    })
    # No re-probe reaches the new ports (offline vantage).
    async def no_confirm(host, ports, stealth):
        return {}
    monkeypatch.setattr(pi, "_reprobe_ports", no_confirm)

    hosts = [{
        "host": "45.33.32.156", "ip": "45.33.32.156", "is_alive": True,
        "open_ports": [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
        ],
    }]
    _run(pi.enrich_hosts(hosts, stealth_level="normal"))

    ports = {p["port"]: p for p in hosts[0]["open_ports"]}
    # Active port that the public record also lists → corroborated, still active.
    assert ports[80].get("corroborated_by") == "internetdb"
    assert ports[80].get("source", "active") in ("active", None)
    # New ports from the public record → passive-observed, honestly labelled.
    assert ports[3306]["state"] == "passive-observed"
    assert ports[3306]["source"] == "passive:internetdb"
    assert ports[3306]["product"] == "mysql" and ports[3306]["version"] == "5.7.44"
    assert ports[5432]["state"] == "passive-observed"
    assert ports[5432]["product"] == "postgresql"
    # CVE list from the public record is stashed for the CVE mapper.
    assert hosts[0]["passive_cves"] == ["CVE-2020-9999"]


def test_enrich_reprobe_promotes_confirmed_port(monkeypatch):
    _mock_lookup(monkeypatch, {"ports": [3306], "cpes": [], "vulns": []})

    async def confirm(host, ports, stealth):
        return {3306: {"port": 3306, "protocol": "tcp", "state": "open",
                       "service": "mysql", "product": "MySQL",
                       "version": "5.7.44", "service_version": "MySQL 5.7.44",
                       "banner": "", "cpe": ""}}
    monkeypatch.setattr(pi, "_reprobe_ports", confirm)

    hosts = [{"host": "45.33.32.156", "ip": "45.33.32.156", "open_ports": []}]
    _run(pi.enrich_hosts(hosts, stealth_level="normal"))
    p = hosts[0]["open_ports"][0]
    assert p["port"] == 3306
    assert p["state"] == "open"
    assert p["source"] == "passive+active"
    assert p["corroborated_by"] == "internetdb"


def test_enrich_stealth_skips_reprobe(monkeypatch):
    _mock_lookup(monkeypatch, {"ports": [3306], "cpes": [], "vulns": []})

    called = {"n": 0}

    async def confirm(host, ports, stealth):
        called["n"] += 1
        return {}
    monkeypatch.setattr(pi, "_reprobe_ports", confirm)

    hosts = [{"host": "45.33.32.156", "ip": "45.33.32.156", "open_ports": []}]
    _run(pi.enrich_hosts(hosts, stealth_level="paranoid"))
    # No active traffic in a paranoid profile — the port still merges, passive.
    assert called["n"] == 0
    assert hosts[0]["open_ports"][0]["state"] == "passive-observed"


def test_enrich_creates_host_for_unreached_public_target(monkeypatch):
    _mock_lookup(monkeypatch, {"ports": [443], "cpes": [], "vulns": []})

    async def no_confirm(host, ports, stealth):
        return {}
    monkeypatch.setattr(pi, "_reprobe_ports", no_confirm)

    hosts: list[dict] = []
    _run(pi.enrich_hosts(hosts, targets=["45.33.32.156"], stealth_level="normal"))
    assert len(hosts) == 1
    assert hosts[0]["host"] == "45.33.32.156"
    assert hosts[0]["open_ports"][0]["port"] == 443
    assert hosts[0]["open_ports"][0]["source"] == "passive:internetdb"


def test_enrich_noop_when_disabled(monkeypatch):
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "1")
    hosts = [{"host": "45.33.32.156", "ip": "45.33.32.156", "open_ports": []}]
    _run(pi.enrich_hosts(hosts))
    assert hosts[0]["open_ports"] == []


def test_enrich_skips_private_target(monkeypatch):
    # A private host key never triggers a lookup even if lookup were reachable.
    calls = {"n": 0}

    async def fake(ip, **kw):
        calls["n"] += 1
        return {"ports": [3306]}
    monkeypatch.setattr(pi, "lookup", fake)
    hosts = [{"host": "10.0.0.5", "ip": "10.0.0.5", "open_ports": []}]
    _run(pi.enrich_hosts(hosts))
    assert calls["n"] == 0
    assert hosts[0]["open_ports"] == []


# ── inventory provenance ──────────────────────────────────────────────────────

def test_active_outranks_passive_in_inventory():
    assets = [
        {"host": "45.33.32.156", "open_ports": [
            {"port": 80, "service": "http", "state": "passive-observed",
             "source": "passive:internetdb"}]},
        {"host": "45.33.32.156", "open_ports": [
            {"port": 80, "service": "http", "state": "open", "product": "Apache",
             "version": "2.4.6", "service_version": "Apache 2.4.6"}]},
    ]
    inv = normalize_assets(assets)
    port80 = inv[0]["ports"][0]
    # The proven, richer active entry wins the (port, proto) merge.
    assert port80["state"] == "open"
    assert port80["service_version"] == "Apache 2.4.6"


def test_inventory_markdown_shows_provenance():
    assets = [{"host": "45.33.32.156", "open_ports": [
        {"port": 22, "service": "ssh", "state": "open", "service_version": "OpenSSH 8.9"},
        {"port": 3306, "service": "mysql", "state": "passive-observed",
         "source": "passive:internetdb", "product": "mysql", "version": "5.7.44",
         "service_version": "mysql 5.7.44"},
    ]}]
    md = render_markdown(assets)
    assert "Source" in md
    assert "passive (public OSINT — unconfirmed)" in md
    assert "public internet-scan data" in md


def test_port_source_label():
    assert port_source_label({"source": "active"}) == "active"
    assert port_source_label({}) == "active"
    assert port_source_label({"corroborated_by": "internetdb"}) == "active + OSINT"
    assert port_source_label(
        {"source": "passive:internetdb"}) == "passive (public OSINT — unconfirmed)"
    assert port_source_label(
        {"source": "passive+active"}) == "active (OSINT-corroborated)"

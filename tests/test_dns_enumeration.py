"""Tests for the DNS enumeration tool and its end-to-end wiring.

Covers the enumeration engine (offline-safe), the shared normalizer, the report
sections (HTML/PDF/Markdown), and the engagement-store round-trip that the
Assets view and reports read from.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from heaven.devsecops.dns_inventory import (
    dns_totals,
    normalize_dns,
    render_markdown,
)

# A representative per-domain enumeration record (as enumerate_dns emits).
SAMPLE = {
    "domain": "example.com",
    "records": {
        "A": ["93.184.216.34"],
        "MX": ["10 mail.example.com"],
        "NS": ["ns1.example.com", "ns2.example.com"],
        "TXT": ["v=spf1 -all"],
        "SOA": ["ns1.example.com admin.example.com 1 2 3 4 5"],
    },
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "mail_servers": [{"priority": 10, "host": "mail.example.com"}],
    "subdomains": [
        {"name": "www.example.com", "addresses": ["93.184.216.34"]},
        {"name": "api.example.com", "addresses": ["93.184.216.35"]},
    ],
    "dnssec": {"enabled": True},
    "wildcard": False,
    "resolver": "dnspython",
}


# ── Normalizer ────────────────────────────────────────────────────────────────

def test_normalize_dns_merges_duplicate_domains():
    dup = {
        "domain": "EXAMPLE.com.",  # case + trailing dot must collapse to one domain
        "records": {"A": ["93.184.216.34"]},  # duplicate A must not double
        "subdomains": [{"name": "vpn.example.com", "addresses": ["1.2.3.4"]}],
        "dnssec": {"enabled": True},
    }
    inv = normalize_dns([SAMPLE, dup])
    assert len(inv) == 1
    node = inv[0]
    assert node["domain"] == "example.com"
    # A record deduped, subdomains merged (www, api, vpn)
    assert node["records"]["A"] == ["93.184.216.34"]
    names = {s["name"] for s in node["subdomains"]}
    assert names == {"www.example.com", "api.example.com", "vpn.example.com"}


def test_dns_totals_counts():
    inv = normalize_dns([SAMPLE])
    tot = dns_totals(inv)
    assert tot == {
        "domains": 1, "records": 6, "subdomains": 2,
        "mail_servers": 1, "nameservers": 2, "dnssec_enabled": 1,
    }


def test_render_markdown_has_section_records_and_subdomains():
    md = render_markdown([SAMPLE])
    assert "## DNS Enumeration" in md
    assert "### example.com" in md
    assert "| MX | 10 mail.example.com |" in md
    assert "www.example.com" in md
    assert "Subdomains discovered (2)" in md


def test_render_markdown_empty_is_blank():
    assert render_markdown([]) == ""
    assert render_markdown(None) == ""


# ── Enumeration engine (offline-safe + structure) ─────────────────────────────

def test_enumerate_dns_offline_safe_returns_structure(monkeypatch):
    """With every resolver call failing (offline), enumerate_dns must still
    return a well-formed, empty-ish structure — never raise."""
    from heaven.recon import dns_recon

    monkeypatch.setattr(dns_recon, "_resolve", lambda *a, **k: [])
    monkeypatch.setattr(dns_recon, "_check_dnssec", lambda d: {"enabled": False})
    monkeypatch.setattr(dns_recon, "_detect_wildcard", lambda d: False)

    rec = asyncio.run(dns_recon.enumerate_dns("example.com", max_subdomains=5))
    assert rec["domain"] == "example.com"
    assert rec["records"] == {}
    assert rec["subdomains"] == []
    assert rec["record_count"] == 0
    assert rec["dnssec"] == {"enabled": False}


def test_enumerate_dns_builds_structured_views(monkeypatch):
    """Records → nameservers / mail_servers / subdomains, from mocked DNS."""
    from heaven.recon import dns_recon

    def fake_resolve(name, rtype, nameservers=None, timeout=5.0):
        if name == "example.com":
            return {
                "A": ["93.184.216.34"],
                "MX": ["10 mail.example.com", "20 mail2.example.com"],
                "NS": ["ns1.example.com.", "ns2.example.com."],
                "TXT": ["v=spf1 -all"],
            }.get(rtype, [])
        if name == "www.example.com" and rtype == "A":
            return ["93.184.216.34"]
        return []

    monkeypatch.setattr(dns_recon, "_resolve", fake_resolve)
    monkeypatch.setattr(dns_recon, "_check_dnssec", lambda d: {"enabled": True})
    monkeypatch.setattr(dns_recon, "_detect_wildcard", lambda d: False)

    rec = asyncio.run(dns_recon.enumerate_dns(
        "example.com", wordlist=["www", "nope"], timeout=1.0))
    assert rec["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert rec["mail_servers"][0] == {"priority": 10, "host": "mail.example.com"}
    assert rec["mail_servers"][1]["priority"] == 20  # sorted by priority
    assert [s["name"] for s in rec["subdomains"]] == ["www.example.com"]
    assert rec["dnssec"] == {"enabled": True}


def test_enumerate_dns_skips_subdomains_on_wildcard(monkeypatch):
    """A wildcard domain must NOT emit brute-forced subdomains (they'd be bogus)."""
    from heaven.recon import dns_recon

    monkeypatch.setattr(dns_recon, "_resolve",
                        lambda name, rtype, *a, **k: ["1.2.3.4"] if rtype == "A" else [])
    monkeypatch.setattr(dns_recon, "_check_dnssec", lambda d: {"enabled": False})
    monkeypatch.setattr(dns_recon, "_detect_wildcard", lambda d: True)

    rec = asyncio.run(dns_recon.enumerate_dns("example.com", wordlist=["www", "api"]))
    assert rec["wildcard"] is True
    assert rec["subdomains"] == []


def test_dns_recon_targets_returns_dns_records(monkeypatch):
    """The orchestrator task's entry point must return a dns_records list."""
    from heaven.recon import dns_recon

    async def fake_enum_targets(domains, *, subdomains=True):
        return [dict(SAMPLE)]

    monkeypatch.setattr(dns_recon, "enumerate_dns_targets", fake_enum_targets)

    async def fake_recon(domain, **k):
        return {"findings": []}

    monkeypatch.setattr(dns_recon, "dns_recon", fake_recon)

    out = asyncio.run(dns_recon.dns_recon_targets(["example.com", "example.com"]))
    assert "dns_records" in out
    assert out["dns_records"][0]["domain"] == "example.com"


# ── Report rendering ──────────────────────────────────────────────────────────

def test_html_report_renders_dns_section_and_toc():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator

    html = ComplianceReportGenerator().generate_html_report(
        [], engagement_name="t", dns_records=[SAMPLE])
    assert 'id="dns"' in html
    assert ">DNS Enumeration<" in html
    assert "www.example.com" in html
    assert "api.example.com" in html
    assert ">DNS Enumeration</a>" in html  # table-of-contents entry


def test_html_report_omits_dns_section_when_empty():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator

    html = ComplianceReportGenerator().generate_html_report([], engagement_name="t")
    assert 'id="dns"' not in html


def test_pdf_report_generates_with_dns(tmp_path):
    pytest.importorskip("reportlab")
    from heaven.devsecops.pdf_report import PDFReportGenerator

    out = tmp_path / "r.pdf"
    ok = PDFReportGenerator().generate(
        {"engagement": "t", "findings": [], "dns_records": [SAMPLE]}, str(out))
    assert ok
    assert out.stat().st_size > 2000


def test_evidence_markdown_includes_dns():
    from heaven.devsecops.evidence import export_findings_markdown

    md = export_findings_markdown([], engagement_name="t", dns_records=[SAMPLE])
    assert "## DNS Enumeration" in md
    assert "example.com" in md


# ── Store round-trip (the channel Assets + reports read from) ─────────────────

def test_dns_records_survive_store_round_trip(tmp_path, monkeypatch):
    from heaven.cli.assets import _collect_engagement_dns
    from heaven.engagement import EngagementStore

    db = tmp_path / "eng.db"
    store = EngagementStore(db)
    scan_id = "dns-test-1"
    store.record_scan_start(scan_id, name="DNS enum", mode="dns")
    store.record_scan_complete(scan_id, {"dns_records": [SAMPLE], "assets": []})

    # Read the summary blob directly to prove persistence.
    scan = store.get_scan(scan_id)
    summ = json.loads(scan["summary_json"])
    assert summ["dns_records"][0]["domain"] == "example.com"

    # And through the CLI collector the Assets command uses (the store resolves
    # from HEAVEN_ENGAGEMENT when set to an explicit path).
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))
    raw = _collect_engagement_dns(None)
    inv = normalize_dns(raw)
    assert len(inv) == 1
    assert inv[0]["domain"] == "example.com"
    assert dns_totals(inv)["subdomains"] == 2


# ── Target-domain gathering (why a plain `--target host` had no DNS) ───────────

def test_scan_domains_gathers_hostnames_from_ips_bucket():
    """A hostname passed as `--target` lands in the ``ips`` bucket; the DNS task
    must still enumerate it. IPs / localhost / single-label hosts are dropped."""
    from heaven.orchestrator import _scan_domains

    targets = {
        "ips": ["example.com", "8.8.8.8", "localhost", "intranet", "www.sub.co.uk"],
        "urls": ["https://api.example.org/v1/health"],
        "domains": ["bar.net"],
    }
    got = _scan_domains(targets)
    # Hostname target collapses to its registered domain; explicit domain kept;
    # URL host reduced to eTLD+1. IP, localhost and single-label host dropped.
    assert "example.com" in got            # from ips bucket — the core fix
    assert "example.org" in got            # from urls
    assert "bar.net" in got                # explicit domains bucket
    assert "8.8.8.8" not in got
    assert "localhost" not in got
    assert "intranet" not in got


def test_scan_domains_empty_for_ip_only_targets():
    from heaven.orchestrator import _scan_domains

    assert _scan_domains({"ips": ["10.0.0.5", "127.0.0.1"], "urls": []}) == []


# ── CLI persistence auto-creates the engagement ───────────────────────────────

def test_dns_cli_persist_auto_creates_engagement(monkeypatch, tmp_path):
    """`heaven dns --engagement <new>` must create the engagement, not error."""
    from heaven.cli import dns as dns_cli
    from heaven.cli.assets import _collect_engagement_dns

    # Point the engagement path resolver at an isolated, non-existent DB.
    db = tmp_path / "engagements" / "fresh.db"
    monkeypatch.setattr(dns_cli, "_engagement_db_path", lambda name: db)
    assert not db.exists()

    dns_cli._persist("fresh", [SAMPLE], [])

    assert db.exists()  # auto-created rather than refused
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))
    inv = normalize_dns(_collect_engagement_dns(None))
    assert inv and inv[0]["domain"] == "example.com"

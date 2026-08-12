"""Regression: version-based CVE findings must carry a real vuln_type.

The inline-CVE and NVD build paths in cve_mapper previously omitted `vuln_type`,
so every version-matched CVE (e.g. an Apache banner → Optionsbleed) persisted as
`vuln_type="unknown"` — which has no KB taxonomy entry and shows up uncategorised
in reports. They must be tagged `vulnerable_service` like the live-feed path,
which aliases to the `vulnerable_component` KB entry.
"""
from __future__ import annotations

import pytest

from heaven.vulnscan.cve_mapper import map_vulnerabilities
from heaven.devsecops.vuln_kb import enrich_finding, lookup, normalize_key


@pytest.mark.asyncio
async def test_inline_cve_findings_are_categorised_not_unknown():
    host_results = [{
        "host": "10.0.0.5",
        "open_ports": [{
            "port": 80,
            "service": "http",
            "banner": "Apache/2.2.8 (Ubuntu)",
            "version": "2.2.8",
        }],
    }]
    # Offline: no nvd_client, no live_feed → only the inline DB path runs.
    vulns = await map_vulnerabilities(host_results)
    assert vulns, "expected inline-DB CVEs for Apache 2.2.8"
    for v in vulns:
        vt = v.get("vuln_type") or v.get("type") or "unknown"
        assert vt != "unknown", f"{v.get('cve')} persisted uncategorised"
        # And the type must resolve to a real KB taxonomy entry.
        assert lookup(vt), f"{vt} has no KB entry"
        # Every CVE finding must name the host:port it came from — a CRITICAL
        # with a blank Target reads as broken in the CLI table / kill chain.
        assert v.get("target") == "10.0.0.5:80", f"{v.get('cve')} has no target: {v.get('target')!r}"


def test_vulnerable_service_resolves_in_kb():
    assert normalize_key("vulnerable_service") in ("vulnerable_service",
                                                   "vulnerable_component")
    assert lookup("vulnerable_service"), "vulnerable_service must resolve in the KB"
    assert not lookup("unknown"), "'unknown' must remain an empty (non-)category"


# ── Bug 2: window-aware version matching (no over-match above the fixed ceiling)

@pytest.mark.parametrize("version,specs,expected", [
    # regreSSHion: affected 8.5p1–9.7p1. A PATCHED 9.9 must NOT match — the old
    # OR-of-specs matched it via ">=8.5p1" alone, the exact FP the user hit.
    ("9.9",    ["<=9.7p1", ">=8.5p1"], False),
    ("9.6",    ["<=9.7p1", ">=8.5p1"], True),
    ("8.4",    ["<=9.7p1", ">=8.5p1"], False),
    # Log4Shell: >=2.0-beta9 <=2.14.1 — a patched 2.17 must not match.
    ("2.17.0", [">=2.0-beta9", "<=2.14.1"], False),
    ("2.14.0", [">=2.0-beta9", "<=2.14.1"], True),
    # GitLab account-takeover: OR of bounded windows; 16.6.0 is above every
    # ceiling → not vulnerable (old code matched via the first ">=16.1.0").
    ("16.6.0", [">=16.1.0", "<16.1.6", ">=16.2.0", "<16.2.9",
                ">=16.3.0", "<16.3.7", ">=16.5.0", "<16.5.6"], False),
    ("16.5.5", [">=16.1.0", "<16.1.6", ">=16.2.0", "<16.2.9",
                ">=16.3.0", "<16.3.7", ">=16.5.0", "<16.5.6"], True),
    # Branch ceilings (uppers-only OR) still match the old branches.
    ("15.0",   ["<=16.1", "<=15.5", "<=14.10"], True),
    ("16.5",   ["<=16.1", "<=15.5", "<=14.10"], False),
    # Standalone clauses: exact, dash-range, "all*".
    ("2.4.49", ["2.4.49"], True),
    ("1.0.1f", ["1.0.1a-1.0.1f"], True),
    ("9.9",    ["all_debian_packages"], True),
])
def test_specs_match_version_windows(version, specs, expected):
    from heaven.vulnscan.cve_mapper import specs_match_version
    assert specs_match_version(version, specs) is expected


@pytest.mark.asyncio
async def test_openssh_99_is_not_regreSSHion():
    """End-to-end: a real OpenSSH 9.9 banner must NOT surface regreSSHion."""
    hosts = [{"host": "h", "open_ports": [
        {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.9",
         "version": "9.9"}]}]
    vulns = await map_vulnerabilities(hosts)
    assert "CVE-2024-6387" not in {v.get("cve") for v in vulns}


# ── Bug 1: version-undetermined → one "potential" finding, not a CVE flood ────

@pytest.mark.asyncio
async def test_versionless_service_collapses_to_one_potential_finding():
    """A banner that names a product but no version (e.g. hardened "Server:
    Apache") must NOT emit every product CVE as a confirmed Critical. It
    collapses to a single low-severity `potential_vulnerable_service` finding —
    the same product seen on several ports reports once."""
    hosts = [{"host": "www.example.test", "open_ports": [
        {"port": 80,  "service": "http",  "banner": "Apache"},
        {"port": 443, "service": "https", "banner": "Apache"}]}]
    vulns = await map_vulnerabilities(hosts)
    potentials = [v for v in vulns if v.get("vuln_type") == "potential_vulnerable_service"]
    # One consolidated finding for the whole host — not 11 CVEs × 2 ports = 22.
    assert len(potentials) == 1, [v.get("cve") or v.get("vuln_type") for v in vulns]
    pf = potentials[0]
    assert pf["severity"] == "low"
    assert not pf.get("cve") and not pf.get("cve_id")   # no single CVE claimed
    assert pf["confidence"] < 0.5                       # explicitly unconfirmed
    assert pf["evidence"]["candidate_cve_count"] >= 5   # CVEs listed for triage
    # No confirmed per-CVE `vulnerable_service` rows leaked from the version-less path.
    assert not any(v.get("vuln_type") == "vulnerable_service" for v in vulns)


@pytest.mark.asyncio
async def test_potential_finding_stays_low_after_enrich():
    """The consolidated potential finding must survive enrich/reconcile in the
    low band (never inheriting the component class's high base) and carry real
    taxonomy so the report is never blank."""
    hosts = [{"host": "h", "open_ports": [
        {"port": 143, "service": "imap", "banner": "Dovecot ready"}]}]
    pf = (await map_vulnerabilities(hosts))[0]
    e = enrich_finding(pf)
    assert e["severity"] == "low"
    base = e.get("cvss_base") or (e.get("evidence") or {}).get("cvss_base") or 0
    assert 0 < float(base) <= 3.9          # capped to the low band, not 7.x
    assert e.get("cwe") and e.get("owasp")  # taxonomy present

"""Regression tests for CVE version-match false positives.

A live full scan of Metasploitable 2 (Apache 2.2.8, OpenSSH 4.7p1, PHP 5.2.4,
MySQL 5.0.51, a Linux VNC, netkit telnetd) surfaced high-confidence CVE false
positives:

* PHP 5.2.4 flagged with PHP 7/8 CVEs (CVE-2024-4577 "PHP CGI RCE on Windows",
  CVE-2019-11043 PHP-FPM, …) — because an upper-bound-only curated spec
  ``<8.3.8`` matches ANY version below it, including an unrelated 5.x line.
* Apache 2.2.8 flagged with Apache 2.4-only CVEs (mod_http2, mod_lua, mod_proxy)
  — ``<=2.4.39`` numerically includes 2.2.8, but those code paths are 2.4-only.
* Version-less services (VNC, telnet) flagged with specific misattributed CVEs
  from a live-feed product-NAME keyword match ("vnc" → RealVNC-on-Windows).

These tests pin the three fixes:
  1. multi-upper-bound records are per-branch (``specs_match_version``);
  2. the Apache inline records carry honest lower bounds / branch ranges;
  3. the live-feed path only asserts version-confirmed hits individually and
     collapses unconfirmed keyword matches into one low "potential" finding.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import cve_mapper as CM
from heaven.vulnscan.cve_mapper import lookup_inline_cves, specs_match_version


# ── 1. Multi-branch upper-bound records are per-branch ────────────────────────
def test_php_524_gets_no_php78_cves():
    """PHP 5.2.4 must match NONE of the curated PHP 7/8 CVEs."""
    assert lookup_inline_cves("php", "5.2.4") == []


def test_mysql_5051_excluded_from_57_80_branch_cves():
    ids = {r.cve_id for r in lookup_inline_cves("mysql", "5.0.51")}
    # CVE-2022-21417 (8.0/5.7) and CVE-2016-6662 (5.5/5.6/5.7) must not match 5.0.
    assert "CVE-2022-21417" not in ids
    assert "CVE-2016-6662" not in ids
    # CVE-2012-2122 (single <=5.6.5, genuinely affects 5.0.x) must stay.
    assert "CVE-2012-2122" in ids


@pytest.mark.parametrize("version,specs,expected", [
    # per-branch fix levels — only the matching branch counts
    ("5.2.4", ["<8.3.8", "<8.2.20", "<8.1.29"], False),
    ("8.2.5", ["<8.3.8", "<8.2.20", "<8.1.29"], True),
    ("5.0.51", ["<=8.0.28", "<=5.7.37"], False),
    ("5.7.20", ["<=8.0.28", "<=5.7.37"], True),
    # single upper bound stays open-ended-down (nginx spans its whole line)
    ("1.14.2", ["<=1.20.0"], True),
    ("5.0.51", ["<=5.6.5"], True),
    # explicit two-sided window unaffected
    ("9.9", [">=8.5p1", "<=9.7p1"], False),
    ("9.0", [">=8.5p1", "<=9.7p1"], True),
])
def test_specs_match_branch_semantics(version, specs, expected):
    assert specs_match_version(version, specs) is expected


# ── 2. Apache inline records carry honest bounds ──────────────────────────────
def test_apache_228_only_real_22_cves():
    ids = {r.cve_id for r in lookup_inline_cves("apache_http_server", "2.2.8")}
    # 2.4-only CVEs must be gone.
    for fp in ("CVE-2019-10082", "CVE-2022-22721", "CVE-2021-40438",
               "CVE-2022-31813", "CVE-2020-13950"):
        assert fp not in ids, f"{fp} is a 2.4-only FP on 2.2.8"
    # The two that genuinely span 2.2 must remain (real positives).
    assert ids == {"CVE-2017-7679", "CVE-2017-9798"}


def test_apache_2430_still_matches_24_cves():
    ids = {r.cve_id for r in lookup_inline_cves("apache_http_server", "2.4.30")}
    assert "CVE-2019-10082" in ids   # mod_http2, 2.4.17–2.4.39
    assert "CVE-2021-40438" in ids   # mod_proxy SSRF, <=2.4.48


def test_apache_2453_above_ceiling_not_matched():
    # A patched 2.4.60 must not pick up ceilings it is above.
    ids = {r.cve_id for r in lookup_inline_cves("apache_http_server", "2.4.60")}
    assert "CVE-2019-10082" not in ids
    assert "CVE-2021-40438" not in ids


def test_openssh_47_not_flagged_with_62plus_cve():
    ids = {r.cve_id for r in lookup_inline_cves("openssh", "4.7p1")}
    assert "CVE-2021-41617" not in ids            # requires >=6.2
    assert "CVE-2018-15473" in ids                # through 7.7 — real positive


# ── 3. Live-feed unconfirmed hits collapse instead of misattributing ──────────
class _FakeLiveCVE:
    def __init__(self, cve_id, cvss, version_confirmed):
        self.cve_id = cve_id
        self.title = f"{cve_id} title"
        self.cvss = cvss
        self.severity = "high"
        self.cwe = "CWE-000"
        self.cvss_vector = ""
        self.in_kev = False
        self.epss = 0.0
        self.exploit_available = False
        self.exploit_url = ""
        self.source = "nvd"
        self.version_confirmed = version_confirmed


def test_live_feed_versionless_collapses_to_one_potential():
    class Feed:
        available = True

        async def discover_for_service(self, service, banner="", version=""):
            # Version-less "vnc" → only unconfirmed keyword matches.
            return [_FakeLiveCVE("CVE-2022-41975", 7.8, False),
                    _FakeLiveCVE("CVE-2022-27502", 6.2, False)]

    host = {"host": "10.0.0.9", "open_ports": [
        {"port": 5900, "service": "vnc", "banner": "", "version": "", "product": ""},
    ]}
    out = asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                             live_feed=Feed(), max_live_lookups=5))
    # No individual RealVNC CVE is asserted…
    assert not any(v.get("cve") in ("CVE-2022-41975", "CVE-2022-27502") for v in out)
    # …just one honest low "potential" finding naming the candidates.
    pots = [v for v in out if v.get("vuln_type") == "potential_vulnerable_service"]
    assert len(pots) == 1
    assert pots[0]["confidence"] < 0.5
    assert pots[0]["severity"] == "low"
    assert set(pots[0]["evidence"]["candidate_cves"]) == {"CVE-2022-41975",
                                                          "CVE-2022-27502"}


def test_live_feed_version_confirmed_hit_emitted_individually():
    class Feed:
        available = True

        async def discover_for_service(self, service, banner="", version=""):
            return [_FakeLiveCVE("CVE-2024-9999", 9.1, True)]

    host = {"host": "10.0.0.9", "open_ports": [
        {"port": 8888, "service": "acme", "banner": "", "version": "1.2.3",
         "product": "acmed"},
    ]}
    out = asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                             live_feed=Feed(), max_live_lookups=5))
    hits = [v for v in out if v.get("cve") == "CVE-2024-9999"]
    assert len(hits) == 1
    assert hits[0]["vuln_type"] == "vulnerable_service"
    assert hits[0]["confidence"] == 0.85


# ── 4. Old-version live-feed fallback (`not inline_cves`, not `product not in DB`) ─
def test_live_feed_fires_for_known_product_unmatched_old_version():
    """A product that IS in the inline DB but whose observed version matches NONE
    of its inline CVEs (ancient Apache 1.3.42 against a DB of 2.2/2.4 entries) must
    STILL fall through to the live feed. Gating the fallback on the product key
    alone silently dropped these decade-old services — they got neither an inline
    hit nor a live lookup, so their era-appropriate CVE was never found."""
    consulted: dict = {}

    class Feed:
        available = True

        async def discover_for_service(self, service, banner="", version=""):
            consulted["service"] = service
            consulted["version"] = version
            return [_FakeLiveCVE("CVE-2002-0392", 7.5, True)]  # Apache 1.3 chunked-encoding RCE

    host = {"host": "10.0.0.7", "open_ports": [
        {"port": 80, "service": "http", "banner": "Apache/1.3.42",
         "version": "1.3.42", "product": "Apache httpd"},
    ]}
    out = asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                             live_feed=Feed(), max_live_lookups=5))
    assert consulted.get("service") == "apache_http_server"
    assert consulted.get("version") == "1.3.42"
    assert any(v.get("cve") == "CVE-2002-0392" for v in out)


def test_live_feed_skipped_when_inline_version_matches():
    """When the inline DB DID match the observed version, inline stays
    authoritative and the live feed is NOT consulted (no double-reporting)."""
    called = {"v": False}

    class Feed:
        available = True

        async def discover_for_service(self, service, banner="", version=""):
            called["v"] = True
            return [_FakeLiveCVE("CVE-9999-0001", 9.9, True)]

    host = {"host": "10.0.0.7", "open_ports": [
        {"port": 21, "service": "ftp", "banner": "220 (vsFTPd 2.3.4)",
         "version": "2.3.4", "product": "vsftpd"},
    ]}
    out = asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                             live_feed=Feed(), max_live_lookups=5))
    assert called["v"] is False
    assert any(v.get("cve") == "CVE-2011-2523" for v in out)   # inline hit stands
    assert not any(v.get("cve") == "CVE-9999-0001" for v in out)


# ── 5. MySQL Connector/J CVE is not a server finding ─────────────────────────
def test_mysql_server_never_flags_connectorj_cve():
    """CVE-2021-2471 is a MySQL Connector/J (JDBC client) CVE. HEAVEN only ever
    fingerprints the server (port 3306), so it must never appear on a MySQL host."""
    assert "CVE-2021-2471" not in {r.cve_id for r in lookup_inline_cves("mysql", "8.0.20")}


# ── 6. Samba banner fingerprinting + era-appropriate CVE scoping ─────────────
def test_samba_banner_fingerprints_with_version():
    assert CM._fingerprint_from_banner("Samba smbd 3.0.20-Debian") == ("samba", "3.0.20")
    assert CM._fingerprint_from_banner("Samba smbd 4.15.13-Ubuntu") == ("samba", "4.15.13")


def test_samba_3020_gets_usermap_rce_not_modern_cves():
    ids = {r.cve_id for r in lookup_inline_cves("samba", "3.0.20")}
    assert "CVE-2007-2447" in ids          # username-map-script RCE — era-appropriate
    assert "CVE-2017-7494" not in ids      # SambaCry needs >=3.5.0
    assert "CVE-2020-1472" not in ids      # Zerologon is a 4.x AD-DC bug


def test_samba_zerologon_scoped_to_vulnerable_ad_dc_range():
    # 4.0–4.7 vulnerable by default; 4.8+ ships a secure schannel; 3.0.x has no DC.
    assert "CVE-2020-1472" in {r.cve_id for r in lookup_inline_cves("samba", "4.5.0")}
    assert "CVE-2020-1472" not in {r.cve_id for r in lookup_inline_cves("samba", "4.15.13")}
    assert "CVE-2020-1472" not in {r.cve_id for r in lookup_inline_cves("samba", "3.0.20")}


# ── 7. Terrapin only affects OpenSSH that can negotiate the vulnerable modes ──
def test_terrapin_not_flagged_on_openssh_before_etm_macs():
    """CVE-2023-48795 (Terrapin) exploits ChaCha20-Poly1305 (OpenSSH 6.5) or an
    EtM MAC (OpenSSH 6.2). A 4.7p1 server supports NEITHER, so it cannot be
    attacked — it was a live false positive on Metasploitable's OpenSSH 4.7p1."""
    assert "CVE-2023-48795" not in {r.cve_id for r in lookup_inline_cves("openssh", "4.7p1")}
    assert "CVE-2023-48795" not in {r.cve_id for r in lookup_inline_cves("openssh", "6.1")}
    # In-range versions (that DO negotiate the modes) are still flagged.
    assert "CVE-2023-48795" in {r.cve_id for r in lookup_inline_cves("openssh", "6.2")}
    assert "CVE-2023-48795" in {r.cve_id for r in lookup_inline_cves("openssh", "8.9p1")}
    assert "CVE-2023-48795" not in {r.cve_id for r in lookup_inline_cves("openssh", "9.6")}


# ── 8. One software instance on several ports is one finding, not one per port ─
def test_same_product_version_cve_collapses_across_ports():
    """Samba answers on 139 AND 445 — the same daemon, so the same
    version-matched RCE must be ONE finding, with the extra port recorded."""
    hosts = [{"host": "10.0.0.9", "open_ports": [
        {"port": 139, "service": "netbios-ssn", "banner": "Samba smbd 3.0.20-Debian",
         "version": "3.0.20"},
        {"port": 445, "service": "netbios-ssn", "banner": "Samba smbd 3.0.20-Debian",
         "version": "3.0.20"},
    ]}]
    vulns = asyncio.run(CM.map_vulnerabilities(hosts))
    usermap = [v for v in vulns if v.get("cve") == "CVE-2007-2447"]
    assert len(usermap) == 1, f"Samba RCE duplicated across ports: {usermap}"
    assert 445 in usermap[0].get("evidence", {}).get("also_on_ports", [])


def test_same_cve_different_versions_stay_distinct_across_ports():
    """Two genuinely different builds (different versions) sharing a CVE are two
    instances, so they must NOT be collapsed."""
    hosts = [{"host": "10.0.0.9", "open_ports": [
        {"port": 80, "service": "http", "banner": "Apache/2.2.8", "version": "2.2.8"},
        {"port": 8080, "service": "http", "banner": "Apache/2.2.14", "version": "2.2.14"},
    ]}]
    vulns = asyncio.run(CM.map_vulnerabilities(hosts))
    versions = {v.get("version") for v in vulns if v.get("cve")}
    assert {"2.2.8", "2.2.14"} <= versions

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

"""Tests for the dynamic, multi-source live CVE feed.

This is the "*the vulnerability is not in my local DB*" solution: when a scan
turns up a product/version the curated inline DB doesn't know, HEAVEN queries
live authoritative feeds (NVD + CIRCL) at scan time. The parsers, merge/dedupe
and version-marking logic are all pure and exercised here fully offline. The one
networked path (:class:`LiveCVEFeed`) is checked for graceful degradation (no
httpx → empty, never raises) and for its disk cache round-trip.
"""

from __future__ import annotations

import heaven.vulnscan.live_cve_feed as lcf
from heaven.vulnscan.cve_mapper import lookup_inline_cves
from heaven.vulnscan.live_cve_feed import (
    LiveCVE,
    LiveCVEFeed,
    _guess_cpe,
    _product_key,
    _score_to_severity,
    filter_by_version,
    merge_and_dedupe,
    parse_circl_response,
)


# ── parse_circl_response ─────────────────────────────────────────────────────
def test_parse_circl_bare_list():
    data = [
        {"id": "CVE-2021-1234", "summary": "Bad bug", "cvss": 9.8, "cwe": "CWE-79"},
        {"id": "CVE-2020-0001", "summary": "Other bug", "cvss": "5.0"},
    ]
    recs = parse_circl_response(data)
    assert {r.cve_id for r in recs} == {"CVE-2021-1234", "CVE-2020-0001"}
    top = next(r for r in recs if r.cve_id == "CVE-2021-1234")
    assert top.cvss == 9.8 and top.severity == "critical" and top.source == "circl"
    assert top.cwe == "CWE-79"


def test_parse_circl_envelope_shapes():
    for key in ("results", "data", "cvelist", "cves"):
        recs = parse_circl_response({key: [{"id": "CVE-2022-9999", "cvss3": "7.5"}]})
        assert len(recs) == 1 and recs[0].cve_id == "CVE-2022-9999"
        assert recs[0].severity == "high"


def test_parse_circl_skips_non_cve_and_junk():
    data = [
        {"id": "not-a-cve", "summary": "x"},
        {"summary": "no id at all"},
        "a bare string",
        {"id": "CVE-2023-5555", "summary": "ok"},
    ]
    recs = parse_circl_response(data)
    assert [r.cve_id for r in recs] == ["CVE-2023-5555"]


def test_parse_circl_normalises_bare_cwe_number():
    recs = parse_circl_response([{"id": "CVE-2021-1", "summary": "x", "cwe": "89"}])
    assert recs[0].cwe == "CWE-89"
    # A non-numeric, non-CWE token is dropped rather than mangled.
    recs2 = parse_circl_response([{"id": "CVE-2021-2", "summary": "x", "cwe": "junk"}])
    assert recs2[0].cwe == ""


def test_parse_circl_cvss_prefers_cvss3_and_parses_string_prefix():
    recs = parse_circl_response([{"id": "CVE-2021-3", "cvss3": "9.1 (high)", "cvss": 2.0}])
    assert recs[0].cvss == 9.1  # cvss3 wins over legacy cvss


def test_parse_circl_empty_and_unknown_shapes():
    assert parse_circl_response({}) == []
    assert parse_circl_response(None) == []
    assert parse_circl_response({"unexpected": 123}) == []


# ── merge_and_dedupe ─────────────────────────────────────────────────────────
def test_merge_dedupes_by_id_keeping_highest_cvss():
    recs = [
        LiveCVE("CVE-2021-1", cvss=5.0, source="circl"),
        LiveCVE("CVE-2021-1", cvss=9.8, source="nvd"),
        LiveCVE("CVE-2021-2", cvss=7.0, source="nvd"),
    ]
    out = merge_and_dedupe(recs)
    ids = {r.cve_id: r for r in out}
    assert len(out) == 2
    assert ids["CVE-2021-1"].cvss == 9.8  # higher score won


def test_merge_preserves_kev_flag_from_either_record():
    recs = [
        LiveCVE("CVE-2021-1", cvss=9.8, source="nvd", in_kev=False),
        LiveCVE("CVE-2021-1", cvss=5.0, source="circl", in_kev=True),
    ]
    out = merge_and_dedupe(recs)
    assert out[0].in_kev is True  # KEV must survive the merge


def test_merge_breaks_cvss_tie_by_nvd_over_circl():
    recs = [
        LiveCVE("CVE-2021-1", cvss=7.0, source="circl"),
        LiveCVE("CVE-2021-1", cvss=7.0, source="nvd"),
    ]
    out = merge_and_dedupe(recs)
    assert out[0].source == "nvd"


def test_merge_sorts_kev_and_score_first():
    recs = [
        LiveCVE("CVE-2021-low", cvss=4.0, source="nvd"),
        LiveCVE("CVE-2021-kev", cvss=4.0, source="nvd", in_kev=True),
        LiveCVE("CVE-2021-high", cvss=9.0, source="nvd"),
    ]
    out = merge_and_dedupe(recs)
    # KEV records sort ahead of non-KEV; within a KEV tier, higher CVSS first.
    assert out[0].cve_id == "CVE-2021-kev"


# ── filter_by_version ────────────────────────────────────────────────────────
def test_filter_by_version_confirms_via_inline_range():
    # CVE-2023-51385 affects OpenSSH <=9.6 in the inline DB.
    recs = [
        LiveCVE("CVE-2023-51385", cvss=7.5, source="nvd"),
        LiveCVE("CVE-9999-0001", cvss=9.0, source="circl"),
    ]
    out = filter_by_version(recs, "openssh", "9.5", lookup_inline_cves)
    by_id = {r.cve_id: r for r in out}
    assert by_id["CVE-2023-51385"].version_confirmed is True
    # A CVE with no authoritative inline range is left unconfirmed, not dropped.
    assert by_id["CVE-9999-0001"].version_confirmed is False
    assert len(out) == 2


def test_filter_by_version_out_of_range_stays_unconfirmed():
    # 10.0 is outside the "<=9.6" range for CVE-2023-51385.
    recs = [LiveCVE("CVE-2023-51385", cvss=7.5, source="nvd")]
    out = filter_by_version(recs, "openssh", "10.0", lookup_inline_cves)
    assert out[0].version_confirmed is False


def test_filter_by_version_no_version_is_noop():
    recs = [LiveCVE("CVE-2023-51385", cvss=7.5, source="nvd")]
    out = filter_by_version(recs, "openssh", "", lookup_inline_cves)
    assert out[0].version_confirmed is False and len(out) == 1


# ── LiveCVE conversions ──────────────────────────────────────────────────────
def test_to_finding_emits_vulnerable_service_type_and_confidence_tiers():
    confirmed = LiveCVE("CVE-2021-1", title="RCE", severity="critical", cvss=9.8,
                        source="nvd", version_confirmed=True)
    f = confirmed.to_finding("10.0.0.5", "nginx", "1.20.0")
    assert f["vuln_type"] == "vulnerable_service"
    assert f["cve"] == "CVE-2021-1"
    assert f["confidence"] == 0.9  # version-confirmed → high confidence
    assert f["evidence"]["version_confirmed"] is True
    assert f["evidence"]["source"] == "live_cve_feed:nvd"

    unconfirmed = LiveCVE("CVE-2021-2", cvss=5.0, source="circl")
    assert unconfirmed.to_finding("t", "p", "")["confidence"] == 0.55


def test_to_dict_is_json_safe():
    import json
    rec = LiveCVE("CVE-2021-1", title="x", severity="high", cvss=7.5, source="nvd",
                  in_kev=True, references=["http://a", "http://b"])
    d = rec.to_dict()
    assert json.loads(json.dumps(d))["cve_id"] == "CVE-2021-1"
    assert d["in_kev"] is True


# ── severity + helpers ───────────────────────────────────────────────────────
def test_score_to_severity_bands():
    assert _score_to_severity(9.9) == "critical"
    assert _score_to_severity(7.0) == "high"
    assert _score_to_severity(4.0) == "medium"
    assert _score_to_severity(0.5) == "low"
    assert _score_to_severity(0.0) == "info"


def test_product_key_normalisation():
    assert _product_key("OpenSSH") == "openssh"
    assert _product_key("Apache-HTTPD") == "apache_httpd"


def test_guess_cpe_shape():
    cpe = _guess_cpe("nginx", "1.20.0")
    assert cpe.startswith("cpe:2.3:a:") and ":1.20.0:" in cpe
    # No version → wildcard.
    assert ":*:*:*:*:*:*:*:*" in _guess_cpe("nginx", "")


# ── LiveCVEFeed graceful degradation + caching ───────────────────────────────
async def test_feed_without_httpx_is_unavailable_and_returns_empty(monkeypatch):
    monkeypatch.setattr(lcf, "httpx", None)
    feed = LiveCVEFeed()
    assert feed.available is False
    assert await feed.discover("some-obscure-product", "1.0") == []


async def test_feed_discover_empty_product_short_circuits():
    feed = LiveCVEFeed()
    assert await feed.discover("", "") == []


async def test_feed_uses_disk_cache_without_network(tmp_path, monkeypatch):
    # Even with httpx removed, a cached lookup must return instantly.
    monkeypatch.setattr(lcf, "httpx", None)
    feed = LiveCVEFeed(cache_dir=tmp_path)
    key = ":openssh:9.5:"
    feed._cache_write(key, [LiveCVE("CVE-2023-51385", cvss=7.5, source="nvd")])
    out = await feed.discover("openssh", "9.5")
    assert [r.cve_id for r in out] == ["CVE-2023-51385"]


def test_cache_round_trip(tmp_path):
    feed = LiveCVEFeed(cache_dir=tmp_path)
    recs = [LiveCVE("CVE-2021-1", cvss=9.8, source="nvd", in_kev=True)]
    feed._cache_write("k", recs)
    back = feed._cache_read("k")
    assert back is not None and back[0].cve_id == "CVE-2021-1" and back[0].in_kev is True


def test_cache_miss_returns_none(tmp_path):
    feed = LiveCVEFeed(cache_dir=tmp_path)
    assert feed._cache_read("never-written") is None


# ── Engagement persistence (the finding shape must be DB-compatible) ─────────
def test_live_cve_finding_persists_into_engagement(tmp_path):
    from heaven.engagement import EngagementStore

    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("cve-test")
    store.record_scan_start("cve-s1", name="CVE lookup: openssh", mode="cve", config={})
    rec = LiveCVE("CVE-2024-6387", title="regreSSHion", severity="critical",
                  cvss=8.1, source="nvd", version_confirmed=True, epss=0.6,
                  exploit_available=True, exploit_url="https://edb/1")
    store.upsert_finding("cve-s1", rec.to_finding("openssh 9.5", "openssh", "9.5"))
    store.record_scan_complete("cve-s1", {"findings_count": 1})

    found = store.list_findings(scan_id="cve-s1")
    assert len(found) == 1
    assert found[0].severity == "critical"


# ── Integration: the dynamic fallback inside map_vulnerabilities ─────────────
class _FakeFeed:
    """A LiveCVEFeed stand-in that records which services it was asked about."""

    def __init__(self, hits):
        self._hits = hits
        self.asked: list[str] = []

    async def discover_for_service(self, service, banner="", version=""):
        self.asked.append(service)
        return self._hits


async def test_map_vulnerabilities_fires_live_feed_only_for_unknown_product():
    from heaven.vulnscan.cve_mapper import map_vulnerabilities

    # "gizmoserver" is NOT in INLINE_CVE_DB → this is the "not in my DB" case.
    host_results = [{
        "host": "10.0.0.9",
        "open_ports": [
            {"port": 8080, "service": "gizmoserver", "banner": "GizmoServer/2.1",
             "version": "2.1"},
        ],
    }]
    feed = _FakeFeed([LiveCVE("CVE-2025-4242", title="Gizmo RCE", severity="critical",
                              cvss=9.8, source="nvd", version_confirmed=True)])
    vulns = await map_vulnerabilities(host_results, live_feed=feed)

    assert feed.asked == ["gizmoserver"]  # the live feed WAS consulted
    live = [v for v in vulns if v.get("source", "").startswith("live:")]
    assert len(live) == 1
    v = live[0]
    assert v["cve"] == "CVE-2025-4242"
    assert v["vuln_type"] == "vulnerable_service"  # categorises in reports
    assert v["confidence"] == 0.85  # version_confirmed → higher confidence
    assert v["in_kev"] is False


async def test_map_vulnerabilities_skips_live_feed_for_known_product():
    from heaven.vulnscan.cve_mapper import map_vulnerabilities

    # OpenSSH IS in the inline DB, so the dynamic feed must NOT be consulted
    # (we already have authoritative, version-matched CVEs for it).
    host_results = [{
        "host": "10.0.0.10",
        "open_ports": [
            {"port": 22, "service": "openssh", "banner": "OpenSSH_9.5", "version": "9.5"},
        ],
    }]
    feed = _FakeFeed([LiveCVE("CVE-2025-9999", cvss=9.0, source="nvd")])
    vulns = await map_vulnerabilities(host_results, live_feed=feed)

    assert feed.asked == []  # inline DB covered it → no live lookup
    assert all(not v.get("source", "").startswith("live:") for v in vulns)


async def test_map_vulnerabilities_carries_epss_and_exploit_fields():
    from heaven.vulnscan.cve_mapper import map_vulnerabilities

    host_results = [{
        "host": "10.0.0.9",
        "open_ports": [{"port": 8080, "service": "gizmoserver",
                        "banner": "GizmoServer/2.1", "version": "2.1"}],
    }]
    hit = LiveCVE("CVE-2025-4242", severity="critical", cvss=9.8, source="nvd",
                  version_confirmed=True, epss=0.91, exploit_available=True,
                  exploit_url="https://www.exploit-db.com/exploits/50000")
    vulns = await map_vulnerabilities(host_results, live_feed=_FakeFeed([hit]))
    live = [v for v in vulns if v.get("source", "").startswith("live:")][0]
    assert live["epss"] == 0.91
    assert live["exploit_available"] is True
    assert live["exploit_url"].endswith("/50000")


# ── EPSS + Exploit-DB enrichment (mocked, offline) ───────────────────────────
async def test_enrich_populates_epss_and_exploit(monkeypatch):
    import heaven.vulnscan.exploitdb_client as edbmod
    import heaven.vulnscan.nvd_client as nvdmod

    class _FakeNVD:
        async def enrich_epss(self, ids):
            return {"CVE-2024-6387": 0.72}

        async def close(self):
            pass

    class _Entry:
        edb_url = "https://www.exploit-db.com/exploits/1"

    class _FakeResult:
        cve = "CVE-2024-6387"
        entries = [_Entry()]

        @property
        def best(self):
            return _Entry()

    async def _fake_lookup(cve):
        return _FakeResult()

    monkeypatch.setattr(nvdmod, "NVDClient", _FakeNVD)
    monkeypatch.setattr(edbmod, "lookup_cve", _fake_lookup)

    feed = LiveCVEFeed()
    recs = [LiveCVE("CVE-2024-6387", cvss=8.1, source="nvd")]
    await feed._enrich(recs)
    assert recs[0].epss == 0.72
    assert recs[0].exploit_available is True
    assert recs[0].exploit_url.endswith("/exploits/1")


async def test_enrich_respects_exploit_lookup_bound(monkeypatch):
    import heaven.vulnscan.exploitdb_client as edbmod
    import heaven.vulnscan.nvd_client as nvdmod

    calls: list[str] = []

    class _FakeResult:
        def __init__(self, cve):
            self.cve = cve
            self.entries = []

        best = None

    async def _fake_lookup(cve):
        calls.append(cve)
        return _FakeResult(cve)

    monkeypatch.setattr(edbmod, "lookup_cve", _fake_lookup)
    # EPSS off so this test isolates the Exploit-DB bound.
    feed = LiveCVEFeed(use_epss=False, max_exploit_lookups=3)
    recs = [LiveCVE(f"CVE-2024-{i:04d}", cvss=float(i), source="nvd")
            for i in range(10)]
    await feed._enrich(recs)
    # Only the top-3 by CVSS should have been looked up.
    assert len(calls) == 3
    assert set(calls) == {"CVE-2024-0009", "CVE-2024-0008", "CVE-2024-0007"}
    # nvd_client import unused here but keeps the monkeypatch symbol referenced.
    assert nvdmod is not None


async def test_enrich_is_graceful_when_sources_raise(monkeypatch):
    import heaven.vulnscan.nvd_client as nvdmod

    class _BoomNVD:
        def __init__(self):
            raise RuntimeError("no network")

    monkeypatch.setattr(nvdmod, "NVDClient", _BoomNVD)
    feed = LiveCVEFeed(use_exploitdb=False)
    recs = [LiveCVE("CVE-2024-6387", cvss=8.1, source="nvd")]
    # Must not raise; record stays un-enriched.
    await feed._enrich(recs)
    assert recs[0].epss == 0.0 and recs[0].exploit_available is False


def test_to_finding_and_dict_expose_epss_exploit():
    r = LiveCVE("CVE-2024-6387", cvss=8.1, source="nvd", epss=0.5,
                exploit_available=True, exploit_url="https://x")
    f = r.to_finding("t", "openssh", "9.5")
    assert f["epss"] == 0.5 and f["exploit_available"] is True
    assert f["evidence"]["exploit_url"] == "https://x"
    d = r.to_dict()
    assert d["epss"] == 0.5 and d["exploit_available"] is True


async def test_map_vulnerabilities_live_feed_error_is_swallowed():
    from heaven.vulnscan.cve_mapper import map_vulnerabilities

    class _BoomFeed:
        async def discover_for_service(self, *a, **k):
            raise RuntimeError("network down")

    host_results = [{
        "host": "10.0.0.11",
        "open_ports": [{"port": 9000, "service": "obscured", "banner": "", "version": ""}],
    }]
    # A failing live feed must never break the scan — it just yields no live hits.
    vulns = await map_vulnerabilities(host_results, live_feed=_BoomFeed())
    assert all(not v.get("source", "").startswith("live:") for v in vulns)

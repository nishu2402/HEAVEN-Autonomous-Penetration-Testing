"""
HEAVEN — Regression tests for the scan-accuracy / sync fixes.

Covers the batch of user-reported issues:

* **Wrong / blank CVE + "fake results" + store↔report disagreement** — every CVE
  on a host used to collapse into one finding (identity ignored the CVE), and the
  surviving cve_id was non-deterministic. Distinct CVEs must now be distinct
  findings; the same CVE must still dedup.
* **Live-CVE false positives** — the live feed was searching NVD for a bare
  protocol label ("http"), pulling Apache CVEs onto any HTTP server (a Python
  ``http.server`` collected ~25 false "Apache" CVEs). A generic label must never
  drive a search; only a concrete product does.
* **Junk findings** — a finding naming neither a target nor a vuln class (empty
  target + vuln_type "unknown") is unactionable noise and must be dropped.
* **Store↔report reconciliation** — ``prune_scan_findings`` trims a scan's rows
  to the final authoritative set after the live progress flush.
* **Duplicate scan launch** — two identical back-to-back POSTs must yield ONE
  scan, not two.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.engagement import (
    EngagementStore,
    _finding_hash,
    _finding_identity,
    _is_junk_finding,
    dedup_findings,
)


# ── CVE-aware finding identity ───────────────────────────────────────────────

class TestCveIdentity:
    def test_distinct_cves_same_host_port_are_distinct(self):
        a = {"host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
             "cve": "CVE-2017-9798", "severity": "medium"}
        b = {"host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
             "cve": "CVE-2021-40438", "severity": "critical"}
        assert _finding_hash(*_finding_identity(a)) != _finding_hash(*_finding_identity(b))

    def test_same_cve_dedups(self):
        b = {"host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
             "cve": "CVE-2021-40438", "severity": "critical", "title": "one"}
        b2 = dict(b, title="two")
        assert _finding_hash(*_finding_identity(b)) == _finding_hash(*_finding_identity(b2))

    def test_same_cve_different_port_is_distinct(self):
        a = {"host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
             "cve": "CVE-2021-40438"}
        b = {"host": "10.0.0.1", "port": 8080, "vuln_type": "vulnerable_service",
             "cve": "CVE-2021-40438"}
        assert _finding_hash(*_finding_identity(a)) != _finding_hash(*_finding_identity(b))

    def test_dedup_keeps_every_distinct_cve(self):
        vulns = [
            {"host": "h", "port": 80, "vuln_type": "vulnerable_service", "cve": f"CVE-2020-{n}"}
            for n in (1001, 1002, 1003)
        ]
        vulns.append(dict(vulns[0]))  # a duplicate of the first
        out = dedup_findings(vulns)
        assert len(out) == 3

    def test_host_level_findings_still_collapse(self):
        h1 = {"target": "https://x/a", "vuln_type": "hsts_missing"}
        h2 = {"target": "https://x/b", "vuln_type": "hsts_missing"}
        assert len(dedup_findings([h1, h2])) == 1

    def test_injection_same_param_still_dedups(self):
        i1 = {"target": "https://x/a?id=1", "vuln_type": "sqli", "param": "id",
              "endpoint": "https://x/a"}
        i2 = {"target": "https://x/a?id=2%20OR%201=1", "vuln_type": "sqli",
              "param": "id", "endpoint": "https://x/a"}
        assert len(dedup_findings([i1, i2])) == 1


# ── Store: distinct CVEs persist + reconciliation ────────────────────────────

class TestStoreCvePersistence:
    @pytest.fixture
    def store(self, tmp_path):
        return EngagementStore(tmp_path / "acc.db")

    def test_multiple_cves_one_host_all_persist(self, store):
        for cve, sev in (("CVE-2017-9798", "medium"), ("CVE-2021-40438", "critical"),
                         ("CVE-2019-10082", "high")):
            store.upsert_finding("s1", {"host": "10.0.0.1", "port": 80,
                                        "vuln_type": "vulnerable_service",
                                        "cve": cve, "severity": sev, "confidence": 0.9})
        assert store.count_findings("s1") == 3
        cves = {f.cve_id for f in store.list_findings(scan_id="s1", limit=50)}
        assert cves == {"CVE-2017-9798", "CVE-2021-40438", "CVE-2019-10082"}

    def test_prune_scan_findings_reconciles_to_final_set(self, store):
        keep = store.upsert_finding("s1", {"host": "h", "port": 80,
                                           "vuln_type": "vulnerable_service",
                                           "cve": "CVE-2021-40438", "confidence": 0.9})
        # a candidate that the final set drops (e.g. FP-suppressed)
        store.upsert_finding("s1", {"host": "h", "port": 80,
                                    "vuln_type": "vulnerable_service",
                                    "cve": "CVE-2099-0001", "confidence": 0.3})
        assert store.count_findings("s1") == 2
        removed = store.prune_scan_findings("s1", {keep})
        assert removed == 1
        assert store.count_findings("s1") == 1
        assert store.list_findings(scan_id="s1")[0].cve_id == "CVE-2021-40438"

    def test_prune_never_touches_other_scans(self, store):
        other = store.upsert_finding("s2", {"host": "h", "port": 22,
                                            "vuln_type": "vulnerable_service",
                                            "cve": "CVE-2000-0001", "confidence": 0.9})
        store.upsert_finding("s1", {"host": "h", "port": 80,
                                    "vuln_type": "vulnerable_service",
                                    "cve": "CVE-2000-0002", "confidence": 0.9})
        store.prune_scan_findings("s1", set())   # keep nothing for s1
        assert store.count_findings("s2") == 1
        assert store.list_findings(scan_id="s2")[0].id == other


# ── Junk-finding suppression ─────────────────────────────────────────────────

class TestJunkFindings:
    def test_empty_target_unknown_type_is_junk_even_with_cve(self):
        assert _is_junk_finding({"vuln_type": "unknown", "target": "",
                                 "cve": "CVE-2020-29396", "severity": "high",
                                 "confidence": 0.8}) is True

    def test_real_finding_with_target_kept(self):
        assert _is_junk_finding({"vuln_type": "vulnerable_service",
                                 "host": "10.0.0.1", "cve": "CVE-2021-40438"}) is False

    def test_junk_dropped_by_dedup(self):
        good = {"host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
                "cve": "CVE-2021-40438"}
        junk = {"vuln_type": "unknown", "target": "", "cve": "CVE-2020-29396",
                "confidence": 0.8}
        out = dedup_findings([good, junk])
        assert len(out) == 1
        assert (out[0].get("cve") or out[0].get("cve_id")) == "CVE-2021-40438"


# ── Live CVE feed: generic products never sweep ──────────────────────────────

class TestLiveFeedGenericGuard:
    def test_discover_generic_returns_empty(self):
        from heaven.vulnscan.live_cve_feed import LiveCVEFeed
        feed = LiveCVEFeed()
        for label in ("http", "https", "ssl", "www"):
            assert asyncio.run(feed.discover(label)) == []
            # a version must NOT rescue a generic label
            assert asyncio.run(feed.discover(label, "0.6")) == []

    def test_discover_for_service_generic_returns_empty(self):
        from heaven.vulnscan.live_cve_feed import LiveCVEFeed
        feed = LiveCVEFeed()
        assert asyncio.run(feed.discover_for_service("http", "", "0.6")) == []


class TestCveMapperNoGenericSweep:
    def test_generic_http_service_does_not_sweep(self):
        from heaven.vulnscan import cve_mapper as CM

        class RecordingFeed:
            available = True

            def __init__(self):
                self.calls = []

            async def discover_for_service(self, service, banner="", version=""):
                self.calls.append(service)
                return []

        # A bare "http" service with no product identified must not call the feed.
        feed = RecordingFeed()
        host = {"host": "10.0.0.1", "open_ports": [
            {"port": 8080, "service": "http", "banner": "", "version": "", "product": ""},
        ]}
        out = asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                                 live_feed=feed, max_live_lookups=5))
        assert feed.calls == []
        assert out == []

    def test_identified_product_passes_resolved_key_not_raw_service(self):
        from heaven.vulnscan import cve_mapper as CM

        class RecordingFeed:
            available = True

            def __init__(self):
                self.calls = []

            async def discover_for_service(self, service, banner="", version=""):
                self.calls.append(service)
                return []

        feed = RecordingFeed()
        host = {"host": "10.0.0.1", "open_ports": [
            {"port": 8080, "service": "http", "banner": "", "version": "0.6",
             "product": "SimpleHTTPServer"},
        ]}
        asyncio.run(CM.map_vulnerabilities([host], nvd_client=None,
                                           live_feed=feed, max_live_lookups=5))
        # The feed is asked about the resolved product, NOT the raw "http" label
        # (which the CPE map would have turned into Apache).
        assert feed.calls == ["simplehttpserver"]


# ── Duplicate-submit guard on the scan endpoint ──────────────────────────────

class TestDuplicateScanGuard:
    def test_identical_back_to_back_launch_is_one_scan(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
        monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

        import heaven.api.server as srv

        # Neutralise the background runner so the POST exercises the duplicate
        # guard WITHOUT launching a real nmap scan (which would linger as an async
        # task and pollute later tests). The scan simply stays "pending".
        async def _noop(scan_id, req):
            return None
        monkeypatch.setattr(srv, "_run_scan_background", _noop)

        from fastapi.testclient import TestClient
        client = TestClient(srv.create_app())
        body = {"targets": ["127.0.0.1"], "mode": "network", "stealth_level": 3,
                "engagement": "dupguard", "i_have_authorization": True}
        try:
            r1 = client.post("/api/scans", json=body)
            r2 = client.post("/api/scans", json=body)
            assert r1.status_code == 200 and r2.status_code == 200, (r1.text, r2.text)
            # Second POST returns the SAME scan id — the duplicate was ignored.
            assert r1.json()["scan_id"] == r2.json()["scan_id"]
            # And exactly one scan is registered for that signature.
            sigs = [s for s in srv.active_scans.values()
                    if s.get("engagement") == "dupguard"]
            assert len(sigs) == 1
        finally:
            # active_scans is a module global — don't leak this test's entry into
            # the shared state other tests read.
            for sid in [k for k, v in list(srv.active_scans.items())
                        if v.get("engagement") == "dupguard"]:
                srv.active_scans.pop(sid, None)

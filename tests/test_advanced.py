"""Tests for kill chain mapping, FP suppression, rate limit, self-test."""
from __future__ import annotations

import sys

import pytest


# ── Kill Chain Analyzer ────────────────────────────────────────────────

class TestKillChain:

    def test_empty_report_structure(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer
        analyzer = KillChainAnalyzer()
        report = analyzer.report()
        assert report["model"] == "Lockheed Cyber Kill Chain"
        assert report["phase_count"] == 7
        assert report["coverage_score"] == 0
        assert len(report["phases"]) == 7

    def test_sqli_maps_to_exploitation_and_exfil(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer, KillChainPhase
        analyzer = KillChainAnalyzer()
        analyzer.ingest([{"type": "sqli", "severity": "critical", "target": "x"}])
        report = analyzer.report()
        phases_with = [p for p in report["phases"] if p["finding_count"] > 0]
        phase_ids = {p["phase_id"] for p in phases_with}
        assert int(KillChainPhase.EXPLOITATION) in phase_ids
        assert int(KillChainPhase.ACTIONS_ON_OBJECTIVES) in phase_ids

    def test_mitre_technique_mapping(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer, KillChainPhase
        analyzer = KillChainAnalyzer()
        analyzer.ingest([{
            "type": "phish_kit",
            "severity": "high",
            "target": "x",
            "mitre_technique": "T1566",  # Phishing → Delivery
        }])
        path = analyzer.attack_path_summary()
        assert any(p["phase"] == KillChainPhase.DELIVERY.label for p in path)

    def test_subtechnique_normalization(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer
        analyzer = KillChainAnalyzer()
        # T1078.004 should map to T1078 (Valid Accounts → Exploitation)
        analyzer.ingest([{"type": "x", "severity": "high", "target": "x",
                          "mitre_technique": "T1078.004"}])
        assert analyzer.coverage_score() > 0

    def test_attack_path_severity_picks_worst(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer
        analyzer = KillChainAnalyzer()
        analyzer.ingest([
            {"type": "sqli", "severity": "low", "target": "x"},
            {"type": "sqli", "severity": "critical", "target": "x"},
        ])
        path = analyzer.attack_path_summary()
        assert any(p["severity"] == "critical" for p in path)

    def test_mermaid_output_has_all_phases(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer
        analyzer = KillChainAnalyzer()
        analyzer.ingest([{"type": "sqli", "severity": "high", "target": "x"}])
        mermaid = analyzer.to_mermaid()
        for label in ("Reconnaissance", "Weaponization", "Delivery",
                      "Exploitation", "Installation",
                      "Command & Control", "Actions on Objectives"):
            assert label in mermaid

    def test_unknown_type_routes_to_recon_default(self):
        from heaven.mitre.kill_chain import KillChainAnalyzer
        analyzer = KillChainAnalyzer()
        analyzer.ingest([{"type": "totally_made_up_finding", "severity": "low", "target": "x"}])
        # Should still produce a report without crashing
        report = analyzer.report()
        assert report["total_findings_mapped"] == 1


# ── FP Suppression ─────────────────────────────────────────────────────

class TestFPSuppression:

    def test_apply_verdict_marks_suppressed(self):
        from heaven.vulnscan.fp_suppress import apply_verdict, SuppressionVerdict
        finding = {"vuln_type": "sqli", "confidence": 0.9}
        verdict = SuppressionVerdict(
            keep=False, final_confidence=0.2, bucket="discarded",
            reasons=["test_reason"],
        )
        out = apply_verdict(finding, verdict)
        assert out["suppressed"] is True
        assert out["result"] == "false_positive"
        assert out["confidence"] == 0.2

    def test_apply_verdict_keeps_high_confidence(self):
        from heaven.vulnscan.fp_suppress import apply_verdict, SuppressionVerdict
        finding = {"vuln_type": "sqli", "confidence": 0.9}
        verdict = SuppressionVerdict(
            keep=True, final_confidence=0.93, bucket="high",
            reasons=["reproducible"],
        )
        out = apply_verdict(finding, verdict)
        assert out["suppressed"] is False
        assert out["confidence"] == 0.93
        assert out["confidence_bucket"] == "high"


# ── Self-test accuracy reporting ───────────────────────────────────────

class TestAccuracyReport:

    def test_perfect_detection(self):
        from heaven.testing.selftest import evaluate_against_truth
        truth = {
            "target": "http://test", "fixture": "test",
            "expected_findings": [
                {"category": "sqli", "present": True},
                {"category": "xss", "present": True},
            ],
        }
        findings = [
            {"vuln_type": "sqli", "confidence": 0.95},
            {"vuln_type": "xss", "confidence": 0.90},
        ]
        report = evaluate_against_truth(findings, truth)
        assert report.true_positives == 2
        assert report.false_negatives == 0
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.f1_score == 1.0

    def test_missed_vuln_lowers_recall(self):
        from heaven.testing.selftest import evaluate_against_truth
        truth = {
            "target": "x", "fixture": "x",
            "expected_findings": [
                {"category": "sqli", "present": True},
                {"category": "xss", "present": True},
            ],
        }
        findings = [{"vuln_type": "sqli", "confidence": 0.95}]
        report = evaluate_against_truth(findings, truth)
        assert report.true_positives == 1
        assert report.false_negatives == 1
        assert report.recall == 0.5

    def test_false_positive_drops_precision(self):
        from heaven.testing.selftest import evaluate_against_truth
        truth = {
            "target": "x", "fixture": "x",
            "expected_findings": [
                {"category": "sqli", "present": True},
                {"category": "ssrf", "present": False},
            ],
        }
        findings = [
            {"vuln_type": "sqli", "confidence": 0.95},
            {"vuln_type": "ssrf", "confidence": 0.80},  # FP — fixture says not present
        ]
        report = evaluate_against_truth(findings, truth)
        assert report.true_positives == 1
        assert report.false_positives == 1
        assert report.precision == 0.5

    def test_unknown_category_treated_as_fp(self):
        from heaven.testing.selftest import evaluate_against_truth
        truth = {
            "target": "x", "fixture": "x",
            "expected_findings": [{"category": "sqli", "present": True}],
        }
        findings = [
            {"vuln_type": "sqli", "confidence": 0.95},
            {"vuln_type": "exotic_vuln_not_in_truth", "confidence": 0.80},
        ]
        report = evaluate_against_truth(findings, truth)
        assert report.false_positives == 1


# ── Rate limit (slowapi) integration ───────────────────────────────────

@pytest.fixture
def api_client(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "rate-limit-test-pwd")
    monkeypatch.setenv("HEAVEN_DB_PASSWORD", "rate-limit-test-db")
    monkeypatch.setenv("HEAVEN_RATE_LIMIT_LOGIN", "3/minute")
    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]
    from heaven.api.server import create_app
    from fastapi.testclient import TestClient
    return TestClient(create_app())


def test_login_rate_limit_kicks_in(api_client):
    """After exceeding the per-minute login cap, requests get 429."""
    # 3/minute limit — fourth request from the same IP should be rate limited.
    statuses = []
    for i in range(5):
        r = api_client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        statuses.append(r.status_code)
    # Some requests will succeed-with-401 (bad credentials), some will hit 429.
    # We just need at least one 429 to confirm the limiter is wired.
    assert 429 in statuses, f"expected at least one 429 in {statuses}"


# ── Hardened parse_port_range ──────────────────────────────────────────

def test_parse_port_range_dedup():
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range("80,80,80,443") == [80, 443]


def test_parse_port_range_whitespace_tolerant():
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range(" 80 , 443 ") == [80, 443]


def test_parse_port_range_empty_segments_tolerated():
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range("80,,443,") == [80, 443]


def test_parse_port_range_rejects_zero():
    from heaven.recon.network_scanner import parse_port_range
    with pytest.raises(ValueError):
        parse_port_range("0")


def test_parse_port_range_rejects_too_high():
    from heaven.recon.network_scanner import parse_port_range
    with pytest.raises(ValueError):
        parse_port_range("65536")
    with pytest.raises(ValueError):
        parse_port_range("100-99999")


def test_parse_port_range_normalizes_reversed():
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range("100-50") == parse_port_range("50-100")


# ── Kill Chain API endpoint ────────────────────────────────────────────

def test_kill_chain_endpoint_exists(api_client):
    """Authed kill-chain endpoint returns a structured report."""
    r = api_client.post("/api/auth/login", json={"username": "admin", "password": "rate-limit-test-pwd"})
    if r.status_code == 429:
        pytest.skip("rate limited from earlier test")
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    r = api_client.get("/api/kill-chain/latest", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert "report" in data
    assert "attack_path" in data
    assert "mermaid" in data
    assert data["report"]["phase_count"] == 7


class _BurstResp:
    """Minimal aiohttp-style response returning a fixed body under ``async with``."""

    def __init__(self, body: str):
        self._body = body
        self.status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def text(self) -> str:
        return self._body


class _BurstSession:
    """Fake session that drives ``RaceConditionDetector.test_race`` through its
    three phases so the reproduce-before-report guard can be exercised
    deterministically. With ``concurrent_requests=4`` the calls fall as:
    burst 1 (indices 0-3, divergent A/B → concurrent divergence), the stable
    4-sample sequential baseline (4-7, all A → not inherently dynamic), then the
    confirmation burst (8-11): divergent again iff ``reproduce`` (a real TOCTOU),
    otherwise stable (a transient artifact that must be dropped)."""

    def __init__(self, reproduce: bool):
        self.reproduce = reproduce
        self.n = 0

    def request(self, method, url, **_kw):
        i = self.n
        self.n += 1
        if i < 4:            # burst 1: diverge so succ_hashes > 1
            body = "A" if i % 2 == 0 else "B"
        elif i < 8:          # sequential baseline: stable so seq_hashes == 1
            body = "A"
        else:                # confirmation burst
            body = ("A" if i % 2 == 0 else "B") if self.reproduce else "A"
        return _BurstResp(body)


class TestRaceConditionPrecision:
    """The low-confidence TOCTOU heuristic must not fire on read-only pages."""

    def test_readonly_info_endpoints_are_skipped(self):
        """A race needs a state-changing target. phpinfo / server-status / metrics
        have no state, but their per-request resource counters diverge under
        concurrency and used to manufacture a bogus low 'race_condition' (the 1
        false positive keeping DVWA's benchmark at 97.9% precision). These are
        skipped outright — no network call, immediate None."""
        import asyncio
        from heaven.vulnscan.advanced_attacks import RaceConditionDetector
        for url in ("http://127.0.0.1:8080/?phpinfo=1", "http://h/server-status",
                    "http://h/info.php", "http://h/metrics", "http://h/opcache.php"):
            out = asyncio.run(RaceConditionDetector.test_race(
                session=None, url=url, method="POST", data={"x": "1"}))
            assert out is None, url

    def test_get_never_evidences_a_race(self):
        """A GET carries no state, so it can never evidence a race."""
        import asyncio
        from heaven.vulnscan.advanced_attacks import RaceConditionDetector
        out = asyncio.run(RaceConditionDetector.test_race(
            session=None, url="http://h/transfer", method="GET"))
        assert out is None

    def test_transient_divergence_that_does_not_reproduce_is_dropped(self):
        """A concurrent divergence that settles on the confirmation burst is a
        transient artifact (server-side lock contention / load jitter), NOT a
        race. Reproduce-before-report drops it — this is the class of spurious
        low-confidence race lead seen live on DVWA's authenticated POST
        endpoints, which kept the web benchmark's precision below 100%."""
        import asyncio
        from heaven.vulnscan.advanced_attacks import RaceConditionDetector
        out = asyncio.run(RaceConditionDetector.test_race(
            session=_BurstSession(reproduce=False), url="http://h/checkout",
            method="POST", data={"x": "1"}, concurrent_requests=4))
        assert out is None

    def test_reproducible_divergence_is_still_reported(self):
        """A genuine TOCTOU keeps committing divergent state, so the divergence
        RECURS on the confirmation burst; that real signal is still reported as
        the low-confidence (0.4) manual-verification lead — recall is preserved."""
        import asyncio
        from heaven.vulnscan.advanced_attacks import RaceConditionDetector
        out = asyncio.run(RaceConditionDetector.test_race(
            session=_BurstSession(reproduce=True), url="http://h/checkout",
            method="POST", data={"x": "1"}, concurrent_requests=4))
        assert out is not None
        assert out.vuln_type == "race_condition"
        assert out.confidence == 0.4

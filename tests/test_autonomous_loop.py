"""
Tests for the autonomous loop and supporting modules. None of these require
an LLM key — they exercise the rule-based fallback paths.
"""

from __future__ import annotations


import pytest


# ═══════════════════════════════════════════
# RULE-BASED PLANNER
# ═══════════════════════════════════════════


class TestRuleBasedPlanner:
    def test_iteration_zero_picks_scan_for_ip_seed(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0,
            targets_seed={"ips": ["10.0.0.1"], "urls": []},
        )
        assert action.kind == "scan"
        assert action.target == "10.0.0.1"
        assert action.mode == "full"

    def test_iteration_zero_picks_web_mode_for_url_seed(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0,
            targets_seed={"ips": [], "urls": ["http://x"]},
        )
        assert action.kind == "scan"
        assert action.mode == "web"

    def test_high_confidence_sqli_triggers_exploit_proof(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[{"vuln_type": "sqli_boolean", "confidence": 0.91,
                       "target": "http://x"}],
            iteration=1, targets_seed={"urls": ["http://x"]},
        )
        assert action.kind == "exploit_proof"

    def test_creds_discovered_triggers_postex(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[{"vuln_type": "default_credentials", "confidence": 0.95,
                       "title": "default admin password", "target": "10.0.0.5"}],
            iteration=1, targets_seed={"ips": ["10.0.0.5"]},
        )
        assert action.kind == "postex_credreuse"

    def test_no_seed_yields_noop(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0, targets_seed={"ips": [], "urls": []},
        )
        assert action.kind == "noop"

    def test_objective_met_simple_string_match(self):
        from heaven.ai.autonomous_loop import _objective_met
        findings = [{"vuln_type": "command_injection", "title": "RCE confirmed on host"}]
        assert _objective_met(findings, "rce confirmed") is True
        assert _objective_met(findings, "csrf bypass") is False
        # Empty objective always returns False
        assert _objective_met(findings, "") is False


# ═══════════════════════════════════════════
# KNOWLEDGE GRAPH
# ═══════════════════════════════════════════


class TestKnowledgeGraph:
    def _kg(self, tmp_path):
        from heaven.ai.knowledge_graph import KnowledgeGraph
        return KnowledgeGraph(tmp_path / "k.db")

    def test_fingerprint_stable(self, tmp_path):
        from heaven.ai.knowledge_graph import TargetProfile
        p1 = TargetProfile(os="linux", web_tech="php", open_ports_top=[22, 80])
        p2 = TargetProfile(os="linux", web_tech="php", open_ports_top=[80, 22])  # order
        assert p1.fingerprint() == p2.fingerprint()

    def test_different_profiles_different_fingerprints(self, tmp_path):
        from heaven.ai.knowledge_graph import TargetProfile
        a = TargetProfile(os="linux", web_tech="php")
        b = TargetProfile(os="windows", web_tech="iis")
        assert a.fingerprint() != b.fingerprint()

    def test_record_and_rank(self, tmp_path):
        from heaven.ai.knowledge_graph import TargetProfile
        kg = self._kg(tmp_path)
        p = TargetProfile(os="linux", web_tech="php", open_ports_top=[80])
        for outcome in ("success", "success", "success", "failure"):
            kg.record_attempt(p, "sqli_union", outcome)
        for outcome in ("failure", "failure", "failure"):
            kg.record_attempt(p, "xxe", outcome)
        rankings = kg.rank_techniques(p, top_n=5)
        assert len(rankings) >= 2
        assert rankings[0].technique == "sqli_union"
        assert rankings[0].posterior_success_rate > 0.5
        # xxe should rank low — 0/3 succeeded
        xxe = next(r for r in rankings if r.technique == "xxe")
        assert xxe.posterior_success_rate < 0.5

    def test_rejects_bad_outcome(self, tmp_path):
        from heaven.ai.knowledge_graph import TargetProfile
        kg = self._kg(tmp_path)
        p = TargetProfile()
        with pytest.raises(ValueError):
            kg.record_attempt(p, "x", "unknown_outcome")

    def test_stats_aggregate(self, tmp_path):
        from heaven.ai.knowledge_graph import TargetProfile
        kg = self._kg(tmp_path)
        p = TargetProfile(os="linux")
        kg.record_attempt(p, "ssrf", "success")
        kg.record_attempt(p, "ssrf", "failure")
        s = kg.stats()
        assert s["profiles"] == 1
        assert s["attempts"] == 2
        assert s["successes"] == 1


# ═══════════════════════════════════════════
# AUTH SESSION
# ═══════════════════════════════════════════


class TestAuthSession:
    def test_parse_auth_string_minimal(self):
        from heaven.recon.auth_session import parse_auth_string
        spec = parse_auth_string("url=/login,user=admin,pass=secret")
        assert spec["url"] == "/login"
        assert spec["user"] == "admin"
        assert spec["pass"] == "secret"
        assert spec["username_field"] == "username"

    def test_parse_auth_string_with_csrf(self):
        from heaven.recon.auth_session import parse_auth_string
        spec = parse_auth_string("url=/login,user=a,pass=b,csrf_field=csrf_token")
        assert spec["csrf_field"] == "csrf_token"

    def test_parse_auth_string_missing_required(self):
        from heaven.recon.auth_session import parse_auth_string
        with pytest.raises(ValueError):
            parse_auth_string("user=a,pass=b")   # missing url
        with pytest.raises(ValueError):
            parse_auth_string("url=/x,user=a")   # missing pass

    def test_empty_session_yields_empty_kwargs(self):
        from heaven.recon.auth_session import aiohttp_session_kwargs, clear_active_session
        clear_active_session()
        assert aiohttp_session_kwargs() == {}

    def test_cookie_file_missing_raises(self, tmp_path):
        from heaven.recon.auth_session import load_cookie_file
        with pytest.raises(FileNotFoundError):
            load_cookie_file(tmp_path / "nope.txt")


# ═══════════════════════════════════════════
# COVERAGE GRADER (rule-based path)
# ═══════════════════════════════════════════


class TestCoverageGrader:
    def _store(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "eng.db")
        store.create_engagement("test-engagement", client="t")
        return store

    def test_grade_empty_engagement_is_f(self, tmp_path):
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        report = grade_engagement_rule_based(store)
        assert report.grade == "F"
        assert report.total_findings == 0
        assert report.owasp_coverage_pct == 0.0

    def test_owasp_classification(self):
        from heaven.ai.coverage_grader import _classify
        assert _classify("sqli_boolean") == "A03_2021"
        assert _classify("ssrf") == "A10_2021"
        assert _classify("idor") == "A01_2021"
        assert _classify("weak_credentials") == "A07_2021"
        assert _classify("") is None

    def test_grade_with_scope_and_findings(self, tmp_path):
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        store.add_scope("10.0.0.1", kind="ip")
        store.add_scope("10.0.0.2", kind="ip")
        store.record_scan_start("scan-001", name="t", mode="full",
                                config={"targets": {"ips": ["10.0.0.1"]}})
        store.upsert_finding("scan-001", {
            "id": "f1", "target": "10.0.0.1", "vuln_type": "sqli_boolean",
            "title": "SQLi", "severity": "high", "confidence": 0.9,
        })
        report = grade_engagement_rule_based(store)
        assert report.scope_target_count == 2
        # one of A03_2021 (injection) should now be covered
        a03 = next(c for c in report.owasp_top10 if c.code == "A03_2021")
        assert a03.covered
        assert report.total_findings == 1
        # Recommendations should fire for missing auth / auto-prove
        assert any("authenticated" in r.lower() for r in report.recommendations)


# ═══════════════════════════════════════════
# EXPLOITDB CLIENT
# ═══════════════════════════════════════════


class TestExploitDBClient:
    @pytest.mark.asyncio
    async def test_invalid_cve_returns_error(self):
        from heaven.vulnscan.exploitdb_client import lookup_cve
        r = await lookup_cve("not-a-cve")
        assert r.error
        assert not r.entries

    @pytest.mark.asyncio
    async def test_enrich_findings_no_cves_returns_empty(self):
        from heaven.vulnscan.exploitdb_client import enrich_findings
        out = await enrich_findings([{"vuln_type": "xss"}])
        assert out == []

    def test_best_picks_verified_then_recent(self):
        from heaven.vulnscan.exploitdb_client import ExploitDBEntry, ExploitDBResult
        r = ExploitDBResult(
            cve="CVE-2024-1",
            entries=[
                ExploitDBEntry(edb_id="1", date_published="2020-01-01", verified=False),
                ExploitDBEntry(edb_id="2", date_published="2024-01-01", verified=True),
                ExploitDBEntry(edb_id="3", date_published="2023-01-01", verified=True),
            ],
        )
        assert r.best.edb_id == "2"


# ═══════════════════════════════════════════
# LATERAL MOVEMENT (auth gating only — actual SSH/SMB needs targets)
# ═══════════════════════════════════════════


class TestLateralAuthGating:
    def test_ssh_scanner_refuses_without_authorization(self):
        from heaven.postex.lateral import SSHKeyReuseScanner
        with pytest.raises(PermissionError):
            SSHKeyReuseScanner(authorized=False)

    def test_smb_executor_refuses_without_authorization(self):
        from heaven.postex.lateral import SMBLateralExecutor
        with pytest.raises(PermissionError):
            SMBLateralExecutor(authorized=False)

    @pytest.mark.asyncio
    async def test_run_lateral_refuses_without_authorization(self):
        from heaven.postex.lateral import run_lateral
        with pytest.raises(PermissionError):
            await run_lateral(authorized=False, targets=[("10.0.0.1", 22)])

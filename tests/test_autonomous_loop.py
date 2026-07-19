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
    def _scan(self, target, mode):
        from heaven.ai.autonomous_loop import AutonomousAction
        return AutonomousAction(kind="scan", target=target, mode=mode)

    def test_iteration_zero_picks_scan_for_ip_seed(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0,
            targets_seed={"ips": ["10.0.0.1"], "urls": []}, history=[],
        )
        assert action.kind == "scan"
        assert action.target == "10.0.0.1"
        assert action.mode == "full"

    def test_iteration_zero_picks_web_mode_for_url_seed(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0,
            targets_seed={"ips": [], "urls": ["http://x"]}, history=[],
        )
        assert action.kind == "scan"
        assert action.mode == "web"

    def test_recons_every_seed_before_moving_on(self):
        # The playbook must recon ALL seeds, not just the first — a run with two
        # hosts should scan both before deciding it's done.
        from heaven.ai.autonomous_loop import _rule_based_next_action
        seed = {"ips": ["10.0.0.1", "10.0.0.2"], "urls": []}
        history = [self._scan("10.0.0.1", "full")]
        action = _rule_based_next_action([], 1, seed, history)
        assert action.kind == "scan" and action.target == "10.0.0.2"

    def test_follows_newly_discovered_web_surface(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        seed = {"ips": [], "urls": ["https://app.example.com"]}
        history = [self._scan("https://app.example.com", "web")]
        findings = [{"target": "https://api.example.com/v1", "vuln_type": "info",
                     "severity": "info", "confidence": 0.3}]
        action = _rule_based_next_action(findings, 1, seed, history)
        assert action.kind == "scan"
        assert action.target == "https://api.example.com"

    def test_high_confidence_sqli_triggers_exploit_proof(self):
        # Once the seed is scanned (in history), an exploitable finding drives proof.
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[{"vuln_type": "sql_injection", "confidence": 0.91,
                       "target": "http://x"}],
            iteration=1, targets_seed={"urls": ["http://x"]},
            history=[self._scan("http://x", "web")],
        )
        assert action.kind == "exploit_proof"

    def test_exploit_proof_not_repeated(self):
        # If proof already ran, the planner must not loop on it forever.
        from heaven.ai.autonomous_loop import _rule_based_next_action, AutonomousAction
        history = [self._scan("http://x", "web"),
                   AutonomousAction(kind="exploit_proof")]
        action = _rule_based_next_action(
            findings=[{"vuln_type": "sql_injection", "confidence": 0.91,
                       "target": "http://x"}],
            iteration=2, targets_seed={"urls": ["http://x"]}, history=history,
        )
        assert action.kind == "noop"

    def test_creds_discovered_triggers_postex(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[{"vuln_type": "default_credentials", "confidence": 0.95,
                       "title": "default admin password", "target": "10.0.0.5"}],
            iteration=1, targets_seed={"ips": ["10.0.0.5"]},
            history=[self._scan("10.0.0.5", "full")],
        )
        assert action.kind == "postex_credreuse"

    def test_no_seed_yields_noop(self):
        from heaven.ai.autonomous_loop import _rule_based_next_action
        action = _rule_based_next_action(
            findings=[], iteration=0, targets_seed={"ips": [], "urls": []}, history=[],
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
# AUTONOMOUS LOOP — bug-fix regression: new-finding diff math
# Previous version did `list_findings()[:N]` to attribute new findings, but
# the engagement store orders by severity, not by recency, so the wrong
# findings got credited as "new" each iteration.
# ═══════════════════════════════════════════


class TestAutonomousLoopDiffMath:
    @pytest.mark.asyncio
    async def test_new_findings_attributed_by_id_diff(self, tmp_path, monkeypatch):
        """Run a one-iteration loop where _execute_action stubs in two new
        findings; verify they're correctly counted, not whichever happen to
        sort high by severity."""
        from heaven.engagement import EngagementStore
        from heaven.ai.autonomous_loop import (
            run_autonomous, AutonomousAction,
        )
        from heaven.ai import autonomous_loop as al

        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.record_scan_start("s1", name="seed", mode="full", config={})
        # Seed with a pre-existing CRITICAL finding so list_findings will
        # always sort it first. The diff math must NOT count it as "new".
        store.upsert_finding("s1", {
            "id": "old-critical", "target": "10.0.0.1",
            "vuln_type": "sqli_boolean", "title": "Old critical",
            "severity": "critical", "confidence": 0.95,
        })

        async def fake_execute_action(action, eng_store, cfg):
            # Add one NEW high-severity finding
            eng_store.upsert_finding("s1", {
                "id": "newly-found-high", "target": "10.0.0.1",
                "vuln_type": "xss", "title": "New high",
                "severity": "high", "confidence": 0.9,
            })

        async def fake_llm_next(*_a, **_kw):
            return None  # force rule-based path

        def fake_rule(_findings, _i, seed, _history):
            return AutonomousAction(
                kind="scan", target="10.0.0.1", mode="full",
                rationale="test", estimated_value=0.5,
            )

        monkeypatch.setattr(al, "_execute_action", fake_execute_action)
        monkeypatch.setattr(al, "_llm_next_action", fake_llm_next)
        monkeypatch.setattr(al, "_rule_based_next_action", fake_rule)

        summary = await run_autonomous(
            seed_targets={"ips": ["10.0.0.1"], "urls": []},
            engagement_store=store, base_config=None,
            max_iterations=1, time_budget_s=30,
            use_llm_planner=False,
        )

        assert len(summary.iterations) == 1
        it = summary.iterations[0]
        # The pre-existing critical must NOT be counted as new
        assert it.new_critical == 0, \
            f"old critical wrongly attributed as new: {it.new_critical}"
        # The newly-added high must be counted
        assert it.new_high == 1, \
            f"new high finding not detected: {it.new_high}"
        assert it.new_findings == 1


# ═══════════════════════════════════════════
# EXECUTIVE REPORT LAYER
# The autonomous summary must read like a professional report, not a bare
# number dump — even on a lean rule-based (no-LLM) run.
# ═══════════════════════════════════════════


class _FakeFinding:
    def __init__(self, severity, target, vuln_type, confidence, cve_id="", title=""):
        self.severity = severity
        self.target = target
        self.vuln_type = vuln_type
        self.confidence = confidence
        self.cve_id = cve_id
        self.title = title or vuln_type


class _FakeStore:
    def __init__(self, findings):
        self._f = findings

    def list_findings(self, **_kw):
        return list(self._f)


class TestExecutiveReport:
    def _summary(self, findings, objective="", objective_met=False, history=None):
        from heaven.ai.autonomous_loop import (
            _finalize_report, AutonomousRunSummary, AutonomousAction, IterationReport,
        )
        s = AutonomousRunSummary(started_at=0.0, ended_at=30.0,
                                 target_objective=objective, objective_met=objective_met)
        s.iterations = [IterationReport(iteration=i, action=AutonomousAction(kind="scan"),
                                        duration_s=5.0) for i in range(3)]
        hist = history or [AutonomousAction(kind="scan"), AutonomousAction(kind="scan")]
        _finalize_report(s, _FakeStore(findings), hist)
        return s.to_dict()

    def test_breakdown_hosts_and_top_findings(self):
        findings = [
            _FakeFinding("critical", "https://app.example.com/x", "sql_injection", 0.95,
                         "CVE-2021-41773", "SQL injection"),
            _FakeFinding("high", "https://app.example.com/y", "ssrf", 0.8),
            _FakeFinding("medium", "10.0.0.5", "ssl_weak_cipher", 0.6),
            _FakeFinding("low", "10.0.0.5", "missing_security_headers", 0.5),
            _FakeFinding("info", "10.0.0.6", "info_disclosure", 0.3),
        ]
        d = self._summary(findings)
        assert d["severity_breakdown"] == {"critical": 1, "high": 1, "medium": 1,
                                           "low": 1, "info": 1}
        assert d["total_findings"] == 5 and d["total_critical"] == 1
        # distinct hosts, URL-normalised
        assert d["hosts_engaged"] == ["10.0.0.5", "10.0.0.6", "app.example.com"]
        assert d["top_findings"][0]["cve_id"] == "CVE-2021-41773"
        assert d["actions_taken"] == {"scan": 2}

    def test_executive_summary_and_recommendations_present(self):
        findings = [_FakeFinding("critical", "10.0.0.1", "rce", 0.9)]
        d = self._summary(findings, objective="rce on host", objective_met=True)
        assert "critical" in d["executive_summary"].lower()
        assert "objective" in d["executive_summary"].lower()
        assert d["recommendations"]
        assert any("critical" in r.lower() for r in d["recommendations"])

    def test_empty_run_still_has_narrative_and_advice(self):
        d = self._summary([])
        assert d["total_findings"] == 0
        assert d["executive_summary"]  # never blank
        assert any("no findings" in r.lower() or "broaden" in r.lower()
                   for r in d["recommendations"])


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

    def test_cve_findings_classify_to_owasp(self):
        # Regression: CVE-derived findings carry vuln_type "vulnerable_service".
        # The old exact-token map had no such key, so every CVE finding
        # classified to None and the Coverage page read 0% OWASP coverage even
        # with dozens of findings. It must now map to A06 (Vulnerable and
        # Outdated Components), matching the HTML/PDF report.
        from heaven.ai.coverage_grader import _classify, _classify_finding
        assert _classify("vulnerable_service") == "A06_2021"
        assert _classify("ssl_weak_cipher") == "A02_2021"

        class _F:
            def __init__(self, vuln_type="", title="", evidence=None):
                self.vuln_type = vuln_type
                self.title = title
                self.evidence = evidence or {}

        # vuln_type + title keyword match
        assert _classify_finding(_F("vulnerable_service", "Apache mod_lua flaw")) == "A06_2021"
        # an enriched owasp evidence field wins over keyword guessing
        assert _classify_finding(
            _F("misc", "x", {"owasp": "A01:2021 Broken Access Control"})
        ) == "A01_2021"

    def test_grade_owasp_coverage_nonzero_with_cve_findings(self, tmp_path):
        # The reported bug end-to-end: an engagement full of CVE findings graded
        # 0% OWASP coverage. It must now be non-zero and mark A06 covered.
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        store.record_scan_start("scan-cve", name="t", mode="network",
                                config={"targets": {"ips": ["10.0.0.9"]}})
        for i, title in enumerate([
            "OpenSSH regreSSHion signal handler race",
            "Apache mod_lua vulnerable version",
            "OpenSSL outdated build",
        ]):
            store.upsert_finding("scan-cve", {
                "id": f"cve{i}", "target": "10.0.0.9:443",
                "vuln_type": "vulnerable_service", "title": title,
                "cve_id": f"CVE-2024-{1000 + i}",
                "severity": "high", "confidence": 0.9,
            })
        report = grade_engagement_rule_based(store)
        assert report.total_findings == 3
        assert report.owasp_coverage_pct > 0.0, "CVE findings must populate OWASP coverage"
        a06 = next(c for c in report.owasp_top10 if c.code == "A06_2021")
        assert a06.covered and a06.finding_count >= 1

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

    # ── Bug-fix regression: scope coverage on URL findings ──
    # Previous version did `f.target.split(":")[0]` which collapsed every URL
    # to "http"/"https" because "://" contains a colon, so every scope target
    # was flagged "untested" even when a finding actually hit it.
    def test_url_finding_marks_scope_target_as_scanned(self, tmp_path):
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        store.add_scope("app.example.com", kind="host")
        store.add_scope("other.example.com", kind="host")
        store.record_scan_start("scan-001", name="t", mode="web",
                                config={"targets": {"urls": ["https://app.example.com"]}})
        store.upsert_finding("scan-001", {
            "id": "f1", "target": "https://app.example.com/login?id=1",
            "vuln_type": "sqli_boolean", "title": "SQLi",
            "severity": "high", "confidence": 0.9,
        })
        report = grade_engagement_rule_based(store)
        assert report.scope_target_count == 2
        # ONLY other.example.com should be untested — app.example.com was scanned
        assert report.untested_scope_targets == ["other.example.com"], \
            f"URL parsing bug regression: {report.untested_scope_targets}"
        assert report.scanned_target_count == 1

    def test_host_port_finding_correctly_attributed(self, tmp_path):
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        store.add_scope("10.0.0.5", kind="ip")
        store.record_scan_start("scan-001", name="t", mode="network",
                                config={"targets": {"ips": ["10.0.0.5"]}})
        # host:port style target
        store.upsert_finding("scan-001", {
            "id": "f1", "target": "10.0.0.5:22",
            "vuln_type": "weak_credentials", "title": "Weak SSH password",
            "severity": "high", "confidence": 0.95,
        })
        report = grade_engagement_rule_based(store)
        assert report.untested_scope_targets == []
        assert report.scanned_target_count == 1

    def test_substring_does_not_match_different_hostname(self, tmp_path):
        # "example.com" must NOT match a scope of "badexample.com" — the old
        # `t in st` substring check was vulnerable to this.
        from heaven.ai.coverage_grader import grade_engagement_rule_based
        store = self._store(tmp_path)
        store.add_scope("badexample.com", kind="host")
        store.record_scan_start("scan-001", name="t", mode="web",
                                config={"targets": {"urls": ["https://example.com"]}})
        store.upsert_finding("scan-001", {
            "id": "f1", "target": "https://example.com/",
            "vuln_type": "xss_reflected", "title": "XSS",
            "severity": "medium", "confidence": 0.8,
        })
        report = grade_engagement_rule_based(store)
        # badexample.com was NOT scanned; example.com was. So untested == ["badexample.com"]
        assert report.untested_scope_targets == ["badexample.com"]


class TestTargetHost:
    """Standalone tests for the URL/host normaliser — the function the
    coverage bug regression hinges on."""

    def test_url_strips_scheme_and_port(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("https://app.example.com:8443/path?q=1") == "app.example.com"

    def test_ip_with_port(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("10.0.0.5:22") == "10.0.0.5"

    def test_bare_ip(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("10.0.0.5") == "10.0.0.5"

    def test_bare_hostname(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("example.com") == "example.com"

    def test_empty(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("") == ""
        assert _target_host("   ") == ""

    def test_url_without_port(self):
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("http://x.example.com/login") == "x.example.com"

    def test_url_with_user_info_handled(self):
        # urlparse strips user:pass@ from .hostname
        from heaven.ai.coverage_grader import _target_host
        assert _target_host("https://user:pass@app.example.com/") == "app.example.com"


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

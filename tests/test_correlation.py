"""Tests for the vulnerability correlation / combination advisor.

Covers the honesty contract: combinations are built only from distinct real
findings, only surfaced when they genuinely elevate above the strongest
constituent, scoped to a shared host unless the rule is cross-host, confidence
tracks the weakest link, and a combination is Confirmed only when every
constituent is confirmed.
"""

from __future__ import annotations

from heaven.vulnscan.correlation import (
    AMPLIFICATION_RULES,
    CombinationFinding,
    CorrelationEngine,
    correlate_findings,
)


def _f(**kw) -> dict:
    """Build a finding dict with sane defaults."""
    base = {
        "id": kw.get("id", ""),
        "target": "http://app.example.com/",
        "severity": "medium",
        "confidence": 0.7,
    }
    base.update(kw)
    return base


# ── Core positive case: LFI + upload → RCE (critical) ────────────────────────


def test_lfi_plus_upload_elevates_to_critical_rce():
    findings = [
        _f(id="a", vuln_type="path_traversal", title="Local file inclusion", severity="high"),
        _f(id="b", vuln_type="file_upload", title="Unrestricted file upload", severity="high"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert len(combos) == 1
    c = combos[0]
    assert isinstance(c, CombinationFinding)
    assert c.rule_id == "lfi_upload_rce"
    assert c.combined_severity == "critical"
    assert {m["id"] for m in c.components} == {"a", "b"}
    assert c.elevated_from == ["high", "high"]
    assert c.representative_cvss >= 9.0
    assert c.id.startswith("HEAVEN-CHAIN-")


def test_convenience_wrapper_returns_summary_shape():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high"),
        _f(id="b", vuln_type="unrestricted_upload", severity="high"),
    ]
    out = correlate_findings(findings)
    assert out["total_combinations"] == 1
    assert out["critical_combinations"] == 1
    assert out["combinations"][0]["rule_id"] == "lfi_upload_rce"


# ── Honesty gate: no elevation when the strongest constituent already tops it ─


def test_no_combo_when_severity_would_not_elevate():
    # sqli is already critical; the sqli+admin rule is also critical, so there is
    # nothing to elevate and it must not be reported.
    findings = [
        _f(id="a", vuln_type="sqli", severity="critical"),
        _f(id="b", vuln_type="admin_panel", severity="medium"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert combos == []


def test_sqli_high_plus_admin_elevates_to_critical():
    findings = [
        _f(id="a", vuln_type="sqli", title="SQL injection", severity="high"),
        _f(id="b", vuln_type="admin_panel", title="Exposed admin panel", severity="medium"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "sqli_admin_rce" and c.combined_severity == "critical"
               for c in combos)


# ── Need two DISTINCT findings ───────────────────────────────────────────────


def test_single_finding_yields_no_combos():
    assert CorrelationEngine().correlate([_f(id="a", vuln_type="lfi", severity="high")]) == []


def test_one_finding_cannot_fill_two_slots():
    # A single finding whose text matches both slots must NOT be reported as a
    # combination with itself.
    findings = [_f(id="a", vuln_type="lfi_file_upload",
                   title="path_traversal and file_upload", severity="high")]
    assert CorrelationEngine().correlate(findings) == []


# ── Host scoping ─────────────────────────────────────────────────────────────


def test_same_host_rule_requires_shared_host():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high", target="http://a.example.com/"),
        _f(id="b", vuln_type="file_upload", severity="high", target="http://b.example.com/"),
    ]
    # Different hosts → the same-host RCE rule must not fire.
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "lfi_upload_rce" for c in combos)


def test_cross_host_rule_spans_hosts():
    findings = [
        _f(id="a", vuln_type="hardcoded_secret", title="Leaked API key",
           severity="medium", target="http://a.example.com/"),
        _f(id="b", vuln_type="ssh", title="SSH exposed", severity="medium",
           target="10.0.0.9"),
    ]
    combos = CorrelationEngine().correlate(findings)
    combo = next((c for c in combos if c.rule_id == "secret_reuse_lateral"), None)
    assert combo is not None
    assert combo.cross_host is True
    assert set(combo.scope) == {"a.example.com", "10.0.0.9"}
    assert combo.combined_severity == "high"


# ── Confidence + confirmation semantics ──────────────────────────────────────


def test_confidence_tracks_weakest_link():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high", confidence=0.9),
        _f(id="b", vuln_type="file_upload", severity="high", confidence=0.6),
    ]
    c = CorrelationEngine().correlate(findings)[0]
    # weakest (0.6) with a one-dependency penalty (0.95): 0.57
    assert c.confidence == 0.57


def test_confirmed_only_when_all_members_confirmed():
    # Both members actively validated → Confirmed.
    confirmed = [
        _f(id="a", vuln_type="lfi", severity="high", evidence={"proof_output": "root:x:0:0"}),
        _f(id="b", vuln_type="file_upload", severity="high", validated=True),
    ]
    assert CorrelationEngine().correlate(confirmed)[0].confirmation == "Confirmed"

    # One member is a weak/low-confidence heuristic (no CVE) → Potential.
    mixed = [
        _f(id="a", vuln_type="lfi", severity="high", evidence={"proof_output": "ok"}),
        _f(id="b", vuln_type="file_upload", title="possible upload", severity="high",
           confidence=0.2),
    ]
    assert CorrelationEngine().correlate(mixed)[0].confirmation == "Potential"


# ── Rejected findings are never combined ─────────────────────────────────────


def test_false_positive_members_are_ignored():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high", status="false_positive"),
        _f(id="b", vuln_type="file_upload", severity="high"),
    ]
    assert CorrelationEngine().correlate(findings) == []


def test_suppressed_members_are_ignored():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high", suppressed=True),
        _f(id="b", vuln_type="file_upload", severity="high"),
    ]
    assert CorrelationEngine().correlate(findings) == []


# ── Unrelated findings produce nothing ───────────────────────────────────────


def test_unrelated_findings_yield_no_combos():
    findings = [
        _f(id="a", vuln_type="missing_security_header", severity="low"),
        _f(id="b", vuln_type="verbose_error", severity="low"),
        _f(id="c", vuln_type="tls_weak_cipher", severity="medium"),
    ]
    assert CorrelationEngine().correlate(findings) == []


# ── Determinism + ordering ───────────────────────────────────────────────────


def test_combo_id_is_stable_across_runs():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high"),
        _f(id="b", vuln_type="file_upload", severity="high"),
    ]
    a = CorrelationEngine().correlate(findings)[0].id
    b = CorrelationEngine().correlate(list(reversed(findings)))[0].id
    assert a == b


def test_results_sorted_critical_first():
    findings = [
        # high-only combo (open redirect + oauth → high)
        _f(id="r", vuln_type="open_redirect", severity="low"),
        _f(id="o", vuln_type="oauth", title="OAuth login", severity="medium"),
        # critical combo (lfi + upload → critical)
        _f(id="l", vuln_type="lfi", severity="high"),
        _f(id="u", vuln_type="file_upload", severity="high"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert len(combos) >= 2
    assert combos[0].combined_severity == "critical"


# ── Rule table integrity ─────────────────────────────────────────────────────


def test_every_rule_has_two_or_more_components_and_metadata():
    seen_ids = set()
    for rule in AMPLIFICATION_RULES:
        assert rule.rule_id not in seen_ids, f"duplicate rule id {rule.rule_id}"
        seen_ids.add(rule.rule_id)
        assert len(rule.components) >= 2
        assert rule.combined_severity in ("critical", "high", "medium")
        assert rule.name and rule.impact and rule.rationale
        # No em/en dashes in operator-visible prose (house style).
        for text in (rule.name, rule.impact, rule.rationale):
            assert "—" not in text and "–" not in text


def test_empty_input_is_safe():
    assert CorrelationEngine().correlate([]) == []
    assert correlate_findings([])["total_combinations"] == 0


# ── Advanced output: playbook, prerequisites, priority, phase, new rules ─────


def test_playbook_is_grounded_in_real_evidence():
    findings = [
        _f(id="a", vuln_type="path_traversal", title="LFI", severity="high",
           target="http://t.example/fi/?page=x", parameter="page"),
        _f(id="b", vuln_type="file_upload", title="Upload", severity="high",
           target="http://t.example/upload.php"),
    ]
    c = CorrelationEngine().correlate(findings)[0]
    steps = " ".join(c.playbook)
    assert c.playbook and c.prerequisites
    assert "http://t.example/upload.php" in steps        # the real upload URL
    assert "http://t.example/fi/?page=" in steps         # the real LFI parameter
    assert "?page==" not in steps                         # no double-equals artefact


def test_playbook_marks_unknown_fields_with_placeholder():
    # No captured parameter -> an explicit <param> placeholder, never blank/crash.
    findings = [
        _f(id="a", vuln_type="lfi", title="LFI", severity="high", target="http://t/view"),
        _f(id="b", vuln_type="file_upload", title="Upload", severity="high", target="http://t/up"),
    ]
    c = CorrelationEngine().correlate(findings)[0]
    assert any("<param>" in s for s in c.playbook)


def test_priority_and_actionability_scored():
    grounded = [
        _f(id="a", vuln_type="path_traversal", title="LFI", severity="high",
           target="http://t/fi?page=1", parameter="page", confidence=0.9),
        _f(id="b", vuln_type="file_upload", title="Upload", severity="high",
           target="http://t/up", evidence={"port": 8080}, confidence=0.9),
    ]
    c = CorrelationEngine().correlate(grounded)[0]
    assert 0.0 <= c.actionability <= 1.0
    assert c.actionability == 1.0            # each slot has url + param/port
    assert 0.0 <= c.priority <= 100.0
    assert c.priority > 70                   # fully actionable critical
    assert c.phase                           # kill-chain phase populated


def test_actionability_lower_without_concrete_evidence():
    bare = [
        _f(id="a", vuln_type="lfi", title="LFI", severity="high",
           target="host-only", confidence=0.9),
        _f(id="b", vuln_type="file_upload", title="Upload", severity="high",
           target="host-only", confidence=0.9),
    ]
    c = CorrelationEngine().correlate(bare)[0]
    # No URL scheme, no parameter/port/CVE -> lower actionability than a grounded combo.
    assert c.actionability < 1.0


def test_jwt_forge_plus_privileged_endpoint_elevates_to_critical():
    findings = [
        _f(id="j", vuln_type="jwt_weak", title="JWT signed with weak secret",
           severity="high", target="http://api/login"),
        _f(id="k", vuln_type="admin_panel", title="Admin API", severity="medium",
           target="http://api/admin"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "jwt_forge_privesc" and c.combined_severity == "critical"
               for c in combos)


def test_cleartext_creds_plus_login_form_elevates():
    findings = [
        _f(id="c", vuln_type="cleartext_transmission", title="Credentials over HTTP",
           severity="medium", target="http://legacy/login"),
        _f(id="l", vuln_type="login_form", title="Login form", severity="low",
           target="http://legacy/login"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "cleartext_creds_mitm" and c.combined_severity == "high"
               for c in combos)


def test_enumeration_plus_no_ratelimit_elevates():
    findings = [
        _f(id="e", vuln_type="username_enumeration", title="User enumeration",
           severity="medium", target="http://api/login"),
        _f(id="r", vuln_type="no_account_lockout", title="No lockout on login",
           severity="medium", target="http://api/login"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "enum_nolimit_bruteforce" and c.combined_severity == "high"
               for c in combos)


def test_to_dict_exposes_advanced_fields():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high"),
        _f(id="b", vuln_type="file_upload", severity="high"),
    ]
    d = CorrelationEngine().correlate(findings)[0].to_dict()
    for key in ("priority", "actionability", "phase", "prerequisites", "playbook"):
        assert key in d
    assert isinstance(d["playbook"], list) and d["playbook"]
    assert isinstance(d["prerequisites"], list) and d["prerequisites"]
    # Components carry the concrete evidence fields for the UI/report/CLI.
    for comp in d["components"]:
        for key in ("param", "port", "cve"):
            assert key in comp


def test_summary_reports_by_severity_and_priority():
    out = correlate_findings([
        _f(id="l", vuln_type="lfi", severity="high"),
        _f(id="u", vuln_type="file_upload", severity="high"),
    ])
    assert out["by_severity"].get("critical") == 1
    assert out["highest_priority"] > 0


def test_every_rule_has_phase_prereqs_and_wellformed_playbook():
    from heaven.vulnscan.correlation import _FIELD_FALLBACK, _TOKEN_RE
    valid_fields = set(_FIELD_FALLBACK)
    for rule in AMPLIFICATION_RULES:
        assert rule.phase, f"{rule.rule_id} missing phase"
        assert rule.prerequisites, f"{rule.rule_id} missing prerequisites"
        assert len(rule.playbook) >= 2, f"{rule.rule_id} needs a real playbook"
        # House style: no em/en dashes in operator-visible prose.
        for text in (*rule.prerequisites, *rule.playbook, rule.phase):
            assert "—" not in text and "–" not in text
        # Every template token must reference a real slot and a known field.
        for text in (*rule.prerequisites, *rule.playbook):
            for m in _TOKEN_RE.finditer(text):
                idx, fld = int(m.group(1)), m.group(2)
                assert idx < len(rule.components), f"{rule.rule_id}: bad slot s{idx}"
                assert fld in valid_fields, f"{rule.rule_id}: unknown field {fld}"


# ── Report section rendering ─────────────────────────────────────────────────


def test_report_includes_combined_risk_section_when_present():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    findings = [
        {"id": "a", "vuln_type": "path_traversal", "title": "LFI in ?page=",
         "severity": "high", "target": "http://x/", "confidence": 0.8},
        {"id": "b", "vuln_type": "file_upload", "title": "Unrestricted upload",
         "severity": "high", "target": "http://x/", "confidence": 0.7},
    ]
    html = ComplianceReportGenerator().generate_html_report(findings, "Test Eng")
    assert 'id="combined"' in html
    assert "Combined Risk" in html
    assert "Remote Code Execution" in html
    # The section carries the prerequisites and the target-grounded playbook.
    assert "Prerequisites for the chain" in html
    assert ("Reproduction steps" in html) or ("Proof / validation steps" in html)
    assert "http://x/" in html  # steps reference the real finding URL
    # TOC entry present.
    assert 'href="#combined"' in html


def test_report_omits_combined_risk_section_when_absent():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    findings = [
        {"id": "a", "vuln_type": "missing_security_header", "title": "No HSTS",
         "severity": "low", "target": "http://x/"},
    ]
    html = ComplianceReportGenerator().generate_html_report(findings, "Test Eng")
    assert 'id="combined"' not in html
    assert 'href="#combined"' not in html


# ── API endpoints ────────────────────────────────────────────────────────────


import pytest  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def test_post_correlate_returns_combinations(client):
    r = client.post("/api/correlate", json={"findings": [
        {"id": "a", "vuln_type": "path_traversal", "severity": "high", "target": "http://x/"},
        {"id": "b", "vuln_type": "file_upload", "severity": "high", "target": "http://x/"},
    ]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total_combinations"] == 1
    assert d["combinations"][0]["combined_severity"] == "critical"


def test_post_correlate_rejects_non_list(client):
    r = client.post("/api/correlate", json={"findings": {"not": "a list"}})
    assert r.status_code == 422, r.text


def test_post_correlate_empty_is_ok(client):
    r = client.post("/api/correlate", json={"findings": []})
    assert r.status_code == 200, r.text
    assert r.json()["total_combinations"] == 0


def test_get_correlations_latest_ok(client):
    r = client.get("/api/correlations/latest")
    assert r.status_code == 200, r.text
    d = r.json()
    assert "combinations" in d and "total_combinations" in d
    assert d["scan_id"] == "latest"


# ── Operator-submitted, natural-language findings (the real user scenario) ────
# A tester pastes their OWN findings, worded the way a human writes them
# ("SQL Injection in login form"), not HEAVEN's internal slugs ("sqli"). The
# matcher must fold separators and match at word boundaries so these still
# correlate, without matching the middle of unrelated words.


def test_users_exact_scenario_three_high_one_medium_natural_titles():
    # The user's example: three high + one medium, worded naturally, submitted
    # to the tool. They must combine into higher-severity issues.
    findings = [
        _f(id="1", title="SQL Injection in login form", severity="high",
           target="http://acme.test/login.php?id=1"),
        _f(id="2", title="Exposed Administrator Panel", severity="medium",
           target="http://acme.test/admin/"),
        _f(id="3", title="Stored Cross-Site Scripting in comments", severity="high",
           target="http://acme.test/guestbook"),
        _f(id="4", title="Session cookie missing SameSite attribute", severity="high",
           target="http://acme.test/"),
    ]
    combos = CorrelationEngine().correlate(findings)
    rule_ids = {c.rule_id for c in combos}
    assert "sqli_admin_rce" in rule_ids
    assert "xss_csrf_account_takeover" in rule_ids
    assert all(c.combined_severity == "critical" for c in combos)


def test_natural_lfi_plus_upload_wording_elevates_to_rce():
    findings = [
        _f(id="1", title="Local File Inclusion via page parameter", severity="high",
           target="http://acme.test/index.php?page=home"),
        _f(id="2", title="Unrestricted File Upload", severity="high",
           target="http://acme.test/upload.php"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert len(combos) == 1
    assert combos[0].rule_id == "lfi_upload_rce"
    assert combos[0].combined_severity == "critical"


def test_natural_default_creds_plus_ssh_wording_elevates():
    findings = [
        _f(id="1", title="Default credentials accepted", severity="high",
           target="http://acme.test/login"),
        _f(id="2", title="SSH service exposed", severity="medium",
           target="acme.test", port=22),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert len(combos) == 1
    assert combos[0].rule_id == "defaultcreds_exposed_service"
    assert combos[0].combined_severity == "critical"


def test_separator_folding_is_symmetric():
    # A slug keyword must match a spaced human title and the reverse.
    from heaven.vulnscan.correlation import _haystack, _kw_matches
    assert _kw_matches(_haystack({"title": "SQL Injection in login"}), "sql_injection")
    assert _kw_matches(_haystack({"vuln_type": "sql_injection"}), "sql injection")
    assert _kw_matches(_haystack({"title": "Open Redirect found"}), "open_redirect")


def test_word_boundary_stops_substring_false_positives():
    from heaven.vulnscan.correlation import _haystack, _kw_matches
    # "iam" must not match the middle of "reclaim"; it must match a real IAM
    # finding (word start). A stem still matches its inflection.
    assert not _kw_matches(_haystack({"title": "User can reclaim account"}), "iam")
    assert _kw_matches(_haystack({"title": "AWS IAM role over-privileged"}), "iam")
    assert _kw_matches(_haystack({"title": "Clickjacking possible"}), "clickjack")


def test_missing_csrf_token_is_not_treated_as_token_theft():
    # Regression: a MISSING csrf token is the opposite of a token-bearing auth
    # flow. Open redirect + "CSRF token missing" must NOT fabricate token theft.
    findings = [
        _f(id="1", title="Open Redirect in return parameter", severity="medium",
           target="http://acme.test/go?url=x"),
        _f(id="2", title="CSRF token missing on form", severity="medium",
           target="http://acme.test/form"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "open_redirect_oauth_ato" for c in combos)


def test_cwe_tagged_findings_correlate_even_with_terse_titles():
    # External tools often emit a CWE with a terse title. The engine should
    # still recognise the class from the CWE alone.
    findings = [
        _f(id="1", title="Injection", cwe="CWE-89", severity="high",
           target="http://acme.test/q?id=1"),
        _f(id="2", vuln_type="admin_panel", severity="medium",
           target="http://acme.test/admin/"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert len(combos) == 1
    assert combos[0].rule_id == "sqli_admin_rce"


def test_cwe_numeric_tail_guard_prevents_prefix_false_match():
    # CWE-890 is not CWE-89: a numeric keyword must not match a longer number.
    findings = [
        _f(id="1", title="Some issue", cwe="CWE-890", severity="high",
           target="http://acme.test/x"),
        _f(id="2", vuln_type="admin_panel", severity="medium",
           target="http://acme.test/admin/"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "sqli_admin_rce" for c in combos)

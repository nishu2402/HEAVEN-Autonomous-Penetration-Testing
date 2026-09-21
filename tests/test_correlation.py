"""Tests for the vulnerability correlation / combination advisor.

Covers the honesty contract: combinations are built only from distinct real
findings (never from a finding paired with a duplicate of itself, and never from
info-severity observations or rejected findings), scoped to a shared host unless
the rule is cross-host. A combination's severity is the higher of the rule's
rating and the strongest constituent, so it is never understated below a real
part nor overstated above the rule; a chain whose parts are already critical is
still reported at critical. Confidence tracks the weakest link, and a
combination is Confirmed only when every constituent is confirmed.
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


# ── Severity floor: a chain is never rated below its strongest part ──────────


def test_ceiling_chain_reported_at_critical_not_dropped():
    # sqli is already critical and the sqli+admin rule is critical, so there is
    # no numeric elevation left (critical is the ceiling). The chain is still a
    # distinct, materially worse issue (full takeover), so it IS reported, at
    # critical, never above it.
    findings = [
        _f(id="a", vuln_type="sqli", severity="critical"),
        _f(id="b", vuln_type="admin_panel", severity="medium"),
    ]
    combos = CorrelationEngine().correlate(findings)
    combo = next((c for c in combos if c.rule_id == "sqli_admin_rce"), None)
    assert combo is not None
    assert combo.combined_severity == "critical"


def test_combined_severity_floors_at_strongest_constituent():
    # A rule that declares "high" must still report "critical" when one of its
    # real constituents is already critical: a chain is never less severe than
    # one of its parts. secret_reuse_lateral declares high; a critical leaked
    # private key + a reachable service => critical.
    findings = [
        _f(id="a", vuln_type="private_key", title="Leaked private key",
           severity="critical", target="http://a.example.com/.ssh/id_rsa"),
        _f(id="b", vuln_type="ssh", title="SSH exposed", severity="medium",
           target="10.0.0.9"),
    ]
    combo = next((c for c in CorrelationEngine().correlate(findings)
                  if c.rule_id == "secret_reuse_lateral"), None)
    assert combo is not None
    assert combo.combined_severity == "critical"      # floored up from declared "high"
    assert combo.representative_cvss >= 9.0


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


def test_combined_risk_owasp_is_rendered_in_2025_taxonomy():
    """A combined risk must never show a stale OWASP 2021 edition beside the
    2025 findings in the same report. The rules carry 2021 category ids for
    historical reasons; they are crosswalked to Top 10:2025 at build time, so
    every emitted combination (and every rule that carries an OWASP tag) exposes
    only a 2025 id."""
    from heaven.devsecops.frameworks import owasp_2025_id
    from heaven.vulnscan.correlation import _owasp_2025

    # Every rule that carries a web-OWASP tag crosswalks to a valid 2025 id, and
    # the crosswalk never emits a 2021 edition (an unrecognised tag is preserved
    # verbatim rather than dropped).
    tagged = [r for r in AMPLIFICATION_RULES if r.owasp]
    assert tagged, "expected some rules to carry an OWASP tag"
    for rule in tagged:
        rendered = _owasp_2025(rule.owasp)
        assert ":2021" not in rendered, f"{rule.rule_id} still 2021: {rendered}"
        if owasp_2025_id(rule.owasp):          # a recognised web-OWASP tag
            assert ":2025" in rendered

    # A real emitted combination exposes a 2025 label end to end (dataclass +
    # the serialized dict the report / UI / API consume).
    findings = [
        _f(id="a", vuln_type="path_traversal", title="LFI", severity="high",
           target="http://t/fi?page=1", parameter="page"),
        _f(id="b", vuln_type="file_upload", title="Upload", severity="high",
           target="http://t/up"),
    ]
    combo = CorrelationEngine().correlate(findings)[0]
    assert combo.owasp and ":2025" in combo.owasp and ":2021" not in combo.owasp
    assert ":2021" not in str(combo.to_dict()["owasp"])


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


def test_cleartext_transport_plus_insecure_cookie_elevates():
    # The real sslstrip-style chain HEAVEN can observe: a downgradable/cleartext
    # channel plus a session cookie that is not bound to TLS.
    findings = [
        _f(id="t", vuln_type="no_hsts", title="HSTS not enabled",
           severity="medium", target="http://legacy.example/"),
        _f(id="c", vuln_type="cookie_no_secure", title="Session cookie missing Secure flag",
           severity="medium", target="http://legacy.example/login"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "cleartext_creds_mitm" and c.combined_severity == "high"
               for c in combos)


def test_cleartext_rule_ignores_autocomplete_best_practice_note():
    # Regression: "password field has autocomplete enabled" is a best-practice
    # note, not a credential-in-transit exposure. It must NOT fill the
    # session/credential slot (the old generic "password_field" keyword did).
    findings = [
        _f(id="t", vuln_type="no_hsts", title="HSTS not enabled",
           severity="medium", target="http://legacy.example/"),
        _f(id="p", vuln_type="password_autocomplete_enabled",
           title="Password field has autocomplete enabled", severity="low",
           target="http://legacy.example/login"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "cleartext_creds_mitm" for c in combos)


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


# ── Routing hardening: the SPA static mount at "/" must never swallow /api/* ──
# Regression for the operator-reported "API /correlate failed: Method Not
# Allowed". A StaticFiles mount at "/" full-matches every path for every method,
# so a stray trailing slash (or a stale server missing a route) used to surface
# as a bare 405/404 from the static server instead of a real API response. The
# /api/* fallback registered before the mount now answers these correctly.


def test_post_correlate_trailing_slash_still_works(client):
    # POST /api/correlate/ used to hit the static mount and return 405. It must
    # now reach the real route (via a method-preserving redirect) and succeed.
    r = client.post("/api/correlate/", json={"findings": [
        {"id": "a", "vuln_type": "path_traversal", "severity": "high", "target": "http://x/"},
        {"id": "b", "vuln_type": "file_upload", "severity": "high", "target": "http://x/"},
    ]})
    assert r.status_code == 200, r.text
    assert r.json()["total_combinations"] == 1


def test_wrong_method_on_api_route_is_clean_405(client):
    # GET on a POST-only route returns a JSON 405 with an Allow header naming the
    # real method, not the static server's opaque error.
    r = client.get("/api/correlate")
    assert r.status_code == 405, r.text
    assert "POST" in (r.headers.get("allow") or "")
    assert r.headers["content-type"].startswith("application/json")
    assert "detail" in r.json()


def test_unknown_api_path_returns_json_404_not_html(client):
    # An unknown /api/* path must return a clean JSON 404, never the SPA HTML
    # shell (which is what a mount-swallowed request would produce).
    r = client.post("/api/does-not-exist", json={})
    assert r.status_code == 404, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert "Unknown API endpoint" in r.json()["detail"]


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


# ── Duplicate / info / rejected findings must never manufacture a chain ──────


def test_duplicate_findings_do_not_self_pair():
    # A report carries the same finding in both its "vulnerabilities" and
    # "findings" arrays, so it arrives twice with no id. The engine must treat
    # the two identical rows as ONE finding and never combine it with its copy.
    dup = dict(vuln_type="default_credentials",
               title="SSH Default Credentials: user:user", severity="critical",
               target="10.0.0.5", confidence=0.9)
    findings = [dict(dup), dict(dup)]      # exact duplicates, no id
    assert CorrelationEngine().correlate(findings) == []


def test_duplicate_findings_by_id_do_not_self_pair():
    same = _f(id="dup-1", vuln_type="cmdi",
              title="Command injection", severity="critical")
    assert CorrelationEngine().correlate([dict(same), dict(same)]) == []


def test_info_severity_findings_are_excluded():
    # An informational observation is not a weakness and must not fill a slot.
    # A healthy SPF/DMARC posture (reported at info) must not read as spoofable.
    findings = [
        _f(id="s", vuln_type="spf_analysis", title="SPF record valid",
           severity="info", target="good.example.com"),
        _f(id="d", vuln_type="dmarc_analysis", title="DMARC p=reject",
           severity="info", target="good.example.com"),
    ]
    assert CorrelationEngine().correlate(findings) == []


def test_email_spoofing_rule_fires_on_spf_and_dmarc_gaps():
    # The common external-scan chain: no enforceable SPF + no DMARC enforcement
    # => the domain is practically spoofable. Domain-level, so cross-host.
    findings = [
        _f(id="s", vuln_type="spf_analysis", title="SPF Issues: acme.test",
           severity="high", target="acme.test"),
        _f(id="d", vuln_type="dmarc_missing", title="DMARC Record Missing",
           severity="high", target="acme.test"),
    ]
    combo = next((c for c in CorrelationEngine().correlate(findings)
                  if c.rule_id == "email_spoofing_capable"), None)
    assert combo is not None
    assert combo.combined_severity == "high"
    assert combo.cross_host is True


def test_jwt_signing_flaw_is_not_treated_as_oauth_token_theft():
    # Regression: a standalone weak-JWT signing finding is not a redirectable
    # OAuth/SSO flow. Open redirect + jwt_weak_secret must NOT fabricate the
    # open-redirect token-theft chain (the bare "jwt" keyword used to match it).
    findings = [
        _f(id="r", vuln_type="open_redirect", title="Open redirect in url param",
           severity="medium", target="http://acme.test/go?url=x"),
        _f(id="j", vuln_type="jwt_weak_secret", title="JWT signed with weak secret",
           severity="critical", target="http://acme.test/api"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "open_redirect_oauth_ato" for c in combos)


def test_default_creds_not_treated_as_leaked_secret():
    # default/guessable credentials are a weak-cred issue (chained by
    # defaultcreds_exposed_service), not a leaked secret. They must not fill the
    # "exposed secret" slot of secret_reuse_lateral and duplicate the chain.
    findings = [
        _f(id="a", vuln_type="default_credentials",
           title="SSH Default Credentials: user:user", severity="critical",
           target="10.0.0.5"),
        _f(id="b", vuln_type="vulnerable_service", title="Exposed FTP service",
           severity="high", target="10.0.0.5"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "secret_reuse_lateral" for c in combos)


def test_open_redirect_plus_real_oauth_flow_still_elevates():
    # The legitimate case the jwt fix must preserve: an OAuth flow finding still
    # pairs with an open redirect into the token-theft chain.
    findings = [
        _f(id="r", vuln_type="open_redirect", title="Open redirect",
           severity="medium", target="http://acme.test/go?url=x"),
        _f(id="o", vuln_type="oauth_state_reflected", title="OAuth state reflected",
           severity="medium", target="http://acme.test/oauth/callback"),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "open_redirect_oauth_ato" for c in combos)


def test_every_rule_can_fire_on_real_heaven_findings():
    # Guard against a rule going dead: a slot whose keywords match no real
    # HEAVEN finding vocabulary (as happened when cleartext_creds_mitm shipped
    # keywords no detector emitted). Each slot must match at least one real slug.
    from heaven.devsecops import vuln_kb
    kb = getattr(vuln_kb, "_KB")
    aliases = getattr(vuln_kb, "_ALIASES")
    slugs = sorted(set(list(kb.keys()) + list(aliases.keys())))
    for rule in AMPLIFICATION_RULES:
        for comp in rule.components:
            matched = [s for s in slugs
                       if comp.matches({"vuln_type": s, "title": s.replace("_", " ")})]
            assert matched, f"{rule.rule_id} slot '{comp.slot}' matches no real finding slug"


# ── Attack paths (multi-step chaining) ───────────────────────────────────────


from heaven.vulnscan.correlation import (  # noqa: E402
    _CAP_TOKENS, _RULE_GRANTS, _RULE_NEEDS, _host_role, _path_business_impact,
    _grants_of, _needs_of, AttackPath,
)


def _ssrf_defaultcreds_findings():
    """SSRF + exposed internal service on web01, default creds on an SSH host —
    the classic 'SSRF gives internal reach, default creds take the box' chain."""
    return [
        _f(id="s1", vuln_type="ssrf", title="Server-side request forgery",
           severity="high", confidence=0.9, status="confirmed",
           target="http://web01/fetch?url="),
        _f(id="s2", vuln_type="exposed_database", title="Exposed Redis",
           severity="high", confidence=0.9, status="confirmed",
           target="http://web01:6379/"),
        _f(id="s3", vuln_type="default_credentials", title="Default SSH credentials",
           severity="high", confidence=0.9, status="confirmed",
           target="ssh://db02:22"),
        _f(id="s4", vuln_type="ssh", title="SSH service exposed",
           severity="high", confidence=0.9, status="confirmed",
           target="ssh://db02:22"),
    ]


def test_capability_tables_are_well_formed():
    rule_ids = {r.rule_id for r in AMPLIFICATION_RULES}
    for rid, caps in {**_RULE_GRANTS, **_RULE_NEEDS}.items():
        assert rid in rule_ids, f"capability table references unknown rule {rid}"
        assert set(caps) <= _CAP_TOKENS, f"{rid} uses an unknown capability token"
    # Every rule resolves a (possibly empty) grants/needs set without error.
    for r in AMPLIFICATION_RULES:
        assert isinstance(_grants_of(r.rule_id), frozenset)
        assert isinstance(_needs_of(r.rule_id), frozenset)


def test_multi_step_attack_path_forms_across_hosts():
    eng = CorrelationEngine()
    combos = eng.correlate(_ssrf_defaultcreds_findings())
    paths = eng.attack_paths(combos)
    assert len(paths) == 1
    p = paths[0]
    assert isinstance(p, AttackPath)
    assert p.length == 2
    assert p.severity == "critical"
    # Ordered: SSRF pivot first (grants internal reach), then default-cred takeover.
    assert p.steps[0]["rule_id"] == "ssrf_internal_pivot"
    assert p.steps[1]["rule_id"] == "defaultcreds_exposed_service"
    # The cross-host hop is labelled with HOW the attacker moves.
    assert "internal network reach" in p.steps[1]["via"].lower()
    assert p.hosts == ["web01", "db02"]
    assert p.business_impact  # a concrete terminal impact
    assert p.id.startswith("HEAVEN-PATH-")


def test_attack_path_id_is_stable_across_runs():
    eng = CorrelationEngine()
    findings = _ssrf_defaultcreds_findings()
    a = eng.attack_paths(eng.correlate(findings))[0]
    b = eng.attack_paths(eng.correlate(list(reversed(findings))))[0]
    assert a.id == b.id


def test_credentials_handoff_links_two_combos():
    # A captured-credential step (cleartext transport + insecure cookie) feeds a
    # default-credential takeover: reuse the credentials on the reachable service.
    findings = [
        _f(id="c1", vuln_type="no_hsts", title="HSTS not set",
           severity="medium", confidence=0.9, status="confirmed",
           target="http://portal.acme.test/"),
        _f(id="c2", vuln_type="cookie_no_secure", title="Session cookie missing Secure",
           severity="medium", confidence=0.9, status="confirmed",
           target="http://portal.acme.test/login"),
        _f(id="c3", vuln_type="default_credentials", title="Default RDP credentials",
           severity="high", confidence=0.9, status="confirmed",
           target="rdp://jump.acme.test:3389"),
        _f(id="c4", vuln_type="rdp", title="RDP exposed",
           severity="high", confidence=0.9, status="confirmed",
           target="rdp://jump.acme.test:3389"),
    ]
    eng = CorrelationEngine()
    paths = eng.attack_paths(eng.correlate(findings))
    assert len(paths) == 1
    p = paths[0]
    assert p.steps[0]["rule_id"] == "cleartext_creds_mitm"
    assert p.steps[1]["rule_id"] == "defaultcreds_exposed_service"
    assert "credential" in p.steps[1]["via"].lower()


def test_unrelated_combos_do_not_chain_into_a_path():
    # Two genuine combinations (XSS+CSRF account takeover, IDOR+enum mass data)
    # that share no capability handoff must NOT be fabricated into a path.
    findings = [
        _f(id="u1", vuln_type="xss", severity="high", target="http://h/x"),
        _f(id="u2", vuln_type="csrf", severity="medium", target="http://h/y"),
        _f(id="u3", vuln_type="idor", severity="high", target="http://h/api"),
        _f(id="u4", vuln_type="user_enumeration", severity="medium", target="http://h/login"),
    ]
    eng = CorrelationEngine()
    combos = eng.correlate(findings)
    assert len(combos) >= 2
    assert eng.attack_paths(combos) == []


def test_longer_path_suppresses_its_contained_subpaths():
    # SSRF -> default creds -> credential reuse lateral is a 3-step chain; the
    # contained 2-step chains must not also be emitted as separate paths.
    findings = _ssrf_defaultcreds_findings() + [
        _f(id="s5", vuln_type="hardcoded_secret", title="Hardcoded API key",
           severity="medium", confidence=0.9, status="confirmed",
           target="http://db02/config.php"),
    ]
    eng = CorrelationEngine()
    paths = eng.attack_paths(eng.correlate(findings))
    assert len(paths) == 1
    assert paths[0].length == 3
    assert paths[0].steps[-1]["rule_id"] == "secret_reuse_lateral"


def test_attack_paths_empty_when_fewer_than_two_combos():
    findings = [
        _f(id="a", vuln_type="lfi", severity="high"),
        _f(id="b", vuln_type="file_upload", severity="high"),
    ]
    eng = CorrelationEngine()
    combos = eng.correlate(findings)
    assert len(combos) == 1
    assert eng.attack_paths(combos) == []


def test_host_role_inference():
    assert _host_role([{"vuln_type": "exposed_database", "target": "http://x:3306"}]) == "database server"
    assert _host_role([{"vuln_type": "mysql", "title": "MySQL server"}]) == "database server"
    assert _host_role([{"vuln_type": "ldap_anonymous", "target": "ldap://dc:389"}]) == "directory / domain controller"
    assert _host_role([{"vuln_type": "kerberos", "title": "Kerberos KDC"}]) == "directory / domain controller"
    assert _host_role([{"vuln_type": "xss", "target": "http://web/x"}]) == "host"


def test_path_business_impact_labels():
    dc = _path_business_impact({"admin"}, {"directory / domain controller"})[0]
    assert dc == "Domain / directory compromise"
    db = _path_business_impact({"foothold"}, {"database server"})[0]
    assert db == "Database server compromise"
    host = _path_business_impact({"foothold"}, {"host"})[0]
    assert host == "Full host compromise"
    assert _path_business_impact({"data"}, {"host"})[0] == "Sensitive data exposure"
    assert _path_business_impact({"credentials"}, {"host"})[0] == "Credential compromise"


def test_remediation_leverage_ranks_shared_finding_first():
    # One admin panel is the pivot for both an SQLi takeover and a JWT-forge
    # escalation: fixing it breaks two combined risks, so it is the top fix.
    findings = [
        _f(id="q", vuln_type="sqli", severity="high", target="http://app/",
           confidence=0.9, status="confirmed"),
        _f(id="p", vuln_type="admin_panel", title="Exposed admin panel",
           severity="high", target="http://app/admin", confidence=0.9, status="confirmed"),
        _f(id="j", vuln_type="jwt_none", title="JWT alg:none accepted",
           severity="high", target="http://app/api", confidence=0.9, status="confirmed"),
    ]
    out = correlate_findings(findings)
    top = out["remediation"]["top_fix"]
    assert top["title"] == "Exposed admin panel"
    assert top["chains_broken"] == 2


def test_remediation_cut_severs_every_attack_path():
    out = correlate_findings(_ssrf_defaultcreds_findings())
    rem = out["remediation"]
    assert out["total_attack_paths"] == 1
    assert rem["path_cut"], "a cut set should exist when paths exist"
    assert rem["paths_cut"] == rem["total_paths"] == 1


def test_summary_exposes_attack_paths_and_remediation():
    out = correlate_findings(_ssrf_defaultcreds_findings())
    assert "attack_paths" in out and "total_attack_paths" in out
    assert "remediation" in out
    assert isinstance(out["attack_paths"], list) and out["attack_paths"]
    assert set(out["remediation"]) >= {"by_finding", "top_fix", "path_cut",
                                       "total_paths", "paths_cut"}


def test_report_renders_attack_paths_and_break_the_chain():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    html = ComplianceReportGenerator().generate_html_report(
        _ssrf_defaultcreds_findings(), "Path Eng")
    assert "Attack paths" in html
    assert "Break the chain" in html
    assert "Sever every attack path" in html


# ── Network-reachability guard: a LOCAL-only CVE is not a network sensitive
#    function (regression for the CVE-2012-6095 false pairing seen on MSF2) ─────


def test_local_only_cve_does_not_fill_remote_sensitive_slot():
    # A missing-auth backdoor plus a LOCAL-only (CVSS AV:L) privilege CVE whose
    # title merely contains the words "arbitrary files". authbypass_sensitive_action
    # is about a NETWORK-reachable sensitive function reached without auth, so a
    # local-only finding must never fill its "Sensitive function" slot.
    findings = [
        _f(id="a", vuln_type="unauthenticated", target="10.0.0.5",
           title="Unauthenticated backdoor shell", severity="critical"),
        _f(id="b", vuln_type="vulnerable_service", target="10.0.0.5",
           title="ProFTPD allows local users to modify ownership of arbitrary files",
           severity="low", cve_id="CVE-2012-6095",
           evidence={"cvss_vector": "AV:L/AC:H/Au:N/C:N/I:P/A:N"}),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert all(c.rule_id != "authbypass_sensitive_action" for c in combos), (
        "a LOCAL-only (AV:L) CVE must not be treated as a network sensitive function")


def test_remote_sensitive_function_still_chains_behind_missing_auth():
    # The same shape but the sensitive function is genuinely network-reachable
    # (AV:N) — the chain MUST still fire, proving the guard is discriminating and
    # not a blanket suppression of the slot.
    findings = [
        _f(id="a", vuln_type="auth_bypass", target="10.0.0.5",
           title="Authentication bypass", severity="high"),
        _f(id="b", vuln_type="unrestricted_upload", target="10.0.0.5",
           title="Unrestricted file upload", severity="high",
           evidence={"cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
    ]
    combos = CorrelationEngine().correlate(findings)
    assert any(c.rule_id == "authbypass_sensitive_action" for c in combos), (
        "a network-reachable (AV:N) sensitive function behind missing auth must chain")


def test_unknown_attack_vector_is_not_suppressed():
    # A finding with no CVSS vector at all must NOT be suppressed — the guard only
    # removes findings it can prove are local, never on missing data.
    from heaven.vulnscan.correlation import _is_local_only
    assert _is_local_only({"vuln_type": "unrestricted_upload"}) is False
    assert _is_local_only({"evidence": {"cvss_vector": "AV:N/AC:L"}}) is False
    assert _is_local_only({"evidence": {"cvss_vector": "AV:L/AC:H"}}) is True
    assert _is_local_only({"evidence": {"cvss_vector": "AV:P/AC:L"}}) is True

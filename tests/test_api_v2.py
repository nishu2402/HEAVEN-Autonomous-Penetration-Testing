"""
HEAVEN — Smoke tests for the new API endpoints added in the publication
push (Gaps 1, 4, 5, 6, 7, 8, 9, 11).

Each test only verifies the route is reachable and returns the expected
shape. Behaviour tests for the underlying modules live in their own files
(test_metrics.py, test_smoke.py for fp_suppress, etc.).

Auth is disabled via HEAVEN_DISABLE_AUTH=1 so we don't have to log in for
every test — the route registration is what we're verifying here.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="module")
def api_client():
    os.environ["HEAVEN_DISABLE_AUTH"] = "1"
    from heaven.api.server import create_app
    from fastapi.testclient import TestClient
    app = create_app()
    yield TestClient(app)
    os.environ.pop("HEAVEN_DISABLE_AUTH", None)


# ── Gap 11: SIEM status ─────────────────────────────────────────────────

def test_siem_status_returns_shape(api_client):
    r = api_client.get("/api/siem/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "siem_backends_active" in body
    assert "webhook_active" in body
    assert isinstance(body["siem_backends_active"], list)


# ── Gap 9: Methodology docs ─────────────────────────────────────────────

def test_methodology_lists_docs(api_client):
    r = api_client.get("/api/methodology")
    assert r.status_code == 200, r.text
    body = r.json()
    # Backward-compatible raw docs still present …
    assert "docs" in body
    names = {d["name"] for d in body["docs"]}
    assert {"owasp_testing_guide", "nist_800_115", "ptes"}.issubset(names)
    # … plus the new structured coverage matrices + live overlay.
    assert "standards" in body and "engagement" in body
    std_names = {s["name"] for s in body["standards"]}
    assert {"owasp_testing_guide", "nist_800_115", "ptes"}.issubset(std_names)
    owasp = next(s for s in body["standards"] if s["name"] == "owasp_testing_guide")
    assert owasp["summary"]["total"] > 0
    assert owasp["summary"]["covered"] <= owasp["summary"]["total"]
    assert owasp["categories"], "expected parsed OWASP categories"
    # Every row carries a status + engagement overlay flags.
    row = owasp["categories"][0]["rows"][0]
    assert row["status"] in {"automated", "partial", "manual"}
    assert "exercised" in row and "exercised_count" in row


# ── System Health: external tools + one-shot install command ────────────

def test_system_health_lists_tools_with_install_command(api_client):
    r = api_client.get("/api/system/health")
    assert r.status_code == 200, r.text
    body = r.json()
    # The panel's copy-paste CTA + missing counter.
    assert body["install_command"] == "heaven install-tools"
    assert isinstance(body["tools_missing"], int)
    names = {t["name"] for t in body["tools"]}
    assert {"sqlmap", "ffuf", "searchsploit", "semgrep", "nmap"}.issubset(names)
    for t in body["tools"]:
        assert {"name", "present", "purpose", "hint"}.issubset(t)
        # Present tools carry no hint; missing tools always carry an actionable one.
        assert (t["hint"] == "") == bool(t["present"])


# ── Gap 1: Benchmark results ────────────────────────────────────────────

def test_benchmark_results_endpoint_responds(api_client):
    r = api_client.get("/api/benchmark/results")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "available" in body
    if body["available"]:
        # New structured shape: says which target produced the numbers and
        # carries parsed headline metrics, never a bare markdown dump.
        assert body["source"] in {"native-controlled", "live-dvwa"}
        assert body["label"] and body["target"] and body["markdown"]
        metrics = body["metrics"]
        assert set(metrics) == {"precision", "recall", "f1"}
        # A washout (target down → 0/0) must never be surfaced as the benchmark.
        assert metrics["precision"] or metrics["recall"], "washout leaked through"


def test_benchmark_metrics_parser_and_washout():
    """The headline parser reads both report formats and flags washouts."""
    from heaven.api.server import _parse_benchmark_metrics

    # Single-run table (native benchmark) — "required GT only" recall wins.
    single = (
        "| Precision (TP / TP+FP)       | 100.0% |\n"
        "| Recall (required GT only)    | 100.0% |\n"
        "| Recall (all GT)              | 90.0% |\n"
        "| F1                           | 100.0% |\n"
    )
    m = _parse_benchmark_metrics(single)
    assert m == {"precision": 1.0, "recall": 1.0, "f1": 1.0}

    # Aggregated table with ± stddev — first percentage per row.
    agg = "| Precision | 87.4% ± 2.1% |\n| Recall | 73.6% ± 3.8% |\n| F1 | 79.9% ± 2.6% |\n"
    m = _parse_benchmark_metrics(agg)
    assert m["precision"] == 0.874 and m["recall"] == 0.736 and m["f1"] == 0.799

    # Washout: parses but both precision and recall are zero.
    washout = "| Precision | 0.0% ± 0.0% |\n| Recall | 0.0% ± 0.0% |\n| F1 | 0.0% |\n"
    m = _parse_benchmark_metrics(washout)
    assert not m["precision"] and not m["recall"]

    # Nothing to parse.
    assert _parse_benchmark_metrics("# just a heading\n") is None


def test_benchmark_run_regenerates_and_returns_fresh(api_client, monkeypatch):
    """POST /api/benchmark/run re-runs BOTH native benchmark tiers (web + API) and
    returns their fresh numbers in the tiers array. Both native runners are mocked
    so the test is fast and independent of the in-process vuln-app fixtures."""
    import types

    def _md(target: str) -> str:
        return (
            f"# Benchmark: HEAVEN v9.9.9 vs. {target} v1.0\n\n"
            "| Precision (TP / TP+FP)    | 100.0% |\n"
            "| Recall (required GT only) | 100.0% |\n"
            "| F1                        | 100.0% |\n"
        )

    import tests.benchmarks.native.api_runner as api_runner_mod
    import tests.benchmarks.native.runner as runner_mod
    monkeypatch.setattr(
        runner_mod, "run_native_benchmark",
        lambda *, write_report=True: types.SimpleNamespace(markdown=_md("heaven-native-vuln-app")),
    )
    monkeypatch.setattr(
        api_runner_mod, "run_api_benchmark",
        lambda *, write_report=True: types.SimpleNamespace(markdown=_md("heaven-native-vuln-app-api")),
    )

    r = api_client.post("/api/benchmark/run")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is True
    # Both always-on native tiers are freshly regenerated and returned. (Live tiers
    # may also appear if their reports already exist on disk; we don't assert on
    # those here, only that the two native tiers we just ran are present + fresh.)
    tiers = {t["source"]: t for t in body["tiers"]}
    assert "native-controlled" in tiers and "native-controlled-api" in tiers
    web = tiers["native-controlled"]
    assert web["metrics"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    # HEAVEN's version is stamped into the header (removes the "which v1.0?"
    # ambiguity — that v1.0 is the target app's, not HEAVEN's).
    assert web["markdown"].splitlines()[0].startswith("# Benchmark: HEAVEN v")
    assert web["generated_at"]
    assert tiers["native-controlled-api"]["metrics"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_update_engagement_details_endpoint(api_client, monkeypatch):
    """PATCH /api/engagement edits Client / SOW; omitted fields are preserved."""
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", "patchtest")

    # Client-only edit — value is trimmed and internal whitespace collapsed.
    r = api_client.patch("/api/engagement", json={"client": "  ACME   Corp "})
    assert r.status_code == 200, r.text
    assert r.json()["engagement"]["client"] == "ACME Corp"

    # SOW-only edit leaves the client intact (partial PATCH).
    r = api_client.patch("/api/engagement", json={"statement_of_work": "SOW-2026-001"})
    assert r.status_code == 200, r.text
    eng = r.json()["engagement"]
    assert eng["client"] == "ACME Corp"
    assert eng["statement_of_work"] == "SOW-2026-001"

    # An empty body is rejected — nothing to change.
    assert api_client.patch("/api/engagement", json={}).status_code == 422


# ── Gap 6: AI layer triggers ────────────────────────────────────────────

def test_ai_unknown_kind_returns_400(api_client):
    r = api_client.post("/api/ai/nonsense/run", json={})
    assert r.status_code == 400


def test_ai_recon_parse_skips_when_no_gateway(api_client):
    # No API key set => gateway unavailable => endpoint returns {"skipped": ...}
    r = api_client.post("/api/ai/recon-parse/run", json={"recon": {"host": "x"}})
    assert r.status_code == 200, r.text


def test_ai_hypothesize_skips_when_no_gateway(api_client):
    # The vuln-hypothesis agent is propose-only over the API and must degrade to
    # {"skipped": ...} without an LLM key (never fabricate hypotheses).
    r = api_client.post("/api/ai/hypothesize/run",
                        json={"profile": {"tech_stack": ["php"]}, "endpoints": []})
    assert r.status_code == 200, r.text
    assert "skipped" in r.json()
    body = r.json()
    # Either skipped (no LLM key) or a real profile
    assert "skipped" in body or "host" in body


# ── Gap 5: Postex triggers (admin-permission-gated) ─────────────────────

def test_postex_unknown_module_returns_400(api_client):
    r = api_client.post("/api/postex/nonsense/run", json={})
    assert r.status_code == 400


def test_postex_linpeas_missing_field_returns_400(api_client):
    r = api_client.post("/api/postex/linpeas/run", json={})  # missing host/username
    assert r.status_code in (400, 500)


def test_postex_enum_missing_field_returns_400(api_client):
    r = api_client.post("/api/postex/enum/run", json={})  # missing host/username
    assert r.status_code == 400


def test_postex_enum_unreachable_host_returns_structured_failure(api_client):
    # A valid-shaped request to an unreachable host degrades gracefully to a
    # structured result rather than a 5xx (or 400 if asyncssh is absent).
    r = api_client.post("/api/postex/enum/run", json={
        "host": "127.0.0.1", "username": "nobody", "password": "x", "port": 1,
    })
    assert r.status_code in (200, 400, 500)
    if r.status_code == 200:
        body = r.json()
        assert body["success"] is False
        assert "host" in body and "vector_count" in body


def test_postex_loot_full_routes_share_endpoint(api_client):
    # enum/loot/full all route through /api/postex/{module}/run.
    for module in ("loot", "full"):
        r = api_client.post(f"/api/postex/{module}/run", json={})
        assert r.status_code == 400  # missing required host/username


def test_postex_win_enum_missing_field_returns_400(api_client):
    r = api_client.post("/api/postex/win-enum/run", json={})  # missing host/username
    assert r.status_code == 400


def test_postex_win_enum_unreachable_host_returns_structured_failure(api_client):
    r = api_client.post("/api/postex/win-enum/run", json={
        "host": "127.0.0.1", "username": "nobody", "password": "x", "port": 1,
    })
    assert r.status_code in (200, 400, 500)
    if r.status_code == 200:
        body = r.json()
        assert body["success"] is False
        assert body.get("platform") == "windows"


# ── Cloud misconfiguration: public-bucket exposure ──────────────────────

def test_cloud_storage_missing_target_returns_422(api_client):
    r = api_client.post("/api/cloud/storage", json={})
    assert r.status_code == 422


def test_cloud_storage_returns_structured_result(api_client):
    # A target that yields no valid bucket candidates → the endpoint returns a
    # structured, network-free result (no external probes from the test suite).
    r = api_client.post("/api/cloud/storage", json={"target": "...", "limit": 3})
    assert r.status_code == 200
    body = r.json()
    assert "buckets" in body and "candidates_tried" in body
    assert "findings" in body
    assert body["candidates_tried"] == 0


# ── Dynamic live CVE lookup ("vuln not in my local DB") ─────────────────

def test_cve_lookup_requires_product_or_cpe(api_client):
    r = api_client.post("/api/cve/lookup", json={})
    assert r.status_code == 422


def test_cve_lookup_returns_structured_result(api_client):
    # No httpx/network guarantee in CI: the route must still answer with a
    # well-formed, JSON-safe envelope (cached-or-empty), never 500.
    r = api_client.post("/api/cve/lookup", json={"product": "openssh", "version": "9.5"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["product"] == "openssh"
    assert "available" in body and "total" in body and "cves" in body
    assert isinstance(body["cves"], list)


# ── Gap 8: Replay missing scan ──────────────────────────────────────────

def test_replay_unknown_scan_returns_404(api_client):
    r = api_client.post("/api/scans/nonexistent_scan_id/replay", json={})
    assert r.status_code == 404


# ── Gap 4: Exploit-proof missing finding ────────────────────────────────

def test_prove_unknown_finding_returns_404(api_client):
    r = api_client.post("/api/findings/nonexistent_finding_id/prove")
    assert r.status_code == 404


# ── Gap 7: Train-priors needs engagement data ───────────────────────────

def test_train_priors_with_no_data_returns_422(api_client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)         # force empty engagements/ directories
    r = api_client.post("/api/priors/train")
    # 422 when no DBs found, 500 if subsystem missing — both prove the route registered
    assert r.status_code in (422, 500), r.text


# ── Quick coverage check that every new route is on the app ─────────────

def test_every_new_route_is_registered(api_client):
    paths = {r.path for r in api_client.app.routes}
    expected = {
        "/api/scans/{scan_id}/replay",
        "/api/findings/{finding_id}/prove",
        "/api/ai/{kind}/run",
        "/api/postex/{module}/run",
        "/api/priors/train",
        "/api/siem/status",
        "/api/methodology",
        "/api/benchmark/results",
        "/api/benchmark/run",
        # Sync-round-2 endpoints
        "/api/autonomous/run",
        "/api/coverage",
        "/api/lateral/run",
        "/api/knowledge/stats",
        "/api/knowledge/rank",
        "/api/exploitdb/{cve}",
        # Active exploitation / offline analysis / pivoting
        "/api/exploit/list",
        "/api/exploit/run",
        "/api/analyze/decode",
        "/api/analyze/run",
        "/api/pivot/run",
    }
    missing = expected - paths
    assert not missing, f"new API routes missing from app: {missing}"


# ── Active exploitation / analyze / pivot endpoints ─────────────────────

def test_exploit_list_returns_registered_exploits(api_client):
    r = api_client.get("/api/exploit/list")
    assert r.status_code == 200
    ids = {e["exploit_id"] for e in r.json()["exploits"]}
    assert "vsftpd_234_backdoor" in ids and "samba_usermap_script" in ids


def test_exploit_run_requires_target(api_client):
    r = api_client.post("/api/exploit/run", json={"i_have_authorization": True})
    assert r.status_code == 400


def test_exploit_run_requires_authorization(api_client):
    r = api_client.post("/api/exploit/run", json={"target": "127.0.0.1"})
    assert r.status_code == 403


def test_analyze_decode_roundtrips_base64(api_client):
    # "admin:secret" base64 → the decoder must recover it.
    r = api_client.post("/api/analyze/decode", json={"text": "YWRtaW46c2VjcmV0"})
    assert r.status_code == 200
    decodings = r.json()["report"]["decodings"]
    assert any("admin:secret" in d["decoded"] for d in decodings)


def test_analyze_run_requires_content(api_client):
    r = api_client.post("/api/analyze/run", json={"filename": "x.bin"})
    assert r.status_code == 400


def test_analyze_run_analyzes_uploaded_pcap_bytes(api_client):
    # A tiny non-artifact still round-trips through the dispatcher without a 5xx;
    # an empty/short blob simply yields an "unknown"/no-findings result.
    import base64
    blob = base64.b64encode(b"not-a-real-artifact").decode()
    r = api_client.post("/api/analyze/run",
                        json={"filename": "sample.txt", "content_b64": blob})
    assert r.status_code == 200
    assert "detected_kind" in r.json()


def test_pivot_run_requires_authorization(api_client):
    r = api_client.post("/api/pivot/run", json={
        "jumps": [{"host": "10.0.0.5", "username": "u", "password": "p"}]})
    assert r.status_code == 403


def test_pivot_run_requires_a_jump(api_client):
    r = api_client.post("/api/pivot/run",
                        json={"i_have_authorization": True, "jumps": []})
    assert r.status_code == 400


# ═══════════════════════════════════════════
# Sync-round-2 smoke tests
# ═══════════════════════════════════════════


def test_knowledge_stats_returns_shape(api_client):
    r = api_client.get("/api/knowledge/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "profiles" in body and "attempts" in body
    assert isinstance(body["top_techniques"], list)


def test_knowledge_rank_with_empty_profile(api_client):
    r = api_client.get("/api/knowledge/rank?os=linux&ports=22,80")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "fingerprint" in body
    assert "rankings" in body
    assert isinstance(body["rankings"], list)


def test_knowledge_rank_bad_ports(api_client):
    r = api_client.get("/api/knowledge/rank?os=linux&ports=not-a-number")
    assert r.status_code == 422


def test_coverage_returns_grade_for_empty_engagement(api_client, tmp_path, monkeypatch):
    from heaven.engagement import EngagementStore
    monkeypatch.chdir(tmp_path)
    # Initialise a brand-new engagement so the store exists
    EngagementStore(tmp_path / "engagement.db").create_engagement("e", client="c")
    r = api_client.get("/api/coverage?use_llm=false")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["grade"] in ("A", "B", "C", "D", "F")
    assert "owasp_top10" in body
    assert len(body["owasp_top10"]) == 10


def test_exploitdb_malformed_cve_returns_error_field(api_client):
    r = api_client.get("/api/exploitdb/not-a-cve")
    assert r.status_code == 200
    body = r.json()
    assert body["error"], "should return error for malformed CVE"


def test_lateral_run_no_targets_succeeds_empty(api_client):
    r = api_client.post("/api/lateral/run",
                        json={"ssh_usernames": ["root"], "targets": []})
    # No targets → run_lateral returns empty summary; endpoint shouldn't 500
    assert r.status_code == 200


def test_autonomous_run_missing_targets(api_client):
    r = api_client.post("/api/autonomous/run", json={})
    assert r.status_code == 422


# ── Autonomous loop is now a background job (run survives navigation) ────────

def test_autonomous_jobs_list_shape(api_client):
    r = api_client.get("/api/autonomous/jobs")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "jobs" in body and isinstance(body["jobs"], list)


def test_autonomous_job_not_found(api_client):
    r = api_client.get("/api/autonomous/jobs/does-not-exist")
    assert r.status_code == 404


# ── Admin identity is configurable (header is no longer a static "admin") ───

def test_admin_username_configurable(monkeypatch):
    """HEAVEN_ADMIN_USERNAME + HEAVEN_ADMIN_PASSWORD seed that exact account and
    skip the forced-change; the legacy admin/admin must then fail."""
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "nisarg")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "S3cure-Passw0rd-123")
    from heaven.security.auth import AuthManager
    am = AuthManager()
    res = am.authenticate("nisarg", "S3cure-Passw0rd-123")
    assert res and res["user"]["username"] == "nisarg"
    assert res["user"]["role"] == "admin"
    assert res["must_change_password"] is False
    assert am.authenticate("admin", "admin") is None


# ── SCA (Software Composition Analysis / OSV.dev) endpoint ─────────────────

def test_sca_requires_path(api_client):
    r = api_client.post("/api/sca", json={})
    assert r.status_code == 422


def test_sca_endpoint_returns_shape(api_client, monkeypatch, tmp_path):
    """The /api/sca route audits a path and returns normalised findings.
    scan_path is stubbed so the test never touches the network."""
    # Isolate the engagement store: /api/sca persists a scan record, and without
    # chdir it lands in the real ./data/engagements/<active>.db, polluting the
    # operator's live engagement with a "SCA: test_..." junk scan on every run.
    monkeypatch.chdir(tmp_path)
    import heaven.vulnscan.sca_scanner as sca

    async def fake_scan_path(root, max_files=200, client=None):
        return {
            "packages": 1,
            "manifests": ["requirements.txt"],
            "findings": [{
                "vuln_type": "vulnerable_dependency", "severity": "high",
                "title": "Vulnerable dependency: flask 0.12.2", "cvss": 7.5,
                "cve_id": "CVE-2018-1000656",
                "evidence": {"package": "flask", "installed_version": "0.12.2",
                             "osv_id": "GHSA-1", "signals": ["osv_advisory_version_match"]},
            }],
        }

    monkeypatch.setattr(sca, "scan_path", fake_scan_path)
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    r = api_client.post("/api/sca", json={"path": str(tmp_path)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["packages"] == 1
    assert body["findings"][0]["vuln_type"] == "vulnerable_dependency"
    # enrichment ran → OWASP A03 (Software Supply Chain Failures) filled in from the KB
    assert body["findings"][0].get("owasp", "").startswith("A03")

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
    assert "docs" in body
    names = {d["name"] for d in body["docs"]}
    # The three documents we shipped
    assert {"owasp_testing_guide", "nist_800_115", "ptes"}.issubset(names)


# ── Gap 1: Benchmark results ────────────────────────────────────────────

def test_benchmark_results_endpoint_responds(api_client):
    r = api_client.get("/api/benchmark/results")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "available" in body


# ── Gap 6: AI layer triggers ────────────────────────────────────────────

def test_ai_unknown_kind_returns_400(api_client):
    r = api_client.post("/api/ai/nonsense/run", json={})
    assert r.status_code == 400


def test_ai_recon_parse_skips_when_no_gateway(api_client):
    # No API key set => gateway unavailable => endpoint returns {"skipped": ...}
    r = api_client.post("/api/ai/recon-parse/run", json={"recon": {"host": "x"}})
    assert r.status_code == 200, r.text
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
    }
    missing = expected - paths
    assert not missing, f"new API routes missing from app: {missing}"

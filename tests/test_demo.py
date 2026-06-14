"""HEAVEN — tests for the demo / sample-data seeder + its API endpoint.

The seeder powers `heaven demo` and the web "Load sample data" button. These
guard that it populates a realistic severity spread, is idempotent, and that the
endpoint writes to the same store the dashboard reads.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def store(tmp_path):
    from heaven.engagement import EngagementStore
    return EngagementStore(tmp_path / "default.db")


def test_seed_populates_severity_spread(store):
    from heaven.demo import seed_demo
    result = seed_demo(store)
    assert result["findings"] == 12
    assert result["by_severity"] == {"critical": 3, "high": 3, "medium": 4, "low": 2}
    assert result["targets"] == 3


def test_seed_is_idempotent(store):
    from heaven.demo import seed_demo
    seed_demo(store)
    seed_demo(store)  # second run must dedupe, not double up
    import sqlite3
    n = sqlite3.connect(store.db_path).execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]
    assert n == 12


def test_seed_records_engagement_and_scan(store):
    from heaven.demo import DEMO_ENGAGEMENT, seed_demo
    seed_demo(store)
    eng = store.get_engagement()
    assert eng is not None and eng.name == DEMO_ENGAGEMENT
    scans = store.list_scans()
    assert any(s["id"] == "demo-scan-0001" for s in scans)


def test_findings_carry_evidence_for_detail_view(store):
    from heaven.demo import seed_demo
    seed_demo(store)
    import json
    import sqlite3
    c = sqlite3.connect(store.db_path)
    row = c.execute(
        "SELECT evidence_json FROM findings WHERE vuln_type='sqli'"
    ).fetchone()
    ev = json.loads(row[0])
    assert ev.get("remediation") and ev.get("description")


# ── API endpoint ──

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def test_api_seed_demo(client):
    r = client.post("/api/demo/seed")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["findings"] == 12
    # and the dashboard now reflects it
    dash = client.get("/api/engagement").json()
    total = (dash.get("stats") or {}).get("total_findings", 0)
    assert total >= 12

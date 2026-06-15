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


def test_api_top_findings_ranked(client):
    client.post("/api/demo/seed")
    r = client.get("/api/engagement/top-findings?limit=5")
    assert r.status_code == 200, r.text
    items = r.json()["findings"]
    assert len(items) == 5
    # ranked by risk_score descending, and each carries a remediation
    scores = [float(f["risk_score"]) for f in items]
    assert scores == sorted(scores, reverse=True)
    assert all(f["remediation"] for f in items)
    assert items[0]["severity"] == "critical"


def test_help_and_version_exit_clean():
    """Regression: the friendly-error wrapper must NOT swallow click's Exit
    (raised by --help / --version), which would print a spurious error and
    exit non-zero."""
    from click.testing import CliRunner
    from heaven.main import cli
    for args in (["--help"], ["--version"], ["demo", "--help"], ["quickstart", "--help"]):
        r = CliRunner().invoke(cli, args)
        assert r.exit_code == 0, (args, r.output)
        assert "re-run with --debug" not in r.output, args


def test_quickstart_creates_env_and_seeds(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HEAVEN_ADMIN_PASSWORD", raising=False)
    from click.testing import CliRunner
    from heaven.main import cli
    result = CliRunner().invoke(cli, ["quickstart"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".env").exists()
    env = (tmp_path / ".env").read_text()
    assert "HEAVEN_ADMIN_PASSWORD=" in env
    # demo data was seeded into the default store
    from heaven.demo import resolve_demo_store
    import sqlite3
    n = sqlite3.connect(resolve_demo_store().db_path).execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]
    assert n == 12


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


async def test_api_demo_scan_runs_full_loop(monkeypatch, tmp_path):
    """The animated demo scan must progress running → completed and land the
    sample findings. Uses an async client so the background task's awaits run,
    and a tiny phase delay so it finishes fast."""
    import asyncio
    import httpx
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "x" * 12)
    monkeypatch.setenv("HEAVEN_DEMO_SCAN_DELAY", "0.02")
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from heaven.api.server import create_app
        app = create_app()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post("/api/demo/scan")
            assert r.status_code == 200, r.text
            sid = r.json()["scan_id"]
            status = None
            for _ in range(60):
                await asyncio.sleep(0.03)
                scans = (await c.get("/api/scans")).json()["scans"]
                me = next((s for s in scans if s.get("scan_id") == sid), None)
                if me and me.get("status") in ("completed", "failed"):
                    status = me.get("status")
                    break
            assert status == "completed"
            tot = (await c.get("/api/engagement")).json().get("stats", {}).get("total_findings", 0)
            assert tot >= 12
    finally:
        auth_mod._auth_manager = None

"""API tests for Watch-mode endpoints.

run_watch is mocked so no real scan runs — these prove the web launcher's
validation, job registry, channel reporting, and stop/404 paths. Mirrors the
auth-disabled TestClient fixture used by test_api_chat.py.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


@pytest.fixture
def client(tmp_path, monkeypatch):
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


def _make_engagement(name="watchtest"):
    """Materialise an engagement DB so watch/start's existence check passes."""
    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import EngagementStore
    path = _engagement_db_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    EngagementStore(path)
    return name


def test_channels_shape(client):
    r = client.get("/api/watch/channels")
    assert r.status_code == 200, r.text
    d = r.json()
    assert {"webhook_active", "siem_backends_active",
            "ticketing_backends"}.issubset(d)
    assert isinstance(d["siem_backends_active"], list)
    assert isinstance(d["ticketing_backends"], list)


def test_start_requires_engagement(client):
    r = client.post("/api/watch/start", json={"urls": ["https://x.example"]})
    assert r.status_code == 422, r.text


def test_start_engagement_not_found(client):
    r = client.post("/api/watch/start",
                    json={"engagement": "does-not-exist",
                          "urls": ["https://x.example"]})
    assert r.status_code == 404, r.text


def test_start_requires_targets(client):
    name = _make_engagement()
    r = client.post("/api/watch/start", json={"engagement": name})
    assert r.status_code == 422, r.text


def test_start_rejects_bad_url(client):
    name = _make_engagement()
    r = client.post("/api/watch/start",
                    json={"engagement": name, "urls": ["not a url"]})
    assert r.status_code == 422, r.text


def test_start_ok_mocked(client, monkeypatch):
    name = _make_engagement()
    import heaven.utils.watcher as watcher_mod
    from heaven.utils.watcher import WatchSummary

    async def fake_run_watch(config, base_config, *, on_iteration=None):
        # No real scan — return an empty summary immediately.
        return WatchSummary()

    monkeypatch.setattr(watcher_mod, "run_watch", fake_run_watch)

    r = client.post("/api/watch/start",
                    json={"engagement": name, "urls": ["https://x.example"],
                          "max_iterations": 2, "interval_s": 15, "mode": "web"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "running" and d["job_id"]

    jid = d["job_id"]
    r2 = client.get(f"/api/watch/jobs/{jid}")
    assert r2.status_code == 200, r2.text
    job = r2.json()
    assert job["engagement"] == name
    assert job["max_iterations"] == 2
    assert job["interval_s"] == 15
    # And it shows up in the list.
    r3 = client.get("/api/watch/jobs")
    assert any(j["job_id"] == jid for j in r3.json()["jobs"])


def test_start_bounds_max_iterations(client, monkeypatch):
    name = _make_engagement()
    import heaven.utils.watcher as watcher_mod
    from heaven.utils.watcher import WatchSummary

    async def fake_run_watch(config, base_config, *, on_iteration=None):
        return WatchSummary()

    monkeypatch.setattr(watcher_mod, "run_watch", fake_run_watch)

    # 0 iterations is rejected (a web-launched watch must be bounded ≥ 1).
    r = client.post("/api/watch/start",
                    json={"engagement": name, "urls": ["https://x.example"],
                          "max_iterations": 0})
    assert r.status_code == 422, r.text

    # An absurd value is clamped to the ceiling (500), not accepted verbatim.
    r2 = client.post("/api/watch/start",
                     json={"engagement": name, "urls": ["https://x.example"],
                           "max_iterations": 999999})
    assert r2.status_code == 200, r2.text
    job = client.get(f"/api/watch/jobs/{r2.json()['job_id']}").json()
    assert job["max_iterations"] == 500


def test_job_and_stop_404(client):
    assert client.get("/api/watch/jobs/deadbeef00").status_code == 404
    assert client.post("/api/watch/jobs/deadbeef00/stop").status_code == 404

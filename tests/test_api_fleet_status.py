"""API test for the Agent Fleet status endpoint.

`GET /api/fleet/status` powers the Settings / Health panel's fleet card. It must
report an honest picture (tier, whether the engine is enabled, and the exact mode
set) and never 500 — the fleet runs at full strength with no brain, so 'AI
optional' is a normal state, not an error. Mirrors the auth-disabled TestClient
fixture used by test_api_chat.py / test_api_watch.py.
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


def test_fleet_status_shape(client):
    r = client.get("/api/fleet/status")
    assert r.status_code == 200, r.text
    d = r.json()
    # Honest status block the UI renders.
    for key in ("tier", "label", "available", "enabled", "modes", "workers", "scale_out"):
        assert key in d, f"missing {key}"
    assert isinstance(d["enabled"], bool)
    assert isinstance(d["modes"], list)
    # Scale-out is off (single worker) unless the operator opts in.
    assert isinstance(d["workers"], int) and d["workers"] >= 1
    assert isinstance(d["scale_out"], bool)
    assert d["scale_out"] == (d["workers"] > 1)


def test_fleet_status_modes_match_scanner(client):
    """The reported mode set is exactly the scanner's backend modes plus `full`, so
    the UI can never advertise a mode the fleet cannot actually drive."""
    from heaven.ai.fleet import BACKEND_MODES

    d = client.get("/api/fleet/status").json()
    assert d["modes"] == ["full", *BACKEND_MODES]
    # And that set equals every ScanMode (the mode-sync guarantee, surfaced to the UI).
    from heaven.config import ScanMode
    assert set(d["modes"]) == {m.value for m in ScanMode}


def test_fleet_status_never_errors_block(client):
    """Even with no brain configured the endpoint returns a clean 200 status block,
    not an error object."""
    d = client.get("/api/fleet/status").json()
    assert "error" not in d
    assert d["tier"] in (0, 1, 4)  # deterministic / local / cloud


# ── run launcher (background job) ────────────────────────────────────────────
def _make_engagement(name="fleetapi"):
    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import EngagementStore
    path = _engagement_db_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    EngagementStore(path)
    return name


def test_fleet_run_requires_engagement(client):
    r = client.post("/api/fleet/run", json={"urls": ["https://x.example"]})
    assert r.status_code == 422, r.text


def test_fleet_run_requires_target(client):
    _make_engagement()
    r = client.post("/api/fleet/run", json={"engagement": "fleetapi"})
    assert r.status_code == 422, r.text


def test_fleet_run_engagement_not_found(client):
    r = client.post("/api/fleet/run",
                    json={"engagement": "does-not-exist", "urls": ["https://x.example"]})
    assert r.status_code == 404, r.text


def test_fleet_run_invalid_mode(client):
    _make_engagement()
    r = client.post("/api/fleet/run",
                    json={"engagement": "fleetapi", "urls": ["https://x.example"],
                          "mode": "not-a-mode"})
    assert r.status_code == 422, r.text


def test_fleet_run_is_read_only_and_streams(client, monkeypatch):
    """A launched run is detached, read-only, and reaches a terminal state with the
    coordinator's summary — run_fleet is mocked so no scan touches the network."""
    import heaven.ai.fleet as fleet_mod

    captured = {}

    class _Summary:
        def to_dict(self):
            return {"stop_reason": "converged", "total_findings": 0, "iterations": []}

    async def _fake_run_fleet(seed_targets, engagement_store, base_config, *,
                              authorized=False, on_iteration=None, **kw):
        captured["authorized"] = authorized
        captured["mode"] = kw.get("active_mode")
        if on_iteration:
            on_iteration({"n": 0, "proposed": 0, "ran": 0, "new_findings": 0})
        return _Summary()

    monkeypatch.setattr(fleet_mod, "run_fleet", _fake_run_fleet)

    _make_engagement()
    r = client.post("/api/fleet/run",
                    json={"engagement": "fleetapi", "urls": ["https://x.example"],
                          "mode": "web", "max_iterations": 2})
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]

    # Poll to a terminal state (the mocked runner completes near-immediately).
    final = None
    for _ in range(50):
        j = client.get(f"/api/fleet/jobs/{job_id}").json()
        if j["status"] in ("done", "error"):
            final = j
            break
    assert final is not None and final["status"] == "done", final
    assert final["authorized"] is False          # web launcher is always read-only
    assert captured["authorized"] is False        # …and that flows into run_fleet
    assert captured["mode"] == "web"
    assert final["result"]["stop_reason"] == "converged"
    assert final["progress"]                       # the iteration trace was recorded

    # It appears in the job list.
    jobs = client.get("/api/fleet/jobs").json()["jobs"]
    assert any(j["job_id"] == job_id for j in jobs)

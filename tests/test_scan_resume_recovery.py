"""HEAVEN — scan lifecycle recovery: no zombie 'running' scans + web resume.

Locks in the fixes for the reported bug where a scan the app was closed on stayed
"running" forever (a ticking clock nothing was driving) and could not be resumed
from the dashboard, plus the store plumbing that backs it.
"""

from __future__ import annotations

import pytest


# ── Store layer ──────────────────────────────────────────────────────────────
def _store(tmp_path):
    from heaven.engagement import EngagementStore
    s = EngagementStore(tmp_path / "eng.db")
    s.create_engagement(name="eng")
    return s


def test_orphaned_scans_reconciled_to_interrupted(tmp_path):
    s = _store(tmp_path)
    s.record_scan_start("run-1", name="A", mode="network",
                        config={"targets": {"ips": ["1.2.3.4"]}})
    s.record_scan_start("run-2", name="B", mode="full", config={})
    s.checkpoint_task("run-1", "t1", "recon", "completed", {"ok": True})
    s.record_scan_complete("done-1", summary={})  # a genuinely finished scan
    # INSERT a finished row so it isn't touched.
    s.record_scan_start("done-2", name="C")
    s.record_scan_complete("done-2", summary={})

    n = s.mark_orphaned_scans_interrupted()
    assert n == 2
    by_id = {r["id"]: r["status"] for r in s.list_scans()}
    assert by_id["run-1"] == "interrupted"
    assert by_id["run-2"] == "interrupted"
    assert by_id["done-2"] == "completed"     # finished scan untouched
    # Checkpoints survive so the scan is resumable.
    assert "t1" in s.load_checkpoints("run-1")
    assert {r["id"] for r in s.find_resumable_scans()} >= {"run-1", "run-2"}


def test_record_scan_resumed_rearms_without_wiping(tmp_path):
    s = _store(tmp_path)
    s.record_scan_start("r", name="A", config={"targets": {"ips": ["1.1.1.1"]}})
    s.mark_orphaned_scans_interrupted()
    assert s.get_scan("r")["status"] == "interrupted"
    assert s.record_scan_resumed("r")
    row = s.get_scan("r")
    assert row["status"] == "running"
    # Config preserved (resume needs it).
    assert "1.1.1.1" in (row["config_json"] or "")


def test_host_labels_roundtrip_and_partial_update(tmp_path):
    s = _store(tmp_path)
    s.set_host_label("192.168.2.97", device_name="Reception PC", device_type="Windows host")
    s.set_host_label("192.168.2.97", device_type="Workstation")   # keep name
    labels = s.get_host_labels()
    assert labels["192.168.2.97"]["device_name"] == "Reception PC"
    assert labels["192.168.2.97"]["device_type"] == "Workstation"


# ── API layer ────────────────────────────────────────────────────────────────
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _seed_running(engagement, scan_id, *, config=None):
    from heaven.api.server import _engagement_store_factory
    st = _engagement_store_factory(engagement)
    st.create_engagement(name=engagement)
    st.record_scan_start(scan_id, name=scan_id, mode="network",
                         config=config or {"targets": {"ips": ["192.168.2.5"]}})
    st.checkpoint_task(scan_id, "recon", "recon", "completed", {"ok": True})
    return st


def test_cancel_of_persisted_zombie_marks_interrupted_and_keeps_checkpoints(client):
    client.post("/api/engagements/active", json={"name": "zombie-eng"})
    st = _seed_running("zombie-eng", "zomb-1")

    # A persisted running scan with no live task (a killed-process zombie) must
    # NOT be hard-deleted — that would destroy its resume checkpoints.
    r = client.delete("/api/scans/zomb-1")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "interrupted"
    assert st.get_scan("zomb-1")["status"] == "interrupted"
    assert "recon" in st.load_checkpoints("zomb-1")   # checkpoints preserved


def test_resume_endpoint_relaunches_interrupted_scan(client, monkeypatch):
    import heaven.api.server as srv

    # A no-op background runner so the endpoint's rebuild logic is exercised
    # without launching a real scan.
    async def fake_bg(scan_id, req, *, resume=False):  # pragma: no cover - not awaited here
        return None
    monkeypatch.setattr(srv, "_run_scan_background", fake_bg)

    client.post("/api/engagements/active", json={"name": "resume-eng"})
    st = _seed_running("resume-eng", "res-1",
                       config={"targets": {"ips": ["192.168.2.9"], "urls": []},
                               "mode": "network"})
    st.record_scan_interrupted("res-1")

    r = client.post("/api/scans/res-1/resume")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "running"
    # The endpoint synchronously registers the resumed scan, rebuilding its
    # targets/mode from the stored config before launching the background task.
    mem = srv.active_scans["res-1"]
    assert mem["resumed"] is True
    assert mem["mode"] == "network"
    assert mem["config"]["targets"] == ["192.168.2.9"]


def test_resume_rejects_a_completed_scan(client):
    from heaven.api.server import _engagement_store_factory
    client.post("/api/engagements/active", json={"name": "done-eng"})
    st = _engagement_store_factory("done-eng")
    st.create_engagement(name="done-eng")
    st.record_scan_start("fin-1", name="fin-1")
    st.record_scan_complete("fin-1", summary={})
    r = client.post("/api/scans/fin-1/resume")
    assert r.status_code == 409, r.text

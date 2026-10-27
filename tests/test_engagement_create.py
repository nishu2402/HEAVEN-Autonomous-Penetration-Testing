"""The `POST /api/engagements` create endpoint.

Backs the web UI "New engagement" action (command palette, dashboard button,
header "Manage engagements" link). The endpoint is thin over
``EngagementStore.create_engagement`` plus the active-pointer helper, so these
pin the HTTP contract: a fresh engagement is materialised on disk, shows up in
the list as the active one, carries any seeded metadata, and the 409/400 guards
hold (duplicate, empty name, reserved 'default', traversal).
"""

from __future__ import annotations

import pytest


class TestCreateAPI:
    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        # The suite-wide _isolate_data_dir fixture (tests/conftest.py) points
        # data_dir at an isolated per-test temp dir, so creating here never
        # touches the real ./data.
        monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
        from fastapi.testclient import TestClient

        from heaven.api.server import create_app
        return TestClient(create_app())

    def test_create_materialises_and_activates(self, client):
        from heaven.config import get_config

        r = client.post("/api/engagements", json={"name": "acme-q2"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["name"] == "acme-q2"
        assert body["active"] == "acme-q2"       # switched to it by default

        # The DB file now exists on disk.
        db = get_config().data_dir / "engagements" / "acme-q2.db"
        assert db.exists()

        # And the list surfaces it as the active engagement.
        rows = client.get("/api/engagements").json()["engagements"]
        match = [e for e in rows if e["name"] == "acme-q2"]
        assert match and match[0]["active"] is True

    def test_create_seeds_metadata(self, client):
        r = client.post("/api/engagements", json={
            "name": "acme-q3", "client": "ACME Corp",
            "sow": "SOW-2026-001", "tester": "Jordan",
        })
        assert r.status_code == 200, r.text
        eng = r.json()["engagement"]
        assert eng["name"] == "acme-q3"
        assert eng["client"] == "ACME Corp"
        assert eng["statement_of_work"] == "SOW-2026-001"
        assert eng["tester"] == "Jordan"

    def test_create_statement_of_work_alias(self, client):
        # The UI sends `statement_of_work`; the CLI-ish `sow` alias also works.
        r = client.post("/api/engagements", json={
            "name": "acme-q4", "statement_of_work": "SOW-42",
        })
        assert r.status_code == 200, r.text
        assert r.json()["engagement"]["statement_of_work"] == "SOW-42"

    def test_create_without_activate_leaves_pointer(self, client):
        # First engagement becomes active; a second with activate:false must not
        # steal the active pointer.
        client.post("/api/engagements", json={"name": "first"})
        r = client.post("/api/engagements",
                        json={"name": "second", "activate": False})
        assert r.status_code == 200, r.text
        assert r.json()["active"] == "first"
        rows = client.get("/api/engagements").json()["engagements"]
        active = {e["name"] for e in rows if e["active"]}
        assert active == {"first"}

    def test_create_duplicate_conflict(self, client):
        client.post("/api/engagements", json={"name": "dup"})
        r = client.post("/api/engagements", json={"name": "dup"})
        assert r.status_code == 409, r.text

    def test_create_rejects_empty_name(self, client):
        r = client.post("/api/engagements", json={"name": "   "})
        assert r.status_code == 400, r.text

    def test_create_rejects_reserved_default(self, client):
        r = client.post("/api/engagements", json={"name": "default"})
        assert r.status_code == 400, r.text

    def test_create_rejects_traversal(self, client):
        from heaven.config import get_config

        r = client.post("/api/engagements", json={"name": "../evil"})
        assert r.status_code == 400, r.text
        # Nothing was written outside the engagements dir.
        assert not (get_config().data_dir / "engagements" / "evil.db").exists()

    def test_summary_shows_fresh_engagement(self, client):
        # The root cause of "create does nothing": a freshly-created engagement
        # has a metadata row but zero scans/findings. The summary must NOT report
        # it as no_engagement, or the UI hides it behind the empty state until
        # the first scan.
        client.post("/api/engagements",
                    json={"name": "fresh", "client": "Globex"})
        s = client.get("/api/engagement").json()
        assert s["no_engagement"] is False, s
        assert s["engagement"]["name"] == "fresh"
        assert s["engagement"]["client"] == "Globex"
        assert s["stats"]["scans_run"] == 0
        assert s["stats"]["total_findings"] == 0

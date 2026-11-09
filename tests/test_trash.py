"""HEAVEN — Recycle Bin (soft-delete trash) tests: store, API and CLI.

Deleting a scan or an engagement moves it to ``data_dir/.trash`` so it can be
reviewed and restored before permanent removal. These lock in move-aside +
restore + purge + retention, that an empty engagement is hard-deleted (never
binned), and that the API/CLI route deletes through the Bin by default while
``?permanent=1`` / ``--permanent`` still hard-delete.

Every test runs against the autouse tmp ``HEAVEN_DATA_DIR`` from conftest, so the
real ``data/engagements`` directory is never touched.
"""

from __future__ import annotations

import json
import stat

import pytest


# ── helpers ──────────────────────────────────────────────────────────────
def _seed_engagement(name: str, scan_id: str = "scan-1", findings: int = 1):
    """Create engagements/<name>.db with a finished scan and N findings."""
    from heaven.config import get_config
    from heaven.engagement import EngagementStore

    db = get_config().data_dir / "engagements" / f"{name}.db"
    st = EngagementStore(db)
    st.create_engagement(name, client="ACME")
    st.add_scope("https://app.example", kind="url")
    st.record_scan_start(scan_id, name=scan_id, mode="web")
    for i in range(findings):
        st.upsert_finding(scan_id, {
            "target": f"https://app.example/{i}", "vuln_type": "sqli",
            "param": "id", "endpoint": "/login",
            "severity": "high", "confidence": 0.9,
        })
    st.record_scan_complete(scan_id, summary={"ok": True})
    return st, db


# ── store / module unit tests ───────────────────────────────────────────
class TestTrashStoreUnit:
    def test_trash_and_restore_scan(self):
        from heaven import trash
        from heaven.config import get_config

        st, _ = _seed_engagement("acme", "scan-1")
        report = get_config().data_dir / "report_scan-1.json"
        report.write_text(json.dumps({"scan_id": "scan-1"}))

        entry = trash.trash_scan(st, "scan-1", engagement="acme", by="t")
        assert st.get_scan("scan-1") is None
        assert st.list_findings() == []
        assert not report.exists()                       # report moved into the bin
        items = trash.list_items()
        assert len(items) == 1 and items[0]["kind"] == "scan"
        assert items[0]["summary"]["findings"] == 1

        res = trash.restore(entry["id"])
        assert res["kind"] == "scan" and res["scan_id"] == "scan-1"
        assert st.get_scan("scan-1") is not None
        assert len(st.list_findings()) == 1
        assert report.exists()                           # report restored
        assert trash.list_items() == []

    def test_trash_and_restore_engagement(self):
        from heaven import trash
        from heaven.config import get_config

        _seed_engagement("acme", "scan-1")
        db = get_config().data_dir / "engagements" / "acme.db"
        entry = trash.trash_engagement("acme", by="t")
        assert not db.exists()                           # db moved out of engagements/
        assert len(trash.list_items()) == 1

        res = trash.restore(entry["id"])
        assert res["restored"] == "acme" and not res["renamed"]
        assert db.exists()
        assert trash.list_items() == []

    def test_restore_engagement_name_collision_suffixes(self):
        from heaven import trash
        from heaven.config import get_config
        from heaven.engagement import EngagementStore

        _seed_engagement("acme", "scan-1")
        entry = trash.trash_engagement("acme", by="t")
        _seed_engagement("acme", "scan-2")               # name reused while binned

        res = trash.restore(entry["id"])
        assert res["renamed"] is True and res["restored"] == "acme (restored)"
        db = get_config().data_dir / "engagements" / "acme (restored).db"
        assert db.exists()
        # the in-DB name row follows the new on-disk stem
        assert EngagementStore(db).get_engagement().name == "acme (restored)"

    def test_empty_engagement_hard_deleted_not_binned(self):
        from heaven import trash
        from heaven.config import get_config
        from heaven.engagement import EngagementStore

        db = get_config().data_dir / "engagements" / "empty.db"
        EngagementStore(db).create_engagement("empty")
        r = trash.trash_engagement("empty", by="t")
        assert r.get("permanent") is True
        assert not db.exists()
        assert trash.list_items() == []

    def test_restore_scan_missing_engagement_raises(self):
        from heaven import trash

        st, _ = _seed_engagement("acme", "scan-1")
        entry = trash.trash_scan(st, "scan-1", engagement="acme", by="t")
        trash.trash_engagement("acme", by="t")           # owning engagement gone too
        with pytest.raises(FileNotFoundError):
            trash.restore(entry["id"])

    def test_purge_and_empty(self):
        from heaven import trash

        st, _ = _seed_engagement("acme", "scan-1")
        e1 = trash.trash_scan(st, "scan-1", engagement="acme", by="t")
        assert trash.purge(e1["id"]) is True
        assert trash.list_items() == []
        assert trash.purge("a" * 32) is False            # unknown id

        _seed_engagement("acme2", "scan-2")
        trash.trash_engagement("acme2", by="t")
        assert len(trash.list_items()) == 1
        assert trash.empty() == 1
        assert trash.list_items() == []

    def test_retention_purge(self, monkeypatch):
        from heaven import trash

        _seed_engagement("acme", "scan-1")
        entry = trash.trash_engagement("acme", by="t")
        with trash.TrashStore()._conn() as c:            # backdate past retention
            c.execute("UPDATE trash SET deleted_at = ? WHERE id = ?",
                      ("2000-01-01T00:00:00+00:00", entry["id"]))
        monkeypatch.setenv("HEAVEN_TRASH_RETENTION_DAYS", "30")
        assert trash.purge_expired() >= 1
        assert trash.list_items() == []

    def test_retention_zero_keeps_forever(self, monkeypatch):
        from heaven import trash

        _seed_engagement("acme", "scan-1")
        entry = trash.trash_engagement("acme", by="t")
        with trash.TrashStore()._conn() as c:
            c.execute("UPDATE trash SET deleted_at = ? WHERE id = ?",
                      ("2000-01-01T00:00:00+00:00", entry["id"]))
        monkeypatch.setenv("HEAVEN_TRASH_RETENTION_DAYS", "0")
        monkeypatch.setenv("HEAVEN_TRASH_MAX_ITEMS", "500")
        assert trash.purge_expired() == 0
        assert len(trash.list_items()) == 1

    def test_max_items_cap(self, monkeypatch):
        from heaven import trash

        monkeypatch.setenv("HEAVEN_TRASH_MAX_ITEMS", "2")
        monkeypatch.setenv("HEAVEN_TRASH_RETENTION_DAYS", "0")
        for i in range(4):
            _seed_engagement(f"e{i}", f"s{i}")
            trash.trash_engagement(f"e{i}", by="t")
        assert len(trash.list_items()) == 2              # oldest trimmed to the cap

    def test_trash_dir_permissions(self):
        from heaven import trash

        _seed_engagement("acme", "scan-1")
        trash.trash_engagement("acme", by="t")
        tdir = trash.trash_dir()
        assert stat.S_IMODE(tdir.stat().st_mode) == 0o700
        assert stat.S_IMODE((tdir / "trash.db").stat().st_mode) & 0o077 == 0

    def test_is_valid_trash_id(self):
        from heaven import trash

        assert trash.is_valid_trash_id("a" * 32)
        assert not trash.is_valid_trash_id("../etc/passwd")
        assert not trash.is_valid_trash_id("short")
        assert not trash.is_valid_trash_id(None)


# ── API tests ────────────────────────────────────────────────────────────
@pytest.fixture
def client(monkeypatch):
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


def _seed_via_api_store(engagement: str, scan_id: str):
    """Seed into the store the API resolves for *engagement* (same factory)."""
    from heaven.api.server import _engagement_store_factory

    st = _engagement_store_factory(engagement)
    st.create_engagement(name=engagement)
    st.record_scan_start(scan_id, name=scan_id, mode="web")
    st.upsert_finding(scan_id, {"target": "https://a.example", "vuln_type": "xss",
                                "title": "X", "severity": "high", "confidence": 0.9})
    st.record_scan_complete(scan_id, summary={})
    return st


class TestTrashAPI:
    def test_scan_delete_goes_to_bin_then_restore(self, client):
        client.post("/api/engagements/active", json={"name": "e2e"})
        _seed_via_api_store("e2e", "scanA")

        r = client.delete("/api/scans/scanA")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "trashed" and r.json()["trash_id"]

        items = client.get("/api/trash").json()["items"]
        assert len(items) == 1 and items[0]["kind"] == "scan"
        tid = items[0]["id"]

        r = client.post(f"/api/trash/{tid}/restore")
        assert r.status_code == 200 and r.json()["kind"] == "scan"
        assert client.get("/api/trash").json()["count"] == 0

    def test_engagement_delete_to_bin_and_permanent(self, client):
        _seed_via_api_store("workA", "s1")
        r = client.delete("/api/engagements/workA")
        assert r.status_code == 200
        assert r.json()["trash_id"] and r.json()["permanent"] is False
        assert client.get("/api/trash").json()["count"] == 1

        _seed_via_api_store("workB", "s2")
        r = client.delete("/api/engagements/workB?permanent=1")
        assert r.status_code == 200 and r.json()["permanent"] is True
        assert client.get("/api/trash").json()["count"] == 1   # workB skipped the bin

    def test_empty_engagement_hard_deleted(self, client):
        client.post("/api/engagements", json={"name": "blank", "activate": False})
        r = client.delete("/api/engagements/blank")
        assert r.status_code == 200 and r.json()["permanent"] is True
        assert client.get("/api/trash").json()["count"] == 0

    def test_purge_and_empty_endpoints(self, client):
        _seed_via_api_store("e1", "s1")
        client.delete("/api/engagements/e1")
        tid = client.get("/api/trash").json()["items"][0]["id"]
        assert client.delete(f"/api/trash/{tid}").status_code == 200
        assert client.get("/api/trash").json()["count"] == 0

        _seed_via_api_store("e2", "s2")
        client.delete("/api/engagements/e2")
        r = client.post("/api/trash/empty")
        assert r.status_code == 200 and r.json()["purged_count"] == 1
        assert client.get("/api/trash").json()["count"] == 0

    def test_invalid_and_missing_ids(self, client):
        assert client.post("/api/trash/not-a-uuid/restore").status_code == 400
        assert client.delete("/api/trash/not-a-uuid").status_code == 400
        assert client.post(f"/api/trash/{'a' * 32}/restore").status_code == 404
        assert client.delete(f"/api/trash/{'a' * 32}").status_code == 404

    def test_restore_scan_missing_engagement_409(self, client):
        client.post("/api/engagements/active", json={"name": "ev"})
        _seed_via_api_store("ev", "sc")
        client.delete("/api/scans/sc")                   # scan -> bin
        tid = client.get("/api/trash").json()["items"][0]["id"]
        client.delete("/api/engagements/ev?permanent=1")  # owning engagement gone
        assert client.post(f"/api/trash/{tid}/restore").status_code == 409


# ── CLI tests ────────────────────────────────────────────────────────────
class TestTrashCLI:
    def test_engage_delete_to_bin_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)                       # contain the `heaven use` pointer
        from click.testing import CliRunner
        from heaven import trash
        from heaven.cli.engage import engage

        _seed_engagement("acme", "scan-1")
        res = CliRunner().invoke(engage, ["delete", "acme", "--yes"])
        assert res.exit_code == 0, res.output
        assert "Recycle Bin" in res.output
        assert len(trash.list_items()) == 1

    def test_engage_delete_permanent_skips_bin(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from click.testing import CliRunner
        from heaven import trash
        from heaven.cli.engage import engage

        _seed_engagement("acme", "scan-1")
        res = CliRunner().invoke(engage, ["delete", "acme", "--yes", "--permanent"])
        assert res.exit_code == 0, res.output
        assert "Permanently deleted" in res.output
        assert trash.list_items() == []

    def test_trash_list_restore_purge_cli(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from click.testing import CliRunner
        from heaven import trash
        from heaven.cli.trash import trash as trash_cli

        _seed_engagement("acme", "scan-1")
        entry = trash.trash_engagement("acme", by="cli")

        r = CliRunner().invoke(trash_cli, ["list"])
        assert r.exit_code == 0 and entry["id"] in r.output

        r = CliRunner().invoke(trash_cli, ["restore", entry["id"]])
        assert r.exit_code == 0 and "Restored" in r.output
        assert trash.list_items() == []

        _seed_engagement("acme2", "s2")
        e2 = trash.trash_engagement("acme2", by="cli")
        r = CliRunner().invoke(trash_cli, ["purge", e2["id"], "--yes"])
        assert r.exit_code == 0
        assert trash.list_items() == []

    def test_trash_empty_cli(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from click.testing import CliRunner
        from heaven import trash
        from heaven.cli.trash import trash as trash_cli

        _seed_engagement("acme", "scan-1")
        trash.trash_engagement("acme", by="cli")
        r = CliRunner().invoke(trash_cli, ["empty", "--yes"])
        assert r.exit_code == 0
        assert trash.list_items() == []

"""Tests for renaming an engagement.

The engagement name is welded to the DB *filename* (``engagements/<name>.db``)
and ``get_engagement`` resolves the canonical row by that stem, so a rename has
to move the ``.db`` file *and* every WAL/SHM sidecar *and* rewrite the in-DB
``engagement.name`` — while preserving the findings/scope inside. These tests pin
that whole contract, plus the case-only rename (macOS: ``foo`` → ``Foo`` is the
same inode) and the never-clobber guards.
"""
from __future__ import annotations

import sqlite3

import pytest


def _make_store(path, name):
    """Create an engagement DB at ``path`` named ``name`` with one finding."""
    from heaven.engagement import EngagementStore

    store = EngagementStore(path)
    store.create_engagement(name, client="ACME Corp")
    store.add_scope("https://app.example", kind="url")
    store.upsert_finding("scan-1", {
        "target": "https://app.example",
        "vuln_type": "sqli",
        "param": "id", "endpoint": "/login",
        "severity": "critical", "confidence": 0.92,
    })
    return store


class TestRenameStore:

    def test_moves_db_and_rewrites_name(self, tmp_path):
        from heaven.engagement import EngagementStore, rename_engagement_store

        old = tmp_path / "certified hacker.db"
        new = tmp_path / "acme-2026-q3.db"
        _make_store(old, "certified hacker")

        rename_engagement_store(old, new)

        # The old file is gone, the new one exists, and its label matches the
        # new filename stem (not the stale "certified hacker" row).
        assert not old.exists()
        assert new.exists()
        eng = EngagementStore(new).get_engagement()
        assert eng is not None
        assert eng.name == "acme-2026-q3"
        assert eng.client == "ACME Corp"     # metadata preserved

    def test_preserves_findings_and_scope(self, tmp_path):
        from heaven.engagement import EngagementStore, rename_engagement_store

        old = tmp_path / "old.db"
        new = tmp_path / "new.db"
        _make_store(old, "old")

        rename_engagement_store(old, new)

        moved = EngagementStore(new)
        assert moved.stats()["total_findings"] == 1
        assert moved.is_in_scope("https://app.example")

    def test_moves_wal_sidecar(self, tmp_path):
        from heaven.engagement import rename_engagement_store

        old = tmp_path / "walme.db"
        new = tmp_path / "walme-renamed.db"
        _make_store(old, "walme")
        # Force a lingering -wal by writing without checkpointing on close.
        conn = sqlite3.connect(old)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA wal_autocheckpoint = 0")
        conn.execute(
            "INSERT INTO scope (target, kind, in_scope, criticality, notes, added_at) "
            "VALUES ('10.0.0.9', 'ip', 1, 'medium', '', '2026-01-01T00:00:00+00:00')"
        )
        conn.commit()
        conn.close()

        rename_engagement_store(old, new)

        # No stale sidecars left at the old name (they were folded in / moved).
        assert not (tmp_path / "walme.db-wal").exists()
        assert not (tmp_path / "walme.db-shm").exists()
        assert not old.exists()

    def test_case_only_rename(self, tmp_path):
        """``certified hacker`` → ``Certified Hacker`` (same inode on a
        case-insensitive filesystem) must actually change the stored case."""
        from heaven.engagement import EngagementStore, rename_engagement_store

        old = tmp_path / "certified hacker.db"
        new = tmp_path / "Certified Hacker.db"
        _make_store(old, "certified hacker")

        rename_engagement_store(old, new)

        # On any filesystem the label now reads the new stem.
        eng = EngagementStore(new).get_engagement()
        assert eng is not None
        assert eng.name == "Certified Hacker"
        # And the store still holds its data.
        assert EngagementStore(new).stats()["total_findings"] == 1

    def test_missing_source_raises(self, tmp_path):
        from heaven.engagement import rename_engagement_store

        with pytest.raises(FileNotFoundError):
            rename_engagement_store(tmp_path / "nope.db", tmp_path / "x.db")

    def test_existing_target_raises(self, tmp_path):
        from heaven.engagement import rename_engagement_store

        old = tmp_path / "a.db"
        new = tmp_path / "b.db"
        _make_store(old, "a")
        _make_store(new, "b")     # a genuinely different engagement already there

        with pytest.raises(FileExistsError):
            rename_engagement_store(old, new)
        # Neither store was touched.
        assert old.exists() and new.exists()

    def test_identical_path_is_noop(self, tmp_path):
        from heaven.engagement import EngagementStore, rename_engagement_store

        p = tmp_path / "same.db"
        _make_store(p, "same")
        rename_engagement_store(p, p)   # must not raise or destroy data
        assert p.exists()
        assert EngagementStore(p).stats()["total_findings"] == 1


class TestSetEngagementName:

    def test_updates_row(self, tmp_path):
        from heaven.engagement import EngagementStore

        store = EngagementStore(tmp_path / "x.db")
        store.create_engagement("before")
        store.set_engagement_name("after")
        assert store.get_engagement().name == "after"

    def test_on_empty_inserts(self, tmp_path):
        from heaven.engagement import EngagementStore

        store = EngagementStore(tmp_path / "y.db")
        assert store.get_engagement() is None
        store.set_engagement_name("fresh")
        assert store.get_engagement().name == "fresh"


class TestRenameAPI:
    """The endpoint is thin over the store helper, so these pin the HTTP
    contract: success + list reflects it, plus the 409/404/400 guards."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        # The suite-wide _isolate_data_dir fixture (tests/conftest.py) already
        # points data_dir at an isolated per-test temp dir, so seeding + renaming
        # here never touches the real ./data. (Previously this fixture relied on
        # chdir, which only isolates a *relative* data_dir, and skipped when an
        # absolute HEAVEN_DATA_DIR was set.)
        monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
        from fastapi.testclient import TestClient

        from heaven.api.server import create_app
        return TestClient(create_app())

    def _seed(self, name):
        from heaven.config import get_config
        from heaven.engagement import EngagementStore
        d = get_config().data_dir / "engagements"
        d.mkdir(parents=True, exist_ok=True)
        s = EngagementStore(d / f"{name}.db")
        s.create_engagement(name)
        s.upsert_finding("s1", {"target": "http://x", "vuln_type": "sqli",
                                "severity": "high", "confidence": 0.9})
        return d / f"{name}.db"

    def test_rename_endpoint(self, client):
        self._seed("certified hacker")
        r = client.post("/api/engagements/certified hacker/rename",
                        json={"new_name": "acme-q3"})
        assert r.status_code == 200, r.text
        names = {e["name"] for e in client.get("/api/engagements").json()["engagements"]}
        assert "acme-q3" in names
        assert "certified hacker" not in names

    def test_rename_conflict(self, client):
        self._seed("one")
        self._seed("two")
        r = client.post("/api/engagements/one/rename", json={"new_name": "two"})
        assert r.status_code == 409, r.text

    def test_rename_missing(self, client):
        r = client.post("/api/engagements/ghost/rename", json={"new_name": "x"})
        assert r.status_code == 404, r.text

    def test_rename_rejects_traversal(self, client):
        self._seed("safe")
        r = client.post("/api/engagements/safe/rename", json={"new_name": "../evil"})
        assert r.status_code == 400, r.text

    def test_rename_rejects_reserved_default(self, client):
        self._seed("safe2")
        r = client.post("/api/engagements/safe2/rename", json={"new_name": "default"})
        assert r.status_code == 400, r.text

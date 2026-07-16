"""
Replay/resume reproducibility — mode + stealth persistence.

These tests lock in that a scan can be faithfully reproduced:

* Web-launched scans now persist a full, replayable config (targets incl. the
  resolved stealth level + mode + seed) — previously they stored no config at
  all, so ``heaven replay`` / the replay endpoint had nothing to reconstruct.
* ``heaven replay`` reproduces the original scan's *focused mode* (not a blanket
  FULL run) and carries its stealth level through ``targets``.
* Both replay paths read the config off ``list_scans()`` (SELECT *), which
  carries ``config_json`` + ``mode`` — ``list_all_scans()`` drops them, which is
  why replay used to silently find "no replayable targets".
"""

from __future__ import annotations

import asyncio
import json

import pytest

from heaven.api.server import _resolve_stealth_name


# ── stealth-name resolver ──────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    (1, "paranoid"),
    (2, "stealth"),
    (3, "normal"),
    (4, "aggressive"),
    (None, "normal"),              # unset → safe default
    (99, "normal"),                # out of range → safe default
    ("paranoid", "paranoid"),      # already a name
    ("  Stealth ", "stealth"),     # trimmed + lower-cased
    ("nonsense", "normal"),        # unknown name → safe default
    ("3", "normal"),               # numeric string is not a name → default
])
def test_resolve_stealth_name(value, expected):
    assert _resolve_stealth_name(value) == expected


# ── web scan persists a replayable config (incl. resolved stealth) ─────────

def test_run_scan_background_persists_replayable_config(tmp_path, monkeypatch):
    from heaven.api import server
    from heaven.config import ScanMode, reload_config
    from heaven.engagement import EngagementStore

    store = EngagementStore(tmp_path / "eng.db")
    monkeypatch.setattr(server, "_engagement_store_factory", lambda name: store)

    captured: dict = {}

    class _FakeOrch:
        scan_id = "orchid"
        results: dict = {}

        def on_progress(self, cb):
            self._cb = cb

        async def run(self):
            return {"vulnerabilities": [], "findings": [], "elapsed_seconds": 0,
                    "assets": []}

    def fake_build(targets, cfg, checkpoint_store=None, scan_mode=None, **kw):
        captured["targets"] = targets
        captured["scan_mode"] = scan_mode
        return _FakeOrch()

    monkeypatch.setattr("heaven.orchestrator.build_full_scan", fake_build)

    # Keep the report JSON out of the repo's data/ dir.
    monkeypatch.setenv("HEAVEN_DATA_DIR", str(tmp_path / "data"))
    reload_config()
    scan_id = "scan-web-paranoid"
    try:
        server.active_scans[scan_id] = {"status": "pending"}
        req = server.ScanRequest(urls=["http://target.example/"], mode="web",
                                 stealth_level=1)
        asyncio.run(server._run_scan_background(scan_id, req))
    finally:
        server.active_scans.pop(scan_id, None)
        monkeypatch.delenv("HEAVEN_DATA_DIR", raising=False)
        reload_config()

    # The dispatch received the resolved stealth level + the focused mode …
    assert captured["scan_mode"] == ScanMode.WEB
    assert captured["targets"]["stealth_level"] == "paranoid"

    # … and the SAME config was persisted, read back through list_scans() — the
    # exact path replay uses (list_all_scans() would drop config_json + mode).
    row = next(s for s in store.list_scans() if s["id"] == scan_id)
    assert row["mode"] == "web"
    cfg = json.loads(row["config_json"])
    assert cfg["targets"]["stealth_level"] == "paranoid"
    assert cfg["targets"]["urls"] == ["http://target.example/"]
    assert cfg["mode"] == "web"


# ── CLI replay reproduces mode + stealth ───────────────────────────────────

def test_cli_replay_reproduces_mode_and_stealth(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from heaven.cli import replay as replay_mod
    from heaven.config import ScanMode
    from heaven.engagement import EngagementStore

    db = tmp_path / "eng.db"
    store = EngagementStore(db)
    store.create_engagement(name="e1")
    store.record_scan_start(
        "abc123def", name="scan", mode="web",
        config={"targets": {"urls": ["http://t/"], "ips": [],
                            "stealth_level": "stealth"},
                "seed": None, "mode": "web"},
    )
    monkeypatch.setattr(replay_mod, "_engagement_db_path", lambda name: db)

    captured: dict = {}

    class _FakeOrch:
        scan_id = "newid"

        def on_progress(self, cb):
            pass

        async def run(self):
            return {"elapsed_seconds": 0, "completed": 0, "total_tasks": 0,
                    "failed": 0, "vulnerabilities": [], "findings": [],
                    "scan_id": "newid"}

    def fake_build(targets, cfg, checkpoint_store=None, scan_mode=None, **kw):
        captured["targets"] = targets
        captured["scan_mode"] = scan_mode
        return _FakeOrch()

    monkeypatch.setattr("heaven.orchestrator.build_full_scan", fake_build)

    result = CliRunner().invoke(
        replay_mod.replay,
        ["abc123", "--engagement", "e1", "--i-have-authorization"],
    )
    assert result.exit_code == 0, result.output
    # Focused mode reproduced (not a blanket FULL run) …
    assert captured["scan_mode"] == ScanMode.WEB
    # … and stealth level carried through targets.
    assert captured["targets"]["stealth_level"] == "stealth"
    assert captured["targets"]["urls"] == ["http://t/"]

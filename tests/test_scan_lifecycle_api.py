"""HEAVEN — end-to-end API tests for the scan lifecycle + engagement wiring.

These lock in the fixes for the web-app bugs where:
  * a report download returned "No findings to report for this engagement"
    (the report read a different store than the one scans wrote to), and
  * clicking / removing / per-scan viewing didn't work.

Auth is bypassed (HEAVEN_DISABLE_AUTH) so we exercise the route logic directly.
Findings are seeded through the *same* store factory the endpoints use, so the
test proves the endpoints and the scan writer agree on which engagement holds
the data — the crux of the original bug.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    # The active-engagement pointer, not an env override, must drive resolution.
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _seed(engagement: str, scans: dict[str, list[dict]]):
    """Seed findings into the store the API resolves for *engagement*."""
    from heaven.api.server import _engagement_store_factory
    store = _engagement_store_factory(engagement)
    store.create_engagement(name=engagement)
    for scan_id, findings in scans.items():
        store.record_scan_start(scan_id, name=scan_id, mode="web")
        for f in findings:
            store.upsert_finding(scan_id, f)
        # Mark finished — these fixtures stand in for completed scans. A scan left
        # 'running' is now treated as an interruptible zombie (delete → interrupted
        # to preserve resume), so a "remove a finished scan" test needs them done.
        store.record_scan_complete(scan_id, summary={})
    return store


def test_report_follows_active_engagement(client):
    """Switching the active engagement makes the report export read *that* store —
    no more spurious 'No findings to report for this engagement'."""
    r = client.post("/api/engagements/active", json={"name": "e2e-eng"})
    assert r.status_code == 200 and r.json()["active"] == "e2e-eng"

    _seed("e2e-eng", {
        "scanA": [{"target": "https://a.example.com", "vuln_type": "xss",
                   "title": "Reflected XSS", "severity": "high",
                   "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b.example.com", "vuln_type": "sqli",
                   "title": "SQL Injection", "severity": "critical",
                   "confidence": 0.95, "risk_score": 9.1}],
    })

    # No engagement param — the server must resolve the *active* engagement.
    r = client.get("/api/report/export?format=json")
    assert r.status_code == 200, r.text
    assert "Reflected XSS" in r.text
    assert "SQL Injection" in r.text


def test_findings_filter_by_scan(client):
    client.post("/api/engagements/active", json={"name": "e2e-filter"})
    _seed("e2e-filter", {
        "scanA": [{"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
                   "severity": "high", "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b", "vuln_type": "sqli", "title": "SQL Injection",
                   "severity": "critical", "confidence": 0.95, "risk_score": 9.1}],
    })

    r = client.get("/api/engagement/findings?scan_id=scanA")
    assert r.status_code == 200, r.text
    assert [f["title"] for f in r.json()["findings"]] == ["Reflected XSS"]


def test_engagement_findings_drops_attack_plan_artifacts(client):
    """A finding whose vuln_type is a bare MITRE technique (T1190) is a leaked
    attack-chain planner step — it has no taxonomy, so it rendered blank in the
    detail view. Older scans persisted these; the list endpoint must filter them
    out so the operator isn't left with a screen of empty rows (and no re-scan is
    needed to clear them)."""
    client.post("/api/engagements/active", json={"name": "e2e-artifact"})
    _seed("e2e-artifact", {
        "scanA": [
            {"target": "http://192.168.1.101/", "vuln_type": "csp_missing",
             "title": "Content-Security-Policy (CSP) Missing", "severity": "medium",
             "confidence": 0.98, "risk_score": 4.6},
            # Leaked planner step, persisted as a pseudo-finding.
            {"target": "192.168.1.101", "vuln_type": "T1190",
             "title": "Exploit Public-Facing Application", "severity": "high",
             "confidence": 0.0, "risk_score": 6.2},
        ],
    })
    r = client.get("/api/engagement/findings")
    assert r.status_code == 200, r.text
    body = r.json()
    types = [f["vuln_type"] for f in body["findings"]]
    assert "csp_missing" in types
    assert "T1190" not in types
    assert body["count"] == 1


def test_assets_default_prefers_scan_with_open_ports(client):
    """The inventory picker must not default to a dead/mistyped-host scan (a host
    row with zero ports) when an earlier scan actually found services."""
    from heaven.api.server import _engagement_store_factory
    client.post("/api/engagements/active", json={"name": "e2e-assets"})
    store = _engagement_store_factory("e2e-assets")
    store.create_engagement(name="e2e-assets")
    store.record_scan_start("scan-ported", name="192.168.1.10", mode="network")
    store.record_scan_complete("scan-ported", {"assets": [
        {"ip": "192.168.1.10", "is_alive": True,
         "open_ports": [{"port": 80, "service": "http"},
                        {"port": 22, "service": "ssh"}]},
    ]})
    store.record_scan_start("scan-dead", name="192.186.1.100", mode="network")
    store.record_scan_complete("scan-dead", {"assets": [
        {"ip": "192.186.1.100", "is_alive": False, "open_ports": []},
    ]})

    r = client.get("/api/assets")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scan_id"] == "scan-ported"          # not the newer, empty scan
    assert body["totals"]["open_ports"] == 2
    assert [h["host"] for h in body["assets"]] == ["192.168.1.10"]
    # The picker still lists both scans, annotated with their port counts.
    ports_by_scan = {s["scan_id"]: s["ports"] for s in body["scans"]}
    assert ports_by_scan == {"scan-ported": 2, "scan-dead": 0}


def test_scan_detail_and_delete(client):
    """A completed scan not in memory is still viewable (store fallback), and a
    finished scan can be permanently removed."""
    client.post("/api/engagements/active", json={"name": "e2e-delete"})
    _seed("e2e-delete", {
        "scanA": [{"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
                   "severity": "high", "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b", "vuln_type": "sqli", "title": "SQL Injection",
                   "severity": "critical", "confidence": 0.95, "risk_score": 9.1}],
    })

    # Clicking a scan → its findings (works even though it's not in active_scans)
    r = client.get("/api/scans/scanB?include_findings=true")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_count"] == 1
    assert body["findings"][0]["title"] == "SQL Injection"

    # engagements listing surfaces the active engagement with its counts
    js = client.get("/api/engagements").json()
    assert js["active"] == "e2e-delete"
    row = next(e for e in js["engagements"] if e["name"] == "e2e-delete")
    assert row["active"] and row["findings"] == 2

    # Remove scanA → its finding is gone; scanB is untouched
    r = client.delete("/api/scans/scanA")
    assert r.status_code == 200 and r.json()["status"] == "deleted", r.text
    assert client.get("/api/engagement/findings?scan_id=scanA").json()["findings"] == []
    assert client.get("/api/scans/scanA").status_code == 404
    assert client.get("/api/scans/scanB").status_code == 200


_FINDING = {"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
            "severity": "high", "confidence": 0.9, "risk_score": 7.5}


def test_delete_engagement_repoints_to_best_survivor(client):
    """Deleting the engagement you're viewing repoints the active pointer to the
    survivor with the most findings — the fix for stale/empty engagements the
    dashboard switcher listed forever with no way to remove them."""
    from heaven.api.server import _engagement_store_factory
    _seed("keep-me", {"s1": [_FINDING]})           # a real engagement with data
    _engagement_store_factory("trash-me").create_engagement(name="trash-me")  # empty
    client.post("/api/engagements/active", json={"name": "trash-me"})
    assert client.get("/api/engagements").json()["active"] == "trash-me"

    r = client.delete("/api/engagements/trash-me")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted"] == "trash-me"
    assert body["active"] == "keep-me"     # repointed to the survivor with findings

    js = client.get("/api/engagements").json()
    assert js["active"] == "keep-me"
    assert all(e["name"] != "trash-me" for e in js["engagements"])   # gone from the list


def test_delete_last_engagement_clears_pointer(client):
    """Deleting the only engagement clears the pointer so the resolver falls back
    to 'default' (empty dashboard / quick-start) rather than dangling."""
    from heaven.api import server
    _seed("solo", {"s1": [_FINDING]})
    client.post("/api/engagements/active", json={"name": "solo"})

    r = client.delete("/api/engagements/solo")
    assert r.status_code == 200, r.text
    assert r.json()["active"] == "default"
    assert not server._active_engagement_file().exists()


def test_delete_engagement_removes_wal_sidecars(client):
    """The DB *and* its WAL/SHM sidecars are removed, so the name can't be
    resurrected from a leftover write-ahead log."""
    from heaven.config import get_config
    _seed("waltest", {"s1": [_FINDING]})
    eng_dir = get_config().data_dir / "engagements"
    assert (eng_dir / "waltest.db").exists()

    r = client.delete("/api/engagements/waltest")
    assert r.status_code == 200, r.text
    assert not (eng_dir / "waltest.db").exists()
    assert not (eng_dir / "waltest.db-wal").exists()
    assert not (eng_dir / "waltest.db-shm").exists()


def test_delete_engagement_rejects_traversal_and_missing(client):
    """A traversal name is blocked (400) before any file op; a real-but-absent
    engagement is a clean 404."""
    assert client.delete("/api/engagements/x..y").status_code == 400
    assert client.delete("/api/engagements/nope").status_code == 404


def test_cli_engage_list_and_delete(tmp_path, monkeypatch):
    """CLI parity: `heaven engage list` shows engagements and `engage delete`
    removes the DB and drops any pointer that named it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    from click.testing import CliRunner

    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import (
        EngagementStore,
        get_active_engagement,
        set_active_engagement,
    )
    from heaven.main import cli

    path = _engagement_db_path("cli-eng")
    EngagementStore(path).create_engagement(name="cli-eng")
    set_active_engagement("cli-eng")
    assert path.exists()

    runner = CliRunner()
    res = runner.invoke(cli, ["engage", "list"])
    assert res.exit_code == 0, res.output
    assert "cli-eng" in res.output

    res = runner.invoke(cli, ["engage", "delete", "cli-eng", "--yes"])
    assert res.exit_code == 0, res.output
    assert not path.exists()                       # DB removed
    assert get_active_engagement() != "cli-eng"    # pointer no longer dangles


def test_dashboard_reads_do_not_create_default_db(client):
    """Opening the dashboard on a fresh install (nothing scanned) must NOT
    materialise an empty data/engagements/default.db. That stray file is what
    used to reappear in the switcher as a "default — empty" row the user could
    never get rid of — recreated by the very act of loading a page."""
    from heaven.config import get_config
    default_db = get_config().data_dir / "engagements" / "default.db"
    assert not default_db.exists()

    # Every read the dashboard + header fire on load, plus the findings page.
    assert client.get("/api/engagement").status_code == 200          # summary
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/engagement/findings").status_code == 200
    assert client.get("/api/engagement/top-findings").status_code == 200
    assert client.get("/api/scans").status_code == 200
    js = client.get("/api/engagements").json()

    # No file was created, and the switcher lists no phantom "default".
    assert not default_db.exists(), "a read materialised default.db"
    assert js["active"] == "default"
    assert js["engagements"] == []
    assert all(e["name"] != "default" for e in js["engagements"])


def test_default_engagement_materialises_only_on_write(client):
    """A genuine write into the fallback engagement still creates the store —
    it's only *reads* that must not."""
    from heaven.config import get_config
    default_db = get_config().data_dir / "engagements" / "default.db"
    assert not default_db.exists()
    _seed("default", {"s1": [_FINDING]})
    assert default_db.exists()
    js = client.get("/api/engagements").json()
    row = next(e for e in js["engagements"] if e["name"] == "default")
    assert row["findings"] == 1


def test_startup_prunes_empty_default_db(tmp_path, monkeypatch):
    """Server startup removes a stray empty default.db left by older builds, but
    preserves a 'default' engagement that actually holds data."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    from fastapi.testclient import TestClient

    from heaven.api.server import create_app
    from heaven.config import get_config
    from heaven.engagement import EngagementStore

    default_db = get_config().data_dir / "engagements" / "default.db"
    EngagementStore(default_db)               # materialise an EMPTY default.db
    assert default_db.exists()

    with TestClient(create_app()):            # entering runs the lifespan startup
        pass
    assert not default_db.exists(), "startup should prune an empty default.db"

    # A default engagement WITH data must survive startup untouched.
    store = EngagementStore(default_db)
    store.create_engagement(name="default")
    store.record_scan_start("s1", name="x", mode="web")
    store.upsert_finding("s1", _FINDING)
    with TestClient(create_app()):
        pass
    assert default_db.exists(), "a non-empty default must be preserved"
    auth_mod._auth_manager = None


def _seed_modes(engagement: str, scans: dict[str, str]):
    """Seed one finding per scan, each recorded under a given mode.

    scans maps scan_id -> mode (e.g. {"web-1": "web", "sast-1": "sast"}).
    """
    from heaven.api.server import _engagement_store_factory
    store = _engagement_store_factory(engagement)
    store.create_engagement(name=engagement)
    for scan_id, mode in scans.items():
        store.record_scan_start(scan_id, name=scan_id, mode=mode)
        store.upsert_finding(scan_id, dict(_FINDING))
    return store


def test_scans_list_excludes_code_analysis_by_default(client):
    """The general Scan Activity list (kind=pentest, the default) must NOT show
    SAST/SCA runs — those have their own sections, so a code-analysis scan
    appears exactly once instead of being merged in twice."""
    client.post("/api/engagements/active", json={"name": "mix"})
    _seed_modes("mix", {
        "web-1": "web", "net-1": "network", "full-1": "full",
        "sast-1": "sast", "sca-1": "sca",
    })

    def ids(r):
        return {s.get("scan_id") or s.get("id") for s in r.json()["scans"]}

    # Default (pentest) — web/network/full only, no sast/sca.
    pentest = ids(client.get("/api/scans"))
    assert {"web-1", "net-1", "full-1"} <= pentest
    assert "sast-1" not in pentest and "sca-1" not in pentest

    # Each code-analysis section returns only its own kind.
    assert ids(client.get("/api/scans?kind=sast")) == {"sast-1"}
    assert ids(client.get("/api/scans?kind=sca")) == {"sca-1"}

    # kind=all is the escape hatch that still returns everything.
    everything = ids(client.get("/api/scans?kind=all"))
    assert {"web-1", "net-1", "full-1", "sast-1", "sca-1"} <= everything


def test_sast_scan_persists_and_activates_engagement(client, monkeypatch):
    """Running SAST with an engagement name must persist the findings AND make
    that engagement active — the Findings page/dashboard read the *active*
    engagement, so without activation the run lands in one store while every
    reader looks at another ('I scanned SAST but Findings is empty')."""
    import heaven.vulnscan.sast_runner as sr

    class _Result:
        success = True
        duration_s = 1.2

        def to_dict(self):
            return {"success": True, "findings_count": 1, "files_scanned": 3,
                    "duration_s": 1.2, "severity_breakdown": {"high": 1},
                    "findings": [{"rule_id": "x.secret", "severity": "high",
                                  "file_path": "app.py", "line": 4,
                                  "title": "Hardcoded secret"}]}

    async def _fake_run_sast(path, **kw):
        return _Result()

    def _fake_persist(store, scan_id, result):
        store.upsert_finding(scan_id, {
            "target": "app.py", "vuln_type": "hardcoded_secret",
            "title": "Hardcoded secret", "severity": "high", "confidence": 0.9,
        })
        return 1

    monkeypatch.setattr(sr, "has_semgrep", lambda: True)
    monkeypatch.setattr(sr, "run_sast", _fake_run_sast)
    monkeypatch.setattr(sr, "persist_findings", _fake_persist)

    # Start out viewing a DIFFERENT engagement, to prove the SAST run repoints.
    _seed("other", {"s0": [_FINDING]})
    client.post("/api/engagements/active", json={"name": "other"})

    r = client.post("/api/sast/scan", json={"path": "/src", "engagement": "code-audit"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["engagement"] == "code-audit"
    assert body["persisted_count"] == 1

    # The active engagement is now the one we scanned into...
    assert client.get("/api/engagements").json()["active"] == "code-audit"
    # ...and the Findings page (which reads the active engagement) shows it.
    titles = [f["title"] for f in client.get("/api/engagement/findings").json()["findings"]]
    assert "Hardcoded secret" in titles


def test_dashboard_empty_engagement_does_not_leak_report_hosts(client):
    """Switching to an engagement with no findings must show an EMPTY topology —
    not fall back to some other engagement's latest report_*.json. Regression for
    'hosts mapped doesn't change when I switch the viewing engagement'."""
    import json

    from heaven.api.server import _engagement_store_factory
    from heaven.config import get_config

    # A global CLI report on disk with a host — the tempting wrong fallback.
    # (Same directory the dashboard globs report_*.json from.)
    d = get_config().data_dir
    d.mkdir(parents=True, exist_ok=True)
    (d / "report_old.json").write_text(json.dumps({
        "scan_id": "old",
        "vulnerabilities": [{"target": "10.9.9.9", "severity": "high", "title": "x"}],
    }))

    # Engagement A has a real host; engagement B is empty.
    _seed("eng-a", {"s1": [{"target": "10.0.0.1", "vuln_type": "xss", "title": "A",
                            "severity": "high", "confidence": 0.9, "risk_score": 7.0}]})
    _engagement_store_factory("eng-b").create_engagement(name="eng-b")

    client.post("/api/engagements/active", json={"name": "eng-a"})
    a = client.get("/api/dashboard").json()
    assert a["total_assets"] == 1
    assert a["assets"][0]["host"] == "10.0.0.1"

    client.post("/api/engagements/active", json={"name": "eng-b"})
    b = client.get("/api/dashboard").json()
    # Empty engagement → empty topology, NOT 10.9.9.9 (report) or 10.0.0.1 (eng-a).
    assert b["total_assets"] == 0
    assert b["assets"] == []


def test_resolve_engagement_priority(tmp_path, monkeypatch):
    """Resolution order: explicit arg > env > active pointer > 'default'."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    from heaven.api import server
    server._active_engagement_file().unlink(missing_ok=True)

    assert server._resolve_engagement_name() == "default"
    server._set_active_engagement("acme")
    assert server._resolve_engagement_name() == "acme"
    assert server._resolve_engagement_name("explicit") == "explicit"
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", "envwins")
    assert server._resolve_engagement_name() == "envwins"


def test_orphaned_running_scan_self_heals_on_list(client):
    """A scan left 'running' by a dead process must not tick forever.

    The header badge counts scans whose status is 'running'. A row is only ever
    flipped to a terminal state from inside its live in-process task, so a killed
    / crashed / closed process strands the row 'running' and the badge shows a
    phantom "1 scanning" indefinitely. Listing scans now self-heals any 'running'
    row that no live task in this process is driving (id absent from both
    active_scans and _scan_tasks_by_id) → 'interrupted' (resumable), so the badge
    clears on the next poll without a server restart.
    """
    from heaven.api.server import _engagement_store_factory
    client.post("/api/engagements/active", json={"name": "orphan-eng"})
    store = _engagement_store_factory("orphan-eng")
    store.create_engagement(name="orphan-eng")
    # A running row that nothing is driving (no task registered) — the orphan.
    store.record_scan_start("zombie1", name="zombie1", mode="web")

    r = client.get("/api/scans?kind=all")
    assert r.status_code == 200
    rows = {s.get("scan_id") or s.get("id"): s for s in r.json()["scans"]}
    assert rows["zombie1"]["status"] == "interrupted"  # healed in the response
    # …and persisted, so it stays healed across polls / restarts.
    assert store.get_scan_state("zombie1")["status"] == "interrupted"


def test_live_running_scan_is_not_reconciled(client):
    """A genuinely in-flight scan (its id IS in the live-task registry) must be
    left alone — the self-heal only touches rows no task is driving."""
    from heaven.api import server
    from heaven.api.server import _engagement_store_factory
    client.post("/api/engagements/active", json={"name": "live-eng"})
    store = _engagement_store_factory("live-eng")
    store.create_engagement(name="live-eng")
    store.record_scan_start("live1", name="live1", mode="web")

    # Register a placeholder task under the scan id — membership is all the
    # self-heal checks, so a sentinel object is enough to mark it "driven".
    server._scan_tasks_by_id["live1"] = object()
    try:
        r = client.get("/api/scans?kind=all")
        rows = {s.get("scan_id") or s.get("id"): s for s in r.json()["scans"]}
        assert rows["live1"]["status"] == "running"  # untouched
        assert store.get_scan_state("live1")["status"] == "running"
    finally:
        server._scan_tasks_by_id.pop("live1", None)


def test_evict_terminal_scans_bounds_memory_without_touching_live():
    """active_scans must not grow without bound. _evict_terminal_scans drops the
    OLDEST terminal entries down to the soft cap, and never evicts a live
    (pending/running) entry even when it is the oldest thing in the dict, a
    running scan's in-memory entry is load-bearing and has no terminal store row
    to fall back to. Regression: completed scans used to accumulate forever, so a
    long-running `serve` leaked memory and GET /api/scans re-copied the whole dict
    on every poll."""
    from heaven.api import server

    cap = server._ACTIVE_SCANS_SOFT_CAP
    snapshot = dict(server.active_scans)
    server.active_scans.clear()
    try:
        # Two live scans with the EARLIEST timestamps: if the guard were missing
        # these would be evicted first. They must survive.
        server.active_scans["live-running"] = {
            "status": "running", "created": "2000-01-01T00:00:00+00:00"}
        server.active_scans["live-pending"] = {
            "status": "pending", "created": "2000-01-01T00:00:01+00:00"}
        # cap + 30 completed scans, strictly increasing (sortable) timestamps.
        overflow = 30
        for i in range(cap + overflow):
            server.active_scans[f"done-{i:05d}"] = {
                "status": "completed",
                "created": f"2020-01-01T00:00:00.{i:05d}+00:00",
                "result": {"x": "y" * 100},  # the payload that used to leak
            }
        assert len(server.active_scans) == cap + overflow + 2

        server._evict_terminal_scans()

        # Bounded to exactly the cap (2 live + cap-2 newest completed).
        assert len(server.active_scans) == cap
        # Both live entries survive despite being the oldest in the dict.
        assert "live-running" in server.active_scans
        assert "live-pending" in server.active_scans
        # The oldest terminal entries were dropped (there were overflow+2 too
        # many, but the 2 live ones are protected, so overflow+2 completed go).
        dropped = overflow + 2
        for i in range(dropped):
            assert f"done-{i:05d}" not in server.active_scans, i
        # The newest terminal entries were kept.
        assert f"done-{cap + overflow - 1:05d}" in server.active_scans
    finally:
        server.active_scans.clear()
        server.active_scans.update(snapshot)


@pytest.fixture
def strict_client(tmp_path, monkeypatch):
    """Like `client`, but surfaces an unhandled route exception as a real 500
    response (what uvicorn does) instead of re-raising, so a coercion regression
    asserts cleanly as a 500 rather than erroring out of the test."""
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
        yield TestClient(create_app(), raise_server_exceptions=False)
    finally:
        auth_mod._auth_manager = None


@pytest.mark.parametrize("path,body", [
    # A malformed (truthy, wrong-type) numeric field used to raise an uncaught
    # ValueError/TypeError -> unsanitized 500. Each body reaches the coercion and
    # fails there, so no background job / scan / lateral action is launched.
    ("/api/fleet/run", {"engagement": "e", "ips": ["127.0.0.1"], "mode": "full",
                        "max_iterations": "abc"}),
    ("/api/fleet/run", {"engagement": "e", "ips": ["127.0.0.1"], "mode": "full",
                        "time_budget_s": "soon"}),
    ("/api/autonomous/run", {"ips": ["127.0.0.1"], "max_iterations": "abc"}),
    ("/api/autonomous/run", {"ips": ["127.0.0.1"], "time_budget_s": {"x": 1}}),
    ("/api/lateral/run", {"targets": ["notapair"]}),      # int('o') ValueError
    ("/api/lateral/run", {"targets": [["onlyhost"]]}),    # IndexError
    ("/api/lateral/run", {"targets": [42]}),              # TypeError (not indexable)
    ("/api/lateral/run", {"targets": "10.0.0.5:22"}),     # str, not a list of pairs
    ("/api/sca", {"path": ".", "max_files": "abc"}),
    ("/api/sast/scan", {"path": ".", "timeout": "abc"}),
])
def test_malformed_numeric_body_is_400_not_500(strict_client, path, body):
    r = strict_client.post(path, json=body)
    assert r.status_code == 400, f"{path} -> {r.status_code}: {r.text[:200]}"


def test_evicted_completed_scan_still_resolves_via_store(client):
    """Evicting an old completed scan from memory is transparent: GET
    /api/scans/{id} falls back to the engagement store (the post-restart path),
    so clicking it still works and its findings are intact."""
    from heaven.api import server

    client.post("/api/engagements/active", json={"name": "evict-eng"})
    _seed("evict-eng", {
        "old-done": [{"target": "https://a", "vuln_type": "xss",
                      "title": "Reflected XSS", "severity": "high",
                      "confidence": 0.9, "risk_score": 7.5}],
    })
    # Put it in memory as completed, then force eviction by flooding past the cap.
    snapshot = dict(server.active_scans)
    try:
        server.active_scans["old-done"] = {
            "scan_id": "old-done", "status": "completed",
            "created": "2019-01-01T00:00:00+00:00", "engagement": "evict-eng",
            "result": {"big": "z" * 100}}
        for i in range(server._ACTIVE_SCANS_SOFT_CAP + 5):
            server.active_scans[f"flood-{i:05d}"] = {
                "status": "completed",
                "created": f"2021-01-01T00:00:00.{i:05d}+00:00"}
        server._evict_terminal_scans()
        assert "old-done" not in server.active_scans  # evicted (oldest terminal)

        # Still viewable via the store fallback, findings intact.
        r = client.get("/api/scans/old-done?include_findings=true")
        assert r.status_code == 200, r.text
        assert r.json()["findings_count"] == 1
        assert r.json()["findings"][0]["title"] == "Reflected XSS"
    finally:
        server.active_scans.clear()
        server.active_scans.update(snapshot)


# ── Internal-exposure: a crashed scan's error must not leak raw exception text ──
def test_safe_error_hides_raw_exception_text():
    """`_safe_error` is the chokepoint for background scan/job failures surfaced
    to the UI: it must return a generic message + correlation ref, never the raw
    ``str(exc)`` (which can carry an absolute path or DB schema detail, CWE-209).
    The full detail is logged server-side under that same ref."""
    import re

    from heaven.api.server import _safe_error

    secret_path = "/private/var/engagements/VerySecret_Client.db"
    exc = FileNotFoundError(2, "No such file or directory", secret_path)
    # Also prove a schema-shaped detail does not pass through.
    exc2 = ValueError("no such column: internal_secret_col in table scans")

    out = _safe_error("background scan sc-1 failed", exc)
    assert secret_path not in out
    assert "No such file or directory" not in out
    assert re.fullmatch(r"background scan sc-1 failed \(ref [0-9a-f]{8}\)", out), out

    out2 = _safe_error("fleet job fj-9 failed", exc2)
    assert "internal_secret_col" not in out2
    assert re.fullmatch(r"fleet job fj-9 failed \(ref [0-9a-f]{8}\)", out2), out2

    # Each failure gets its own ref so an operator can correlate precisely.
    assert out.rsplit("ref ", 1)[1] != out2.rsplit("ref ", 1)[1]


def test_crashed_scan_error_is_sanitized_not_leaked(client, monkeypatch):
    """End to end: when a background scan crashes with an exception whose text
    carries an internal filesystem path, neither the in-memory record nor the
    status endpoints (/api/scans, /api/scans/{id}) expose that raw path; only a
    generic message plus a correlation ref, matching the _server_error contract."""
    import asyncio
    import re

    import heaven.orchestrator as orch_mod
    from heaven.api import server

    secret_path = "/private/var/secret/engagements/VerySecret.db"

    def _boom(*_a, **_k):
        # str() of this carries the absolute path, exactly the leak we guard.
        raise FileNotFoundError(2, "No such file or directory", secret_path)

    monkeypatch.setattr(orch_mod, "build_full_scan", _boom)

    scan_id = "scan-crash-e2e"
    snapshot = dict(server.active_scans)
    try:
        server.active_scans[scan_id] = {
            "scan_id": scan_id, "status": "pending", "mode": "web",
            "created": "2026-01-01T00:00:00+00:00",
        }
        req = server.ScanRequest(targets=["10.0.0.1"], engagement="e2e-crash")
        asyncio.run(server._run_scan_background(scan_id, req))

        entry = server.active_scans[scan_id]
        assert entry["status"] == "failed"
        err = entry["error"]
        # Sanitized: generic message + ref, NOT the raw internal path.
        assert secret_path not in err
        assert re.search(r"\(ref [0-9a-f]{8}\)$", err), err

        # And neither status endpoint re-exposes the raw path to the client.
        assert secret_path not in client.get(f"/api/scans/{scan_id}").text
        assert secret_path not in client.get("/api/scans").text
    finally:
        server.active_scans.clear()
        server.active_scans.update(snapshot)

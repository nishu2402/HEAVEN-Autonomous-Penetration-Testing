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

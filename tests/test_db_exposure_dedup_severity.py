"""Regression tests for the exposed-database finding: one canonical slug (so the
two detectors that both flag a reachable DB dedup instead of double-reporting)
and honest, reconcile-stable severity (auth-gated engines stay High; no-auth
engines exposed to the public Internet are Critical).

Root cause history: ``network_exposure`` emitted ``database_exposed`` while the
orchestrator's per-port ``_db_check`` emitted the reversed ``exposed_database``
with an empty evidence blob — so a single exposed MySQL surfaced TWICE under two
spellings and never deduped. Separately, a plain ``critical`` label with no score
was realigned back down to the class's 8.6 (High) band by ``reconcile_severity``.
"""
import asyncio
import copy
import json
import sqlite3
from datetime import datetime, timezone

from heaven.devsecops.vuln_kb import enrich_finding
from heaven.engagement import EngagementStore, dedup_findings
from heaven.recon import network_exposure as ne
from heaven.utils.cvss import reconcile_severity


def _analyze(ports):
    net = {"hosts": [{
        "ip": "162.241.216.11", "host": "162.241.216.11",
        "open_ports": [dict(p) for p in ports],
    }]}
    res = asyncio.run(ne.analyze_network_exposure(
        net, active_snmp=False, active_probes=False))
    findings = res.get("findings", []) if isinstance(res, dict) else res
    return [f for f in findings if f.get("vuln_type") == "database_exposed"]


def test_auth_gated_db_is_high_and_survives_reconcile():
    """A publicly-reachable MySQL/Postgres (auth required) is High — and stays
    High after severity reconciliation, never silently demoted or inflated."""
    db = _analyze([
        {"port": 3306, "service": "mysql", "product": "MySQL", "version": "5.7.44"},
        {"port": 5432, "service": "postgresql", "product": "PostgreSQL"},
    ])
    assert {f["target"].rsplit(":", 1)[1] for f in db} == {"3306", "5432"}
    for f in db:
        assert f["severity"] == "high"
        assert reconcile_severity(copy.deepcopy(f))["severity"] == "high"


def test_noauth_db_public_exposure_is_critical_and_sticks():
    """A no-auth-by-default engine (Redis/Mongo/Elasticsearch/…) reachable from
    a public address is Critical, and the label survives reconcile_severity
    because the finding pins a critical-band ``typical_cvss``."""
    db = _analyze([
        {"port": 6379, "service": "redis", "product": "Redis"},
        {"port": 27017, "service": "mongodb", "product": "MongoDB"},
    ])
    assert db, "expected database_exposed findings for redis/mongodb"
    for f in db:
        assert f["severity"] == "critical", f
        assert f["evidence"].get("no_auth_by_default") is True
        assert reconcile_severity(copy.deepcopy(f))["severity"] == "critical"


def test_two_detectors_one_exposed_db_dedup_to_one():
    """The orchestrator's per-port ``_db_check`` finding and network_exposure's
    richer finding for the SAME host:port collapse to a single entry (the richer
    one wins), instead of double-reporting the same exposed database."""
    ne_mysql = _analyze(
        [{"port": 3306, "service": "mysql", "product": "MySQL"}])[0]
    # The orchestrator emitter's shape (now the canonical ``database_exposed``).
    orch_mysql = {
        "target": "162.241.216.11:3306", "vuln_type": "database_exposed",
        "title": "Exposed MYSQL service on port 3306", "severity": "high",
        "confidence": 0.8,
        "evidence": {"port": 3306, "service": "mysql", "product": "mysql"},
    }
    merged = dedup_findings([orch_mysql, ne_mysql])
    db = [m for m in merged
          if m.get("vuln_type") in ("database_exposed", "exposed_database")]
    assert len(db) == 1, db
    # The richer network_exposure copy wins (carries the public_exposure marker).
    assert db[0]["evidence"].get("public_exposure") is True


def test_list_and_detail_agree_on_reconciled_severity(tmp_path):
    """The findings LIST and the finding DETAIL must show the SAME severity.

    The reported bug: an LFI at CVSS 8.1 showed as Critical in the list (raw
    stored label) but High on its detail page (which reconciles on read). The
    store now persists the reconciled band, so the list's stored severity equals
    the detail path's enriched severity — both High, matching the 8.1 score."""
    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("sev")
    fid = store.upsert_finding("s1", {
        "target": "http://h/mutillidae/index.php", "vuln_type": "lfi",
        "title": "Local File Inclusion", "severity": "critical",
        "confidence": 0.9, "param": "page",
    })
    stored = store.get_finding(fid)
    # What the LIST endpoint returns (the raw stored column) is already canonical.
    assert stored.severity == "high"
    # What the DETAIL endpoint shows (enrich reconciles on read) is identical —
    # never a contradiction between the two surfaces again.
    detail = enrich_finding({
        "target": stored.target, "vuln_type": stored.vuln_type,
        "title": stored.title, "severity": stored.severity,
        "confidence": stored.confidence, "cve_id": stored.cve_id,
        "evidence": stored.evidence,
    })
    assert detail["severity"] == stored.severity == "high"


def test_legacy_row_severity_reconciled_on_open(tmp_path):
    """A row written before write-time reconciliation (raw ``critical`` on an 8.1
    LFI) is corrected the first time the store is opened — including the
    read-only open the findings list uses — so existing data is fixed without a
    re-scan. Guarded by user_version, the backfill runs once."""
    db = tmp_path / "legacy.db"
    EngagementStore(db)                       # materialise the schema
    now = datetime.now(timezone.utc).isoformat()
    # Write a legacy row directly, bypassing the reconciling upsert, and reset
    # the migration marker so the next open runs the one-time backfill.
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO scans (id, started_at, status) VALUES (?, ?, 'completed')",
                  ("sc", now))
        c.execute(
            "INSERT INTO findings (id, scan_id, target, vuln_type, title, severity, "
            "confidence, first_seen_at, last_seen_at, seen_count, status, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open', ?)",
            ("legacy1", "sc", "http://h/x", "lfi", "LFI", "critical", 0.9, now, now,
             json.dumps({})),
        )
        c.execute("PRAGMA user_version = 0")
    EngagementStore._MIGRATED_PATHS.discard(str(db))
    # Read-only open, exactly like the findings list — the backfill still runs.
    reopened = EngagementStore(db, create=False)
    assert reopened.get_finding("legacy1").severity == "high"
    with sqlite3.connect(db) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == EngagementStore._SCHEMA_VERSION


def test_orchestrator_db_check_no_longer_uses_reversed_slug():
    """The orchestrator must not resurrect the reversed ``exposed_database``
    spelling (which broke dedup against network_exposure's ``database_exposed``)."""
    import inspect

    from heaven import orchestrator
    src = inspect.getsource(orchestrator)
    # The only place either spelling appears in a `"vuln_type": ...` literal is
    # the _db_check emitter; it must be the canonical database_exposed.
    assert '"vuln_type": "exposed_database"' not in src
    assert '"vuln_type": "database_exposed"' in src

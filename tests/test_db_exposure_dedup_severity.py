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

import pytest

from heaven.devsecops.vuln_kb import enrich_finding
from heaven.engagement import EngagementStore, dedup_findings
from heaven.recon import network_exposure as ne
from heaven.utils.cvss import confirmation_status, reconcile_severity


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


def _samba_pair():
    """The two findings that collide on ``host:139:CVE-2007-2447`` in a live
    Metasploitable-2 scan: the exploitation engine's proven RCE and the weaker,
    FP-reviewed version/banner match for the same component."""
    exploit = {
        "target": "192.168.0.162:139", "host": "192.168.0.162", "port": 139,
        "vuln_type": "samba_usermap_script", "severity": "critical",
        "confidence": 1.0, "confirmed": True, "status": "confirmed",
        "title": "Samba usermap_script — remote command execution CONFIRMED",
        "cve": "CVE-2007-2447", "cwe": "CWE-78", "scanner": "exploit_engine",
        "evidence": {"technique": "usermap script", "proof_command": "id; uname -a",
                     "proof_output": "uid=0(root) gid=0(root) groups=0(root)\nLinux",
                     "ran_as": "uid=0(root) gid=0(root) groups=0(root)"},
    }
    banner = {
        "target": "192.168.0.162:139", "host": "192.168.0.162", "port": 139,
        "vuln_type": "vulnerable_service", "severity": "medium", "confidence": 0.6,
        "confidence_bucket": "medium", "signal_count": 1,
        "fp_check_reasons": ["banner version match"],
        "title": "Samba 3.0.20 vulnerable version", "cve_id": "CVE-2007-2447",
        "source": "inline_db",
        "evidence": {"product": "Samba", "version": "3.0.20", "source": "inline_db"},
    }
    return exploit, banner


@pytest.mark.parametrize("reverse", [False, True])
def test_proven_rce_wins_merge_over_weaker_banner(reverse):
    """A confirmed critical RCE must survive dedup against a weaker, FP-reviewed
    version match of the same identity — keeping its Critical severity and its
    Confirmed status, not the banner copy's Medium/Potential. Order-independent."""
    exploit, banner = _samba_pair()
    pair = [banner, exploit] if reverse else [exploit, banner]
    merged = dedup_findings([copy.deepcopy(f) for f in pair])
    samba = [m for m in merged if m["target"].endswith(":139")]
    assert len(samba) == 1, samba
    win = samba[0]
    assert win["vuln_type"] == "samba_usermap_script", win
    assert win["severity"] == "critical"
    # And the reconciler must NOT demote it to the published CVSS v2 6.0 (Medium).
    assert reconcile_severity(copy.deepcopy(win))["severity"] == "critical"
    assert confirmation_status(win) == "Confirmed"


def test_proven_rce_persists_critical_and_confirmed(tmp_path):
    """Full persist path: the proven RCE is stored Critical (never demoted to the
    stale published 6.0) and reads back as Confirmed after the DB round-trip —
    the exact live regression (Samba RCE filed as medium/Potential)."""
    exploit, banner = _samba_pair()
    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("rce")
    fid = store.upsert_finding("s1", dedup_findings([exploit, banner])[0])
    row = store.get_finding(fid)
    assert row.severity == "critical", row.severity
    reread = {"target": row.target, "vuln_type": row.vuln_type, "title": row.title,
              "severity": row.severity, "confidence": row.confidence,
              "cve_id": row.cve_id, "evidence": row.evidence}
    assert confirmation_status(reread) == "Confirmed"


def test_rescan_without_proof_does_not_demote_stored_rce(tmp_path):
    """A confirmed Critical RCE already in the store must not be demoted when a
    LATER scan (e.g. re-run without exploit mode) upserts only the weaker,
    unproven banner match of the same identity. The persist path applies the same
    merge policy as the in-memory dedup, so the store never drifts from it."""
    exploit, banner = _samba_pair()
    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("rce")
    fid = store.upsert_finding("scan-exploit", exploit)
    assert store.get_finding(fid).severity == "critical"
    # Re-scan finds only the version banner for the same host:port:CVE.
    fid2 = store.upsert_finding("scan-recon", banner)
    assert fid2 == fid, "same identity must dedup to the same row"
    row = store.get_finding(fid)
    assert row.severity == "critical", f"stored RCE was demoted to {row.severity}"
    assert row.seen_count == 2
    assert row.evidence.get("proof_output"), "proof output must be retained"
    reread = {"target": row.target, "vuln_type": row.vuln_type, "title": row.title,
              "severity": row.severity, "cve_id": row.cve_id, "evidence": row.evidence}
    assert confirmation_status(reread) == "Confirmed"


def test_fp_review_downgrade_still_wins_for_unproven():
    """Guardrail: the fix must not weaken the FP-review path. When NEITHER copy is
    proven, a suppressor's confidence downgrade still wins over a raw candidate."""
    from heaven.engagement import _richer_finding
    raw = {"vuln_type": "sqli", "severity": "high", "confidence": 0.9,
           "evidence": {"param": "id"}}
    review = {"vuln_type": "sqli", "severity": "low", "confidence": 0.3,
              "confidence_bucket": "low", "fp_check_reasons": ["likely FP"],
              "evidence": {"param": "id"}}
    assert _richer_finding(raw, review) is review
    assert _richer_finding(review, raw) is review


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

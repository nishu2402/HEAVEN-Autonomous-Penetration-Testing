"""
HEAVEN — Engagement Workflow.

A pentester runs many scans across many targets over the course of a single
engagement. They need:

  - One canonical "scope" file that all scans share
  - Findings dedup'd across scans (same SQLi shouldn't appear 5 times)
  - Resumable scans (network drops, machine reboots, finding mid-week)
  - A way to add notes, mark FPs, mark accepted-risk
  - Export the engagement state at the end for the report

This module is a SQLite-backed engagement store. Local-only, file-based, no
server. The intent is that one file = one engagement.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from heaven.utils.logger import get_logger

logger = get_logger("engagement")


SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    client          TEXT,
    statement_of_work TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS scope (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,            -- 'ip', 'cidr', 'host', 'url', 'domain'
    in_scope        INTEGER NOT NULL DEFAULT 1,
    notes           TEXT,
    added_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    name            TEXT,
    mode            TEXT,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    config_json     TEXT,
    summary_json    TEXT
);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
    scan_id         TEXT NOT NULL,
    task_id         TEXT NOT NULL,
    task_name       TEXT,
    state           TEXT NOT NULL,        -- pending/running/completed/failed/skipped
    result_json     TEXT,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (scan_id, task_id)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_scan ON scan_checkpoints(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,           -- deterministic hash, see _finding_hash
    scan_id         TEXT NOT NULL,
    target          TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    confidence_bucket TEXT,
    cve_id          TEXT,
    risk_score      REAL,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'open',  -- open, verified, false_positive, accepted_risk, fixed
    operator_notes  TEXT,
    evidence_json   TEXT,                          -- full ValidationResult / probe data
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def _finding_hash(target: str, vuln_type: str, param: str = "",
                  endpoint: str = "") -> str:
    """
    Stable hash that identifies a finding across re-scans.

    Two scans of the same SQLi on the same parameter and endpoint will produce
    identical hashes — they get deduped, not duplicated.
    """
    key = f"{target.lower()}|{vuln_type.lower()}|{endpoint.lower()}|{param.lower()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class Engagement:
    name: str
    client: str = ""
    statement_of_work: str = ""
    created_at: str = ""
    updated_at: str = ""
    notes: str = ""
    id: Optional[int] = None


@dataclass
class ScopeEntry:
    target: str
    kind: str = "host"
    in_scope: bool = True
    notes: str = ""
    added_at: str = ""
    id: Optional[int] = None


@dataclass
class Finding:
    id: str
    scan_id: str
    target: str
    vuln_type: str
    title: str
    severity: str
    confidence: float = 0.0
    confidence_bucket: str = ""
    cve_id: str = ""
    risk_score: float = 0.0
    first_seen_at: str = ""
    last_seen_at: str = ""
    seen_count: int = 1
    status: str = "open"
    operator_notes: str = ""
    evidence: dict = field(default_factory=dict)


class EngagementStore:
    """SQLite-backed engagement state. One DB file per engagement."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)

    # ── Engagement metadata ────────────────────────────────────────────
    def create_engagement(self, name: str, client: str = "",
                          statement_of_work: str = "") -> Engagement:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO engagement (name, client, statement_of_work, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, client, statement_of_work, now, now),
            )
            if cur.rowcount == 0:
                # Already exists — return it
                row = c.execute("SELECT * FROM engagement WHERE name = ?", (name,)).fetchone()
                return Engagement(**dict(row))
        return Engagement(name=name, client=client, statement_of_work=statement_of_work,
                          created_at=now, updated_at=now)

    def get_engagement(self) -> Optional[Engagement]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM engagement LIMIT 1").fetchone()
            return Engagement(**dict(row)) if row else None

    # ── Scope ──────────────────────────────────────────────────────────
    def add_scope(self, target: str, kind: str = "host", in_scope: bool = True,
                  notes: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO scope (target, kind, in_scope, notes, added_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, kind, 1 if in_scope else 0, notes, now),
            )

    def remove_scope(self, target: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM scope WHERE target = ?", (target,))
            return cur.rowcount > 0

    def list_scope(self, in_scope_only: bool = True) -> list[ScopeEntry]:
        with self._conn() as c:
            if in_scope_only:
                rows = c.execute("SELECT * FROM scope WHERE in_scope = 1 ORDER BY target").fetchall()
            else:
                rows = c.execute("SELECT * FROM scope ORDER BY target").fetchall()
            return [
                ScopeEntry(
                    id=r["id"], target=r["target"], kind=r["kind"],
                    in_scope=bool(r["in_scope"]), notes=r["notes"] or "",
                    added_at=r["added_at"],
                )
                for r in rows
            ]

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is explicitly authorized in this engagement."""
        with self._conn() as c:
            row = c.execute(
                "SELECT in_scope FROM scope WHERE target = ?", (target,)
            ).fetchone()
            return bool(row and row["in_scope"])

    def import_scope_file(self, path: Path | str) -> int:
        """Import a scope file (one target per line, # for comments)."""
        path = Path(path)
        count = 0
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Crude kind detection
            if line.startswith("http://") or line.startswith("https://"):
                kind = "url"
            elif "/" in line and line.replace(".", "").replace("/", "").isdigit():
                kind = "cidr"
            elif all(c.isdigit() or c == "." for c in line):
                kind = "ip"
            else:
                kind = "host"
            self.add_scope(line, kind=kind)
            count += 1
        return count

    # ── Scans ──────────────────────────────────────────────────────────
    def record_scan_start(self, scan_id: str, name: str = "", mode: str = "",
                          config: Optional[dict] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO scans (id, name, mode, started_at, status, config_json) "
                "VALUES (?, ?, ?, ?, 'running', ?)",
                (scan_id, name, mode, now, json.dumps(config or {})),
            )

    def record_scan_complete(self, scan_id: str, summary: dict,
                             status: str = "completed") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "UPDATE scans SET completed_at = ?, status = ?, summary_json = ? WHERE id = ?",
                (now, status, json.dumps(summary), scan_id),
            )

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Scan checkpoints (resumable scans) ─────────────────────────────
    def checkpoint_task(self, scan_id: str, task_id: str, task_name: str,
                         state: str, result: Optional[dict] = None) -> None:
        """Record a task's terminal state so the scan can resume after crash."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO scan_checkpoints "
                "(scan_id, task_id, task_name, state, result_json, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, task_id, task_name, state,
                 json.dumps(result, default=str) if result else None, now),
            )

    def load_checkpoints(self, scan_id: str) -> dict[str, dict]:
        """Return {task_id: {state, result, ...}} for resume logic."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM scan_checkpoints WHERE scan_id = ?", (scan_id,)
            ).fetchall()
            out = {}
            for r in rows:
                result = None
                if r["result_json"]:
                    try:
                        result = json.loads(r["result_json"])
                    except json.JSONDecodeError:
                        pass
                out[r["task_id"]] = {
                    "task_id": r["task_id"],
                    "task_name": r["task_name"],
                    "state": r["state"],
                    "result": result,
                    "updated_at": r["updated_at"],
                }
            return out

    def pause_scan(self, scan_id: str) -> bool:
        try:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE scans SET status='paused' WHERE id=?",
                    (scan_id,)
                )
            return True
        except Exception:
            return False

    def get_scan_state(self, scan_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, name, status, config_json, started_at FROM scans WHERE id=?",
                (scan_id,)
            ).fetchone()
        if not row:
            return None
        return {"id": row[0], "name": row[1], "status": row[2],
                "config_json": row[3], "started_at": row[4]}

    def list_all_scans(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, name, status, started_at, completed_at,
                          (SELECT COUNT(*) FROM findings WHERE scan_id=scans.id) as n_findings
                   FROM scans ORDER BY started_at DESC LIMIT ?""",
                (limit,)
            ).fetchall()
        return [{"id": r[0], "name": r[1], "status": r[2],
                 "started_at": r[3], "completed_at": r[4],
                 "findings": r[5]} for r in rows]

    def find_resumable_scans(self) -> list[dict]:
        """Find scans that didn't finish (for resume command)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM scans WHERE status IN ('running', 'pending') "
                "ORDER BY started_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Findings ───────────────────────────────────────────────────────
    def upsert_finding(self, scan_id: str, finding: dict) -> str:
        """
        Insert a finding or update an existing one (dedup on hash).

        Returns the finding ID. If the finding already exists, increments
        seen_count and updates last_seen_at, but preserves operator_notes
        and status.
        """
        target = finding.get("target", "") or finding.get("target_url", "") or finding.get("host", "")
        vuln_type = finding.get("vuln_type", "") or finding.get("type", "") or "unknown"
        param = finding.get("param", "")
        endpoint = finding.get("endpoint", "") or finding.get("url", "") or ""
        fid = finding.get("id") or _finding_hash(target, vuln_type, param, endpoint)

        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as c:
            # Auto-register scan if missing — keeps the API forgiving when callers
            # drop a finding without explicit record_scan_start
            scan_exists = c.execute(
                "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if not scan_exists:
                c.execute(
                    "INSERT INTO scans (id, started_at, status) VALUES (?, ?, 'completed')",
                    (scan_id, now),
                )

            existing = c.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
            # Enrich evidence with top-level fields so they survive DB round-trip
            evidence = dict(finding.get("evidence", {}))
            if "method" not in evidence and finding.get("method"):
                evidence["method"] = finding["method"]
            if "param" not in evidence and finding.get("param"):
                evidence["param"] = finding["param"]
            if "url" not in evidence and finding.get("request_url"):
                evidence["url"] = finding["request_url"]
            evidence_json = json.dumps(evidence)

            if existing:
                # Dedup — update last_seen_at + seen_count, preserve human-set fields
                c.execute(
                    "UPDATE findings SET last_seen_at = ?, seen_count = seen_count + 1, "
                    "scan_id = ?, evidence_json = ? "
                    "WHERE id = ?",
                    (now, scan_id, evidence_json, fid),
                )
            else:
                c.execute(
                    "INSERT INTO findings ("
                    "id, scan_id, target, vuln_type, title, severity, confidence, "
                    "confidence_bucket, cve_id, risk_score, first_seen_at, last_seen_at, "
                    "seen_count, status, evidence_json"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open', ?)",
                    (
                        fid, scan_id, target, vuln_type,
                        finding.get("title", finding.get("type", "Unknown")),
                        finding.get("severity", "info"),
                        float(finding.get("confidence", 0.0)),
                        finding.get("confidence_bucket", ""),
                        finding.get("cve_id", ""),
                        float(finding.get("risk_score", 0.0)),
                        now, now,
                        evidence_json,
                    ),
                )
        return fid

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def _row_to_finding(self, row) -> Finding:
        evidence = {}
        if row["evidence_json"]:
            try:
                evidence = json.loads(row["evidence_json"])
            except json.JSONDecodeError:
                pass
        return Finding(
            id=row["id"], scan_id=row["scan_id"], target=row["target"],
            vuln_type=row["vuln_type"], title=row["title"], severity=row["severity"],
            confidence=row["confidence"], confidence_bucket=row["confidence_bucket"] or "",
            cve_id=row["cve_id"] or "", risk_score=row["risk_score"] or 0.0,
            first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
            seen_count=row["seen_count"], status=row["status"],
            operator_notes=row["operator_notes"] or "", evidence=evidence,
        )

    def list_findings(
        self, severity: Optional[str] = None, status: Optional[str] = None,
        target: Optional[str] = None, vuln_type: Optional[str] = None,
        min_confidence: float = 0.0, limit: int = 1000,
    ) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        if severity:
            sql += " AND severity = ?"; args.append(severity)
        if status:
            sql += " AND status = ?"; args.append(status)
        if target:
            sql += " AND target LIKE ?"; args.append(f"%{target}%")
        if vuln_type:
            sql += " AND vuln_type = ?"; args.append(vuln_type)
        if min_confidence > 0:
            sql += " AND confidence >= ?"; args.append(min_confidence)
        sql += " ORDER BY CASE severity "
        sql += "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        sql += "WHEN 'low' THEN 3 ELSE 4 END, confidence DESC LIMIT ?"
        args.append(limit)

        with self._conn() as c:
            rows = c.execute(sql, args).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def update_finding_status(self, finding_id: str, status: str,
                              notes: str = "") -> bool:
        valid = ("open", "verified", "false_positive", "accepted_risk", "fixed")
        if status not in valid:
            raise ValueError(f"status must be one of {valid}")
        with self._conn() as c:
            cur = c.execute(
                "UPDATE findings SET status = ?, operator_notes = COALESCE(?, operator_notes) "
                "WHERE id = ?",
                (status, notes if notes else None, finding_id),
            )
            return cur.rowcount > 0

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_sev = dict(c.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            ).fetchall())
            by_status = dict(c.execute(
                "SELECT status, COUNT(*) FROM findings GROUP BY status"
            ).fetchall())
            scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            scope = c.execute("SELECT COUNT(*) FROM scope WHERE in_scope = 1").fetchone()[0]
        return {
            "total_findings": total,
            "by_severity": by_sev,
            "by_status": by_status,
            "scans_run": scans,
            "scope_targets": scope,
        }

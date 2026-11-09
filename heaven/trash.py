"""
HEAVEN — Recycle Bin (soft-delete trash store).

HEAVEN has two destructive deletes: removing a scan (its findings, checkpoints
and report file) and removing an engagement (its whole SQLite DB). Both used to
wipe data immediately after a single confirm. This module moves a deleted item
ASIDE into a trash store under ``data_dir/.trash`` and records a manifest row, so
an operator can review recently deleted scans and engagements on the Bin page (or
``heaven trash``) and either restore them or delete them permanently. Items
auto-purge after a retention window.

Design: "move aside + manifest".
  - ``trash.db``            a small SQLite manifest, one row per trashed item.
  - ``engagements/<id>/``   a trashed engagement's ``.db`` (+ WAL/SHM/journal).
  - ``scans/<id>/``         a trashed scan's ``bundle.json`` (+ ``report.json``).

Moves are atomic ``os.replace`` within one filesystem (``.trash`` lives under
``data_dir`` alongside ``engagements/``), so trashing even a large engagement is
instant and never duplicates data; a cross-filesystem data dir falls back to a
copy via ``shutil.move``. The store holds client findings, so the ``.trash``
directory is locked to 0700 and ``trash.db`` to 0600 (CWE-276), mirroring
``EngagementStore``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from heaven.utils.logger import get_logger

logger = get_logger("trash")

# A trash id is a uuid4 hex (32 lowercase hex chars): filename-safe and
# unguessable, so it is never a path-traversal vector when it arrives over HTTP.
_TRASH_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_DEFAULT_RETENTION_DAYS = 30
_DEFAULT_MAX_ITEMS = 500

# Tables captured when a scan is trashed, in dependency order (findings carry a
# FOREIGN KEY to scans(id), so scans must be reinserted first on restore). Only
# these fixed names are ever used to build SQL; column names come from the live
# schema, never from request input.
_SCAN_TABLES = ("scans", "scan_checkpoints", "findings")


class TrashPayloadError(RuntimeError):
    """A trashed item's payload is missing or corrupt, so it cannot be restored.

    Distinct from the ``FileNotFoundError`` that means the owning engagement is
    gone, so the API can report the real cause (payload lost) instead of a
    misleading "engagement no longer exists" 409 or an opaque 500.
    """


# ── configuration knobs ────────────────────────────────────────────────
def retention_days() -> int:
    """Days a trashed item is kept before auto-purge. 0 disables time-purge."""
    raw = os.environ.get("HEAVEN_TRASH_RETENTION_DAYS")
    if raw is None or raw.strip() == "":
        return _DEFAULT_RETENTION_DAYS
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_RETENTION_DAYS


def max_items() -> int:
    """Hard cap on the number of trashed items kept (oldest purged beyond it)."""
    raw = os.environ.get("HEAVEN_TRASH_MAX_ITEMS")
    if raw is None or raw.strip() == "":
        return _DEFAULT_MAX_ITEMS
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_MAX_ITEMS


def is_valid_trash_id(tid: Optional[str]) -> bool:
    """True when a trash id is safe to interpolate into a payload path."""
    return bool(tid) and bool(_TRASH_ID_RE.match(tid or ""))


# ── paths ───────────────────────────────────────────────────────────────
def _data_dir() -> Path:
    from heaven.config import get_config
    return get_config().data_dir


def trash_dir() -> Path:
    return _data_dir() / ".trash"


def _engagements_dir() -> Path:
    return _data_dir() / "engagements"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _move_file(src: Path, dst: Path) -> None:
    """Move one file, atomically within a filesystem, with a cross-device copy
    fallback. A missing source is a no-op (sidecars may not exist)."""
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(src, dst)
    except OSError:
        # Different filesystem (EXDEV) or similar: fall back to copy+unlink.
        shutil.move(str(src), str(dst))


# ── manifest store ──────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS trash (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,          -- 'scan' | 'engagement'
    label         TEXT NOT NULL,          -- human label for the Bin row
    engagement    TEXT,                   -- scan: owning engagement; engagement: its own name
    summary_json  TEXT,                   -- counts / severity / size
    payload_path  TEXT NOT NULL,          -- relative to the .trash directory
    deleted_at    TEXT NOT NULL,          -- UTC ISO-8601
    deleted_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_trash_deleted_at ON trash(deleted_at);
"""


class TrashStore:
    """SQLite manifest of trashed items, one small DB under ``data_dir/.trash``."""

    def __init__(self) -> None:
        self.root = trash_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "trash.db"
        self._init_schema()
        self._harden_permissions()

    def _harden_permissions(self) -> None:
        """Keep the trash store owner-only (CWE-276): it holds the same client
        findings the engagement DBs do. Best-effort, never widens, never raises."""
        with suppress(OSError):
            os.chmod(self.root, 0o700)
        with suppress(OSError):
            if self.db_path.exists() and (self.db_path.stat().st_mode & 0o077):
                os.chmod(self.db_path, 0o600)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
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
            c.executescript(_SCHEMA)

    def add(self, entry: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO trash (id, kind, label, engagement, summary_json, "
                "payload_path, deleted_at, deleted_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (entry["id"], entry["kind"], entry["label"], entry.get("engagement"),
                 json.dumps(entry.get("summary", {}), default=str),
                 entry["payload_path"], entry["deleted_at"], entry.get("deleted_by")),
            )

    def _row_to_item(self, row: sqlite3.Row) -> dict:
        try:
            summary = json.loads(row["summary_json"]) if row["summary_json"] else {}
        except (ValueError, TypeError):
            summary = {}
        return {
            "id": row["id"], "kind": row["kind"], "label": row["label"],
            "engagement": row["engagement"], "summary": summary,
            "payload_path": row["payload_path"], "deleted_at": row["deleted_at"],
            "deleted_by": row["deleted_by"],
        }

    def get(self, tid: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM trash WHERE id = ?", (tid,)).fetchone()
            return self._row_to_item(row) if row else None

    def list(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM trash ORDER BY deleted_at DESC").fetchall()
            return [self._row_to_item(r) for r in rows]

    def remove_row(self, tid: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM trash WHERE id = ?", (tid,))
            return cur.rowcount > 0


# ── trash operations (filesystem + manifest) ───────────────────────────
def trash_engagement(name: str, *, by: Optional[str] = None,
                     db_path: Optional[Path] = None) -> dict:
    """Move an engagement's DB (+ WAL/SHM/journal) into the Bin and record it.

    An empty engagement (0 findings and 0 scans) is hard-deleted instead of
    cluttering the Bin: there is nothing to restore. Returns ``{permanent: True,
    deleted: name}`` in that case, otherwise the manifest entry with its ``id``.

    ``db_path`` overrides the default ``data_dir/engagements/<name>.db`` so the
    CLI can bin an engagement that lives in its legacy ``./engagements`` dir; a
    restore always lands in the canonical ``data_dir/engagements``.

    Raises ``FileNotFoundError`` if the engagement DB does not exist.
    """
    from heaven.engagement import EngagementStore, delete_engagement_store

    db = Path(db_path) if db_path else _engagements_dir() / f"{name}.db"
    if not db.exists():
        raise FileNotFoundError(db)

    # An empty store is not worth keeping: hard-delete it (parity with the old
    # "Remove N empty engagements" cleanup).
    findings = scans = 0
    readable = False
    try:
        stats = EngagementStore(db, create=False).stats()
        findings = int(stats.get("total_findings", 0) or 0)
        scans = int(stats.get("scans_run", 0) or 0)
        readable = True
    except Exception:  # noqa: BLE001 — an unreadable store still gets binned, not lost
        logger.debug("suppressed non-fatal exception", exc_info=True)
    # Only hard-delete when the store was READABLE and is genuinely empty. If
    # stats() raised (corrupt/odd schema) we must not treat it as empty: bin it so
    # it stays recoverable, never silently wipe it.
    if readable and findings <= 0 and scans <= 0:
        delete_engagement_store(db)
        logger.info("Empty engagement '%s' hard-deleted (nothing to bin)", name)
        return {"permanent": True, "deleted": name}

    # Fold the WAL into the main DB so there is no live -wal to move (mirrors
    # rename_engagement_store), then relocate every file into a fresh payload dir.
    with suppress(sqlite3.Error):
        conn = sqlite3.connect(db, timeout=30.0)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        finally:
            conn.close()

    tid = uuid.uuid4().hex
    rel = f"engagements/{tid}"
    payload = trash_dir() / rel
    payload.mkdir(parents=True, exist_ok=True)
    with suppress(OSError):
        os.chmod(trash_dir(), 0o700)
    size_bytes = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        src = db if suffix == "" else db.with_name(db.name + suffix)
        if src.exists():
            with suppress(OSError):
                size_bytes += src.stat().st_size
        _move_file(src, payload / (db.name + suffix))

    entry = {
        "id": tid, "kind": "engagement", "label": name, "engagement": name,
        "summary": {"findings": findings, "scans": scans, "size_bytes": size_bytes},
        "payload_path": rel, "deleted_at": _now(), "deleted_by": by,
    }
    TrashStore().add(entry)
    logger.info("Engagement '%s' moved to Bin (%s findings, %s scans) by %s",
                name, findings, scans, by or "?")
    return entry


def trash_scan(store, scan_id: str, *, engagement: str,
               by: Optional[str] = None) -> dict:
    """Export a scan (its ``scans`` row + ``findings`` + ``scan_checkpoints`` +
    its ``report_<id>.json``) into the Bin, then delete the live rows.

    ``store`` is the owning engagement's ``EngagementStore``; ``engagement`` is
    its name, recorded so the scan can be restored into the same DB later. After
    this returns, the live engagement DB is exactly as a hard delete would leave
    it (the existing ``store.delete_scan`` runs last), so no read path anywhere
    else needs to change. Raises ``LookupError`` when the scan does not exist.
    """
    with store._conn() as c:  # noqa: SLF001 — same-package pragmatic access
        scan_row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finding_rows = c.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        checkpoint_rows = c.execute(
            "SELECT * FROM scan_checkpoints WHERE scan_id = ?", (scan_id,)).fetchall()

    scan = dict(scan_row) if scan_row else None
    findings = [dict(r) for r in finding_rows]
    checkpoints = [dict(r) for r in checkpoint_rows]
    if scan is None and not findings and not checkpoints:
        raise LookupError(scan_id)

    tid = uuid.uuid4().hex
    rel = f"scans/{tid}"
    payload = trash_dir() / rel
    payload.mkdir(parents=True, exist_ok=True)
    with suppress(OSError):
        os.chmod(trash_dir(), 0o700)

    bundle = {"scan_id": scan_id, "scan": scan,
              "findings": findings, "checkpoints": checkpoints}
    bundle_path = payload / "bundle.json"
    bundle_path.write_text(json.dumps(bundle, default=str), encoding="utf-8")
    with suppress(OSError):
        os.chmod(bundle_path, 0o600)

    # The report JSON lives at the data-dir root (report_<id>.json); keep it with
    # the bundle so a restore brings back the dashboard's report-file fallback.
    report_src = _data_dir() / f"report_{scan_id}.json"
    had_report = report_src.exists()
    if had_report:
        _move_file(report_src, payload / "report.json")

    label = (scan or {}).get("name") or (scan or {}).get("mode") or f"scan {scan_id[:8]}"
    entry = {
        "id": tid, "kind": "scan", "label": str(label), "engagement": engagement,
        "summary": {
            "scan_id": scan_id, "findings": len(findings),
            "mode": (scan or {}).get("mode"), "status": (scan or {}).get("status"),
            "started_at": (scan or {}).get("started_at"), "had_report": had_report,
        },
        "payload_path": rel, "deleted_at": _now(), "deleted_by": by,
    }
    TrashStore().add(entry)

    # Remove the live rows last, so a crash mid-export never loses the scan.
    store.delete_scan(scan_id)
    logger.info("Scan '%s' (engagement '%s') moved to Bin by %s",
                scan_id, engagement, by or "?")
    return entry


def _reinsert(c: sqlite3.Connection, table: str, rows: list[dict]) -> None:
    """Upsert captured rows back into a live table. ``table`` is one of the fixed
    ``_SCAN_TABLES``; columns come from the stored schema, not from any request."""
    for row in rows:
        cols = list(row.keys())
        if not cols:
            continue
        collist = ",".join(cols)
        placeholders = ",".join("?" for _ in cols)
        c.execute(
            f"INSERT OR REPLACE INTO {table} ({collist}) VALUES ({placeholders})",
            [row[col] for col in cols],
        )


def _unique_engagement_name(base: str) -> str:
    """A free engagement name for a restore whose original name is taken now."""
    eng_dir = _engagements_dir()
    if not (eng_dir / f"{base}.db").exists():
        return base
    candidate = f"{base} (restored)"
    if not (eng_dir / f"{candidate}.db").exists():
        return candidate
    return f"{base} (restored {uuid.uuid4().hex[:6]})"


def restore(tid: str) -> dict:
    """Restore a trashed item to its original place and drop it from the Bin.

    Engagement: its DB is moved back to ``engagements/<name>.db``; if that name is
    taken now (a new engagement reused it) it is restored under a suffixed name,
    returned as ``restored``. Scan: its rows are reinserted into the owning
    engagement DB and its report file is moved back. Raises ``KeyError`` if the id
    is unknown and ``FileNotFoundError`` if a scan's owning engagement is gone.
    """
    store = TrashStore()
    item = store.get(tid)
    if item is None:
        raise KeyError(tid)
    payload = trash_dir() / item["payload_path"]

    if item["kind"] == "engagement":
        original = item["label"]
        restored = _unique_engagement_name(original)
        eng_dir = _engagements_dir()
        eng_dir.mkdir(parents=True, exist_ok=True)
        src_db = payload / f"{original}.db"
        for suffix in ("", "-wal", "-shm", "-journal"):
            src = src_db if suffix == "" else src_db.with_name(src_db.name + suffix)
            _move_file(src, eng_dir / f"{restored}.db{'' if suffix == '' else suffix}")
        # If the on-disk name changed, keep the in-DB name row consistent.
        if restored != original:
            with suppress(Exception):
                from heaven.engagement import EngagementStore
                EngagementStore(eng_dir / f"{restored}.db").set_engagement_name(restored)
        _cleanup_payload(payload)
        store.remove_row(tid)
        logger.info("Engagement restored from Bin as '%s'", restored)
        return {"kind": "engagement", "restored": restored,
                "renamed": restored != original}

    # scan
    engagement = item["engagement"]
    target_db = _engagements_dir() / f"{engagement}.db"
    if not target_db.exists():
        raise FileNotFoundError(engagement)
    bundle_file = payload / "bundle.json"
    try:
        bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        # Missing or corrupt payload (e.g. an interrupted purge or a truncated
        # file): fail with the real cause, not a misleading "engagement gone"
        # 409 (that FileNotFoundError path) or a bare 500 from json.loads.
        raise TrashPayloadError(
            f"scan payload is missing or corrupt ({bundle_file.name})") from e
    scan_id = bundle.get("scan_id")

    from heaven.engagement import EngagementStore
    st = EngagementStore(target_db)  # create=True: schema is idempotent
    with st._conn() as c:  # noqa: SLF001
        if bundle.get("scan"):
            _reinsert(c, "scans", [bundle["scan"]])
        _reinsert(c, "scan_checkpoints", bundle.get("checkpoints", []))
        _reinsert(c, "findings", bundle.get("findings", []))

    report_payload = payload / "report.json"
    if report_payload.exists() and scan_id:
        _move_file(report_payload, _data_dir() / f"report_{scan_id}.json")

    _cleanup_payload(payload)
    store.remove_row(tid)
    logger.info("Scan '%s' restored from Bin into engagement '%s'",
                scan_id, engagement)
    return {"kind": "scan", "restored": item["label"], "engagement": engagement,
            "scan_id": scan_id}


def _cleanup_payload(payload: Path) -> None:
    with suppress(OSError):
        if payload.exists():
            shutil.rmtree(payload)


def purge(tid: str) -> bool:
    """Permanently delete one trashed item (its payload + manifest row)."""
    store = TrashStore()
    item = store.get(tid)
    if item is None:
        return False
    _cleanup_payload(trash_dir() / item["payload_path"])
    store.remove_row(tid)
    logger.info("Trashed %s '%s' permanently deleted", item["kind"], item["label"])
    return True


def empty() -> int:
    """Permanently delete every item in the Bin. Returns the count removed."""
    store = TrashStore()
    items = store.list()
    for item in items:
        _cleanup_payload(trash_dir() / item["payload_path"])
        store.remove_row(item["id"])
    if items:
        logger.info("Bin emptied (%d item(s) permanently deleted)", len(items))
    return len(items)


def purge_expired(days: Optional[int] = None, cap: Optional[int] = None,
                  store: Optional["TrashStore"] = None) -> int:
    """Permanently delete items older than the retention window, then enforce the
    item cap by purging the oldest beyond it. Returns the count removed. Accepts a
    ``store`` so a caller (e.g. ``list_items``) can reuse one TrashStore instead of
    opening a second one."""
    days = retention_days() if days is None else days
    cap = max_items() if cap is None else cap
    store = store or TrashStore()
    items = store.list()  # newest first
    purged = 0

    if days > 0:
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        for item in items:
            try:
                ts = datetime.fromisoformat(item["deleted_at"]).timestamp()
            except (ValueError, TypeError):
                continue
            if ts < cutoff:
                _cleanup_payload(trash_dir() / item["payload_path"])
                store.remove_row(item["id"])
                purged += 1

    # Re-list after time-purge, then trim the oldest beyond the cap.
    remaining = store.list()
    if len(remaining) > cap:
        for item in remaining[cap:]:  # list() is newest-first, so these are oldest
            _cleanup_payload(trash_dir() / item["payload_path"])
            store.remove_row(item["id"])
            purged += 1
    if purged:
        logger.info("Auto-purged %d expired/overflow Bin item(s)", purged)
    return purged


def list_items() -> list[dict]:
    """The Bin contents, newest first, after an auto-purge of expired items."""
    store = TrashStore()
    with suppress(Exception):
        purge_expired(store=store)
    return store.list()


def get_item(tid: str) -> Optional[dict]:
    return TrashStore().get(tid)

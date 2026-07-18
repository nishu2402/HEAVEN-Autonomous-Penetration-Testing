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


# Dedicated engagement slug for sample/demo data. The demo seeder writes here and
# switches the active pointer to it, so sample findings never contaminate a real
# engagement's DB (which previously left a stray "demo (sample data)" row behind).
DEMO_DB_NAME = "demo"


# ── Active-engagement pointer (single source of truth) ──────────────────
# One small pointer file records which engagement the app is currently viewing.
# The CLI, the web API and the demo seeder all read/write it through these
# helpers so they can never disagree about which store holds the live data.
def active_engagement_file() -> Path:
    from heaven.config import get_config
    return get_config().data_dir / ".active_engagement"


def get_active_engagement() -> Optional[str]:
    """The most-recently-selected engagement name, or None if never set."""
    try:
        p = active_engagement_file()
        if p.exists():
            name = p.read_text(encoding="utf-8").strip()
            return name or None
    except Exception:  # noqa: BLE001 — a missing/corrupt pointer just means "default"
        logger.debug("suppressed non-fatal exception", exc_info=True)
    return None


def set_active_engagement(name: Optional[str]) -> None:
    """Persist the active engagement so dashboard, findings and reports agree."""
    if not name:
        return
    try:
        p = active_engagement_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(name).strip(), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        logger.debug("Could not persist active engagement '%s': %s", name, e)


def clear_active_engagement() -> bool:
    """Remove the active-engagement pointer so the resolver falls back to
    'default'. Returns True if a pointer existed. Used after deleting the
    engagement the app was currently viewing."""
    try:
        p = active_engagement_file()
        if p.exists():
            p.unlink()
            return True
    except Exception as e:  # noqa: BLE001 — a missing pointer is already the goal
        logger.debug("Could not clear active engagement pointer: %s", e)
    return False


def best_populated_engagement() -> Optional[str]:
    """Name of the on-disk engagement richest in real data — most findings,
    then most scans, then most-recently modified.

    Used as a smarter fallback than a bare ``default`` when nothing is
    explicitly selected and no active pointer exists (e.g. right after the
    engagement the app was viewing got deleted): a page load then lands on the
    operator's actual work instead of an empty ``default`` that also silently
    absorbs new scans. Opens each DB read-only (never materialises one), skips
    the dedicated demo DB, and returns ``None`` when no engagement holds real
    data.
    """
    from heaven.config import get_config
    try:
        eng_dir = get_config().data_dir / "engagements"
        if not eng_dir.exists():
            return None
    except Exception:  # noqa: BLE001 — config problems just mean "no fallback"
        return None

    best: Optional[str] = None
    best_key: tuple = (0, 0, 0.0)
    for db in eng_dir.glob("*.db"):
        if db.stem == DEMO_DB_NAME:
            continue
        try:
            stats = EngagementStore(db, create=False).stats()
        except Exception:  # noqa: BLE001 — skip locked/unreadable DBs
            logger.debug("suppressed non-fatal exception", exc_info=True)
            continue
        findings = int(stats.get("total_findings", 0) or 0)
        scans = int(stats.get("scans_run", 0) or 0)
        if findings <= 0 and scans <= 0:
            continue  # empty — not a real fallback candidate
        try:
            mtime = db.stat().st_mtime
        except OSError:
            mtime = 0.0
        key = (findings, scans, mtime)
        if key > best_key:
            best_key = key
            best = db.stem
    return best


def delete_engagement_store(db_path: Path | str) -> bool:
    """Permanently delete an engagement's SQLite DB and its sidecar files.

    SQLite in WAL mode keeps ``<name>.db-wal`` and ``<name>.db-shm`` alongside the
    main file; a stray rollback journal (``-journal``) can also exist. Removing
    only ``<name>.db`` would let SQLite resurrect data from the leftover WAL the
    next time the name is opened, so every sidecar is unlinked too. Returns True
    when the main DB file was present and removed."""
    p = Path(db_path)
    removed_main = False
    for suffix in ("", "-wal", "-shm", "-journal"):
        sidecar = p if suffix == "" else p.with_name(p.name + suffix)
        try:
            if sidecar.exists():
                sidecar.unlink()
                if suffix == "":
                    removed_main = True
        except OSError as e:
            logger.warning("Could not delete %s: %s", sidecar, e)
    return removed_main


def rename_engagement_store(old_path: Path | str, new_path: Path | str) -> None:
    """Rename an engagement's SQLite DB (plus its WAL/SHM/journal sidecars) and
    rewrite the engagement's own name row so its label stays consistent.

    The engagement name is welded to the DB filename (``engagements/<name>.db``)
    and ``EngagementStore.get_engagement`` resolves the canonical row by that
    stem. A correct rename therefore has to (1) fold the WAL back into the main
    DB, (2) move every sidecar alongside the main file — moving only ``.db``
    would strand the WAL and let SQLite resurrect stale rows — and (3) update the
    in-DB ``engagement.name`` to the new filename stem, or the dashboard label
    falls back to a stale row.

    Handles a case-only rename on a case-insensitive filesystem (e.g. macOS:
    ``certified hacker`` → ``Certified Hacker``, which is the *same* inode) by
    hopping through a temp name so the stored case actually changes.

    Raises ``FileNotFoundError`` if the source is missing and ``FileExistsError``
    if the destination is a *different* existing engagement (never silently
    clobber another engagement's data).
    """
    old_p = Path(old_path)
    new_p = Path(new_path)
    if old_p == new_p:
        return
    if not old_p.exists():
        raise FileNotFoundError(old_p)
    # A case-insensitive filesystem reports the differently-cased target as
    # "existing" because it is the same file — that is an allowed case-only
    # rename, not a clobber. Only a genuinely distinct existing file is a clash.
    if new_p.exists() and not new_p.samefile(old_p):
        raise FileExistsError(new_p)

    # Fold the WAL back into the main DB so there is no live -wal to move.
    try:
        conn = sqlite3.connect(old_p, timeout=30.0)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error as e:  # checkpoint is best-effort — the move still works
        logger.debug("WAL checkpoint before rename failed (continuing): %s", e)

    def _move(src: Path, dst: Path) -> None:
        if src == dst or not src.exists():
            return
        if dst.exists() and dst.samefile(src):
            # Case-only rename on a case-insensitive fs: go via a temp name so
            # the on-disk case is actually updated rather than being a no-op.
            tmp = src.with_name(src.name + ".renaming.tmp")
            src.rename(tmp)
            tmp.rename(dst)
        else:
            src.rename(dst)

    new_p.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        src = old_p if suffix == "" else old_p.with_name(old_p.name + suffix)
        dst = new_p if suffix == "" else new_p.with_name(new_p.name + suffix)
        _move(src, dst)

    # Keep the in-DB engagement name consistent with the new filename stem.
    EngagementStore(new_p).set_engagement_name(new_p.stem)


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
    criticality     TEXT NOT NULL DEFAULT 'medium',  -- low | medium | high | crown_jewel
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


# Vuln types that are a property of a whole host/domain, not a single URL
# path. A server sends (or fails to send) a security header the same way on
# every page; TLS config and request-smuggling behaviour belong to the
# host:port pair; SPF/DMARC belong to the domain. Reporting "CSP missing"
# once per crawled page is noise — a real pentester reports it once per host.
# These dedup on host, ignoring the path/param/endpoint.
HOST_LEVEL_VULN_TYPES = frozenset({
    # missing / weak HTTP security headers (server-wide)
    "csp_missing", "missing_csp", "clickjacking_no_xfo", "x_frame_options_missing",
    "hsts_missing", "missing_hsts", "x_content_type_missing", "missing_security_headers",
    "referrer_policy_missing", "permissions_policy_missing", "cors_misconfig",
    "cookie_security", "insecure_cookie",
    # TLS / certificate (property of host:port)
    "weak_cipher", "ssl_weak", "weak_tls", "tls_version", "ssl_expired",
    "ssl_self_signed", "sslv3_enabled", "heartbleed", "ssl_misconfiguration",
    # request smuggling (front-end/back-end pair — host level)
    "request_smuggling", "http_smuggling", "http_smuggling_indicator",
    # email / DNS posture (domain level)
    "spf_analysis", "spf_missing", "spf_weak", "dmarc_missing", "dmarc_weak",
    "dkim_missing", "dkim_weak", "dns_misconfig",
    # server-wide config disclosure
    "dangerous_http_method", "directory_listing", "server_banner",
    "version_disclosure",
})

# Substring signals for host/domain-level posture findings. The exact vuln_type
# strings drift between scanners ("no_x_content_type" vs "x_content_type_missing"
# vs "missing_x_content_type"), so an exact-set match alone silently lets the
# same site-wide issue multiply once-per-URL. Matching these substrings collapses
# every spelling to one finding per host. Per-endpoint bug classes (xss, sqli,
# idor, csrf, lfi, ssrf, rce, open_redirect…) deliberately contain none of them.
_HOST_LEVEL_SUBSTRINGS = (
    "header", "hsts", "csp", "clickjacking", "x_frame", "x_content_type",
    "referrer_policy", "permissions_policy", "cors",
    "ssl", "_tls", "tls_", "cipher", "forward_secrecy", "heartbleed", "certificate",
    "smuggling", "spf", "dmarc", "dkim", "dnssec", "dns_",
    "version_disclosure", "server_version", "server_banner", "directory_listing",
    "xml_accepted", "rate_limit",
)


def _host_key(target: str) -> str:
    """
    Reduce a target to ``scheme://host[:port]`` (or bare ``host[:port]``).

    Drops path + query so site-wide findings collapse to one host.
    """
    t = (target or "").strip()
    if "://" in t:
        try:
            from urllib.parse import urlparse
            p = urlparse(t)
            host = (p.hostname or "").lower()
            if p.port:
                host = f"{host}:{p.port}"
            scheme = (p.scheme or "https").lower()
            if host:
                return f"{scheme}://{host}"
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
    # bare host / host:port / host/path
    return t.split("/")[0].lower()


def scan_display_name(targets, mode: str = "") -> str:
    """A human, target-based name for a scan, e.g. ``app.example.com`` or
    ``app.example.com +2`` for several targets.

    Used so the scan shows up identifiably by *what it assessed* — in the Scans
    list, the dashboard, and downloaded reports — instead of a bare id or a
    generic "HEAVEN Scan". ``targets`` is any iterable of raw target strings
    (URLs, IPs, hosts, CIDRs); ``mode`` is only used as a fallback label when no
    targets are given.
    """
    raw = [str(t).strip() for t in (targets or []) if str(t).strip()]

    def _host(t: str) -> str:
        # For a URL, drop scheme + path so we keep just the host. For a bare
        # host / IP / CIDR, keep it verbatim (don't strip a CIDR's "/24").
        if "://" in t:
            return t.split("://", 1)[-1].split("/", 1)[0] or t
        return t
    if not raw:
        return f"{mode} scan".strip() if mode else "scan"
    head = _host(raw[0])
    extra = len(raw) - 1
    return f"{head} +{extra}" if extra > 0 else head


def is_host_level(vuln_type: str) -> bool:
    """True when a vuln type dedups per host rather than per URL.

    Matches the explicit set OR any host-level substring signal, so spelling
    drift between scanners can't cause a site-wide finding to multiply per URL.
    """
    vt = (vuln_type or "").strip().lower()
    if vt in HOST_LEVEL_VULN_TYPES:
        return True
    return any(s in vt for s in _HOST_LEVEL_SUBSTRINGS)


def _strip_query(url: str) -> str:
    """Drop the query string + fragment so payload-varying URLs collapse to one
    canonical endpoint. Critical for injection findings: `?id=1`, `?id=1' OR 1=1`
    and `?id=1 AND sleep(5)` are the SAME vulnerability (one injectable param),
    not 188 separate findings — the differing payload lives in the query string."""
    return url.split("?", 1)[0].split("#", 1)[0]


def _finding_hash(target: str, vuln_type: str, param: str = "",
                  endpoint: str = "", cve: str = "", port: str = "") -> str:
    """
    Stable hash that identifies a finding across re-scans.

    Two scans of the same SQLi on the same parameter and endpoint produce
    identical hashes — they dedup, not duplicate. Host-level vuln types
    (missing headers, TLS, smuggling, SPF/DMARC) dedup per host, ignoring the
    URL path, so "CSP missing" reports once per host instead of once per
    crawled page. For path-level vulns the query string is stripped from the
    identity so the same injectable parameter probed with N payloads collapses
    to a single finding (the parameter, not the payload, is the vulnerability).

    CVE-bearing service/component findings are identified by ``(host, port,
    CVE)``. Without the CVE in the key every CVE on one host shares the same
    identity (``target=host``, ``vuln_type=vulnerable_service``, no
    endpoint/param), so N distinct CVEs collapse into a single finding and all
    but the first silently vanish — with a *non-deterministic* surviving
    ``cve_id`` that decoupled the persisted severity/title from the real
    finding. Only a real ``CVE-…`` id discriminates; ``HEAVEN-HEURISTIC`` and
    empty values fall through to the normal path.
    """
    vt = (vuln_type or "").strip().lower()
    cve_norm = (cve or "").strip().upper()
    if cve_norm.startswith("CVE-"):
        host = _host_key(target)
        p = str(port or "").strip()
        key = f"{host}|{p}|{cve_norm}"
    elif is_host_level(vt):
        key = f"{_host_key(target)}|{vt}"
    else:
        base = _strip_query(target).lower()
        ep = _strip_query(endpoint).lower()
        key = f"{base}|{vt}|{ep}|{param.lower()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _finding_identity(f: dict) -> tuple[str, str, str, str, str, str]:
    """Pull (target, vuln_type, param, endpoint, cve, port) out of a finding.

    ``cve``/``port`` feed :func:`_finding_hash` so distinct CVEs on one host do
    not collapse into a single row. ``cve`` is normalised the same way it is
    persisted (via :func:`_cve_id_of`, which accepts either ``cve`` or
    ``cve_id``)."""
    target = f.get("target", "") or f.get("target_url", "") or f.get("host", "")
    vuln_type = f.get("vuln_type", "") or f.get("type", "") or "unknown"
    param = f.get("param", "") or ""
    endpoint = f.get("endpoint", "") or f.get("url", "") or ""
    cve = _cve_id_of(f)
    port = str(f.get("port", "") or "")
    return str(target), str(vuln_type), str(param), str(endpoint), cve, port


def _risk_value(finding: dict) -> float:
    """Headline risk for the DB ``risk_score`` column.

    The ML scoring phase annotates findings with ``predicted_cvss_score`` /
    ``priority_score`` — **not** ``risk_score`` — so persisting only
    ``finding.get("risk_score")`` left the column at 0 for every finding and the
    web dashboard's risk display (avg + per-finding) was always zero even though
    the CLI/JSON report showed the real CVSS. Fall back through the ML fields.
    """
    for key in ("risk_score", "predicted_cvss_score", "priority_score"):
        v = finding.get(key)
        try:
            if v is not None and float(v) > 0:
                return round(float(v), 1)
        except (TypeError, ValueError):
            continue
    return 0.0


def _cve_id_of(finding: dict) -> str:
    """CVE id for the ``cve_id`` column.

    Detectors are inconsistent about the key: auth/ssl/web_fuzzer/misconfig/sast
    set ``cve_id`` while cve_mapper/anomaly_probe/exploitdb/nuclei set ``cve``.
    Reading only ``cve_id`` (the old behaviour) silently dropped the CVE for the
    latter group, leaving the report/UI "CVE" column blank. Prefer a real
    CVE-prefixed value from either key; ignore non-CVE sentinels like
    ``HEAVEN-HEURISTIC`` but keep any explicit ``cve_id`` for back-compat.
    """
    for key in ("cve_id", "cve"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip().upper().startswith("CVE-"):
            return v.strip().upper()
    v = finding.get("cve_id")
    return v.strip() if isinstance(v, str) and v.strip() else ""


def _confidence_bucket(conf: float) -> str:
    """Human-readable confidence tier for a persisted finding.

    Mirrors the thresholds of :func:`heaven.vulnscan.fp_suppress._bucket_for`
    (so buckets are consistent whether or not a finding passed through FP
    review) but floors at ``tentative`` — a *persisted* finding is never
    ``discarded``. Only the FP-review path sets ``confidence_bucket`` on the
    finding dict, so deriving it here keeps the web UI / reports from showing a
    blank bucket for everything else.
    """
    if conf >= 0.95:
        return "strong"
    if conf >= 0.80:
        return "high"
    if conf >= 0.60:
        return "medium"
    if conf >= 0.40:
        return "low"
    return "tentative"


def _is_junk_finding(f: dict) -> bool:
    """True for reportless noise: a finding carrying no usable type, no
    evidence, and no confidence signal — e.g. a stray log line or docstring that
    leaked into a scanner's output (seen live: a Python ``http.cookies.Morsel``
    deprecation string surfacing as a finding). Deliberately conservative — a
    genuine finding always has at least one of the three — so it never drops a
    real result.
    """
    vt = (f.get("vuln_type") or f.get("type") or "").strip().lower()
    target = (f.get("target") or f.get("target_url") or f.get("host") or "").strip()
    # A CVE finding that names no host/target points a vulnerability at nothing —
    # you can't say what to patch. Drop it even though it carries a CVE and a
    # confidence (seen live: a stray CVE-2020-29396 with an empty target and
    # vuln_type 'unknown', which otherwise persisted as a bogus high-severity row).
    if _cve_id_of(f) and not target:
        return True
    if vt and vt != "unknown":
        return False
    if f.get("evidence"):
        return False
    conf = f.get("confidence")
    try:
        return not (conf is not None and float(conf) > 0)
    except (TypeError, ValueError):
        return True


def _is_fp_reviewed(f: dict) -> bool:
    """True when a finding carries an FP-suppression verdict — it went through the
    validator / FP-review layer, so its confidence is the *adjudicated* value and
    should win over a raw candidate's un-reviewed (usually higher) number."""
    return bool(f.get("fp_check_reasons")) or "confidence_bucket" in f \
        or "signal_count" in f


def _richer_finding(a: dict, b: dict) -> dict:
    """
    When two findings dedup to the same identity, keep the one carrying more
    signal: an FP-reviewed verdict is authoritative and wins outright; otherwise
    higher confidence wins; ties break toward the larger evidence blob (a
    validated/scored finding is richer than a raw candidate).
    """
    a_rev, b_rev = _is_fp_reviewed(a), _is_fp_reviewed(b)
    if a_rev != b_rev:
        # The adjudicated copy wins even if the raw candidate's number is higher,
        # so a suppressor's confidence *downgrade* is not silently reverted.
        return a if a_rev else b
    ca = float(a.get("confidence", 0.0) or 0.0)
    cb = float(b.get("confidence", 0.0) or 0.0)
    if cb > ca:
        return b
    if ca > cb:
        return a
    return b if len(str(b.get("evidence", ""))) >= len(str(a.get("evidence", ""))) else a


def dedup_findings(findings: list) -> list:
    """
    Collapse findings that refer to the same vulnerability.

    One vuln flows through the pipeline as a candidate, then a validated
    finding, then a scored finding — and a single scanner emits it under both
    the ``findings`` and ``vulnerabilities`` keys. Summing all of those
    double-counts. This collapses them to one entry per stable identity (the
    same key :func:`_finding_hash` uses), keeping the richest copy, and
    normalises host-level targets so the UI shows one row per host.
    """
    best: dict[str, dict] = {}
    order: list[str] = []
    suppressed_keys: set[str] = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        if _is_junk_finding(f):
            continue
        target, vuln_type, param, endpoint, cve, port = _finding_identity(f)
        key = _finding_hash(target, vuln_type, param, endpoint, cve, port)
        # A finding the FP layer adjudicated as a false positive taints its whole
        # identity: drop every copy — including any raw candidate for the same
        # vuln that slipped through unmarked — so a rejected finding never reaches
        # the report, engagement store or UI. This is what makes the suppression
        # layer's verdicts actually take effect on the user-facing output.
        if f.get("suppressed") is True or f.get("result") == "false_positive":
            suppressed_keys.add(key)
            continue
        if key not in best:
            best[key] = dict(f)
            order.append(key)
        else:
            best[key] = _richer_finding(best[key], dict(f))
        if is_host_level(vuln_type):
            best[key]["target"] = _host_key(target)
    return [best[k] for k in order if k not in suppressed_keys]


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
    criticality: str = "medium"  # low / medium / high / crown_jewel
    notes: str = ""
    added_at: str = ""
    id: Optional[int] = None


# Risk-score multipliers per asset criticality. Used to bias scan
# prioritisation and report ordering — a critical SQLi on a "crown_jewel"
# asset outranks the same finding on a "low"-criticality dev box.
CRITICALITY_MULTIPLIER = {
    "low":          0.7,
    "medium":       1.0,
    "high":         1.3,
    "crown_jewel":  1.5,
}


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

    def __init__(self, db_path: Path | str, *, create: bool = True):
        self.db_path = Path(db_path)
        self._create = create
        # create=True (the default) materialises the DB immediately so writers
        # can persist. create=False opens the store read-only: if the file does
        # not exist yet it is NOT created — reads are served from an ephemeral
        # in-memory schema instead (see _conn). This stops a page-load that only
        # *reads* the fallback "default" engagement from leaving an empty
        # default.db behind, which used to haunt the dashboard switcher as a
        # "default — empty" row the user could never get rid of.
        if create:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # Read-only view of a not-yet-scanned engagement: serve an ephemeral
        # in-memory schema so reads return empty results without materialising
        # an empty file on disk. Writers always use create=True, so this branch
        # is never taken for a write.
        if not self._create and not self.db_path.exists():
            mem = sqlite3.connect(":memory:")
            mem.row_factory = sqlite3.Row
            mem.executescript(SCHEMA)
            try:
                yield mem
            finally:
                mem.close()
            return
        # timeout=30 + WAL: the API flushes findings on every scan-progress
        # callback while record_scan_complete writes concurrently. Without
        # these, concurrent writers hit "database is locked" and findings
        # are lost. WAL allows a reader + writer without blocking.
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
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
        """Return this store's engagement, deterministically.

        A single DB file can end up holding more than one ``engagement`` row —
        e.g. the demo seeder once wrote ``demo (sample data)`` into a real
        engagement's DB. A bare ``LIMIT 1`` with no ordering then returned an
        arbitrary row (often the stale demo one), so the dashboard label and the
        downloaded report filename showed "demo" for a genuine scan.

        Resolve it against the DB's own filename, which *is* the canonical
        engagement name (``engagements/<name>.db``): prefer the row whose name
        matches that stem, then the most-recently-updated row, then any row.
        """
        stem = self.db_path.stem
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM engagement WHERE name = ? LIMIT 1", (stem,)
            ).fetchone()
            if row is None:
                row = c.execute(
                    "SELECT * FROM engagement ORDER BY updated_at DESC, id DESC LIMIT 1"
                ).fetchone()
            return Engagement(**dict(row)) if row else None

    def set_engagement_name(self, new_name: str) -> None:
        """Rename this store's engagement row to ``new_name``.

        The canonical name is the DB filename stem and ``get_engagement``
        resolves the row by that stem, so after the DB file is renamed the in-DB
        ``engagement.name`` must be rewritten to match or the label falls back to
        a stale row. Updates the row ``get_engagement`` would pick (the
        most-recently-updated one), leaves any other rows untouched, and is
        constraint-safe if a row already carries the target name.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM engagement ORDER BY updated_at DESC, id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO engagement (name, client, statement_of_work, "
                    "created_at, updated_at) VALUES (?, '', '', ?, ?)",
                    (new_name, now, now),
                )
                return
            clash = c.execute(
                "SELECT id FROM engagement WHERE name = ? AND id != ?",
                (new_name, row["id"]),
            ).fetchone()
            if clash is not None:
                # Another row already holds the target name (the column is
                # UNIQUE). The rename target file did not exist, so this is an
                # internal duplicate — leave it rather than violate the constraint.
                return
            c.execute(
                "UPDATE engagement SET name = ?, updated_at = ? WHERE id = ?",
                (new_name, now, row["id"]),
            )

    # ── Scope ──────────────────────────────────────────────────────────
    def add_scope(self, target: str, kind: str = "host", in_scope: bool = True,
                  notes: str = "", criticality: str = "medium") -> None:
        if criticality not in CRITICALITY_MULTIPLIER:
            raise ValueError(
                f"criticality must be one of {sorted(CRITICALITY_MULTIPLIER)}, "
                f"got {criticality!r}"
            )
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            # Migration-safe insert: try the 6-column form; if criticality
            # doesn't exist (older engagement DB) add it and retry.
            try:
                c.execute(
                    "INSERT OR REPLACE INTO scope "
                    "(target, kind, in_scope, criticality, notes, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (target, kind, 1 if in_scope else 0, criticality, notes, now),
                )
            except sqlite3.OperationalError:
                c.execute(
                    "ALTER TABLE scope ADD COLUMN criticality TEXT NOT NULL "
                    "DEFAULT 'medium'"
                )
                c.execute(
                    "INSERT OR REPLACE INTO scope "
                    "(target, kind, in_scope, criticality, notes, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (target, kind, 1 if in_scope else 0, criticality, notes, now),
                )

    def purge_demo_artifacts(self) -> int:
        """Strip leftover sample-data rows from a *real* engagement DB.

        The demo seeder used to write into whatever engagement was active,
        leaving behind a ``demo (sample data)`` engagement row and scope targets
        in the reserved demo ranges. Even after the operator deleted the demo
        findings, those rows persisted and leaked "demo" into the dashboard
        label / report filename. This removes exactly those artifacts (and
        nothing else — real findings and scope are never touched). Returns the
        number of rows removed. Safe/no-op on a clean or demo DB.
        """
        demo_engagement_name = "demo (sample data)"
        demo_scope = (
            "https://demo.heaven.local", "demo.heaven.local",
            "10.10.10.10/32", "10.10.10.0/24",
        )
        removed = 0
        with self._conn() as c:
            removed += c.execute(
                "DELETE FROM engagement WHERE name = ?", (demo_engagement_name,)
            ).rowcount
            for t in demo_scope:
                removed += c.execute(
                    "DELETE FROM scope WHERE target = ?", (t,)
                ).rowcount
        if removed:
            logger.info("Purged %d leftover demo artifact(s) from %s",
                        removed, self.db_path.name)
        return removed

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
            entries: list[ScopeEntry] = []
            for r in rows:
                row_dict = dict(r)
                entries.append(ScopeEntry(
                    id=row_dict.get("id"),
                    target=row_dict["target"],
                    kind=row_dict["kind"],
                    in_scope=bool(row_dict.get("in_scope", 1)),
                    criticality=row_dict.get("criticality") or "medium",
                    notes=row_dict.get("notes") or "",
                    added_at=row_dict.get("added_at") or "",
                ))
            return entries

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is explicitly authorized in this engagement."""
        with self._conn() as c:
            row = c.execute(
                "SELECT in_scope FROM scope WHERE target = ?", (target,)
            ).fetchone()
            return bool(row and row["in_scope"])

    def criticality_for_target(self, target: str) -> str:
        """Look up the criticality tag for a target. Returns 'medium' (the
        neutral multiplier) when the target isn't in scope or the column
        doesn't exist on older DBs.

        Matches exact target first, then prefix (so a finding at
        https://app.example.com/login inherits the 'crown_jewel' tag of
        https://app.example.com)."""
        with self._conn() as c:
            try:
                row = c.execute(
                    "SELECT criticality FROM scope "
                    "WHERE target = ? OR ? LIKE target || '%' "
                    "ORDER BY length(target) DESC LIMIT 1",
                    (target, target),
                ).fetchone()
                if row and row["criticality"]:
                    return str(row["criticality"])
            except sqlite3.OperationalError:
                pass
        return "medium"

    def criticality_multiplier(self, target: str) -> float:
        """Return the risk-score multiplier (0.7 / 1.0 / 1.3 / 1.5) for a target."""
        return CRITICALITY_MULTIPLIER.get(
            self.criticality_for_target(target), 1.0,
        )

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

    def prune_scan_findings(self, scan_id: str, keep_ids) -> int:
        """Delete this scan's findings whose id is not in ``keep_ids``.

        Reconciles the store to a scan's FINAL authoritative finding set after a
        live progress flush persisted intermediate candidates that the final
        dedup / FP-suppression later dropped. Only rows whose ``scan_id`` matches
        are considered, so findings owned by other scans are never touched.
        Returns the number of rows removed.
        """
        keep = {str(k) for k in (keep_ids or ())}
        with self._conn() as c:
            rows = c.execute(
                "SELECT id FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
            stale = [r[0] for r in rows if r[0] not in keep]
            for fid in stale:
                c.execute("DELETE FROM findings WHERE id = ?", (fid,))
            return len(stale)

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and everything it produced (findings + checkpoints).

        Returns True if the scan row (or any of its findings) existed. Used by
        the API's "remove scan" action so an operator can prune runs from the
        engagement without hand-editing the SQLite file.
        """
        with self._conn() as c:
            existed = c.execute(
                "SELECT 1 FROM scans WHERE id = ? "
                "UNION SELECT 1 FROM findings WHERE scan_id = ? LIMIT 1",
                (scan_id, scan_id),
            ).fetchone()
            c.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            c.execute("DELETE FROM scan_checkpoints WHERE scan_id = ?", (scan_id,))
            c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return existed is not None

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Fetch a single scan row (with its deduped finding count), or None."""
        with self._conn() as c:
            row = c.execute(
                "SELECT *, "
                "(SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) "
                "AS findings_count "
                "FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            return dict(row) if row else None

    def list_scans(self, limit: int = 50) -> list[dict]:
        """List scans, each annotated with its deduped finding count."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT *, "
                "(SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) "
                "AS findings_count "
                "FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
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
        cve = _cve_id_of(finding)
        port = str(finding.get("port", "") or "")
        # Always derive the id from content. A scanner-supplied "id" is not a
        # stable cross-scan identifier and would defeat dedup — the content
        # hash IS the canonical id. The CVE + port are part of the identity so
        # distinct CVEs on the same host each get their own row instead of
        # collapsing into one (with a non-deterministic surviving cve_id).
        fid = _finding_hash(target, vuln_type, param, endpoint, cve, port)
        # Host-level findings (missing headers, TLS, smuggling, SPF/DMARC)
        # store the host as the target so the UI shows one row per host, not
        # one per crawled path.
        if is_host_level(vuln_type):
            target = _host_key(target)

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
            # Preserve the ML scoring detail so the web FindingDetail can show it
            # (the column only holds the headline score).
            for mlk in ("predicted_cvss_score", "priority_score", "risk_band",
                        "epss", "in_kev"):
                if mlk not in evidence and finding.get(mlk) is not None:
                    evidence[mlk] = finding[mlk]
            # Preserve the component-identity fields (product / version / CWE /
            # exploit availability) so per-CVE remediation and the finding detail
            # can be reconstructed after the DB round-trip — the columns don't
            # hold these, so without this they'd be lost.
            for ck in ("product", "version", "cwe", "exploit_available"):
                if ck not in evidence and finding.get(ck):
                    evidence[ck] = finding[ck]
            evidence_json = json.dumps(evidence)
            risk_score = _risk_value(finding)
            confidence = float(finding.get("confidence", 0.0) or 0.0)
            confidence_bucket = (
                finding.get("confidence_bucket") or _confidence_bucket(confidence)
            )

            if existing:
                # Dedup — refresh last_seen_at + seen_count + the (re-computed) risk
                # score, but preserve human-set fields (status, notes).
                c.execute(
                    "UPDATE findings SET last_seen_at = ?, seen_count = seen_count + 1, "
                    "scan_id = ?, evidence_json = ?, risk_score = ? "
                    "WHERE id = ?",
                    (now, scan_id, evidence_json, risk_score, fid),
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
                        confidence,
                        confidence_bucket,
                        _cve_id_of(finding),
                        risk_score,
                        now, now,
                        evidence_json,
                    ),
                )
        return fid

    def count_findings(self, scan_id: Optional[str] = None) -> int:
        """
        Number of distinct (deduped) findings in the store.

        Scoped to one scan when *scan_id* is given. This is the authoritative
        finding count — the scan list, kill chain and engagement view all read
        it so they never disagree.
        """
        with self._conn() as c:
            if scan_id:
                row = c.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()
            else:
                row = c.execute("SELECT COUNT(*) FROM findings").fetchone()
            return int(row[0]) if row else 0

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
        scan_id: Optional[str] = None,
    ) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        if scan_id:
            sql += " AND scan_id = ?"
            args.append(scan_id)
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        if status:
            sql += " AND status = ?"
            args.append(status)
        if target:
            sql += " AND target LIKE ?"
            args.append(f"%{target}%")
        if vuln_type:
            sql += " AND vuln_type = ?"
            args.append(vuln_type)
        if min_confidence > 0:
            sql += " AND confidence >= ?"
            args.append(min_confidence)
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

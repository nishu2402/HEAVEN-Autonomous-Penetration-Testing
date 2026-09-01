"""
HEAVEN — FastAPI Application & REST API
Central API server with WebSocket support, JWT/API-key auth, and RBAC.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import sys
import time
import uuid
import json
import glob
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, cast

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Depends, Header, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response
    from pydantic import BaseModel, Field
    from contextlib import asynccontextmanager
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    BaseModel = object  # type: ignore[assignment,misc]

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    HAS_SLOWAPI = True
except ImportError:
    HAS_SLOWAPI = False

from heaven import __version__
from heaven.security.auth import get_auth_manager, Role, User
from heaven.utils.logger import get_logger

logger = get_logger("api")


def _safe_unlink(path: str) -> None:
    """Best-effort delete of a temp file once a FileResponse has been streamed."""
    try:
        os.unlink(path)
    except OSError:
        pass


# URL regex — single-escaped (was double-escaped, broken)
_URL_REGEX = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)


# ── Pydantic Request/Response Models ──

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int
    user: dict
    # True when the account is still on the seeded default (admin/admin) and the
    # UI must force a password change before proceeding.
    must_change_password: bool = False


# Scan modes that get their OWN dedicated result section in the web UI (the
# SAST and SCA pages). They are kept OUT of the general "Scan Activity" list so
# a code-analysis run shows up exactly once — in its own section — instead of
# being merged in with the pentest scans. `/api/scans?kind=<mode>` returns just
# that section; the default `kind=pentest` returns everything except these.
CODE_ANALYSIS_MODES = frozenset({"sast", "sca"})


def _scan_mode_of(scan: dict) -> str:
    """The scan's mode/type, however it happens to be recorded (top-level
    ``mode`` on a persisted row, or ``mode``/``scan_type`` inside an in-memory
    scan's config)."""
    cfg = scan.get("config") or {}
    return str(
        scan.get("mode") or cfg.get("mode") or cfg.get("scan_type") or ""
    ).lower()


# Web launcher exposes stealth as an int 1-4; the evasion engine speaks names.
_STEALTH_INT_TO_NAME = {1: "paranoid", 2: "stealth", 3: "normal", 4: "aggressive"}


def _resolve_stealth_name(level: object) -> str:
    """Map a web-launcher stealth level (int 1-4, or an already-resolved name)
    to its evasion-profile name. Unknown values fall back to ``normal`` so a
    scan is never accidentally silent or maximally loud."""
    if isinstance(level, str):
        name = level.strip().lower()
        return name if name in _STEALTH_INT_TO_NAME.values() else "normal"
    if isinstance(level, int):
        return _STEALTH_INT_TO_NAME.get(level, "normal")
    return "normal"


class ScanRequest(BaseModel):
    name: str = "HEAVEN Scan"
    targets: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    repositories: list[str] = Field(default_factory=list)
    cloud_providers: list[str] = Field(default_factory=list)
    # Full 65 535-port sweep by default so the web/API path matches `heaven scan`
    # (CLI default) and a plain `nmap -p-` — the launcher exposes a Port scope
    # control to narrow this to a fast common-ports run when speed matters.
    ports: str = "1-65535"
    scan_type: str = "full"
    mode: str = "full"
    stealth_level: int = 3
    engagement: Optional[str] = None
    i_have_authorization: bool = False
    # ── Authenticated scanning (optional) — the target credentials HEAVEN uses
    # to reach pages behind a login. Mirrors the CLI's --cookie-file/--auth and
    # --low-priv-* flags so the web path can run authenticated crawls, IDOR and
    # the multi-role Broken Access Control audit. `cookie` is a raw Cookie header
    # ("k=v; k2=v2"); `auth` is a form-login spec ("url=/login,user=a,pass=b").
    # The low-priv pair supplies a second, deliberately lower-privilege identity
    # that lets the access-control audit prove authorization is not enforced.
    cookie: str = ""
    auth: str = ""
    low_priv_cookie: str = ""
    low_priv_auth: str = ""
    # Firewall/IDS evasion for authorized testing. When true, nmap evasion
    # (fragmentation / padding / trusted source port / decoys) is applied to
    # every host. Off by default — HEAVEN still auto-detects a filtering
    # perimeter and runs a bounded evasion re-probe of the affected hosts.
    evade: bool = False
    # Active exploitation of discovered services (confirm RCE via the real
    # exploit path with a benign proof command). Implied when mode == "exploit".
    # Authorization-gated (requires i_have_authorization); never runs implicitly.
    active_exploit: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingStatusUpdate(BaseModel):
    status: str
    notes: str = ""


class FindingNotesUpdate(BaseModel):
    notes: str = ""


class ManualFindingRequest(BaseModel):
    target: str
    vuln_type: str
    title: str
    severity: str
    confidence: float = 0.9
    evidence: dict = {}
    notes: str = ""


class DashboardData(BaseModel):
    total_scans: int = 0
    total_assets: int = 0
    total_vulns: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    confirmed: int = 0
    secrets: int = 0
    avg_risk: float = 0.0
    recent_scans: list[dict] = Field(default_factory=list)
    top_vulns: list[dict] = Field(default_factory=list)
    severity_trend: list[dict] = Field(default_factory=list)
    assets: list[dict] = Field(default_factory=list)
    # Confirmation split — Overall Risk is rated from *confirmed* findings so an
    # unauthenticated, version-based match never inflates the headline.
    overall_risk: str = "Informational"
    confirmed_total: int = 0
    potential_total: int = 0
    confirmed_critical: int = 0
    confirmed_high: int = 0
    confirmed_medium: int = 0
    confirmed_low: int = 0


def _confirmation_of(finding: Any) -> str:
    """Canonical confirmation label — 'Confirmed' or 'Potential' — for a finding
    dict or ORM object. Single source of truth in ``heaven.utils.cvss``."""
    from heaven.utils.cvss import is_confirmed_finding
    d = finding if isinstance(finding, dict) else getattr(finding, "__dict__", {})
    return "Confirmed" if is_confirmed_finding(d) else "Potential"


def _overall_risk_from(sev_counts: dict[str, int]) -> str:
    """Highest severity band present, as a title-case label (matches the report
    generator's ``_overall_risk``)."""
    for band, label in (("critical", "Critical"), ("high", "High"),
                        ("medium", "Medium"), ("low", "Low")):
        if sev_counts.get(band):
            return label
    return "Informational"


# ── Active scan tracking ──
active_scans: dict[str, Any] = {}
ws_connections: list = []
log_ws_connections: list = []
# Strong references to background scan tasks. Kept OUT of active_scans because
# that dict is JSON-serialised by the API — an asyncio.Task is not serialisable.
_background_scan_tasks: set = set()
# scan_id → its running asyncio.Task, so "Cancel" can actually stop the work
# (previously it only relabelled the in-memory dict while the scan ran on).
_scan_tasks_by_id: dict[str, "asyncio.Task"] = {}

# ── Autonomous-loop jobs ──
# The autonomous loop can run for minutes. Running it inline in the request
# handler blocked the HTTP response for the whole run and made the UI lose all
# state the moment the operator navigated away. Instead we launch each run as a
# detached background task, return a job_id immediately, and let the UI poll
# GET /api/autonomous/jobs/{job_id}. Mirrors the active_scans pattern.
# For *live* progress the UI can also subscribe to a WebSocket
# (/api/autonomous/jobs/{id}/stream); each subscriber gets its own asyncio.Queue
# registered here, and each completed iteration is fanned out to all of them.
autonomous_jobs: dict[str, dict] = {}
_autonomous_tasks: set = set()
_autonomous_subscribers: dict[str, set] = {}  # job_id -> set[asyncio.Queue]


def _autonomous_broadcast(job_id: str, message: dict) -> None:
    """Push a message to every live WebSocket subscriber of an autonomous job.
    Safe to call from the loop thread — uses put_nowait and swallows errors."""
    for q in list(_autonomous_subscribers.get(job_id, set())):
        try:
            q.put_nowait(message)
        except Exception:  # noqa: BLE001 — a full/closed queue must not break the run
            logger.debug("suppressed non-fatal exception", exc_info=True)


# ── Watch-mode jobs ──
# `heaven watch` is a continuous monitoring loop (scan → diff → alert-on-change).
# Like the autonomous loop it can run for a long time, so the web launcher runs
# it as a DETACHED background task with a bounded iteration count, streams each
# iteration over a WebSocket, and supports Stop (task cancellation — run_watch
# treats CancelledError as a clean operator interrupt and returns its summary).
watch_jobs: dict[str, dict] = {}
_watch_tasks: dict[str, Any] = {}                 # job_id -> asyncio.Task (for Stop)
_watch_subscribers: dict[str, set] = {}           # job_id -> set[asyncio.Queue]

# ── Self-update (web app "Update now") ──────────────────────────────────────
# A single code-update runs at a time; this holds its live state so the UI can
# poll a progress log. Only ever mutated by the one background apply task.
_update_apply_state: dict[str, Any] = {
    "running": False, "done": False, "ok": False,
    "log": [], "result": None, "job_id": None, "started_at": None,
}
# Strong reference to the in-flight apply task. asyncio only holds a weak ref to
# a fire-and-forget create_task(), so under GC pressure the task can be collected
# mid-flight — it then receives CancelledError (a BaseException the worker's
# `except Exception` won't catch) and the run ends with done=True but ok=False.
# Holding the reference until the task completes prevents that.
_update_apply_tasks: set = set()


def _web_update_apply_enabled() -> bool:
    """Is applying a code update *from the browser* permitted on this server?

    Detection (checking whether a newer HEAVEN exists) is always available, but
    *applying* it means a git fast-forward + reinstall/rebuild — i.e. running new
    code — triggered over HTTP. That's a powerful action to expose in a shared or
    hosted deployment, so it's gated by a deploy-time kill switch:
    ``HEAVEN_DISABLE_WEB_UPDATE=1`` turns web-apply OFF (the CLI ``heaven update``
    still works). It is read from the process environment at request time and is
    deliberately NOT a web-editable setting, so a browser session can't grant
    itself the capability — the operator must set it before launching, exactly
    like the ``HEAVEN_ALLOW_LOCALHOST`` hosted-lockdown vars. Default: enabled
    (single-operator local install — the common case the user asked for).
    """
    v = (os.environ.get("HEAVEN_DISABLE_WEB_UPDATE") or "").strip().lower()
    return v not in ("1", "true", "yes", "on")


def _watch_broadcast(job_id: str, message: dict) -> None:
    """Fan a message out to every live WebSocket subscriber of a watch job."""
    for q in list(_watch_subscribers.get(job_id, set())):
        try:
            q.put_nowait(message)
        except Exception:  # noqa: BLE001 — a full/closed queue must not break the run
            logger.debug("suppressed non-fatal exception", exc_info=True)


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list] = {}

    async def connect(self, scan_id: str, ws):
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws):
        if scan_id in self._connections:
            try:
                self._connections[scan_id].remove(ws)
            except ValueError:
                pass

    async def broadcast(self, scan_id: str, msg: dict):
        dead = []
        for ws in self._connections.get(scan_id, []):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


ws_manager = ConnectionManager()


class WebSocketLogHandler(logging.Handler):
    """Broadcast log records to connected WebSockets.

    Log records may be emitted from the event-loop thread (API requests) or
    from worker threads (sync scan tasks). We cache the loop on first sight
    and use run_coroutine_threadsafe for cross-thread emits so log frames
    from background scans still reach connected clients.
    """

    _loop = None  # type: ignore[var-annotated]

    def emit(self, record):
        msg = self.format(record)
        try:
            loop = asyncio.get_running_loop()
            WebSocketLogHandler._loop = loop
            same_thread = True
        except RuntimeError:
            loop = WebSocketLogHandler._loop
            same_thread = False
        if loop is None:
            return
        for ws in list(log_ws_connections):
            try:
                if same_thread:
                    loop.create_task(ws.send_text(msg))
                else:
                    asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
            except Exception:
                # Drop dead WebSockets silently
                if ws in log_ws_connections:
                    try:
                        log_ws_connections.remove(ws)
                    except ValueError:
                        # Deliberately silent: this runs inside a
                        # logging.Handler.emit(); logging here would re-enter
                        # the logging system.
                        pass


# ── Auth dependency ──
def _auth_disabled() -> bool:
    return os.environ.get("HEAVEN_DISABLE_AUTH", "").lower() in ("1", "true", "yes")


async def require_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> User:
    """FastAPI dependency: extract user from Authorization: Bearer <token> or X-API-Key header."""
    if _auth_disabled():
        # Test/dev mode only — log loudly so it can't be missed in prod
        logger.warning("HEAVEN_DISABLE_AUTH set — request bypassing auth")
        admin = next((u for u in get_auth_manager()._users.values() if u.role == Role.ADMIN), None)
        if admin:
            return admin
        # No admin account exists yet — synthesise one so auth-disabled mode always works
        from heaven.security.auth import User as _User
        return _User(id="ci-admin", username="ci-admin", role=Role.ADMIN)

    auth = get_auth_manager()
    if x_api_key:
        user = auth.authenticate_api_key(x_api_key)
        if user:
            return user
    if authorization and authorization.lower().startswith("bearer "):
        # A header of "Bearer" / "Bearer " with no token splits to a single part —
        # guard the index so a malformed header returns 401, not a 500.
        parts = authorization.split(None, 1)
        token = parts[1].strip() if len(parts) > 1 else ""
        if token:
            session = auth._sessions.get(token)
            if session and session.expires_at > __import__("time").time():
                user = auth._users.get(session.user_id)
                if user and user.is_active:
                    return user
    raise HTTPException(status_code=401, detail="Authentication required")


def require_permission(permission: str):
    """FastAPI dependency factory: require a specific RBAC permission."""
    async def _checker(user: User = Depends(require_user)) -> User:
        if not get_auth_manager().check_permission(user, permission):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return user
    return _checker


# The active-engagement pointer helpers live in heaven.engagement so the CLI,
# the web API and the demo seeder all read/write one file the same way. Re-exported
# under the historical `_`-prefixed names the rest of this module (and tests) use.
from heaven.engagement import (  # noqa: E402, F401
    active_engagement_file as _active_engagement_file,  # re-exported for tests
    best_populated_engagement as _best_populated_engagement,
    clear_active_engagement as _clear_active_engagement,
    dedup_findings as _dedup_findings,
    delete_engagement_store as _delete_engagement_store,
    get_active_engagement as _get_active_engagement,
    rename_engagement_store as _rename_engagement_store,
    set_active_engagement as _set_active_engagement,
)


def _resolve_engagement_name(name: Optional[str] = None) -> str:
    """Single source of truth for 'which engagement is the app looking at'.

    Priority: explicit arg > HEAVEN_ENGAGEMENT env > active-engagement pointer >
    the most-populated real engagement on disk > 'default'. The most-populated
    fallback means that when no pointer is set (e.g. the viewed engagement was
    deleted) a page load lands on the operator's actual work instead of a blank
    'default'. Every reader (dashboard, findings, reports) and the scan writer go
    through this, so they can never disagree about which store holds the data.
    """
    return (name or os.environ.get("HEAVEN_ENGAGEMENT")
            or _get_active_engagement()
            or _best_populated_engagement()
            or "default")


# ── Path-traversal guards for HTTP-supplied identifiers ──
# The engagement name becomes a DB *filename* and the scan id becomes part of a
# report *filename*, so an attacker-controlled value containing path separators,
# "..", or an absolute path could make the server read/write/delete files outside
# the data dir. These validate only values that arrive over HTTP; trusted sources
# (HEAVEN_ENGAGEMENT env, the CLI passing real paths) are intentionally exempt.
_SAFE_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_http_engagement(name: Optional[str]) -> Optional[str]:
    """Reject an engagement name supplied in a request body/query if it could
    escape the engagements directory. Returns the name unchanged when safe;
    ``None`` passes straight through (means 'use the resolver default')."""
    if name is None:
        return None
    raw = str(name)
    if ("/" in raw or "\\" in raw or "\x00" in raw
            or ".." in raw or Path(raw).is_absolute()
            or raw.strip() in ("", ".", "..")):
        raise HTTPException(status_code=400, detail="Invalid engagement name")
    return raw


def _is_safe_scan_id(scan_id: Optional[str]) -> bool:
    """True when a scan id is safe to interpolate into a report filename."""
    return bool(scan_id) and bool(_SAFE_SCAN_ID_RE.match(scan_id or ""))


def _parse_benchmark_metrics(md: str) -> Optional[dict]:
    """Pull headline precision / recall / F1 (as 0–1 floats) out of a report.

    Handles both the single-run table (``| Precision (TP / TP+FP) | 100.0% |``)
    and the aggregated table (``| Precision | 87.4% ± 2.1% |``). For recall the
    first matching row wins, which in the single-run format is the headline
    "required GT only" recall. Returns None when nothing parses.
    """
    def _first_pct(metric_re: str) -> Optional[float]:
        m = re.search(rf"^\|\s*{metric_re}\b[^|]*\|\s*([0-9]+(?:\.[0-9]+)?)\s*%",
                      md, re.MULTILINE)
        return round(float(m.group(1)) / 100.0, 4) if m else None

    precision = _first_pct("Precision")
    recall = _first_pct("Recall")
    f1 = _first_pct("F1")
    if precision is None and recall is None and f1 is None:
        return None
    return {"precision": precision, "recall": recall, "f1": f1}


# The benchmark tiers, in DISPLAY order. Each is (report filename, source slug,
# human label, target slug). The two native tiers (web + api) are always-on and
# regenerated on every test run / re-run; the two live tiers only exist once an
# operator has run them against a real target, so a fresh checkout simply shows
# the native pair. Nothing is fabricated — a tier appears only if its report file
# is present and did not wash out.
_BENCHMARK_TIER_SPECS = [
    ("native_benchmark.md", "native-controlled",
     "Native controlled target — web tier (DVWA-class), Docker-free, always current",
     "heaven-native-vuln-app"),
    ("api_benchmark.md", "native-controlled-api",
     "Native controlled target — API tier (OWASP API Top 10), Docker-free, always current",
     "heaven-native-vuln-app-api"),
    ("dvwa_aggregated.md", "live-dvwa",
     "Live DVWA — Docker, multi-run aggregate (web tier)", "dvwa"),
    ("msf2_aggregated.md", "live-network",
     "Live Metasploitable-2 — network / service tier, multi-run aggregate",
     "metasploitable-2"),
]
# Preference order for the single "primary" tier surfaced at the top level (kept
# for the pre-tiers UI): a valid live run wins, else the always-on native web run.
_BENCHMARK_PRIMARY_PREF = [
    "live-dvwa", "live-network", "native-controlled", "native-controlled-api",
]

# source → (label, target), so a freshly-run native tier can be shaped without
# re-reading its report file off disk.
_BENCHMARK_TIER_META = {
    source: (label, target)
    for _fname, source, label, target in _BENCHMARK_TIER_SPECS
}


def _benchmark_tier_from_markdown(markdown: str, source: str) -> dict:
    """Shape a freshly-run benchmark's markdown into a tier dict (no disk read)."""
    from datetime import datetime, timezone

    label, target = _BENCHMARK_TIER_META.get(source, ("Benchmark", source))
    return {
        "source": source,
        "label": label,
        "target": target,
        "markdown": markdown,
        "metrics": _parse_benchmark_metrics(markdown),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": len(markdown.encode("utf-8")),
    }


def _load_benchmark_report(path: Path, source: str, label: str,
                           target: str) -> Optional[dict]:
    """Read one benchmark report into a tier dict, or None if absent / a washout.

    A washout is a run where the target was unreachable, so precision AND recall
    are both 0% — never surfaced as "the benchmark".
    """
    from datetime import datetime, timezone

    if not path.exists():
        return None
    md = path.read_text(encoding="utf-8")
    metrics = _parse_benchmark_metrics(md)
    if metrics and not metrics.get("precision") and not metrics.get("recall"):
        return None
    stat = path.stat()
    return {
        "source": source,
        "label": label,
        "target": target,
        "markdown": md,
        "metrics": metrics,
        "generated_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "size_bytes": stat.st_size,
    }


def _collect_benchmark_tiers(reports_dir: Path) -> list[dict]:
    """Every available, non-washout benchmark tier, in display order."""
    tiers = []
    for filename, source, label, target in _BENCHMARK_TIER_SPECS:
        tier = _load_benchmark_report(reports_dir / filename, source, label, target)
        if tier is not None:
            tiers.append(tier)
    return tiers


def _benchmark_response(tiers: list[dict]) -> dict:
    """Shape the tiers into the API response: the full list plus the primary
    tier's fields spread at the top level (backward-compatible with the pre-tiers
    single-object UI)."""
    if not tiers:
        return {
            "available": False,
            "tiers": [],
            "note": ("No benchmark results yet. Generate the built-in ones with: "
                     "heaven benchmark --tier all"),
        }
    primary = min(
        tiers,
        key=lambda t: (_BENCHMARK_PRIMARY_PREF.index(t["source"])
                       if t["source"] in _BENCHMARK_PRIMARY_PREF else 99),
    )
    return {"available": True, "tiers": tiers, **primary}


def _engagement_store_factory(name: Optional[str] = None, *, create: bool = True):
    """Resolve engagement store. Falls back to env var, active pointer, then default.

    ``create=True`` (default) materialises the DB on open so writers can persist.
    ``create=False`` opens it read-only and never creates a missing file — use it
    for pure reads (dashboard, findings, reports) so merely viewing a fresh,
    never-scanned install doesn't leave a stray ``default.db`` behind. Prefer the
    ``_read_store`` helper below for that.
    """
    from heaven.config import get_config
    from heaven.engagement import EngagementStore

    data_dir = get_config().data_dir
    path = _resolve_engagement_name(name)
    # A plain name is sandboxed to data_dir/engagements/<name>.db. Anything with a
    # path separator, "..", an absolute path or a suffix would be used as a raw
    # filesystem path — that's only safe when it comes from operator config
    # (HEAVEN_ENGAGEMENT), never from an HTTP request or the active-engagement
    # pointer, so a non-plain value that doesn't match the env var is rejected as
    # a path-traversal attempt. This is the single choke point every reader and
    # the scan writer pass through.
    p = Path(path)
    is_plain = (not p.suffix and not p.is_absolute()
                and "/" not in path and "\\" not in path and ".." not in path)
    if is_plain:
        p = data_dir / "engagements" / f"{path}.db"
    elif path != os.environ.get("HEAVEN_ENGAGEMENT"):
        raise HTTPException(status_code=400, detail="Invalid engagement name")
    return EngagementStore(p, create=create)


def _read_store(name: Optional[str] = None):
    """Resolve an engagement store for READ-ONLY access.

    Unlike the plain factory this never materialises an empty DB file, so simply
    loading the dashboard/findings/report for the fallback "default" engagement
    (or any engagement that hasn't been scanned yet) doesn't leave a stray
    ``default.db`` that then reappears in the engagement switcher forever.
    """
    return _engagement_store_factory(name, create=False)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        # Native-crash safety net. Scans run in-process, so a native (C-level)
        # segfault in any dependency would take the whole server down — the
        # user sees "Python quit unexpectedly" and every in-flight scan dies.
        # asyncssh's optional UMAC MACs are a broken ctypes→Nettle binding that
        # segfaults on some platforms the moment an SSH MAC is computed; strip
        # them before any connection. faulthandler turns any *future* native
        # crash into a Python traceback instead of a silent kill.
        try:
            from heaven.utils import ssh_safe
            ssh_safe.enable_crash_dumps()
            ssh_safe.harden_asyncssh()
        except Exception:  # a safety shim must never block startup
            logger.debug("ssh_safe hardening skipped", exc_info=True)
        admin_pwd_set = bool(os.environ.get("HEAVEN_ADMIN_PASSWORD"))
        if not admin_pwd_set:
            logger.warning(
                "HEAVEN_ADMIN_PASSWORD not set — a random admin password was generated "
                "at startup (see the boxed 'first-run admin credentials' log line above) "
                "and a password change is forced on first login. Set HEAVEN_ADMIN_PASSWORD "
                "in your .env (or run `heaven init`) to pin a persistent password."
            )
        if _auth_disabled():
            logger.error("HEAVEN_DISABLE_AUTH is enabled — DO NOT USE IN PRODUCTION")
        # One-time self-heal: older builds let the demo seeder write a
        # "demo (sample data)" engagement row + demo scope into whatever
        # engagement was active, which then leaked "demo" into the dashboard
        # label and report filename. Strip those leftovers from every real
        # engagement DB (never the dedicated demo DB, never real findings).
        try:
            from heaven.config import get_config
            from heaven.engagement import DEMO_DB_NAME, EngagementStore
            eng_dir = get_config().data_dir / "engagements"
            if eng_dir.exists():
                for db in eng_dir.glob("*.db"):
                    if db.stem == DEMO_DB_NAME:
                        continue
                    try:
                        EngagementStore(db).purge_demo_artifacts()
                    except Exception:  # noqa: BLE001 — skip locked/unreadable DBs
                        logger.debug("suppressed non-fatal exception", exc_info=True)
                        continue
        except Exception as e:  # noqa: BLE001
            logger.debug("Demo-artifact self-heal skipped: %s", e)
        # One-time cleanup: older builds materialised data/engagements/default.db
        # the moment any page loaded (the resolver's fallback name), leaving an
        # empty "default — empty" row in the switcher a user could never remove.
        # If it holds no scans, findings or scope it carries no data, so delete
        # it; a real "default" engagement the user actually scanned into (any of
        # those counts > 0) is left untouched. Reads no longer recreate it.
        try:
            from heaven.config import get_config
            from heaven.engagement import (
                EngagementStore,
                delete_engagement_store,
            )
            default_db = get_config().data_dir / "engagements" / "default.db"
            if default_db.exists():
                dstats = EngagementStore(default_db, create=False).stats()
                if (dstats.get("total_findings", 0) == 0
                        and dstats.get("scans_run", 0) == 0
                        and dstats.get("scope_targets", 0) == 0):
                    delete_engagement_store(default_db)
                    logger.info("Removed empty auto-created 'default' engagement")
        except Exception as e:  # noqa: BLE001
            logger.debug("Empty-default prune skipped: %s", e)
        # Reconcile orphaned scans: a scan persists status='running' at start and
        # only flips to a terminal state from inside its (in-process) task, so a
        # process that was killed or closed mid-scan leaves the row 'running'
        # forever — the UI then shows a perpetual, ticking "running" scan that
        # nothing is driving (the reported symptom). At startup no scan can still
        # be live, so flip every stranded row to 'interrupted' (checkpoints kept,
        # so it stays resumable) across every engagement DB.
        try:
            from heaven.config import get_config
            from heaven.engagement import DEMO_DB_NAME, EngagementStore
            eng_dir = get_config().data_dir / "engagements"
            if eng_dir.exists():
                _reconciled = 0
                for db in eng_dir.glob("*.db"):
                    if db.stem == DEMO_DB_NAME:
                        continue
                    try:
                        _reconciled += EngagementStore(
                            db, create=False).mark_orphaned_scans_interrupted()
                    except Exception:  # noqa: BLE001 — skip locked/unreadable DBs
                        logger.debug("suppressed non-fatal exception", exc_info=True)
                if _reconciled:
                    logger.info("Reconciled %d orphaned scan(s) → interrupted "
                                "(resumable) at startup", _reconciled)
        except Exception as e:  # noqa: BLE001
            logger.debug("Orphaned-scan reconciliation skipped: %s", e)
        # Self-heal the active pointer: if nothing is actively selected but the
        # operator has real work on disk, adopt the most-populated engagement so
        # the app opens on their data instead of a blank 'default' (which is what
        # made scans and the dashboard keep landing on the wrong/empty store).
        try:
            from heaven.engagement import (
                best_populated_engagement,
                get_active_engagement,
                set_active_engagement,
            )
            if not get_active_engagement():
                best = best_populated_engagement()
                if best:
                    set_active_engagement(best)
                    logger.info("Active engagement defaulted to '%s' (most populated)", best)
        except Exception as e:  # noqa: BLE001
            logger.debug("Active-engagement self-heal skipped: %s", e)
        yield
        # Shutdown — close any open WebSockets
        for ws in list(ws_connections) + list(log_ws_connections):
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

    app = FastAPI(
        title="HEAVEN Command Centre",
        description="Automated Vulnerability Scanner & Risk Triage Platform",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # ── Rate limiting ──
    # Global cap: protects against scrape/DoS. Login endpoint has its own
    # per-IP cap to slow brute-force on top of the per-user lockout.
    if HAS_SLOWAPI:
        rate_default = os.environ.get("HEAVEN_RATE_LIMIT_DEFAULT", "100/minute")
        rate_login = os.environ.get("HEAVEN_RATE_LIMIT_LOGIN", "5/minute")
        limiter = Limiter(key_func=get_remote_address, default_limits=[rate_default])
        app.state.limiter = limiter
        app.add_exception_handler(
            RateLimitExceeded,
            cast(Any, _rate_limit_exceeded_handler),
        )
    else:
        limiter = None
        rate_login = None
        logger.warning("slowapi not installed — API rate limiting is disabled")

    # CORS — explicit origins only. Wildcard + credentials is invalid per spec.
    cors_origins_raw = os.environ.get("HEAVEN_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    is_wildcard = (len(cors_origins) == 1 and cors_origins[0] == "*")
    if is_wildcard:
        # Wildcard requested — disable credentials (browsers reject the combo anyway)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        logger.warning("CORS wildcard configured via HEAVEN_CORS_ORIGINS — credentials disabled")
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Security headers middleware — defense-in-depth for the API
    from starlette.middleware.base import BaseHTTPMiddleware

    # Strict CSP for the SPA + API. The bundled UI loads its own JS/CSS from
    # 'self' (Vite output, no inline <script>), so script-src can stay tight —
    # the main defence-in-depth win against injected script. Inline *styles* are
    # allowed because the UI uses element style attributes throughout. The
    # interactive docs (/api/docs, /api/redoc) pull Swagger/ReDoc + an inline
    # bootstrap script from a CDN, so they get a relaxed policy rather than a
    # broken page.
    # script-src stays 'self' (the Vite bundle has no inline <script>) — the key
    # anti-XSS win. The other sources match exactly what the shipped UI loads:
    # Google Fonts (stylesheet + font files) and same-origin WebSockets for the
    # live scan/log streams. Widen only if the UI genuinely starts loading more.
    _CSP_APP = (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "object-src 'none'; img-src 'self' data:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "script-src 'self'; connect-src 'self' ws: wss:"
    )
    _CSP_DOCS = (
        "default-src 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "worker-src 'self' blob:; frame-ancestors 'none'; object-src 'none'"
    )
    _DOCS_PATHS = ("/api/docs", "/api/redoc", "/api/openapi.json")

    class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
            path = request.url.path
            response.headers["Content-Security-Policy"] = (
                _CSP_DOCS if path.startswith(_DOCS_PATHS) else _CSP_APP
            )
            if not os.environ.get("HEAVEN_DEV"):
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            return response

    app.add_middleware(_SecurityHeadersMiddleware)

    def _data_dir() -> Path:
        from heaven.config import get_config
        return get_config().data_dir

    def _clean_report_data(data: dict) -> dict:
        """Drop leaked attack-chain planner steps from a report's finding lists.

        Older reports persisted planner hypotheses (vuln_type = a bare MITRE
        technique like ``T1190``) alongside real findings, so every
        report-derived view (coverage, kill chain, risk scores) inherited the
        blank rows. Strip them here — one choke point — so those views agree with
        the cleaned findings list without needing a re-scan.
        """
        if not isinstance(data, dict):
            return data
        from heaven.engagement import is_attack_plan_artifact
        for key in ("vulnerabilities", "findings"):
            items = data.get(key)
            if isinstance(items, list):
                data[key] = [
                    v for v in items
                    if not (isinstance(v, dict) and is_attack_plan_artifact(v))
                ]
        # Fold in the active engagement's current metadata (client / statement of
        # work / tester) so a report always shows the latest edited values on its
        # cover, even when those were changed after the scan JSON was written.
        try:
            eng = _read_store().get_engagement()
            if eng is not None:
                if getattr(eng, "client", ""):
                    data["client"] = eng.client
                    data.setdefault("client_name", eng.client)
                if getattr(eng, "statement_of_work", ""):
                    data["statement_of_work"] = eng.statement_of_work
                if getattr(eng, "tester", ""):
                    data["tester"] = eng.tester
        except Exception:
            logger.debug("engagement metadata enrich skipped", exc_info=True)
        return data

    def _get_latest_report_data(scan_id: Optional[str] = None) -> dict:
        d = _data_dir()
        if scan_id:
            # scan_id lands in a filename — a value with "../" must never escape
            # the data dir. Unsafe ids just yield "no report" rather than 400,
            # since these read endpoints treat a missing report as empty.
            if not _is_safe_scan_id(scan_id):
                logger.warning("Rejected unsafe scan_id in report lookup: %r", scan_id)
                return {}
            file_path = d / f"report_{scan_id}.json"
            if file_path.exists():
                try:
                    return _clean_report_data(json.loads(file_path.read_text()))
                except Exception as e:
                    logger.error(f"Failed to read report {scan_id}: {e}")
            return {}

        files = glob.glob(str(d / "report_*.json"))
        if not files:
            return {}
        latest_file = max(files, key=os.path.getmtime)
        try:
            with open(latest_file, "r") as f:
                return _clean_report_data(json.load(f))
        except Exception as e:
            logger.error(f"Failed to read latest report {latest_file}: {e}")
            return {}

    def _collect_raw_assets(engagement: Optional[str] = None,
                            scan_id: Optional[str] = None) -> list[dict]:
        """Gather raw network-scan host assets (open ports / service / OS).

        Each completed scan persists its host assets inside ``summary_json`` and
        mirrors them into ``report_<id>.json``. We read the engagement store
        first — that covers both web- and CLI-launched scans — and fall back to
        the report JSON when there's no store row yet. ``normalize_assets`` then
        dedupes across scans by host, so a fresh scan's data supersedes an older
        one for the same machine.
        """
        raw: list[dict] = []
        try:
            store = _read_store(engagement)
            scans = ([store.get_scan(scan_id)] if scan_id
                     else store.list_scans(limit=200))
            for s in scans:
                if not s:
                    continue
                blob = s.get("summary_json")
                if not blob:
                    continue
                try:
                    summ = json.loads(blob)
                except (ValueError, TypeError):
                    continue
                raw.extend(a for a in (summ.get("assets") or []) if isinstance(a, dict))
        except Exception:
            logger.debug("suppressed non-fatal exception collecting store assets",
                         exc_info=True)
        if not raw:
            if scan_id:
                data = _get_latest_report_data(scan_id)
                raw.extend(a for a in (data.get("assets") or []) if isinstance(a, dict))
            else:
                # Engagement-scoped report fallback: walk only THIS engagement's
                # own scans (newest first) and use the first report JSON that
                # carries assets. Reading the single global "latest report" here
                # leaked another engagement's hosts into this one's Assets view.
                try:
                    st = _read_store(engagement)
                    for s in (st.list_scans(limit=50) if st else []):
                        sid = s.get("scan_id") or s.get("id")
                        if not sid or not _is_safe_scan_id(sid):
                            continue
                        data = _get_latest_report_data(sid)
                        found = [a for a in (data.get("assets") or []) if isinstance(a, dict)]
                        if found:
                            raw.extend(found)
                            break
                except Exception:
                    logger.debug("suppressed non-fatal exception in report-asset fallback",
                                 exc_info=True)
        # Overlay operator-set device names/types (Assets manual override) so both
        # the Assets view and the report reflect them — this is the single point
        # both read raw host assets.
        try:
            store = _read_store(engagement)
            labels = store.get_host_labels() if store else {}
            if labels:
                from heaven.devsecops.inventory import merge_host_labels
                merge_host_labels(raw, labels)
        except Exception:
            logger.debug("suppressed non-fatal exception overlaying host labels",
                         exc_info=True)
        return raw

    def _collect_raw_dns(engagement: Optional[str] = None,
                         scan_id: Optional[str] = None) -> list[dict]:
        """Gather raw DNS enumeration records (records + subdomains) from scans.

        Mirrors :func:`_collect_raw_assets` but for the DNS enumeration blob a
        scan persists inside ``summary_json`` under ``dns_records``. Falls back
        to the report JSON when there's no store row yet. ``normalize_dns`` then
        dedupes across scans by domain.
        """
        raw: list[dict] = []
        try:
            store = _read_store(engagement)
            scans = ([store.get_scan(scan_id)] if scan_id
                     else store.list_scans(limit=200))
            for s in scans:
                if not s:
                    continue
                blob = s.get("summary_json")
                if not blob:
                    continue
                try:
                    summ = json.loads(blob)
                except (ValueError, TypeError):
                    continue
                raw.extend(d for d in (summ.get("dns_records") or []) if isinstance(d, dict))
        except Exception:
            logger.debug("suppressed non-fatal exception collecting store DNS records",
                         exc_info=True)
        if not raw:
            if scan_id:
                data = _get_latest_report_data(scan_id)
                raw.extend(d for d in (data.get("dns_records") or []) if isinstance(d, dict))
            else:
                try:
                    st = _read_store(engagement)
                    for s in (st.list_scans(limit=50) if st else []):
                        sid = s.get("scan_id") or s.get("id")
                        if not sid or not _is_safe_scan_id(sid):
                            continue
                        data = _get_latest_report_data(sid)
                        found = [d for d in (data.get("dns_records") or []) if isinstance(d, dict)]
                        if found:
                            raw.extend(found)
                            break
                except Exception:
                    logger.debug("suppressed non-fatal exception in report-DNS fallback",
                                 exc_info=True)
        return raw

    def _asset_scan_index(engagement: Optional[str] = None) -> list[dict]:
        """Newest-first list of scans that carry host assets, for the picker.

        The inventory view is per-scan: showing every scan's hosts merged into
        one table blends two unrelated engagements' targets together. This lets
        the UI/CLI offer one scan at a time and default to the most recent.
        """
        from heaven.devsecops.inventory import inventory_totals, normalize_assets
        out: list[dict] = []
        try:
            store = _read_store(engagement)
            for s in (store.list_scans(limit=200) if store else []):
                sid = s.get("id") or s.get("scan_id")
                if not sid:
                    continue
                blob = s.get("summary_json")
                if not blob:
                    continue
                try:
                    summ = json.loads(blob)
                except (ValueError, TypeError):
                    continue
                assets = [a for a in (summ.get("assets") or []) if isinstance(a, dict)]
                if not assets:
                    continue
                # Count the open ports this scan actually discovered so the picker
                # can default to a scan that has data — a scan of a dead/mistyped
                # host records a host row with zero ports, and defaulting to it (as
                # the newest) made the whole inventory look empty.
                totals = inventory_totals(normalize_assets(assets))
                out.append({
                    "scan_id": sid,
                    "label": s.get("name") or sid,
                    "when": s.get("started_at") or s.get("completed_at") or "",
                    "hosts": totals["hosts"],
                    "ports": totals["open_ports"],
                })
        except Exception:
            logger.debug("suppressed non-fatal exception building asset scan index",
                         exc_info=True)
        return out

    # ── Health (unauthenticated) ──
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": __version__}

    # ── Auth ──
    if limiter and rate_login:
        @app.post("/api/auth/login", response_model=LoginResponse)
        @limiter.limit(rate_login)
        async def login(request: Request, req: LoginRequest):
            result = get_auth_manager().authenticate(
                req.username, req.password,
                source_ip=request.client.host if request.client else "",
            )
            if not result:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return LoginResponse(**result)
    else:
        @app.post("/api/auth/login", response_model=LoginResponse)
        async def login(req: LoginRequest, request: Request):
            result = get_auth_manager().authenticate(
                req.username, req.password,
                source_ip=request.client.host if request.client else "",
            )
            if not result:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return LoginResponse(**result)

    @app.post("/api/auth/logout")
    async def logout(authorization: Optional[str] = Header(None)):
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(None, 1)[1].strip()
            get_auth_manager().revoke_token(token)
        return {"status": "logged_out"}

    @app.get("/api/auth/me")
    async def me(user: User = Depends(require_user)):
        return user.to_dict()

    # ── Dashboard ──
    @app.get("/api/dashboard", response_model=DashboardData)
    async def get_dashboard(
        scan_id: Optional[str] = None,
        user: User = Depends(require_permission("scan.view")),
    ):
        # Primary: engagement store (populated by UI-launched + CLI scans)
        eng_store = _read_store()
        eng_findings = []
        if eng_store:
            try:
                eng_findings = [f.__dict__ for f in eng_store.list_findings(limit=1000)]
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

        # Fallback: report JSON files (written by CLI scans without engagement set)
        report_findings: list[dict] = []
        data = _get_latest_report_data(scan_id)
        report_findings = data.get("vulnerabilities", []) or data.get("findings", [])

        # Merge — engagement store takes priority. Critically, the report-JSON
        # fallback only applies when NO engagement is actively selected (a
        # fresh/CLI-only install). Once an operator is viewing a specific
        # engagement, the dashboard must show ONLY that engagement's data — even
        # when it's empty — otherwise switching to an engagement with no findings
        # would fall through to some *other* engagement's latest report and the
        # topology/stats would show the wrong hosts ("hosts mapped doesn't change
        # when I switch engagement").
        has_active_engagement = _get_active_engagement() is not None
        if eng_findings:
            vulns = eng_findings
        elif has_active_engagement:
            vulns = []
        else:
            vulns = report_findings

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        # Confirmed-only severity tally drives the Overall Risk headline so a
        # version-based "potential" match never inflates it (parity with reports).
        csev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        confirmed_total = 0
        for f in vulns:
            s = (f.get("severity") or "info").lower()
            if s in sev:
                sev[s] += 1
            if _confirmation_of(f) == "Confirmed":
                confirmed_total += 1
                if s in csev:
                    csev[s] += 1
        potential_total = len(vulns) - confirmed_total
        overall_risk = _overall_risk_from(csev)

        avg_risk = 0.0
        if vulns:
            scores = [float(f.get("priority_score") or f.get("predicted_cvss_score") or 0) for f in vulns]
            avg_risk = round(sum(scores) / len(scores), 1)

        # Recent scans: in-memory running + persisted
        all_scans = []
        seen_ids: set[str] = set()
        for sid, active in active_scans.items():
            seen_ids.add(sid)
            all_scans.append({
                "id": sid,
                "name": active.get("config", {}).get("name", "HEAVEN Scan"),
                "status": active.get("status", "running"),
                "vulns": active.get("findings_count", 0),
                "date": active.get("created", ""),
            })

        # From engagement store
        if eng_store:
            try:
                for s in eng_store.list_scans(limit=20):
                    sid = s.get("id") or s.get("scan_id", "")
                    if sid not in seen_ids:
                        seen_ids.add(sid)
                        all_scans.append({
                            "id": sid,
                            "name": s.get("name", "HEAVEN Scan"),
                            "status": s.get("status", "completed"),
                            "vulns": s.get("findings_count", 0),
                            "date": s.get("started_at", ""),
                        })
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

        # From report JSON files
        d = _data_dir()
        for file in sorted(glob.glob(str(d / "report_*.json")), key=os.path.getmtime, reverse=True)[:10]:
            try:
                with open(file, "r") as f:
                    r = json.load(f)
                sid = r.get("scan_id", "unknown")
                if sid not in seen_ids:
                    seen_ids.add(sid)
                    all_scans.append({
                        "id": sid,
                        "name": r.get("config", {}).get("name", "HEAVEN Scan"),
                        "status": "completed",
                        "vulns": len(r.get("vulnerabilities", [])),
                        "date": r.get("timestamp", ""),
                    })
            except Exception as e:
                logger.debug(f"Skipping unreadable report {file}: {e}")

        top_vulns = [
            {**f, "confirmation": _confirmation_of(f)}
            for f in sorted(vulns, key=lambda f: float(
                f.get("priority_score") or f.get("predicted_cvss_score") or 0),
                reverse=True)[:5]
        ]

        # Real host topology — aggregated from actual findings. Each node is a
        # host that a scan actually touched; severity is the worst finding on
        # it. No demo/placeholder data.
        #
        # Code-analysis findings (SAST/SCA) are excluded here: their "target" is
        # a source file or package name, not a network host, so mapping them
        # would spawn phantom nodes like "src" in the 3D topology. They still
        # count toward severity/totals and appear on the Findings page — they
        # just aren't network assets.
        code_scan_ids: set[str] = set()
        if eng_store:
            try:
                for s in eng_store.list_scans(limit=1000):
                    if _scan_mode_of(s) in CODE_ANALYSIS_MODES:
                        sid = s.get("id") or s.get("scan_id")
                        if sid:
                            code_scan_ids.add(sid)
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        from heaven.engagement import _host_key
        _sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        host_map: dict[str, dict] = {}
        for f in vulns:
            if f.get("scan_id") in code_scan_ids:
                continue
            tgt = f.get("target", "") or f.get("host", "")
            if not tgt:
                continue
            host = _host_key(tgt)
            if not host:
                continue
            node = host_map.get(host)
            if node is None:
                node = {"host": host, "ip": host, "severity": "info",
                        "open_ports": [], "finding_count": 0}
                host_map[host] = node
            node["finding_count"] += 1
            sev_l = (f.get("severity") or "info").lower()
            if _sev_rank.get(sev_l, 0) > _sev_rank.get(node["severity"], 0):
                node["severity"] = sev_l
            for p in (f.get("evidence") or {}).get("open_ports", []) or []:
                if p not in node["open_ports"]:
                    node["open_ports"].append(p)
        assets = list(host_map.values())

        return DashboardData(
            total_scans=len(all_scans),
            total_assets=len(host_map),
            total_vulns=len(vulns),
            critical=sev["critical"],
            high=sev["high"],
            medium=sev["medium"],
            low=sev["low"],
            confirmed=sum(1 for f in vulns if f.get("status") == "verified"),
            secrets=0,
            avg_risk=avg_risk,
            recent_scans=all_scans,
            top_vulns=top_vulns,
            severity_trend=[],
            assets=assets,
            overall_risk=overall_risk,
            confirmed_total=confirmed_total,
            potential_total=potential_total,
            confirmed_critical=csev["critical"],
            confirmed_high=csev["high"],
            confirmed_medium=csev["medium"],
            confirmed_low=csev["low"],
        )

    # ── Scans ──
    @app.post("/api/scans", response_model=ScanResponse)
    async def create_scan(
        req: ScanRequest,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Launch a new vulnerability scan. Caller must explicitly assert authorization."""
        if not req.i_have_authorization:
            raise HTTPException(
                status_code=400,
                detail="i_have_authorization must be true — operator must confirm written authorization for all targets",
            )

        # Engagement name becomes a DB filename — block traversal from the request.
        _validate_http_engagement(req.engagement)

        scan_id = uuid.uuid4().hex[:8]

        # Sort targets into ips and urls
        ips = []
        urls = list(req.urls)
        for t in req.targets:
            if _URL_REGEX.match(t):
                urls.append(t)
            else:
                ips.append(t)

        # ── SSRF / injection guard ──
        # Validate every target before it reaches the orchestrator → scanners →
        # nmap/nuclei/sqlmap argv and HTTP clients. Blocks argument-injection
        # (leading '-'), shell/SQL metacharacters, and SSRF-to-infrastructure
        # (cloud metadata 169.254.169.254, reserved ranges — always; loopback/
        # private per policy). Localhost/private are allowed by default because
        # scanning your own lab is the common case; set HEAVEN_ALLOW_LOCALHOST=0
        # / HEAVEN_ALLOW_PRIVATE=0 to lock a shared/hosted deployment down.
        from heaven.security.sanitizer import InputSanitizer

        def _flag(name: str, default: str) -> bool:
            return os.environ.get(name, default).lower() in ("1", "true", "yes")

        sanitizer = InputSanitizer(
            allow_private=_flag("HEAVEN_ALLOW_PRIVATE", "1"),
            allow_localhost=_flag("HEAVEN_ALLOW_LOCALHOST", "1"),
        )
        target_errors: list[str] = []
        for t in ips + urls:
            r = sanitizer.sanitize_target(t)
            if not r.valid:
                target_errors.extend(r.errors)
        if target_errors:
            raise HTTPException(
                status_code=400,
                detail="Target validation failed: " + "; ".join(target_errors[:10]),
            )

        req.targets = ips
        req.urls = urls

        # Resolve engagement first (explicit field > env var > active pointer >
        # default) so both the duplicate-submit guard and the active-engagement
        # pointer key off the real target store.
        req.engagement = _resolve_engagement_name(req.engagement)

        # ── Duplicate-submit guard ──
        # One user action can reach this endpoint twice (a double click,
        # Enter-then-click, a network retry, or a dev StrictMode re-fire). Each
        # POST otherwise spawns its own scan, so "launch one" quietly ran two.
        # If an identical scan (same targets + mode + engagement) is already
        # pending/running — or was created in the last few seconds — return that
        # scan instead of starting a duplicate.
        _sig = (
            tuple(sorted((req.targets or []) + (req.urls or []))),
            str(req.mode or req.scan_type or "full").lower(),
            req.engagement,
        )
        _now = datetime.now(timezone.utc)
        for _sid, _sc in list(active_scans.items()):
            _cfg = _sc.get("config") or {}
            _osig = (
                tuple(sorted((_cfg.get("targets") or []) + (_cfg.get("urls") or []))),
                str(_cfg.get("mode") or _cfg.get("scan_type") or "full").lower(),
                _sc.get("engagement"),
            )
            if _osig != _sig:
                continue
            if _sc.get("status") in ("pending", "running"):
                return ScanResponse(scan_id=_sid, status=str(_sc.get("status", "pending")),
                                    message="Identical scan already in progress — duplicate ignored")
            try:
                _c = _sc.get("created")
                if _c and (_now - datetime.fromisoformat(_c)).total_seconds() < 8:
                    return ScanResponse(scan_id=_sid, status=str(_sc.get("status", "completed")),
                                        message="Duplicate scan submit ignored")
            except (ValueError, TypeError):
                pass

        # Persist the resolved engagement as active so the dashboard, findings and
        # reports immediately follow this scan's data.
        _set_active_engagement(req.engagement)

        active_scans[scan_id] = {
            "status": "pending",
            # Authoritative mode for the badge/filter while the scan is in memory.
            # The launcher sends `mode`; `scan_type` stays at its "full" default,
            # so the UI must not fall back to scan_type or focused scans show FULL.
            "mode": (req.mode or req.scan_type or "full"),
            "config": req.model_dump(),
            "created": _now.isoformat(),
            "created_by": user.username,
            "engagement": req.engagement,
        }

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_STARTED, target=",".join((req.targets or []) + (req.urls or []))[:200],
            details={"scan_id": scan_id, "mode": req.scan_type}, actor=user.username,
            severity=AuditSeverity.INFO,
        )

        active_scans[scan_id]["scan_id"] = scan_id
        # Keep a strong reference to the task in a module-level set. Without it,
        # asyncio only holds a weak ref and the GC can kill a running scan
        # mid-flight. The ref must NOT live in active_scans — that dict is
        # JSON-serialised by the API and a Task object is not serialisable.
        task = asyncio.create_task(_run_scan_background(scan_id, req))
        _background_scan_tasks.add(task)
        _scan_tasks_by_id[scan_id] = task

        def _scan_done(t: asyncio.Task):
            _background_scan_tasks.discard(t)
            _scan_tasks_by_id.pop(scan_id, None)
            try:
                exc = t.exception()
            except asyncio.CancelledError:
                exc = None
            if exc is not None:
                logger.error(f"Background scan {scan_id} crashed: {exc}")
                if scan_id in active_scans:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = str(exc)

        task.add_done_callback(_scan_done)
        return ScanResponse(scan_id=scan_id, status="pending", message="Scan queued")

    @app.get("/api/scans")
    async def list_scans(
        limit: int = Query(20, ge=1, le=100),
        kind: str = Query(
            "pentest",
            description="Which section's scans to list: 'pentest' (default — "
            "active scans, excludes SAST/SCA which have their own sections), "
            "'sast', 'sca', or 'all'.",
        ),
        user: User = Depends(require_permission("scan.view")),
    ):
        # Which scans belong to the requested section. Each code-analysis mode
        # (sast/sca) lives in its own section, so the default pentest list must
        # not double-show them — that was the "same scan appears twice" bug.
        kind = (kind or "pentest").lower()
        if kind == "all":
            def _keep(s: dict) -> bool:
                return True
        elif kind in CODE_ANALYSIS_MODES:
            def _keep(s: dict) -> bool:
                return _scan_mode_of(s) == kind
        else:  # "pentest" — everything that isn't a code-analysis section
            def _keep(s: dict) -> bool:
                return _scan_mode_of(s) not in CODE_ANALYSIS_MODES

        # In-memory scans (current session)
        mem = [{**v, "scan_id": k} for k, v in active_scans.items()]
        # Persisted scans from engagement store. Pull extra rows before filtering
        # so a section still fills its page even when other kinds dominate.
        persisted = []
        store = _read_store()
        if store:
            try:
                for s in store.list_scans(limit=limit * 3):
                    sid = s.get("scan_id") or s.get("id", "")
                    if sid not in active_scans:
                        persisted.append(s)
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        combined = [s for s in (mem + persisted) if _keep(s)]
        combined.sort(key=lambda s: s.get("created") or s.get("started_at") or "", reverse=True)
        return {"scans": combined[:limit]}

    @app.get("/api/scans/{scan_id}")
    async def get_scan(
        scan_id: str,
        include_findings: bool = False,
        user: User = Depends(require_permission("scan.view")),
    ):
        """A single scan's live/persisted state. Falls back to the engagement
        store when the scan is no longer in memory (e.g. after a server restart),
        so clicking a completed scan always shows its result. With
        ``include_findings=true`` the scan's deduped findings are attached."""
        detail: dict = {}
        if scan_id in active_scans:
            detail = dict(active_scans[scan_id])
        else:
            store = _read_store()
            row = None
            try:
                row = store.get_scan(scan_id)
            except Exception:  # noqa: BLE001
                row = None
            if not row:
                raise HTTPException(404, "Scan not found")
            detail = {
                "scan_id": scan_id,
                "id": scan_id,
                "name": row.get("name") or "HEAVEN Scan",
                "mode": row.get("mode", ""),
                "status": row.get("status", "completed"),
                "created": row.get("started_at", ""),
                "started_at": row.get("started_at", ""),
                "completed_at": row.get("completed_at", ""),
                "findings_count": row.get("findings_count", 0),
            }

        if include_findings:
            store = _read_store()
            try:
                rows = store.list_findings(scan_id=scan_id, limit=1000)
                detail["findings"] = [f.__dict__ for f in rows]
            except Exception:  # noqa: BLE001
                detail["findings"] = []
        return detail

    @app.delete("/api/scans/{scan_id}")
    async def delete_scan(
        scan_id: str,
        user: User = Depends(require_permission("scan.cancel")),
    ):
        """Cancel a running scan, or permanently remove a finished one.

        - Running/pending scans are *cancelled* (findings kept).
        - Otherwise the scan is *deleted*: its findings, checkpoints, the report
          JSON file and the in-memory record are all removed. This backs the
          web-UI "Remove scan" action.
        """
        # scan_id is interpolated into a filename below (report_<id>.json) and
        # passed to the store — reject traversal/oddball ids before any file op.
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=400, detail="Invalid scan id")

        mem = active_scans.get(scan_id)
        # 1. A scan running in THIS process — genuinely cancel it. The old code
        #    only relabelled the in-memory dict, so the scan kept running; now we
        #    cancel the real task and persist 'cancelled' (findings kept).
        if mem and mem.get("status") in ("running", "pending"):
            mem["status"] = "cancelled"
            _task = _scan_tasks_by_id.get(scan_id)
            if _task and not _task.done():
                _task.cancel()
            try:
                _engagement_store_factory(mem.get("engagement")).record_scan_complete(
                    scan_id, summary={"cancelled": True}, status="cancelled")
            except Exception:  # noqa: BLE001
                logger.debug("suppressed non-fatal exception", exc_info=True)
            return {"status": "cancelled", "scan_id": scan_id}

        # 2. A persisted scan still marked running/pending but with no live task
        #    (a zombie left by a killed process that startup reconciliation hasn't
        #    reached, or a same-session edge). Do NOT hard-delete — that would
        #    destroy its checkpoints and make resume impossible. Mark it
        #    interrupted so the operator can resume or explicitly remove it.
        try:
            _row = _read_store().get_scan(scan_id) if _read_store() else None
        except Exception:  # noqa: BLE001
            _row = None
        if _row and _row.get("status") in ("running", "pending"):
            try:
                _engagement_store_factory().record_scan_interrupted(scan_id)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed non-fatal exception", exc_info=True)
            return {"status": "interrupted", "scan_id": scan_id}

        removed = False
        # 1. Report JSON file (powers the dashboard's report-file fallback)
        try:
            rp = _data_dir() / f"report_{scan_id}.json"
            if rp.exists():
                rp.unlink()
                removed = True
        except OSError as e:
            logger.warning(f"Could not delete report file for {scan_id}: {e}")
        # 2. Engagement store rows (findings + scan + checkpoints)
        try:
            if _engagement_store_factory().delete_scan(scan_id):
                removed = True
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not delete scan {scan_id} from store: {e}")
        # 3. In-memory record
        if scan_id in active_scans:
            active_scans.pop(scan_id, None)
            removed = True

        if not removed:
            raise HTTPException(404, "Scan not found")
        return {"status": "deleted", "scan_id": scan_id}

    @app.post("/api/scans/{scan_id}/resume")
    async def resume_scan_endpoint(
        scan_id: str,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Resume an interrupted / paused scan from its last checkpoints.

        Backs the web "Resume" action for a scan the dashboard shows as
        interrupted (e.g. after the app was closed mid-scan). The stored,
        replayable config is used to rebuild the same task graph; the orchestrator
        skips tasks that already completed (their checkpoints) and continues.
        Mirrors the CLI ``heaven resume``.
        """
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(400, "Invalid scan id")
        # Already running in this process? Don't double-launch.
        if scan_id in active_scans and active_scans[scan_id].get("status") in (
                "running", "pending"):
            return ScanResponse(scan_id=scan_id, status="running",
                                message="Scan already running")
        store = _read_store()
        row = store.get_scan(scan_id) if store else None
        if not row:
            raise HTTPException(404, "Scan not found")
        if row.get("status") not in ("running", "pending", "paused", "interrupted"):
            raise HTTPException(409, f"Scan is {row.get('status')} — not resumable")

        try:
            cfg = json.loads(row.get("config_json") or "{}")
        except (ValueError, TypeError):
            cfg = {}
        tgt = cfg.get("targets") or {}
        ips = list(tgt.get("ips") or [])
        urls = list(tgt.get("urls") or [])
        if not ips and not urls:
            raise HTTPException(422, "Resumed scan has no targets in its stored config")

        _name2int = {v: k for k, v in _STEALTH_INT_TO_NAME.items()}
        req = ScanRequest(
            name=row.get("name") or "HEAVEN Scan",
            targets=ips,
            urls=urls,
            repositories=list(tgt.get("repositories") or []),
            cloud_providers=list(tgt.get("cloud_providers") or []),
            ports=str(tgt.get("ports") or "1-65535"),
            mode=row.get("mode") or cfg.get("mode") or "full",
            stealth_level=_name2int.get(str(tgt.get("stealth_level") or "normal"), 3),
            evade=bool(tgt.get("evade")),
            engagement=_resolve_engagement_name(),
            i_have_authorization=True,
        )
        active_scans[scan_id] = {
            "status": "pending", "mode": req.mode, "config": req.model_dump(),
            "created": row.get("started_at") or datetime.now(timezone.utc).isoformat(),
            "created_by": user.username, "engagement": req.engagement,
            "scan_id": scan_id, "resumed": True,
        }
        task = asyncio.create_task(_run_scan_background(scan_id, req, resume=True))
        _background_scan_tasks.add(task)
        _scan_tasks_by_id[scan_id] = task

        def _resume_done(t: asyncio.Task):
            _background_scan_tasks.discard(t)
            _scan_tasks_by_id.pop(scan_id, None)
            try:
                exc = t.exception()
            except asyncio.CancelledError:
                exc = None
            if exc is not None:
                logger.error(f"Resumed scan {scan_id} crashed: {exc}")
                if scan_id in active_scans:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = str(exc)

        task.add_done_callback(_resume_done)
        logger.info("Resuming scan %s by %s", scan_id, user.username)
        return ScanResponse(scan_id=scan_id, status="running", message="Scan resumed")

    # ── Vulnerabilities ──
    @app.get("/api/vulnerabilities")
    async def list_vulnerabilities(
        severity: Optional[str] = None,
        limit: int = Query(50, ge=1, le=500),
        scan_id: Optional[str] = None,
        user: User = Depends(require_permission("vuln.view")),
    ):
        data = _get_latest_report_data(scan_id)
        vulns = data.get("vulnerabilities", [])

        if severity:
            vulns = [v for v in vulns if v.get("severity") == severity.lower()]

        formatted = []
        for v in vulns:
            formatted.append({
                "id": v.get("cve_id") or v.get("title", ""),
                "cve": v.get("cve_id", "N/A"),
                "title": v.get("title", v.get("type", "Unknown")),
                "severity": v.get("severity", "info").lower(),
                "risk": v.get("risk_score", 0),
                "asset": v.get("target", "unknown"),
                "port": v.get("port", 0),
                "validated": v.get("validated", False),
                "epss": v.get("epss", 0),
            })
        return {"vulnerabilities": formatted[:limit], "total": len(formatted)}

    # ── Assets ──
    @app.get("/api/assets")
    async def list_assets(
        limit: int = Query(50, ge=1, le=500),
        scan_id: Optional[str] = None,
        engagement: Optional[str] = None,
        all_scans: bool = Query(False, alias="all"),
        user: User = Depends(require_permission("scan.view")),
    ):
        """Host & service inventory: open ports, service versions and OS for
        every host the network scanner discovered.

        Every value is reported exactly as nmap observed it — nothing is
        fabricated. An OS labelled ``(heuristic — unconfirmed)`` was inferred
        from a TTL, not an nmap ``-O`` stack fingerprint, and is flagged as such
        so a guess is never mistaken for a confirmed fact.
        """
        from heaven.devsecops.inventory import inventory_totals, normalize_assets
        from heaven.devsecops.dns_inventory import dns_totals, normalize_dns
        # The inventory is scoped to ONE scan so two separate scans never merge
        # into a single blended host table. Default to the most recent scan that
        # produced assets; the caller can pass ?scan_id= to view an older one, or
        # ?all=1 for the engagement-wide union (used by the lateral-movement page
        # to gather every discovered pivot host).
        scans = _asset_scan_index(engagement)
        if all_scans:
            selected = None  # scan_id=None → _collect_raw_assets merges every scan
        elif scan_id and _is_safe_scan_id(scan_id):
            selected = scan_id
        elif scans:
            # Default to the newest scan that actually found open ports; only fall
            # back to the newest asset-bearing scan when none did (so a dead-host
            # scan doesn't hide an earlier scan that has real inventory).
            selected = next(
                (s["scan_id"] for s in scans if s.get("ports")),
                scans[0]["scan_id"],
            )
        else:
            selected = None
        # selected None → engagement-wide (either ?all=1, or no scan carries
        # summary assets and we fall back to the report-JSON path for legacy data).
        raw = _collect_raw_assets(engagement, selected)
        inventory = normalize_assets(raw)
        # DNS enumeration (records + subdomains) for the Assets view's own
        # section. Prefer the selected scan's records; fall back to the
        # engagement-wide union so a DNS-only scan (or a web scan whose host
        # picker selected a different scan) still surfaces here. DNS records are
        # keyed by domain, so merging across scans is well-defined (unlike the
        # per-scan host table).
        dns_raw = _collect_raw_dns(engagement, selected) or _collect_raw_dns(engagement)
        dns_inv = normalize_dns(dns_raw)
        return {
            "assets": inventory[:limit],
            "total": len(inventory),
            "totals": inventory_totals(inventory),
            "dns": dns_inv,
            "dns_totals": dns_totals(dns_inv),
            "scans": scans,
            "scan_id": selected,
        }

    @app.patch("/api/assets/label")
    async def set_asset_label(
        body: dict,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Set an operator device name / type for a host (Assets manual override).

        Backs the inline "✎ Edit" on each Assets host card — the "add it manually
        when the scan couldn't observe it" path. Send ``host`` plus any of
        ``device_name`` / ``device_type`` (empty string clears a field). The label
        is stored per engagement and ranks above any scan-inferred value, so it
        shows in the Assets view and the report. Nothing is fabricated — this is
        explicit human input.
        """
        if not isinstance(body, dict):
            raise HTTPException(422, "expected a JSON object")
        from heaven.devsecops.inventory import host_key
        host = host_key(str(body.get("host") or ""))
        if not host:
            raise HTTPException(422, "a valid host/IP is required")
        if "device_name" not in body and "device_type" not in body:
            raise HTTPException(422, "provide device_name and/or device_type")

        def _clean(v: Any) -> str:
            return " ".join(str(v or "").split())[:120]

        name = _clean(body.get("device_name")) if "device_name" in body else None
        dtype = _clean(body.get("device_type")) if "device_type" in body else None
        store = _engagement_store_factory()
        try:
            store.set_host_label(host, device_name=name, device_type=dtype)
        except Exception as e:  # noqa: BLE001 — surface to the UI
            logger.warning("Host label update failed for %s: %s", host, e)
            raise HTTPException(500, "Could not save the device label")
        logger.info("Host label set by %s for %s (name=%s, type=%s)",
                    user.username, host, name, dtype)
        return {"ok": True, "host": host,
                "device_name": name, "device_type": dtype}

    # ── Attack Tree ──
    @app.get("/api/attack-tree/{scan_id}")
    async def get_attack_tree(
        scan_id: str,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Generate Mermaid diagram data for attack paths."""
        actual_scan_id = None if scan_id == "latest" else scan_id
        data = _get_latest_report_data(actual_scan_id)
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return {
                "mermaid": "graph TD\n    A[External Attacker] --> B[No Vulnerabilities Found]",
                "chains": [],
            }

        mermaid_lines = ["graph TD", "    A[External Attacker]"]
        chains = []
        targets_seen = set()
        colors = []

        for idx, v in enumerate(vulns[:8]):
            target = str(v.get("target", "Unknown Asset")).replace('"', "").replace("(", "").replace(")", "")
            cve = str(v.get("cve_id", v.get("title", "Unknown"))).replace('"', "").replace("(", "").replace(")", "")

            target_id = f"T{abs(hash(target)) % 10000}"
            vuln_id = f"V{idx}"

            if target not in targets_seen:
                mermaid_lines.append(f"    A -->|Network| {target_id}[{target}]")
                targets_seen.add(target)
                colors.append(f"style {target_id} fill:#1e1e2e,stroke:#00f0ff,color:#00f0ff")

            mermaid_lines.append(f"    {target_id} -->|Exploit| {vuln_id}[{cve}]")

            sev = v.get("severity", "low").lower()
            if sev == "critical":
                colors.append(f"style {vuln_id} fill:#ff0040,stroke:#ff0040,color:#fff")
                chains.append({"name": f"{target} → Full Compromise", "score": v.get("risk_score", 95.0), "steps": 3})
            elif sev == "high":
                colors.append(f"style {vuln_id} fill:#ff6600,stroke:#ff6600,color:#fff")
                chains.append({"name": f"{target} → Data Access", "score": v.get("risk_score", 75.0), "steps": 2})
            elif sev == "medium":
                colors.append(f"style {vuln_id} fill:#ffaa00,stroke:#ffaa00,color:#000")
            else:
                colors.append(f"style {vuln_id} fill:#1e1e2e,stroke:#00ff00,color:#00ff00")

        colors.append("style A fill:#ff0040,stroke:#ff0040,color:#fff")

        return {
            "mermaid": "\n".join(mermaid_lines + [""] + colors),
            "chains": chains,
        }

    # ── Kill Chain Coverage ──
    @app.get("/api/kill-chain/{scan_id}")
    async def get_kill_chain(
        scan_id: str,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Map findings to Lockheed Cyber Kill Chain phases."""
        from heaven.mitre.kill_chain import KillChainAnalyzer
        actual_scan_id = None if scan_id == "latest" else scan_id
        data = _get_latest_report_data(actual_scan_id)
        findings = data.get("vulnerabilities", []) + data.get("findings", [])

        analyzer = KillChainAnalyzer()
        analyzer.ingest(findings)
        return {
            "scan_id": scan_id,
            "report": analyzer.report(),
            "attack_path": analyzer.attack_path_summary(),
            "mermaid": analyzer.to_mermaid(),
        }

    # ── Engagement workflow ──
    @app.get("/api/engagement")
    async def engagement_summary(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Active engagement summary + stats."""
        store = _read_store()
        try:
            eng = store.get_engagement()
            stats = store.stats()
            no_engagement = stats.get("total_findings", 0) == 0 and stats.get("scans_run", 0) == 0
            # Confirmation split — Overall Risk from confirmed findings only, in
            # parity with the reports and /api/dashboard. Computed on read.
            try:
                from heaven.engagement import is_attack_plan_artifact
                csev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                conf_total = 0
                real = 0
                for f in store.list_findings(limit=5000):
                    d = f.__dict__
                    if is_attack_plan_artifact(d):
                        continue
                    real += 1
                    if _confirmation_of(d) == "Confirmed":
                        conf_total += 1
                        s = (d.get("severity") or "info").lower()
                        if s in csev:
                            csev[s] += 1
                stats["confirmed_total"] = conf_total
                stats["potential_total"] = max(0, real - conf_total)
                stats["confirmed_by_severity"] = csev
                stats["overall_risk"] = _overall_risk_from(csev)
            except Exception:
                logger.debug("confirmation stats unavailable", exc_info=True)
            return {
                "engagement": eng.__dict__ if eng else None,
                "stats": stats,
                "no_engagement": no_engagement,
            }
        except Exception as e:
            logger.warning(f"Engagement store read error: {e}")
            return {
                "engagement": None,
                "stats": {
                    "scope_targets": 0, "scans_run": 0, "total_findings": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "by_status": {},
                },
                "no_engagement": True,
            }

    @app.patch("/api/engagement")
    async def update_engagement_details_endpoint(
        body: dict,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Edit the active engagement's Client, Statement-of-work and/or Tester.

        Backs the inline edit on the Engagement page. Send any of ``client`` /
        ``statement_of_work`` / ``tester``; omitted fields are left unchanged.
        Values are trimmed and length-capped so the dashboard label and the
        report cover page stay tidy. Returns the refreshed engagement.
        """
        if not isinstance(body, dict):
            raise HTTPException(422, "expected a JSON object")

        has_client = "client" in body
        has_sow = "statement_of_work" in body
        has_tester = "tester" in body
        if not (has_client or has_sow or has_tester):
            raise HTTPException(422, "provide client, statement_of_work and/or tester")

        def _clean(v: Any) -> str:
            # Collapse to a tidy single-line string; cap length to keep the DB
            # and the report cover page sane. None/whitespace → "".
            return " ".join(str(v or "").split())[:200]

        client = _clean(body.get("client")) if has_client else None
        sow = _clean(body.get("statement_of_work")) if has_sow else None
        tester = _clean(body.get("tester")) if has_tester else None

        # A write store (create=True) so the row materialises even on a
        # switched-to-but-never-scanned engagement.
        store = _engagement_store_factory()
        try:
            eng = store.update_engagement_details(
                client=client, statement_of_work=sow, tester=tester
            )
        except Exception as e:  # noqa: BLE001 — surface the failure to the UI
            logger.warning("Engagement details update failed: %s", e)
            raise HTTPException(500, "Could not update engagement details")
        logger.info(
            "Engagement details updated by %s (client=%s, sow=%s, tester=%s)",
            user.username, has_client, has_sow, has_tester,
        )
        return {"ok": True, "engagement": eng.__dict__ if eng else None}

    @app.get("/api/engagements")
    async def list_engagements(
        user: User = Depends(require_permission("scan.view")),
    ):
        """List every engagement store on disk, with finding/scan counts and
        which one is currently active. Backs the dashboard engagement switcher
        so an operator can flip between the targets they've scanned."""
        from heaven.config import get_config
        from heaven.engagement import EngagementStore
        eng_dir = get_config().data_dir / "engagements"
        active = _resolve_engagement_name()
        out: list[dict] = []
        seen: set[str] = set()
        if eng_dir.exists():
            for db in sorted(eng_dir.glob("*.db")):
                name = db.stem
                seen.add(name)
                try:
                    st = EngagementStore(db, create=False)
                    stats = st.stats()
                    eng = st.get_engagement()
                    out.append({
                        "name": name,
                        "display_name": (eng.name if eng else name) or name,
                        "findings": stats.get("total_findings", 0),
                        "scans": stats.get("scans_run", 0),
                        "active": name == active,
                    })
                except Exception:  # noqa: BLE001 — skip unreadable/locked DBs
                    logger.debug("suppressed non-fatal exception", exc_info=True)
                    continue
        # A real, user-chosen engagement may not have a DB yet (switched to but
        # not scanned) — surface it so the switcher shows a consistent selection.
        # But NEVER invent the bare "default" fallback: it isn't a real
        # engagement, and its phantom "default — empty" row is exactly the one a
        # fresh, never-scanned install could never get rid of.
        if active not in seen and active != "default":
            out.insert(0, {"name": active, "display_name": active,
                           "findings": 0, "scans": 0, "active": True})
        out.sort(key=lambda e: (not e["active"], -e["findings"], e["name"]))
        return {"engagements": out, "active": active}

    @app.post("/api/engagements/active")
    async def set_active_engagement_endpoint(
        body: dict,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Switch which engagement the dashboard, findings and reports show."""
        name = str((body or {}).get("name", "")).strip()
        if not name:
            raise HTTPException(400, "name is required")
        # This name is persisted to the pointer file and later becomes a DB
        # filename — block traversal before it can poison the resolver.
        _validate_http_engagement(name)
        _set_active_engagement(name)
        return {"ok": True, "active": name}

    @app.delete("/api/engagements/{name}")
    async def delete_engagement_endpoint(
        name: str,
        user: User = Depends(require_permission("scan.cancel")),
    ):
        """Permanently delete an engagement store (its scans, findings and scope).

        Backs the dashboard "remove engagement" action so operators can clean up
        stray/empty engagements the switcher would otherwise list forever. If the
        engagement being deleted is the one the app is currently viewing, the
        active pointer is repointed to the best remaining engagement (the one with
        the most findings, real engagements before the sample 'demo' one) or
        cleared so the resolver falls back to 'default'.
        """
        from heaven.config import get_config
        from heaven.engagement import DEMO_DB_NAME, EngagementStore

        # The name becomes a DB filename — reject traversal before any file op.
        _validate_http_engagement(name)
        eng_dir = get_config().data_dir / "engagements"
        db = eng_dir / f"{name}.db"
        if not db.exists():
            raise HTTPException(404, "Engagement not found")

        was_active = _resolve_engagement_name() == name
        _delete_engagement_store(db)

        new_active: Optional[str] = None
        if was_active:
            # Rank the survivors: real engagements with findings first, then the
            # sample 'demo', then anything else; empty stores never auto-activate.
            candidates: list[tuple[int, int, str]] = []
            for other in sorted(eng_dir.glob("*.db")):
                other_name = other.stem
                if other_name == name:
                    continue
                try:
                    findings = EngagementStore(other).stats().get("total_findings", 0)
                except Exception:  # noqa: BLE001 — skip unreadable/locked DBs
                    logger.debug("suppressed non-fatal exception", exc_info=True)
                    continue
                if findings <= 0:
                    continue
                is_demo = 1 if other_name == DEMO_DB_NAME else 0
                # sort key: real-before-demo, then most findings, then name
                candidates.append((is_demo, -findings, other_name))
            candidates.sort()
            if candidates:
                new_active = candidates[0][2]
                _set_active_engagement(new_active)
            else:
                _clear_active_engagement()
                new_active = _resolve_engagement_name()

        logger.info("Engagement '%s' deleted by %s (was_active=%s, new_active=%s)",
                    name, user.username, was_active, new_active)
        return {"ok": True, "deleted": name, "active": new_active or _resolve_engagement_name()}

    @app.post("/api/engagements/{name}/rename")
    async def rename_engagement_endpoint(
        name: str,
        body: dict,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Rename an engagement so an operator is never stuck with an awkward
        name (the name is welded to the store key *and* the DB filename, so this
        moves the SQLite DB + its WAL sidecars and rewrites the in-DB name row).

        Backs the dashboard "rename" action. If the renamed engagement is the one
        the app is currently viewing, the active pointer follows it to the new
        name so the dashboard keeps showing the same data.
        """
        from heaven.config import get_config

        new_name = str((body or {}).get("new_name", "")).strip()
        # Both the current and the new name become DB *filenames* — reject
        # traversal on either before any filesystem operation.
        _validate_http_engagement(name)
        _validate_http_engagement(new_name)
        if not new_name:
            raise HTTPException(400, "new_name is required")
        if new_name == "default":
            raise HTTPException(400, "'default' is reserved and cannot be used as a name")
        if new_name == name:
            # No-op rename — report success so the UI stays simple.
            return {"ok": True, "renamed": {"from": name, "to": new_name},
                    "active": _resolve_engagement_name()}

        eng_dir = get_config().data_dir / "engagements"
        old_db = eng_dir / f"{name}.db"
        new_db = eng_dir / f"{new_name}.db"
        if not old_db.exists():
            raise HTTPException(404, "Engagement not found")
        # A case-only rename targets the same file on a case-insensitive fs — that
        # is allowed; only a genuinely different existing engagement is a clash.
        if new_db.exists() and not new_db.samefile(old_db):
            raise HTTPException(409, f"An engagement named '{new_name}' already exists")

        was_active = _resolve_engagement_name() == name
        try:
            _rename_engagement_store(old_db, new_db)
        except FileExistsError:
            raise HTTPException(409, f"An engagement named '{new_name}' already exists")
        except FileNotFoundError:
            raise HTTPException(404, "Engagement not found")
        except OSError as e:
            logger.warning("Rename '%s'→'%s' failed: %s", name, new_name, e)
            raise HTTPException(500, "Could not rename engagement")

        if was_active:
            _set_active_engagement(new_name)
        logger.info("Engagement '%s' renamed to '%s' by %s (was_active=%s)",
                    name, new_name, user.username, was_active)
        return {"ok": True, "renamed": {"from": name, "to": new_name},
                "active": _resolve_engagement_name()}

    @app.get("/api/engagement/findings")
    async def engagement_findings(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        target: Optional[str] = None,
        vuln_type: Optional[str] = None,
        min_confidence: float = 0.0,
        scan_id: Optional[str] = None,
        limit: int = Query(100, ge=1, le=10000),
        user: User = Depends(require_permission("vuln.view")),
    ):
        """List findings from the active engagement (optionally one scan)."""
        from heaven.engagement import is_attack_plan_artifact
        from heaven.devsecops.vuln_kb import enrich_finding
        store = _read_store()
        results = store.list_findings(
            severity=severity, status=status, target=target,
            vuln_type=vuln_type, min_confidence=min_confidence, limit=limit,
            scan_id=scan_id,
        )
        # Drop any attack-chain planner steps that older scans persisted as
        # pseudo-findings (vuln_type is a bare MITRE technique like ``T1190`` with
        # no taxonomy) so a re-scan isn't needed to clear the blank rows.
        # Enrich each row from the knowledge base so the list carries the SAME
        # per-finding taxonomy and CVSS v4.0 / v3.1 scores + vectors the detail
        # view and reports show — the list must never disagree with them.
        findings = [
            {**enrich_finding(f.__dict__), "confirmation": _confirmation_of(f.__dict__)}
            for f in results
            if not is_attack_plan_artifact(f.__dict__)
        ]
        return {"findings": findings, "count": len(findings)}

    @app.post("/api/engagement/findings")
    async def create_manual_finding(
        req: ManualFindingRequest,
        user: User = Depends(require_permission("vuln.create")),
    ):
        """Record a finding discovered manually (e.g. via Burp Suite)."""
        store = _engagement_store_factory()
        if not store:
            raise HTTPException(404, "No active engagement.")
        finding_dict = {
            "target": req.target,
            "vuln_type": req.vuln_type,
            "title": req.title,
            "severity": req.severity,
            "confidence": req.confidence,
            "evidence": req.evidence,
            "notes": req.notes,
            "source": "manual",
        }
        finding_id = store.upsert_finding("manual", finding_dict)
        return {"finding_id": finding_id, "status": "created"}

    @app.put("/api/engagement/findings/{finding_id}/status")
    async def update_finding_status_endpoint(
        finding_id: str, payload: FindingStatusUpdate,
        user: User = Depends(require_permission("vuln.update")),
    ):
        """Mark a finding as verified, false-positive, accepted-risk, or fixed."""
        store = _engagement_store_factory()
        if not store:
            raise HTTPException(404, "No active engagement.")
        try:
            ok = store.update_finding_status(finding_id, payload.status, notes=payload.notes)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not ok:
            raise HTTPException(404, "Finding not found")
        return {"status": "updated", "finding_id": finding_id, "new_status": payload.status}

    @app.put("/api/engagement/findings/{finding_id}/notes")
    async def save_finding_notes_endpoint(
        finding_id: str, payload: FindingNotesUpdate,
        user: User = Depends(require_permission("vuln.update")),
    ):
        """Save operator notes for a finding WITHOUT changing its status.

        Backs the explicit "Save note" action so a note typed while leaving the
        status unchanged is persisted (it used to be lost unless the operator
        also flipped the status)."""
        store = _engagement_store_factory()
        if not store:
            raise HTTPException(404, "No active engagement.")
        ok = store.set_finding_notes(finding_id, payload.notes)
        if not ok:
            raise HTTPException(404, "Finding not found")
        return {"status": "saved", "finding_id": finding_id}

    @app.get("/api/engagement/findings/{finding_id}/evidence")
    async def get_finding_evidence(
        finding_id: str,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Full evidence package for a finding (request, response, repro)."""
        store = _read_store()
        if not store:
            raise HTTPException(404, "No active engagement.")
        f = store.get_finding(finding_id)
        if not f:
            raise HTTPException(404, "Finding not found")
        from heaven.devsecops.evidence import package_finding
        from heaven.devsecops.vuln_kb import enrich_finding
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "confidence_bucket": f.confidence_bucket, "cve_id": f.cve_id,
            "risk_score": f.risk_score, "status": f.status,
            "operator_notes": f.operator_notes, "evidence": f.evidence,
            # Real stored fields the UI detail table reads (previously omitted →
            # blank rows). risk_score doubles as the engine's CVSS-scale score.
            "predicted_cvss_score": f.risk_score or None,
            "priority_score": f.risk_score or None,
            "seen_count": f.seen_count, "last_seen_at": f.last_seen_at,
            "first_seen_at": f.first_seen_at,
        }
        # Enrich from the vuln knowledge base so description / remediation /
        # references / CWE / OWASP / MITRE / typical-CVSS are never blank.
        finding_dict = enrich_finding(finding_dict)
        # Show the SAME genuinely-per-finding CVSS the report renders: the real
        # published base score (persisted in evidence.cvss_base) via the one
        # shared resolver, so the web detail's CVSS row can never disagree with
        # the report or collapse onto a per-severity constant. risk_score stays
        # the priority number.
        from heaven.utils.cvss import contextual_score, objective_base_score
        # Tag the finding with its asset criticality (from engagement scope) so the
        # contextual score's environmental adjustment is real, not defaulted.
        with contextlib.suppress(Exception):
            crit = store.criticality_for_target(f.target)
            if crit:
                finding_dict["criticality"] = crit
        _obj_cvss = objective_base_score(finding_dict)
        if _obj_cvss > 0:
            finding_dict["predicted_cvss_score"] = round(_obj_cvss, 1)
        # The genuinely per-finding CVSS: base adjusted by exploit maturity (EPSS/
        # KEV/exploit), detection confidence and asset criticality + exposure.
        _ctx = contextual_score(finding_dict)
        if _ctx > 0:
            finding_dict["contextual_cvss_score"] = round(_ctx, 1)
        # Confirmation status (Confirmed vs Potential) for the detail meta table.
        finding_dict["confirmation"] = _confirmation_of(finding_dict)
        pkg = package_finding(finding_dict)
        return {
            "finding": finding_dict,
            "evidence_package": pkg.to_dict(),
            "markdown": pkg.to_markdown(),
        }

    # ── Risk Scores ──
    @app.get("/api/risk-scores")
    async def get_risk_scores(user: User = Depends(require_permission("vuln.view"))):
        data = _get_latest_report_data()
        vulns = data.get("vulnerabilities", [])
        scores = [
            {"id": v.get("cve_id") or v.get("title", ""), "score": v.get("risk_score", 0)}
            for v in vulns
        ]
        return {"scores": scores}

    # ── Report export (download) ──
    @app.get("/api/report/export")
    async def export_report(
        format: str = "html",
        engagement: Optional[str] = None,
        framework: str = "OWASP_TOP10",
        user: User = Depends(require_permission("report.view")),
    ):
        """Generate + download an engagement report. Reuses the exact reporters
        behind `heaven export` / `heaven report`, so CLI and webapp produce the
        same output. Formats: html, pdf, markdown, csv, json, sarif, burp,
        proxy-jsonl."""
        from fastapi import Response
        from fastapi.responses import FileResponse
        from heaven.devsecops.vuln_kb import enrich_finding

        store = _read_store(engagement)
        eng = store.get_engagement()
        eng_name = (eng.name if eng else None) or engagement or \
            os.environ.get("HEAVEN_ENGAGEMENT") or "HEAVEN Engagement"
        # Strip a stray .db (engagement may resolve from a DB filename) so the
        # downloaded report isn't named "heaven-report-foo.db.json".
        if eng_name.endswith(".db"):
            eng_name = eng_name[:-3]
        # Engagement metadata for the report cover: the tester lands in the
        # "Assessor" slot, the client in "Client". Empty fields are dropped so
        # the report derives sensible defaults.
        report_meta: dict[str, str] = {}
        report_tester = getattr(eng, "tester", "") if eng else ""
        if report_tester:
            report_meta["assessor"] = report_tester
        if eng and getattr(eng, "client", ""):
            report_meta["client"] = eng.client
        rows = store.list_findings(limit=10000)
        if not rows:
            raise HTTPException(404, "No findings to report for this engagement")
        # A finding triaged as a false positive is NOT part of the client
        # deliverable — drop it from every export format so it never appears in
        # the report after the operator flags it.
        rows = [r for r in rows if (r.status or "").lower() != "false_positive"]
        if not rows:
            raise HTTPException(
                404, "No reportable findings — every finding is marked "
                "false-positive (or none exist) for this engagement.")
        findings = []
        for f in rows:
            d = {
                "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                "title": f.title, "severity": f.severity, "confidence": f.confidence,
                "confidence_bucket": f.confidence_bucket, "cve_id": f.cve_id,
                "risk_score": f.risk_score, "predicted_cvss_score": f.risk_score,
                "priority_score": f.risk_score, "first_seen_at": f.first_seen_at,
                "last_seen_at": f.last_seen_at, "status": f.status,
                "operator_notes": f.operator_notes, "evidence": f.evidence,
            }
            # Surface the real per-finding CVSS base score + vector (persisted in
            # evidence) to the top level so EVERY export format — SARIF, Burp,
            # JSON — carries the true score, not just the HTML/PDF resolver.
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            if ev.get("cvss_base") is not None:
                d["cvss_base"] = ev["cvss_base"]
            if ev.get("cvss_vector"):
                d["cvss_vector"] = ev["cvss_vector"]
            # Tag the asset criticality (from engagement scope) so the report's
            # per-finding contextual CVSS applies a real environmental adjustment.
            with contextlib.suppress(Exception):
                crit = store.criticality_for_target(f.target)
                if crit and crit != "medium":
                    d["criticality"] = crit
            # Attach the genuinely per-finding contextual CVSS so machine exports
            # (JSON / SARIF / Burp) carry the same number the HTML/PDF report shows.
            with contextlib.suppress(Exception):
                from heaven.utils.cvss import contextual_score as _ctx
                _cv = _ctx(d)
                if _cv > 0:
                    d["contextual_cvss_score"] = round(_cv, 1)
            findings.append(enrich_finding(d))

        # Host/service inventory (open ports, versions, OS) for this engagement,
        # so HTML/PDF/Markdown reports document the attack surface, not just the
        # findings. Empty for engagements with no network scan.
        raw_assets = _collect_raw_assets(engagement)
        # DNS enumeration (records + subdomains) for the report's DNS section.
        raw_dns = _collect_raw_dns(engagement)

        fmt = (format or "html").lower()
        media = {
            "html": "text/html", "markdown": "text/markdown", "csv": "text/csv",
            "json": "application/json", "sarif": "application/json",
            "junit": "application/xml",
            "burp": "application/xml", "proxy-jsonl": "application/x-ndjson",
        }
        ext = {"markdown": "md", "proxy-jsonl": "jsonl", "junit": "xml"}
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", eng_name)[:60] or "engagement"
        # A recognised compliance framework id (hipaa, uk_gdpr, …) adds a mapped
        # control-coverage section to the html/pdf/markdown deliverables; anything
        # else (the OWASP_TOP10 default) leaves the standard report unchanged.
        from heaven.devsecops import compliance_frameworks as _cf
        compliance_fw = framework if _cf.is_compliance_framework(framework) else None
        if compliance_fw:
            safe = f"{safe}-{compliance_fw}"
        try:
            if fmt == "pdf":
                import importlib.util
                if importlib.util.find_spec("reportlab") is None:
                    raise HTTPException(
                        503, "PDF export needs reportlab — `pip install reportlab`. "
                        "Use HTML/Markdown export, which need no extra dependency.")
                import tempfile

                from starlette.background import BackgroundTask
                from heaven.devsecops.pdf_report import PDFReportGenerator
                tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
                tmp.close()
                # strict=True → a real build error is raised (with its message)
                # instead of silently falling back to an empty .pdf and the old,
                # misleading "reportlab installed?" — reportlab is confirmed above.
                try:
                    PDFReportGenerator().generate(
                        {"engagement": eng_name, "vulnerabilities": findings,
                         "findings": findings, "assets": raw_assets,
                         "dns_records": raw_dns, "tester": report_tester,
                         "client": report_meta.get("client", ""),
                         "compliance_framework": compliance_fw}, tmp.name, strict=True)
                except Exception as exc:  # noqa: BLE001
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
                    logger.exception("PDF report generation failed")
                    raise HTTPException(500, f"PDF generation failed: {exc}") from exc
                if not os.path.getsize(tmp.name):
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
                    raise HTTPException(500, "PDF generation produced an empty file")
                # Delete the temp file once the response has been streamed.
                return FileResponse(tmp.name, media_type="application/pdf",
                                    filename=f"heaven-report-{safe}.pdf",
                                    background=BackgroundTask(_safe_unlink, tmp.name))
            if fmt == "html":
                from heaven.devsecops.compliance_report import ComplianceReportGenerator
                body = ComplianceReportGenerator().generate_html_report(
                    findings, engagement_name=eng_name, assets=raw_assets,
                    dns_records=raw_dns, compliance_framework=compliance_fw,
                    meta=report_meta or None)
            elif fmt == "markdown":
                from heaven.devsecops.evidence import export_findings_markdown
                body = export_findings_markdown(findings, engagement_name=eng_name,
                                                assets=raw_assets, dns_records=raw_dns,
                                                compliance_framework=compliance_fw)
            elif fmt == "csv":
                from heaven.devsecops.evidence import export_findings_csv
                body = export_findings_csv(findings)
            elif fmt == "json":
                body = json.dumps(findings, indent=2, default=str)
            elif fmt == "sarif":
                from heaven.devsecops.ci_export import findings_to_sarif_str
                body = findings_to_sarif_str(findings, engagement_name=eng_name)
            elif fmt == "junit":
                from heaven.devsecops.ci_export import findings_to_junit
                body = findings_to_junit(findings, engagement_name=eng_name)
            elif fmt == "burp":
                from heaven.devsecops.burp_export import export_burp_xml
                body = export_burp_xml(findings, engagement_name=eng_name)
            elif fmt == "proxy-jsonl":
                from heaven.devsecops.burp_export import export_proxy_history_jsonl
                body = export_proxy_history_jsonl(findings)
            else:
                raise HTTPException(400, f"unsupported format: {fmt}")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"report generation failed: {e}")
        filename = f"heaven-report-{safe}.{ext.get(fmt, fmt)}"
        return Response(content=body, media_type=media.get(fmt, "text/plain"),
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # ── Change password (forced-change flow) ──
    @app.post("/api/auth/change-password")
    async def change_password(body: dict, user: User = Depends(require_user)):
        """Change the current user's password; clears the forced-change flag.

        The AuthManager is in-memory, so for the env-backed admin account we also
        persist the new password to `.env` (HEAVEN_ADMIN_PASSWORD). That way the
        change survives a server restart — `heaven serve` re-reads `.env` on boot
        — instead of silently reverting to the old value or to admin/admin.
        """
        am = get_auth_manager()
        current = (body or {}).get("current_password", "")
        new = (body or {}).get("new_password", "")
        if not am.verify_user_password(user.username, current):
            raise HTTPException(401, "Current password is incorrect")
        try:
            am.set_password(user.username, new)
        except ValueError as e:
            raise HTTPException(422, str(e))

        # Persist to .env for the env-backed admin account (the only one mapped
        # to HEAVEN_ADMIN_PASSWORD). Never fail the change on a write error — the
        # in-memory update already succeeded.
        persisted = False
        admin_username = os.environ.get("HEAVEN_ADMIN_USERNAME", "admin")
        if user.username == admin_username:
            try:
                from heaven.utils.env_file import resolve_env_path, set_env_var
                env_path = resolve_env_path()
                set_env_var(env_path, "HEAVEN_ADMIN_PASSWORD", new)
                # Keep the running process consistent if the manager is rebuilt.
                os.environ["HEAVEN_ADMIN_PASSWORD"] = new
                persisted = True
                logger.info("Admin password change persisted to %s", env_path)
            except Exception as e:  # noqa: BLE001
                logger.warning("Password changed in memory but .env persist failed: %s", e)

        return {"ok": True, "message": "Password changed", "persisted": persisted}

    # ══════════════════════════════════════════════════════════════════
    # Settings — API keys & integrations (the web-UI Settings page)
    # ══════════════════════════════════════════════════════════════════
    # One catalog (heaven/settings_catalog.py) backs the CLI, the wizard and
    # this page. Writes land in .env + os.environ, so a key entered in the
    # browser is live immediately, survives a restart, and the next CLI command
    # sees it too. Secrets are returned masked only — never in full.

    @app.get("/api/settings")
    async def get_settings(user: User = Depends(require_permission("config.modify"))):
        """List every configurable key, its group/help/where-to-get link, and
        whether it's currently set (secrets masked)."""
        from heaven.settings_catalog import catalog_status
        return catalog_status()

    @app.post("/api/settings")
    async def update_settings(
        body: dict, user: User = Depends(require_permission("config.modify")),
    ):
        """Persist ``{key: value}`` updates. Empty value unsets the key.

        Unknown keys are rejected (422). Returns the changed keys + fresh status.
        """
        from heaven.settings_catalog import apply_settings
        updates = (body or {}).get("settings", body) or {}
        if not isinstance(updates, dict):
            raise HTTPException(422, "expected a JSON object of {key: value}")
        try:
            result = apply_settings({str(k): ("" if v is None else str(v))
                                     for k, v in updates.items()})
        except ValueError as e:
            raise HTTPException(422, str(e))
        logger.info("Settings updated by %s: %s", user.username, result["changed"])
        return {"ok": True, **result}

    @app.post("/api/settings/test-llm")
    async def test_llm(user: User = Depends(require_permission("config.modify"))):
        """Live-test the current LLM configuration end to end.

        Confirms a provider/key/SDK are present *and* makes one tiny real
        completion, because "key present + SDK importable" is not the same as
        "the model actually answers" — a wrong key, a retired model, or a
        provider-side block all pass the cheap check but return nothing. This is
        the difference between the Settings page saying "ready" and the AI
        features actually working.
        """
        try:
            from heaven.ai.llm_gateway import LLMGateway, LLMRequest, reset_gateway
            reset_gateway()  # pick up any just-saved key
            gw = LLMGateway()
            if not gw.available:
                # Provider-aware reason: a keyless local provider that isn't
                # configured/reachable must not report "no key". gw._init_error
                # already carries the precise local reason (endpoint/model).
                if gw._init_error:
                    reason = gw._init_error
                elif not gw.provider:
                    reason = "no provider configured — add a key or run `heaven ai setup`"
                elif not (gw.api_key or getattr(gw, "_is_local", False)):
                    reason = "no API key configured for this provider"
                else:
                    reason = "provider SDK not installed (pip install the provider extra)"
                return {
                    "provider": gw.provider or None, "model": gw.model or None,
                    "available": False, "reason": reason,
                }
            resp = await gw.acomplete(LLMRequest(
                prompt="Reply with exactly the word: OK", max_tokens=16, temperature=0,
            ))
            if resp.ok():
                return {"provider": gw.provider, "model": gw.model, "available": True,
                        "reason": f"ready — live reply in {resp.latency_ms:.0f}ms"}
            return {"provider": gw.provider, "model": gw.model, "available": False,
                    "reason": f"configured but the live call failed: {resp.error or 'empty response'}"}
        except Exception as e:  # noqa: BLE001
            return {"provider": None, "model": None, "available": False,
                    "reason": f"error: {e}"}

    @app.post("/api/settings/test-nvd")
    async def test_nvd(user: User = Depends(require_permission("config.modify"))):
        """Live-test NVD connectivity and the configured API key.

        Makes one real lookup so the operator can confirm the key works (and CVE
        enrichment will return results) instead of discovering empty scans later.
        Distinguishes 'key valid', 'key rejected', and 'no key / slow tier'.
        """
        try:
            from heaven.vulnscan.nvd_client import NVDClient
            client = NVDClient()
            try:
                return await client.test_connectivity()
            finally:
                await client.close()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "has_key": False, "status_code": None,
                    "sample_results": None, "reason": f"error: {e}"}

    # ══════════════════════════════════════════════════════════════════
    # Self-update — check for + apply a newer HEAVEN from the web app
    # ══════════════════════════════════════════════════════════════════
    # Reuses the exact, unit-tested core behind `heaven update` (git-checkout
    # aware, fast-forward only, never overwrites uncommitted work). Detection is
    # available to any signed-in user; applying is admin-only (config.modify).

    @app.get("/api/update/status")
    async def update_status(
        fetch: bool = True,
        user: User = Depends(require_permission("scan.view")),
    ):
        """Is a newer HEAVEN available? ``fetch=false`` skips the network hop.

        Adds ``current_version``, the auto-check preference, and ``can_apply``
        (a git checkout, not dirty, and no apply already running) so the UI knows
        whether to offer 'Update now'. Never raises — a non-git install or an
        offline remote returns an honest, non-error payload.
        """
        from heaven.cli import update as _upd
        auto_check = (os.environ.get("HEAVEN_UPDATE_AUTO_CHECK") or "").strip().lower() == "on"
        web_apply = _web_update_apply_enabled()
        root = _upd.find_repo_root()
        if root is None:
            return {
                "is_git": False, "available": False, "can_apply": False,
                "web_apply_enabled": web_apply,
                "reason": "not an editable git checkout, so it can't self-update in place",
                "current_version": __version__, "auto_check": auto_check,
                "apply_running": _update_apply_state["running"],
            }
        try:
            check = await asyncio.to_thread(_upd.check_for_update, root, fetch=fetch)
        except Exception as e:  # noqa: BLE001 — status must never 500
            return {"is_git": True, "available": False, "can_apply": False,
                    "web_apply_enabled": web_apply,
                    "error": f"update check failed: {e}",
                    "current_version": __version__, "auto_check": auto_check,
                    "apply_running": _update_apply_state["running"]}
        d = check.to_dict()
        d["current_version"] = d.get("current_version") or __version__
        d["auto_check"] = auto_check
        d["apply_running"] = _update_apply_state["running"]
        d["web_apply_enabled"] = web_apply
        d["can_apply"] = bool(
            web_apply
            and check.is_git and check.available and check.remote_reachable
            and not check.dirty and not _update_apply_state["running"])
        return d

    @app.post("/api/update/apply")
    async def update_apply(
        body: Optional[dict] = None,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Apply the code update in the background (admin only).

        Fast-forwards the checkout to the fetched remote and reinstalls / rebuilds
        only what changed — never a merge/rebase/reset, never overwriting
        uncommitted work (``force`` auto-stashes non-destructively). Returns a
        ``job_id``; poll ``/api/update/apply/status`` for the live log. The server
        keeps running the old code until it's restarted — the response says so.
        """
        from heaven.cli import update as _upd
        body = body or {}
        force = bool(body.get("force"))
        skip_ui = bool(body.get("skip_ui"))
        # Deploy-time kill switch (see _web_update_apply_enabled). Enforced here
        # too — not only hidden in the UI — so bypassing the button can't apply.
        if not _web_update_apply_enabled():
            raise HTTPException(
                403, "Applying updates from the web app is disabled on this server "
                "(HEAVEN_DISABLE_WEB_UPDATE). Run `heaven update` from the shell, or "
                "unset that variable and restart to allow web-based updates.")
        if _update_apply_state["running"]:
            raise HTTPException(409, "an update is already in progress")
        root = _upd.find_repo_root()
        if root is None:
            raise HTTPException(
                400, "This HEAVEN isn't an editable git checkout, so it can't "
                "self-update in place. Update via git pull / Docker / release.")
        check = await asyncio.to_thread(_upd.check_for_update, root)
        if not check.is_git:
            raise HTTPException(400, check.reason or "not an updatable git checkout")
        if not check.remote_reachable:
            raise HTTPException(503, f"couldn't reach the remote: {check.error or 'offline?'}")
        if not check.available:
            raise HTTPException(409, f"already up to date (v{check.current_version or '?'})")
        if check.dirty and not force:
            raise HTTPException(
                409, f"{len(check.dirty_files)} uncommitted change(s) on the server — "
                "refusing to overwrite them. Commit/stash them, or retry with force.")

        job_id = uuid.uuid4().hex[:12]
        _update_apply_state.update({
            "running": True, "done": False, "ok": False, "log": [],
            "result": None, "job_id": job_id, "started_at": time.time(),
        })

        def _log(msg: str) -> None:
            _update_apply_state["log"].append(msg)
            logger.info("update.apply: %s", msg)

        async def _run() -> None:
            try:
                _log(f"Updating v{check.current_version or '?'} → "
                     f"v{check.latest_version or '?'} ({check.behind} commit(s))…")
                res = await asyncio.to_thread(
                    _upd.apply_code_update, root, check, force=force, skip_ui=skip_ui)
                for n in res.notes:
                    _log(n)
                _update_apply_state["result"] = res.to_dict()
                _update_apply_state["ok"] = bool(res.applied and not res.error)
                if res.applied:
                    _log(f"✓ Updated to v{res.to_version or '?'}. Restart `heaven serve` "
                         "to run the new code.")
                else:
                    _log(f"⚠ {res.error or 'update did not apply'}")
            except Exception as e:  # noqa: BLE001 — surface, never crash the worker
                _log(f"error: {e}")
                _update_apply_state["ok"] = False
            finally:
                _update_apply_state["running"] = False
                _update_apply_state["done"] = True

        _apply_task = asyncio.create_task(_run())
        _update_apply_tasks.add(_apply_task)
        _apply_task.add_done_callback(_update_apply_tasks.discard)
        logger.info("Code update launched by %s (job %s)", user.username, job_id)
        return {"job_id": job_id, "running": True,
                "from_version": check.current_version, "to_version": check.latest_version}

    @app.get("/api/update/apply/status")
    async def update_apply_status(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Live state of the in-flight (or last) code update: running / done / ok
        / log lines / the CodeUpdateResult."""
        s = _update_apply_state
        return {"running": s["running"], "done": s["done"], "ok": s["ok"],
                "log": list(s["log"]), "result": s["result"], "job_id": s["job_id"]}

    # ── Egress / anonymity (TOR / VPN / WireGuard) ──────────────────────────
    # The dashboard stays local; these control how *scanning* traffic leaves the
    # host. Config lives in the shared settings catalog (persisted to .env);
    # these endpoints add the live actions: confirm the exit IP (leak check) and
    # raise/drop the WireGuard tunnel.

    @app.get("/api/egress")
    async def egress_status(user: User = Depends(require_permission("config.modify"))):
        """Current egress mode, kill-switch, tool availability and (for
        WireGuard) tunnel status — a synchronous snapshot, no network calls."""
        from heaven.net import egress as _egress
        return _egress.status()

    @app.post("/api/egress/confirm")
    async def egress_confirm(user: User = Depends(require_permission("config.modify"))):
        """Fetch the apparent public IP *through* the active egress and compare
        it to the direct baseline — the leak check. Reaches out to a public
        IP-echo service, so it takes a few seconds."""
        from heaven.net import egress as _egress
        try:
            return await _egress.confirm_egress(timeout=12.0)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "detail": f"error: {e}", "mode": None}

    @app.post("/api/egress/tunnel")
    async def egress_tunnel(
        body: dict, user: User = Depends(require_permission("config.modify")),
    ):
        """Raise or drop the WireGuard tunnel. Body: ``{"action": "up"|"down"}``.
        Needs a configured ``HEAVEN_WG_CONFIG`` and root for ``wg-quick`` (via the
        passwordless-sudo policy). Runs in a worker thread — wg-quick is blocking."""
        from heaven.net import egress as _egress
        action = str((body or {}).get("action", "")).strip().lower()
        if action not in ("up", "down"):
            raise HTTPException(422, "action must be 'up' or 'down'")
        fn = _egress.tunnel_up if action == "up" else _egress.tunnel_down
        result = await asyncio.to_thread(fn)
        logger.info("Egress tunnel %s by %s: %s", action, user.username, result)
        return result

    @app.get("/api/ai/local/status")
    async def ai_local_status(user: User = Depends(require_permission("config.modify"))):
        """Local-LLM runtime status for the Settings 'Local AI' card + Health:
        is Ollama installed / reachable, which models are pulled, the recommended
        default. Read-only; heavy pulls stay on the CLI (`heaven ai pull`)."""
        from heaven.ai import local_llm
        provider = (os.environ.get("HEAVEN_LLM_PROVIDER") or "").lower()
        base = os.environ.get("HEAVEN_LLM_BASE_URL", "") if provider == "local" else ""
        try:
            return local_llm.local_status(provider="local" if provider == "local" else "ollama",
                                          base_url=base)
        except Exception as e:  # noqa: BLE001 — status must never 500
            return {"provider": provider or "ollama", "installed": None,
                    "reachable": False, "host": "", "models": [],
                    "default_model": local_llm.DEFAULT_OLLAMA_MODEL, "recommended": [],
                    "error": str(e)}

    @app.get("/api/ai/models")
    async def ai_models(
        refresh: bool = False,
        user: User = Depends(require_permission("config.modify")),
    ):
        """The model catalog for the Settings model picker — dynamic, not static.

        Per provider HEAVEN discovers the models the operator's key/endpoint will
        actually serve by querying that provider's live "list models" API, then
        merges them with a curated short-list (which supplies friendly labels, the
        note text, and the recommended default). So the picker shows every current
        Claude / GPT / Gemini / DeepSeek model and every locally-pulled Ollama tag,
        not just a hand-picked few. Live discovery only runs where it can succeed
        (a keyed cloud provider, or a keyless local runtime); otherwise the curated
        list stands. Every failure degrades to curated — the picker is never empty,
        and a custom id is always allowed. `refresh=1` bypasses the short cache.

        Response per provider: {models:[{id,label,note,recommended?}], default,
        keyless, source:'live'|'catalog'|'curated', live_count}. `source` is
        'live' when discovered from the operator's key/endpoint, 'catalog' when it
        fell back to the broader offline known roster (no key yet), and 'curated'
        for the short-list only. Also returns the active provider + model override
        so the UI can preselect them.
        """
        from heaven.ai import llm_gateway as _gw
        provider = (os.environ.get("HEAVEN_LLM_PROVIDER") or "").lower()
        model = (os.environ.get("HEAVEN_LLM_MODEL") or "").strip()
        prov_names = ("anthropic", "openai", "gemini", "deepseek", "ollama", "local")

        async def _one(p: str) -> tuple[str, dict[str, Any]]:
            # One resolver (shared with the CLI) does the live→catalog→curated
            # ladder. The blocking discovery call runs off the event loop.
            merged, source, live_count = await asyncio.to_thread(
                _gw.resolve_picker_models, p, None, use_cache=not refresh)
            return p, {
                "models": merged,
                "default": _gw.PROVIDER_DEFAULT_MODELS.get(p, ""),
                "keyless": p in _gw.LOCAL_PROVIDERS,
                "source": source,
                "live_count": live_count,
            }

        # Discover every provider concurrently so the picker never waits on the
        # sum of the round-trips, only the slowest one (each is bounded).
        results = await asyncio.gather(*[_one(p) for p in prov_names])
        providers = {p: info for p, info in results}
        return {"provider": provider, "model": model, "providers": providers,
                "provider_default": _gw.PROVIDER_DEFAULT_MODELS.get(provider, "")}

    @app.post("/api/ai/local/configure")
    async def ai_local_configure(
        request: Request, user: User = Depends(require_permission("config.modify")),
    ):
        """Point HEAVEN's LLM at a local model in one click (Settings wizard).

        Body: {provider:'ollama'|'local', model?, host?, base_url?}. Persists the
        config via the same settings pipeline the CLI uses (so it's live
        everywhere and survives restart), resets the gateway, then makes one tiny
        real completion so the UI can confirm 'Local AI is live' rather than just
        'saved'. Never installs or pulls here — pulls stream over the WS below.
        """
        from heaven.ai import local_llm
        from heaven.settings_catalog import apply_settings
        try:
            body = await request.json()
        except Exception:
            body = {}
        provider = str((body or {}).get("provider") or "ollama").lower()
        if provider not in ("ollama", "local"):
            raise HTTPException(422, "provider must be 'ollama' or 'local'")
        model = str((body or {}).get("model") or "").strip()
        updates: dict[str, str] = {"HEAVEN_LLM_PROVIDER": provider}
        if provider == "ollama":
            model = model or local_llm.DEFAULT_OLLAMA_MODEL
            host = str((body or {}).get("host") or local_llm.ollama_host()).strip()
            updates["HEAVEN_LLM_MODEL"] = model
            updates["HEAVEN_OLLAMA_HOST"] = host
        else:  # local / OpenAI-compatible
            base_url = str((body or {}).get("base_url") or "").strip()
            if not base_url:
                raise HTTPException(422, "base_url is required for provider 'local'")
            if not model:
                raise HTTPException(422, "model is required for provider 'local'")
            updates["HEAVEN_LLM_BASE_URL"] = base_url
            updates["HEAVEN_LLM_MODEL"] = model
        try:
            apply_settings(updates)  # writes .env + os.environ, resets the gateway
        except ValueError as e:
            raise HTTPException(422, str(e))
        # Live self-test so setup ends with proof, not just a saved file.
        test: dict[str, Any] = {"available": False, "reason": ""}
        try:
            from heaven.ai.llm_gateway import LLMGateway, LLMRequest, reset_gateway
            reset_gateway()
            gw = LLMGateway()
            if not gw.available:
                test["reason"] = gw._init_error or "gateway not ready"
            else:
                resp = await gw.acomplete(LLMRequest(
                    prompt="Reply with exactly the word: OK", max_tokens=16, temperature=0))
                test = {"available": bool(resp.ok()),
                        "reason": (f"live reply in {resp.latency_ms:.0f}ms" if resp.ok()
                                   else (resp.error or "empty response")),
                        "latency_ms": resp.latency_ms}
        except Exception as e:  # noqa: BLE001 — a failed test must not fail the save
            test = {"available": False, "reason": f"error: {e}"}
        provider_for_status = "local" if provider == "local" else "ollama"
        base = updates.get("HEAVEN_LLM_BASE_URL", "")
        return {"ok": True, "provider": provider, "model": model, "test": test,
                "status": local_llm.local_status(provider=provider_for_status, base_url=base)}

    @app.websocket("/api/ai/local/pull")
    async def ai_local_pull(websocket: WebSocket, token: Optional[str] = Query(None)):
        """Stream an Ollama model pull to the Settings wizard so a user can get a
        local model entirely from the browser — no terminal.

        Auth via `token` query param (browsers can't set WS headers). Client sends
        {model}; server relays Ollama's native streaming ``/api/pull`` as
        {type:'progress', status, percent, completed, total} frames, then
        {type:'done', ok, models}. A dead/absent Ollama server fails fast with a
        friendly {type:'error'} instead of hanging.
        """
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            session = auth._sessions[token]
            if session.expires_at < time.time():
                await websocket.close(code=4401, reason="Token expired")
                return
        await websocket.accept()
        from heaven.ai import local_llm
        try:
            raw = await websocket.receive_json()
        except Exception:
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "error": "expected {model}"})
                await websocket.close()
            return
        model = str((raw or {}).get("model") or "").strip()
        if not model:
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "error": "no model specified"})
                await websocket.close()
            return
        host = local_llm.ollama_host()
        ok = False
        try:
            import httpx
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=None)) as client:
                async with client.stream("POST", f"{host}/api/pull",
                                         json={"model": model, "stream": True}) as resp:
                    if resp.status_code >= 400:
                        await resp.aread()
                        raise RuntimeError(f"Ollama returned HTTP {resp.status_code}")
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                        except ValueError:
                            continue
                        frame = local_llm.pull_progress_frame(data)
                        if frame["error"]:
                            with contextlib.suppress(Exception):
                                await websocket.send_json({"type": "error", "error": frame["error"]})
                            break
                        await websocket.send_json({"type": "progress", **frame})
                        if frame["done"] and frame["status"].lower() == "success":
                            ok = True
        except WebSocketDisconnect:
            return
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.PoolTimeout):
            with contextlib.suppress(Exception):
                await websocket.send_json({
                    "type": "error",
                    "error": f"Ollama not reachable at {host} — is it running? "
                             "(open the Ollama app, or run `ollama serve`)"})
        except Exception as e:  # noqa: BLE001 — never crash the socket worker
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "error": str(e)})
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "done", "ok": ok,
                                       "models": local_llm.list_models()})
            await websocket.close()

    # ══════════════════════════════════════════════════════════════════
    # AI security assistant (chatbot) — local or cloud, engagement-grounded
    # ══════════════════════════════════════════════════════════════════

    @app.post("/api/chat")
    async def chat_reply(
        request: Request, user: User = Depends(require_permission("vuln.view")),
    ):
        """One grounded reply from the AI security assistant.

        Body: {messages:[{role,content}], engagement?, grounded?:bool, max_tokens?}.
        Works with any configured provider (local Ollama / OpenAI-compatible /
        cloud). Returns {skipped: reason} when no LLM is configured so the UI can
        show a friendly 'set up local AI' hint instead of erroring.
        """
        try:
            body = await request.json()
        except Exception:
            body = {}
        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            raise HTTPException(422, "expected non-empty 'messages': [{role, content}]")
        grounded = bool(body.get("grounded", True))
        from heaven.ai.chat_assistant import ChatAssistant
        assistant = ChatAssistant()
        if not assistant.available:
            gw = assistant.gateway
            return {"skipped": gw._init_error or
                    "no LLM configured — add a key or run `heaven ai setup`",
                    "provider": gw.provider or None, "model": gw.model or None}
        store = _read_store(body.get("engagement")) if grounded else None
        resp = await asyncio.to_thread(
            assistant.reply, messages, store=store, include_context=grounded,
            max_tokens=int(body.get("max_tokens") or 1024),
        )
        if not resp.ok():
            return {"skipped": resp.error or "the model returned no text",
                    "provider": resp.provider, "model": resp.model}
        return {"reply": resp.text, "provider": resp.provider, "model": resp.model,
                "grounded": bool(store is not None), "latency_ms": resp.latency_ms}

    @app.websocket("/api/chat/stream")
    async def chat_stream(websocket: WebSocket, token: Optional[str] = Query(None)):
        """Streaming AI assistant. Auth via `token` query param (browsers can't
        set WS headers). Client sends one JSON {messages, engagement?, grounded?,
        max_tokens?}; server streams {type:'delta', text} frames, then 'done'."""
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            session = auth._sessions[token]
            if session.expires_at < time.time():
                await websocket.close(code=4401, reason="Token expired")
                return
        await websocket.accept()
        try:
            raw = await websocket.receive_json()
        except Exception:
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "error": "expected a JSON message"})
                await websocket.close()
            return
        messages = raw.get("messages") or []
        grounded = bool(raw.get("grounded", True))
        from heaven.ai.chat_assistant import ChatAssistant
        assistant = ChatAssistant()
        gw = assistant.gateway
        if not assistant.available:
            with contextlib.suppress(Exception):
                await websocket.send_json({
                    "type": "skipped",
                    "error": gw._init_error or
                    "no LLM configured — add a key or run `heaven ai setup`",
                    "provider": gw.provider or None, "model": gw.model or None})
                await websocket.close()
            return
        store = _read_store(raw.get("engagement")) if grounded else None
        got = False
        try:
            await websocket.send_json({"type": "start", "provider": gw.provider,
                                       "model": gw.model, "grounded": bool(store is not None)})
            async for piece in assistant.astream(
                messages, store=store, include_context=grounded,
                max_tokens=int(raw.get("max_tokens") or 1024),
            ):
                got = True
                await websocket.send_json({"type": "delta", "text": piece})
        except WebSocketDisconnect:
            return
        except Exception as e:  # noqa: BLE001 — never crash the socket worker
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "error": str(e)})
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "done", "empty": not got})
            await websocket.close()

    # ══════════════════════════════════════════════════════════════════
    # "Fix this first" — highest-risk findings + remediation
    # ══════════════════════════════════════════════════════════════════

    @app.get("/api/engagement/top-findings")
    async def engagement_top_findings(
        limit: int = Query(5, ge=1, le=25),
        user: User = Depends(require_permission("vuln.view")),
    ):
        """The 'fix this first' list — findings ranked by risk_score (then
        severity), each with a one-line remediation so an operator knows the
        highest-impact next action at a glance."""
        from heaven.devsecops.vuln_kb import component_remediation
        from heaven.devsecops.vuln_kb import lookup as kb_lookup
        store = _read_store()
        results = store.list_findings(limit=2000)
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        results.sort(
            key=lambda f: (
                float(getattr(f, "risk_score", 0) or 0),
                sev_rank.get((getattr(f, "severity", "") or "").lower(), 0),
            ),
            reverse=True,
        )
        top = []
        for f in results[:limit]:
            ev = getattr(f, "evidence", {}) or {}
            # Prefer a stored remediation; otherwise build one. For a CVE/component
            # finding, generate the per-CVE remediation (naming the actual product
            # + CVE + weakness class) so the "fix this first" list never shows the
            # same generic component boilerplate for every different CVE.
            remediation = ev.get("remediation") or ""
            if not remediation:
                remediation = component_remediation({
                    "vuln_type": getattr(f, "vuln_type", ""),
                    "cve_id": getattr(f, "cve_id", ""),
                    "title": getattr(f, "title", ""),
                    "evidence": ev,
                })
            if not remediation:
                remediation = kb_lookup(getattr(f, "vuln_type", "")).get("remediation") or ""
            top.append({
                "id": getattr(f, "id", ""),
                "title": getattr(f, "title", ""),
                "severity": getattr(f, "severity", ""),
                "vuln_type": getattr(f, "vuln_type", ""),
                "target": getattr(f, "target", ""),
                "risk_score": getattr(f, "risk_score", 0),
                "confidence": getattr(f, "confidence", 0),
                "confirmation": _confirmation_of(f),
                "remediation": remediation,
            })
        return {"findings": top, "total": len(results)}

    # ══════════════════════════════════════════════════════════════════
    # System health — the web-UI equivalent of `heaven doctor`
    # ══════════════════════════════════════════════════════════════════

    @app.get("/api/system/health")
    async def system_health(user: User = Depends(require_permission("scan.view"))):
        """Web-UI System Health — mirrors `heaven doctor`.

        Reports external tools (with install hints), optional integrations, which
        API keys are configured (masked), Python module health, and actionable
        next steps — so an operator can see at a glance whether a capability is
        missing vs. genuinely broken.
        """
        from heaven.cli.status import _collect_status, _next_steps
        from heaven.cli._helpers import check_module_health
        from heaven.settings_catalog import catalog_status
        from heaven.utils.tool_installer import TOOLS, install_hint, is_present

        report = _collect_status(None)
        # Enrich external tools with purpose + platform-aware install hint, both
        # sourced from the shared catalog so the panel matches `heaven doctor`
        # and `heaven install-tools` exactly (no drift between hint strings).
        tools = []
        for spec in TOOLS:
            present = is_present(spec.name)
            tools.append({
                "name": spec.name, "present": present,
                "purpose": spec.purpose,
                "hint": "" if present else install_hint(spec),
            })
        report["tools"] = tools
        # The one command that installs every missing tool at once — surfaced as
        # a copy-paste call-to-action in the System-Health panel.
        report["install_command"] = "heaven install-tools"
        report["tools_missing"] = sum(1 for t in tools if not t["present"])
        report["modules"] = check_module_health()
        report["settings"] = catalog_status()
        # Strip Rich markup so the UI gets plain strings.
        report["next_steps"] = [
            re.sub(r"\[/?[^\]]+\]", "", s) for s in _next_steps(report)
        ]
        return report

    # ══════════════════════════════════════════════════════════════════
    # Demo / sample data — "Load sample data" button on a fresh install
    # ══════════════════════════════════════════════════════════════════

    @app.post("/api/demo/seed")
    async def seed_demo_data(user: User = Depends(require_permission("scan.create"))):
        """Populate the active engagement with realistic sample findings.

        Backs the web-UI "Load sample data" button so a fresh install shows a
        full dashboard instantly. Writes to the same store the dashboard reads;
        idempotent (content-hashed IDs dedupe). Shares its data with
        `heaven demo` via heaven/demo.py.
        """
        from heaven.demo import seed_demo
        from heaven.engagement import DEMO_DB_NAME
        # Sample data goes into its OWN engagement DB and we switch to it — never
        # into a real engagement (which used to leave a stray "demo (sample data)"
        # row behind that then leaked into the dashboard label + report filename).
        store = _engagement_store_factory(DEMO_DB_NAME)
        result = seed_demo(store)
        _set_active_engagement(DEMO_DB_NAME)
        logger.info("Demo data seeded by %s: %s findings", user.username,
                    result.get("findings"))
        return {"ok": True, **result}

    @app.post("/api/demo/scan")
    async def run_demo_scan(user: User = Depends(require_permission("scan.create"))):
        """Run an animated demo scan so a new user experiences the full loop.

        Streams realistic phase progress through ``active_scans`` (so the Scans
        page shows it run live, like a real scan), then lands the sample findings
        under its own scan id. Offline and safe — nothing is sent to any target.
        """
        scan_id = f"demo-scan-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        active_scans[scan_id] = {
            "scan_id": scan_id, "status": "running", "progress_pct": 0,
            "name": "Demo scan (sample)", "mode": "full", "created": now,
            "phase": "Starting", "findings_count": 0, "demo": True,
        }

        # Per-phase delay (seconds). Overridable so tests can run it instantly.
        try:
            phase_delay = float(os.environ.get("HEAVEN_DEMO_SCAN_DELAY", "2.2"))
        except ValueError:
            phase_delay = 2.2

        async def _run() -> None:
            from heaven.demo import insert_findings
            from heaven.engagement import DEMO_DB_NAME
            # Dedicated demo engagement — see seed_demo_data above.
            store = _engagement_store_factory(DEMO_DB_NAME)
            _set_active_engagement(DEMO_DB_NAME)
            try:
                store.record_scan_start(scan_id, name="Demo scan (sample)", mode="full")
                phases = [
                    ("Reconnaissance", 20), ("Crawling endpoints", 45),
                    ("Injection testing", 70), ("Risk scoring + reporting", 90),
                ]
                for i, (label, pct) in enumerate(phases):
                    await asyncio.sleep(phase_delay)
                    if active_scans.get(scan_id, {}).get("status") == "cancelled":
                        return
                    active_scans[scan_id]["phase"] = label
                    active_scans[scan_id]["progress_pct"] = pct
                    # Remaining phases × per-phase delay → a real time-to-complete.
                    active_scans[scan_id]["eta_s"] = round((len(phases) - i - 1) * phase_delay)
                res = insert_findings(store, scan_id)
                store.record_scan_complete(scan_id, res["summary"])
                active_scans[scan_id].update(
                    status="completed", progress_pct=100, phase="Done",
                    eta_s=0, findings_count=res["findings"],
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Demo scan failed: %s", e)
                if scan_id in active_scans:
                    active_scans[scan_id].update(status="failed", phase=str(e))

        task = asyncio.create_task(_run())
        _background_scan_tasks.add(task)
        task.add_done_callback(lambda t: _background_scan_tasks.discard(t))
        return {"ok": True, "scan_id": scan_id, "message": "Demo scan started"}

    # ══════════════════════════════════════════════════════════════════
    # New API surface — exposes the publication-gap features to the UI
    # ══════════════════════════════════════════════════════════════════

    # ── Gap 8: Reproducibility — replay a completed scan ──

    @app.post("/api/scans/{scan_id}/replay")
    async def replay_scan(
        scan_id: str, request: Request,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Re-execute a stored scan deterministically (uses stored --seed if set).

        Body (optional JSON): {"engagement": "name", "new_engagement": "name"}
        Returns: {"new_scan_id": "..."}
        """
        try:
            from heaven.engagement import EngagementStore
            from heaven.orchestrator import build_full_scan
            from heaven.utils.seeding import set_seed
            from heaven.config import get_config
            from heaven.cli._helpers import _engagement_db_path
        except Exception as e:
            raise HTTPException(500, f"replay subsystem unavailable: {e}")

        body: dict = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        engagement = body.get("engagement")
        new_engagement = body.get("new_engagement", "")
        # Both become DB filenames — reject traversal. (`engagement` also flows
        # through the factory guard, but validate here for a clean 400.)
        _validate_http_engagement(engagement)
        _validate_http_engagement(new_engagement or None)

        store = _engagement_store_factory(engagement)
        # list_scans() (SELECT *) carries config_json + mode; list_all_scans()
        # drops them, which would leave every replay with an empty config.
        all_scans = store.list_scans(limit=1000)
        target_scan = next((s for s in all_scans if s["id"].startswith(scan_id)), None)
        if not target_scan:
            raise HTTPException(404, f"Scan {scan_id} not found")

        cfg_json = target_scan.get("config_json") or "{}"
        original_config = json.loads(cfg_json)
        targets = original_config.get("targets") or {}
        seed = original_config.get("seed")
        if seed is not None:
            set_seed(int(seed))
        if not (targets.get("ips") or targets.get("urls")):
            raise HTTPException(422, "Original scan has no replayable targets")

        # Optional: persist into a fresh engagement so the original is preserved
        if new_engagement:
            store = EngagementStore(_engagement_db_path(new_engagement))
            try:
                store.create_engagement(name=new_engagement,
                                        client=f"replay of {scan_id[:8]}")
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

        cfg = get_config()
        from heaven.config import ScanMode as _ScanMode
        try:
            _replay_mode = _ScanMode(target_scan.get("mode")
                                     or original_config.get("mode") or "full")
        except ValueError:
            _replay_mode = _ScanMode.FULL
        orch = build_full_scan(targets, cfg, checkpoint_store=store,
                               scan_mode=_replay_mode)
        store.record_scan_start(
            orch.scan_id, name=f"replay of {target_scan['id'][:8]}",
            mode=target_scan.get("mode", ""),
            config={"targets": targets, "seed": seed,
                    "replayed_from": target_scan["id"]},
        )

        async def _run():
            try:
                summary = await orch.run()
                for f in summary.get("vulnerabilities", []) + summary.get("findings", []):
                    try:
                        store.upsert_finding(orch.scan_id, f)
                    except Exception:
                        logger.debug("suppressed non-fatal exception", exc_info=True)
                store.record_scan_complete(orch.scan_id, summary)
            except Exception as e:
                logger.error(f"replay scan {orch.scan_id} failed: {e}")

        # Keep a strong reference: asyncio only weak-refs a fire-and-forget task,
        # so without this the GC can collect the replay scan mid-run.
        _replay_task = asyncio.create_task(_run())
        _background_scan_tasks.add(_replay_task)
        _scan_tasks_by_id[orch.scan_id] = _replay_task
        _replay_task.add_done_callback(_background_scan_tasks.discard)
        _replay_task.add_done_callback(
            lambda _t: _scan_tasks_by_id.pop(orch.scan_id, None))
        return {"new_scan_id": orch.scan_id, "replayed_from": target_scan["id"], "seed": seed}

    # ── Gap 4: Exploitation proof — actively confirm a finding ──

    @app.post("/api/findings/{finding_id}/prove")
    async def prove_finding_endpoint(
        finding_id: str,
        engagement: Optional[str] = Query(None),
        external_callback_url: Optional[str] = Query(None),
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Actively confirm one finding via the unified confirmation dispatcher.

        Runs the best available SAFE, read-only proof for the finding's class —
        an exploitation canary (injection), a behavioural CVE probe, an HTTP
        re-check (headers / exposed file / CORS / redirect / directory listing),
        a fresh TLS handshake, or a TCP-reachability connect — and returns a
        structured, honest verdict (see ``heaven.vulnscan.confirm``). A class with
        no safe automated proof returns ``not_applicable`` with a manual next step
        rather than a misleading "not proven".

        The ``vuln.validate`` permission gate IS the operator's authorization, so
        ``authorized=True`` is passed through. On a fresh proof the finding is
        promoted to Confirmed and persisted.
        """
        try:
            from heaven.vulnscan.confirm import confirm_finding
        except Exception as e:
            raise HTTPException(500, f"confirm module not importable: {e}")

        store = _engagement_store_factory(engagement)
        f = store.get_finding(finding_id)
        if not f:
            raise HTTPException(404, f"Finding {finding_id} not found")
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "cve_id": getattr(f, "cve_id", "") or "",
            "evidence": f.evidence or {},
        }
        out = await confirm_finding(
            finding_dict, authorized=True,
            external_callback_url=external_callback_url or "",
        )
        confirmed_finding = out.pop("finding", finding_dict)
        # Persist any promotion / recorded confirmation history.
        store.upsert_finding(scan_id=f.scan_id, finding=confirmed_finding)
        return {
            "finding_id": finding_id,
            # Structured verdict the UI renders directly.
            "status": out.get("status"),
            "proved": bool(out.get("proved", False)),
            "method": out.get("method"),
            "technique": out.get("technique"),
            "family": out.get("family"),
            "summary": out.get("summary"),
            "detail": out.get("detail"),
            "reprobed": bool(out.get("reprobed", False)),
            "evidence": out.get("evidence", []),
            # Back-compat: older clients read exploit_proof[] directly.
            "exploit_proof": (confirmed_finding.get("evidence", {}) or {}).get("exploit_proof", []),
        }

    @app.post("/api/findings/{finding_id}/remediation")
    async def remediation_finding_endpoint(
        finding_id: str,
        engagement: Optional[str] = Query(None),
        user: User = Depends(require_permission("vuln.view")),
    ):
        """AI-assisted remediation for one finding.

        Uses the configured LLM provider; when none is set it returns the
        knowledge-base remediation, so ``ai_generated`` tells the caller which
        path produced the text. Same engine backs ``heaven remediate``.
        """
        store = _engagement_store_factory(engagement)
        f = store.get_finding(finding_id)
        if not f:
            raise HTTPException(404, f"Finding {finding_id} not found")

        from heaven.devsecops.ai_remediation import AIRemediationEngine
        from heaven.devsecops.vuln_kb import enrich_finding
        enriched = enrich_finding({
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "cve_id": f.cve_id,
            "evidence": f.evidence,
        })
        ev = enriched.get("evidence") or {}
        finding_dict = {
            "title": f.title, "target": f.target, "vuln_type": f.vuln_type,
            "description": ev.get("description") or f.title,
            "patch": ev.get("remediation") or "",
        }
        engine = AIRemediationEngine()
        # generate_patch_with_source() makes a BLOCKING LLM call. Running it
        # directly in this async endpoint would freeze the entire uvicorn event
        # loop for the whole call (so a slow AI provider makes every page hang,
        # not just this request). Offload to a worker thread — the AI agent
        # endpoints already do this via acomplete().
        text, used_ai = await asyncio.to_thread(
            engine.generate_patch_with_source, finding_dict,
        )
        return {
            "finding_id": finding_id,
            "remediation": text,
            "ai_generated": used_ai,
        }

    # ── SBOM (CycloneDX) export ──
    @app.get("/api/sbom")
    async def export_sbom(
        engagement: Optional[str] = Query(None),
        download: bool = Query(False),
        user: User = Depends(require_permission("report.view")),
    ):
        """CycloneDX 1.5 SBOM for an engagement.

        components = discovered services (product/version per open port),
        vulnerabilities = CVE-bearing findings. Same generator as
        ``heaven sbom``. ``download=true`` sets an attachment filename.
        """
        from heaven.devsecops.sbom import collect_scan_data, generate_cyclonedx_sbom
        store = _engagement_store_factory(engagement)
        scan_data = collect_scan_data(store)
        doc = generate_cyclonedx_sbom(scan_data, output_path=None)
        if download:
            from fastapi.responses import JSONResponse
            return JSONResponse(doc, headers={
                "Content-Disposition": 'attachment; filename="heaven-sbom.json"'})
        return doc

    # ── Gap 6: Agentic AI — manual triggers ──

    @app.post("/api/ai/{kind}/run")
    async def run_ai_layer(
        kind: str, request: Request,
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Trigger an AI layer manually. kind ∈ {recon-parse, plan, fp-review,
        hypothesize}.

        Body JSON varies by kind:
          recon-parse: {"recon": {host data}}
          plan:        {"findings": [...], "assets": [...], "objective_hint": ""}
          fp-review:   {"finding": {...}}
          hypothesize: {"profile": {...}, "endpoints": [...], "max_hypotheses": 8}

        Returns the structured AI output (or {"skipped": "..."} when LLM unavailable).
        """
        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
            if kind == "recon-parse":
                from heaven.ai import ReconAgent
                agent = ReconAgent()
                if not agent.available:
                    return {"skipped": "LLM gateway unavailable"}
                profile = await agent.parse(body.get("recon", {}))
                return profile.model_dump() if hasattr(profile, "model_dump") else profile.__dict__
            if kind == "plan":
                # The planner always produces grounded chains from the findings
                # (deterministic builder); an LLM key just adds creative variants.
                from heaven.ai import AttackChainPlanner
                planner = AttackChainPlanner()
                out = await planner.plan(
                    findings=body.get("findings", []),
                    assets=body.get("assets", []),
                    objective_hint=body.get("objective_hint", ""),
                )
                result = out.model_dump() if hasattr(out, "model_dump") else out.__dict__
                result["llm_used"] = planner.available
                return result
            if kind == "fp-review":
                from heaven.ai import FPReviewer
                reviewer = FPReviewer()
                if not reviewer.available:
                    # The only reason a manual review can't run: no AI provider is
                    # configured (or pydantic is missing). ``reason`` lets the UI
                    # show an honest message instead of always blaming a missing key.
                    from heaven.ai.llm_gateway import get_gateway
                    gw_ok = False
                    try:
                        gw_ok = get_gateway().available
                    except Exception:
                        gw_ok = False
                    reason = ("no_llm" if not gw_ok else "unavailable")
                    return {"skipped": True, "reason": reason,
                            "message": ("No AI provider is configured — add a provider "
                                        "key in Settings to enable a second-opinion "
                                        "verdict." if reason == "no_llm" else
                                        "The LLM review layer is unavailable on this "
                                        "server.")}
                # An operator asked for a verdict on THIS finding — force the review
                # regardless of the borderline band (which only governs the
                # automatic bulk pass), so a high/low-confidence finding still gets
                # a second opinion instead of a misleading "unavailable".
                verdict = await reviewer.review(body.get("finding", {}), force=True)
                if verdict is None:
                    # Surface the ACTUAL provider reason (rate limit, 503
                    # overload, timeout, empty response) so the operator can tell
                    # a transient hiccup from a misconfiguration — a generic "no
                    # usable verdict" left them guessing.
                    detail = getattr(reviewer, "last_error", None) or ""
                    transient = any(
                        tok in detail.lower() for tok in
                        ("503", "unavailable", "overload", "high demand",
                         "timeout", "timed out", "exhausted retries", "deadline")
                    )
                    if transient:
                        msg = (f"The AI provider is busy ({detail}). This is "
                               "usually temporary — try again in a moment.")
                    elif detail:
                        msg = (f"The AI second-opinion could not complete: {detail}. "
                               "Check the AI provider status in Settings.")
                    else:
                        msg = ("The LLM did not return a usable verdict — try "
                               "again, or check the AI provider status in Settings.")
                    return {"skipped": True, "reason": "no_verdict",
                            "detail": detail, "message": msg}
                verdict_out = verdict.model_dump() if hasattr(verdict, "model_dump") else verdict.__dict__
                verdict_out["skipped"] = False
                return verdict_out
            if kind == "hypothesize":
                # Propose-only: the LLM ranks vuln classes worth probing. Active
                # verification runs in the authorised scan path, never here.
                from heaven.ai import VulnHypothesisAgent
                hyp_agent = VulnHypothesisAgent()
                if not hyp_agent.available:
                    return {"skipped": "LLM gateway unavailable"}
                hyp_out = await hyp_agent.propose(
                    profile=body.get("profile", {}),
                    endpoints=body.get("endpoints", []),
                    max_hypotheses=int(body.get("max_hypotheses") or 8),
                )
                return hyp_out.model_dump() if hasattr(hyp_out, "model_dump") else hyp_out.__dict__
        except Exception as e:
            raise HTTPException(500, f"AI {kind} failed: {e}")

        raise HTTPException(400, f"unknown AI layer kind: {kind!r}")

    # ── Gap 5: Post-exploitation triggers (admin only — destructive) ──

    @app.post("/api/postex/{module}/run")
    async def run_postex(
        module: str, request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Run a post-exploitation module.

        module ∈ {enum, win-enum, loot, full, linpeas, bloodhound, cred-reuse}.

        Body JSON depends on module:
          enum/win-enum/loot/full: {"host": "...", "username": "...",
                           "password": "...", "private_key": "...", "port": 22}
          full also accepts {"os": "auto|linux|windows"}.
          linpeas:    {"host": "...", "username": "...", "password": "..."}
          bloodhound: {"domain": "...", "dc_host": "...", "username": "...", "password": "..."}
          cred-reuse: {"credentials": [["u","p"], ...], "targets": [["h", port, "ssh"], ...]}

        These all require explicit authorization — admin permission is the gate.
        Output is returned synchronously for now (long-running modules log progress).
        Secrets harvested by loot/full are redacted in the response.
        """
        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
            if module == "enum":
                from heaven.postex import LinuxEnumEngine
                enum_res = await LinuxEnumEngine(authorized=True).enumerate(
                    host=body["host"], username=body["username"],
                    password=body.get("password"),
                    private_key=body.get("private_key"),
                    port=int(body.get("port", 22)),
                )
                return enum_res.to_dict()
            if module == "win-enum":
                from heaven.postex import WindowsEnumEngine
                win_res = await WindowsEnumEngine(authorized=True).enumerate(
                    host=body["host"], username=body["username"],
                    password=body.get("password"),
                    private_key=body.get("private_key"),
                    port=int(body.get("port", 22)),
                )
                return win_res.to_dict()
            if module == "loot":
                from heaven.postex import LootHarvester
                loot_res = await LootHarvester(authorized=True).harvest(
                    host=body["host"], username=body["username"],
                    password=body.get("password"),
                    private_key=body.get("private_key"),
                    port=int(body.get("port", 22)),
                )
                return loot_res.to_dict()  # already redacted
            if module == "full":
                from heaven.postex import PostExSession
                session = PostExSession(
                    body["host"], body["username"],
                    password=body.get("password"),
                    private_key=body.get("private_key"),
                    port=int(body.get("port", 22)), authorized=True,
                    target_os=str(body.get("os", "auto")),
                )
                rep = await session.run_full_postex(
                    enable_loot=bool(body.get("enable_loot", True)),
                    ai_analysis=bool(body.get("ai_analysis", True)),
                )
                return rep.to_dict()  # reusable_credentials excluded by design
            if module == "linpeas":
                from heaven.postex import LinpeasRunner
                runner = LinpeasRunner(authorized=True)
                linpeas_res = await runner.run(
                    host=body["host"], username=body["username"],
                    password=body.get("password"),
                    private_key=body.get("private_key"),
                    port=int(body.get("port", 22)),
                )
                return {
                    "success": linpeas_res.success, "error": linpeas_res.error,
                    "privesc_vectors": linpeas_res.privesc_vectors,
                    "suid_binaries": linpeas_res.suid_binaries,
                    "kernel_version": linpeas_res.kernel_version,
                }
            if module == "bloodhound":
                from heaven.postex import BloodHoundCollector
                col = BloodHoundCollector(authorized=True)
                bh_res = col.collect(
                    domain=body["domain"], dc_host=body["dc_host"],
                    username=body["username"], password=body["password"],
                    use_ssl=bool(body.get("use_ssl", False)),
                )
                return {
                    "success": bh_res.success, "error": bh_res.error,
                    "counts": bh_res.counts, "files": bh_res.files,
                }
            if module == "cred-reuse":
                from heaven.postex import CredentialValidator
                v = CredentialValidator(authorized=True)
                creds = [tuple(c) for c in body.get("credentials", [])]
                targets = [tuple(t) for t in body.get("targets", [])]
                summary = await v.validate(creds, targets)
                return {
                    "attempted": summary.attempted,
                    "hits": [
                        {"host": h.host, "port": h.port, "service": h.service,
                         "username": h.username, "notes": h.notes}
                        for h in summary.hits
                    ],
                    "errors": summary.errors[:20],
                }
        except KeyError as e:
            raise HTTPException(400, f"missing required field: {e}")
        except Exception as e:
            raise HTTPException(500, f"postex {module} failed: {e}")

        raise HTTPException(400, f"unknown postex module: {module!r}")

    # ── Active exploitation (admin only — confirms real RCE) ──

    @app.get("/api/exploit/list")
    async def list_exploit_modules(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Metadata for every registered exploit (id, ports, signatures)."""
        from heaven.vulnscan.exploit_engine import list_exploits
        return {"exploits": list_exploits()}

    @app.post("/api/exploit/run")
    async def run_exploit(
        request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Actively exploit a target and CONFIRM remote code execution.

        Body JSON:
          {"target": "192.168.0.162", "ports": [21, 445] | "21,445",
           "proof_command": "id; uname -a", "only": ["vsftpd_234_backdoor"],
           "i_have_authorization": true}

        Drives the real exploit path and captures live command output from a
        benign proof command (no persistence). Admin permission AND an explicit
        i_have_authorization in the body are both required.
        """
        try:
            body = await request.json()
        except Exception:
            body = {}
        target = str(body.get("target") or "").strip()
        if not target:
            raise HTTPException(400, "target is required")
        if not bool(body.get("i_have_authorization")):
            raise HTTPException(
                403, "i_have_authorization must be true — active exploitation "
                     "requires explicit written authorization for the target")
        # Ports may arrive as a list or a comma string; None → engine auto-discovers.
        raw_ports = body.get("ports")
        ports: Optional[list[int]] = None
        if isinstance(raw_ports, str):
            ports = [int(p) for p in raw_ports.split(",") if p.strip().isdigit()]
        elif isinstance(raw_ports, list):
            ports = [int(p) for p in raw_ports if str(p).strip().isdigit()]
        only = body.get("only") or None
        if isinstance(only, str):
            only = [o.strip() for o in only.split(",") if o.strip()]
        proof_command = str(body.get("proof_command") or "id; uname -a")
        try:
            from heaven.vulnscan.exploit_engine import run_exploitation
            return await run_exploitation(
                authorized=True, target=target, ports=ports or None,
                proof_command=proof_command, only=only)
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except Exception as e:
            raise HTTPException(500, f"exploitation failed: {e}")

    # ── Offline artifact analysis (forensics — authorized files only) ──

    @app.post("/api/analyze/decode")
    async def analyze_decode(
        request: Request,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Decode a base64/hex/base32/rot13 string. Body: {"text": "..."}."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        text = str(body.get("text") or "")
        if not text:
            raise HTTPException(400, "text is required")
        from heaven.forensics.crypto import analyze_crypto
        return analyze_crypto("", decode_text=text)

    @app.post("/api/analyze/run")
    async def analyze_upload(
        request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Analyze an offline artifact (pcap/binary/firmware/apk/image/hash file)
        and return findings. The file arrives base64-encoded in JSON so no extra
        server dependency is needed; it is written to a private temp path,
        analyzed, then deleted — nothing is persisted.

        Body JSON:
          {"filename": "capture.pcap", "content_b64": "<base64>",
           "kind": ""}   # kind optional — forces the type, else auto-detected
        """
        import base64
        import tempfile
        try:
            body = await request.json()
        except Exception:
            body = {}
        b64 = body.get("content_b64") or ""
        if not b64:
            raise HTTPException(400, "content_b64 is required")
        try:
            data = base64.b64decode(b64, validate=False)
        except Exception:
            raise HTTPException(400, "content_b64 is not valid base64")
        # Bounded so an oversized artifact cannot exhaust memory/disk.
        max_bytes = 40 * 1024 * 1024
        if len(data) > max_bytes:
            raise HTTPException(413, "file too large (limit 40 MB)")
        kind = str(body.get("kind") or "")
        filename = str(body.get("filename") or "artifact")
        from heaven.forensics.dispatch import analyze_artifact, detect_kind
        safe_suffix = Path(filename).suffix[:12]
        tmp = tempfile.NamedTemporaryFile(prefix="heaven_analyze_",
                                          suffix=safe_suffix, delete=False)
        try:
            tmp.write(data)
            tmp.flush()
            tmp.close()
            detected = kind or detect_kind(tmp.name)
            result = analyze_artifact(tmp.name, kind=kind or "")
            result.setdefault("detected_kind", detected)
            result["filename"] = filename
            return result
        except Exception as e:
            raise HTTPException(500, f"analysis failed: {e}")
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                logger.debug("temp artifact cleanup failed", exc_info=True)

    # ── Network pivoting (admin only — tunnels into networks behind a foothold) ──

    @app.post("/api/pivot/run")
    async def run_pivot_endpoint(
        request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Establish an SSH pivot chain and scan hosts behind it.

        Body JSON:
          {"jumps": [{"host": "...", "port": 22, "username": "...",
                       "password": "...", "key_path": "..."}],
           "targets": ["10.1.1.20"], "ports": [22, 445, 3389],
           "socks": false, "i_have_authorization": true}

        Repeat `jumps` for a double pivot (each tunnels through the previous).
        """
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not bool(body.get("i_have_authorization")):
            raise HTTPException(
                403, "i_have_authorization must be true — pivoting tunnels into "
                     "networks behind the foothold")
        raw_jumps = body.get("jumps") or []
        if not isinstance(raw_jumps, list) or not raw_jumps:
            raise HTTPException(400, "at least one jump host is required")
        from heaven.postex.pivot import JumpSpec, run_pivot
        try:
            jumps = [
                JumpSpec(host=str(j["host"]), port=int(j.get("port", 22)),
                         username=str(j.get("username", "")),
                         password=str(j.get("password", "")),
                         key_path=str(j.get("key_path", "")))
                for j in raw_jumps
            ]
        except (KeyError, TypeError, ValueError) as e:
            raise HTTPException(400, f"invalid jump spec: {e}")
        targets = body.get("targets") or None
        raw_ports = body.get("ports")
        ports = None
        if isinstance(raw_ports, list):
            ports = [int(p) for p in raw_ports if str(p).strip().isdigit()]
        try:
            return await run_pivot(
                authorized=True, jumps=jumps, targets=targets,
                ports=ports, socks=bool(body.get("socks")))
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except Exception as e:
            raise HTTPException(500, f"pivot failed: {e}")

    # ── Gap 7: Trigger train-priors from the UI ──

    @app.post("/api/priors/train")
    async def trigger_train_priors(
        user: User = Depends(require_permission("config.modify")),
    ):
        """Aggregate engagement DBs into learned priors. Long-running but bounded."""
        try:
            from heaven.ml.train_priors import discover_engagement_dbs, train_priors
        except Exception as e:
            raise HTTPException(500, f"train_priors not importable: {e}")

        dirs = [Path("engagements"), Path("data/engagements")]
        dbs = discover_engagement_dbs(*dirs)
        if not dbs:
            raise HTTPException(422, "No engagement *.db files found")
        result = train_priors(
            engagement_paths=dbs,
            bootstrap_path=Path("data/models/priors_bootstrap.json"),
            out_path=Path("data/models/priors_learned.json"),
        )
        return {
            "engagement_dbs": len(dbs),
            "finding_count": result.finding_count,
            "services_observed": result.services_observed,
            "service_priors_updated": result.service_priors_updated,
            "output": str(result.out_path),
        }

    # ── Gap 11: SIEM / SOC integration status ──

    @app.get("/api/siem/status")
    async def siem_status(user: User = Depends(require_permission("scan.view"))):
        """Report which SIEM backends are configured (env-driven)."""
        from heaven.devsecops.alerting import SIEMNotifier, WebhookAlerter
        notifier = SIEMNotifier()
        alerter = WebhookAlerter()
        return {
            "siem_backends_active": notifier.configured_backends,
            "webhook_active": bool(alerter.webhook_url),
        }

    # ── Gap 9: Methodology mapping docs ──

    @app.get("/api/methodology")
    async def list_methodology(user: User = Depends(require_permission("scan.view"))):
        """Structured OWASP/NIST/PTES coverage matrices + a LIVE overlay.

        The matrices are parsed from ``docs/methodology`` and classified per row
        (automated / partial / manual) with summary counts computed from the
        rows. On top of that, the active engagement's real findings are joined
        in: a row is marked ``exercised`` when the detector it names actually
        produced a finding in this engagement — so the page reflects what THIS
        assessment covered, not just a static reference. ``docs`` (raw markdown)
        is retained for backward compatibility.
        """
        from heaven import methodology as _methodology

        docs_dir = Path(__file__).parent.parent.parent / "docs" / "methodology"

        # Raw findings of the active engagement drive the live overlay.
        findings: list[dict[str, Any]] = []
        engagement_name = ""
        try:
            store = _read_store()
            eng = store.get_engagement()
            engagement_name = getattr(eng, "name", "") or ""
            findings = [
                {"id": f.id, "vuln_type": f.vuln_type, "title": f.title,
                 "severity": f.severity, "target": f.target,
                 "owasp": getattr(f, "owasp", "")}
                for f in store.list_findings(limit=10000)
            ]
        except Exception:
            findings = []

        built = await asyncio.to_thread(_methodology.build, findings, docs_dir)
        built["engagement"]["name"] = engagement_name

        # Backward-compatible raw docs.
        docs = []
        if docs_dir.exists():
            for md in sorted(docs_dir.glob("*.md")):
                if md.stem == "README":
                    continue
                try:
                    docs.append({"name": md.stem, "content": md.read_text(encoding="utf-8")})
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)
        built["docs"] = docs
        return built

    @app.get("/api/methodology/export")
    async def export_methodology(
        standard: str,
        format: str = "html",
        engagement: Optional[str] = None,
        user: User = Depends(require_permission("scan.view")),
    ):
        """Download ONE standard's live coverage matrix as a report.

        Renders the same overlaid coverage the Methodology page shows — every
        test row, its status, and the concrete findings that exercised it — for a
        single standard (a doc stem, e.g. ``owasp_testing_guide`` / ``iso_27001``)
        in html / markdown / json. Reuses ``heaven.methodology`` so CLI, page and
        this download never diverge.
        """
        from fastapi import Response
        from heaven import methodology as _methodology

        docs_dir = Path(__file__).parent.parent.parent / "docs" / "methodology"
        findings: list[dict[str, Any]] = []
        engagement_name = ""
        try:
            store = _read_store(engagement)
            eng = store.get_engagement()
            engagement_name = getattr(eng, "name", "") or ""
            findings = [
                {"id": f.id, "vuln_type": f.vuln_type, "title": f.title,
                 "severity": f.severity, "target": f.target,
                 "owasp": getattr(f, "owasp", "")}
                for f in store.list_findings(limit=10000)
            ]
        except Exception:
            findings = []

        built = await asyncio.to_thread(_methodology.build, findings, docs_dir)
        std = _methodology.find_standard(built, standard)
        if std is None:
            available = ", ".join(s["name"] for s in built.get("standards", []))
            raise HTTPException(404, f"unknown standard '{standard}'. Available: {available}")

        fmt = (format or "html").lower()
        safe_std = re.sub(r"[^A-Za-z0-9_.-]+", "_", standard)[:60] or "standard"
        if fmt == "html":
            body = _methodology.render_coverage_html(std, engagement_name)
            media, ext = "text/html", "html"
        elif fmt in ("markdown", "md"):
            body = _methodology.render_coverage_markdown(std, engagement_name)
            media, ext = "text/markdown", "md"
        elif fmt == "json":
            body = json.dumps({"engagement": engagement_name, "standard": std},
                              indent=2, default=str)
            media, ext = "application/json", "json"
        elif fmt == "pdf":
            import importlib.util
            if importlib.util.find_spec("reportlab") is None:
                raise HTTPException(
                    503, "PDF export needs reportlab — `pip install reportlab`. "
                    "Use HTML/Markdown export, which need no extra dependency.")
            try:
                pdf_bytes = await asyncio.to_thread(
                    _methodology.render_coverage_pdf, std, engagement_name)
            except Exception as exc:  # noqa: BLE001
                logger.exception("methodology PDF generation failed")
                raise HTTPException(500, f"PDF generation failed: {exc}") from exc
            filename = f"heaven-methodology-{safe_std}.pdf"
            return Response(content=pdf_bytes, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        else:
            raise HTTPException(400, f"unsupported format: {fmt} (use html/markdown/json/pdf)")
        filename = f"heaven-methodology-{safe_std}.{ext}"
        return Response(content=body, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/compliance/frameworks")
    async def list_compliance_frameworks(
        user: User = Depends(require_permission("report.view")),
    ):
        """The finding-mapped compliance frameworks available for a report.

        Each entry (id/title/subtitle/reference/controls_total) can be downloaded
        as a mapped report via ``/api/report/export?format=…&framework=<id>``.
        """
        from heaven.devsecops import compliance_frameworks as _cf
        return {"frameworks": _cf.list_frameworks()}

    def _compliance_findings(engagement: Optional[str] = None) -> tuple[str, list[dict]]:
        """(engagement_name, enriched findings) for the compliance overlay.

        Findings are enriched (CWE / OWASP) so the control mapping has the same
        grounding the report export uses, and false-positives are excluded — a
        control-coverage view must reflect the real, reportable findings.
        """
        from heaven.devsecops.vuln_kb import enrich_finding
        name = ""
        out: list[dict] = []
        try:
            store = _read_store(engagement)
            eng = store.get_engagement()
            name = getattr(eng, "name", "") or ""
            for f in store.list_findings(limit=10000):
                if (getattr(f, "status", "") or "").lower() == "false_positive":
                    continue
                d = {
                    "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                    "title": f.title, "severity": f.severity, "cve_id": f.cve_id,
                    "cwe": getattr(f, "cwe", "") or "",
                    "owasp": getattr(f, "owasp", "") or "",
                    "status": f.status,
                    "evidence": f.evidence if isinstance(f.evidence, dict) else {},
                }
                out.append(enrich_finding(d))
        except Exception:
            logger.debug("suppressed non-fatal exception collecting compliance findings",
                         exc_info=True)
        return name, out

    @app.get("/api/compliance/coverage")
    async def compliance_coverage(
        framework: str,
        engagement: Optional[str] = None,
        user: User = Depends(require_permission("report.view")),
    ):
        """Live control-coverage overlay for ONE framework — the data behind the
        interactive Compliance page (the control analogue of ``/api/methodology``).

        Every control lists the distinct engagement findings that provide evidence
        of a gap against it. Honest coverage view, not an attestation.
        """
        from heaven.devsecops import compliance_frameworks as _cf
        if not _cf.is_compliance_framework(framework):
            available = ", ".join(f["id"] for f in _cf.list_frameworks())
            raise HTTPException(404, f"unknown framework '{framework}'. Available: {available}")
        name, findings = _compliance_findings(engagement)
        cov = await asyncio.to_thread(_cf.coverage_for, framework, findings, name)
        return cov

    @app.get("/api/compliance/export")
    async def export_compliance(
        framework: str,
        format: str = "html",
        engagement: Optional[str] = None,
        user: User = Depends(require_permission("report.view")),
    ):
        """Download ONE framework's live control-coverage matrix as a deliverable
        (html / markdown / json / pdf) — mirrors ``/api/methodology/export``."""
        from fastapi import Response
        from heaven.devsecops import compliance_frameworks as _cf
        if not _cf.is_compliance_framework(framework):
            available = ", ".join(f["id"] for f in _cf.list_frameworks())
            raise HTTPException(404, f"unknown framework '{framework}'. Available: {available}")
        name, findings = _compliance_findings(engagement)
        cov = await asyncio.to_thread(_cf.coverage_for, framework, findings, name)
        fmt = (format or "html").lower()
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", framework)[:60] or "framework"
        if fmt == "html":
            body = _cf.render_coverage_html(cov)
            media, ext = "text/html", "html"
        elif fmt in ("markdown", "md"):
            body = _cf.render_coverage_markdown(cov)
            media, ext = "text/markdown", "md"
        elif fmt == "json":
            body = json.dumps(cov, indent=2, default=str)
            media, ext = "application/json", "json"
        elif fmt == "pdf":
            import importlib.util
            if importlib.util.find_spec("reportlab") is None:
                raise HTTPException(
                    503, "PDF export needs reportlab — `pip install reportlab`. "
                    "Use HTML/Markdown export, which need no extra dependency.")
            try:
                pdf_bytes = await asyncio.to_thread(_cf.render_coverage_pdf, cov)
            except Exception as exc:  # noqa: BLE001
                logger.exception("compliance PDF generation failed")
                raise HTTPException(500, f"PDF generation failed: {exc}") from exc
            filename = f"heaven-compliance-{safe}.pdf"
            return Response(content=pdf_bytes, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        else:
            raise HTTPException(400, f"unsupported format: {fmt} (use html/markdown/json/pdf)")
        filename = f"heaven-compliance-{safe}.{ext}"
        return Response(content=body, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # ── Gap 1: Latest benchmark results ──

    @app.get("/api/benchmark/results")
    async def latest_benchmark(user: User = Depends(require_permission("scan.view"))):
        """Return every available benchmark tier with parsed headline metrics.

        Surfaces all tiers present on disk (always-on native web + API, and the
        live DVWA / Metasploitable-2 runs once an operator has produced them), in
        display order, plus the "primary" tier spread at the top level for the
        pre-tiers UI. A washout — a failed run where the target was down, so
        precision AND recall are both 0% — is never surfaced.
        """
        reports = Path(__file__).parent.parent.parent / "tests" / "benchmarks" / "reports"
        return _benchmark_response(_collect_benchmark_tiers(reports))

    @app.post("/api/benchmark/run")
    async def run_benchmark(
        user: User = Depends(require_permission("scan.create")),
    ):
        """Regenerate BOTH native, Docker-free benchmark tiers and return fresh numbers.

        Backs the Benchmark page's "Re-run" button so a web-only operator gets
        genuinely current precision / recall / F1 without shelling into the
        server — it runs the exact in-process reproductions ``heaven benchmark``
        uses for the web and API tiers. Needs the benchmark extras (flask / bs4 /
        aiohttp / pyyaml); if they're missing it returns a clear 503 and the page
        keeps showing the last cached reports. The runs are CPU-bound and
        self-contained (~1–20 s), so they execute off the event loop.
        """
        # The native runners live under tests/ (shipped with the source tree but
        # not importable unless the repo root is on sys.path). Derive the root
        # from this module so it works regardless of the server's cwd — memory
        # notes `heaven serve` is often launched from outside the repo.
        repo_root = Path(__file__).parent.parent.parent
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        try:
            from tests.benchmarks.native.api_runner import run_api_benchmark
            from tests.benchmarks.native.runner import run_native_benchmark
        except Exception as e:  # noqa: BLE001 — missing optional benchmark deps
            raise HTTPException(
                503,
                "Benchmark runner unavailable — install the benchmark extras "
                f"(flask/bs4/aiohttp/pyyaml) or run `heaven benchmark` on the server. ({e})",
            )
        try:
            web_run = await asyncio.to_thread(run_native_benchmark, write_report=True)
            api_run = await asyncio.to_thread(run_api_benchmark, write_report=True)
        except Exception as e:  # noqa: BLE001 — surface the failure to the UI
            logger.exception("Native benchmark run failed")
            raise HTTPException(500, f"Benchmark run failed: {e}")

        logger.info("Native benchmarks (web + API) re-run by %s", user.username)
        # Return the two tiers we just ran (fresh markdown, not a stale disk read),
        # plus any live tiers already present on disk so the page keeps showing them.
        reports = repo_root / "tests" / "benchmarks" / "reports"
        live_tiers = [
            t for t in _collect_benchmark_tiers(reports)
            if t["source"] in ("live-dvwa", "live-network")
        ]
        tiers = [
            _benchmark_tier_from_markdown(web_run.markdown, "native-controlled"),
            _benchmark_tier_from_markdown(api_run.markdown, "native-controlled-api"),
            *live_tiers,
        ]
        return _benchmark_response(tiers)

    # ══════════════════════════════════════════════════════════════════
    # CLI ↔ API sync — every backend capability has a UI-reachable route
    # ══════════════════════════════════════════════════════════════════

    # ── Autonomous loop (heaven autonomous equivalent) ──
    @app.post("/api/autonomous/run")
    async def autonomous_run(
        request: Request,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Start the LLM-driven iterative pen-test loop as a BACKGROUND job.

        Body JSON:
          {"engagement": "name", "ips": [...], "urls": [...],
           "max_iterations": 5, "time_budget_s": 600, "objective": "rce",
           "use_llm": true}

        Returns immediately with {"job_id", "status": "running"}. The loop runs
        detached so a multi-minute run neither blocks the HTTP request nor gets
        lost when the operator navigates away in the UI. Poll
        GET /api/autonomous/jobs/{job_id} for progress and the final summary.
        """
        try:
            from heaven.ai.autonomous_loop import run_autonomous
            from heaven.config import get_config as _get_config
        except Exception as e:
            raise HTTPException(500, f"autonomous loop unavailable: {e}")

        try:
            body = await request.json()
        except Exception:
            body = {}

        engagement = body.get("engagement")
        seed_targets = {
            "ips": list(body.get("ips") or []),
            "urls": list(body.get("urls") or []),
        }
        if not (seed_targets["ips"] or seed_targets["urls"]):
            raise HTTPException(422, "need at least one ip or url")

        max_iterations = int(body.get("max_iterations") or 5)
        time_budget_s = int(body.get("time_budget_s") or 600)
        objective = str(body.get("objective") or "")
        use_llm = bool(body.get("use_llm", True))

        job_id = uuid.uuid4().hex[:12]
        job: dict = {
            "job_id": job_id,
            "status": "running",          # running | done | error
            "engagement": engagement,
            "seeds": seed_targets,
            "objective": objective,
            "max_iterations": max_iterations,
            "use_llm": use_llm,
            "started_by": user.username,
            "started_at": time.time(),
            "ended_at": None,
            "result": None,
            "error": None,
            "progress": [],   # accumulates per-iteration dicts for poll + late WS join
        }
        autonomous_jobs[job_id] = job

        # Bound the history so the registry doesn't grow without limit.
        if len(autonomous_jobs) > 30:
            stale = sorted(autonomous_jobs.values(), key=lambda j: j["started_at"])
            for old in stale[:-30]:
                autonomous_jobs.pop(old["job_id"], None)
                _autonomous_subscribers.pop(old["job_id"], None)

        def _on_iteration(item: dict) -> None:
            # Called synchronously from run_autonomous (same event loop) after each
            # iteration — record it and fan it out to live WebSocket subscribers.
            job["progress"].append(item)
            _autonomous_broadcast(job_id, {"type": "iteration", "data": item})

        async def _runner() -> None:
            try:
                store = _engagement_store_factory(engagement) if engagement else None
                summary = await run_autonomous(
                    seed_targets=seed_targets,
                    engagement_store=store,
                    base_config=_get_config(),
                    max_iterations=max_iterations,
                    time_budget_s=time_budget_s,
                    objective=objective,
                    use_llm_planner=use_llm,
                    on_iteration=_on_iteration,
                )
                job["result"] = summary.to_dict()
                job["status"] = "done"
            except Exception as e:  # noqa: BLE001 — surface any failure to the UI
                job["error"] = str(e)
                job["status"] = "error"
                logger.exception("Autonomous job %s failed", job_id)
            finally:
                job["ended_at"] = time.time()
                # Signal end-of-stream to any live WebSocket subscribers.
                _autonomous_broadcast(job_id, {"type": "done", "job": job})

        task = asyncio.create_task(_runner())
        _autonomous_tasks.add(task)
        task.add_done_callback(_autonomous_tasks.discard)

        return {"job_id": job_id, "status": "running"}

    @app.get("/api/autonomous/jobs")
    async def autonomous_jobs_list(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Most-recent-first list of autonomous jobs this server has launched."""
        return {
            "jobs": sorted(
                autonomous_jobs.values(),
                key=lambda j: j["started_at"], reverse=True,
            ),
        }

    @app.get("/api/autonomous/jobs/{job_id}")
    async def autonomous_job_get(
        job_id: str,
        user: User = Depends(require_permission("scan.view")),
    ):
        """Status + (when finished) the full AutonomousRunSummary for one job."""
        job = autonomous_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "no such autonomous job")
        return job

    @app.websocket("/api/autonomous/jobs/{job_id}/stream")
    async def autonomous_stream(
        websocket: WebSocket, job_id: str, token: Optional[str] = Query(None),
    ):
        """Live per-iteration progress for an autonomous job.

        On connect, sends a `snapshot` (status + iterations so far), then streams
        `iteration` messages as they complete and a final `done` message with the
        full job. Auth is via the `token` query param (browsers can't set headers
        on a WebSocket handshake). Polling GET /api/autonomous/jobs/{id} remains a
        complete fallback.
        """
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            session = auth._sessions[token]
            if session.expires_at < time.time():
                await websocket.close(code=4401, reason="Token expired")
                return

        job = autonomous_jobs.get(job_id)
        if not job:
            await websocket.close(code=4404, reason="No such job")
            return

        await websocket.accept()
        # Catch-up snapshot so a late subscriber (or reconnect) sees prior work.
        await websocket.send_json({
            "type": "snapshot", "status": job["status"],
            "progress": list(job.get("progress", [])),
        })
        if job["status"] != "running":
            await websocket.send_json({"type": "done", "job": job})
            await websocket.close()
            return

        queue: asyncio.Queue = asyncio.Queue()
        _autonomous_subscribers.setdefault(job_id, set()).add(queue)
        try:
            while True:
                msg = await queue.get()
                await websocket.send_json(msg)
                if msg.get("type") == "done":
                    break
        except WebSocketDisconnect:
            pass
        except Exception as e:  # noqa: BLE001 — never let a socket error crash the worker
            logger.debug("autonomous stream error for %s: %s", job_id, e)
        finally:
            subs = _autonomous_subscribers.get(job_id)
            if subs is not None:
                subs.discard(queue)
                if not subs:
                    _autonomous_subscribers.pop(job_id, None)
            try:
                await websocket.close()
            except Exception:  # noqa: BLE001
                logger.debug("suppressed non-fatal exception", exc_info=True)

    # ── Watch mode (heaven watch equivalent) ──
    @app.get("/api/watch/channels")
    async def watch_channels(user: User = Depends(require_permission("scan.view"))):
        """Which outgoing alert channels are actually configured (env-driven).

        Drives the Watch page's channel tiles honestly — a channel shows
        "active" only when its env vars are set, not just because the page
        loaded.
        """
        from heaven.devsecops.alerting import (
            SIEMNotifier, TicketingDispatcher, WebhookAlerter,
        )
        return {
            "webhook_active": bool(WebhookAlerter().webhook_url),
            "siem_backends_active": SIEMNotifier().configured_backends,
            "ticketing_backends": TicketingDispatcher().configured_backends,
        }

    @app.post("/api/watch/start")
    async def watch_start(
        request: Request,
        user: User = Depends(require_permission("scan.create")),
    ):
        """Launch a continuous watch loop as a BACKGROUND job.

        Body JSON:
          {"engagement": "prod-monitor", "ips": [...], "urls": [...],
           "interval_s": 1800, "max_iterations": 6, "mode": "web",
           "jitter": 0.1, "heartbeat": false, "auto_tickets": false,
           "ports": "1-1024", "stealth_level": "normal"}

        Returns {"job_id", "status": "running"} immediately. The loop scans on
        the interval, diffs each run against the previous, and only alerts when
        a NEW or REGRESSED finding appears (or every run when heartbeat is on).
        Poll GET /api/watch/jobs/{id} or subscribe to the WS stream for live
        per-iteration progress; POST /api/watch/jobs/{id}/stop to end it early.

        A web-launched watch is BOUNDED (max_iterations 1..500, interval
        15s..24h) so a browser click can't spawn an unkillable infinite loop —
        the CLI (`heaven watch`) remains the tool for a truly endless monitor.
        """
        from heaven.cli._helpers import _engagement_db_path
        from heaven.config import ScanMode
        from heaven.config import get_config as _get_config
        from heaven.utils.watcher import WatchConfig, run_watch

        try:
            body = await request.json()
        except Exception:
            body = {}

        engagement = str(body.get("engagement") or "").strip()
        if not engagement:
            raise HTTPException(422, "engagement is required: a watch loop "
                                     "persists every run into an engagement")
        db_path = _engagement_db_path(engagement)
        if not db_path.exists():
            raise HTTPException(404, f"engagement '{engagement}' not found — "
                                     f"create it first (Dashboard → New engagement)")

        ips = [str(x).strip() for x in (body.get("ips") or []) if str(x).strip()]
        urls = [str(x).strip() for x in (body.get("urls") or []) if str(x).strip()]
        if not (ips or urls):
            raise HTTPException(422, "need at least one target ip or url")
        for u in urls:
            if not _URL_REGEX.match(u):
                raise HTTPException(422, f"invalid url: {u}")

        # Note: parse with an explicit None-check, not `or`, so an explicit 0
        # is honoured (0 iterations must be REJECTED, not silently defaulted;
        # jitter 0.0 means "no jitter", not "use the default").
        _iv = body.get("interval_s")
        interval_s = max(15, min(int(_iv if _iv is not None else 3600), 86400))
        _mi = body.get("max_iterations")
        max_iterations = int(_mi if _mi is not None else 6)
        if max_iterations < 1:
            raise HTTPException(422, "max_iterations must be ≥ 1 for a "
                                     "web-launched watch (use the CLI for ∞)")
        max_iterations = min(max_iterations, 500)
        _jt = body.get("jitter")
        jitter = max(0.0, min(float(_jt if _jt is not None else 0.1), 0.5))
        try:
            scan_mode = ScanMode(str(body.get("mode") or "web").lower())
        except ValueError:
            scan_mode = ScanMode.WEB
        heartbeat = bool(body.get("heartbeat", False))
        auto_tickets = bool(body.get("auto_tickets", False))

        targets = {
            "ips": ips, "urls": urls,
            "repositories": [], "cloud_providers": [],
            "ports": str(body.get("ports") or "1-1024"),
            "stealth_level": str(body.get("stealth_level") or "normal"),
            "ad_domain": "", "ad_dc": "",
            "enable_iot": False, "enable_api_scan": False,
            "enable_container": False, "enable_mitre": True,
            "auto_prove": False, "autonomous": False,
        }

        cfg = _get_config()
        cfg.scan_mode = scan_mode
        wc = WatchConfig(
            targets=targets, engagement_name=engagement,
            interval_s=interval_s, jitter_pct=jitter,
            max_iterations=max_iterations,
            alert_on_heartbeat=heartbeat, auto_create_tickets=auto_tickets,
        )

        job_id = uuid.uuid4().hex[:12]
        job: dict = {
            "job_id": job_id,
            "status": "running",           # running | done | stopped | error
            "engagement": engagement,
            "targets": {"ips": ips, "urls": urls},
            "mode": scan_mode.value,
            "interval_s": interval_s,
            "jitter": jitter,
            "max_iterations": max_iterations,
            "heartbeat": heartbeat,
            "auto_tickets": auto_tickets,
            "started_by": user.username,
            "started_at": time.time(),
            "ended_at": None,
            "stop_requested": False,
            "result": None,
            "error": None,
            "progress": [],                # accumulates per-iteration dicts
        }
        watch_jobs[job_id] = job

        # Bound the registry so it can't grow without limit.
        if len(watch_jobs) > 30:
            for old in sorted(watch_jobs.values(),
                              key=lambda j: j["started_at"])[:-30]:
                watch_jobs.pop(old["job_id"], None)
                _watch_subscribers.pop(old["job_id"], None)

        def _on_iteration(it) -> None:
            data = it.to_dict()
            job["progress"].append(data)
            _watch_broadcast(job_id, {"type": "iteration", "data": data})

        async def _runner() -> None:
            try:
                summary = await run_watch(wc, cfg, on_iteration=_on_iteration)
                job["result"] = summary.to_dict()
                stopped = (job["stop_requested"]
                           or summary.stop_reason == "operator_interrupt")
                job["status"] = "stopped" if stopped else "done"
            except asyncio.CancelledError:
                # run_watch normally swallows cancellation and returns, but guard
                # the case where it propagates (e.g. cancelled before the loop).
                job["status"] = "stopped"
                job["ended_at"] = time.time()
                _watch_broadcast(job_id, {"type": "done", "job": job})
                raise
            except Exception as e:  # noqa: BLE001 — surface any failure to the UI
                job["error"] = str(e)
                job["status"] = "error"
                logger.exception("Watch job %s failed", job_id)
            finally:
                if job["ended_at"] is None:
                    job["ended_at"] = time.time()
                    _watch_broadcast(job_id, {"type": "done", "job": job})

        def _drop_task(_task: Any) -> None:
            _watch_tasks.pop(job_id, None)

        task = asyncio.create_task(_runner())
        _watch_tasks[job_id] = task
        task.add_done_callback(_drop_task)

        return {"job_id": job_id, "status": "running"}

    @app.get("/api/watch/jobs")
    async def watch_jobs_list(user: User = Depends(require_permission("scan.view"))):
        """Most-recent-first list of watch jobs this server has launched."""
        return {
            "jobs": sorted(watch_jobs.values(),
                           key=lambda j: j["started_at"], reverse=True),
        }

    @app.get("/api/watch/jobs/{job_id}")
    async def watch_job_get(
        job_id: str, user: User = Depends(require_permission("scan.view")),
    ):
        """Status + progress (+ final summary once finished) for one watch job."""
        job = watch_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "no such watch job")
        return job

    @app.post("/api/watch/jobs/{job_id}/stop")
    async def watch_job_stop(
        job_id: str, user: User = Depends(require_permission("scan.cancel")),
    ):
        """Stop a running watch loop. It finishes the current iteration's scan,
        then exits cleanly (state is already persisted per-iteration)."""
        job = watch_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "no such watch job")
        if job["status"] != "running":
            return {"ok": True, "status": job["status"], "note": "already ended"}
        job["stop_requested"] = True
        task = _watch_tasks.get(job_id)
        if task:
            task.cancel()
        return {"ok": True, "status": "stopping"}

    @app.websocket("/api/watch/jobs/{job_id}/stream")
    async def watch_stream(
        websocket: WebSocket, job_id: str, token: Optional[str] = Query(None),
    ):
        """Live per-iteration progress for a watch job. Sends a `snapshot`
        (status + progress so far), then `iteration` frames, then a final
        `done`. Auth via the `token` query param (WS handshakes can't set
        headers). Polling GET /api/watch/jobs/{id} is a complete fallback."""
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            session = auth._sessions[token]
            if session.expires_at < time.time():
                await websocket.close(code=4401, reason="Token expired")
                return

        job = watch_jobs.get(job_id)
        if not job:
            await websocket.close(code=4404, reason="No such job")
            return

        await websocket.accept()
        await websocket.send_json({
            "type": "snapshot", "status": job["status"],
            "progress": list(job.get("progress", [])),
        })
        if job["status"] != "running":
            await websocket.send_json({"type": "done", "job": job})
            await websocket.close()
            return

        queue: asyncio.Queue = asyncio.Queue()
        _watch_subscribers.setdefault(job_id, set()).add(queue)
        try:
            while True:
                msg = await queue.get()
                await websocket.send_json(msg)
                if msg.get("type") == "done":
                    break
        except WebSocketDisconnect:
            pass
        except Exception as e:  # noqa: BLE001 — never let a socket error crash the worker
            logger.debug("watch stream error for %s: %s", job_id, e)
        finally:
            subs = _watch_subscribers.get(job_id)
            if subs is not None:
                subs.discard(queue)
                if not subs:
                    _watch_subscribers.pop(job_id, None)
            try:
                await websocket.close()
            except Exception:  # noqa: BLE001
                logger.debug("suppressed non-fatal exception", exc_info=True)

    # ── Coverage self-grading (heaven coverage equivalent) ──
    @app.get("/api/coverage")
    async def coverage_report(
        engagement: Optional[str] = Query(None),
        use_llm: bool = Query(True),
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Return the rule-based + (optional) LLM coverage report for an engagement."""
        try:
            from heaven.ai.coverage_grader import grade_engagement
        except Exception as e:
            raise HTTPException(500, f"coverage_grader unavailable: {e}")
        store = _read_store(engagement)
        report = await grade_engagement(store, use_llm=use_llm)
        return report.to_dict()

    # ── Lateral movement (no CLI equivalent yet — admin-gated) ──
    @app.post("/api/lateral/run")
    async def lateral_run(
        request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """SSH key reuse + SMB/PsExec + pass-the-hash lateral.

        Body JSON:
          {"ssh_key_path": "/path/id_rsa",
           "ssh_usernames": ["root","ubuntu"],
           "smb_username": "Administrator", "smb_domain": "CORP",
           "smb_password": "..." OR "smb_nthash": "...",
           "targets": [["10.0.0.5", 22], ["10.0.0.5", 445]]}
        """
        try:
            from heaven.postex.lateral import run_lateral
        except Exception as e:
            raise HTTPException(500, f"lateral module unavailable: {e}")
        try:
            body = await request.json()
        except Exception:
            body = {}
        targets = [(t[0], int(t[1])) for t in body.get("targets") or []]
        try:
            return await run_lateral(
                authorized=True,
                ssh_key_path=body.get("ssh_key_path"),
                ssh_usernames=body.get("ssh_usernames") or [],
                smb_username=body.get("smb_username"),
                smb_password=body.get("smb_password", ""),
                smb_nthash=body.get("smb_nthash", ""),
                smb_domain=body.get("smb_domain", ""),
                targets=targets,
            )
        except Exception as e:
            raise HTTPException(500, f"lateral.run failed: {e}")

    # ── Knowledge graph (cross-engagement memory) ──
    @app.get("/api/knowledge/stats")
    async def knowledge_stats(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Aggregate counts + top-success techniques from ~/.heaven/knowledge.db."""
        try:
            from heaven.ai.knowledge_graph import get_knowledge_graph
        except Exception as e:
            raise HTTPException(500, f"knowledge_graph unavailable: {e}")
        return get_knowledge_graph().stats()

    @app.get("/api/knowledge/rank")
    async def knowledge_rank(
        os: str = Query(""), web_tech: str = Query(""),
        ad_domain: str = Query(""), cloud: str = Query(""),
        ports: str = Query("", description="comma-separated open ports, e.g. 22,80,443"),
        top: int = Query(10),
        user: User = Depends(require_permission("scan.view")),
    ):
        """Beta-smoothed posterior success-rate per technique for the supplied profile."""
        try:
            from heaven.ai.knowledge_graph import TargetProfile, get_knowledge_graph
        except Exception as e:
            raise HTTPException(500, f"knowledge_graph unavailable: {e}")
        try:
            port_ints = [int(p) for p in ports.split(",") if p.strip()]
        except ValueError:
            raise HTTPException(422, "ports must be comma-separated integers")
        profile = TargetProfile(
            os=os, web_tech=web_tech, ad_domain=ad_domain, cloud=cloud,
            open_ports_top=port_ints,
        )
        rankings = get_knowledge_graph().rank_techniques(profile, top_n=top)
        return {
            "fingerprint": profile.fingerprint(),
            "rankings": [
                {"technique": r.technique,
                 "posterior_success_rate": round(r.posterior_success_rate, 4),
                 "evidence_count": r.evidence_count,
                 "last_success_at": r.last_success_at}
                for r in rankings
            ],
        }

    # ── SAST (static source-code analysis via Semgrep) ──
    @app.post("/api/sast/scan")
    async def sast_scan(
        request: Request,
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Run Semgrep against a source-code path. Persists findings into the
        engagement if `engagement` is supplied.

        Body JSON: {"path": "/abs/path", "engagement": "name",
                    "extra_configs": ["p/owasp-top-ten"], "no_builtin": false,
                    "timeout": 300}
        """
        try:
            from heaven.vulnscan.sast_runner import (
                has_semgrep, run_sast, persist_findings,
            )
        except Exception as e:
            raise HTTPException(500, f"sast_runner unavailable: {e}")
        if not has_semgrep():
            raise HTTPException(412, "semgrep not installed on the server "
                                     "(pip install semgrep)")

        try:
            body = await request.json()
        except Exception:
            body = {}
        path = body.get("path")
        if not path:
            raise HTTPException(422, "body.path is required")

        result = await run_sast(
            path,
            extra_configs=list(body.get("extra_configs") or []),
            use_builtin_rules=not bool(body.get("no_builtin", False)),
            timeout_s=int(body.get("timeout") or 300),
        )

        # Persist into an engagement so the findings surface in triage/dashboard.
        # Target = the name the operator typed, else the engagement the app is
        # currently viewing (active pointer). Crucially we then make that
        # engagement active, exactly like the pentest scan endpoint does: the
        # Findings page and dashboard always read the *active* engagement, so
        # without this the run would persist into one store while every reader
        # looked at another — the "I scanned SAST but Findings is empty" bug.
        engagement = _validate_http_engagement(body.get("engagement")) or _get_active_engagement()
        if engagement and result.success:
            import uuid as _uuid
            from pathlib import Path as _P
            engagement = _resolve_engagement_name(engagement)
            store = _engagement_store_factory(engagement)
            scan_id = f"sast-{_uuid.uuid4().hex[:12]}"
            store.record_scan_start(
                scan_id, name=f"SAST: {_P(path).name}", mode="sast",
                config={"path": path,
                        "extra_configs": list(body.get("extra_configs") or [])},
            )
            persisted = persist_findings(store, scan_id, result)
            store.record_scan_complete(scan_id, {
                "findings_count": persisted,
                "duration_s": result.duration_s,
            })
            _set_active_engagement(engagement)
            out = result.to_dict()
            out["engagement"] = engagement
            out["engagement_scan_id"] = scan_id
            out["persisted_count"] = persisted
            return out
        return result.to_dict()

    @app.post("/api/sca")
    async def sca_scan(
        request: Request,
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Software Composition Analysis: audit a codebase's dependency
        manifests against OSV.dev. Persists findings if `engagement` is given.

        Body JSON: {"path": "/abs/path", "engagement": "name", "max_files": 200}
        """
        try:
            from heaven.devsecops.vuln_kb import enrich_finding
            from heaven.vulnscan.osv_client import OSVClient
            from heaven.vulnscan.sca_scanner import scan_path
        except Exception as e:  # pragma: no cover
            raise HTTPException(500, f"sca_scanner unavailable: {e}")
        if not OSVClient().available:
            raise HTTPException(412, "httpx not installed on the server "
                                     "(needed for OSV lookups)")

        try:
            body = await request.json()
        except Exception:
            body = {}
        path = body.get("path")
        if not path:
            raise HTTPException(422, "body.path is required")

        result = await scan_path(path, max_files=int(body.get("max_files") or 200))
        result["findings"] = [enrich_finding(f) for f in result.get("findings", [])]

        # Same contract as SAST above: persist into the typed engagement (or the
        # currently-viewed one) and make it active so the audit shows up in the
        # Findings page / dashboard, which always read the active engagement.
        engagement = _validate_http_engagement(body.get("engagement")) or _get_active_engagement()
        if engagement and not result.get("error"):
            import uuid as _uuid
            from pathlib import Path as _P
            engagement = _resolve_engagement_name(engagement)
            store = _engagement_store_factory(engagement)
            scan_id = f"sca-{_uuid.uuid4().hex[:12]}"
            store.record_scan_start(
                scan_id, name=f"SCA: {_P(path).name}", mode="sca",
                config={"path": path, "manifests": result.get("manifests", [])},
            )
            for f in result["findings"]:
                store.upsert_finding(scan_id, f)
            store.record_scan_complete(
                scan_id, {"findings_count": len(result["findings"])})
            _set_active_engagement(engagement)
            result["engagement"] = engagement
            result["engagement_scan_id"] = scan_id
            result["persisted_count"] = len(result["findings"])
        return result

    @app.post("/api/cloud/storage")
    async def cloud_storage_scan(
        request: Request,
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Unauthenticated public-bucket exposure scan (S3/GCS/Azure).

        Body JSON: {"target": "example.com", "names": ["codename"],
                    "providers": ["s3","gcs","azure"], "limit": 60,
                    "engagement": "name"}
        No cloud credentials are used — bucket names are guessed from the target
        and each provider's response is parsed to prove listability.
        """
        try:
            from heaven.vulnscan.cloud_scanner import CloudStorageScanner
        except Exception as e:  # pragma: no cover
            raise HTTPException(500, f"cloud_scanner unavailable: {e}")

        try:
            body = await request.json()
        except Exception:
            body = {}
        target = body.get("target")
        if not target:
            raise HTTPException(422, "body.target is required")

        scanner = CloudStorageScanner(providers=body.get("providers") or None)
        result = await scanner.scan(
            str(target), extra_names=body.get("names") or [],
            limit=int(body.get("limit") or 60))
        out = result.to_dict()
        findings = result.to_findings()
        out["findings"] = findings

        engagement = _validate_http_engagement(body.get("engagement")) or _get_active_engagement()
        if engagement and result.success and findings:
            import uuid as _uuid
            engagement = _resolve_engagement_name(engagement)
            store = _engagement_store_factory(engagement)
            scan_id = f"cloud-{_uuid.uuid4().hex[:12]}"
            store.record_scan_start(
                scan_id, name=f"cloud/storage: {target}", mode="cloud",
                config={"target": target})
            for f in findings:
                store.upsert_finding(scan_id, f)
            store.record_scan_complete(scan_id, {"findings_count": len(findings)})
            _set_active_engagement(engagement)
            out["engagement"] = engagement
            out["engagement_scan_id"] = scan_id
            out["persisted_count"] = len(findings)
        return out

    @app.post("/api/cve/lookup")
    async def cve_lookup(
        request: Request,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Dynamic live CVE lookup for a product/version NOT in the local DB.

        Body JSON: {"product": "openssh", "version": "9.6", "vendor": "",
                    "cpe": "", "limit": 25}
        Queries NVD + CIRCL live, merges/de-dupes, marks version-confirmed hits.
        """
        try:
            from heaven.vulnscan.live_cve_feed import LiveCVEFeed
        except Exception as e:  # pragma: no cover
            raise HTTPException(500, f"live_cve_feed unavailable: {e}")

        try:
            body = await request.json()
        except Exception:
            body = {}
        product = body.get("product", "")
        cpe = body.get("cpe", "")
        if not product and not cpe:
            raise HTTPException(422, "body.product (or body.cpe) is required")

        feed = LiveCVEFeed()
        records = await feed.discover(
            str(product), str(body.get("version", "")),
            vendor=str(body.get("vendor", "")), cpe=str(cpe),
            max_results=int(body.get("limit") or 25))
        return {
            "product": product, "version": body.get("version", ""),
            "available": feed.available, "total": len(records),
            "cves": [r.to_dict() for r in records],
        }

    @app.get("/api/sast/rules")
    async def sast_rules_list(
        user: User = Depends(require_permission("scan.view")),
    ):
        """List the built-in HEAVEN SAST rule files."""
        from pathlib import Path as _P
        rules_dir = _P(__file__).parent.parent / "vulnscan" / "sast_rules"
        out: list[dict] = []
        if rules_dir.exists():
            for f in sorted(rules_dir.glob("*.yml")):
                out.append({
                    "name": f.stem,
                    "size_bytes": f.stat().st_size,
                })
        return {"rules_dir": str(rules_dir), "files": out,
                "semgrep_installed": __import__("shutil").which("semgrep") is not None}

    # ── Differential scanning ──
    @app.get("/api/scans/{scan_id}/diff")
    async def scan_diff(
        scan_id: str,
        baseline: str = Query(..., description="baseline scan id"),
        engagement: Optional[str] = Query(None),
        include_unchanged: bool = Query(False),
        user: User = Depends(require_permission("scan.view")),
    ):
        """Compare two scans of the same engagement. Returns bucketed diff."""
        try:
            from heaven.devsecops.diff_finder import compute_diff
        except Exception as e:
            raise HTTPException(500, f"diff_finder unavailable: {e}")
        store = _engagement_store_factory(engagement)
        # compute_diff raises ValueError when a scan id isn't in THIS engagement
        # (the common "diff isn't working" cause: the two scans live in different
        # engagements). Surface that as an actionable 400, not an opaque 500.
        try:
            report = compute_diff(store, baseline, scan_id)
        except ValueError as e:
            raise HTTPException(
                400,
                f"{e}. Both scans must belong to the engagement you're viewing — "
                "switch to that engagement, or pick two scans from the same one.",
            )
        out = report.to_dict()
        if include_unchanged:
            from heaven.devsecops.diff_finder import _row_dict
            out["unchanged"] = [_row_dict(r) for r in report.unchanged]
        return out

    @app.get("/api/scans/{scan_id}/retest")
    async def scan_retest(
        scan_id: str,
        baseline: str = Query(..., description="baseline scan id"),
        engagement: Optional[str] = Query(None),
        user: User = Depends(require_permission("scan.view")),
    ):
        """Remediation-retest posture for a re-scan vs. a baseline scan.

        Returns the remediation rate and the Fixed / Still-open / Reintroduced /
        Newly-introduced counts plus the bucketed diff — the data behind the
        client-facing retest report.
        """
        try:
            from heaven.devsecops.diff_finder import compute_diff
            from heaven.devsecops.retest_report import retest_posture
        except Exception as e:
            raise HTTPException(500, f"retest unavailable: {e}")
        store = _engagement_store_factory(engagement)
        try:
            report = compute_diff(store, baseline, scan_id)
        except ValueError as e:
            raise HTTPException(
                400,
                f"{e}. Both scans must belong to the engagement you're viewing.",
            )
        return {"posture": retest_posture(report), "diff": report.to_dict()}

    @app.get("/api/scans/{scan_id}/retest.html", response_class=HTMLResponse)
    async def scan_retest_html(
        scan_id: str,
        baseline: str = Query(..., description="baseline scan id"),
        engagement: Optional[str] = Query(None),
        user: User = Depends(require_permission("scan.view")),
    ):
        """Rendered, self-contained HTML remediation-retest report (downloadable)."""
        try:
            from heaven.devsecops.diff_finder import compute_diff
            from heaven.devsecops.retest_report import render_retest_html
        except Exception as e:
            raise HTTPException(500, f"retest unavailable: {e}")
        store = _engagement_store_factory(engagement)
        try:
            report = compute_diff(store, baseline, scan_id)
        except ValueError as e:
            raise HTTPException(400, f"{e}. Both scans must belong to this engagement.")
        eng = store.get_engagement()
        html_text = render_retest_html(
            report, engagement_name=eng.name if eng else "",
            baseline_label=baseline[:8], current_label=scan_id[:8])
        return HTMLResponse(content=html_text)

    # ── Ticketing (Jira / Linear) ──
    @app.get("/api/tickets/status")
    async def tickets_status(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Report which ticketing backends (Jira / Linear) are configured."""
        from heaven.devsecops.alerting import TicketingDispatcher
        d = TicketingDispatcher()
        return {
            "configured_backends": d.configured_backends,
            "jira_configured": d.jira.configured,
            "linear_configured": d.linear.configured,
        }

    @app.post("/api/tickets/push/{finding_id}")
    async def tickets_push(
        finding_id: str,
        engagement: Optional[str] = Query(None),
        user: User = Depends(require_permission("vuln.update")),
    ):
        """Push one finding to every configured ticketing backend."""
        from heaven.devsecops.alerting import TicketingDispatcher
        store = _engagement_store_factory(engagement)
        f = store.get_finding(finding_id)
        if not f:
            raise HTTPException(404, f"finding {finding_id} not found")
        d = TicketingDispatcher()
        if not d.has_any:
            raise HTTPException(412, "No ticketing backends configured")
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "cve_id": f.cve_id,
        }
        return await d.dispatch(finding_dict)

    # ── ExploitDB lookup (per-CVE) ──
    @app.get("/api/exploitdb/{cve}")
    async def exploitdb_lookup(
        cve: str,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Return Exploit-DB entries for one CVE. Tries local searchsploit
        first, falls back to ExploitDB CSV mirror.
        """
        try:
            from heaven.vulnscan.exploitdb_client import lookup_cve as _lookup
        except Exception as e:
            raise HTTPException(500, f"exploitdb_client unavailable: {e}")
        result = await _lookup(cve)
        return {
            "cve": result.cve,
            "error": result.error,
            "count": len(result.entries),
            "best": {
                "edb_id": result.best.edb_id,
                "title": result.best.title,
                "url": result.best.edb_url,
                "platform": result.best.platform,
                "verified": result.best.verified,
                "source": result.best.source,
            } if result.best else None,
            "entries": [
                {"edb_id": e.edb_id, "url": e.edb_url, "title": e.title[:200],
                 "date_published": e.date_published, "verified": e.verified,
                 "platform": e.platform, "type": e.type}
                for e in result.entries[:25]
            ],
        }

    # ── WebSocket for real-time updates ──
    @app.websocket("/api/ws/scan/{scan_id}")
    async def scan_websocket(websocket: WebSocket, scan_id: str, token: Optional[str] = Query(None)):
        # WebSocket auth via query param (browsers can't set headers on WS open)
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return
            session = auth._sessions[token]
            if session.expires_at < __import__("time").time():
                await websocket.close(code=4401, reason="Token expired")
                return

        await websocket.accept()
        ws_connections.append(websocket)
        await ws_manager.connect(scan_id, websocket)
        try:
            while True:
                await websocket.receive_text()
                if scan_id in active_scans:
                    await websocket.send_json(active_scans[scan_id])
        except WebSocketDisconnect:
            pass
        finally:
            ws_manager.disconnect(scan_id, websocket)
            if websocket in ws_connections:
                ws_connections.remove(websocket)

    @app.websocket("/api/ws/logs")
    async def logs_websocket(websocket: WebSocket, token: Optional[str] = Query(None)):
        """Stream real-time orchestrator logs."""
        if not _auth_disabled():
            auth = get_auth_manager()
            if not token or token not in auth._sessions:
                await websocket.close(code=4401, reason="Unauthorized")
                return

        await websocket.accept()
        log_ws_connections.append(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            if websocket in log_ws_connections:
                log_ws_connections.remove(websocket)

    # Attach the WebSocket Log Handler
    ws_handler = WebSocketLogHandler()
    ws_handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger("heaven").addHandler(ws_handler)

    # Serve static frontend.
    # ui_dist may be missing for two reasons: (1) pip/site-packages install where
    # the repo layout differs, (2) the React UI was never built (no Node.js at
    # install time). In both cases, instead of letting "/" fall through to a bare
    # {"detail":"Not Found"} 404, serve a readable placeholder that tells the
    # operator exactly how to build the UI and where the API + docs live.
    ui_dist = Path(__file__).parent.parent.parent / "heaven-ui" / "dist"
    if ui_dist.exists() and (ui_dist / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(ui_dist), html=True), name="frontend")

        @app.exception_handler(404)
        async def custom_404_handler(request, exc):
            if request.url.path.startswith("/api/"):
                # Preserve the real message (e.g. "Scan not found") instead of
                # flattening every API 404 to a generic string.
                detail = getattr(exc, "detail", None) or "Not Found"
                return JSONResponse({"detail": detail}, status_code=404)
            return FileResponse(ui_dist / "index.html")
    else:
        logger.warning(
            "Web UI not built (heaven-ui/dist missing) — serving placeholder at '/'. "
            "Build it with: cd heaven-ui && npm install && npm run build"
        )

        @app.get("/", include_in_schema=False)
        async def _ui_placeholder():
            return HTMLResponse(_UI_NOT_BUILT_HTML)

        @app.get("/favicon.ico", include_in_schema=False)
        async def _favicon():
            return Response(status_code=204)

    return app


_UI_NOT_BUILT_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>HEAVEN — API running</title>
<style>
 body{background:#05070f;color:#00FF41;font-family:monospace;margin:0;
   display:flex;align-items:center;justify-content:center;min-height:100vh}
 .box{max-width:620px;padding:40px;border:1px solid rgba(0,255,65,.35);
   box-shadow:0 0 40px rgba(0,255,65,.12)}
 h1{font-size:34px;letter-spacing:.2em;margin:0 0 4px}
 .sub{color:rgba(0,255,65,.45);letter-spacing:.3em;font-size:11px;margin-bottom:24px}
 code{background:rgba(0,255,65,.08);padding:2px 6px}
 pre{background:rgba(0,255,65,.05);border:1px solid rgba(0,255,65,.2);
   padding:12px;overflow:auto}
 a{color:#00FF41}
 .ok{color:#00FF41}.warn{color:#FFB800}
</style></head><body><div class="box">
 <h1 style="display:flex;align-items:center;gap:14px">
   <svg width="38" height="38" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="HEAVEN"><defs><linearGradient id="e" x1="18" y1="12" x2="110" y2="118" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#6D7CFF"/><stop offset=".5" stop-color="#22D3EE"/><stop offset="1" stop-color="#34E5A3"/></linearGradient></defs><polygon points="64,10 110,37 110,91 64,118 18,91 18,37" fill="#05070f" stroke="url(#e)" stroke-width="7" stroke-linejoin="round"/><g stroke="url(#e)" stroke-width="9" stroke-linecap="round" stroke-linejoin="round" fill="none"><path d="M48 52V88"/><path d="M80 52V88"/><path d="M48 72 64 54 80 72"/></g><circle cx="64" cy="45" r="5.5" fill="#34E5A3"/></svg>
   HEAVEN</h1>
 <div class="sub">AUTONOMOUS PENETRATION TESTING</div>
 <p class="ok">&#10003; API server is running.</p>
 <p class="warn">&#9888; The web UI has not been built yet.</p>
 <p>Build the React UI, then restart this server:</p>
 <pre>cd heaven-ui
npm install --legacy-peer-deps
npm run build</pre>
 <p>Meanwhile the full API is live:</p>
 <ul>
   <li><a href="/api/docs">/api/docs</a> &mdash; interactive API documentation</li>
   <li><a href="/api/health">/api/health</a> &mdash; health check</li>
 </ul>
 <p>Or drive HEAVEN entirely from the CLI: <code>heaven scan --help</code></p>
</div></body></html>"""


def _parse_cookie_header(raw: str) -> dict[str, str]:
    """Parse a raw Cookie header ("k=v; k2=v2") into a name→value dict."""
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def _auth_base_url(req: ScanRequest) -> str:
    """Pick the base URL a form login should target — the first http(s) target,
    falling back to the first target (http-prefixed) or localhost."""
    cands = [str(c).strip() for c in (list(req.urls) + list(req.targets)) if str(c).strip()]
    for c in cands:
        if c.startswith(("http://", "https://")):
            return c
    if cands:
        c = cands[0]
        return c if "://" in c else f"http://{c}"
    return "http://localhost"


async def _setup_scan_auth(req: ScanRequest) -> list[str]:
    """Activate the authenticated-scan session(s) for a web-launched scan.

    Mirrors the CLI's ``--cookie-file``/``--auth`` and ``--low-priv-*`` handling
    so the web path can run authenticated crawls, IDOR and the multi-role Broken
    Access Control audit. ``req.cookie`` is a raw Cookie header; ``req.auth`` is a
    form-login spec (``url=/login,user=a,pass=b``). The low-priv pair supplies a
    second, lower-privilege identity for the access-control differential.

    Sessions are process-wide singletons, so the caller MUST clear them in a
    ``finally`` (``_clear_scan_auth``) — otherwise one scan's credentials leak
    into the next. Raises ``ValueError`` on a login failure so the caller can
    fail the scan visibly instead of silently scanning unauthenticated.
    """
    from heaven.recon.auth_session import (
        AuthSession, parse_auth_string, perform_form_login,
        remember_login, set_active_session, set_low_priv_session,
    )
    notes: list[str] = []
    base = _auth_base_url(req)

    # Primary (higher-privilege) session.
    if req.cookie.strip():
        sess = AuthSession(cookies=_parse_cookie_header(req.cookie),
                           origin=base, label="web-cookie")
        if not sess.cookies:
            raise ValueError("cookie header supplied but no name=value pairs parsed")
        set_active_session(sess)
        notes.append(f"primary session via cookie ({len(sess.cookies)} cookie(s))")
    elif req.auth.strip():
        spec = parse_auth_string(req.auth)
        sess = await perform_form_login(base, spec)
        set_active_session(sess)
        remember_login(base, spec)          # renew if the session dies mid-scan
        notes.append(f"primary session via form login: {sess.label}")

    # Second, lower-privilege session for the access-control differential.
    if req.low_priv_cookie.strip():
        lp = AuthSession(cookies=_parse_cookie_header(req.low_priv_cookie),
                         origin=base, label="web-cookie-lowpriv")
        if not lp.cookies:
            raise ValueError("low-priv cookie header supplied but no name=value pairs parsed")
        set_low_priv_session(lp)
        notes.append(f"low-priv session via cookie ({len(lp.cookies)} cookie(s))")
    elif req.low_priv_auth.strip():
        spec = parse_auth_string(req.low_priv_auth)
        lp = await perform_form_login(base, spec)
        set_low_priv_session(lp)
        notes.append(f"low-priv session via form login: {lp.label}")

    return notes


def _clear_scan_auth() -> None:
    """Drop any authenticated-scan sessions so they never leak into a later scan."""
    from heaven.recon.auth_session import clear_active_session, set_low_priv_session
    clear_active_session()
    set_low_priv_session(None)


async def _run_scan_background(scan_id: str, req: ScanRequest, *, resume: bool = False):
    """Run a scan in the background, persist findings to engagement store and report file.

    When ``resume`` is True the scan already exists in the store: its checkpoints
    are replayed (``build_full_scan(resume_scan_id=...)`` skips completed tasks)
    and the existing row is kept — so an interrupted scan continues instead of
    starting over.
    """
    active_scans[scan_id]["status"] = "running"
    active_scans[scan_id]["progress_pct"] = 0

    # Build the target dict once, up front, so it is available both for the
    # dispatch (build_full_scan) and for the persisted config — and survives a
    # store-open failure below. Resolving the stealth level here (int 1-4 → name)
    # means the operator's stealth choice is what gets persisted and replayed.
    stealth_name = _resolve_stealth_name(req.stealth_level)
    scan_targets: dict[str, Any] = {
        "ips": req.targets,
        "urls": req.urls,
        "repositories": req.repositories,
        "cloud_providers": req.cloud_providers,
        "ports": req.ports,
        "stealth_level": stealth_name,
        "evade": bool(req.evade),
        # Active exploitation is gated in the orchestrator; the task also fires
        # when the mode is "exploit". i_have_authorization was already asserted
        # by the create_scan endpoint before this runner is scheduled.
        "active_exploit": bool(req.active_exploit)
        or str(req.mode or req.scan_type or "").lower() == "exploit",
    }

    # Engagement store — always open one (defaults to "default" engagement)
    engagement_name = req.engagement or os.environ.get("HEAVEN_ENGAGEMENT") or "default"
    store = None
    try:
        store = _engagement_store_factory(engagement_name)
        # Auto-create engagement record so the header/dashboard shows it
        store.create_engagement(name=engagement_name)
        # Name the scan after what it assesses (e.g. "app.example.com +2") so it's
        # identifiable in the Scans list, dashboard and downloaded report — instead
        # of the generic default "HEAVEN Scan". An explicit non-default req.name wins.
        from heaven.engagement import scan_display_name
        _scan_mode = req.mode or req.scan_type or "web"
        _scan_name = (
            req.name if (req.name and req.name != "HEAVEN Scan")
            else scan_display_name(list(req.urls or []) + list(req.targets or []), _scan_mode)
        )
        active_scans[scan_id]["name"] = _scan_name  # so the running (in-memory) scan shows it too
        # Persist a full, replayable config (targets incl. stealth level, mode,
        # and the active seed if any) so `heaven replay` / the replay endpoint
        # reproduce this scan faithfully — previously web scans stored no config
        # at all, so they were unreplayable and their stealth choice was lost.
        from heaven.utils.seeding import current_seed
        if resume:
            # The row + its replayable config already exist; just re-arm it to
            # 'running' (keeps checkpoints/config) instead of INSERT-OR-REPLACEing.
            store.record_scan_resumed(scan_id)
        else:
            store.record_scan_start(
                scan_id, name=_scan_name, mode=_scan_mode,
                config={"targets": scan_targets, "seed": current_seed(), "mode": _scan_mode},
            )
        # Record what we're actually assessing as engagement scope, so the
        # dashboard/report reflect the real targets instead of "0 targets".
        for _tgt in list(req.urls or []) + list(req.targets or []):
            _t = str(_tgt).strip()
            if not _t:
                continue
            if _t.startswith(("http://", "https://")):
                _kind = "url"
            elif "/" in _t and _t.replace(".", "").replace("/", "").isdigit():
                _kind = "cidr"
            elif _t and all(ch.isdigit() or ch == "." for ch in _t):
                _kind = "ip"
            else:
                _kind = "host"
            try:
                store.add_scope(_t, kind=_kind, notes="auto-added from scan")
            except Exception:  # noqa: BLE001 — scope is best-effort, never block a scan
                logger.debug("suppressed non-fatal exception", exc_info=True)
    except Exception as e:
        logger.warning(f"Could not open engagement store '{engagement_name}': {e}")

    try:
        from heaven.orchestrator import build_full_scan
        from heaven.config import ScanMode, get_config
        cfg = get_config()

        # Honor the mode the operator picked in the web launcher so the scan
        # actually runs that mode's modules (previously every mode ran the full
        # pipeline). Pass it explicitly — never mutate the shared config
        # singleton, or concurrent scans of different modes would race.
        try:
            _mode = ScanMode(req.mode or req.scan_type or "full")
        except ValueError:
            _mode = ScanMode.FULL

        # Authenticated scanning — activate the operator-supplied session(s)
        # before building the pipeline so every scanner module (crawler, IDOR,
        # access-control audit) picks them up. A login failure raises here and
        # fails the scan visibly rather than silently scanning unauthenticated.
        # Sessions are process-wide singletons, cleared in the finally below.
        try:
            _auth_notes = await _setup_scan_auth(req)
        except Exception as _auth_err:
            raise RuntimeError(f"Authenticated-scan setup failed: {_auth_err}") from _auth_err
        if _auth_notes:
            active_scans[scan_id]["auth"] = _auth_notes
            logger.info("scan %s authenticated: %s", scan_id, "; ".join(_auth_notes))

        orch = build_full_scan(
            scan_targets,
            cfg,
            checkpoint_store=store,
            scan_mode=_mode,
            resume_scan_id=scan_id if resume else None,
        )

        # Remembers the size of the raw finding union at the last live reconcile,
        # so a pure progress heartbeat (no new findings) skips the dedup/prune work.
        _live_reconcile = {"union_size": -1}

        async def progress_update(progress):
            pct = getattr(progress, "progress_pct", None)
            if pct is not None:
                # Keep one decimal so the fine-grained, time-based advances the
                # orchestrator now emits aren't rounded away into visible steps.
                active_scans[scan_id]["progress_pct"] = round(pct, 1)
            # Surface the estimated time-to-complete at the top level so the
            # scans list can render "~2m left" without digging into the nested
            # progress blob. None until there's enough signal to estimate.
            _eta = getattr(progress, "eta_seconds", None)
            active_scans[scan_id]["eta_s"] = round(_eta) if _eta is not None else None
            active_scans[scan_id]["progress"] = progress.to_dict() if hasattr(progress, "to_dict") else {}
            for ws in list(ws_connections):
                try:
                    await ws.send_json({"scan_id": scan_id, **(progress.to_dict() if hasattr(progress, "to_dict") else {})})
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)

            # Flush the LIVE finding set to the engagement store in real time.
            # This mirrors the finalizer (heaven/orchestrator.py :: run()) exactly
            # — same source keys + dedup_findings + a store reconcile — so the live
            # count tracks the AUTHORITATIVE deduped + junk-dropped + FP-suppressed
            # set, not the raw candidate stream. Without this the store just
            # accumulated every raw candidate a completed task emitted, so the count
            # ballooned (e.g. 65 → 346) as noisy candidates surfaced and only
            # collapsed back to the real ~66 when the final prune ran at completion.
            # By carrying each task's suppressed_findings into the same dedup, a
            # candidate is dropped the moment its validator emits the matching
            # false-positive twin — the number converges as verdicts land instead of
            # snapping down at the very end.
            if store:
                try:
                    union: list[dict] = []
                    for res in orch.results.values():
                        if res.state != "completed" or not res.data:
                            continue
                        data = res.data if isinstance(res.data, dict) else {}
                        for key in ("vulnerabilities", "findings", "candidates",
                                    "validated_findings", "suppressed_findings"):
                            union.extend(data.get(key, []) or [])
                    # A pure progress heartbeat (no task completed since the last
                    # tick) adds no findings — skip the dedup/upsert/prune work.
                    if len(union) != _live_reconcile["union_size"]:
                        _live_reconcile["union_size"] = len(union)
                        live = _dedup_findings(union)
                        keep_ids: set[str] = set()
                        for f in live:
                            try:
                                keep_ids.add(store.upsert_finding(scan_id, f))
                            except Exception:
                                logger.debug("suppressed non-fatal exception", exc_info=True)
                        # Reconcile the store to the deduped survivors so a candidate
                        # that a later verdict suppressed is removed live, not just
                        # at completion.
                        try:
                            store.prune_scan_findings(scan_id, keep_ids)
                        except Exception:
                            logger.debug("suppressed non-fatal exception pruning live findings",
                                         exc_info=True)
                    # Live count = real deduped rows in the store, so the scan
                    # list and the engagement view never disagree.
                    active_scans[scan_id]["findings_count"] = store.count_findings(scan_id)
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)

        orch.on_progress(progress_update)
        result = await orch.run()

        findings = result.get("vulnerabilities", []) or result.get("findings", [])
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["findings_count"] = len(findings)
        active_scans[scan_id]["progress_pct"] = 100
        active_scans[scan_id]["result"] = {k: v for k, v in result.items() if k != "vulnerabilities"}

        # 1. Persist findings to engagement store (powers /api/engagement/findings + dashboard)
        if store:
            try:
                final_ids = {store.upsert_finding(scan_id, finding) for finding in findings}
                # Reconcile the store to the FINAL authoritative set. The live
                # progress flush above persists findings as they surface, but the
                # final result is deduped + FP-suppressed — so drop any of this
                # scan's rows that aren't in the final set. Without this the store
                # kept superseded/suppressed candidates the report had already
                # dropped, so the engagement view, scan list and downloaded report
                # disagreed (the "results don't match / look fake" symptom).
                try:
                    store.prune_scan_findings(scan_id, final_ids)
                except Exception:
                    logger.debug("suppressed non-fatal exception pruning scan findings",
                                 exc_info=True)
                # Authoritative finding count = deduped rows actually in the
                # store, so the scan list, kill chain and engagement view all
                # report the same number.
                persisted_count = store.count_findings(scan_id)
                active_scans[scan_id]["findings_count"] = persisted_count
                store.record_scan_complete(scan_id, summary={
                    "total": persisted_count,
                    "elapsed_seconds": result.get("elapsed_seconds", 0),
                    # Persist host/service assets INTO the scan summary (the CLI
                    # path already does this via the full summary). The inventory
                    # /api/assets reads the store first; without assets here a
                    # web-launched scan's open ports/services were invisible unless
                    # the global "latest report" happened to be this exact scan.
                    "assets": result.get("assets", []),
                    # DNS enumeration (records + subdomains) for the Assets view's
                    # DNS section and the report's DNS Enumeration section.
                    "dns_records": result.get("dns_records", []),
                    "severity": {
                        s: sum(1 for f in findings if (f.get("severity") or "info").lower() == s)
                        for s in ("critical", "high", "medium", "low", "info")
                    },
                })
            except Exception as e:
                logger.error(f"Failed persisting findings to engagement store: {e}")

        # 2. Save report JSON (powers /api/dashboard, /api/vulnerabilities)
        try:
            from heaven.config import get_config as _gc
            data_dir = _gc().data_dir
            data_dir.mkdir(parents=True, exist_ok=True)
            report_path = data_dir / f"report_{scan_id}.json"
            report_data = {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": req.model_dump(),
                "vulnerabilities": findings,
                "findings": findings,
                "assets": result.get("assets", []),
                "dns_records": result.get("dns_records", []),
                "summary": {
                    "total_vulnerabilities": len(findings),
                    "total_assets": len(result.get("assets", [])),
                    "elapsed_seconds": result.get("elapsed_seconds", 0),
                    **{s: sum(1 for f in findings if (f.get("severity") or "info").lower() == s)
                       for s in ("critical", "high", "medium", "low", "info")},
                },
            }
            report_path.write_text(json.dumps(report_data, indent=2, default=str))
            logger.info(f"Report saved to {report_path} ({len(findings)} findings)")
        except Exception as e:
            logger.error(f"Failed saving report JSON: {e}")

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_COMPLETED, target=scan_id,
            details={"elapsed_s": result.get("elapsed_seconds", 0), "findings": len(findings)},
            actor=active_scans[scan_id].get("created_by", "system"),
            severity=AuditSeverity.INFO,
        )

    except asyncio.CancelledError:
        # The operator cancelled this scan (delete_scan called task.cancel()).
        # CancelledError is a BaseException, so it bypasses the `except Exception`
        # below — persist 'cancelled' here (not left stranded 'running') and
        # re-raise so the task is properly torn down. Checkpoints are kept, so a
        # cancelled scan is still resumable.
        active_scans[scan_id]["status"] = "cancelled"
        if store:
            try:
                store.record_scan_complete(scan_id, summary={"cancelled": True},
                                           status="cancelled")
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        raise

    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        logger.error(f"Background scan {scan_id} failed: {e}", exc_info=True)

        if store:
            try:
                store.record_scan_complete(scan_id, summary={"error": str(e)}, status="failed")
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_FAILED, target=scan_id, details={"error": str(e)},
            actor=active_scans[scan_id].get("created_by", "system"),
            severity=AuditSeverity.WARNING,
        )

    finally:
        # Drop any authenticated-scan session so it never leaks into a later
        # scan run in this long-lived server process.
        _clear_scan_auth()

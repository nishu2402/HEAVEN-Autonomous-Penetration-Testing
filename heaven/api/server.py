"""
HEAVEN — FastAPI Application & REST API
Central API server with WebSocket support, JWT/API-key auth, and RBAC.
"""

from __future__ import annotations

import asyncio
import os
import re
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


class ScanRequest(BaseModel):
    name: str = "HEAVEN Scan"
    targets: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    repositories: list[str] = Field(default_factory=list)
    cloud_providers: list[str] = Field(default_factory=list)
    ports: str = "1-1024"
    scan_type: str = "full"
    mode: str = "web"
    stealth_level: int = 3
    engagement: Optional[str] = None
    i_have_authorization: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingStatusUpdate(BaseModel):
    status: str
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


# ── Active scan tracking ──
active_scans: dict[str, Any] = {}
ws_connections: list = []
log_ws_connections: list = []
# Strong references to background scan tasks. Kept OUT of active_scans because
# that dict is JSON-serialised by the API — an asyncio.Task is not serialisable.
_background_scan_tasks: set = set()

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
            pass


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
        token = authorization.split(None, 1)[1].strip()
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


def _active_engagement_file() -> Path:
    """Pointer file that records which engagement the web UI is currently viewing."""
    from heaven.config import get_config
    return get_config().data_dir / ".active_engagement"


def _get_active_engagement() -> Optional[str]:
    """The most-recently-selected engagement (set when a scan is launched or the
    operator switches engagements). None when nothing has been selected yet."""
    try:
        p = _active_engagement_file()
        if p.exists():
            name = p.read_text(encoding="utf-8").strip()
            return name or None
    except Exception:  # noqa: BLE001 — a missing/corrupt pointer just means "default"
        pass
    return None


def _set_active_engagement(name: Optional[str]) -> None:
    """Persist the active engagement so the dashboard, findings and reports all
    read the same store the latest scan wrote to."""
    if not name:
        return
    try:
        p = _active_engagement_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(name).strip(), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        logger.debug(f"Could not persist active engagement '{name}': {e}")


def _resolve_engagement_name(name: Optional[str] = None) -> str:
    """Single source of truth for 'which engagement is the app looking at'.

    Priority: explicit arg > HEAVEN_ENGAGEMENT env > active-engagement pointer >
    'default'. Every reader (dashboard, findings, reports) and the scan writer go
    through this, so they can never disagree about which store holds the data.
    """
    return (name or os.environ.get("HEAVEN_ENGAGEMENT")
            or _get_active_engagement() or "default")


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


def _engagement_store_factory(name: Optional[str] = None):
    """Resolve engagement store. Falls back to env var, active pointer, then default."""
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
    return EngagementStore(p)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        admin_pwd_set = bool(os.environ.get("HEAVEN_ADMIN_PASSWORD"))
        if not admin_pwd_set:
            logger.warning(
                "HEAVEN_ADMIN_PASSWORD not set — random admin password was generated at startup. "
                "Check earlier log lines for the value, then SET HEAVEN_ADMIN_PASSWORD in your environment."
            )
        if _auth_disabled():
            logger.error("HEAVEN_DISABLE_AUTH is enabled — DO NOT USE IN PRODUCTION")
        yield
        # Shutdown — close any open WebSockets
        for ws in list(ws_connections) + list(log_ws_connections):
            try:
                await ws.close(code=1001, reason="Server shutting down")
            except Exception:
                pass

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
                    return json.loads(file_path.read_text())
                except Exception as e:
                    logger.error(f"Failed to read report {scan_id}: {e}")
            return {}

        files = glob.glob(str(d / "report_*.json"))
        if not files:
            return {}
        latest_file = max(files, key=os.path.getmtime)
        try:
            with open(latest_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read latest report {latest_file}: {e}")
            return {}

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
        eng_store = _engagement_store_factory()
        eng_findings = []
        if eng_store:
            try:
                eng_findings = [f.__dict__ for f in eng_store.list_findings(limit=1000)]
            except Exception:
                pass

        # Fallback: report JSON files (written by CLI scans without engagement set)
        report_findings: list[dict] = []
        data = _get_latest_report_data(scan_id)
        report_findings = data.get("vulnerabilities", []) or data.get("findings", [])

        # Merge — engagement store takes priority
        vulns = eng_findings if eng_findings else report_findings

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in vulns:
            s = (f.get("severity") or "info").lower()
            if s in sev:
                sev[s] += 1

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
                pass

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

        top_vulns = sorted(vulns, key=lambda f: float(f.get("priority_score") or f.get("predicted_cvss_score") or 0), reverse=True)[:5]

        # Real host topology — aggregated from actual findings. Each node is a
        # host that a scan actually touched; severity is the worst finding on
        # it. No demo/placeholder data.
        from heaven.engagement import _host_key
        _sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        host_map: dict[str, dict] = {}
        for f in vulns:
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

        active_scans[scan_id] = {
            "status": "pending",
            "config": req.dict(),
            "created": datetime.now(timezone.utc).isoformat(),
            "created_by": user.username,
        }

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_STARTED, target=",".join((req.targets or []) + (req.urls or []))[:200],
            details={"scan_id": scan_id, "mode": req.scan_type}, actor=user.username,
            severity=AuditSeverity.INFO,
        )

        # Resolve engagement: explicit field > env var > active pointer > default.
        # Persist it as the active engagement so the dashboard, findings and
        # reports immediately follow this scan's data (previously they always
        # read the fixed "default" store, so a named-engagement scan vanished
        # from the UI and the report said "no findings").
        req.engagement = _resolve_engagement_name(req.engagement)
        _set_active_engagement(req.engagement)

        active_scans[scan_id]["scan_id"] = scan_id
        active_scans[scan_id]["engagement"] = req.engagement
        # Keep a strong reference to the task in a module-level set. Without it,
        # asyncio only holds a weak ref and the GC can kill a running scan
        # mid-flight. The ref must NOT live in active_scans — that dict is
        # JSON-serialised by the API and a Task object is not serialisable.
        task = asyncio.create_task(_run_scan_background(scan_id, req))
        _background_scan_tasks.add(task)

        def _scan_done(t: asyncio.Task):
            _background_scan_tasks.discard(t)
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
        user: User = Depends(require_permission("scan.view")),
    ):
        # In-memory scans (current session)
        mem = [{**v, "scan_id": k} for k, v in active_scans.items()]
        # Persisted scans from engagement store
        persisted = []
        store = _engagement_store_factory()
        if store:
            try:
                for s in store.list_scans(limit=limit):
                    sid = s.get("scan_id") or s.get("id", "")
                    if sid not in active_scans:
                        persisted.append(s)
            except Exception:
                pass
        combined = mem + persisted
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
            store = _engagement_store_factory()
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
            store = _engagement_store_factory()
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
        if mem and mem.get("status") in ("running", "pending"):
            mem["status"] = "cancelled"
            return {"status": "cancelled", "scan_id": scan_id}

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
        user: User = Depends(require_permission("scan.view")),
    ):
        data = _get_latest_report_data(scan_id)
        assets = data.get("assets", [])
        return {"assets": assets[:limit], "total": len(assets)}

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
        store = _engagement_store_factory()
        try:
            eng = store.get_engagement()
            stats = store.stats()
            no_engagement = stats.get("total_findings", 0) == 0 and stats.get("scans_run", 0) == 0
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
                    st = EngagementStore(db)
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
                    continue
        # The active engagement may not have a DB yet (nothing scanned) — still
        # surface it so the switcher shows a consistent current selection.
        if active not in seen:
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
        store = _engagement_store_factory()
        results = store.list_findings(
            severity=severity, status=status, target=target,
            vuln_type=vuln_type, min_confidence=min_confidence, limit=limit,
            scan_id=scan_id,
        )
        return {
            "findings": [
                {**f.__dict__} for f in results
            ],
            "count": len(results),
        }

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

    @app.get("/api/engagement/findings/{finding_id}/evidence")
    async def get_finding_evidence(
        finding_id: str,
        user: User = Depends(require_permission("vuln.view")),
    ):
        """Full evidence package for a finding (request, response, repro)."""
        store = _engagement_store_factory()
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

        store = _engagement_store_factory(engagement)
        eng = store.get_engagement()
        eng_name = (eng.name if eng else None) or engagement or \
            os.environ.get("HEAVEN_ENGAGEMENT") or "HEAVEN Engagement"
        # Strip a stray .db (engagement may resolve from a DB filename) so the
        # downloaded report isn't named "heaven-report-foo.db.json".
        if eng_name.endswith(".db"):
            eng_name = eng_name[:-3]
        rows = store.list_findings(limit=10000)
        if not rows:
            raise HTTPException(404, "No findings to report for this engagement")
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
            findings.append(enrich_finding(d))

        fmt = (format or "html").lower()
        media = {
            "html": "text/html", "markdown": "text/markdown", "csv": "text/csv",
            "json": "application/json", "sarif": "application/json",
            "burp": "application/xml", "proxy-jsonl": "application/x-ndjson",
        }
        ext = {"markdown": "md", "proxy-jsonl": "jsonl"}
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", eng_name)[:60] or "engagement"
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
                ok = PDFReportGenerator().generate(
                    {"engagement": eng_name, "vulnerabilities": findings,
                     "findings": findings}, tmp.name)
                if not ok or not os.path.getsize(tmp.name):
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
                    raise HTTPException(500, "PDF generation failed (reportlab installed?)")
                # Delete the temp file once the response has been streamed.
                return FileResponse(tmp.name, media_type="application/pdf",
                                    filename=f"heaven-report-{safe}.pdf",
                                    background=BackgroundTask(_safe_unlink, tmp.name))
            if fmt == "html":
                from heaven.devsecops.compliance_report import ComplianceReportGenerator
                body = ComplianceReportGenerator().generate_html_report(
                    findings, engagement_name=eng_name)
            elif fmt == "markdown":
                from heaven.devsecops.evidence import export_findings_markdown
                body = export_findings_markdown(findings, engagement_name=eng_name)
            elif fmt == "csv":
                from heaven.devsecops.evidence import export_findings_csv
                body = export_findings_csv(findings)
            elif fmt == "json":
                body = json.dumps(findings, indent=2, default=str)
            elif fmt == "sarif":
                from heaven.devsecops.aggregator import export_sarif
                body = json.dumps(export_sarif({"vulnerabilities": findings}), indent=2)
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
        """Report whether the current LLM configuration is usable.

        Cheap check only — confirms a provider is selected, a key is present and
        the SDK is importable. Does not make a billed API call.
        """
        try:
            from heaven.ai.llm_gateway import LLMGateway
            gw = LLMGateway()
            return {
                "provider": gw.provider or None,
                "model": gw.model or None,
                "available": bool(gw.available),
                "reason": (
                    "ready" if gw.available else
                    "no provider/key configured" if not (gw.provider and gw.api_key) else
                    "provider SDK not installed (pip install the provider extra)"
                ),
            }
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
        from heaven.devsecops.vuln_kb import lookup as kb_lookup
        store = _engagement_store_factory()
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
            remediation = (ev.get("remediation")
                           or kb_lookup(getattr(f, "vuln_type", "")).get("remediation") or "")
            top.append({
                "id": getattr(f, "id", ""),
                "title": getattr(f, "title", ""),
                "severity": getattr(f, "severity", ""),
                "vuln_type": getattr(f, "vuln_type", ""),
                "target": getattr(f, "target", ""),
                "risk_score": getattr(f, "risk_score", 0),
                "confidence": getattr(f, "confidence", 0),
                "remediation": remediation,
            })
        return {"findings": top, "total": len(results)}

    # ══════════════════════════════════════════════════════════════════
    # System health — the web-UI equivalent of `heaven doctor`
    # ══════════════════════════════════════════════════════════════════

    # Install hints surfaced next to any missing external tool, so the operator
    # knows exactly how to enable a degraded capability.
    _TOOL_HINTS = {
        "nmap": "apt install nmap  ·  brew install nmap",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "sqlmap": "apt install sqlmap  ·  pip install sqlmap",
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        "searchsploit": "apt install exploitdb",
        "semgrep": "pip install semgrep",
        "docker": "https://docs.docker.com/get-docker/",
    }
    _TOOL_PURPOSE = {
        "nmap": "Network port/service scanning",
        "nuclei": "Template-based vulnerability checks",
        "sqlmap": "Automated SQL-injection exploitation proof",
        "ffuf": "Content/directory fuzzing",
        "searchsploit": "Local Exploit-DB PoC lookup",
        "semgrep": "Static analysis (SAST)",
        "docker": "Container/Kubernetes recon + DVWA benchmark",
    }

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

        report = _collect_status(None)
        # Enrich external tools with purpose + install hint.
        tools = []
        for name, present in (report.get("external_tools") or {}).items():
            tools.append({
                "name": name, "present": bool(present),
                "purpose": _TOOL_PURPOSE.get(name, ""),
                "hint": "" if present else _TOOL_HINTS.get(name, ""),
            })
        report["tools"] = tools
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
        store = _engagement_store_factory()
        result = seed_demo(store)
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
            store = _engagement_store_factory()
            try:
                store.record_scan_start(scan_id, name="Demo scan (sample)", mode="full")
                phases = [
                    ("Reconnaissance", 20), ("Crawling endpoints", 45),
                    ("Injection testing", 70), ("Risk scoring + reporting", 90),
                ]
                for label, pct in phases:
                    await asyncio.sleep(phase_delay)
                    if active_scans.get(scan_id, {}).get("status") == "cancelled":
                        return
                    active_scans[scan_id]["phase"] = label
                    active_scans[scan_id]["progress_pct"] = pct
                res = insert_findings(store, scan_id)
                store.record_scan_complete(scan_id, res["summary"])
                active_scans[scan_id].update(
                    status="completed", progress_pct=100, phase="Done",
                    findings_count=res["findings"],
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
        all_scans = store.list_all_scans()
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
                pass

        cfg = get_config()
        orch = build_full_scan(targets, cfg, checkpoint_store=store)
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
                        pass
                store.record_scan_complete(orch.scan_id, summary)
            except Exception as e:
                logger.error(f"replay scan {orch.scan_id} failed: {e}")

        asyncio.create_task(_run())
        return {"new_scan_id": orch.scan_id, "replayed_from": target_scan["id"], "seed": seed}

    # ── Gap 4: Exploitation proof — actively confirm a finding ──

    @app.post("/api/findings/{finding_id}/prove")
    async def prove_finding_endpoint(
        finding_id: str,
        engagement: Optional[str] = Query(None),
        external_callback_url: Optional[str] = Query(None),
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Run the exploit-proof dispatcher on one finding.

        Adds proof artifacts to finding.evidence.exploit_proof[].
        Refuses to run without vuln.validate permission AND an authorized=True flag
        (auth gating is built into the prover, the permission check is the second).
        """
        try:
            from heaven.vulnscan.exploit_proof import prove_finding
        except Exception as e:
            raise HTTPException(500, f"exploit_proof not importable: {e}")

        store = _engagement_store_factory(engagement)
        f = store.get_finding(finding_id)
        if not f:
            raise HTTPException(404, f"Finding {finding_id} not found")
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "evidence": f.evidence or {},
        }
        # The permission gate above is the operator's authorization — pass through
        out = await prove_finding(
            finding_dict, authorized=True,
            external_callback_url=external_callback_url or "",
        )
        store.upsert_finding(scan_id=f.scan_id, finding=out)
        return {
            "finding_id": finding_id,
            "proved": bool(out.get("proved", False)),
            "exploit_proof": out.get("evidence", {}).get("exploit_proof", []),
        }

    # ── Gap 6: Agentic AI — manual triggers ──

    @app.post("/api/ai/{kind}/run")
    async def run_ai_layer(
        kind: str, request: Request,
        user: User = Depends(require_permission("vuln.validate")),
    ):
        """Trigger an AI layer manually. kind ∈ {recon-parse, plan, fp-review}.

        Body JSON varies by kind:
          recon-parse: {"recon": {host data}}
          plan:        {"findings": [...], "assets": [...], "objective_hint": ""}
          fp-review:   {"finding": {...}}

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
                from heaven.ai import AttackChainPlanner
                planner = AttackChainPlanner()
                if not planner.available:
                    return {"skipped": "LLM gateway unavailable"}
                out = await planner.plan(
                    findings=body.get("findings", []),
                    assets=body.get("assets", []),
                    objective_hint=body.get("objective_hint", ""),
                )
                return out.model_dump() if hasattr(out, "model_dump") else out.__dict__
            if kind == "fp-review":
                from heaven.ai import FPReviewer
                reviewer = FPReviewer()
                if not reviewer.available:
                    return {"skipped": "LLM gateway unavailable"}
                verdict = await reviewer.review(body.get("finding", {}))
                if verdict is None:
                    return {"skipped": "finding outside review band"}
                return verdict.model_dump() if hasattr(verdict, "model_dump") else verdict.__dict__
        except Exception as e:
            raise HTTPException(500, f"AI {kind} failed: {e}")

        raise HTTPException(400, f"unknown AI layer kind: {kind!r}")

    # ── Gap 5: Post-exploitation triggers (admin only — destructive) ──

    @app.post("/api/postex/{module}/run")
    async def run_postex(
        module: str, request: Request,
        user: User = Depends(require_permission("config.modify")),
    ):
        """Run a post-exploitation module. module ∈ {linpeas, bloodhound, cred-reuse}.

        Body JSON depends on module:
          linpeas:    {"host": "...", "username": "...", "password": "..."}
          bloodhound: {"domain": "...", "dc_host": "...", "username": "...", "password": "..."}
          cred-reuse: {"credentials": [["u","p"], ...], "targets": [["h", port, "ssh"], ...]}

        These all require explicit authorization — admin permission is the gate.
        Output is returned synchronously for now (long-running modules log progress).
        """
        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
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
        """Return the markdown content of every methodology mapping doc."""
        docs_dir = Path(__file__).parent.parent.parent / "docs" / "methodology"
        if not docs_dir.exists():
            return {"docs": []}
        out = []
        for md in sorted(docs_dir.glob("*.md")):
            try:
                out.append({"name": md.stem, "content": md.read_text(encoding="utf-8")})
            except Exception:
                pass
        return {"docs": out}

    # ── Gap 1: Latest benchmark results ──

    @app.get("/api/benchmark/results")
    async def latest_benchmark(user: User = Depends(require_permission("scan.view"))):
        """Return the most-recent aggregated benchmark report markdown."""
        reports = Path(__file__).parent.parent.parent / "tests" / "benchmarks" / "reports"
        agg = reports / "dvwa_aggregated.md"
        if not agg.exists():
            return {
                "available": False,
                "note": "No benchmark results yet. Run: HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/",
            }
        return {
            "available": True,
            "target": "dvwa",
            "markdown": agg.read_text(encoding="utf-8"),
        }

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
                pass

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
        store = _engagement_store_factory(engagement)
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

        engagement = body.get("engagement")
        if engagement and result.success:
            import uuid as _uuid
            from pathlib import Path as _P
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
            out = result.to_dict()
            out["engagement_scan_id"] = scan_id
            out["persisted_count"] = persisted
            return out
        return result.to_dict()

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
        report = compute_diff(store, baseline, scan_id)
        out = report.to_dict()
        if include_unchanged:
            from heaven.devsecops.diff_finder import _row_dict
            out["unchanged"] = [_row_dict(r) for r in report.unchanged]
        return out

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
 <h1>&#9889; HEAVEN</h1>
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


async def _run_scan_background(scan_id: str, req: ScanRequest):
    """Run a scan in the background, persist findings to engagement store and report file."""
    active_scans[scan_id]["status"] = "running"
    active_scans[scan_id]["progress_pct"] = 0

    # Engagement store — always open one (defaults to "default" engagement)
    engagement_name = req.engagement or os.environ.get("HEAVEN_ENGAGEMENT") or "default"
    store = None
    try:
        store = _engagement_store_factory(engagement_name)
        # Auto-create engagement record so the header/dashboard shows it
        store.create_engagement(name=engagement_name)
        store.record_scan_start(scan_id, name=req.name or engagement_name,
                                mode=req.mode or req.scan_type or "web")
    except Exception as e:
        logger.warning(f"Could not open engagement store '{engagement_name}': {e}")

    try:
        from heaven.orchestrator import build_full_scan
        from heaven.config import get_config
        cfg = get_config()

        orch = build_full_scan(
            {
                "ips": req.targets,
                "urls": req.urls,
                "repositories": req.repositories,
                "cloud_providers": req.cloud_providers,
                "ports": req.ports,
                "stealth_level": {1: "paranoid", 2: "stealth", 3: "normal", 4: "aggressive"}.get(
                    req.stealth_level or 3, "normal"
                ),
            },
            cfg,
            checkpoint_store=store,
        )

        # Track which findings we've already persisted to avoid duplicates
        persisted_finding_keys: set[str] = set()

        async def progress_update(progress):
            pct = getattr(progress, "progress_pct", None)
            if pct is not None:
                active_scans[scan_id]["progress_pct"] = round(pct)
            active_scans[scan_id]["progress"] = progress.to_dict() if hasattr(progress, "to_dict") else {}
            for ws in list(ws_connections):
                try:
                    await ws.send_json({"scan_id": scan_id, **(progress.to_dict() if hasattr(progress, "to_dict") else {})})
                except Exception:
                    pass

            # Flush any new findings to the engagement store in real time
            if store:
                try:
                    for tid, res in orch.results.items():
                        if res.state != "completed" or not res.data:
                            continue
                        data = res.data if isinstance(res.data, dict) else {}
                        for key in ("vulnerabilities", "findings", "candidates", "validated_findings"):
                            for f in data.get(key, []):
                                fkey = f"{f.get('target','')}:{f.get('vuln_type','')}:{f.get('title','')}"
                                if fkey not in persisted_finding_keys:
                                    persisted_finding_keys.add(fkey)
                                    try:
                                        store.upsert_finding(scan_id, f)
                                    except Exception:
                                        pass
                    # Live count = real deduped rows in the store, so the scan
                    # list and the engagement view never disagree.
                    active_scans[scan_id]["findings_count"] = store.count_findings(scan_id)
                except Exception:
                    pass

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
                for finding in findings:
                    store.upsert_finding(scan_id, finding)
                # Authoritative finding count = deduped rows actually in the
                # store, so the scan list, kill chain and engagement view all
                # report the same number.
                persisted_count = store.count_findings(scan_id)
                active_scans[scan_id]["findings_count"] = persisted_count
                store.record_scan_complete(scan_id, summary={
                    "total": persisted_count,
                    "elapsed_seconds": result.get("elapsed_seconds", 0),
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
                "config": req.dict(),
                "vulnerabilities": findings,
                "findings": findings,
                "assets": result.get("assets", []),
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

    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        logger.error(f"Background scan {scan_id} failed: {e}", exc_info=True)

        if store:
            try:
                store.record_scan_complete(scan_id, summary={"error": str(e)}, status="failed")
            except Exception:
                pass

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_FAILED, target=scan_id, details={"error": str(e)},
            actor=active_scans[scan_id].get("created_by", "system"),
            severity=AuditSeverity.WARNING,
        )

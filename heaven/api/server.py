"""
HEAVEN — FastAPI Application & REST API
Central API server with WebSocket support, JWT/API-key auth, and RBAC.
"""

from __future__ import annotations

import asyncio
import os
import re
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


def _engagement_store_factory(name: Optional[str] = None):
    """Resolve engagement store. Falls back to env var, then a default DB."""
    from heaven.config import get_config
    from heaven.engagement import EngagementStore

    data_dir = get_config().data_dir
    path = name or os.environ.get("HEAVEN_ENGAGEMENT") or "default"
    # If it's just a name (no path separator), put it in data_dir
    p = Path(path)
    if not p.suffix and not p.is_absolute() and "/" not in path and "\\" not in path:
        p = data_dir / "engagements" / f"{path}.db"
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

    class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
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

        scan_id = uuid.uuid4().hex[:8]

        # Sort targets into ips and urls
        ips = []
        urls = list(req.urls)
        for t in req.targets:
            if _URL_REGEX.match(t):
                urls.append(t)
            else:
                ips.append(t)
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

        # Resolve engagement: explicit field > env var
        if not req.engagement:
            req.engagement = os.environ.get("HEAVEN_ENGAGEMENT")

        active_scans[scan_id]["scan_id"] = scan_id
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
        user: User = Depends(require_permission("scan.view")),
    ):
        if scan_id not in active_scans:
            raise HTTPException(404, "Scan not found")
        return active_scans[scan_id]

    @app.delete("/api/scans/{scan_id}")
    async def cancel_scan(
        scan_id: str,
        user: User = Depends(require_permission("scan.cancel")),
    ):
        if scan_id not in active_scans:
            raise HTTPException(404, "Scan not found")
        active_scans[scan_id]["status"] = "cancelled"
        return {"status": "cancelled", "scan_id": scan_id}

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

    @app.get("/api/engagement/findings")
    async def engagement_findings(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        target: Optional[str] = None,
        vuln_type: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = Query(100, ge=1, le=10000),
        user: User = Depends(require_permission("vuln.view")),
    ):
        """List findings from the active engagement."""
        store = _engagement_store_factory()
        results = store.list_findings(
            severity=severity, status=status, target=target,
            vuln_type=vuln_type, min_confidence=min_confidence, limit=limit,
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
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "confidence_bucket": f.confidence_bucket, "cve_id": f.cve_id,
            "risk_score": f.risk_score, "status": f.status,
            "operator_notes": f.operator_notes, "evidence": f.evidence,
        }
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

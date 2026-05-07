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
from typing import Any, Optional

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Depends, Header, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import JSONResponse, FileResponse
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


# ── Active scan tracking ──
active_scans: dict[str, Any] = {}
ws_connections: list = []
log_ws_connections: list = []


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
    """Broadcast log records to connected WebSockets."""

    def emit(self, record):
        msg = self.format(record)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        for ws in list(log_ws_connections):
            try:
                loop.create_task(ws.send_text(msg))
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
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
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
                            "vulns": s.get("n_findings", 0),
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

        return DashboardData(
            total_scans=len(all_scans),
            total_assets=len(set(f.get("target", "") for f in vulns if f.get("target"))),
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
        asyncio.create_task(_run_scan_background(scan_id, req))
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
    def _engagement_store_factory(name: Optional[str] = None):
        from pathlib import Path
        from heaven.config import get_config
        _data_dir = get_config().data_dir
        """Resolve engagement store. Falls back to env var, then a default DB."""
        import os
        from heaven.engagement import EngagementStore
        path = name or os.environ.get("HEAVEN_ENGAGEMENT") or "default"
        # If it's just a name (no path separator), put it in data_dir
        p = Path(path)
        if not p.suffix and not p.is_absolute() and "/" not in path and "\\" not in path:
            p = _data_dir / "engagements" / f"{path}.db"
        return EngagementStore(p)

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

    # Serve static frontend
    ui_dist = Path(__file__).parent.parent.parent / "heaven-ui" / "dist"
    if ui_dist.exists():
        app.mount("/", StaticFiles(directory=str(ui_dist), html=True), name="frontend")

        @app.exception_handler(404)
        async def custom_404_handler(request, exc):
            if request.url.path.startswith("/api/"):
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            return FileResponse(ui_dist / "index.html")

    return app


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
        cfg.stealth_level = req.stealth_level or 3

        orch = build_full_scan(
            {
                "ips": req.targets,
                "urls": req.urls,
                "repositories": req.repositories,
                "cloud_providers": req.cloud_providers,
                "ports": req.ports,
                "stealth_level": req.stealth_level or 3,
            },
            cfg,
            checkpoint_store=store,
        )

        # Track which findings we've already persisted to avoid duplicates
        persisted_finding_keys: set[str] = set()

        async def progress_update(progress):
            pct = getattr(progress, "percent", None)
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
                                        count = active_scans[scan_id].get("findings_count", 0) + 1
                                        active_scans[scan_id]["findings_count"] = count
                                    except Exception:
                                        pass
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
                store.record_scan_complete(scan_id, summary={
                    "total": len(findings),
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

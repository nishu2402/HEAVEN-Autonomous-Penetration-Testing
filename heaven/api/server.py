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
    i_have_authorization: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingStatusUpdate(BaseModel):
    status: str
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
        data = _get_latest_report_data(scan_id)
        summary = data.get("summary", {})

        vulns = data.get("vulnerabilities", [])
        avg_risk = sum(v.get("risk_score", 0) for v in vulns) / len(vulns) if vulns else 0.0

        all_scans = []
        for sid, active in active_scans.items():
            if active.get("status") != "completed":
                all_scans.append({
                    "id": sid,
                    "name": active.get("config", {}).get("name", "HEAVEN Scan"),
                    "status": active.get("status", "running"),
                    "vulns": 0,
                    "date": active.get("created", ""),
                })

        d = _data_dir()
        for file in sorted(glob.glob(str(d / "report_*.json")), key=os.path.getmtime, reverse=True)[:10]:
            try:
                with open(file, "r") as f:
                    r = json.load(f)
                all_scans.append({
                    "id": r.get("scan_id", "unknown"),
                    "name": r.get("config", {}).get("name", "HEAVEN Scan") if "config" in r else "HEAVEN Scan",
                    "status": "completed",
                    "vulns": len(r.get("vulnerabilities", [])),
                    "date": r.get("timestamp", ""),
                })
            except Exception as e:
                logger.debug(f"Skipping unreadable report {file}: {e}")

        return DashboardData(
            total_scans=len(all_scans),
            total_assets=summary.get("total_assets", 0),
            total_vulns=summary.get("total_vulnerabilities", 0),
            critical=summary.get("critical", 0),
            high=summary.get("high", 0),
            medium=summary.get("medium", 0),
            low=summary.get("low", 0),
            confirmed=summary.get("confirmed", 0),
            secrets=summary.get("secrets_found", 0),
            avg_risk=round(avg_risk, 1),
            recent_scans=all_scans,
            top_vulns=vulns[:5],
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

        asyncio.create_task(_run_scan_background(scan_id, req))
        return ScanResponse(scan_id=scan_id, status="pending", message="Scan queued")

    @app.get("/api/scans")
    async def list_scans(
        limit: int = Query(20, ge=1, le=100),
        user: User = Depends(require_permission("scan.view")),
    ):
        return {"scans": list(active_scans.values())[:limit]}

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
    def _engagement_store_factory():
        """Resolve engagement store from env var; None if not set."""
        import os
        from heaven.engagement import EngagementStore
        path = os.environ.get("HEAVEN_ENGAGEMENT")
        if not path:
            return None
        return EngagementStore(path)

    @app.get("/api/engagement")
    async def engagement_summary(
        user: User = Depends(require_permission("scan.view")),
    ):
        """Active engagement summary + stats."""
        store = _engagement_store_factory()
        if not store:
            raise HTTPException(404, "No active engagement. Set HEAVEN_ENGAGEMENT env var.")
        eng = store.get_engagement()
        return {
            "engagement": eng.__dict__ if eng else None,
            "stats": store.stats(),
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
        if not store:
            raise HTTPException(404, "No active engagement.")
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
    """Run a scan in the background and update status."""
    active_scans[scan_id]["status"] = "running"

    try:
        from heaven.orchestrator import build_full_scan
        orch = build_full_scan({
            "ips": req.targets, "urls": req.urls,
            "repositories": req.repositories,
            "cloud_providers": req.cloud_providers,
            "ports": req.ports,
        })

        async def progress_update(progress):
            active_scans[scan_id]["progress"] = progress.to_dict()
            for ws in list(ws_connections):
                try:
                    await ws.send_json(progress.to_dict())
                except Exception:
                    pass

        orch.on_progress(progress_update)
        result = await orch.run()
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["result"] = result

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_COMPLETED, target=scan_id,
            details={"elapsed_s": result.get("elapsed_seconds", 0)},
            actor=active_scans[scan_id].get("created_by", "system"),
            severity=AuditSeverity.INFO,
        )

    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        logger.error(f"Background scan {scan_id} failed: {e}")

        from heaven.security.audit import get_audit_logger, AuditAction, AuditSeverity
        get_audit_logger().log(
            AuditAction.SCAN_FAILED, target=scan_id, details={"error": str(e)},
            actor=active_scans[scan_id].get("created_by", "system"),
            severity=AuditSeverity.WARNING,
        )

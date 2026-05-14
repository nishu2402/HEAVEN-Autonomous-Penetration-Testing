"""
HEAVEN — Database Package
=========================
Public interface for all database operations.

Quick-start
-----------
PostgreSQL (production)::

    from heaven.db import init_db, get_session
    await init_db()
    async with get_session() as session:
        repos = get_repository_factory(session)
        scan = await repos.scans.create(name="My Scan", scan_type="full")

SQLite (offline / local)::

    from heaven.db import init_sqlite, get_sqlite_connection
    await init_sqlite("data/heaven.db")
    async with get_sqlite_connection() as db:
        await db.execute("SELECT * FROM scans")

Health check::

    from heaven.db import health_check
    status = await health_check()
    # {"backend": "postgres", "postgres": {"status": "ok", "latency_ms": 1.2, ...}}
"""

from __future__ import annotations

# ── Connection layer ─────────────────────────────────────────────────────────
from heaven.db.connection import (
    bulk_insert,
    close_all,
    close_pool,
    execute_query,
    execute_scalar,
    get_backend,
    get_connection,
    get_engine,
    get_pool,
    get_session,
    get_session_factory,
    get_sqlite_connection,
    get_transaction,
    health_check,
    init_db,
    init_sqlite,
    is_connected,
)

# ── ORM models ───────────────────────────────────────────────────────────────
from heaven.db.models import (
    Asset,
    AuditLog,
    Base,
    CloudResource,
    Credential,
    DnsRecord,
    Engagement,
    EngagementScope,
    FindingTag,
    MitreTechnique,
    NetworkTopology,
    Notification,
    OperatorNote,
    Port,
    Report,
    RiskScore,
    Scan,
    ScanCheckpoint,
    ScanFinding,
    Secret,
    SslCertificate,
    Tag,
    Validation,
    Vulnerability,
    VulnChain,
    WebPath,
)

# ── Repository / DAL layer ───────────────────────────────────────────────────
from heaven.db.repository import (
    AssetRepository,
    AuditRepository,
    BaseRepository,
    EngagementRepository,
    NotificationRepository,
    ReportRepository,
    ScanRepository,
    VulnerabilityRepository,
    WebPathRepository,
    get_repository_factory,
)

__all__ = [
    # Connection
    "init_db",
    "init_sqlite",
    "health_check",
    "get_pool",
    "get_connection",
    "get_transaction",
    "get_session",
    "get_session_factory",
    "get_engine",
    "get_sqlite_connection",
    "close_pool",
    "close_all",
    "bulk_insert",
    "execute_query",
    "execute_scalar",
    "get_backend",
    "is_connected",
    # Models
    "Base",
    "Scan",
    "Asset",
    "Port",
    "Vulnerability",
    "Validation",
    "Secret",
    "RiskScore",
    "ScanFinding",
    "VulnChain",
    "Engagement",
    "EngagementScope",
    "DnsRecord",
    "SslCertificate",
    "WebPath",
    "Credential",
    "MitreTechnique",
    "NetworkTopology",
    "CloudResource",
    "Report",
    "Tag",
    "FindingTag",
    "OperatorNote",
    "ScanCheckpoint",
    "Notification",
    "AuditLog",
    # Repositories
    "BaseRepository",
    "ScanRepository",
    "AssetRepository",
    "VulnerabilityRepository",
    "EngagementRepository",
    "WebPathRepository",
    "NotificationRepository",
    "AuditRepository",
    "ReportRepository",
    "get_repository_factory",
]

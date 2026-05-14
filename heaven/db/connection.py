"""
HEAVEN — Async Database Connection Layer  (Ultra Edition)
==========================================================
Provides two backends:
  • PostgreSQL via asyncpg (high-perf raw queries) + SQLAlchemy async ORM
  • SQLite via aiosqlite (offline / local mode — zero-config fallback)

All callers use the same public interface regardless of which backend is active.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger("heaven.db")

# ── Optional heavy dependencies ───────────────────────────────────────────────

try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    asyncpg = None  # type: ignore[assignment]
    HAS_ASYNCPG = False

try:
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        AsyncEngine,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.pool import AsyncAdaptedQueuePool
    HAS_SQLALCHEMY = True
except ImportError:
    AsyncSession = None  # type: ignore[assignment,misc]
    AsyncEngine = None   # type: ignore[assignment,misc]
    HAS_SQLALCHEMY = False

try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    aiosqlite = None  # type: ignore[assignment]
    HAS_AIOSQLITE = False

# ── Pool singletons ───────────────────────────────────────────────────────────

_pg_pool: Optional[Any] = None          # asyncpg.Pool
_sa_engine: Optional[Any] = None        # AsyncEngine
_sa_session_factory: Optional[Any] = None
_sqlite_path: Optional[str] = None

# ── Backend mode ─────────────────────────────────────────────────────────────

_backend: str = "none"   # "postgres" | "sqlite" | "none"


def get_backend() -> str:
    """Return the currently active database backend."""
    return _backend


def is_connected() -> bool:
    """Return True if a usable DB connection is available."""
    return _backend in ("postgres", "sqlite")


# ═════════════════════════════════════════════════════════════════════════════
# PostgreSQL — asyncpg raw pool
# ═════════════════════════════════════════════════════════════════════════════

def _build_ssl_context(cfg) -> ssl.SSLContext | bool:
    """Build an SSL context from config, or return False to disable TLS."""
    ssl_mode = getattr(cfg, "ssl_mode", "prefer")
    if ssl_mode == "disable":
        return False
    ctx = ssl.create_default_context()
    ctx.check_hostname = ssl_mode in ("verify-full",)
    ctx.verify_mode = ssl.CERT_REQUIRED if ssl_mode in ("verify-ca", "verify-full") else ssl.CERT_NONE
    ca_cert = getattr(cfg, "ssl_ca_cert", None)
    if ca_cert:
        ctx.load_verify_locations(ca_cert)
    return ctx


async def get_pool(retry: int = 3, delay: float = 2.0) -> Any:
    """
    Get or create the asyncpg connection pool.
    Retries *retry* times with exponential backoff on connection failure.
    Raises RuntimeError if asyncpg is not installed.
    """
    global _pg_pool, _backend
    if not HAS_ASYNCPG:
        raise RuntimeError("asyncpg not installed — pip install asyncpg")

    if _pg_pool is not None:
        return _pg_pool

    from heaven.config import get_config
    cfg = get_config().db

    ssl_ctx = _build_ssl_context(cfg)
    last_exc: Exception | None = None

    for attempt in range(1, retry + 1):
        try:
            _pg_pool = await asyncpg.create_pool(
                host=cfg.host,
                port=cfg.port,
                database=cfg.name,
                user=cfg.user,
                password=cfg.password,
                ssl=ssl_ctx,
                min_size=3,
                max_size=20,
                max_inactive_connection_lifetime=300,
                command_timeout=60,
                statement_cache_size=100,
                server_settings={
                    "application_name": "heaven-pentest",
                    "jit": "off",          # deterministic explain plans
                },
            )
            _backend = "postgres"
            logger.info(
                "PostgreSQL pool ready — %s:%s/%s (min=3, max=20)",
                cfg.host, cfg.port, cfg.name,
            )
            return _pg_pool
        except (ConnectionRefusedError, OSError, Exception) as exc:
            last_exc = exc
            if attempt < retry:
                wait = delay * (2 ** (attempt - 1))
                logger.warning(
                    "DB connect attempt %d/%d failed: %s — retrying in %.1fs",
                    attempt, retry, exc, wait,
                )
                await asyncio.sleep(wait)

    raise ConnectionError(
        f"PostgreSQL unreachable after {retry} attempts: {last_exc}\n"
        "  Run: docker compose up -d postgres\n"
        "  Or:  heaven init-db"
    ) from last_exc


async def close_pool() -> None:
    """Close the asyncpg connection pool gracefully."""
    global _pg_pool, _backend
    if _pg_pool is not None:
        await _pg_pool.close()
        _pg_pool = None
        if _backend == "postgres":
            _backend = "none"
        logger.info("PostgreSQL pool closed")


@asynccontextmanager
async def get_connection() -> AsyncGenerator[Any, None]:
    """Acquire a raw asyncpg connection from the pool."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn


@asynccontextmanager
async def get_transaction() -> AsyncGenerator[Any, None]:
    """Acquire a raw asyncpg connection inside an explicit transaction."""
    async with get_connection() as conn:
        async with conn.transaction():
            yield conn


# ═════════════════════════════════════════════════════════════════════════════
# PostgreSQL — SQLAlchemy async ORM
# ═════════════════════════════════════════════════════════════════════════════

def get_engine(echo: bool | None = None) -> Any:
    """Get or create the SQLAlchemy async engine."""
    global _sa_engine
    if not HAS_SQLALCHEMY:
        raise RuntimeError("SQLAlchemy not installed — pip install sqlalchemy[asyncio]")

    if _sa_engine is not None:
        return _sa_engine

    from heaven.config import get_config
    cfg = get_config()
    _echo = cfg.debug if echo is None else echo

    _sa_engine = create_async_engine(
        cfg.db.async_dsn,
        echo=_echo,
        poolclass=AsyncAdaptedQueuePool,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=1800,          # recycle connections every 30 min
        connect_args={
            "server_settings": {"application_name": "heaven-orm"},
        },
    )
    return _sa_engine


def get_session_factory() -> Any:
    """Get or create the async session factory."""
    global _sa_session_factory
    if _sa_session_factory is None:
        engine = get_engine()
        _sa_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autobegin=True,
        )
    return _sa_session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[Any, None]:
    """
    Get an auto-committing async SQLAlchemy session.
    Rolls back and re-raises on any exception.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_nested_session(parent: Any) -> AsyncGenerator[Any, None]:
    """Create a SAVEPOINT nested transaction inside an existing session."""
    async with parent.begin_nested() as sp:
        try:
            yield parent
            await sp.commit()
        except Exception:
            await sp.rollback()
            raise


# ═════════════════════════════════════════════════════════════════════════════
# SQLite — offline / local fallback via aiosqlite
# ═════════════════════════════════════════════════════════════════════════════

async def init_sqlite(path: str = "data/heaven.db") -> None:
    """
    Initialise a local SQLite database for offline operation.
    Creates the minimal schema needed for core engagement tracking.
    """
    global _sqlite_path, _backend
    if not HAS_AIOSQLITE:
        raise RuntimeError("aiosqlite not installed — pip install aiosqlite")

    import os
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    _sqlite_path = path
    _backend = "sqlite"

    async with aiosqlite.connect(path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA cache_size=-64000")   # 64 MB page cache
        await _apply_sqlite_schema(db)
        await db.commit()

    logger.info("SQLite store initialised: %s", path)


async def _apply_sqlite_schema(db: Any) -> None:
    """Apply the SQLite schema (subset of PG schema for offline use)."""
    statements = _SQLITE_SCHEMA.strip().split(";")
    for stmt in statements:
        stmt = stmt.strip()
        if stmt:
            await db.execute(stmt)


@asynccontextmanager
async def get_sqlite_connection() -> AsyncGenerator[Any, None]:
    """Get a raw aiosqlite connection to the offline store."""
    if _sqlite_path is None:
        raise RuntimeError("SQLite not initialised — call init_sqlite() first")
    async with aiosqlite.connect(_sqlite_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys=ON")
        yield db


# ═════════════════════════════════════════════════════════════════════════════
# Schema initialisation
# ═════════════════════════════════════════════════════════════════════════════

async def init_db(force: bool = False) -> bool:
    """
    Initialise the PostgreSQL schema from schema.sql.

    Returns True on success, False if PostgreSQL is unavailable
    (HEAVEN continues in SQLite mode in that case).
    """
    if not HAS_ASYNCPG:
        logger.warning(
            "asyncpg not installed — PostgreSQL init skipped. "
            "Install: pip install asyncpg"
        )
        return False

    from pathlib import Path
    schema_path = Path(__file__).parent / "schema.sql"
    if not schema_path.exists():
        logger.error("Schema file missing: %s", schema_path)
        return False

    schema_sql = schema_path.read_text()

    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(schema_sql)
        logger.info("PostgreSQL schema applied successfully")
        return True
    except (ConnectionRefusedError, ConnectionError, OSError) as exc:
        logger.warning(
            "PostgreSQL unavailable (%s) — falling back to SQLite mode.\n"
            "  To enable PostgreSQL: docker compose up -d postgres && heaven init-db",
            exc,
        )
        return False
    except Exception as exc:
        logger.warning("PostgreSQL schema init failed: %s", exc)
        return False


async def health_check() -> dict[str, Any]:
    """
    Return a health status dict for all active DB backends.
    Used by the /health API endpoint.
    """
    result: dict[str, Any] = {
        "backend": _backend,
        "postgres": {"status": "disabled"},
        "sqlite": {"status": "disabled"},
    }

    # PostgreSQL check
    if HAS_ASYNCPG and _pg_pool is not None:
        t0 = time.monotonic()
        try:
            async with get_connection() as conn:
                row = await conn.fetchrow(
                    "SELECT version(), pg_database_size(current_database()) AS db_size"
                )
            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            result["postgres"] = {
                "status": "ok",
                "latency_ms": latency_ms,
                "version": (row["version"] if row else "unknown").split(" ")[1] if row else "?",
                "db_size_mb": round(row["db_size"] / 1_048_576, 2) if row else 0,
                "pool_size": _pg_pool.get_size(),
                "pool_free": _pg_pool.get_idle_size(),
            }
        except Exception as exc:
            result["postgres"] = {"status": "error", "error": str(exc)}

    # SQLite check
    if HAS_AIOSQLITE and _sqlite_path is not None:
        import os
        t0 = time.monotonic()
        try:
            async with get_sqlite_connection() as db:
                await db.execute("SELECT 1")
            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            size_mb = round(os.path.getsize(_sqlite_path) / 1_048_576, 2)
            result["sqlite"] = {
                "status": "ok",
                "latency_ms": latency_ms,
                "path": _sqlite_path,
                "size_mb": size_mb,
            }
        except Exception as exc:
            result["sqlite"] = {"status": "error", "error": str(exc)}

    return result


async def close_all() -> None:
    """Close all database connections and dispose engines."""
    global _sa_engine, _sa_session_factory, _backend
    await close_pool()
    if _sa_engine is not None:
        await _sa_engine.dispose()
        _sa_engine = None
        _sa_session_factory = None
        logger.info("SQLAlchemy engine disposed")
    _backend = "none"


# ═════════════════════════════════════════════════════════════════════════════
# Bulk helpers
# ═════════════════════════════════════════════════════════════════════════════

async def bulk_insert(table: str, rows: list[dict[str, Any]], on_conflict: str = "DO NOTHING") -> int:
    """
    Fast bulk INSERT using asyncpg's copy protocol fallback via executemany.
    Returns number of rows inserted.
    on_conflict: raw SQL clause, e.g. "DO NOTHING" or "DO UPDATE SET col=EXCLUDED.col"
    """
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ", ".join(f"${i + 1}" for i in range(len(cols)))
    col_names = ", ".join(f'"{c}"' for c in cols)
    sql = (
        f'INSERT INTO "{table}" ({col_names}) VALUES ({placeholders}) '
        f"ON CONFLICT {on_conflict}"
    )
    values = [tuple(row[c] for c in cols) for row in rows]
    try:
        async with get_connection() as conn:
            await conn.executemany(sql, values)
        return len(rows)
    except Exception as exc:
        logger.error("bulk_insert into %s failed: %s", table, exc)
        raise


async def execute_query(sql: str, *args: Any) -> list[dict[str, Any]]:
    """
    Execute a raw SQL query and return results as list of dicts.
    Uses asyncpg for maximum performance.
    """
    async with get_connection() as conn:
        rows = await conn.fetch(sql, *args)
        return [dict(r) for r in rows]


async def execute_scalar(sql: str, *args: Any) -> Any:
    """Execute a raw SQL query and return the first column of the first row."""
    async with get_connection() as conn:
        return await conn.fetchval(sql, *args)


# ═════════════════════════════════════════════════════════════════════════════
# SQLite offline schema (core tables only — keeps PG and SQLite in sync)
# ═════════════════════════════════════════════════════════════════════════════

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client_name TEXT,
    operator TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    notes TEXT,
    config TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'pending',
    target_spec TEXT DEFAULT '{}',
    config TEXT DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    stats TEXT DEFAULT '{}',
    error_log TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    hostname TEXT,
    metadata TEXT DEFAULT '{}',
    is_honeypot INTEGER DEFAULT 0,
    honeypot_score REAL DEFAULT 0.0,
    criticality INTEGER DEFAULT 1 CHECK (criticality BETWEEN 1 AND 5),
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_type, value)
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service TEXT,
    version TEXT,
    banner TEXT,
    cpe TEXT,
    fingerprint TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port_id TEXT REFERENCES ports(id) ON DELETE SET NULL,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    cve_id TEXT,
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    cvss_base REAL CHECK (cvss_base BETWEEN 0 AND 10),
    cvss_vector TEXT,
    epss_score REAL CHECK (epss_score BETWEEN 0 AND 1),
    risk_score REAL CHECK (risk_score BETWEEN 0 AND 100),
    exploit_available INTEGER DEFAULT 0,
    in_kev INTEGER DEFAULT 0,
    details TEXT DEFAULT '{}',
    remediation TEXT,
    refs TEXT DEFAULT '[]',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, cve_id, port_id)
);

CREATE TABLE IF NOT EXISTS web_paths (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    http_status INTEGER,
    content_type TEXT,
    response_size INTEGER,
    title TEXT,
    is_sensitive INTEGER DEFAULT 0,
    path_category TEXT DEFAULT 'other',
    redirect_url TEXT,
    tech_stack TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    service TEXT,
    protocol TEXT,
    username TEXT,
    password_hash TEXT,
    is_default INTEGER DEFAULT 0,
    is_valid INTEGER DEFAULT 0,
    source TEXT DEFAULT 'spray',
    confidence REAL DEFAULT 0.0,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    vuln_id TEXT REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    technique_id TEXT NOT NULL,
    sub_technique_id TEXT,
    tactic TEXT,
    technique_name TEXT,
    url TEXT,
    confidence REAL DEFAULT 0.0,
    evidence TEXT DEFAULT '{}',
    mapped_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL,
    report_type TEXT NOT NULL DEFAULT 'technical',
    format TEXT NOT NULL DEFAULT 'pdf',
    file_path TEXT,
    file_size INTEGER,
    finding_count INTEGER DEFAULT 0,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    generated_by TEXT DEFAULT 'heaven',
    checksum TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    color TEXT DEFAULT '#6366f1',
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS finding_tags (
    finding_id TEXT NOT NULL,
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    tagged_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (finding_id, tag_id)
);

CREATE TABLE IF NOT EXISTS operator_notes (
    id TEXT PRIMARY KEY,
    author TEXT,
    resource_type TEXT,
    resource_id TEXT,
    content TEXT NOT NULL,
    is_private INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    phase TEXT,
    completed_tasks TEXT DEFAULT '[]',
    state TEXT DEFAULT '{}',
    last_updated TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    severity TEXT DEFAULT 'info',
    category TEXT,
    title TEXT NOT NULL,
    message TEXT,
    is_read INTEGER DEFAULT 0,
    delivered_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sl_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_sl_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_sl_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_sl_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_sl_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_sl_notif_read ON notifications(is_read)
"""

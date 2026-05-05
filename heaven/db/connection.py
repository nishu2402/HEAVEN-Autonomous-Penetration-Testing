"""
HEAVEN — Async Database Connection Pool
Uses asyncpg for high-performance PostgreSQL access with connection pooling.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

try:
    import asyncpg
except ImportError:
    asyncpg = None  # type: ignore[assignment]

try:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
except ImportError:
    AsyncSession = None  # type: ignore[assignment,misc]

from heaven.config import get_config

logger = logging.getLogger("heaven.db")

# ── Raw asyncpg pool (for high-perf bulk operations) ──

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the asyncpg connection pool."""
    global _pool
    if _pool is None:
        cfg = get_config().db
        _pool = await asyncpg.create_pool(
            host=cfg.host,
            port=cfg.port,
            database=cfg.name,
            user=cfg.user,
            password=cfg.password,
            ssl=False,
            min_size=5,
            max_size=20,
            command_timeout=60,
        )
        logger.info(f"Database pool created: {cfg.host}:{cfg.port}/{cfg.name}")
    return _pool


async def close_pool() -> None:
    """Close the connection pool gracefully."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


@asynccontextmanager
async def get_connection() -> AsyncGenerator[asyncpg.Connection, None]:
    """Get a connection from the pool."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn


# ── SQLAlchemy async engine (for ORM operations) ──

_engine = None
_session_factory = None


def get_engine():
    """Get or create the SQLAlchemy async engine."""
    global _engine
    if _engine is None:
        cfg = get_config()
        _engine = create_async_engine(
            cfg.db.async_dsn,
            echo=cfg.debug,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async SQLAlchemy session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Initialise the database schema from schema.sql."""
    from pathlib import Path

    schema_path = Path(__file__).parent / "schema.sql"
    schema_sql = schema_path.read_text()

    try:
        async with get_connection() as conn:
            await conn.execute(schema_sql)
            logger.info("Database schema initialised")
    except (ConnectionRefusedError, OSError) as e:
        logger.error(
            f"Connection error: {e}\n"
            "The PostgreSQL database is not running or unreachable.\n"
            "Please start the database first using:\n"
            "    docker-compose up -d postgres"
        )
        import sys
        sys.exit(1)
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        import sys
        sys.exit(1)


async def close_all() -> None:
    """Close all database connections."""
    global _engine
    await close_pool()
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        logger.info("SQLAlchemy engine disposed")

"""
HEAVEN — Alembic environment.
Loads the database URL from the HEAVEN config (which itself reads env vars),
so secrets are never written into alembic.ini.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import the metadata so autogenerate works once SQLAlchemy models exist.
# Currently HEAVEN's `db/models.py` defines dataclasses, not SQLAlchemy models.
# When you add SQLAlchemy ORM tables in heaven.db.models, set target_metadata
# to your declarative Base.metadata.
try:
    from heaven.db.models import Base  # type: ignore
    target_metadata = Base.metadata
except (ImportError, AttributeError):
    target_metadata = None

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Pull DSN from heaven config — single source of truth, env-var driven
from heaven.config import get_config  # noqa: E402
heaven_cfg = get_config()
config.set_main_option("sqlalchemy.url", heaven_cfg.db.async_dsn)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no DB connection, emits SQL)."""
    url = config.get_main_option("sqlalchemy.url")
    # Strip the +asyncpg driver suffix for offline SQL emission
    sync_url = url.replace("+asyncpg", "") if url else url
    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode against an async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())

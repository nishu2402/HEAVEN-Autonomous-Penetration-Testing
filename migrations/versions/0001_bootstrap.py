"""Bootstrap from schema.sql

Revision ID: 0001_bootstrap
Revises:
Create Date: 2026-05-04

This is the *bootstrap* migration. It sources the canonical schema from
heaven/db/schema.sql so existing installs don't need to be torn down.
Future schema changes should be authored as new Alembic revisions, not by
editing schema.sql.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0001_bootstrap"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SCHEMA_FILE = Path(__file__).resolve().parent.parent.parent / "heaven" / "db" / "schema.sql"


def upgrade() -> None:
    """
    Apply the existing schema.sql as the baseline. We split on `;` carefully
    so we can execute each statement individually — Alembic's `op.execute`
    works one statement at a time.
    """
    if not SCHEMA_FILE.exists():
        raise RuntimeError(f"Schema file not found: {SCHEMA_FILE}")

    sql = SCHEMA_FILE.read_text()

    # Strip line comments to make splitting simpler
    cleaned_lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        cleaned_lines.append(line)
    sql = "\n".join(cleaned_lines)

    # Split on `;` at end of line; this is a simplification but works for
    # the existing schema.sql (no PL/pgSQL function bodies).
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    for stmt in statements:
        op.execute(stmt)


def downgrade() -> None:
    """Drop everything in the public schema."""
    op.execute("DROP SCHEMA IF EXISTS public CASCADE")
    op.execute("CREATE SCHEMA public")

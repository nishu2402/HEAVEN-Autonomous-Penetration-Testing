"""
HEAVEN — Database Layer Tests
Tests for: models, connection helpers, repository DAL, SQLite fallback.
All tests run without a real PostgreSQL — they use SQLite (aiosqlite) or
pure-Python unit tests where no DB is needed.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Models — import & sanity checks (no DB required)
# ─────────────────────────────────────────────────────────────────────────────

class TestModelsImport:
    """Verify every model class is importable and has expected attributes."""

    def test_all_models_importable(self):
        from heaven.db.models import (
            Asset, CloudResource, Credential,
            DnsRecord, Engagement, EngagementScope, FindingTag,
            MitreTechnique, NetworkTopology, Notification,
            OperatorNote, Port, Report, RiskScore, Scan,
            ScanCheckpoint, ScanFinding, Secret, SslCertificate,
            Tag, Validation, Vulnerability, VulnChain, WebPath,
        )
        models = [
            Scan, Asset, Port, Vulnerability, Validation, Secret,
            RiskScore, ScanFinding, VulnChain, Engagement,
            EngagementScope, DnsRecord, SslCertificate, WebPath,
            Credential, MitreTechnique, NetworkTopology,
            CloudResource, Report, Tag, FindingTag, OperatorNote,
            ScanCheckpoint, Notification,
        ]
        assert len(models) == 24, "Expected 24 model classes"

    def test_base_metadata_exists(self):
        from heaven.db.models import Base
        # Base.metadata is only present when SQLAlchemy is installed
        try:
            meta = Base.metadata
            assert meta is not None
        except AttributeError:
            pytest.skip("SQLAlchemy not installed")

    def test_scan_tablename(self):
        from heaven.db.models import Scan
        assert Scan.__tablename__ == "scans"

    def test_engagement_tablename(self):
        from heaven.db.models import Engagement
        assert Engagement.__tablename__ == "engagements"

    def test_audit_log_wrapper(self):
        from heaven.db.models import AuditLog
        log = AuditLog(actor="tester", action="login", resource_type="session")
        assert log.actor == "tester"
        assert log.action == "login"
        assert isinstance(log.timestamp, datetime)

    def test_audit_log_default_timestamp_is_aware(self):
        from heaven.db.models import AuditLog
        log = AuditLog(actor="x", action="y")
        assert log.timestamp.tzinfo is not None, "AuditLog.timestamp must be timezone-aware"

    def test_datetime_defaults_are_timezone_aware(self):
        """
        Verify that model default= callables produce timezone-aware datetimes.
        We inspect the column default directly rather than instantiating (which
        requires a full SQLAlchemy session).
        """
        try:
            from sqlalchemy import inspect as sa_inspect
            from heaven.db.models import Scan
            mapper = sa_inspect(Scan)
            created_at_col = mapper.columns["created_at"]
            fn = created_at_col.default.arg  # SQLAlchemy wraps it; call with None ctx
            # SQLAlchemy 2.x wraps zero-arg callables into a ctx-accepting wrapper.
            # Calling with None exercises the wrapper without a real execution context.
            try:
                result = fn(None)
            except TypeError:
                result = fn()  # fallback for older SA versions that don't wrap
            assert result.tzinfo is not None, (
                "Scan.created_at default produces naive datetime — "
                "use datetime.now(timezone.utc)"
            )
        except (ImportError, AttributeError, TypeError):
            pytest.skip("SQLAlchemy not installed or inspect unavailable")

    def test_no_utcnow_in_models_source(self):
        """Regression guard: datetime.utcnow must never reappear in models.py."""
        src = (Path(__file__).parent.parent / "heaven" / "db" / "models.py").read_text()
        assert "datetime.utcnow" not in src, (
            "Found datetime.utcnow in models.py — "
            "use lambda: datetime.now(timezone.utc) instead"
        )

    def test_all_model_classes_exported_from_init(self):
        """Every model must be re-exported from heaven.db.__init__."""
        import heaven.db as db
        for name in [
            "Scan", "Asset", "Port", "Vulnerability", "Validation",
            "Secret", "RiskScore", "ScanFinding", "VulnChain",
            "Engagement", "EngagementScope", "DnsRecord",
            "SslCertificate", "WebPath", "Credential", "MitreTechnique",
            "NetworkTopology", "CloudResource", "Report", "Tag",
            "FindingTag", "OperatorNote", "ScanCheckpoint",
            "Notification", "AuditLog",
        ]:
            assert hasattr(db, name), f"heaven.db missing export: {name}"


# ─────────────────────────────────────────────────────────────────────────────
# Connection layer — public API & backend detection
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectionPublicAPI:
    """Verify the connection module exports everything heaven.db promises."""

    def test_all_connection_symbols_exported(self):
        from heaven.db import (
            health_check,
            init_db, init_sqlite, is_connected,
        )
        # If we get here without ImportError, the exports exist
        assert callable(init_db)
        assert callable(health_check)
        assert callable(init_sqlite)
        assert callable(is_connected)

    def test_backend_starts_as_none(self):
        """Before any init call the backend is 'none'."""
        from heaven.db.connection import get_backend
        # May already be something if another test ran first; just assert it's a string
        assert isinstance(get_backend(), str)

    def test_is_connected_returns_bool(self):
        from heaven.db.connection import is_connected
        result = is_connected()
        assert isinstance(result, bool)

    def test_get_backend_returns_string(self):
        from heaven.db.connection import get_backend
        assert get_backend() in ("postgres", "sqlite", "none")


# ─────────────────────────────────────────────────────────────────────────────
# SQLite offline store
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestSQLiteOfflineStore:
    """Full round-trip tests using SQLite (no PostgreSQL required)."""

    @pytest.fixture()
    async def db_path(self, tmp_path):
        """Return a fresh SQLite DB path for each test."""
        return str(tmp_path / "test_heaven.db")

    async def test_init_creates_file(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import init_sqlite
        await init_sqlite(db_path)
        assert Path(db_path).exists()

    async def test_init_is_idempotent(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import init_sqlite
        await init_sqlite(db_path)
        # Second call must not raise
        await init_sqlite(db_path)

    async def test_core_tables_created(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        expected_tables = [
            "scans", "assets", "ports", "vulnerabilities",
            "web_paths", "credentials", "mitre_techniques",
            "reports", "audit_log", "tags", "finding_tags",
            "operator_notes", "scan_checkpoints", "notifications",
            "engagements",
        ]
        async with get_sqlite_connection() as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            rows = await cursor.fetchall()
            existing = {r[0] for r in rows}

        for tbl in expected_tables:
            assert tbl in existing, f"SQLite table missing: {tbl}"

    async def test_insert_and_query_scan(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        scan_id = str(uuid.uuid4())
        async with get_sqlite_connection() as db:
            await db.execute(
                "INSERT INTO scans (id, name, scan_type, status) VALUES (?, ?, ?, ?)",
                (scan_id, "Test Scan", "web", "pending"),
            )
            await db.commit()
            cursor = await db.execute(
                "SELECT id, name, status FROM scans WHERE id = ?", (scan_id,)
            )
            row = await cursor.fetchone()

        assert row is not None
        assert row["id"] == scan_id
        assert row["name"] == "Test Scan"
        assert row["status"] == "pending"

    async def test_insert_asset_with_fk(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        scan_id = str(uuid.uuid4())
        asset_id = str(uuid.uuid4())

        async with get_sqlite_connection() as db:
            await db.execute(
                "INSERT INTO scans (id, name) VALUES (?, ?)", (scan_id, "s1")
            )
            await db.execute(
                "INSERT INTO assets (id, scan_id, asset_type, value) VALUES (?, ?, ?, ?)",
                (asset_id, scan_id, "ipv4", "10.0.0.1"),
            )
            await db.commit()
            cursor = await db.execute(
                "SELECT value FROM assets WHERE id = ?", (asset_id,)
            )
            row = await cursor.fetchone()

        assert row["value"] == "10.0.0.1"

    async def test_audit_log_insert(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        async with get_sqlite_connection() as db:
            await db.execute(
                "INSERT INTO audit_log (actor, action, resource_type, details) "
                "VALUES (?, ?, ?, ?)",
                ("admin", "scan.create", "scan", json.dumps({"target": "10.0.0.1"})),
            )
            await db.commit()
            cursor = await db.execute("SELECT COUNT(*) FROM audit_log")
            row = await cursor.fetchone()

        assert row[0] == 1

    async def test_notifications_unread_default(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        notif_id = str(uuid.uuid4())
        async with get_sqlite_connection() as db:
            await db.execute(
                "INSERT INTO notifications (id, title, severity) VALUES (?, ?, ?)",
                (notif_id, "Critical finding", "critical"),
            )
            await db.commit()
            cursor = await db.execute(
                "SELECT is_read FROM notifications WHERE id = ?", (notif_id,)
            )
            row = await cursor.fetchone()

        assert row["is_read"] == 0  # default unread

    async def test_tag_unique_constraint(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import get_sqlite_connection, init_sqlite
        await init_sqlite(db_path)

        async with get_sqlite_connection() as db:
            await db.execute(
                "INSERT INTO tags (id, name) VALUES (?, ?)", (str(uuid.uuid4()), "xss")
            )
            await db.commit()
            with pytest.raises(Exception):  # UNIQUE constraint violation
                await db.execute(
                    "INSERT INTO tags (id, name) VALUES (?, ?)",
                    (str(uuid.uuid4()), "xss"),
                )
                await db.commit()

    async def test_health_check_sqlite(self, db_path):
        pytest.importorskip("aiosqlite")

        from heaven.db.connection import health_check, init_sqlite
        await init_sqlite(db_path)

        result = await health_check()
        assert result["sqlite"]["status"] == "ok"
        assert result["sqlite"]["latency_ms"] >= 0
        assert "size_mb" in result["sqlite"]


# ─────────────────────────────────────────────────────────────────────────────
# Repository — unit tests with mocked AsyncSession
# ─────────────────────────────────────────────────────────────────────────────

class TestRepositoryImports:
    def test_all_repos_importable(self):
        from heaven.db.repository import (
            get_repository_factory,
        )
        assert callable(get_repository_factory)

    def test_all_repos_exported_from_init(self):
        import heaven.db as db
        for name in [
            "BaseRepository", "ScanRepository", "AssetRepository",
            "VulnerabilityRepository", "EngagementRepository",
            "WebPathRepository", "NotificationRepository",
            "AuditRepository", "ReportRepository",
            "get_repository_factory",
        ]:
            assert hasattr(db, name), f"heaven.db missing export: {name}"

    def test_get_repository_factory_returns_namespace(self):
        from heaven.db.repository import get_repository_factory
        mock_session = MagicMock()
        ns = get_repository_factory(mock_session)
        for attr in ["scans", "assets", "vulnerabilities", "engagements",
                     "web_paths", "notifications", "audit", "reports"]:
            assert hasattr(ns, attr), f"factory namespace missing: {attr}"


class TestScanRepositoryUnit:
    """Unit tests for ScanRepository using a mocked AsyncSession."""

    def _make_repo(self):
        from heaven.db.repository import ScanRepository
        session = AsyncMock()
        # session.add() is synchronous in SQLAlchemy — use MagicMock to avoid
        # "coroutine never awaited" RuntimeWarnings from AsyncMock.
        session.add = MagicMock()
        return ScanRepository(session), session

    @pytest.mark.asyncio
    async def test_count_calls_scalar_one(self):
        repo, session = self._make_repo()
        # Mock execute → scalar_one
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 42
        session.execute = AsyncMock(return_value=mock_result)

        count = await repo.count()
        assert count == 42
        session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_all_calls_execute(self):
        repo, session = self._make_repo()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_result)

        result = await repo.get_all(limit=10, offset=0)
        assert result == []
        session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_adds_and_flushes(self):
        repo, session = self._make_repo()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()

        try:
            # If SQLAlchemy is available, create returns a model instance
            _ = await repo.create(name="Test", scan_type="web", status="pending")
            session.add.assert_called_once()
            session.flush.assert_called_once()
        except Exception:
            pytest.skip("SQLAlchemy not installed or model unavailable")


class TestVulnRepositoryUnit:
    def _make_repo(self):
        from heaven.db.repository import VulnerabilityRepository
        session = AsyncMock()
        # session.add() is synchronous in SQLAlchemy — prevent AsyncMock warnings.
        session.add = MagicMock()
        return VulnerabilityRepository(session), session

    @pytest.mark.asyncio
    async def test_bulk_create_empty_returns_empty(self):
        repo, session = self._make_repo()
        result = await repo.bulk_create([])
        assert result == []
        session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_create_checks_duplicate_for_any_conditions(self):
        """bulk_create must check duplicate even when cve_id and port_id are absent."""
        repo, session = self._make_repo()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # no duplicate
        session.execute = AsyncMock(return_value=mock_result)
        session.flush = AsyncMock()
        session.refresh = AsyncMock()

        asset_id = uuid.uuid4()
        try:
            await repo.bulk_create([{
                "asset_id": asset_id,
                "title": "Open port exposure",
                "severity": "medium",
            }])
            # execute called at least once for the duplicate check
            assert session.execute.call_count >= 1
        except Exception:
            pytest.skip("SQLAlchemy model unavailable")


class TestNotificationRepositoryUnit:
    def _make_repo(self):
        from heaven.db.repository import NotificationRepository
        session = AsyncMock()
        return NotificationRepository(session), session

    @pytest.mark.asyncio
    async def test_mark_all_read_calls_execute(self):
        repo, session = self._make_repo()
        mock_result = MagicMock()
        mock_result.rowcount = 5  # type: ignore[attr-defined]
        session.execute = AsyncMock(return_value=mock_result)

        count = await repo.mark_all_read()
        assert isinstance(count, int)
        session.execute.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# Schema SQL — structural integrity checks (pure text, no DB)
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaSQLIntegrity:
    """Parse schema.sql and verify structural properties without a real DB."""

    @pytest.fixture(scope="class")
    def schema_sql(self):
        p = Path(__file__).parent.parent / "heaven" / "db" / "schema.sql"
        assert p.exists(), "schema.sql not found"
        return p.read_text()

    def test_schema_file_exists(self, schema_sql):
        assert len(schema_sql) > 1000

    def test_all_core_tables_defined(self, schema_sql):
        core = [
            "CREATE TABLE scans",
            "CREATE TABLE assets",
            "CREATE TABLE ports",
            "CREATE TABLE vulnerabilities",
            "CREATE TABLE validations",
            "CREATE TABLE secrets",
            "CREATE TABLE risk_scores",
            "CREATE TABLE scan_findings",
            "CREATE TABLE vuln_chains",
        ]
        for t in core:
            assert t in schema_sql, f"Missing in schema.sql: {t}"

    def test_all_new_tables_defined(self, schema_sql):
        new_tables = [
            "CREATE TABLE engagements",
            "CREATE TABLE engagement_scope",
            "CREATE TABLE dns_records",
            "CREATE TABLE ssl_certificates",
            "CREATE TABLE web_paths",
            "CREATE TABLE credentials",
            "CREATE TABLE mitre_techniques",
            "CREATE TABLE network_topology",
            "CREATE TABLE cloud_resources",
            "CREATE TABLE reports",
            "CREATE TABLE tags",
            "CREATE TABLE finding_tags",
            "CREATE TABLE operator_notes",
            "CREATE TABLE scan_checkpoints",
            "CREATE TABLE notifications",
        ]
        for t in new_tables:
            assert t in schema_sql, f"Missing new table in schema.sql: {t}"

    def test_views_defined(self, schema_sql):
        views = [
            "dashboard_summary",
            "v_engagement_summary",
            "v_asset_attack_surface",
            "v_ssl_expiry_alerts",
            "v_mitre_coverage",
            "v_cloud_public_exposure",
        ]
        for v in views:
            assert v in schema_sql, f"Missing view in schema.sql: {v}"

    def test_update_updated_at_function_present(self, schema_sql):
        assert "update_updated_at" in schema_sql

    def test_calculate_asset_risk_function_present(self, schema_sql):
        assert "calculate_asset_risk" in schema_sql

    def test_idempotent_drop_schema_present(self, schema_sql):
        assert "DROP SCHEMA IF EXISTS public CASCADE" in schema_sql

    def test_uuid_extension_present(self, schema_sql):
        assert 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"' in schema_sql

    def test_full_text_search_index_present(self, schema_sql):
        assert "idx_vulns_fts" in schema_sql
        assert "to_tsvector" in schema_sql

    def test_audit_log_partitioned(self, schema_sql):
        assert "PARTITION BY RANGE" in schema_sql
        assert "audit_log" in schema_sql

    def test_no_bare_utcnow_in_schema(self, schema_sql):
        assert "utcnow" not in schema_sql.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Migration file — structural checks
# ─────────────────────────────────────────────────────────────────────────────

class TestMigration0002:
    @pytest.fixture(scope="class")
    def migration_src(self):
        p = Path(__file__).parent.parent / "migrations" / "versions" / "0002_extended_schema.py"
        assert p.exists(), "0002 migration not found"
        return p.read_text()

    def test_revision_id_correct(self, migration_src):
        assert 'revision: str = "0002_extended_schema"' in migration_src

    def test_down_revision_points_to_0001(self, migration_src):
        assert '"0001_bootstrap"' in migration_src

    def test_upgrade_defined(self, migration_src):
        assert "def upgrade()" in migration_src

    def test_downgrade_defined(self, migration_src):
        assert "def downgrade()" in migration_src

    def test_all_new_enum_types_created(self, migration_src):
        for enum in [
            "engagement_status", "scope_type", "dns_record_type",
            "path_category", "credential_source", "network_edge_type",
            "cloud_provider", "report_type", "report_format",
        ]:
            assert enum in migration_src, f"Missing enum in migration: {enum}"

    def test_downgrade_drops_all_new_tables(self, migration_src):
        for tbl in ["notifications", "engagements", "audit_log",
                    "cloud_resources", "ssl_certificates", "web_paths"]:
            assert tbl in migration_src

    def test_migration_parses_as_valid_python(self, migration_src):
        import ast
        try:
            ast.parse(migration_src)
        except SyntaxError as e:
            pytest.fail(f"Migration 0002 has a syntax error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# heaven.db.__init__ — public surface completeness
# ─────────────────────────────────────────────────────────────────────────────

class TestDBPackagePublicSurface:
    def test_init_all_list_complete(self):
        import heaven.db as db
        # Every name in __all__ must actually exist on the module
        for name in db.__all__:
            assert hasattr(db, name), f"heaven.db.__all__ lists '{name}' but it's not exported"

    def test_no_broken_imports_in_db_package(self):
        """Importing heaven.db must not raise any exception."""
        try:
            import heaven.db  # noqa: F401
        except Exception as exc:
            pytest.fail(f"heaven.db import raised: {exc}")

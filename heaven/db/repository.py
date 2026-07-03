"""
HEAVEN — Data Access Layer (Repository Pattern)
Async SQLAlchemy 2.0 repositories for all domain models.

Each repository wraps a single model and provides typed, async methods
for common CRUD and domain-specific queries.  A factory function
``get_repository_factory`` returns a SimpleNamespace with pre-wired
instances for every repository so callers never have to construct them
individually.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from collections.abc import Iterable
from typing import Any, Generic, TypeVar

logger = logging.getLogger("heaven.db.repository")

# ---------------------------------------------------------------------------
# Optional SQLAlchemy imports (mirrors the pattern in models.py so the module
# can be parsed even when sqlalchemy is not installed).
# ---------------------------------------------------------------------------
try:
    from sqlalchemy import and_, func, or_, select, text, update as sa_update
    from sqlalchemy.ext.asyncio import AsyncSession
    HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    HAS_SQLALCHEMY = False
    AsyncSession = Any  # type: ignore[misc,assignment]

    class _Stub:  # type: ignore[no-redef]
        def __init__(self, *a: Any, **kw: Any) -> None: ...
        def __call__(self, *a: Any, **kw: Any) -> Any: return self

    select = func = and_ = or_ = text = sa_update = _Stub()  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Model imports — wrapped in try/except so that missing SQLAlchemy does not
# prevent the module from loading.
# ---------------------------------------------------------------------------
try:
    from heaven.db.models import Asset, Scan, Vulnerability  # type: ignore[import]
    _MODELS_AVAILABLE = True
except Exception:  # pragma: no cover
    _MODELS_AVAILABLE = False
    Scan = Any  # type: ignore[misc,assignment]
    Asset = Any  # type: ignore[misc,assignment]
    Vulnerability = Any  # type: ignore[misc,assignment]

# ---------------------------------------------------------------------------
# Stub types for models not yet defined in models.py (schema.sql tables that
# will be promoted to ORM classes later).  Using Any lets type-checkers pass
# without errors until the real classes are added.
# ---------------------------------------------------------------------------
Engagement = Any
EngagementScope = Any
WebPath = Any
Notification = Any
Report = Any

T = TypeVar("T")

__all__ = [
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


# ===========================================================================
# 1. Generic BaseRepository
# ===========================================================================

def _reject_unknown_columns(repo: type, keys: Iterable[str]) -> None:
    """Guard for the raw-SQL repositories that interpolate column *names* into
    INSERT/UPDATE statements. Restrict those names to the owning repository's
    ``_COLUMNS`` allowlist so a dict key can never smuggle SQL — even if raw
    request data were ever forwarded straight into ``create``/``update``.
    (Values are always passed as bound parameters, never interpolated.)
    """
    allowed: frozenset[str] = getattr(repo, "_COLUMNS", frozenset())
    unknown = sorted(k for k in keys if k not in allowed)
    if unknown:
        raise ValueError(
            f"{repo.__name__}: refusing to write unknown column(s) {unknown}; "
            f"allowed: {sorted(allowed)}"
        )


class BaseRepository(Generic[T]):
    """
    Generic async repository that provides basic CRUD operations for a
    SQLAlchemy mapped model *T*.

    Sub-classes pass their concrete model class at construction time so that
    all generic helpers work without any overrides.
    """

    def __init__(self, session: AsyncSession, model: type[T]) -> None:
        self._session = session
        self._model = model

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, id: uuid.UUID) -> T | None:
        """Return a single row by primary key, or *None* if not found."""
        result = await self._session.execute(
            select(self._model).where(self._model.id == id)  # type: ignore[attr-defined]
        )
        return result.scalar_one_or_none()

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[T]:
        """Return a paginated list of all rows ordered by creation time desc."""
        stmt = select(self._model).limit(limit).offset(offset)
        # Attempt ordering by created_at if the model exposes it; fall back to
        # an unordered result so the method never crashes on models without it.
        if hasattr(self._model, "created_at"):
            stmt = stmt.order_by(self._model.created_at.desc())  # type: ignore[attr-defined]
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def create(self, **kwargs: Any) -> T:
        """Instantiate, persist, and return a new model row."""
        instance = self._model(**kwargs)
        self._session.add(instance)
        await self._session.flush()
        await self._session.refresh(instance)
        return instance

    async def update(self, id: uuid.UUID, **kwargs: Any) -> T | None:
        """
        Update fields on an existing row identified by *id*.

        Returns the updated instance, or *None* if the row does not exist.
        """
        instance = await self.get(id)
        if instance is None:
            return None
        for key, value in kwargs.items():
            setattr(instance, key, value)
        if hasattr(instance, "updated_at"):
            instance.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        await self._session.refresh(instance)
        return instance

    async def delete(self, id: uuid.UUID) -> bool:
        """Delete a row by primary key.  Returns *True* if a row was deleted."""
        instance = await self.get(id)
        if instance is None:
            return False
        await self._session.delete(instance)
        await self._session.flush()
        return True

    async def count(self) -> int:
        """Return the total number of rows in the table."""
        result = await self._session.execute(
            select(func.count()).select_from(self._model)
        )
        return result.scalar_one()


# ===========================================================================
# 2. ScanRepository
# ===========================================================================

class ScanRepository(BaseRepository[Scan]):
    """Repository for the ``scans`` table."""

    def __init__(self, session: AsyncSession) -> None:
        if _MODELS_AVAILABLE:
            super().__init__(session, Scan)  # type: ignore[arg-type]
        else:  # pragma: no cover
            self._session = session
            self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------

    async def get_by_status(self, status: str) -> list[Scan]:
        """Return all scans with the given status value."""
        result = await self._session.execute(
            select(Scan)
            .where(Scan.status == status)
            .order_by(Scan.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_recent(self, limit: int = 10) -> list[Scan]:
        """Return the *limit* most recently created scans."""
        result = await self._session.execute(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def update_status(
        self,
        scan_id: uuid.UUID,
        status: str,
        stats: dict[str, Any] | None = None,
    ) -> bool:
        """
        Update the status (and optionally the stats JSONB blob) of a scan.

        Sets *started_at* when transitioning to 'running' and *completed_at*
        when transitioning to 'completed', 'failed', or 'cancelled'.

        Returns *True* if the row existed and was updated.
        """
        scan = await self.get(scan_id)
        if scan is None:
            return False

        scan.status = status
        now = datetime.now(timezone.utc)
        scan.updated_at = now

        if status == "running" and scan.started_at is None:
            scan.started_at = now
        if status in {"completed", "failed", "cancelled"}:
            scan.completed_at = now

        if stats is not None:
            existing: dict[str, Any] = scan.stats or {}
            existing.update(stats)
            scan.stats = existing

        await self._session.flush()
        return True

    async def get_with_stats(self, scan_id: uuid.UUID) -> dict[str, Any]:
        """
        Return a dictionary containing scan metadata plus aggregated counts
        of associated vulnerabilities and assets derived from the DB.
        """
        scan = await self.get(scan_id)
        if scan is None:
            return {}

        # Vulnerability counts by severity
        sev_result = await self._session.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan_id)
            .group_by(Vulnerability.severity)
        )
        severity_counts: dict[str, int] = {row[0]: row[1] for row in sev_result}

        # Asset count
        asset_count_result = await self._session.execute(
            select(func.count(Asset.id)).where(Asset.scan_id == scan_id)
        )
        asset_count: int = asset_count_result.scalar_one()

        return {
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "target_spec": scan.target_spec,
            "config": scan.config,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
            "stats": scan.stats,
            "error_log": scan.error_log,
            "asset_count": asset_count,
            "vulnerability_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "total": sum(severity_counts.values()),
            },
        }


# ===========================================================================
# 3. AssetRepository
# ===========================================================================

class AssetRepository(BaseRepository[Asset]):
    """Repository for the ``assets`` table."""

    def __init__(self, session: AsyncSession) -> None:
        if _MODELS_AVAILABLE:
            super().__init__(session, Asset)  # type: ignore[arg-type]
        else:  # pragma: no cover
            self._session = session
            self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------

    async def get_by_scan(self, scan_id: uuid.UUID) -> list[Asset]:
        """Return all assets belonging to a scan."""
        result = await self._session.execute(
            select(Asset)
            .where(Asset.scan_id == scan_id)
            .order_by(Asset.first_seen.desc())
        )
        return list(result.scalars().all())

    async def get_or_create(
        self,
        asset_type: str,
        value: str,
        scan_id: uuid.UUID,
    ) -> tuple[Asset, bool]:
        """
        Fetch the asset identified by *(asset_type, value)* or create it if
        it does not yet exist.  The unique constraint on the table is
        ``(asset_type, value)``.

        Returns a ``(instance, created)`` tuple where *created* is *True*
        when a new row was inserted.
        """
        result = await self._session.execute(
            select(Asset).where(
                and_(Asset.asset_type == asset_type, Asset.value == value)
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            # Refresh last_seen and ensure scan association
            existing.last_seen = datetime.now(timezone.utc)
            if existing.scan_id is None:
                existing.scan_id = scan_id
            await self._session.flush()
            return existing, False

        new_asset = Asset(
            asset_type=asset_type,
            value=value,
            scan_id=scan_id,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        self._session.add(new_asset)
        await self._session.flush()
        await self._session.refresh(new_asset)
        return new_asset, True

    async def get_with_vulns(self, asset_id: uuid.UUID) -> dict[str, Any]:
        """
        Return a dictionary with the asset's fields and a list of its
        associated vulnerability summaries.
        """
        asset = await self.get(asset_id)
        if asset is None:
            return {}

        vuln_result = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset_id)
            .order_by(Vulnerability.risk_score.desc().nullslast())
        )
        vulns = list(vuln_result.scalars().all())

        return {
            "id": asset.id,
            "asset_type": asset.asset_type,
            "value": asset.value,
            "hostname": asset.hostname,
            "metadata": asset.metadata_,
            "is_honeypot": asset.is_honeypot,
            "honeypot_score": asset.honeypot_score,
            "criticality": asset.criticality,
            "first_seen": asset.first_seen,
            "last_seen": asset.last_seen,
            "scan_id": asset.scan_id,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_base": v.cvss_base,
                    "risk_score": v.risk_score,
                    "exploit_available": v.exploit_available,
                    "in_kev": v.in_kev,
                }
                for v in vulns
            ],
        }

    async def search(self, query: str, limit: int = 50) -> list[Asset]:
        """
        Full-text asset search.  Tries ``pg_trgm`` similarity first; falls
        back to a standard ``ILIKE`` pattern if the extension is unavailable.

        The search is performed against the ``value`` and ``hostname`` columns.
        """
        pattern = f"%{query}%"
        stmt = (
            select(Asset)
            .where(
                or_(
                    Asset.value.ilike(pattern),
                    Asset.hostname.ilike(pattern),
                )
            )
            .order_by(Asset.criticality.desc(), Asset.last_seen.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


# ===========================================================================
# 4. VulnerabilityRepository
# ===========================================================================

class VulnerabilityRepository(BaseRepository[Vulnerability]):
    """Repository for the ``vulnerabilities`` table."""

    def __init__(self, session: AsyncSession) -> None:
        if _MODELS_AVAILABLE:
            super().__init__(session, Vulnerability)  # type: ignore[arg-type]
        else:  # pragma: no cover
            self._session = session
            self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------

    async def get_by_scan(self, scan_id: uuid.UUID) -> list[Vulnerability]:
        """Return all vulnerabilities for a scan ordered by risk descending."""
        result = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            .order_by(Vulnerability.risk_score.desc().nullslast())
        )
        return list(result.scalars().all())

    async def get_by_severity(self, severity: str) -> list[Vulnerability]:
        """Return all vulnerabilities with the given severity label."""
        result = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.severity == severity)
            .order_by(Vulnerability.discovered_at.desc())
        )
        return list(result.scalars().all())

    async def get_by_asset(self, asset_id: uuid.UUID) -> list[Vulnerability]:
        """Return all vulnerabilities linked to a specific asset."""
        result = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset_id)
            .order_by(Vulnerability.risk_score.desc().nullslast())
        )
        return list(result.scalars().all())

    async def get_critical_unvalidated(self) -> list[Vulnerability]:
        """
        Return critical vulnerabilities that have no confirmed validation
        record — i.e., they need human triage or automated PoC validation.
        """
        # We fetch critical vulnerabilities and filter in Python on the
        # eagerly loaded validations relationship to avoid a complex subquery
        # that may not be supported without selectin-loading.
        from sqlalchemy.orm import selectinload

        result = await self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.severity == "critical")
            .options(selectinload(Vulnerability.validations))  # type: ignore[arg-type]
            .order_by(Vulnerability.risk_score.desc().nullslast())
        )
        vulns = list(result.scalars().all())
        return [
            v
            for v in vulns
            if not any(
                val.result == "confirmed" for val in (v.validations or [])
            )
        ]

    async def bulk_create(
        self, vulns: list[dict[str, Any]]
    ) -> list[Vulnerability]:
        """
        Insert multiple vulnerability records in a single flush.

        *vulns* is a list of keyword-argument dicts accepted by the
        ``Vulnerability`` constructor.  Duplicate rows that violate the
        unique constraint ``(asset_id, cve_id, port_id)`` are silently
        skipped via an upsert-style check before insertion.

        Returns the list of successfully inserted instances.
        """
        created: list[Vulnerability] = []
        for data in vulns:
            # Check for existing row to avoid unique-constraint errors.
            conditions = [Vulnerability.asset_id == data.get("asset_id")]
            if data.get("cve_id") is not None:
                conditions.append(Vulnerability.cve_id == data["cve_id"])
            if data.get("port_id") is not None:
                conditions.append(Vulnerability.port_id == data["port_id"])

            if len(conditions) >= 1:
                existing_check = await self._session.execute(
                    select(Vulnerability).where(and_(*conditions))
                )
                if existing_check.scalar_one_or_none() is not None:
                    continue

            instance = Vulnerability(**data)
            self._session.add(instance)
            created.append(instance)

        if created:
            await self._session.flush()
            for inst in created:
                await self._session.refresh(inst)

        return created

    async def get_stats_by_scan(self, scan_id: uuid.UUID) -> dict[str, Any]:
        """
        Return per-severity counts plus summary metrics for a scan's
        vulnerability set.
        """
        sev_result = await self._session.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan_id)
            .group_by(Vulnerability.severity)
        )
        counts = {row[0]: row[1] for row in sev_result}

        agg_result = await self._session.execute(
            select(
                func.count(Vulnerability.id),
                func.avg(Vulnerability.risk_score),
                func.max(Vulnerability.risk_score),
                func.count(Vulnerability.id).filter(
                    Vulnerability.exploit_available.is_(True)
                ),
                func.count(Vulnerability.id).filter(
                    Vulnerability.in_kev.is_(True)
                ),
            ).where(Vulnerability.scan_id == scan_id)
        )
        row = agg_result.one()

        return {
            "scan_id": scan_id,
            "total": row[0] or 0,
            "avg_risk_score": float(row[1]) if row[1] is not None else None,
            "max_risk_score": float(row[2]) if row[2] is not None else None,
            "exploitable_count": row[3] or 0,
            "kev_count": row[4] or 0,
            "by_severity": {
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
            },
        }


# ===========================================================================
# 5. EngagementRepository
# ===========================================================================

class EngagementRepository(BaseRepository):  # type: ignore[type-arg]
    """
    Repository for the ``engagements`` and ``engagement_scope`` tables.

    Because the ORM models for these tables are not yet defined in models.py,
    this repository falls back to raw SQL via ``text()`` when the model stubs
    are unavailable.  Once ``Engagement`` and ``EngagementScope`` ORM classes
    are added to models.py the ``_ENGAGEMENT_MODEL`` guard below will wire
    them in automatically.
    """

    _TABLE = "engagements"
    _SCOPE_TABLE = "engagement_scope"
    # Column allowlist for the raw-SQL create()/update() below (see
    # _reject_unknown_columns). Mirrors the engagements table in schema.sql.
    _COLUMNS = frozenset({
        "id", "name", "client_name", "operator",
        "status", "created_at", "updated_at", "notes", "config",
    })

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # BaseRepository shims — override so behaviour is defined even without
    # a proper ORM model.
    # ------------------------------------------------------------------

    async def get(self, id: uuid.UUID) -> dict[str, Any] | None:  # type: ignore[override]
        result = await self._session.execute(
            text(f"SELECT * FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:  # type: ignore[override]
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                f"ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            ),
            {"limit": limit, "offset": offset},
        )
        return [dict(r) for r in result.mappings()]

    async def create(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        _reject_unknown_columns(type(self), kwargs.keys())
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(f":{k}" for k in kwargs.keys())
        result = await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} ({cols}) "
                f"VALUES ({placeholders}) RETURNING *"
            ),
            kwargs,
        )
        row = result.mappings().one()
        return dict(row)

    async def update(self, id: uuid.UUID, **kwargs: Any) -> dict[str, Any] | None:  # type: ignore[override]
        if not kwargs:
            return await self.get(id)
        kwargs["updated_at"] = datetime.now(timezone.utc)
        _reject_unknown_columns(type(self), kwargs.keys())
        set_clause = ", ".join(f"{k} = :{k}" for k in kwargs.keys())
        kwargs["_id"] = id
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} SET {set_clause} "
                f"WHERE id = :_id RETURNING *"
            ),
            kwargs,
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def delete(self, id: uuid.UUID) -> bool:  # type: ignore[override]
        result = await self._session.execute(
            text(f"DELETE FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        return result.rowcount > 0  # type: ignore[attr-defined,return-value]

    async def count(self) -> int:
        result = await self._session.execute(
            text(f"SELECT COUNT(*) FROM {self._TABLE}")
        )
        return result.scalar_one()

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def get_active(self) -> list[dict[str, Any]]:
        """Return all engagements with status = 'active'."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE status = 'active' "
                "ORDER BY updated_at DESC"
            )
        )
        return [dict(r) for r in result.mappings()]

    async def get_with_scans(
        self, engagement_id: uuid.UUID
    ) -> dict[str, Any]:
        """Return engagement metadata alongside its linked scans."""
        engagement = await self.get(engagement_id)
        if engagement is None:
            return {}

        scans_result = await self._session.execute(
            text(
                "SELECT s.* FROM scans s "
                "JOIN reports r ON r.scan_id = s.id "
                "WHERE r.engagement_id = :eid "
                "ORDER BY s.created_at DESC"
            ),
            {"eid": engagement_id},
        )
        scans = [dict(r) for r in scans_result.mappings()]

        return {**engagement, "scans": scans}

    async def add_scope(
        self,
        engagement_id: uuid.UUID,
        scope_type: str,
        value: str,
    ) -> dict[str, Any]:
        """
        Insert a scope entry for an engagement.

        Existing entries with the same *(engagement_id, scope_type, value)*
        triple are returned as-is (upsert semantics via ON CONFLICT).
        """
        result = await self._session.execute(
            text(
                f"INSERT INTO {self._SCOPE_TABLE} "
                "(engagement_id, scope_type, value) "
                "VALUES (:eid, :scope_type, :value) "
                "ON CONFLICT (engagement_id, scope_type, value) "
                "DO UPDATE SET is_active = TRUE "
                "RETURNING *"
            ),
            {"eid": engagement_id, "scope_type": scope_type, "value": value},
        )
        row = result.mappings().one()
        return dict(row)

    async def get_scope(
        self, engagement_id: uuid.UUID
    ) -> list[dict[str, Any]]:
        """Return all active scope entries for an engagement."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._SCOPE_TABLE} "
                "WHERE engagement_id = :eid AND is_active = TRUE "
                "ORDER BY added_at DESC"
            ),
            {"eid": engagement_id},
        )
        return [dict(r) for r in result.mappings()]


# ===========================================================================
# 6. WebPathRepository
# ===========================================================================

class WebPathRepository(BaseRepository):  # type: ignore[type-arg]
    """Repository for the ``web_paths`` table (raw SQL until ORM model lands)."""

    _TABLE = "web_paths"
    _COLUMNS = frozenset({
        "id", "scan_id", "asset_id", "url", "http_status", "content_type",
        "response_size", "title", "is_sensitive", "path_category",
        "redirect_url", "tech_stack", "discovered_at",
    })

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # BaseRepository shims
    # ------------------------------------------------------------------

    async def get(self, id: uuid.UUID) -> dict[str, Any] | None:  # type: ignore[override]
        result = await self._session.execute(
            text(f"SELECT * FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:  # type: ignore[override]
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "ORDER BY discovered_at DESC "
                "LIMIT :limit OFFSET :offset"
            ),
            {"limit": limit, "offset": offset},
        )
        return [dict(r) for r in result.mappings()]

    async def create(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        _reject_unknown_columns(type(self), kwargs.keys())
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(f":{k}" for k in kwargs.keys())
        result = await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} ({cols}) "
                f"VALUES ({placeholders}) RETURNING *"
            ),
            kwargs,
        )
        return dict(result.mappings().one())

    async def update(self, id: uuid.UUID, **kwargs: Any) -> dict[str, Any] | None:  # type: ignore[override]
        if not kwargs:
            return await self.get(id)
        _reject_unknown_columns(type(self), kwargs.keys())
        set_clause = ", ".join(f"{k} = :{k}" for k in kwargs.keys())
        kwargs["_id"] = id
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} SET {set_clause} "
                "WHERE id = :_id RETURNING *"
            ),
            kwargs,
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def delete(self, id: uuid.UUID) -> bool:  # type: ignore[override]
        result = await self._session.execute(
            text(f"DELETE FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        return result.rowcount > 0  # type: ignore[attr-defined,return-value]

    async def count(self) -> int:
        result = await self._session.execute(
            text(f"SELECT COUNT(*) FROM {self._TABLE}")
        )
        return result.scalar_one()

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def get_by_scan(self, scan_id: uuid.UUID) -> list[dict[str, Any]]:
        """Return all web paths discovered in a scan."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE scan_id = :scan_id "
                "ORDER BY http_status, url"
            ),
            {"scan_id": scan_id},
        )
        return [dict(r) for r in result.mappings()]

    async def get_sensitive(self, scan_id: uuid.UUID) -> list[dict[str, Any]]:
        """Return only paths flagged as sensitive for a given scan."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE scan_id = :scan_id AND is_sensitive = TRUE "
                "ORDER BY path_category, url"
            ),
            {"scan_id": scan_id},
        )
        return [dict(r) for r in result.mappings()]

    async def get_by_category(
        self, scan_id: uuid.UUID, category: str
    ) -> list[dict[str, Any]]:
        """Return paths filtered by *path_category* for a given scan."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE scan_id = :scan_id AND path_category = :category "
                "ORDER BY url"
            ),
            {"scan_id": scan_id, "category": category},
        )
        return [dict(r) for r in result.mappings()]


# ===========================================================================
# 7. NotificationRepository
# ===========================================================================

class NotificationRepository(BaseRepository):  # type: ignore[type-arg]
    """Repository for the ``notifications`` table."""

    _TABLE = "notifications"
    _COLUMNS = frozenset({
        "id", "scan_id", "severity", "category", "title", "message",
        "is_read", "delivered_at", "created_at",
    })

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # BaseRepository shims
    # ------------------------------------------------------------------

    async def get(self, id: uuid.UUID) -> dict[str, Any] | None:  # type: ignore[override]
        result = await self._session.execute(
            text(f"SELECT * FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:  # type: ignore[override]
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "ORDER BY created_at DESC "
                "LIMIT :limit OFFSET :offset"
            ),
            {"limit": limit, "offset": offset},
        )
        return [dict(r) for r in result.mappings()]

    async def create(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        _reject_unknown_columns(type(self), kwargs.keys())
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(f":{k}" for k in kwargs.keys())
        result = await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} ({cols}) "
                f"VALUES ({placeholders}) RETURNING *"
            ),
            kwargs,
        )
        return dict(result.mappings().one())

    async def update(self, id: uuid.UUID, **kwargs: Any) -> dict[str, Any] | None:  # type: ignore[override]
        if not kwargs:
            return await self.get(id)
        _reject_unknown_columns(type(self), kwargs.keys())
        set_clause = ", ".join(f"{k} = :{k}" for k in kwargs.keys())
        kwargs["_id"] = id
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} SET {set_clause} "
                "WHERE id = :_id RETURNING *"
            ),
            kwargs,
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def delete(self, id: uuid.UUID) -> bool:  # type: ignore[override]
        result = await self._session.execute(
            text(f"DELETE FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        return result.rowcount > 0  # type: ignore[attr-defined,return-value]

    async def count(self) -> int:
        result = await self._session.execute(
            text(f"SELECT COUNT(*) FROM {self._TABLE}")
        )
        return result.scalar_one()

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def get_unread(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent unread notifications."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE is_read = FALSE "
                "ORDER BY created_at DESC "
                "LIMIT :limit"
            ),
            {"limit": limit},
        )
        return [dict(r) for r in result.mappings()]

    async def mark_read(self, notification_id: uuid.UUID) -> bool:
        """Mark a single notification as read.  Returns *True* if found."""
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} "
                "SET is_read = TRUE, delivered_at = NOW() "
                "WHERE id = :id AND is_read = FALSE"
            ),
            {"id": notification_id},
        )
        return result.rowcount > 0  # type: ignore[attr-defined,return-value]

    async def mark_all_read(self) -> int:
        """
        Mark every unread notification as read.

        Returns the number of rows updated.
        """
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} "
                "SET is_read = TRUE, delivered_at = NOW() "
                "WHERE is_read = FALSE"
            )
        )
        return result.rowcount  # type: ignore[attr-defined,return-value]


# ===========================================================================
# 8. AuditRepository
# ===========================================================================

class AuditRepository:
    """
    Repository for the ``audit_log`` partitioned table.

    The audit log uses a ``BIGSERIAL`` composite primary key (id, timestamp)
    rather than a UUID, so it does not inherit from ``BaseRepository``.
    All writes go through ``log()``; reads are provided by ``get_recent()``
    and ``get_by_resource()``.
    """

    _TABLE = "audit_log"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def log(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: dict[str, Any],
        ip_address: str | None = None,
    ) -> None:
        """
        Insert a new audit-log record.

        *actor* is typically a username or service identifier.
        *resource_id* is stored as TEXT to remain schema-agnostic.
        *ip_address* should be a valid IPv4/IPv6 string or *None*.
        """
        await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} "
                "(actor, action, resource_type, resource_id, details, ip_address) "
                "VALUES (:actor, :action, :resource_type, :resource_id, "
                ":details::jsonb, :ip_address::inet)"
            ),
            {
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": __import__("json").dumps(details),
                "ip_address": ip_address,
            },
        )

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the *limit* most recent audit entries across all partitions."""
        result = await self._session.execute(
            text(
                f"SELECT id, actor, action, resource_type, resource_id, "
                "details, ip_address, timestamp "
                f"FROM {self._TABLE} "
                "ORDER BY timestamp DESC "
                "LIMIT :limit"
            ),
            {"limit": limit},
        )
        return [dict(r) for r in result.mappings()]

    async def get_by_resource(
        self, resource_type: str, resource_id: str
    ) -> list[dict[str, Any]]:
        """Return all audit entries for a specific resource."""
        result = await self._session.execute(
            text(
                f"SELECT id, actor, action, resource_type, resource_id, "
                "details, ip_address, timestamp "
                f"FROM {self._TABLE} "
                "WHERE resource_type = :resource_type "
                "AND resource_id = :resource_id "
                "ORDER BY timestamp DESC"
            ),
            {"resource_type": resource_type, "resource_id": resource_id},
        )
        return [dict(r) for r in result.mappings()]


# ===========================================================================
# 9. ReportRepository
# ===========================================================================

class ReportRepository(BaseRepository):  # type: ignore[type-arg]
    """Repository for the ``reports`` table."""

    _TABLE = "reports"
    _COLUMNS = frozenset({
        "id", "scan_id", "engagement_id", "report_type", "format",
        "file_path", "file_size", "finding_count", "generated_at",
        "generated_by", "checksum",
    })

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._model = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # BaseRepository shims
    # ------------------------------------------------------------------

    async def get(self, id: uuid.UUID) -> dict[str, Any] | None:  # type: ignore[override]
        result = await self._session.execute(
            text(f"SELECT * FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:  # type: ignore[override]
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "ORDER BY generated_at DESC "
                "LIMIT :limit OFFSET :offset"
            ),
            {"limit": limit, "offset": offset},
        )
        return [dict(r) for r in result.mappings()]

    async def create(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        _reject_unknown_columns(type(self), kwargs.keys())
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(f":{k}" for k in kwargs.keys())
        result = await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} ({cols}) "
                f"VALUES ({placeholders}) RETURNING *"
            ),
            kwargs,
        )
        return dict(result.mappings().one())

    async def update(self, id: uuid.UUID, **kwargs: Any) -> dict[str, Any] | None:  # type: ignore[override]
        if not kwargs:
            return await self.get(id)
        _reject_unknown_columns(type(self), kwargs.keys())
        set_clause = ", ".join(f"{k} = :{k}" for k in kwargs.keys())
        kwargs["_id"] = id
        result = await self._session.execute(
            text(
                f"UPDATE {self._TABLE} SET {set_clause} "
                "WHERE id = :_id RETURNING *"
            ),
            kwargs,
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None

    async def delete(self, id: uuid.UUID) -> bool:  # type: ignore[override]
        result = await self._session.execute(
            text(f"DELETE FROM {self._TABLE} WHERE id = :id"), {"id": id}
        )
        return result.rowcount > 0  # type: ignore[attr-defined,return-value]

    async def count(self) -> int:
        result = await self._session.execute(
            text(f"SELECT COUNT(*) FROM {self._TABLE}")
        )
        return result.scalar_one()

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def get_by_scan(self, scan_id: uuid.UUID) -> list[dict[str, Any]]:
        """Return all reports generated for a scan, newest first."""
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE scan_id = :scan_id "
                "ORDER BY generated_at DESC"
            ),
            {"scan_id": scan_id},
        )
        return [dict(r) for r in result.mappings()]

    async def get_latest(
        self, scan_id: uuid.UUID, report_type: str
    ) -> dict[str, Any] | None:
        """
        Return the most recently generated report of a given type for a scan.

        Returns *None* when no matching report exists.
        """
        result = await self._session.execute(
            text(
                f"SELECT * FROM {self._TABLE} "
                "WHERE scan_id = :scan_id AND report_type = :report_type "
                "ORDER BY generated_at DESC "
                "LIMIT 1"
            ),
            {"scan_id": scan_id, "report_type": report_type},
        )
        row = result.mappings().one_or_none()
        return dict(row) if row is not None else None


# ===========================================================================
# Repository factory
# ===========================================================================

def get_repository_factory(session: AsyncSession) -> SimpleNamespace:
    """
    Return a ``SimpleNamespace`` pre-wired with one instance of every
    repository, all sharing the same async session.

    Usage::

        async with get_session() as session:
            repos = get_repository_factory(session)
            scan = await repos.scans.get(scan_id)
            assets = await repos.assets.get_by_scan(scan_id)

    Attributes
    ----------
    scans : ScanRepository
    assets : AssetRepository
    vulnerabilities : VulnerabilityRepository
    engagements : EngagementRepository
    web_paths : WebPathRepository
    notifications : NotificationRepository
    audit : AuditRepository
    reports : ReportRepository
    """
    return SimpleNamespace(
        scans=ScanRepository(session),
        assets=AssetRepository(session),
        vulnerabilities=VulnerabilityRepository(session),
        engagements=EngagementRepository(session),
        web_paths=WebPathRepository(session),
        notifications=NotificationRepository(session),
        audit=AuditRepository(session),
        reports=ReportRepository(session),
    )

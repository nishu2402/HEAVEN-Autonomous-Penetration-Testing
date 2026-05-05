"""
HEAVEN — Database Models (SQLAlchemy 2.0 async)
Mirrors the PostgreSQL schema with full ORM support.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

try:
    from sqlalchemy import (
        ARRAY, Boolean, CheckConstraint, Column, DateTime, Enum, Float,
        ForeignKey, Index, Integer, String, Text, UniqueConstraint,
    )
    from sqlalchemy.dialects.postgresql import JSONB, UUID
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

if not HAS_SQLALCHEMY:
    # Stubs so model classes can be parsed by Python without sqlalchemy
    class DeclarativeBase:  # type: ignore[no-redef]
        pass
    class _Stub:
        def __init__(self, *a, **kw): pass
        def __call__(self, *a, **kw): return self
        def __class_getitem__(cls, item): return Any
    mapped_column = _Stub()
    relationship = _Stub()
    Mapped = Any  # type: ignore[assignment]
    # Type stubs
    UUID = String = Text = Integer = Float = Boolean = DateTime = _Stub
    JSONB = ARRAY = ForeignKey = UniqueConstraint = CheckConstraint = Index = Column = Enum = _Stub


class Base(DeclarativeBase):
    """Base class for all HEAVEN models."""
    pass



class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False, default="full")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    target_spec: Mapped[dict] = mapped_column(JSONB, default=dict)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_log: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    assets: Mapped[list["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    chains: Mapped[list["VulnChain"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.id} [{self.scan_type}] {self.status}>"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("asset_type", "value", name="uq_asset_type_value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(512))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    is_honeypot: Mapped[bool] = mapped_column(Boolean, default=False)
    honeypot_score: Mapped[float] = mapped_column(Float, default=0.0)
    criticality: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="assets")
    ports: Mapped[list["Port"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Asset {self.asset_type}:{self.value}>"


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    service: Mapped[Optional[str]] = mapped_column(String(128))
    version: Mapped[Optional[str]] = mapped_column(String(256))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    cpe: Mapped[Optional[str]] = mapped_column(String(512))
    fingerprint: Mapped[dict] = mapped_column(JSONB, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="ports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="port")

    def __repr__(self) -> str:
        return f"<Port {self.port}/{self.protocol} ({self.service})>"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", "port_id", name="uq_vuln_asset_cve"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("ports.id", ondelete="SET NULL"))
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    cve_id: Mapped[Optional[str]] = mapped_column(String(20))
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    cvss_base: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(256))
    epss_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    references_: Mapped[list] = mapped_column("references", JSONB, default=list)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="vulnerabilities")
    port: Mapped[Optional["Port"]] = relationship(back_populates="vulnerabilities")
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="vulnerabilities")
    validations: Mapped[list["Validation"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")
    risk_scores: Mapped[list["RiskScore"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Vuln {self.cve_id or self.title} [{self.severity}]>"


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    method: Mapped[str] = mapped_column(String(50), nullable=False)
    result: Mapped[str] = mapped_column(String(20), default="inconclusive")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    request_sent: Mapped[Optional[str]] = mapped_column(Text)
    response_received: Mapped[Optional[str]] = mapped_column(Text)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="validations")


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    repo_url: Mapped[Optional[str]] = mapped_column(String(2048))
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret_type: Mapped[str] = mapped_column(String(30), nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    snippet: Mapped[Optional[str]] = mapped_column(Text)
    entropy: Mapped[Optional[float]] = mapped_column(Float)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(40))
    commit_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    author: Mapped[Optional[str]] = mapped_column(String(256))
    is_active: Mapped[Optional[bool]] = mapped_column(Boolean)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    predicted_score: Mapped[float] = mapped_column(Float, nullable=False)
    exploit_probability: Mapped[Optional[float]] = mapped_column(Float)
    features: Mapped[dict] = mapped_column(JSONB, default=dict)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    explanation: Mapped[dict] = mapped_column(JSONB, default=dict)
    scored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="risk_scores")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class VulnChain(Base):
    __tablename__ = "vuln_chains"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    chain_name: Mapped[Optional[str]] = mapped_column(String(256))
    chain_score: Mapped[float] = mapped_column(Float, default=0.0)
    vuln_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False)
    attack_path: Mapped[list] = mapped_column(JSONB, default=list)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="chains")

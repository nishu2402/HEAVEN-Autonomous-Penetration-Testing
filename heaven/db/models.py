"""
HEAVEN — Database Models (SQLAlchemy 2.0 async)
Mirrors the PostgreSQL schema with full ORM support.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

try:
    from sqlalchemy import (
        ARRAY, BigInteger, Boolean, CheckConstraint, Column,
        DateTime, Enum, Float, ForeignKey, Index, Integer,
        String, Table, Text, UniqueConstraint,
    )
    from sqlalchemy.dialects.postgresql import JSONB, UUID
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

if not HAS_SQLALCHEMY:
    # Stubs so model classes can be parsed by Python without sqlalchemy installed
    class DeclarativeBase:  # type: ignore[no-redef]
        pass

    class _Stub:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

        def __call__(self, *a: Any, **kw: Any) -> "_Stub":
            return self

        def __class_getitem__(cls, item: Any) -> Any:
            return Any

    mapped_column = _Stub()  # type: ignore[assignment]
    relationship = _Stub()   # type: ignore[assignment]
    Mapped = Any             # type: ignore[misc,assignment]

    # Column-type stubs
    UUID = String = Text = Integer = BigInteger = Float = Boolean = DateTime = _Stub  # type: ignore[misc,assignment]
    JSONB = ARRAY = ForeignKey = UniqueConstraint = CheckConstraint = Index = Column = Enum = Table = _Stub  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# Declarative Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Base class for all HEAVEN ORM models."""
    pass


# ---------------------------------------------------------------------------
# ENUM type definitions (PostgreSQL-backed)
# ---------------------------------------------------------------------------

asset_type_enum = Enum(
    "ipv4", "ipv6", "url", "domain", "arn", "bssid", "repository", "container",
    name="asset_type",
)

scan_status_enum = Enum(
    "pending", "running", "completed", "failed", "cancelled",
    name="scan_status",
)

scan_segment_enum = Enum(
    "network", "web", "cloud", "wireless", "devsecops", "full",
    name="scan_segment",
)

severity_level_enum = Enum(
    "info", "low", "medium", "high", "critical",
    name="severity_level",
)

validation_method_enum = Enum(
    "sqli_boolean", "xss_reflection", "ssrf_callback", "open_redirect",
    "directory_traversal", "cors_misconfig", "header_injection", "info_disclosure",
    "banner_check", "version_check", "config_check",
    name="validation_method",
)

validation_result_enum = Enum(
    "confirmed", "likely", "inconclusive", "false_positive",
    name="validation_result",
)

secret_type_enum = Enum(
    "aws_key", "github_token", "google_api", "stripe_key", "slack_token",
    "private_key", "password", "jwt_secret", "database_url", "generic_secret",
    name="secret_type",
)

engagement_status_enum = Enum(
    "planned", "active", "paused", "completed", "archived",
    name="engagement_status",
)

scope_type_enum = Enum(
    "cidr", "domain", "url", "ip",
    name="scope_type",
)

dns_record_type_enum = Enum(
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SRV", "PTR", "SOA",
    name="dns_record_type",
)

path_category_enum = Enum(
    "admin", "backup", "config", "api_doc", "git", "env", "upload", "login", "other",
    name="path_category",
)

credential_source_enum = Enum(
    "spray", "brute", "default", "leaked", "git",
    name="credential_source",
)

network_edge_type_enum = Enum(
    "route", "arp", "traceroute", "service_dep",
    name="network_edge_type",
)

cloud_provider_enum = Enum(
    "aws", "gcp", "azure", "other",
    name="cloud_provider",
)

report_type_enum = Enum(
    "executive", "technical", "compliance", "patch_matrix",
    name="report_type",
)

report_format_enum = Enum(
    "pdf", "html", "json", "csv",
    name="report_format",
)


# ===========================================================================
# EXISTING MODELS — preserved exactly
# ===========================================================================

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(
        scan_segment_enum, nullable=False, default="full"
    )
    status: Mapped[str] = mapped_column(
        scan_status_enum, nullable=False, default="pending"
    )
    target_spec: Mapped[dict] = mapped_column(JSONB, default=dict)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_log: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    assets: Mapped[List["Asset"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[List["ScanFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    chains: Mapped[List["VulnChain"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    secrets: Mapped[List["Secret"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    dns_records: Mapped[List["DnsRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    web_paths: Mapped[List["WebPath"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    credentials: Mapped[List["Credential"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    mitre_techniques: Mapped[List["MitreTechnique"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    network_topology: Mapped[List["NetworkTopology"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    cloud_resources: Mapped[List["CloudResource"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[List["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    scan_checkpoint: Mapped[Optional["ScanCheckpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", uselist=False
    )
    notifications: Mapped[List["Notification"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id} [{self.scan_type}] {self.status}>"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("asset_type", "value", name="uq_asset_type_value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_type: Mapped[str] = mapped_column(asset_type_enum, nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(512))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    is_honeypot: Mapped[bool] = mapped_column(Boolean, default=False)
    honeypot_score: Mapped[float] = mapped_column(Float, default=0.0)
    criticality: Mapped[int] = mapped_column(
        Integer,
        CheckConstraint("criticality BETWEEN 1 AND 5", name="chk_asset_criticality"),
        default=1,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="assets")
    ports: Mapped[List["Port"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    secrets: Mapped[List["Secret"]] = relationship(back_populates="asset")
    ssl_certificates: Mapped[List["SslCertificate"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    web_paths: Mapped[List["WebPath"]] = relationship(back_populates="asset")
    credentials: Mapped[List["Credential"]] = relationship(back_populates="asset")
    dns_records: Mapped[List["DnsRecord"]] = relationship(back_populates="asset")
    outgoing_topology: Mapped[List["NetworkTopology"]] = relationship(
        back_populates="src_asset",
        foreign_keys="NetworkTopology.src_asset_id",
    )
    incoming_topology: Mapped[List["NetworkTopology"]] = relationship(
        back_populates="dst_asset",
        foreign_keys="NetworkTopology.dst_asset_id",
    )

    def __repr__(self) -> str:
        return f"<Asset {self.asset_type}:{self.value}>"


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(
        Integer,
        CheckConstraint("port BETWEEN 0 AND 65535", name="chk_port_range"),
        nullable=False,
    )
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    service: Mapped[Optional[str]] = mapped_column(String(128))
    version: Mapped[Optional[str]] = mapped_column(String(256))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    cpe: Mapped[Optional[str]] = mapped_column(String(512))
    fingerprint: Mapped[dict] = mapped_column(JSONB, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="ports")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="port"
    )
    ssl_certificates: Mapped[List["SslCertificate"]] = relationship(
        back_populates="port"
    )

    def __repr__(self) -> str:
        return f"<Port {self.port}/{self.protocol} ({self.service})>"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", "port_id", name="uq_vuln_asset_cve"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    port_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ports.id", ondelete="SET NULL")
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    cve_id: Mapped[Optional[str]] = mapped_column(String(20))
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(severity_level_enum, default="info")
    cvss_base: Mapped[Optional[float]] = mapped_column(
        Float,
        CheckConstraint("cvss_base BETWEEN 0 AND 10", name="chk_cvss_base"),
    )
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(256))
    epss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        CheckConstraint("epss_score BETWEEN 0 AND 1", name="chk_epss_score"),
    )
    risk_score: Mapped[Optional[float]] = mapped_column(
        Float,
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="chk_risk_score"),
    )
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    references_: Mapped[list] = mapped_column("references", JSONB, default=list)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="vulnerabilities")
    port: Mapped[Optional["Port"]] = relationship(back_populates="vulnerabilities")
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="vulnerabilities")
    validations: Mapped[List["Validation"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    risk_scores: Mapped[List["RiskScore"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    mitre_techniques: Mapped[List["MitreTechnique"]] = relationship(
        back_populates="vulnerability"
    )

    def __repr__(self) -> str:
        return f"<Vuln {self.cve_id or self.title} [{self.severity}]>"


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vuln_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    method: Mapped[str] = mapped_column(validation_method_enum, nullable=False)
    result: Mapped[str] = mapped_column(
        validation_result_enum, default="inconclusive"
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        CheckConstraint("confidence BETWEEN 0 AND 1", name="chk_validation_confidence"),
        default=0.0,
    )
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    request_sent: Mapped[Optional[str]] = mapped_column(Text)
    response_received: Mapped[Optional[str]] = mapped_column(Text)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(
        back_populates="validations"
    )

    def __repr__(self) -> str:
        return f"<Validation {self.method} -> {self.result}>"


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    repo_url: Mapped[Optional[str]] = mapped_column(String(2048))
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret_type: Mapped[str] = mapped_column(secret_type_enum, nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    snippet: Mapped[Optional[str]] = mapped_column(Text)
    entropy: Mapped[Optional[float]] = mapped_column(Float)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(40))
    commit_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    author: Mapped[Optional[str]] = mapped_column(String(256))
    is_active: Mapped[Optional[bool]] = mapped_column(Boolean)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="secrets")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="secrets")

    def __repr__(self) -> str:
        return f"<Secret {self.secret_type} @ {self.file_path}:{self.line_number}>"


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vuln_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    predicted_score: Mapped[float] = mapped_column(
        Float,
        CheckConstraint(
            "predicted_score BETWEEN 0 AND 100", name="chk_predicted_score"
        ),
        nullable=False,
    )
    exploit_probability: Mapped[Optional[float]] = mapped_column(
        Float,
        CheckConstraint(
            "exploit_probability BETWEEN 0 AND 1", name="chk_exploit_prob"
        ),
    )
    features: Mapped[dict] = mapped_column(JSONB, default=dict)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    explanation: Mapped[dict] = mapped_column(JSONB, default=dict)
    scored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(
        back_populates="risk_scores"
    )

    def __repr__(self) -> str:
        return f"<RiskScore {self.predicted_score:.1f} (v{self.model_version})>"


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(severity_level_enum, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings")

    def __repr__(self) -> str:
        return f"<ScanFinding {self.finding_type} [{self.severity}]>"


class VulnChain(Base):
    __tablename__ = "vuln_chains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    chain_name: Mapped[Optional[str]] = mapped_column(String(256))
    chain_score: Mapped[float] = mapped_column(Float, default=0.0)
    vuln_ids: Mapped[list] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )
    attack_path: Mapped[list] = mapped_column(JSONB, default=list)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="chains")

    def __repr__(self) -> str:
        return f"<VulnChain {self.chain_name!r} score={self.chain_score}>"


# ===========================================================================
# NEW MODELS
# ===========================================================================

class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    client_name: Mapped[str] = mapped_column(String(256), nullable=False)
    operator: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        engagement_status_enum, nullable=False, default="planned"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    scope_entries: Mapped[List["EngagementScope"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    reports: Mapped[List["Report"]] = relationship(back_populates="engagement")

    def __repr__(self) -> str:
        return f"<Engagement {self.name!r} [{self.status}] client={self.client_name!r}>"


class EngagementScope(Base):
    __tablename__ = "engagement_scope"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id", "scope_type", "value",
            name="uq_engagement_scope_value",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(scope_type_enum, nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    engagement: Mapped["Engagement"] = relationship(back_populates="scope_entries")

    def __repr__(self) -> str:
        return f"<EngagementScope {self.scope_type}:{self.value}>"


class DnsRecord(Base):
    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "record_type", "name", "value",
            name="uq_dns_record",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    record_type: Mapped[str] = mapped_column(dns_record_type_enum, nullable=False)
    name: Mapped[str] = mapped_column(String(2048), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(
        Integer,
        CheckConstraint("ttl >= 0", name="chk_dns_ttl"),
    )
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="dns_records")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="dns_records")

    def __repr__(self) -> str:
        return f"<DnsRecord {self.record_type} {self.name} -> {self.value}>"


class SslCertificate(Base):
    __tablename__ = "ssl_certificates"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "fingerprint_sha256",
            name="uq_ssl_cert_fingerprint",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    port_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ports.id", ondelete="SET NULL")
    )
    subject: Mapped[str] = mapped_column(String(2048), nullable=False)
    issuer: Mapped[Optional[str]] = mapped_column(String(2048))
    serial_number: Mapped[Optional[str]] = mapped_column(String(256))
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    san: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    cipher_suite: Mapped[Optional[str]] = mapped_column(String(256))
    tls_version: Mapped[Optional[str]] = mapped_column(String(20))
    fingerprint_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    key_bits: Mapped[Optional[int]] = mapped_column(
        Integer,
        CheckConstraint("key_bits > 0", name="chk_key_bits"),
    )
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(128))
    is_ev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ocsp_stapling: Mapped[Optional[bool]] = mapped_column(Boolean)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="ssl_certificates")
    port: Mapped[Optional["Port"]] = relationship(back_populates="ssl_certificates")

    def __repr__(self) -> str:
        return f"<SslCertificate {self.subject} expires={self.not_after}>"


class WebPath(Base):
    __tablename__ = "web_paths"
    __table_args__ = (
        UniqueConstraint("scan_id", "url", name="uq_web_path_scan_url"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[Optional[int]] = mapped_column(
        Integer,
        CheckConstraint(
            "http_status BETWEEN 100 AND 599", name="chk_http_status"
        ),
    )
    content_type: Mapped[Optional[str]] = mapped_column(String(256))
    response_size: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        CheckConstraint("response_size >= 0", name="chk_response_size"),
    )
    title: Mapped[Optional[str]] = mapped_column(String(1024))
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    path_category: Mapped[str] = mapped_column(
        path_category_enum, nullable=False, default="other"
    )
    redirect_url: Mapped[Optional[str]] = mapped_column(Text)
    tech_stack: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="web_paths")
    asset: Mapped["Asset"] = relationship(back_populates="web_paths")

    def __repr__(self) -> str:
        return f"<WebPath {self.url} [{self.http_status}]>"


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    service: Mapped[Optional[str]] = mapped_column(String(128))
    protocol: Mapped[Optional[str]] = mapped_column(String(50))
    username: Mapped[Optional[str]] = mapped_column(String(512))
    password_hash: Mapped[Optional[str]] = mapped_column(String(512))
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source: Mapped[str] = mapped_column(credential_source_enum, nullable=False)
    confidence: Mapped[float] = mapped_column(
        Float,
        CheckConstraint(
            "confidence BETWEEN 0 AND 1", name="chk_credential_confidence"
        ),
        nullable=False,
        default=0.0,
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="credentials")
    asset: Mapped["Asset"] = relationship(back_populates="credentials")

    def __repr__(self) -> str:
        return (
            f"<Credential {self.username!r} @ {self.service} "
            f"source={self.source} valid={self.is_valid}>"
        )


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    vuln_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="SET NULL")
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    sub_technique_id: Mapped[Optional[str]] = mapped_column(String(30))
    tactic: Mapped[str] = mapped_column(String(128), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(512), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(
        Float,
        CheckConstraint(
            "confidence BETWEEN 0 AND 1", name="chk_mitre_confidence"
        ),
        nullable=False,
        default=0.0,
    )
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    mapped_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="mitre_techniques")
    vulnerability: Mapped[Optional["Vulnerability"]] = relationship(
        back_populates="mitre_techniques"
    )

    def __repr__(self) -> str:
        tid = self.sub_technique_id or self.technique_id
        return f"<MitreTechnique {tid} [{self.tactic}]>"


class NetworkTopology(Base):
    __tablename__ = "network_topology"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "src_asset_id", "dst_asset_id", "edge_type",
            name="uq_topology_edge",
        ),
        CheckConstraint(
            "src_asset_id <> dst_asset_id", name="chk_no_self_loop"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    src_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    edge_type: Mapped[str] = mapped_column(network_edge_type_enum, nullable=False)
    hop_count: Mapped[Optional[int]] = mapped_column(
        Integer,
        CheckConstraint("hop_count >= 0", name="chk_hop_count"),
    )
    latency_ms: Mapped[Optional[float]] = mapped_column(
        Float,
        CheckConstraint("latency_ms >= 0", name="chk_latency_ms"),
    )
    is_bidirectional: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="network_topology")
    src_asset: Mapped["Asset"] = relationship(
        back_populates="outgoing_topology",
        foreign_keys=[src_asset_id],
    )
    dst_asset: Mapped["Asset"] = relationship(
        back_populates="incoming_topology",
        foreign_keys=[dst_asset_id],
    )

    def __repr__(self) -> str:
        return (
            f"<NetworkTopology {self.src_asset_id} --[{self.edge_type}]--> "
            f"{self.dst_asset_id}>"
        )


class CloudResource(Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "provider", "resource_id",
            name="uq_cloud_resource",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(cloud_provider_enum, nullable=False)
    service_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[Optional[str]] = mapped_column(String(64))
    resource_name: Mapped[Optional[str]] = mapped_column(String(512))
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    risk_flags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="cloud_resources")

    def __repr__(self) -> str:
        return (
            f"<CloudResource {self.provider}/{self.service_type} "
            f"id={self.resource_id!r} public={self.is_public}>"
        )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    engagement_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="SET NULL")
    )
    report_type: Mapped[str] = mapped_column(report_type_enum, nullable=False)
    format: Mapped[str] = mapped_column(report_format_enum, nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    file_size: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        CheckConstraint("file_size >= 0", name="chk_file_size"),
    )
    finding_count: Mapped[Optional[int]] = mapped_column(
        Integer,
        CheckConstraint("finding_count >= 0", name="chk_finding_count"),
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    generated_by: Mapped[Optional[str]] = mapped_column(String(256))
    checksum: Mapped[Optional[str]] = mapped_column(String(128))

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="reports")
    engagement: Mapped[Optional["Engagement"]] = relationship(
        back_populates="reports"
    )

    def __repr__(self) -> str:
        return (
            f"<Report {self.report_type}/{self.format} "
            f"findings={self.finding_count}>"
        )


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    color: Mapped[Optional[str]] = mapped_column(String(20))
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    finding_tags: Mapped[List["FindingTag"]] = relationship(
        back_populates="tag", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Tag {self.name!r} color={self.color!r}>"


class FindingTag(Base):
    """Junction table linking tags to vulnerabilities or scan_findings.

    ``finding_id`` is an untyped UUID — ``resource_type`` indicates which
    table it references (``vulnerability`` or ``scan_finding``).
    """
    __tablename__ = "finding_tags"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tagged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    tag: Mapped["Tag"] = relationship(back_populates="finding_tags")

    def __repr__(self) -> str:
        return f"<FindingTag finding={self.finding_id} tag={self.tag_id}>"


class OperatorNote(Base):
    __tablename__ = "operator_notes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    author: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return (
            f"<OperatorNote by={self.author!r} "
            f"resource={self.resource_type}/{self.resource_id}>"
        )


class ScanCheckpoint(Base):
    __tablename__ = "scan_checkpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_scan_checkpoint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    phase: Mapped[str] = mapped_column(String(128), nullable=False)
    completed_tasks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="scan_checkpoint")

    def __repr__(self) -> str:
        return f"<ScanCheckpoint scan={self.scan_id} phase={self.phase!r}>"


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        CheckConstraint(
            "severity IN ('info', 'warning', 'error', 'critical')",
            name="chk_notification_severity",
        ),
        nullable=False,
        default="info",
    )
    category: Mapped[Optional[str]] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="notifications")

    def __repr__(self) -> str:
        return (
            f"<Notification [{self.severity}] {self.title!r} "
            f"read={self.is_read}>"
        )


# ---------------------------------------------------------------------------
# AuditLog — partitioned table
#
# PostgreSQL partitioned tables cannot use normal ORM declarative mapping with
# a single-column primary key when the partition key is also part of the PK.
# We expose a plain Core Table object so code can INSERT / SELECT without
# mapper issues, and wrap a lightweight class for convenience.
# ---------------------------------------------------------------------------

audit_log_table = Table(
    "audit_log",
    Base.metadata,
    Column("id", BigInteger, nullable=False),
    Column("actor", String(256)),
    Column("action", String(256), nullable=False),
    Column("resource_type", String(128)),
    Column("resource_id", Text),
    Column("details", JSONB, nullable=False),
    Column("ip_address", String(45)),   # INET stored as text for portability
    Column("user_agent", Text),
    Column("timestamp", DateTime(timezone=True), nullable=False),
)


class AuditLog:
    """Lightweight wrapper around the partitioned ``audit_log`` table.

    Use ``audit_log_table`` directly for Core INSERT/SELECT; this class exists
    so the name can appear in ``__all__`` and be used as a type hint.
    """

    __table__ = audit_log_table

    def __init__(
        self,
        action: str,
        *,
        actor: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        self.action = action
        self.actor = actor
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.details = details or {}
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return (
            f"<AuditLog actor={self.actor!r} action={self.action!r} "
            f"resource={self.resource_type}/{self.resource_id}>"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
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
]

"""Extended schema: engagements, DNS, SSL, web paths, credentials,
MITRE techniques, network topology, cloud resources, reports,
audit log, tags, notes, checkpoints, notifications.

Revision ID: 0002_extended_schema
Revises: 0001_bootstrap
Create Date: 2026-05-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_extended_schema"
down_revision: Union[str, None] = "0001_bootstrap"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _enum(*values: str, name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, create_type=False)


# ─────────────────────────────────────────────────────────────────────────────
# upgrade
# ─────────────────────────────────────────────────────────────────────────────

def upgrade() -> None:
    conn = op.get_bind()

    # ── New ENUM types ────────────────────────────────────────────────────────
    for name, values in [
        ("engagement_status", ("active", "paused", "completed", "archived")),
        ("scope_type",        ("cidr", "domain", "url", "ip")),
        ("dns_record_type",   ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SRV", "PTR", "SOA")),
        ("path_category",     ("admin", "backup", "config", "api_doc", "git", "env",
                               "upload", "login", "other")),
        ("credential_source", ("spray", "brute", "default", "leaked", "git")),
        ("network_edge_type", ("route", "arp", "traceroute", "service_dep")),
        ("cloud_provider",    ("aws", "gcp", "azure", "other")),
        ("report_type",       ("executive", "technical", "compliance", "patch_matrix")),
        ("report_format",     ("pdf", "html", "json", "csv")),
    ]:
        conn.execute(sa.text(
            f"DO $$ BEGIN "
            f"  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{name}') THEN "
            f"    CREATE TYPE {name} AS ENUM ({', '.join(repr(v) for v in values)}); "
            f"  END IF; "
            f"END $$"
        ))

    # ── updated_at column on assets (non-breaking — default NOW()) ────────────
    op.execute(sa.text(
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS "
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
    ))

    # ── engagements ───────────────────────────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name",        sa.String(255), nullable=False),
        sa.Column("client_name", sa.String(255)),
        sa.Column("operator",    sa.String(128)),
        sa.Column("status",      _enum("active", "paused", "completed", "archived",
                                       name="engagement_status"),
                  nullable=False, server_default="active"),
        sa.Column("notes",       sa.Text),
        sa.Column("config",      postgresql.JSONB, server_default="{}"),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_engagements_status", "engagements", ["status"])
    op.create_index("idx_engagements_created", "engagements", ["created_at"])

    # ── engagement_scope ──────────────────────────────────────────────────────
    op.create_table(
        "engagement_scope",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope_type",    _enum("cidr", "domain", "url", "ip", name="scope_type"),
                  nullable=False),
        sa.Column("value",         sa.String(2048), nullable=False),
        sa.Column("is_active",     sa.Boolean, server_default="TRUE"),
        sa.Column("added_at",      sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("engagement_id", "value", name="uq_scope_eng_value"),
        if_not_exists=True,
    )
    op.create_index("idx_scope_engagement", "engagement_scope", ["engagement_id"])

    # ── dns_records ───────────────────────────────────────────────────────────
    op.create_table(
        "dns_records",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("asset_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE")),
        sa.Column("record_type",  _enum("A","AAAA","MX","NS","TXT","CNAME","SRV","PTR","SOA",
                                        name="dns_record_type"), nullable=False),
        sa.Column("name",         sa.String(512), nullable=False),
        sa.Column("value",        sa.Text, nullable=False),
        sa.Column("ttl",          sa.Integer),
        sa.Column("priority",     sa.Integer),
        sa.Column("is_wildcard",  sa.Boolean, server_default="FALSE"),
        sa.Column("discovered_at",sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_dns_scan",   "dns_records", ["scan_id"])
    op.create_index("idx_dns_asset",  "dns_records", ["asset_id"])
    op.create_index("idx_dns_type",   "dns_records", ["record_type"])
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_records "
        "USING gin (name gin_trgm_ops)"
    ))

    # ── ssl_certificates ──────────────────────────────────────────────────────
    op.create_table(
        "ssl_certificates",
        sa.Column("id",                  postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("asset_id",            postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE")),
        sa.Column("port_id",             postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ports.id", ondelete="SET NULL")),
        sa.Column("subject",             sa.String(512)),
        sa.Column("issuer",              sa.String(512)),
        sa.Column("serial_number",       sa.String(128)),
        sa.Column("not_before",          sa.DateTime(timezone=True)),
        sa.Column("not_after",           sa.DateTime(timezone=True)),
        sa.Column("is_expired",          sa.Boolean, server_default="FALSE"),
        sa.Column("is_self_signed",      sa.Boolean, server_default="FALSE"),
        sa.Column("san",                 postgresql.JSONB, server_default="[]"),
        sa.Column("cipher_suite",        sa.String(256)),
        sa.Column("tls_version",         sa.String(20)),
        sa.Column("fingerprint_sha256",  sa.String(64)),
        sa.Column("key_bits",            sa.Integer),
        sa.Column("signature_algorithm", sa.String(128)),
        sa.Column("is_ev",               sa.Boolean, server_default="FALSE"),
        sa.Column("ocsp_stapling",       sa.Boolean),
        sa.Column("discovered_at",       sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_ssl_asset",   "ssl_certificates", ["asset_id"])
    op.create_index("idx_ssl_expiry",  "ssl_certificates", ["not_after"])
    op.create_index("idx_ssl_expired", "ssl_certificates", ["is_expired"],
                    postgresql_where=sa.text("is_expired = TRUE"))

    # ── web_paths ─────────────────────────────────────────────────────────────
    op.create_table(
        "web_paths",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("asset_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE")),
        sa.Column("url",           sa.Text, nullable=False),
        sa.Column("http_status",   sa.Integer,
                  sa.CheckConstraint("http_status BETWEEN 100 AND 599")),
        sa.Column("content_type",  sa.String(256)),
        sa.Column("response_size", sa.BigInteger),
        sa.Column("title",         sa.String(512)),
        sa.Column("is_sensitive",  sa.Boolean, server_default="FALSE"),
        sa.Column("path_category", _enum("admin","backup","config","api_doc","git","env",
                                         "upload","login","other", name="path_category"),
                  server_default="other"),
        sa.Column("redirect_url",  sa.Text),
        sa.Column("tech_stack",    postgresql.JSONB, server_default="{}"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_webpath_scan",      "web_paths", ["scan_id"])
    op.create_index("idx_webpath_asset",     "web_paths", ["asset_id"])
    op.create_index("idx_webpath_status",    "web_paths", ["http_status"])
    op.create_index("idx_webpath_sensitive", "web_paths", ["is_sensitive"],
                    postgresql_where=sa.text("is_sensitive = TRUE"))
    op.create_index("idx_webpath_category",  "web_paths", ["path_category"])

    # ── credentials ───────────────────────────────────────────────────────────
    op.create_table(
        "credentials",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("asset_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE")),
        sa.Column("service",       sa.String(128)),
        sa.Column("protocol",      sa.String(32)),
        sa.Column("username",      sa.String(512)),
        sa.Column("password_hash", sa.String(512)),
        sa.Column("is_default",    sa.Boolean, server_default="FALSE"),
        sa.Column("is_valid",      sa.Boolean, server_default="FALSE"),
        sa.Column("source",        _enum("spray","brute","default","leaked","git",
                                         name="credential_source"),
                  server_default="spray"),
        sa.Column("confidence",    sa.Float,
                  sa.CheckConstraint("confidence BETWEEN 0 AND 1"),
                  server_default="0.0"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_creds_scan",    "credentials", ["scan_id"])
    op.create_index("idx_creds_asset",   "credentials", ["asset_id"])
    op.create_index("idx_creds_valid",   "credentials", ["is_valid"],
                    postgresql_where=sa.text("is_valid = TRUE"))
    op.create_index("idx_creds_service", "credentials", ["service"])

    # ── mitre_techniques ──────────────────────────────────────────────────────
    op.create_table(
        "mitre_techniques",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",          postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("vuln_id",          postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL")),
        sa.Column("technique_id",     sa.String(12),
                  sa.CheckConstraint(r"technique_id ~ '^T\d{4}$'"),
                  nullable=False),
        sa.Column("sub_technique_id", sa.String(16)),
        sa.Column("tactic",           sa.String(64)),
        sa.Column("technique_name",   sa.String(256)),
        sa.Column("url",              sa.String(512)),
        sa.Column("confidence",       sa.Float,
                  sa.CheckConstraint("confidence BETWEEN 0 AND 1"),
                  server_default="0.0"),
        sa.Column("evidence",         postgresql.JSONB, server_default="{}"),
        sa.Column("mapped_at",        sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,  # type: ignore[call-arg]
    )
    op.create_index("idx_mitre_scan",      "mitre_techniques", ["scan_id"])
    op.create_index("idx_mitre_technique", "mitre_techniques", ["technique_id"])
    op.create_index("idx_mitre_tactic",    "mitre_techniques", ["tactic"])

    # ── network_topology ──────────────────────────────────────────────────────
    op.create_table(
        "network_topology",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",         postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("src_asset_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dst_asset_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("edge_type",       _enum("route","arp","traceroute","service_dep",
                                           name="network_edge_type"),
                  nullable=False, server_default="route"),
        sa.Column("hop_count",       sa.Integer, sa.CheckConstraint("hop_count >= 0")),
        sa.Column("latency_ms",      sa.Float, sa.CheckConstraint("latency_ms >= 0")),
        sa.Column("is_bidirectional",sa.Boolean, server_default="FALSE"),
        sa.Column("metadata",        postgresql.JSONB, server_default="{}"),
        sa.Column("discovered_at",   sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.CheckConstraint("src_asset_id <> dst_asset_id", name="ck_topo_no_self_loop"),
        sa.UniqueConstraint("scan_id", "src_asset_id", "dst_asset_id", "edge_type",
                            name="uq_topology_edge"),
        if_not_exists=True,
    )
    op.create_index("idx_topo_scan",    "network_topology", ["scan_id"])
    op.create_index("idx_topo_src",     "network_topology", ["src_asset_id"])
    op.create_index("idx_topo_dst",     "network_topology", ["dst_asset_id"])

    # ── cloud_resources ───────────────────────────────────────────────────────
    op.create_table(
        "cloud_resources",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("provider",     _enum("aws","gcp","azure","other", name="cloud_provider"),
                  nullable=False),
        sa.Column("service_type", sa.String(128), nullable=False),
        sa.Column("resource_id",  sa.String(512), nullable=False),
        sa.Column("region",       sa.String(64)),
        sa.Column("resource_name",sa.String(512)),
        sa.Column("is_public",    sa.Boolean, server_default="FALSE"),
        sa.Column("is_encrypted", sa.Boolean, server_default="FALSE"),
        sa.Column("config",       postgresql.JSONB, server_default="{}"),
        sa.Column("tags",         postgresql.JSONB, server_default="{}"),
        sa.Column("risk_flags",   postgresql.JSONB, server_default="{}"),
        sa.Column("discovered_at",sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("scan_id", "provider", "resource_id", name="uq_cloud_resource"),
        if_not_exists=True,
    )
    op.create_index("idx_cloud_scan",     "cloud_resources", ["scan_id"])
    op.create_index("idx_cloud_provider", "cloud_resources", ["provider"])
    op.create_index("idx_cloud_public",   "cloud_resources", ["is_public"],
                    postgresql_where=sa.text("is_public = TRUE"))

    # ── reports ───────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("engagements.id", ondelete="SET NULL")),
        sa.Column("report_type",   _enum("executive","technical","compliance","patch_matrix",
                                          name="report_type"),
                  nullable=False, server_default="technical"),
        sa.Column("format",        _enum("pdf","html","json","csv", name="report_format"),
                  nullable=False, server_default="pdf"),
        sa.Column("file_path",     sa.Text),
        sa.Column("file_size",     sa.BigInteger),
        sa.Column("finding_count", sa.Integer, server_default="0"),
        sa.Column("generated_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("generated_by",  sa.String(128), server_default="heaven"),
        sa.Column("checksum",      sa.String(64)),
        if_not_exists=True,
    )
    op.create_index("idx_reports_scan",       "reports", ["scan_id"])
    op.create_index("idx_reports_engagement", "reports", ["engagement_id"])
    op.create_index("idx_reports_type",       "reports", ["report_type"])

    # ── audit_log (range-partitioned) ─────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id            BIGSERIAL,
            actor         VARCHAR(128),
            action        VARCHAR(128) NOT NULL,
            resource_type VARCHAR(64),
            resource_id   TEXT,
            details       JSONB DEFAULT '{}',
            ip_address    INET,
            user_agent    TEXT,
            timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (id, timestamp)
        ) PARTITION BY RANGE (timestamp)
    """))
    for suffix, start, end in [
        ("2026_q1", "2026-01-01", "2026-04-01"),
        ("2026_q2", "2026-04-01", "2026-07-01"),
        ("2026_q3", "2026-07-01", "2026-10-01"),
        ("2026_q4", "2026-10-01", "2027-01-01"),
        ("2027_q1", "2027-01-01", "2027-04-01"),
    ]:
        op.execute(sa.text(f"""
            CREATE TABLE IF NOT EXISTS audit_log_{suffix}
            PARTITION OF audit_log
            FOR VALUES FROM ('{start}') TO ('{end}')
        """))
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS audit_log_default
        PARTITION OF audit_log DEFAULT
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id)"
    ))

    # ── tags ─────────────────────────────────────────────────────────────────
    op.create_table(
        "tags",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name",        sa.String(64), nullable=False),
        sa.Column("color",       sa.String(16), server_default="'#6366f1'"),
        sa.Column("description", sa.Text),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("name", name="uq_tag_name"),
        if_not_exists=True,
    )

    # ── finding_tags ──────────────────────────────────────────────────────────
    op.create_table(
        "finding_tags",
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tag_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tags.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tagged_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.PrimaryKeyConstraint("finding_id", "tag_id"),
        if_not_exists=True,
    )
    op.create_index("idx_ftags_tag", "finding_tags", ["tag_id"])

    # ── operator_notes ────────────────────────────────────────────────────────
    op.create_table(
        "operator_notes",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("author",        sa.String(128)),
        sa.Column("resource_type", sa.String(64)),
        sa.Column("resource_id",   postgresql.UUID(as_uuid=True)),
        sa.Column("content",       sa.Text, nullable=False),
        sa.Column("is_private",    sa.Boolean, server_default="FALSE"),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_notes_resource", "operator_notes", ["resource_type", "resource_id"])
    op.create_index("idx_notes_author",   "operator_notes", ["author"])

    # ── scan_checkpoints ──────────────────────────────────────────────────────
    op.create_table(
        "scan_checkpoints",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",         postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("phase",           sa.String(64)),
        sa.Column("completed_tasks", postgresql.JSONB, server_default="[]"),
        sa.Column("state",           postgresql.JSONB, server_default="{}"),
        sa.Column("last_updated",    sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_checkpoint_scan", "scan_checkpoints", ["scan_id"])

    # ── notifications ─────────────────────────────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("severity",     sa.String(20), server_default="'info'"),
        sa.Column("category",     sa.String(64)),
        sa.Column("title",        sa.String(512), nullable=False),
        sa.Column("message",      sa.Text),
        sa.Column("is_read",      sa.Boolean, server_default="FALSE"),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        if_not_exists=True,
    )
    op.create_index("idx_notif_scan",    "notifications", ["scan_id"])
    op.create_index("idx_notif_unread",  "notifications", ["is_read"],
                    postgresql_where=sa.text("is_read = FALSE"))
    op.create_index("idx_notif_created", "notifications", ["created_at"])

    # ── additional indexes on existing tables ─────────────────────────────────
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_vulns_fts ON vulnerabilities "
        "USING gin(to_tsvector('english', "
        "coalesce(title,'') || ' ' || coalesce(description,'')))"
    ))

    # ── triggers for new tables ───────────────────────────────────────────────
    for tbl in ("engagements", "operator_notes"):
        op.execute(sa.text(f"""
            CREATE OR REPLACE TRIGGER trg_{tbl}_updated
                BEFORE UPDATE ON {tbl}
                FOR EACH ROW EXECUTE FUNCTION update_updated_at()
        """))

    op.execute(sa.text("""
        CREATE OR REPLACE TRIGGER trg_assets_updated
            BEFORE UPDATE ON assets
            FOR EACH ROW EXECUTE FUNCTION update_updated_at()
    """))


# ─────────────────────────────────────────────────────────────────────────────
# downgrade
# ─────────────────────────────────────────────────────────────────────────────

def downgrade() -> None:
    for tbl in [
        "notifications", "scan_checkpoints", "operator_notes",
        "finding_tags", "tags", "audit_log", "reports",
        "cloud_resources", "network_topology", "mitre_techniques",
        "credentials", "web_paths", "ssl_certificates",
        "dns_records", "engagement_scope", "engagements",
    ]:
        op.execute(sa.text(f"DROP TABLE IF EXISTS {tbl} CASCADE"))

    for enum in [
        "engagement_status", "scope_type", "dns_record_type",
        "path_category", "credential_source", "network_edge_type",
        "cloud_provider", "report_type", "report_format",
    ]:
        op.execute(sa.text(f"DROP TYPE IF EXISTS {enum}"))

    # Remove added column
    op.execute(sa.text(
        "ALTER TABLE assets DROP COLUMN IF EXISTS updated_at"
    ))

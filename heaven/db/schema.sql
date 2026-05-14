-- ============================================================
-- HEAVEN — PostgreSQL Database Schema
-- Automated Vulnerability Scanner & Risk Triage Platform
-- Version 2.0 — Production-Quality Schema
-- ============================================================

-- ============================================================
-- RESET SCHEMA FOR IDEMPOTENCY
-- ============================================================
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";  -- multi-column GIN indexes

-- ============================================================
-- ENUM TYPES — EXISTING (preserved exactly)
-- ============================================================

CREATE TYPE asset_type AS ENUM (
    'ipv4', 'ipv6', 'url', 'domain', 'arn', 'bssid', 'repository', 'container'
);

CREATE TYPE scan_status AS ENUM (
    'pending', 'running', 'completed', 'failed', 'cancelled'
);

CREATE TYPE scan_segment AS ENUM (
    'network', 'web', 'cloud', 'wireless', 'devsecops', 'full'
);

CREATE TYPE severity_level AS ENUM (
    'info', 'low', 'medium', 'high', 'critical'
);

CREATE TYPE validation_method AS ENUM (
    'sqli_boolean', 'xss_reflection', 'ssrf_callback', 'open_redirect',
    'directory_traversal', 'cors_misconfig', 'header_injection', 'info_disclosure',
    'banner_check', 'version_check', 'config_check'
);

CREATE TYPE validation_result AS ENUM (
    'confirmed', 'likely', 'inconclusive', 'false_positive'
);

CREATE TYPE secret_type AS ENUM (
    'aws_key', 'github_token', 'google_api', 'stripe_key', 'slack_token',
    'private_key', 'password', 'jwt_secret', 'database_url', 'generic_secret'
);

-- ============================================================
-- ENUM TYPES — NEW
-- ============================================================

CREATE TYPE engagement_status AS ENUM (
    'planned', 'active', 'paused', 'completed', 'archived'
);

CREATE TYPE scope_type AS ENUM (
    'cidr', 'domain', 'url', 'ip'
);

CREATE TYPE dns_record_type AS ENUM (
    'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SRV', 'PTR', 'SOA'
);

CREATE TYPE path_category AS ENUM (
    'admin', 'backup', 'config', 'api_doc', 'git', 'env', 'upload', 'login', 'other'
);

CREATE TYPE credential_source AS ENUM (
    'spray', 'brute', 'default', 'leaked', 'git'
);

CREATE TYPE network_edge_type AS ENUM (
    'route', 'arp', 'traceroute', 'service_dep'
);

CREATE TYPE cloud_provider AS ENUM (
    'aws', 'gcp', 'azure', 'other'
);

CREATE TYPE report_type AS ENUM (
    'executive', 'technical', 'compliance', 'patch_matrix'
);

CREATE TYPE report_format AS ENUM (
    'pdf', 'html', 'json', 'csv'
);

-- ============================================================
-- CORE TABLES — EXISTING (preserved exactly)
-- ============================================================

-- Scan sessions
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    scan_type       scan_segment NOT NULL DEFAULT 'full',
    status          scan_status NOT NULL DEFAULT 'pending',
    target_spec     JSONB NOT NULL DEFAULT '{}',
    config          JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stats           JSONB DEFAULT '{}',
    error_log       TEXT
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Discovered assets (updated_at added for trigger support)
CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_type      asset_type NOT NULL,
    value           VARCHAR(2048) NOT NULL,
    hostname        VARCHAR(512),
    metadata        JSONB DEFAULT '{}',
    is_honeypot     BOOLEAN DEFAULT FALSE,
    honeypot_score  FLOAT DEFAULT 0.0,
    criticality     INTEGER DEFAULT 1 CHECK (criticality BETWEEN 1 AND 5),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,

    CONSTRAINT uq_asset_type_value UNIQUE (asset_type, value)
);

CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_value ON assets USING gin (value gin_trgm_ops);
CREATE INDEX idx_assets_honeypot ON assets(is_honeypot) WHERE is_honeypot = TRUE;
CREATE INDEX idx_assets_scan ON assets(scan_id);

-- Open ports discovered per asset
CREATE TABLE ports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',
    state           VARCHAR(20) NOT NULL DEFAULT 'open',
    service         VARCHAR(128),
    version         VARCHAR(256),
    banner          TEXT,
    cpe             VARCHAR(512),
    fingerprint     JSONB DEFAULT '{}',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_asset_port_proto UNIQUE (asset_id, port, protocol)
);

CREATE INDEX idx_ports_asset ON ports(asset_id);
CREATE INDEX idx_ports_service ON ports(service);

-- Discovered vulnerabilities
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port_id         UUID REFERENCES ports(id) ON DELETE SET NULL,
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,
    cve_id          VARCHAR(20),
    cwe_id          VARCHAR(20),
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    severity        severity_level NOT NULL DEFAULT 'info',
    cvss_base       FLOAT CHECK (cvss_base BETWEEN 0 AND 10),
    cvss_vector     VARCHAR(256),
    epss_score      FLOAT CHECK (epss_score BETWEEN 0 AND 1),
    risk_score      FLOAT CHECK (risk_score BETWEEN 0 AND 100),
    exploit_available BOOLEAN DEFAULT FALSE,
    in_kev          BOOLEAN DEFAULT FALSE,
    details         JSONB DEFAULT '{}',
    remediation     TEXT,
    "references"    JSONB DEFAULT '[]',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_vuln_asset_cve UNIQUE (asset_id, cve_id, port_id)
);

CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_risk ON vulnerabilities(risk_score DESC NULLS LAST);
CREATE INDEX idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);

-- Full-text search index on vulnerabilities
CREATE INDEX idx_vulns_fts ON vulnerabilities
    USING gin(to_tsvector('english',
        coalesce(title, '') || ' ' || coalesce(description, '')
    ));

-- Safe PoC validation results
CREATE TABLE validations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vuln_id         UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    method          validation_method NOT NULL,
    result          validation_result NOT NULL DEFAULT 'inconclusive',
    confidence      FLOAT DEFAULT 0.0 CHECK (confidence BETWEEN 0 AND 1),
    evidence        JSONB DEFAULT '{}',
    request_sent    TEXT,
    response_received TEXT,
    duration_ms     INTEGER,
    validated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_validations_vuln ON validations(vuln_id);
CREATE INDEX idx_validations_result ON validations(result);

-- Leaked secrets from git repositories
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,
    asset_id        UUID REFERENCES assets(id) ON DELETE CASCADE,
    repo_url        VARCHAR(2048),
    file_path       VARCHAR(2048) NOT NULL,
    secret_type     secret_type NOT NULL,
    line_number     INTEGER,
    snippet         TEXT,
    entropy         FLOAT,
    commit_hash     VARCHAR(40),
    commit_date     TIMESTAMPTZ,
    author          VARCHAR(256),
    is_active       BOOLEAN DEFAULT NULL,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secrets_type ON secrets(secret_type);
CREATE INDEX idx_secrets_scan ON secrets(scan_id);

-- ML risk score predictions
CREATE TABLE risk_scores (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vuln_id         UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    predicted_score FLOAT NOT NULL CHECK (predicted_score BETWEEN 0 AND 100),
    exploit_probability FLOAT CHECK (exploit_probability BETWEEN 0 AND 1),
    features        JSONB NOT NULL DEFAULT '{}',
    model_version   VARCHAR(50) NOT NULL,
    explanation     JSONB DEFAULT '{}',
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_vuln ON risk_scores(vuln_id);
CREATE INDEX idx_risk_score ON risk_scores(predicted_score DESC);

-- Aggregated scan findings for reporting
CREATE TABLE scan_findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_type    VARCHAR(100) NOT NULL,
    severity        severity_level NOT NULL,
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    data            JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON scan_findings(scan_id);
CREATE INDEX idx_findings_severity ON scan_findings(severity);

-- Vulnerability chains (for attack tree generation)
CREATE TABLE vuln_chains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    chain_name      VARCHAR(256),
    chain_score     FLOAT DEFAULT 0.0,
    vuln_ids        UUID[] NOT NULL,
    attack_path     JSONB NOT NULL DEFAULT '[]',
    impact          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chains_scan ON vuln_chains(scan_id);
CREATE INDEX idx_chains_score ON vuln_chains(chain_score DESC);

-- ============================================================
-- NEW TABLES
-- ============================================================

-- Penetration testing engagements
CREATE TABLE engagements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(512) NOT NULL,
    client_name     VARCHAR(256) NOT NULL,
    operator        VARCHAR(256) NOT NULL,
    status          engagement_status NOT NULL DEFAULT 'planned',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes           TEXT,
    config          JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_engagements_status ON engagements(status);
CREATE INDEX idx_engagements_operator ON engagements(operator);
CREATE INDEX idx_engagements_created ON engagements(created_at DESC);

-- Scope entries for each engagement
CREATE TABLE engagement_scope (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    scope_type      scope_type NOT NULL,
    value           VARCHAR(2048) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_engagement_scope_value UNIQUE (engagement_id, scope_type, value)
);

CREATE INDEX idx_engagement_scope_engagement ON engagement_scope(engagement_id);
CREATE INDEX idx_engagement_scope_active ON engagement_scope(engagement_id, is_active) WHERE is_active = TRUE;

-- DNS records discovered during enumeration
CREATE TABLE dns_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id        UUID REFERENCES assets(id) ON DELETE SET NULL,
    record_type     dns_record_type NOT NULL,
    name            VARCHAR(2048) NOT NULL,
    value           TEXT NOT NULL,
    ttl             INTEGER CHECK (ttl >= 0),
    priority        INTEGER,
    is_wildcard     BOOLEAN NOT NULL DEFAULT FALSE,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_dns_record UNIQUE (scan_id, record_type, name, value)
);

CREATE INDEX idx_dns_records_scan ON dns_records(scan_id);
CREATE INDEX idx_dns_records_asset ON dns_records(asset_id);
CREATE INDEX idx_dns_records_type ON dns_records(record_type);
CREATE INDEX idx_dns_records_name ON dns_records USING gin (name gin_trgm_ops);

-- TLS/SSL certificates discovered on services
CREATE TABLE ssl_certificates (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id            UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port_id             UUID REFERENCES ports(id) ON DELETE SET NULL,
    subject             VARCHAR(2048) NOT NULL,
    issuer              VARCHAR(2048),
    serial_number       VARCHAR(256),
    not_before          TIMESTAMPTZ,
    not_after           TIMESTAMPTZ,
    is_expired          BOOLEAN NOT NULL DEFAULT FALSE,
    is_self_signed      BOOLEAN NOT NULL DEFAULT FALSE,
    san                 JSONB NOT NULL DEFAULT '[]',
    cipher_suite        VARCHAR(256),
    tls_version         VARCHAR(20),
    fingerprint_sha256  VARCHAR(64),
    key_bits            INTEGER CHECK (key_bits > 0),
    signature_algorithm VARCHAR(128),
    is_ev               BOOLEAN NOT NULL DEFAULT FALSE,
    ocsp_stapling       BOOLEAN,
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_ssl_cert_fingerprint UNIQUE (asset_id, fingerprint_sha256)
);

CREATE INDEX idx_ssl_asset ON ssl_certificates(asset_id);
CREATE INDEX idx_ssl_port ON ssl_certificates(port_id);
CREATE INDEX idx_ssl_not_after ON ssl_certificates(not_after);
CREATE INDEX idx_ssl_expired ON ssl_certificates(is_expired) WHERE is_expired = TRUE;
CREATE INDEX idx_ssl_self_signed ON ssl_certificates(is_self_signed) WHERE is_self_signed = TRUE;

-- Web paths and endpoints discovered via crawling / directory brute-force
CREATE TABLE web_paths (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    http_status     INTEGER CHECK (http_status BETWEEN 100 AND 599),
    content_type    VARCHAR(256),
    response_size   BIGINT CHECK (response_size >= 0),
    title           VARCHAR(1024),
    is_sensitive    BOOLEAN NOT NULL DEFAULT FALSE,
    path_category   path_category NOT NULL DEFAULT 'other',
    redirect_url    TEXT,
    tech_stack      JSONB NOT NULL DEFAULT '[]',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_web_path_scan_url UNIQUE (scan_id, url)
);

CREATE INDEX idx_web_paths_scan ON web_paths(scan_id);
CREATE INDEX idx_web_paths_asset ON web_paths(asset_id);
CREATE INDEX idx_web_paths_status ON web_paths(http_status);
CREATE INDEX idx_web_paths_sensitive ON web_paths(is_sensitive) WHERE is_sensitive = TRUE;
CREATE INDEX idx_web_paths_category ON web_paths(path_category);

-- Discovered credentials (hashed or partially redacted)
CREATE TABLE credentials (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    service         VARCHAR(128),
    protocol        VARCHAR(50),
    username        VARCHAR(512),
    password_hash   VARCHAR(512),
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,
    is_valid        BOOLEAN NOT NULL DEFAULT FALSE,
    source          credential_source NOT NULL,
    confidence      FLOAT NOT NULL DEFAULT 0.0 CHECK (confidence BETWEEN 0 AND 1),
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credentials_scan ON credentials(scan_id);
CREATE INDEX idx_credentials_asset ON credentials(asset_id);
CREATE INDEX idx_credentials_service ON credentials(service);
CREATE INDEX idx_credentials_valid ON credentials(is_valid) WHERE is_valid = TRUE;
CREATE INDEX idx_credentials_source ON credentials(source);

-- MITRE ATT&CK technique mappings for findings
CREATE TABLE mitre_techniques (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_id             UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    technique_id        VARCHAR(20) NOT NULL,  -- e.g. 'T1059'
    sub_technique_id    VARCHAR(30),           -- e.g. 'T1059.001'
    tactic              VARCHAR(128) NOT NULL,
    technique_name      VARCHAR(512) NOT NULL,
    url                 TEXT,
    confidence          FLOAT NOT NULL DEFAULT 0.0 CHECK (confidence BETWEEN 0 AND 1),
    evidence            JSONB NOT NULL DEFAULT '{}',
    mapped_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_technique_id_format CHECK (technique_id ~ '^T\d{4}$')
);

CREATE INDEX idx_mitre_scan ON mitre_techniques(scan_id);
CREATE INDEX idx_mitre_vuln ON mitre_techniques(vuln_id);
CREATE INDEX idx_mitre_technique_id ON mitre_techniques(technique_id);
CREATE INDEX idx_mitre_tactic ON mitre_techniques(tactic);

-- Network topology edges (discovered routes and relationships between assets)
CREATE TABLE network_topology (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    src_asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dst_asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    edge_type           network_edge_type NOT NULL,
    hop_count           INTEGER CHECK (hop_count >= 0),
    latency_ms          FLOAT CHECK (latency_ms >= 0),
    is_bidirectional    BOOLEAN NOT NULL DEFAULT FALSE,
    metadata            JSONB NOT NULL DEFAULT '{}',
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_topology_edge UNIQUE (scan_id, src_asset_id, dst_asset_id, edge_type),
    CONSTRAINT chk_no_self_loop CHECK (src_asset_id <> dst_asset_id)
);

CREATE INDEX idx_topology_scan ON network_topology(scan_id);
CREATE INDEX idx_topology_src ON network_topology(src_asset_id);
CREATE INDEX idx_topology_dst ON network_topology(dst_asset_id);
CREATE INDEX idx_topology_edge_type ON network_topology(edge_type);

-- Cloud resources discovered during cloud enumeration
CREATE TABLE cloud_resources (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider        cloud_provider NOT NULL,
    service_type    VARCHAR(128) NOT NULL,
    resource_id     VARCHAR(512) NOT NULL,
    region          VARCHAR(64),
    resource_name   VARCHAR(512),
    is_public       BOOLEAN NOT NULL DEFAULT FALSE,
    is_encrypted    BOOLEAN NOT NULL DEFAULT FALSE,
    config          JSONB NOT NULL DEFAULT '{}',
    tags            JSONB NOT NULL DEFAULT '{}',
    risk_flags      JSONB NOT NULL DEFAULT '[]',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_cloud_resource UNIQUE (scan_id, provider, resource_id)
);

CREATE INDEX idx_cloud_scan ON cloud_resources(scan_id);
CREATE INDEX idx_cloud_provider ON cloud_resources(provider);
CREATE INDEX idx_cloud_public ON cloud_resources(is_public) WHERE is_public = TRUE;
CREATE INDEX idx_cloud_service_type ON cloud_resources(service_type);
CREATE INDEX idx_cloud_risk_flags ON cloud_resources USING gin(risk_flags);

-- Generated reports (references both scans and engagements)
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    engagement_id   UUID REFERENCES engagements(id) ON DELETE SET NULL,
    report_type     report_type NOT NULL,
    format          report_format NOT NULL,
    file_path       TEXT,
    file_size       BIGINT CHECK (file_size >= 0),
    finding_count   INTEGER CHECK (finding_count >= 0),
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by    VARCHAR(256),
    checksum        VARCHAR(128)
);

CREATE INDEX idx_reports_scan ON reports(scan_id);
CREATE INDEX idx_reports_engagement ON reports(engagement_id);
CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_generated ON reports(generated_at DESC);

-- Audit log — partitioned by month for scalability
CREATE TABLE audit_log (
    id              BIGSERIAL,
    actor           VARCHAR(256),
    action          VARCHAR(256) NOT NULL,
    resource_type   VARCHAR(128),
    resource_id     TEXT,
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      INET,
    user_agent      TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create initial monthly partitions (current month and two ahead)
CREATE TABLE audit_log_2026_05 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE audit_log_2026_06 PARTITION OF audit_log
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE TABLE audit_log_2026_07 PARTITION OF audit_log
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

-- Default catch-all partition for older/future data
CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_actor ON audit_log(actor);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- Taxonomy tags for findings
CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(128) NOT NULL UNIQUE,
    color       VARCHAR(20),
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tags_name ON tags(name);

-- Junction table linking tags to findings (vulns or scan_findings)
-- finding_id is an untyped UUID; resource_type distinguishes the referenced table
CREATE TABLE finding_tags (
    finding_id  UUID NOT NULL,
    tag_id      UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    tagged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (finding_id, tag_id)
);

CREATE INDEX idx_finding_tags_tag ON finding_tags(tag_id);
CREATE INDEX idx_finding_tags_finding ON finding_tags(finding_id);

-- Operator notes attached to any resource
CREATE TABLE operator_notes (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    author          VARCHAR(256) NOT NULL,
    resource_type   VARCHAR(128) NOT NULL,
    resource_id     UUID NOT NULL,
    content         TEXT NOT NULL,
    is_private      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_operator_notes_resource ON operator_notes(resource_type, resource_id);
CREATE INDEX idx_operator_notes_author ON operator_notes(author);
CREATE INDEX idx_operator_notes_private ON operator_notes(is_private, resource_type);

-- Scan checkpoints for resumable scanning
CREATE TABLE scan_checkpoints (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase               VARCHAR(128) NOT NULL,
    completed_tasks     JSONB NOT NULL DEFAULT '[]',
    state               JSONB NOT NULL DEFAULT '{}',
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_scan_checkpoint UNIQUE (scan_id)
);

CREATE INDEX idx_scan_checkpoints_scan ON scan_checkpoints(scan_id);
CREATE INDEX idx_scan_checkpoints_phase ON scan_checkpoints(phase);

-- In-platform notifications for operators
CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,
    severity        VARCHAR(20) NOT NULL DEFAULT 'info'
                        CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    category        VARCHAR(128),
    title           VARCHAR(512) NOT NULL,
    message         TEXT,
    is_read         BOOLEAN NOT NULL DEFAULT FALSE,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_scan ON notifications(scan_id);
CREATE INDEX idx_notifications_unread ON notifications(is_read, created_at DESC) WHERE is_read = FALSE;
CREATE INDEX idx_notifications_severity ON notifications(severity);
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);

-- ============================================================
-- VIEWS
-- ============================================================

-- Dashboard summary (preserved from v1)
CREATE OR REPLACE VIEW dashboard_summary AS
SELECT
    (SELECT COUNT(*) FROM scans WHERE status = 'completed')         AS total_scans,
    (SELECT COUNT(*) FROM assets WHERE is_honeypot = FALSE)         AS total_assets,
    (SELECT COUNT(*) FROM vulnerabilities)                          AS total_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical') AS critical_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high')  AS high_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium') AS medium_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low')   AS low_vulns,
    (SELECT COUNT(*) FROM validations WHERE result = 'confirmed')   AS confirmed_vulns,
    (SELECT COUNT(*) FROM secrets)                                  AS total_secrets,
    (SELECT AVG(risk_score) FROM vulnerabilities WHERE risk_score IS NOT NULL) AS avg_risk_score;

-- Top risks view (preserved from v1, extended with engagement linkage)
CREATE OR REPLACE VIEW v_top_risks AS
SELECT
    v.id,
    v.cve_id,
    v.title,
    v.severity,
    v.cvss_base,
    v.risk_score,
    v.epss_score,
    v.exploit_available,
    v.in_kev,
    a.asset_type,
    a.value           AS asset_value,
    a.is_honeypot,
    a.criticality     AS asset_criticality,
    val.result        AS validation_result,
    val.confidence    AS validation_confidence,
    s.name            AS scan_name,
    rs.predicted_score AS ml_risk_score
FROM vulnerabilities v
JOIN assets a ON v.asset_id = a.id
JOIN scans s ON v.scan_id = s.id
LEFT JOIN LATERAL (
    SELECT result, confidence
    FROM validations
    WHERE vuln_id = v.id
    ORDER BY validated_at DESC
    LIMIT 1
) val ON TRUE
LEFT JOIN LATERAL (
    SELECT predicted_score
    FROM risk_scores
    WHERE vuln_id = v.id
    ORDER BY scored_at DESC
    LIMIT 1
) rs ON TRUE
WHERE a.is_honeypot = FALSE
ORDER BY v.risk_score DESC NULLS LAST;

-- Legacy alias so existing code referencing top_risks still works
CREATE OR REPLACE VIEW top_risks AS
SELECT * FROM v_top_risks LIMIT 100;

-- Per-engagement vulnerability counts by severity
CREATE OR REPLACE VIEW v_engagement_summary AS
SELECT
    e.id                                                            AS engagement_id,
    e.name                                                          AS engagement_name,
    e.client_name,
    e.operator,
    e.status,
    COUNT(DISTINCT s.id)                                            AS scan_count,
    COUNT(DISTINCT v.id)                                            AS total_vulns,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical')    AS critical_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'high')        AS high_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'medium')      AS medium_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'low')         AS low_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'info')        AS info_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.exploit_available = TRUE) AS exploitable_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.in_kev = TRUE)            AS kev_count,
    ROUND(AVG(v.risk_score)::NUMERIC, 2)                           AS avg_risk_score,
    e.created_at,
    e.updated_at
FROM engagements e
LEFT JOIN reports r ON r.engagement_id = e.id
LEFT JOIN scans s ON s.id = r.scan_id
LEFT JOIN vulnerabilities v ON v.scan_id = s.id
GROUP BY e.id, e.name, e.client_name, e.operator, e.status, e.created_at, e.updated_at;

-- Per-asset attack surface metrics
CREATE OR REPLACE VIEW v_asset_attack_surface AS
SELECT
    a.id                                                             AS asset_id,
    a.asset_type,
    a.value,
    a.hostname,
    a.criticality,
    a.is_honeypot,
    a.first_seen,
    a.last_seen,
    COUNT(DISTINCT p.id)                                             AS open_port_count,
    COUNT(DISTINCT v.id)                                             AS vuln_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical')     AS critical_vuln_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.exploit_available = TRUE)  AS exploitable_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.in_kev = TRUE)             AS kev_count,
    COUNT(DISTINCT c.id)                                             AS credential_count,
    COUNT(DISTINCT sc.id) FILTER (WHERE sc.is_expired = TRUE)       AS expired_cert_count,
    MAX(v.risk_score)                                                AS max_risk_score,
    ROUND(AVG(v.risk_score)::NUMERIC, 2)                            AS avg_risk_score
FROM assets a
LEFT JOIN ports p ON p.asset_id = a.id AND p.state = 'open'
LEFT JOIN vulnerabilities v ON v.asset_id = a.id
LEFT JOIN credentials c ON c.asset_id = a.id AND c.is_valid = TRUE
LEFT JOIN ssl_certificates sc ON sc.asset_id = a.id
WHERE a.is_honeypot = FALSE
GROUP BY a.id, a.asset_type, a.value, a.hostname, a.criticality,
         a.is_honeypot, a.first_seen, a.last_seen;

-- Daily vulnerability discovery trend for the past 30 days
CREATE OR REPLACE VIEW v_vuln_trend_30d AS
SELECT
    day::DATE                                                                   AS day,
    COUNT(v.id)                                                                 AS total_new,
    COUNT(v.id) FILTER (WHERE v.severity = 'critical')                         AS critical_new,
    COUNT(v.id) FILTER (WHERE v.severity = 'high')                             AS high_new,
    COUNT(v.id) FILTER (WHERE v.severity = 'medium')                           AS medium_new,
    COUNT(v.id) FILTER (WHERE v.severity = 'low')                              AS low_new,
    COUNT(v.id) FILTER (WHERE v.exploit_available = TRUE)                      AS exploitable_new
FROM generate_series(
    NOW() - INTERVAL '29 days',
    NOW(),
    INTERVAL '1 day'
) AS gs(day)
LEFT JOIN vulnerabilities v
    ON v.discovered_at >= gs.day
   AND v.discovered_at <  gs.day + INTERVAL '1 day'
GROUP BY day
ORDER BY day;

-- SSL certificates expiring within 30 days
CREATE OR REPLACE VIEW v_ssl_expiry_alerts AS
SELECT
    sc.id,
    sc.subject,
    sc.issuer,
    sc.not_after,
    sc.not_after - NOW()                    AS time_until_expiry,
    EXTRACT(DAY FROM sc.not_after - NOW())  AS days_until_expiry,
    sc.tls_version,
    sc.cipher_suite,
    sc.is_self_signed,
    sc.is_expired,
    sc.fingerprint_sha256,
    a.value                                 AS asset_value,
    a.asset_type,
    p.port,
    p.protocol
FROM ssl_certificates sc
JOIN assets a ON a.id = sc.asset_id
LEFT JOIN ports p ON p.id = sc.port_id
WHERE sc.not_after IS NOT NULL
  AND sc.not_after <= NOW() + INTERVAL '30 days'
  AND sc.is_expired = FALSE
ORDER BY sc.not_after ASC;

-- Credential findings aggregated by service
CREATE OR REPLACE VIEW v_credential_summary AS
SELECT
    c.service,
    c.protocol,
    c.source,
    COUNT(*)                                           AS total_found,
    COUNT(*) FILTER (WHERE c.is_valid = TRUE)          AS valid_count,
    COUNT(*) FILTER (WHERE c.is_default = TRUE)        AS default_count,
    ROUND(AVG(c.confidence)::NUMERIC, 3)               AS avg_confidence,
    COUNT(DISTINCT c.asset_id)                         AS affected_assets,
    MAX(c.discovered_at)                               AS last_seen
FROM credentials c
GROUP BY c.service, c.protocol, c.source
ORDER BY valid_count DESC, total_found DESC;

-- MITRE ATT&CK coverage matrix
CREATE OR REPLACE VIEW v_mitre_coverage AS
SELECT
    mt.tactic,
    mt.technique_id,
    mt.sub_technique_id,
    mt.technique_name,
    mt.url,
    COUNT(*)                                AS occurrence_count,
    COUNT(DISTINCT mt.scan_id)              AS scan_count,
    COUNT(DISTINCT mt.vuln_id)              AS linked_vuln_count,
    ROUND(AVG(mt.confidence)::NUMERIC, 3)  AS avg_confidence,
    MAX(mt.mapped_at)                       AS last_seen
FROM mitre_techniques mt
GROUP BY mt.tactic, mt.technique_id, mt.sub_technique_id, mt.technique_name, mt.url
ORDER BY mt.tactic, mt.technique_id, mt.sub_technique_id;

-- Public cloud resources correlated with vulnerabilities
CREATE OR REPLACE VIEW v_cloud_public_exposure AS
SELECT
    cr.id                           AS resource_id,
    cr.provider,
    cr.service_type,
    cr.resource_id                  AS cloud_resource_id,
    cr.resource_name,
    cr.region,
    cr.is_encrypted,
    cr.risk_flags,
    cr.tags,
    a.value                         AS asset_value,
    a.asset_type,
    COUNT(DISTINCT v.id)            AS vuln_count,
    COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical') AS critical_count,
    MAX(v.risk_score)               AS max_risk_score,
    cr.discovered_at
FROM cloud_resources cr
JOIN scans s ON s.id = cr.scan_id
LEFT JOIN assets a ON a.scan_id = s.id
LEFT JOIN vulnerabilities v ON v.asset_id = a.id
WHERE cr.is_public = TRUE
GROUP BY cr.id, cr.provider, cr.service_type, cr.resource_id,
         cr.resource_name, cr.region, cr.is_encrypted, cr.risk_flags,
         cr.tags, a.value, a.asset_type, cr.discovered_at
ORDER BY critical_count DESC NULLS LAST, max_risk_score DESC NULLS LAST;

-- Scan phase completion progress
CREATE OR REPLACE VIEW v_scan_progress AS
SELECT
    s.id                                            AS scan_id,
    s.name                                          AS scan_name,
    s.status,
    s.scan_type,
    s.started_at,
    s.created_at,
    sc.phase                                        AS current_phase,
    sc.last_updated                                 AS phase_updated_at,
    jsonb_array_length(COALESCE(sc.completed_tasks, '[]'::JSONB))
                                                    AS completed_task_count,
    COUNT(DISTINCT a.id)                            AS asset_count,
    COUNT(DISTINCT p.id)                            AS port_count,
    COUNT(DISTINCT v.id)                            AS vuln_count,
    COUNT(DISTINCT n.id) FILTER (WHERE n.is_read = FALSE)
                                                    AS unread_notifications,
    EXTRACT(EPOCH FROM (COALESCE(s.completed_at, NOW()) - s.started_at)) / 60
                                                    AS elapsed_minutes
FROM scans s
LEFT JOIN scan_checkpoints sc ON sc.scan_id = s.id
LEFT JOIN assets a ON a.scan_id = s.id
LEFT JOIN ports p ON p.asset_id = a.id
LEFT JOIN vulnerabilities v ON v.scan_id = s.id
LEFT JOIN notifications n ON n.scan_id = s.id
GROUP BY s.id, s.name, s.status, s.scan_type, s.started_at, s.created_at,
         s.completed_at, sc.phase, sc.last_updated, sc.completed_tasks
ORDER BY s.created_at DESC;

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Preserved from v1: auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Map severity label to integer for ordering/comparison
CREATE OR REPLACE FUNCTION fn_severity_to_int(severity TEXT)
RETURNS INT AS $$
BEGIN
    RETURN CASE lower(trim(severity))
        WHEN 'info'     THEN 1
        WHEN 'low'      THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'high'     THEN 4
        WHEN 'critical' THEN 5
        ELSE 0
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- Weighted average risk score for an asset (higher asset criticality amplifies scores)
CREATE OR REPLACE FUNCTION calculate_asset_risk(asset_uuid UUID)
RETURNS FLOAT AS $$
DECLARE
    result       FLOAT;
    asset_crit   INTEGER;
BEGIN
    SELECT COALESCE(criticality, 1)
      INTO asset_crit
      FROM assets
     WHERE id = asset_uuid;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(
        -- Weight by severity: critical=5, high=4, medium=3, low=2, info=1
        SUM(
            COALESCE(v.risk_score, v.cvss_base * 10, 0)
            * fn_severity_to_int(v.severity::TEXT)
        ) / NULLIF(SUM(fn_severity_to_int(v.severity::TEXT)), 0),
        0.0
    ) * (0.8 + asset_crit * 0.04)  -- scale by criticality (1→0.84x … 5→1.0x)
    INTO result
    FROM vulnerabilities v
    WHERE v.asset_id = asset_uuid;

    RETURN GREATEST(0.0, LEAST(100.0, COALESCE(result, 0.0)));
END;
$$ LANGUAGE plpgsql STABLE;

-- Full statistics for an engagement, returned as a single row
CREATE OR REPLACE FUNCTION get_engagement_stats(eng_id UUID)
RETURNS TABLE (
    engagement_id       UUID,
    engagement_name     VARCHAR,
    client_name         VARCHAR,
    operator            VARCHAR,
    status              engagement_status,
    scan_count          BIGINT,
    asset_count         BIGINT,
    port_count          BIGINT,
    total_vulns         BIGINT,
    critical_count      BIGINT,
    high_count          BIGINT,
    medium_count        BIGINT,
    low_count           BIGINT,
    info_count          BIGINT,
    exploitable_count   BIGINT,
    kev_count           BIGINT,
    confirmed_count     BIGINT,
    credential_count    BIGINT,
    secret_count        BIGINT,
    report_count        BIGINT,
    avg_risk_score      FLOAT,
    max_risk_score      FLOAT,
    scope_entries       BIGINT,
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        e.id,
        e.name,
        e.client_name,
        e.operator,
        e.status,
        COUNT(DISTINCT s.id),
        COUNT(DISTINCT a.id),
        COUNT(DISTINCT p.id),
        COUNT(DISTINCT v.id),
        COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical'),
        COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'high'),
        COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'medium'),
        COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'low'),
        COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'info'),
        COUNT(DISTINCT v.id) FILTER (WHERE v.exploit_available = TRUE),
        COUNT(DISTINCT v.id) FILTER (WHERE v.in_kev = TRUE),
        COUNT(DISTINCT val.id) FILTER (WHERE val.result = 'confirmed'),
        COUNT(DISTINCT c.id),
        COUNT(DISTINCT sec.id),
        COUNT(DISTINCT r.id),
        ROUND(AVG(v.risk_score)::NUMERIC, 2)::FLOAT,
        MAX(v.risk_score),
        COUNT(DISTINCT es.id),
        e.created_at,
        e.updated_at
    FROM engagements e
    LEFT JOIN engagement_scope es ON es.engagement_id = e.id
    LEFT JOIN reports r ON r.engagement_id = e.id
    LEFT JOIN scans s ON s.id = r.scan_id
    LEFT JOIN assets a ON a.scan_id = s.id
    LEFT JOIN ports p ON p.asset_id = a.id
    LEFT JOIN vulnerabilities v ON v.scan_id = s.id
    LEFT JOIN validations val ON val.vuln_id = v.id
    LEFT JOIN credentials c ON c.scan_id = s.id
    LEFT JOIN secrets sec ON sec.scan_id = s.id
    WHERE e.id = eng_id
    GROUP BY e.id, e.name, e.client_name, e.operator,
             e.status, e.created_at, e.updated_at;
END;
$$ LANGUAGE plpgsql STABLE;

-- Trigger function: insert audit record when a new vulnerability is created
CREATE OR REPLACE FUNCTION fn_audit_vuln_insert()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (actor, action, resource_type, resource_id, details)
    VALUES (
        COALESCE(current_setting('app.current_user', TRUE), 'system'),
        'created',
        'vulnerability',
        NEW.id::TEXT,
        jsonb_build_object(
            'cve_id',    NEW.cve_id,
            'severity',  NEW.severity,
            'title',     NEW.title,
            'asset_id',  NEW.asset_id,
            'scan_id',   NEW.scan_id,
            'risk_score', NEW.risk_score
        )
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- TRIGGERS
-- ============================================================

-- Preserved from v1: auto-update scans.updated_at
CREATE TRIGGER trg_scans_updated
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- New: auto-update assets.updated_at
CREATE TRIGGER trg_assets_updated
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- New: auto-update engagements.updated_at
CREATE TRIGGER trg_engagements_updated
    BEFORE UPDATE ON engagements
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- New: auto-update operator_notes.updated_at
CREATE TRIGGER trg_operator_notes_updated
    BEFORE UPDATE ON operator_notes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- New: audit log on vulnerability insert
CREATE TRIGGER trg_audit_vulns
    AFTER INSERT ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION fn_audit_vuln_insert();

-- ============================================================
-- HEAVEN — PostgreSQL Database Schema
-- Automated Vulnerability Scanner & Risk Triage Platform
-- ============================================================

-- ============================================================
-- RESET SCHEMA FOR IDEMPOTENCY
-- ============================================================
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- fuzzy text search

-- ============================================================
-- ENUM TYPES
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
-- CORE TABLES
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

-- Discovered assets
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
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,

    CONSTRAINT uq_asset_type_value UNIQUE (asset_type, value)
);

CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_value ON assets USING gin (value gin_trgm_ops);
CREATE INDEX idx_assets_honeypot ON assets(is_honeypot) WHERE is_honeypot = TRUE;

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
-- VIEWS
-- ============================================================

-- Dashboard summary view
CREATE OR REPLACE VIEW dashboard_summary AS
SELECT
    (SELECT COUNT(*) FROM scans WHERE status = 'completed') AS total_scans,
    (SELECT COUNT(*) FROM assets WHERE is_honeypot = FALSE) AS total_assets,
    (SELECT COUNT(*) FROM vulnerabilities) AS total_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical') AS critical_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high') AS high_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium') AS medium_vulns,
    (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low') AS low_vulns,
    (SELECT COUNT(*) FROM validations WHERE result = 'confirmed') AS confirmed_vulns,
    (SELECT COUNT(*) FROM secrets) AS total_secrets,
    (SELECT AVG(risk_score) FROM vulnerabilities WHERE risk_score IS NOT NULL) AS avg_risk_score;

-- Top risks view
CREATE OR REPLACE VIEW top_risks AS
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
    a.value AS asset_value,
    a.is_honeypot,
    val.result AS validation_result,
    val.confidence AS validation_confidence
FROM vulnerabilities v
JOIN assets a ON v.asset_id = a.id
LEFT JOIN LATERAL (
    SELECT result, confidence
    FROM validations
    WHERE vuln_id = v.id
    ORDER BY validated_at DESC
    LIMIT 1
) val ON TRUE
WHERE a.is_honeypot = FALSE
ORDER BY v.risk_score DESC NULLS LAST
LIMIT 100;

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scans_updated
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

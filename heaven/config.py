"""
HEAVEN — Global Configuration Module
Configuration with environment variable overrides and cross-platform support.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class ScanMode(str, Enum):
    FULL = "full"
    NETWORK = "network"
    WEB = "web"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    DEVSECOPS = "devsecops"
    AD = "ad"
    IOT = "iot"
    API = "api"
    CONTAINER = "container"
    EMAIL = "email"
    CI = "ci"


class Platform(str, Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"


def detect_platform() -> Platform:
    """Detect the current operating system."""
    if sys.platform.startswith("linux"):
        return Platform.LINUX
    elif sys.platform == "darwin":
        return Platform.MACOS
    elif sys.platform in ("win32", "cygwin"):
        return Platform.WINDOWS
    return Platform.LINUX


def _env(key: str, default: Any = None, cast: type = str) -> Any:
    """Read environment variable with type casting."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        if cast is bool:
            return val.lower() in ("1", "true", "yes")
        return cast(val)
    except (ValueError, TypeError):
        return default


# Track whether secrets were auto-generated so we can warn loudly
_GENERATED_SECRETS: list[str] = []


def _resolve_secret(env_key: str, label: str, fallback_generator=None) -> str:
    """
    Resolve a secret from env. If missing and a generator is provided, generate one
    and record that we did so (for logging at startup).
    """
    val = os.environ.get(env_key, "").strip()
    if val:
        return val
    if fallback_generator:
        generated = fallback_generator()
        _GENERATED_SECRETS.append(env_key)
        return generated
    return ""


@dataclass
class DatabaseConfig:
    """PostgreSQL connection configuration."""
    host: str = ""
    port: int = 5432
    name: str = "heaven"
    user: str = "heaven"
    password: str = ""

    def __post_init__(self):
        self.host = _env("HEAVEN_DB_HOST", self.host or "localhost")
        self.port = _env("HEAVEN_DB_PORT", self.port, int)
        self.name = _env("HEAVEN_DB_NAME", self.name)
        self.user = _env("HEAVEN_DB_USER", self.user)
        # No more hardcoded "heaven_secret" default — generate or require
        self.password = _resolve_secret(
            "HEAVEN_DB_PASSWORD", "DB password",
            fallback_generator=lambda: secrets.token_urlsafe(24),
        )

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def async_dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass
class ScannerConfig:
    """Scanner concurrency and timeout configuration."""
    net_concurrency: int = 500
    net_timeout: float = 2.0
    net_port_range: str = "1-65535"
    web_concurrency: int = 100
    web_timeout: float = 10.0
    web_max_depth: int = 5
    web_max_pages: int = 500
    cloud_concurrency: int = 50
    cloud_timeout: float = 30.0
    wireless_interface: str = "wlan0"

    def __post_init__(self):
        self.net_concurrency = _env("HEAVEN_NET_CONCURRENCY", self.net_concurrency, int)
        self.net_timeout = _env("HEAVEN_NET_TIMEOUT", self.net_timeout, float)
        self.net_port_range = _env("HEAVEN_NET_PORTS", self.net_port_range)
        self.web_concurrency = _env("HEAVEN_WEB_CONCURRENCY", self.web_concurrency, int)
        self.web_timeout = _env("HEAVEN_WEB_TIMEOUT", self.web_timeout, float)
        self.web_max_depth = _env("HEAVEN_WEB_DEPTH", self.web_max_depth, int)
        self.web_max_pages = _env("HEAVEN_WEB_MAX_PAGES", self.web_max_pages, int)
        self.cloud_concurrency = _env("HEAVEN_CLOUD_CONCURRENCY", self.cloud_concurrency, int)
        self.wireless_interface = _env("HEAVEN_WLAN_IFACE", self.wireless_interface)


@dataclass
class MLConfig:
    """ML risk model configuration."""
    model_path: Path = field(default_factory=lambda: Path("models/risk_model_v2.joblib"))
    retrain_threshold: int = 1000
    confidence_min: float = 0.6

    def __post_init__(self):
        mp = _env("HEAVEN_ML_MODEL", None)
        if mp:
            self.model_path = Path(mp)
        self.retrain_threshold = _env("HEAVEN_ML_RETRAIN_THRESHOLD", self.retrain_threshold, int)
        self.confidence_min = _env("HEAVEN_ML_CONFIDENCE_MIN", self.confidence_min, float)


@dataclass
class APIConfig:
    """API server and external service configuration."""
    host: str = "127.0.0.1"  # Was 0.0.0.0 — secure default
    port: int = 8443
    nvd_api_key: Optional[str] = None
    nvd_rate_limit: float = 6.0
    epss_enabled: bool = True

    def __post_init__(self):
        self.host = _env("HEAVEN_API_HOST", self.host)
        self.port = _env("HEAVEN_API_PORT", self.port, int)
        self.nvd_api_key = _env("HEAVEN_NVD_API_KEY", self.nvd_api_key)
        self.nvd_rate_limit = _env("HEAVEN_NVD_RATE_LIMIT", self.nvd_rate_limit, float)
        self.epss_enabled = _env("HEAVEN_EPSS_ENABLED", self.epss_enabled, bool)


@dataclass
class ADConfig:
    """Active Directory scanning configuration."""
    domain: str = ""
    dc_host: str = ""
    username: str = ""
    password: str = ""
    use_ssl: bool = False

    def __post_init__(self):
        self.domain = _env("HEAVEN_AD_DOMAIN", self.domain)
        self.dc_host = _env("HEAVEN_AD_DC", self.dc_host)
        self.username = _env("HEAVEN_AD_USER", self.username)
        self.password = _env("HEAVEN_AD_PASSWORD", self.password)
        self.use_ssl = _env("HEAVEN_AD_SSL", self.use_ssl, bool)


@dataclass
class MITREConfig:
    """MITRE ATT&CK integration configuration."""
    taxii_url: str = "https://cti-taxii.mitre.org"
    cache_ttl_hours: int = 24
    offline_mode: bool = False
    navigator_export: bool = True
    cache_dir: Path = field(default_factory=lambda: Path("data/mitre_cache"))

    def __post_init__(self):
        self.taxii_url = _env("HEAVEN_MITRE_TAXII_URL", self.taxii_url)
        self.cache_ttl_hours = _env("HEAVEN_MITRE_CACHE_TTL", self.cache_ttl_hours, int)
        self.offline_mode = _env("HEAVEN_MITRE_OFFLINE", self.offline_mode, bool)


@dataclass
class SecurityConfig:
    """Tool security hardening configuration."""
    vault_path: Path = field(default_factory=lambda: Path("data/vault.enc"))
    audit_log_dir: Path = field(default_factory=lambda: Path("data/audit"))
    rbac_enabled: bool = True
    rate_limit_rpm: int = 100
    allow_localhost_scan: bool = False
    allow_private_scan: bool = True
    auto_lock_seconds: int = 900
    # Newline/comma-separated allowlist of target IPs/hosts/URLs operator has authorized
    authorized_scope: str = ""

    def __post_init__(self):
        vp = _env("HEAVEN_VAULT_PATH", None)
        if vp:
            self.vault_path = Path(vp)
        self.rbac_enabled = _env("HEAVEN_RBAC_ENABLED", self.rbac_enabled, bool)
        self.rate_limit_rpm = _env("HEAVEN_RATE_LIMIT", self.rate_limit_rpm, int)
        self.allow_localhost_scan = _env("HEAVEN_ALLOW_LOCALHOST", self.allow_localhost_scan, bool)
        self.allow_private_scan = _env("HEAVEN_ALLOW_PRIVATE", self.allow_private_scan, bool)
        self.authorized_scope = _env("HEAVEN_AUTHORIZED_SCOPE", self.authorized_scope)


@dataclass
class ContainerConfig:
    """Container/Kubernetes scanning configuration."""
    docker_socket: str = "/var/run/docker.sock"
    kubeconfig_path: str = ""
    k8s_api_port: int = 6443

    def __post_init__(self):
        self.docker_socket = _env("HEAVEN_DOCKER_SOCKET", self.docker_socket)
        self.kubeconfig_path = _env("HEAVEN_KUBECONFIG", self.kubeconfig_path)
        self.k8s_api_port = _env("HEAVEN_K8S_PORT", self.k8s_api_port, int)


@dataclass
class HeavenConfig:
    """Master configuration aggregating all sub-configs."""
    platform: Platform = field(default_factory=detect_platform)
    debug: bool = False
    log_level: str = "INFO"
    data_dir: Path = field(default_factory=lambda: Path("data"))
    scan_mode: ScanMode = ScanMode.FULL
    honeypot_threshold: float = 0.7

    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    api: APIConfig = field(default_factory=APIConfig)
    ad: ADConfig = field(default_factory=ADConfig)
    mitre: MITREConfig = field(default_factory=MITREConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    container: ContainerConfig = field(default_factory=ContainerConfig)

    def __post_init__(self):
        self.debug = _env("HEAVEN_DEBUG", self.debug, bool)
        self.log_level = _env("HEAVEN_LOG_LEVEL", self.log_level)
        dd = _env("HEAVEN_DATA_DIR", None)
        if dd:
            self.data_dir = Path(dd)
        sm = _env("HEAVEN_SCAN_MODE", None)
        if sm:
            try:
                self.scan_mode = ScanMode(sm)
            except ValueError:
                pass
        self.honeypot_threshold = _env("HEAVEN_HONEYPOT_THRESHOLD", self.honeypot_threshold, float)

    def ensure_dirs(self) -> None:
        """Create required data directories."""
        for d in (self.data_dir, self.data_dir / "scans", self.data_dir / "reports",
                  self.data_dir / "models", self.data_dir / "cache",
                  self.security.audit_log_dir):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass


_config: Optional[HeavenConfig] = None


def get_config() -> HeavenConfig:
    """Get or create the global configuration singleton."""
    global _config
    if _config is None:
        _config = HeavenConfig()
        _config.ensure_dirs()
        _warn_about_generated_secrets()
    return _config


def reload_config() -> HeavenConfig:
    """Force reload configuration from environment."""
    global _config
    _GENERATED_SECRETS.clear()
    _config = HeavenConfig()
    _config.ensure_dirs()
    _warn_about_generated_secrets()
    return _config


def _warn_about_generated_secrets() -> None:
    if not _GENERATED_SECRETS:
        return
    try:
        from heaven.utils.logger import get_logger
        log = get_logger("config")
        for k in _GENERATED_SECRETS:
            log.warning(f"{k} not set — generated a random value for this run only. Set it explicitly for persistent installs.")
    except Exception:
        for k in _GENERATED_SECRETS:
            print(f"[heaven config] WARN: {k} not set — random value generated for this run only.")

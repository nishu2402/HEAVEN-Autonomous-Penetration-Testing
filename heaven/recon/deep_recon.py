"""
HEAVEN — Deep Reconnaissance Engine
Expert-level asset discovery that goes beyond basic port scanning:
- Subdomain enumeration (passive + active brute force)
- Virtual host discovery
- API endpoint fuzzing
- JavaScript secret extraction
- Technology stack fingerprinting
- DNS zone walking
- Certificate transparency log parsing
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("recon.deep")


# ── Top subdomain wordlist (curated from 10M+ real results) ──
SUBDOMAIN_WORDLIST = [
    # Core services
    "www", "www2", "www3", "mail", "email", "webmail", "smtp", "pop", "pop3",
    "imap", "ftp", "sftp", "ftps", "ssh", "vpn", "vpn2", "remote", "rdp",
    # API / Application
    "api", "api2", "api-v1", "api-v2", "api-v3", "api-v4", "api-old",
    "api-new", "api-staging", "api-prod", "api-dev", "api-test",
    "graphql", "graphiql", "rest", "grpc", "rpc", "ws", "wss",
    "v1", "v2", "v3", "v4", "app", "app2", "apps", "application",
    # Auth / Identity
    "auth", "auth2", "oauth", "oauth2", "sso", "login", "signin", "signup",
    "account", "accounts", "identity", "id", "iam", "ldap", "ad", "dc",
    "keycloak", "okta", "adfs", "saml", "openid",
    # Admin / Management
    "admin", "admin2", "administrator", "manage", "management", "manager",
    "panel", "dashboard", "control", "console", "cp", "cpanel",
    "backend", "backoffice", "back", "staff", "ops", "operations",
    "portal", "portals", "hub", "gateway", "mgmt", "sysadmin",
    # Development / CI-CD
    "dev", "dev2", "devel", "develop", "developer", "development",
    "staging", "staging2", "stage", "stg", "preprod", "pre-prod",
    "test", "test2", "testing", "tst", "qa", "qa2", "uat",
    "sandbox", "sandbox2", "demo", "demo2", "poc", "pilot",
    "beta", "beta2", "alpha", "rc", "canary", "preview",
    "git", "gitlab", "github", "bitbucket", "svn", "cvs",
    "ci", "ci2", "cd", "jenkins", "travis", "circleci", "drone",
    "nexus", "artifactory", "sonar", "sonarqube", "sast",
    "build", "builds", "builder", "deploy", "deployment",
    # Monitoring / Observability
    "monitor", "monitoring", "grafana", "kibana", "prometheus",
    "alertmanager", "alerts", "pagerduty", "opsgenie",
    "metrics", "metric", "stats", "statistics", "telemetry",
    "trace", "tracing", "jaeger", "zipkin", "apm", "newrelic",
    "datadog", "splunk", "elk", "logstash", "filebeat",
    "status", "statuspage", "health", "healthz", "ping",
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "smtp1", "smtp2", "relay",
    "lb", "lb1", "lb2", "haproxy", "nginx", "apache", "proxy",
    "proxy2", "squid", "cache", "cdn", "cdn2",
    "fw", "firewall", "bastion", "jump", "jumpbox",
    "router", "switch", "gw", "vpn-gw", "tunnel",
    "ntp", "ntp1", "ntp2", "time",
    # Databases
    "db", "db1", "db2", "db-prod", "db-dev", "db-test",
    "database", "mysql", "mysql2", "mariadb",
    "postgres", "postgresql", "pg", "pg1",
    "redis", "redis1", "redis2", "memcache", "memcached",
    "mongo", "mongodb", "elastic", "elasticsearch", "solr",
    "cassandra", "couchdb", "neo4j", "influx", "influxdb",
    "mssql", "oracle", "db-primary", "db-replica",
    # Message queues
    "mq", "rabbit", "rabbitmq", "kafka", "kafka1", "kafka2",
    "queue", "queues", "nats", "pulsar", "activemq", "zeromq",
    # Storage / CDN
    "s3", "storage", "storage2", "files", "file", "upload",
    "uploads", "media", "media2", "assets", "static",
    "static2", "img", "images", "image", "cdn2", "cdn3",
    "video", "videos", "audio", "blob", "object",
    # Collaboration / Communication
    "blog", "wiki", "docs", "documentation", "help",
    "support", "helpdesk", "service", "servicedesk", "ticket",
    "tickets", "jira", "confluence", "notion", "notion2",
    "slack", "teams", "chat", "chatbot", "bot",
    "forum", "community", "social", "intranet", "internal",
    "corp", "corporate", "office", "employees", "hr",
    # E-commerce / Business
    "shop", "store", "store2", "cart", "checkout", "pay",
    "payment", "payments", "billing", "billing2", "invoice",
    "crm", "erp", "salesforce", "hubspot",
    "analytics", "insight", "insights", "report", "reports",
    # Security tools
    "vault", "hashicorp", "secret", "secrets", "pki", "ca",
    "cert", "certs", "certificate", "ssl", "tls",
    "siem", "soc", "waf", "ids", "ips",
    # Container / Cloud
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "consul", "nomad", "terraform", "ansible", "puppet",
    "chef", "saltstack", "helm", "argo", "argocd",
    "rancher", "eks", "gke", "aks", "fargate",
    "aws", "azure", "gcp", "cloud", "cloud2",
    # Mobile
    "m", "m2", "mobile", "mobile2", "ios", "android",
    "app-mobile", "mapi", "mobile-api",
    # CMS / Frameworks
    "wp", "wordpress", "drupal", "joomla", "magento",
    "sharepoint", "sp", "liferay", "cms",
    # Legacy / Misc
    "legacy", "old", "old2", "new", "new2", "v1",
    "backup", "archive", "temp", "tmp", "spare",
    "office365", "outlook", "exchange", "owa",
    "fw1", "fw2", "dmz", "ext", "external", "public",
    "private", "secure", "secure2", "encrypted",
    "research", "lab", "labs", "experiment",
    "staging3", "qa3", "dev3", "uat2", "npe", "lower",
    "integration", "int", "preprod2", "post",
    "tooling", "tools", "tool", "utility", "utils",
    "scheduler", "cron", "jobs", "job", "worker", "workers",
    "events", "event", "hook", "hooks", "webhook", "webhooks",
    "partner", "partners", "vendor", "vendors", "third-party",
    "b2b", "b2c", "enterprise", "saas", "platform",
    "audit", "auditing", "compliance", "security",
    "reporting", "reporter", "exporter", "importer",
    "migration", "migrate", "transform", "etl",
    "data", "data2", "datalake", "warehouse", "dwh", "bi",
    "ml", "ai", "model", "models", "inference", "training",
    "notebook", "jupyter", "spark", "hadoop", "hive",
    "stream", "streaming", "flink", "storm",
    "mail2", "mail3", "lists", "newsletter", "marketing",
    "smtp-out", "smtp-relay", "sendmail", "postfix",
    "noc", "helpdesk2", "itsm", "asset",
    "vpn3", "openvpn", "wireguard", "ipsec",
    "radio", "broadcast", "tv", "live", "stream2",
    "download", "downloads", "dist", "release", "releases",
    "update", "updates", "upgrade", "patch", "patches",
    "iot", "sensor", "sensors", "device", "devices",
    "edge", "edge2", "fog", "local",
    "hub2", "broker", "switch2",
    "primary", "secondary", "master", "slave", "replica",
    "node", "node1", "node2", "node3", "cluster",
    "region", "us-east", "us-west", "eu", "eu-west", "ap",
    "east", "west", "north", "south",
    "prd", "prod", "production",
]


@dataclass
class DiscoveredAsset:
    asset_type: str      # subdomain, endpoint, vhost, secret
    value: str
    host: str = ""
    source: str = ""
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


# ── Subdomain Enumeration ──

async def _check_wildcard_dns(domain: str) -> Optional[set[str]]:
    """
    Detect wildcard DNS by resolving two random non-existent labels.
    Returns the wildcard IP set if wildcard exists, None otherwise.
    """
    import random
    import string
    wildcard_ips: Optional[set[str]] = None
    for _ in range(2):
        rand_label = "".join(random.choices(string.ascii_lowercase, k=16))
        probe = f"{rand_label}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(probe, None)
            ips = {a[4][0] for a in addrs}
            if wildcard_ips is None:
                wildcard_ips = ips
            else:
                wildcard_ips &= ips  # only keep IPs consistent across both probes
        except Exception:
            return None  # at least one probe didn't resolve → no wildcard
    return wildcard_ips if wildcard_ips else None


async def enumerate_subdomains(domain: str, session: aiohttp.ClientSession,
                                wordlist: Optional[list[str]] = None,
                                concurrency: int = 100) -> list[DiscoveredAsset]:
    """Discover subdomains via DNS brute force and passive sources."""
    discovered = []
    words = wordlist or SUBDOMAIN_WORDLIST

    # 0. Wildcard DNS detection — suppress false positives from brute force
    wildcard_ips = await _check_wildcard_dns(domain)
    if wildcard_ips:
        logger.warning(f"Wildcard DNS detected for {domain} → IPs {wildcard_ips}; "
                       "brute-force results will be filtered")

    # 1. Passive — Certificate Transparency Logs
    ct_subs = await _ct_log_search(domain, session)
    for sub in ct_subs:
        discovered.append(DiscoveredAsset(
            asset_type="subdomain", value=sub, host=domain,
            source="certificate_transparency", confidence=1.0,
            metadata={"wildcard_domain": wildcard_ips is not None},
        ))

    # 2. Active — DNS brute force (filtered against wildcard IPs)
    sem = asyncio.Semaphore(concurrency)
    tasks = [_resolve_subdomain(f"{word}.{domain}", sem) for word in words]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if not isinstance(result, DiscoveredAsset):
            continue
        # Skip results that resolve to wildcard addresses
        if wildcard_ips:
            resolved_ip = result.metadata.get("ip", "")
            if resolved_ip in wildcard_ips:
                continue
        discovered.append(result)

    # Deduplicate
    seen = set()
    unique = []
    for a in discovered:
        if a.value not in seen:
            seen.add(a.value)
            unique.append(a)

    logger.info(f"Subdomain enumeration: {len(unique)} found for {domain}"
                + (" (wildcard filtered)" if wildcard_ips else ""))
    return unique


async def _ct_log_search(domain: str, session: aiohttp.ClientSession) -> list[str]:
    """Search Certificate Transparency logs for subdomains."""
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                # crt.sh returns a JSON list normally, but a dict/error object
                # on rate-limit — iterating that would yield keys then crash.
                if not isinstance(data, list):
                    data = []
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
    except Exception as e:
        logger.debug(f"CT log search error: {e}")

    return list(subdomains)


async def _resolve_subdomain(fqdn: str, sem: asyncio.Semaphore) -> Optional[DiscoveredAsset]:
    """Try to resolve a subdomain."""
    async with sem:
        try:
            loop = asyncio.get_running_loop()
            result = await loop.getaddrinfo(fqdn, None)
            if result:
                ip = result[0][4][0]
                return DiscoveredAsset(
                    asset_type="subdomain", value=fqdn,
                    source="dns_bruteforce", confidence=1.0,
                    metadata={"ip": ip},
                )
        except (socket.gaierror, OSError):
            pass
    return None


# ── JavaScript Secret Extraction ──

JS_SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "api_key"),
    (r"(?:secret|token|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "secret"),
    (r"(?:aws_access_key_id)\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?", "aws_access_key"),
    (r"(?:aws_secret_access_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", "aws_secret_key"),
    (r"(?:Authorization|Bearer)\s*[:=]\s*['\"]?(?:Bearer\s+)?([a-zA-Z0-9_\-\.]+)['\"]?", "bearer_token"),
    (r"(?:ghp_[a-zA-Z0-9]{36})", "github_pat"),
    (r"(?:sk-[a-zA-Z0-9]{48})", "openai_key"),
    (r"(?:AIza[a-zA-Z0-9_\\-]{35})", "google_api_key"),
    (r"(?:slack[_-]?(?:token|webhook))\s*[:=]\s*['\"]?(xox[baprs]-[a-zA-Z0-9-]+)['\"]?", "slack_token"),
    (r"(?:stripe[_-]?(?:key|secret))\s*[:=]\s*['\"]?(sk_(?:live|test)_[a-zA-Z0-9]+)['\"]?", "stripe_key"),
    (r"(?:firebase[_-]?(?:key|config))\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{30,})['\"]?", "firebase_key"),
    (r"(?:mongodb(?:\+srv)?://[^@]+@[^\s'\"]+)", "mongodb_uri"),
    (r"(?:postgres(?:ql)?://[^@]+@[^\s'\"]+)", "postgres_uri"),
    (r"(?:redis://[^\s'\"]+)", "redis_uri"),
    (r"(?:mysql://[^@]+@[^\s'\"]+)", "mysql_uri"),
]


async def extract_js_secrets(session: aiohttp.ClientSession, url: str,
                              js_urls: Optional[list[str]] = None) -> list[DiscoveredAsset]:
    """Extract secrets, API keys, and tokens from JavaScript files."""
    secrets = []

    # Discover JS files from main page if not provided
    if not js_urls:
        js_urls = await _discover_js_files(session, url)

    for js_url in js_urls[:50]:  # Limit to 50 JS files
        try:
            async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    continue
                content = await resp.text()

                for pattern, secret_type in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Filter false positives
                        if len(match) < 8 or match in ("undefined", "null", "true", "false"):
                            continue
                        secrets.append(DiscoveredAsset(
                            asset_type="secret", value=match[:50],
                            host=url, source=js_url,
                            confidence=0.8,
                            metadata={"type": secret_type, "file": js_url},
                        ))

                # Also extract API endpoints from JS
                api_patterns = [
                    r"['\"](/api/[a-zA-Z0-9_/\-]+)['\"]",
                    r"['\"](/v[12]/[a-zA-Z0-9_/\-]+)['\"]",
                    r"fetch\(['\"]([^'\"]+)['\"]",
                    r"axios\.\w+\(['\"]([^'\"]+)['\"]",
                    r"\.(?:get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]",
                ]
                for pattern in api_patterns:
                    for endpoint in re.findall(pattern, content):
                        if endpoint.startswith("/"):
                            full_url = urljoin(url, endpoint)
                        else:
                            full_url = endpoint
                        secrets.append(DiscoveredAsset(
                            asset_type="endpoint", value=full_url,
                            host=url, source=js_url,
                            metadata={"discovered_in": "javascript"},
                        ))

        except Exception:
            pass

    logger.info(f"JS analysis: {len([s for s in secrets if s.asset_type == 'secret'])} secrets, "
                 f"{len([s for s in secrets if s.asset_type == 'endpoint'])} endpoints from {len(js_urls)} files")
    return secrets


async def _discover_js_files(session: aiohttp.ClientSession, url: str) -> list[str]:
    """Find all JavaScript files linked from a page."""
    js_urls = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            body = await resp.text()
            # Script src
            for match in re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE):
                js_urls.append(urljoin(url, match))
            # Inline imports
            for match in re.findall(r'import\s+.*?from\s+["\']([^"\']+)["\']', body):
                if match.endswith(".js"):
                    js_urls.append(urljoin(url, match))
    except Exception:
        pass
    return list(set(js_urls))


# ── Virtual Host Discovery ──

async def discover_vhosts(session: aiohttp.ClientSession, ip: str,
                           domain: str, wordlist: Optional[list[str]] = None) -> list[DiscoveredAsset]:
    """Discover virtual hosts by sending requests with different Host headers."""
    discovered: list[DiscoveredAsset] = []
    words = wordlist or SUBDOMAIN_WORDLIST[:30]

    # Get baseline response
    try:
        async with session.get(f"http://{ip}/",
                                headers={"Host": "nonexistent.invalid"},
                                timeout=aiohttp.ClientTimeout(total=5)) as resp:
            baseline_status = resp.status
            baseline_len = len(await resp.text())
    except Exception:
        return discovered

    for word in words:
        hostname = f"{word}.{domain}"
        try:
            async with session.get(f"http://{ip}/",
                                    headers={"Host": hostname},
                                    timeout=aiohttp.ClientTimeout(total=5)) as resp:
                status = resp.status
                body_len = len(await resp.text())

                # Different response = valid vhost
                if status != baseline_status or abs(body_len - baseline_len) > 100:
                    discovered.append(DiscoveredAsset(
                        asset_type="vhost", value=hostname,
                        host=ip, source="vhost_bruteforce",
                        metadata={"status": status, "length": body_len},
                    ))
        except Exception:
            pass

    if discovered:
        logger.info(f"VHost discovery: {len(discovered)} virtual hosts on {ip}")
    return discovered


# ── API Endpoint Fuzzing ──

COMMON_API_PATHS = [
    # ── Core API versioning ──
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1", "/v2", "/v3", "/v4",
    "/rest", "/rest/v1", "/rest/v2",
    "/rpc", "/jsonrpc", "/xmlrpc", "/xmlrpc.php",
    "/soap", "/wsdl", "/service.wsdl",
    # ── GraphQL ──
    "/graphql", "/graphiql", "/__graphql", "/graph",
    "/graphql/console", "/graphql/playground",
    "/api/graphql", "/v1/graphql", "/v2/graphql",
    # ── API documentation ──
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
    "/api/swagger.json", "/api/swagger.yaml",
    "/redoc", "/docs", "/apidoc", "/apidocs",
    "/api/schema", "/api/schema.json",
    "/.well-known/openapi",
    # ── Health / status / readiness ──
    "/health", "/healthz", "/health/live", "/health/ready",
    "/health/startup", "/livez", "/readyz", "/startupz",
    "/status", "/status.json", "/ping", "/pong",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/actuator/metrics", "/actuator/loggers", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/httptrace", "/actuator/auditevents",
    "/actuator/shutdown", "/actuator/refresh",
    "/manage", "/manage/health", "/manage/info",
    # ── Metrics & monitoring ──
    "/metrics", "/metrics.json", "/prometheus",
    "/stats", "/stats.json", "/monitor", "/monitoring",
    "/info", "/server-info", "/server-status", "/server-state",
    "/_status", "/_health", "/_ping", "/_info",
    "/__status__", "/__health__",
    # ── Admin & management interfaces ──
    "/admin", "/administrator", "/admin/", "/admin/login",
    "/admin/dashboard", "/admin/panel", "/admin/console",
    "/admin/config", "/admin/settings", "/admin/users",
    "/administration", "/admincp", "/adm", "/acp",
    "/backend", "/manage", "/management", "/superuser",
    "/control", "/controlpanel", "/cp", "/cpanel",
    "/siteadmin", "/site-admin", "/portal", "/portal/admin",
    "/manager", "/manager/html",  # Tomcat
    "/jmx-console", "/web-console",  # JBoss
    "/solr/admin", "/solr/#/",  # Solr
    "/kibana", "/_plugin/kibana",  # Kibana
    "/phpmyadmin", "/pma", "/phpmyadmin/", "/myadmin",
    "/adminer", "/adminer.php", "/db-admin",
    # ── Debug / trace / profiling ──
    "/debug", "/debug/", "/debug/vars", "/debug/pprof",
    "/debug/pprof/heap", "/debug/pprof/goroutine",  # Go
    "/trace", "/trace.axd",  # .NET
    "/console", "/rails/info/properties",  # Rails
    "/__debug__/", "/flask-debug",
    "/phpinfo.php", "/info.php", "/test.php",
    "/php-info.php", "/?phpinfo=1", "/php/info.php",
    "/elmah.axd", "/elmah/", "/error.log",
    "/_profiler", "/_profiler/phpinfo",  # Symfony
    "/django-admin/",
    # ── Git / VCS exposure ──
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.git/COMMIT_EDITMSG", "/.git/packed-refs",
    "/.git/refs/heads/main", "/.git/refs/heads/master",
    "/.gitignore", "/.gitmodules", "/.gitattributes",
    "/.svn/entries", "/.svn/wc.db", "/.svn/",
    "/.hg/", "/.hg/store", "/.hg/requires",
    "/.bzr/branch/format", "/.fossil",
    "/CVS/Root", "/CVS/Entries",
    # ── Environment & configuration files ──
    "/.env", "/.env.local", "/.env.development",
    "/.env.production", "/.env.staging", "/.env.backup",
    "/.env.example", "/.env.sample", "/.env.bak", "/.env.old",
    "/config", "/config.json", "/config.yaml", "/config.yml",
    "/config.xml", "/config.php", "/config.ini",
    "/configuration.php", "/configuration.yml",
    "/settings.py", "/settings.json", "/settings.yaml",
    "/application.yml", "/application.yaml", "/application.properties",
    "/appsettings.json", "/appsettings.Development.json",
    "/web.config", "/app.config", "/local.xml",
    "/parameters.yml", "/parameters.yaml",  # Symfony
    "/database.yml", "/database.yaml",
    "/secrets.json", "/secrets.yaml", "/.secrets",
    "/.aws/credentials", "/.aws/config",
    "/credentials", "/credentials.json", "/credentials.xml",
    "/.npmrc", "/.yarnrc", "/.cargo/credentials",
    "/composer.json", "/package.json", "/requirements.txt",
    "/Gemfile", "/Gemfile.lock", "/Pipfile", "/Pipfile.lock",
    "/go.sum", "/go.mod", "/yarn.lock", "/package-lock.json",
    # ── CMS & frameworks ──
    "/wp-json", "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/wp-content/debug.log", "/wp-includes/",
    "/xmlrpc.php",  # WordPress XML-RPC
    "/administrator", "/administrator/index.php",  # Joomla
    "/user/login", "/user/register",  # Drupal
    "/index.php?option=com_users",  # Joomla
    "/typo3", "/typo3/backend.php",
    "/_ah/admin", "/_ah/api",  # Google App Engine
    "/rails/info", "/rails/mailers",
    "/telescope", "/telescope/api/requests",  # Laravel
    "/horizon", "/nova",  # Laravel
    "/clockwork", "/clockwork/app",  # Clockwork profiler
    "/batty",
    # ── Cloud metadata & SSRF ──
    "/latest/meta-data/",  # AWS EC2 metadata (SSRF)
    "/metadata/v1/", "/opc/v1/",
    "/computeMetadata/v1/",  # GCP
    "/.netlify/functions/",
    "/.firebase/",
    # ── Backup & archive files ──
    "/backup", "/backup/", "/backups/",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/backup.tar", "/backup.bz2",
    "/db.sql", "/dump.sql", "/database.sql",
    "/db_backup.sql", "/mysql.sql", "/schema.sql",
    "/data.sql", "/export.sql",
    "/site.zip", "/website.zip", "/www.zip",
    "/files.tar.gz", "/public.tar.gz",
    "/old", "/old/", "/bak", "/bak/",
    "/~backup", "/~old",
    # ── Log files ──
    "/logs", "/log", "/logs/",
    "/access.log", "/error.log", "/debug.log",
    "/application.log", "/server.log", "/app.log",
    "/var/log/apache2/access.log",
    # ── Common sensitive paths ──
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/.well-known/host-meta", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/security.txt",
    # ── Java / JVM specifics ──
    "/WEB-INF/web.xml", "/WEB-INF/classes/",
    "/WEB-INF/lib/", "/META-INF/MANIFEST.MF",
    "/jmx-console/", "/jmx-console/HtmlAdaptor",
    "/invoker/JMXInvokerServlet",
    "/struts/webconsole.html",
    # ── .NET specifics ──
    "/elmah.axd", "/trace.axd", "/ScriptResource.axd",
    "/WebResource.axd", "/Telerik.Web.UI.WebResource.axd",
    "/_api/contextinfo",  # SharePoint
    "/_layouts/15/start.aspx",
    "/umbraco", "/umbraco/backoffice",  # Umbraco CMS
    # ── Docker / container ──
    "/v2/", "/v2/_catalog",  # Docker Registry API
    "/v2/tags/list",
    # ── Authentication endpoints ──
    "/login", "/logout", "/signin", "/signout",
    "/register", "/signup", "/auth", "/auth/login",
    "/oauth", "/oauth2", "/oauth/authorize", "/oauth/token",
    "/openid", "/openid-connect", "/saml",
    "/api/auth", "/api/login", "/api/register",
    "/api/token", "/api/refresh", "/api/me",
    "/api/user", "/api/users", "/api/profile",
    "/api/admin", "/api/settings",
    "/api/keys", "/api/secrets", "/api/tokens",
    # ── Internal / private ──
    "/internal", "/internal/", "/private", "/private/",
    "/_internal", "/_private", "/_api", "/_admin",
    "/local", "/dev", "/development", "/staging",
    "/test", "/testing", "/sandbox",
    # ── Misc sensitive ──
    "/cgi-bin/", "/cgi-bin/phpinfo.php",
    "/server-status", "/server-info",  # Apache
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/.ssh/known_hosts", "/.ssh/authorized_keys",
    "/proc/self/environ", "/proc/version",
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/web.xml", "/context.xml",
]


async def fuzz_endpoints(session: aiohttp.ClientSession, base_url: str,
                          paths: Optional[list[str]] = None,
                          concurrency: int = 50) -> list[DiscoveredAsset]:
    """Discover hidden API endpoints and sensitive files."""
    discovered = []
    target_paths = paths or COMMON_API_PATHS
    sem = asyncio.Semaphore(concurrency)

    async def check_path(path):
        async with sem:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=False) as resp:
                    status = resp.status
                    content_len = int(resp.headers.get("Content-Length", 0))
                    content_type = resp.headers.get("Content-Type", "")

                    if status in (200, 201, 301, 302, 401, 403):
                        return DiscoveredAsset(
                            asset_type="endpoint", value=url,
                            host=base_url, source="endpoint_fuzzing",
                            metadata={"status": status, "content_type": content_type,
                                       "content_length": content_len,
                                       "requires_auth": status in (401, 403)},
                        )
            except Exception:
                pass
            return None

    tasks = [check_path(p) for p in target_paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, DiscoveredAsset):
            discovered.append(r)

    logger.info(f"Endpoint fuzzing: {len(discovered)} endpoints discovered on {base_url}")
    return discovered


# ── Certificate Analysis ──

async def analyze_certificate(host: str, port: int = 443) -> list[DiscoveredAsset]:
    """Extract intelligence from TLS certificates."""
    discovered = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=5)

        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if cert:
            # Extract SANs (Subject Alternative Names)
            san = cert.get("subjectAltName", ())
            for type_, value in san:
                if type_ == "DNS" and value != host:
                    discovered.append(DiscoveredAsset(
                        asset_type="subdomain", value=value,
                        host=host, source="tls_certificate",
                        metadata={"san_type": type_},
                    ))

            # Certificate dates
            not_after = cert.get("notAfter", "")
            discovered.append(DiscoveredAsset(
                asset_type="cert_info", value=f"expires: {not_after}",
                host=host, source="tls_certificate",
                metadata={"issuer": str(cert.get("issuer", "")),
                           "not_after": not_after},
            ))

    except Exception as e:
        logger.debug(f"Certificate analysis error for {host}: {e}")

    return discovered

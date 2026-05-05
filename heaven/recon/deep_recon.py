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
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "blog", "shop", "store", "app", "portal", "secure", "vpn", "remote",
    "dashboard", "panel", "login", "auth", "sso", "oauth", "cdn", "assets",
    "static", "media", "img", "images", "video", "docs", "wiki", "help",
    "support", "status", "monitor", "grafana", "kibana", "jenkins", "ci",
    "cd", "git", "gitlab", "github", "bitbucket", "jira", "confluence",
    "slack", "teams", "chat", "internal", "intranet", "corp", "office",
    "webmail", "outlook", "exchange", "mx", "ns1", "ns2", "dns",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "solr", "mq", "rabbit", "kafka", "queue",
    "s3", "storage", "backup", "archive", "logs", "logging",
    "staging2", "preprod", "uat", "qa", "demo", "sandbox",
    "m", "mobile", "ios", "android",
    "api-v1", "api-v2", "api2", "graphql", "rest", "ws", "wss",
    "proxy", "gateway", "lb", "haproxy", "nginx", "apache",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "vault", "consul", "terraform", "ansible", "puppet",
    "prometheus", "alertmanager", "metrics", "trace", "jaeger",
    "legacy", "old", "new", "v2", "v3", "next",
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

async def enumerate_subdomains(domain: str, session: aiohttp.ClientSession,
                                wordlist: list[str] = None,
                                concurrency: int = 100) -> list[DiscoveredAsset]:
    """Discover subdomains via DNS brute force and passive sources."""
    discovered = []
    words = wordlist or SUBDOMAIN_WORDLIST

    # 1. Passive — Certificate Transparency Logs
    ct_subs = await _ct_log_search(domain, session)
    for sub in ct_subs:
        discovered.append(DiscoveredAsset(
            asset_type="subdomain", value=sub, host=domain,
            source="certificate_transparency", confidence=1.0,
        ))

    # 2. Active — DNS brute force
    sem = asyncio.Semaphore(concurrency)
    tasks = [_resolve_subdomain(f"{word}.{domain}", sem) for word in words]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, DiscoveredAsset):
            discovered.append(result)

    # Deduplicate
    seen = set()
    unique = []
    for a in discovered:
        if a.value not in seen:
            seen.add(a.value)
            unique.append(a)

    logger.info(f"Subdomain enumeration: {len(unique)} found for {domain}")
    return unique


async def _ct_log_search(domain: str, session: aiohttp.ClientSession) -> list[str]:
    """Search Certificate Transparency logs for subdomains."""
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
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
                              js_urls: list[str] = None) -> list[DiscoveredAsset]:
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
                           domain: str, wordlist: list[str] = None) -> list[DiscoveredAsset]:
    """Discover virtual hosts by sending requests with different Host headers."""
    discovered = []
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
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/__graphql",
    "/swagger", "/swagger.json", "/swagger-ui", "/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/.env", "/config", "/config.json", "/.git/config",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-json", "/wp-admin", "/wp-login.php",
    "/admin", "/administrator", "/panel", "/dashboard", "/console",
    "/debug", "/trace", "/status", "/health", "/healthz", "/ready",
    "/metrics", "/prometheus", "/actuator", "/actuator/health",
    "/info", "/server-info", "/server-status",
    "/.git/HEAD", "/.svn/entries", "/.hg/store",
    "/backup", "/backup.zip", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/test.php", "/info.php",
    "/elmah.axd", "/trace.axd",  # .NET
    "/WEB-INF/web.xml",  # Java
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]


async def fuzz_endpoints(session: aiohttp.ClientSession, base_url: str,
                          paths: list[str] = None,
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

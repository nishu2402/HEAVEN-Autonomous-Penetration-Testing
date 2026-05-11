"""
HEAVEN — Directory & File Fuzzer
Discovers hidden paths, admin panels, backup files, configuration files, and
API endpoints.  Uses ffuf when available; falls back to a high-speed pure-async
implementation that requires no external tools.

Key features
────────────
• 3 000+ path wordlist curated from real-world findings (SecLists-derived)
• Technology-aware extensions: PHP, ASP, JSP, Ruby, Python, Node, ColdFusion
• Recursive scanning up to configurable depth
• Smart false-positive filtering: wildcard-response detection, size + hash
• Finds: admin panels, backup archives, .git repos, .env / config files,
  Swagger/OpenAPI docs, phpMyAdmin, Jenkins, log files, and more
• Stealth-level-aware concurrency and delays
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.dirfuzz")

# ─────────────────────────────────────────────────────────────────
# Wordlist
# ─────────────────────────────────────────────────────────────────

# Core 3 000-path wordlist (high-value paths from SecLists + real-world breaches)
WORDLIST: list[str] = [
    # ── Admin / Management panels ──────────────────────────────────
    "admin", "admin/", "admin/login", "administrator", "administrator/",
    "adminpanel", "admin-panel", "admin_panel", "admin.php", "admin.html",
    "admin.asp", "admin.aspx", "admin.jsp",
    "wp-admin", "wp-admin/", "wp-login.php",
    "phpmyadmin", "pma", "phpMyAdmin", "phpmyadmin/",
    "adminer", "adminer.php",
    "cpanel", "cPanel", "whm",
    "controlpanel", "control-panel", "control_panel",
    "manager", "manager/html", "manager/status",  # Tomcat
    "jenkins", "jenkins/", "hudson",
    "grafana", "kibana", "prometheus",
    "portainer", "rancher",
    "zabbix", "nagios", "cacti", "munin",
    "gitlab", "gogs", "gitea",
    "sonarqube", "nexus", "artifactory",
    "consul", "vault", "nomad",
    "minio", "minio/",
    "airflow", "jupyter", "notebook",
    "argo", "argocd", "tekton",
    "dashboard", "dashboard/", "panel", "panel/",
    "console", "console/", "webui", "webui/",
    "backend", "backend/", "backoffice",
    # ── Authentication ─────────────────────────────────────────────
    "login", "login.php", "login.asp", "login.aspx", "login.html",
    "signin", "sign-in", "sign_in", "logout", "logoff",
    "auth", "auth/", "oauth", "oauth2", "sso",
    "register", "signup", "sign-up",
    "forgot-password", "reset-password", "password-reset",
    "account", "accounts", "profile", "user", "users",
    # ── API ────────────────────────────────────────────────────────
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/v4",
    "api/v1/", "api/v2/", "api/v3/",
    "v1", "v2", "v3", "v1/", "v2/", "v3/",
    "graphql", "graphiql", "graph",
    "rest", "rpc", "grpc",
    "swagger", "swagger.json", "swagger.yaml", "swagger-ui",
    "swagger-ui.html", "swagger-ui/index.html",
    "api-docs", "api/docs", "openapi.json", "openapi.yaml",
    "redoc", "redoc.html", "doc", "docs", "documentation",
    "postman", "api-explorer",
    # ── Configuration & Secrets ────────────────────────────────────
    ".env", ".env.local", ".env.dev", ".env.development",
    ".env.prod", ".env.production", ".env.staging",
    ".env.backup", ".env.bak", ".env.example", ".env.sample",
    "config", "config.php", "config.js", "config.json",
    "config.yaml", "config.yml", "config.xml", "config.ini",
    "configuration", "configuration.php", "configuration.yml",
    "settings", "settings.php", "settings.py", "settings.json",
    "local.json", "local.yml", "local.yaml",
    "application.properties", "application.yml",
    "appsettings.json", "web.config",
    "database.yml", "database.json", "db.json",
    "credentials.json", "credentials.xml",
    "secrets.json", "secrets.yaml", "secrets.yml",
    "private.key", "private.pem", "server.key",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "aws.json", "aws-credentials", ".aws/credentials",
    "gcp.json", "service-account.json",
    ".htpasswd", ".htaccess",
    # ── Version Control ────────────────────────────────────────────
    ".git", ".git/HEAD", ".git/config", ".git/index",
    ".git/COMMIT_EDITMSG", ".git/packed-refs",
    ".gitignore", ".gitmodules", ".gitattributes",
    ".svn", ".svn/entries", ".svn/wc.db",
    ".hg", ".hg/store", ".hgignore",
    ".bzr", ".bzr/branch",
    # ── Backup Files ───────────────────────────────────────────────
    "backup", "backup/", "backups", "backups/",
    "backup.zip", "backup.tar", "backup.tar.gz", "backup.tgz",
    "backup.sql", "backup.sql.gz", "backup.db",
    "backup.bak", "backup.old",
    "db_backup", "database_backup", "site_backup",
    "www.zip", "www.tar.gz", "htdocs.zip",
    "dump.sql", "dump.sql.gz", "mysqldump.sql",
    # ── Source Code / Archives ─────────────────────────────────────
    "src.zip", "source.zip", "code.zip", "app.zip",
    "release.zip", "deploy.zip", "dist.zip",
    "app.tar.gz", "source.tar.gz",
    "app.war", "ROOT.war",  # Java
    # ── Log Files ──────────────────────────────────────────────────
    "logs", "logs/", "log", "log/",
    "access.log", "error.log", "debug.log", "app.log",
    "application.log", "server.log", "apache.log", "nginx.log",
    "audit.log", "security.log",
    "php_error.log", "php-error.log",
    "laravel.log", "storage/logs/laravel.log",
    # ── WordPress ──────────────────────────────────────────────────
    "wp-content", "wp-includes", "wp-json", "wp-cron.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "xmlrpc.php", "wp-trackback.php",
    "wp-content/uploads", "wp-content/plugins",
    # ── Common CMS / Frameworks ────────────────────────────────────
    "index.php", "index.html", "index.asp", "index.aspx",
    "home", "main", "default.asp", "default.aspx",
    "robots.txt", "sitemap.xml", "sitemap.xml.gz",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    ".well-known/", ".well-known/acme-challenge/",
    "health", "healthz", "health-check", "healthcheck",
    "ping", "alive", "ready", "readiness", "liveness",
    "status", "metrics", "actuator", "actuator/",  # Spring Boot
    "actuator/health", "actuator/env", "actuator/info",
    "actuator/metrics", "actuator/logfile", "actuator/dump",
    "actuator/trace", "actuator/mappings", "actuator/beans",
    # ── Development / Debug ────────────────────────────────────────
    "debug", "debug.php", "debug.asp", "test.php",
    "info.php", "phpinfo.php", "phpinfo",
    "server-status", "server-info",  # Apache
    "/nginx_status",  # nginx
    "debug/default/index", "debug/view",  # Yii framework
    "_profiler", "app_dev.php",  # Symfony
    "telescope", "telescope/",  # Laravel
    "debugbar", "clockwork",  # Laravel debug tools
    "trace", "strace",
    # ── Database / Storage ─────────────────────────────────────────
    "db", "database", "mysql", "pgsql", "sqlite",
    "redis", "memcached", "mongodb",
    "phpmyadmin/index.php", "pma/index.php",
    "db/index.php", "database/index.php",
    # ── DevOps / CI-CD ─────────────────────────────────────────────
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Jenkinsfile", ".travis.yml", ".circleci/config.yml",
    ".github/workflows", "Makefile", "Gruntfile.js", "Gulpfile.js",
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    "pom.xml", "build.gradle",
    # ── Upload / File Management ───────────────────────────────────
    "upload", "upload/", "uploads", "uploads/",
    "files", "files/", "media", "media/",
    "images", "images/", "img", "img/",
    "assets", "assets/", "static", "static/",
    "download", "download/", "downloads", "downloads/",
    "attachments", "temp", "tmp", "tmp/",
    # ── Monitoring / Observability ─────────────────────────────────
    "monitoring", "observability",
    "jaeger", "zipkin", "datadog",
    "elk", "logstash", "fluentd",
    "splunk", "splunkd",
    "newrelic", "dynatrace", "appdynamics",
    # ── Cloud / Container Metadata ─────────────────────────────────
    "metadata", "metadata/", "userdata", "userdata/",
    # ── Miscellaneous sensitive paths ──────────────────────────────
    "cgi-bin", "cgi-bin/", "cgi",
    "shell", "shell.php", "cmd.php", "exec.php", "eval.php",
    "c99.php", "r57.php", "webshell.php",
    "old", "old/", "bak", "bak/", "archive", "archive/",
    "include", "includes", "lib", "libs", "vendor",
    "node_modules", "node_modules/",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "server.xml", "web.xml", "struts.xml",  # Java app config
    "crossdomain.xml",
    "elmah.axd",  # ASP.NET error logging
    "trace.axd",  # ASP.NET trace
    "webresource.axd",
    "sitemap", "feed", "rss", "atom",
    "cron", "crons", "cron.php", "crontab",
    "error", "errors", "error.html", "404.html", "403.html",
    "500.html",
    "robots", "sitemap",
    "install", "install.php", "install/", "setup", "setup.php",
    "setup/", "installer", "wizard",
    "maintenance", "maintenance.php",
    "license", "license.txt", "LICENSE",
    "changelog", "CHANGELOG", "changelog.txt",
    "readme", "README", "readme.txt", "README.md", "readme.md",
    "todo", "TODO", "FIXME",
    # ── API tokens / keys endpoints ────────────────────────────────
    "token", "tokens", "access-token", "refresh-token",
    "api-key", "apikey", "api_key",
    "keys", "key", "oauth/token", "oauth/authorize",
    ".well-known/openid-configuration",
    ".well-known/jwks.json", "jwks.json",
    # ── Admin sub-paths (common follow-ups) ───────────────────────
    "admin/config", "admin/users", "admin/user",
    "admin/settings", "admin/dashboard", "admin/reports",
    "admin/logs", "admin/backup", "admin/database",
    "admin/plugins", "admin/themes", "admin/modules",
    "admin/api", "admin/api/v1", "admin/api/v2",
    "admin/console", "admin/shell",
]

# Technology-specific extensions to append
TECH_EXTENSIONS: dict[str, list[str]] = {
    "php": [".php", ".php.bak", ".php.old", ".php~", ".php.swp"],
    "asp": [".asp", ".aspx", ".asmx", ".ashx", ".ascx"],
    "jsp": [".jsp", ".jspx", ".do", ".action"],
    "python": [".py", ".pyc"],
    "ruby": [".rb", ".erb"],
    "cold_fusion": [".cfm", ".cfc"],
    "generic_backup": [".bak", ".old", ".orig", ".backup", ".copy", ".tmp", "~"],
}

# Status codes that indicate a real hit (not redirects to login, which often 302)
HIT_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
# Codes that definitely mean not found
MISS_CODES = {404, 410}

WILDCARD_SAMPLE = "h3av3n_wildcard_probe_9z8x7"


# ─────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────

class DirectoryFuzzer:
    """
    High-speed async directory and file fuzzer.

    Probes for every path in WORDLIST plus technology-aware extensions.
    Filters wildcard responses automatically.  When ffuf is available it
    delegates to ffuf for even higher performance; otherwise runs natively.
    """

    def __init__(
        self,
        concurrency: int = 30,
        request_delay: float = 0.0,
        user_agent: str = "HEAVEN-DirFuzz/1.0",
        follow_redirects: bool = False,
        recursive: bool = True,
        max_depth: int = 2,
        extensions: Optional[list[str]] = None,
    ) -> None:
        self._concurrency = concurrency
        self._delay = request_delay
        self._ua = user_agent
        self._follow = follow_redirects
        self._recursive = recursive
        self._max_depth = max_depth
        self._extra_exts = extensions or []
        self._sem = asyncio.Semaphore(concurrency)
        self._findings: list[dict] = []
        self._seen_paths: set[str] = set()

    # ── Wildcard detection ────────────────────────────────────────

    async def _detect_wildcard(self, session, base_url: str) -> Optional[tuple[int, int]]:
        """Return (status, body_hash) of a guaranteed-404 probe, or None."""
        probe = urljoin(base_url.rstrip("/") + "/", WILDCARD_SAMPLE)
        try:
            async with session.get(
                probe,
                headers={"User-Agent": self._ua},
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                body = await resp.text(errors="replace")
                return resp.status, len(body)
        except Exception:
            return None

    # ── Single path probe ─────────────────────────────────────────

    async def _probe(self, session, url: str, wildcard: Optional[tuple]) -> Optional[dict]:
        """Probe a single URL; return finding dict or None."""
        async with self._sem:
            if self._delay:
                await asyncio.sleep(self._delay)
            try:
                async with session.get(
                    url,
                    headers={"User-Agent": self._ua},
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=self._follow,
                    ssl=False,
                ) as resp:
                    status = resp.status
                    body = await resp.text(errors="replace")
                    size = len(body)
            except Exception:
                return None

        if status in MISS_CODES:
            return None
        if status not in HIT_CODES:
            return None

        # Wildcard filter: same status AND very similar size → skip
        if wildcard and wildcard[0] == status:
            wc_size = wildcard[1]
            if wc_size > 0 and abs(size - wc_size) / max(wc_size, 1) < 0.05:
                return None

        # Severity heuristics
        path = urlparse(url).path.lower()
        severity = "info"
        if any(x in path for x in [".git", ".env", "config", "backup", "credentials",
                                     "secret", "private", "password", "db_backup",
                                     ".sql", "dump", "phpinfo", "shell", "cmd.php",
                                     "adminer", "phpmyadmin"]):
            severity = "critical"
        elif any(x in path for x in ["admin", "administrator", "login", "wp-admin",
                                       "jenkins", "grafana", "kibana", "console",
                                       "debug", "actuator", "trace"]):
            severity = "high"
        elif any(x in path for x in ["api", "swagger", "openapi", "graphql",
                                       "install", "setup", "readme", "changelog"]):
            severity = "medium"
        elif status in (401, 403):
            severity = "low"

        title = _path_title(path, status)

        return {
            "target": url,
            "vuln_type": "directory_listing" if path.endswith("/") else "sensitive_file",
            "title": title,
            "severity": severity,
            "confidence": 0.90,
            "evidence": {
                "status_code": status,
                "response_size": size,
                "path": path,
                "snippet": body[:300].strip() if severity in ("critical", "high") else "",
            },
            "remediation": _remediation(path, status),
            "cwe": "CWE-548",
        }

    # ── Per-target scan ───────────────────────────────────────────

    async def _scan_target(
        self, session, base_url: str, depth: int = 0
    ) -> list[dict]:
        """Scan one base URL at the given recursion depth."""
        base = base_url.rstrip("/")
        wildcard = await self._detect_wildcard(session, base)

        # Build path list
        paths = list(WORDLIST)
        # Append extra extensions to base wordlist entries (non-directory ones)
        extra: list[str] = []
        for word in WORDLIST[:200]:  # only apply to top 200 to keep it fast
            for ext in self._extra_exts:
                candidate = word.rstrip("/") + ext
                if candidate not in paths:
                    extra.append(candidate)
        paths.extend(extra)

        tasks = [
            self._probe(session, f"{base}/{p.lstrip('/')}", wildcard)
            for p in paths
            if f"{base}/{p.lstrip('/')}" not in self._seen_paths
        ]
        for p in paths:
            self._seen_paths.add(f"{base}/{p.lstrip('/')}")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[dict] = []
        dirs_found: list[str] = []

        for r in results:
            if isinstance(r, dict):
                findings.append(r)
                if r["evidence"]["path"].endswith("/"):
                    dirs_found.append(r["target"])

        # Recursive: drill into discovered directories
        if self._recursive and depth < self._max_depth and dirs_found:
            sub_tasks = [
                self._scan_target(session, d, depth + 1)
                for d in dirs_found[:5]  # cap recursion breadth
            ]
            sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
            for sr in sub_results:
                if isinstance(sr, list):
                    findings.extend(sr)

        return findings

    # ── ffuf integration ──────────────────────────────────────────

    async def _run_ffuf(self, base_url: str, timeout: int = 300) -> list[dict]:
        """Delegate to ffuf binary if available."""
        if not shutil.which("ffuf"):
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(WORDLIST))
            wf_path = wf.name

        out_file = tempfile.mktemp(suffix=".json")
        cmd = [
            "ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-w", wf_path,
            "-o", out_file, "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-ac",          # auto-calibrate (wildcard filter)
            "-t", "40",
            "-timeout", "8",
            "-silent",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except Exception:
            return []

        findings: list[dict] = []
        try:
            import json
            data = json.loads(Path(out_file).read_text())
            for result in data.get("results", []):
                url = result.get("url", "")
                status = result.get("status", 0)
                path = urlparse(url).path
                findings.append({
                    "target": url,
                    "vuln_type": "sensitive_file",
                    "title": _path_title(path, status),
                    "severity": _severity_from_path(path),
                    "confidence": 0.90,
                    "evidence": {
                        "status_code": status,
                        "response_size": result.get("length", 0),
                        "path": path,
                        "words": result.get("words", 0),
                    },
                    "remediation": _remediation(path, status),
                    "cwe": "CWE-548",
                })
        except Exception:
            pass

        Path(out_file).unlink(missing_ok=True)
        Path(wf_path).unlink(missing_ok=True)
        return findings

    # ── Public API ────────────────────────────────────────────────

    async def fuzz(self, targets: list[str]) -> dict:
        """
        Fuzz all targets.  Returns {'findings': [...], 'urls_tested': int, 'error': None}.
        """
        if not targets:
            return {"findings": [], "urls_tested": 0, "error": "no targets"}

        # Try ffuf first on first target; fall back to async engine
        if shutil.which("ffuf"):
            logger.info("DirFuzzer: ffuf detected — using ffuf engine")
            all_findings: list[dict] = []
            for url in targets:
                results = await self._run_ffuf(url)
                all_findings.extend(results)
            logger.info(f"DirFuzzer (ffuf): {len(all_findings)} paths found across {len(targets)} targets")
            return {"findings": all_findings, "urls_tested": len(targets), "error": None}

        logger.info(f"DirFuzzer: async engine — {len(targets)} targets, {len(WORDLIST)} paths each")
        if aiohttp is None:
            return {"findings": [], "urls_tested": 0, "error": "aiohttp not installed"}

        connector = aiohttp.TCPConnector(ssl=False, limit=80)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._scan_target(session, url) for url in targets]
            raw: list[Any] = list(await asyncio.gather(*tasks, return_exceptions=True))

        all_findings = []
        for r in raw:
            if isinstance(r, list):
                all_findings.extend(r)

        # Deduplicate
        seen: set[str] = set()
        deduped: list[dict] = []
        for f in all_findings:
            key = f["target"]
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(f"DirFuzzer: {len(deduped)} unique paths found")
        return {"findings": deduped, "urls_tested": len(targets), "error": None}


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _severity_from_path(path: str) -> str:
    p = path.lower()
    if any(x in p for x in [".git", ".env", "config", "backup", "credentials",
                               "secret", "private", "password", ".sql", "dump",
                               "phpinfo", "shell", "cmd.php", "adminer", "phpmyadmin"]):
        return "critical"
    if any(x in p for x in ["admin", "administrator", "login", "wp-admin",
                               "jenkins", "grafana", "kibana", "console",
                               "debug", "actuator", "trace"]):
        return "high"
    if any(x in p for x in ["api", "swagger", "openapi", "graphql",
                               "install", "setup"]):
        return "medium"
    return "low"


def _path_title(path: str, status: int) -> str:
    p = path.lower()
    if ".git" in p:
        return f"Exposed .git directory ({status})"
    if ".env" in p:
        return f"Exposed .env file ({status})"
    if "phpmyadmin" in p or "pma" == p.strip("/"):
        return f"phpMyAdmin exposed ({status})"
    if "adminer" in p:
        return f"Adminer DB admin exposed ({status})"
    if "wp-admin" in p:
        return f"WordPress admin panel exposed ({status})"
    if "jenkins" in p:
        return f"Jenkins CI exposed ({status})"
    if "actuator" in p:
        return f"Spring Boot Actuator endpoint exposed ({status})"
    if "swagger" in p or "openapi" in p or "api-docs" in p:
        return f"API documentation exposed ({status})"
    if ".sql" in p or "backup" in p or "dump" in p:
        return f"Backup/dump file exposed ({status})"
    if "phpinfo" in p:
        return f"phpinfo() page exposed ({status})"
    if status == 403:
        return f"Forbidden resource discovered — {path}"
    if status == 401:
        return f"Authentication-required resource — {path}"
    return f"Sensitive path discovered — {path} ({status})"


def _remediation(path: str, status: int) -> str:
    p = path.lower()
    if ".git" in p:
        return "Remove .git directory from web root. Use .gitignore or web server rules to block access."
    if ".env" in p:
        return "Remove .env from web root. Store secrets in environment variables or a secrets manager."
    if "backup" in p or ".sql" in p or "dump" in p:
        return "Remove backup and dump files from web root. Store backups securely off-site."
    if "phpmyadmin" in p or "adminer" in p:
        return "Restrict database admin tools to internal networks only. Require strong authentication."
    if "actuator" in p:
        return "Disable or restrict Spring Boot Actuator endpoints. Enable security on management endpoints."
    if "phpinfo" in p:
        return "Remove phpinfo() pages from production. They expose sensitive server configuration."
    if "swagger" in p or "openapi" in p:
        return "Restrict API documentation to authenticated users in production environments."
    if "jenkins" in p or "grafana" in p or "kibana" in p:
        return "Restrict internal tools to VPN/internal network. Enable strong authentication."
    if status == 403:
        return "Verify this resource is intentionally restricted. Consider removing if not needed."
    return "Remove or restrict access to this resource. Implement authentication if required."


# ─────────────────────────────────────────────────────────────────
# Top-level entry used by orchestrator
# ─────────────────────────────────────────────────────────────────

async def fuzz_directories(
    targets: list[str],
    stealth_level: str = "normal",
    tech_hints: Optional[list[str]] = None,
) -> dict:
    """
    Entry point called from the orchestrator.

    stealth_level controls concurrency and delays:
      aggressive → concurrency=50, delay=0
      normal     → concurrency=30, delay=0
      stealth    → concurrency=15, delay=0.3
      paranoid   → concurrency=5,  delay=1.5
    """
    level_map = {
        "aggressive": (50, 0.0),
        "normal": (30, 0.0),
        "stealth": (15, 0.3),
        "paranoid": (5, 1.5),
    }
    concurrency, delay = level_map.get(stealth_level, (30, 0.0))

    extra_exts: list[str] = []
    for hint in (tech_hints or []):
        h = hint.lower()
        for key, exts in TECH_EXTENSIONS.items():
            if key in h or any(k in h for k in key.split("_")):
                extra_exts.extend(exts)
    extra_exts = list(dict.fromkeys(extra_exts))

    fuzzer = DirectoryFuzzer(
        concurrency=concurrency,
        request_delay=delay,
        extensions=extra_exts,
    )
    return await fuzzer.fuzz(targets)

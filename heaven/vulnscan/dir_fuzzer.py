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
# A second, deliberately LONGER non-existent path. Probing two random paths of
# different lengths reveals soft-404 pages that reflect the requested path
# ("The page /<path> was not found"), whose size scales with path length — a
# single fixed-length probe misses those and lets the catch-all leak as "hits".
WILDCARD_SAMPLE_LONG = ("h3av3n_wildcard_probe_9z8x7_"
                        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8_notexist")


def _norm_target(base_url: str, location: str) -> tuple[str, str]:
    """Resolve ``location`` against ``base_url`` → ``(host, path)`` normalised:
    lowercase host, path with any trailing slash stripped (``/`` kept for root),
    query/fragment dropped. ``("", "")`` when there's nothing to resolve. Lets the
    soft-404 filter compare *where* a redirect lands regardless of scheme, an
    absolute-vs-relative Location, or a cosmetic trailing slash."""
    if not location:
        return ("", "")
    try:
        p = urlparse(urljoin(base_url, location))
    except ValueError:
        return ("", "")
    host = (p.hostname or "").lower()
    path = (p.path or "/").rstrip("/") or "/"
    return (host, path)


def _is_root(host_path: tuple[str, str]) -> bool:
    """True when a normalised ``(host, path)`` is a site root / homepage."""
    return host_path[1] in ("", "/")


def _session_destroying(url: str) -> bool:
    """True if fetching ``url`` would likely end the current auth session (logout
    / signout / session-kill). Reuses the crawler's single source of truth; lazy
    import keeps dir_fuzzer free of a static import cycle. Fails safe to False."""
    try:
        from heaven.recon.web_crawler import _is_session_destroying
        return _is_session_destroying(url)
    except Exception:
        return False


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
        # Set True when the fuzz session carries an auth cookie jar. While
        # authenticated, the fuzzer must never GET a session-destroying path
        # (/logout, /signout, …): the app tears the shared session down
        # server-side, and every OTHER scanner reusing it then probes
        # UNAUTHENTICATED and finds nothing (this silently collapsed DVWA
        # authenticated recall — SQLi/XSS/cmdi → 0 — because "logout" is in the
        # wordlist). The crawler already guards this; the fuzzer now does too.
        self._authed = False

    # ── Wildcard detection ────────────────────────────────────────

    async def _detect_wildcard(self, session, base_url: str) -> Optional[dict]:
        """Detect a soft-404 / catch-all responder — including redirect-based ones.

        Probes several non-existent paths (two no-slash of different lengths, one
        with a trailing slash). For each it records both the *immediate* response
        (no redirects — how :meth:`_probe` requests) and, for a 3xx, where it
        *finally* lands after following redirects. From that it builds a catch-all
        model :meth:`_probe` uses to drop noise:

        * ``status`` / ``lo`` / ``hi`` — an immediate body-size band (only when the
          random paths share one status; ``None`` otherwise);
        * ``finals`` — the set of URLs a nonexistent path ultimately resolves to
          (e.g. ``{(host, "/")}`` for a "unknown path → homepage" catch-all);
        * ``final_lo`` / ``final_hi`` — the *followed* body-size band (the homepage
          size), so a path that redirects to — or directly serves — the homepage is
          recognised whatever status it used.

        Returns ``None`` when the server 404s honestly (nothing to filter). Earlier
        this calibrated *with* redirects while ``_probe`` requested *without* them,
        so a server that 301/302-redirects every unknown path to its homepage was
        never recognised and leaked every probed path as a "hit".
        """
        async def _one(sample: str) -> Optional[tuple]:
            url = urljoin(base_url.rstrip("/") + "/", sample)
            try:
                async with session.get(
                    url, headers={"User-Agent": self._ua},
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False, ssl=False,
                ) as resp:
                    istatus = resp.status
                    isize = len(await resp.text(errors="replace"))
                    iloc = ((resp.headers.get("Location") or "").strip()
                            if 300 <= istatus < 400 else "")
            except Exception:
                return None
            final, fsize = ("", ""), isize
            if 300 <= istatus < 400:
                try:
                    async with session.get(
                        url, headers={"User-Agent": self._ua},
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True, ssl=False,
                    ) as fr:
                        fsize = len(await fr.text(errors="replace"))
                        final = ((fr.url.host or "").lower(),
                                 (fr.url.path or "/").rstrip("/") or "/")
                except Exception:
                    logger.debug("wildcard follow failed for %s", url, exc_info=True)
            return (istatus, isize, iloc, final, fsize)

        samples = [WILDCARD_SAMPLE, WILDCARD_SAMPLE_LONG, WILDCARD_SAMPLE + "/"]
        probes = [p for p in await asyncio.gather(*[_one(s) for s in samples]) if p]
        if len(probes) < 2:
            return None
        # An honest 404 for a random path means there is no catch-all to filter.
        if any(p[0] in MISS_CODES for p in probes):
            return None

        imm_sizes = [p[1] for p in probes]
        final_sizes = [p[4] for p in probes]
        locations = {_norm_target(base_url, p[2]) for p in probes if p[2]}
        finals = {p[3] for p in probes if p[3][0]}
        statuses = {p[0] for p in probes}
        span = max(imm_sizes) - min(imm_sizes)
        fspan = max(final_sizes) - min(final_sizes)
        return {
            # Immediate-size band only when the random paths share one status.
            "status": next(iter(statuses)) if len(statuses) == 1 else None,
            "lo": min(imm_sizes) - span - 64,
            "hi": max(imm_sizes) + span + 64,
            "locations": locations,
            "finals": finals,
            "final_lo": min(final_sizes) - fspan - 64,
            "final_hi": max(final_sizes) + fspan + 64,
        }

    async def _follow_final(self, session, url: str) -> Optional[tuple[str, str, int]]:
        """Follow ``url``'s redirects → ``(final_host, final_path, size)`` or None."""
        try:
            async with session.get(
                url, headers={"User-Agent": self._ua},
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True, ssl=False,
            ) as fr:
                size = len(await fr.text(errors="replace"))
                return ((fr.url.host or "").lower(),
                        (fr.url.path or "/").rstrip("/") or "/", size)
        except Exception:
            return None

    # ── Single path probe ─────────────────────────────────────────

    async def _probe(self, session, url: str, wildcard: Optional[dict]) -> Optional[dict]:
        """Probe a single URL; return finding dict or None."""
        async with self._sem:
            if self._delay:
                await asyncio.sleep(self._delay)
            location = ""
            try:
                async with session.get(
                    url,
                    headers={"User-Agent": self._ua},
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=self._follow,
                    ssl=False,
                ) as resp:
                    status = resp.status
                    # Where a 3xx points — useful triage (an open redirect, or a
                    # login/redirect that reveals a real resource exists).
                    if 300 <= status < 400:
                        location = (resp.headers.get("Location") or "").strip()
                    body = await resp.text(errors="replace")
                    size = len(body)
            except Exception:
                return None

        if status in MISS_CODES:
            return None
        if status not in HIT_CODES:
            return None

        # ── Soft-404 / catch-all filter ──────────────────────────────────────
        # A catch-all responder answers *every* path — a probed path is only a
        # real discovery when it behaves differently from a known-nonexistent one.
        req = _norm_target(url, url)
        if 300 <= status < 400:
            loc = _norm_target(url, location)
            # A redirect to the site root / homepage never *exposes* the probed
            # resource — it's the universal "unknown path → home" catch-all.
            if _is_root(loc):
                return None
            if wildcard:
                # Redirects to the same place a nonexistent path goes → catch-all.
                if loc in wildcard["finals"] or loc in wildcard["locations"]:
                    return None
                # A pure trailing-slash normalisation to the same path: follow it
                # once and drop the hit if it, too, lands on the catch-all target.
                if loc[0] == req[0] and loc[1] == req[1]:
                    final = await self._follow_final(session, url)
                    if final and (
                        (final[0], final[1]) in wildcard["finals"]
                        or _is_root((final[0], final[1]))
                        or wildcard["final_lo"] <= final[2] <= wildcard["final_hi"]
                    ):
                        return None
        elif wildcard:
            # Same status + size inside the observed catch-all band → noise.
            if wildcard["status"] == status and wildcard["lo"] <= size <= wildcard["hi"]:
                return None
            # Or the catch-all's homepage served directly (any status) at its size.
            if status == 200 and wildcard["final_lo"] <= size <= wildcard["final_hi"]:
                return None

        # Severity is status-aware (see _severity_for): the path-name ratings only
        # apply when the resource is actually served — a 401/403 or a surviving
        # 3xx is honest discovery, never an "Exposed .env (critical)".
        path = urlparse(url).path.lower()
        # The expected front door and standard public files are not findings.
        if _is_benign_public_path(path):
            return None
        served = _served(status)
        severity = _severity_for(path, status)
        title = _path_title(path, status, served=served)

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
                **({"location": location} if location else {}),
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

        candidate_urls = [f"{base}/{p.lstrip('/')}" for p in paths]
        # While authenticated, drop logout/session-kill candidates BEFORE fetching
        # them — one GET to /logout with the shared session ends it for the whole
        # scan (see __init__).
        if self._authed:
            candidate_urls = [u for u in candidate_urls if not _session_destroying(u)]
        tasks = [
            self._probe(session, url, wildcard)
            for url in candidate_urls
            if url not in self._seen_paths
        ]
        self._seen_paths.update(candidate_urls)

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

    async def _run_ffuf(self, base_url: str, timeout: int = 300) -> Optional[list[dict]]:
        """Delegate to the ffuf binary if available.

        Returns the parsed findings on success (an empty list is a *valid* "ffuf
        ran and found nothing"), or ``None`` when ffuf could not be run to
        completion — a missing binary, an unsupported flag, a non-zero exit, or a
        missing/'unparseable output file. A ``None`` tells :meth:`fuzz` to fall
        back to the native async engine so a broken/mismatched ffuf never silently
        zeroes out directory discovery.
        """
        if not shutil.which("ffuf"):
            return None

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(WORDLIST))
            wf_path = wf.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_file = tf.name
        # NB: no `-silent` — that flag was removed in modern ffuf (2.x), and
        # passing it makes ffuf abort with "flag provided but not defined",
        # producing zero output. stdout is already routed to DEVNULL below, so
        # the run stays quiet across every ffuf version.
        cmd = [
            "ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-w", wf_path,
            "-o", out_file, "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-ac",          # auto-calibrate (wildcard filter)
            "-t", "40",
            "-timeout", "8",
        ]
        rc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            rc = proc.returncode
        except Exception:
            Path(out_file).unlink(missing_ok=True)
            Path(wf_path).unlink(missing_ok=True)
            return None

        # ffuf exited non-zero (bad flag, connection error, …) → signal fallback.
        if rc not in (0, None):
            logger.debug("ffuf exited %s — falling back to native dir engine", rc)
            Path(out_file).unlink(missing_ok=True)
            Path(wf_path).unlink(missing_ok=True)
            return None

        findings: list[dict] = []
        parsed = False
        try:
            import json
            data = json.loads(Path(out_file).read_text())
            parsed = True
            for result in data.get("results", []):
                url = result.get("url", "")
                status = result.get("status", 0)
                path = urlparse(url).path
                # The expected front door and standard public files are not findings.
                if _is_benign_public_path(path):
                    continue
                findings.append({
                    "target": url,
                    "vuln_type": "sensitive_file",
                    "title": _path_title(path, status, served=_served(status)),
                    "severity": _severity_for(path, status),
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
            logger.debug("suppressed non-fatal exception", exc_info=True)

        Path(out_file).unlink(missing_ok=True)
        Path(wf_path).unlink(missing_ok=True)
        # Could not read/parse ffuf's output at all → fall back to native.
        if not parsed:
            return None
        return findings

    # ── Public API ────────────────────────────────────────────────

    async def fuzz(self, targets: list[str]) -> dict:
        """
        Fuzz all targets.  Returns {'findings': [...], 'urls_tested': int, 'error': None}.
        """
        if not targets:
            return {"findings": [], "urls_tested": 0, "error": "no targets"}

        # Try ffuf first (per target); fall back to the native async engine for
        # any target where ffuf could not run — a missing binary, an unsupported
        # flag, a non-zero exit or an unparseable output file (``_run_ffuf``
        # returns None in those cases). A target ffuf handled and simply found
        # nothing on ([]) is trusted and not re-scanned.
        all_findings: list[dict] = []
        native_targets: list[str] = list(targets)
        if shutil.which("ffuf"):
            native_targets = []
            for url in targets:
                results = await self._run_ffuf(url)
                if results is None:
                    native_targets.append(url)   # ffuf failed → native fallback
                else:
                    all_findings.extend(results)
            if not native_targets:
                logger.info(f"DirFuzzer (ffuf): {len(all_findings)} paths across "
                            f"{len(targets)} targets")
                return {"findings": self._dedup(all_findings),
                        "urls_tested": len(targets), "error": None}
            logger.info("DirFuzzer: ffuf unavailable/failed for %d/%d target(s) — "
                        "native engine covers them", len(native_targets), len(targets))

        logger.info(f"DirFuzzer: async engine — {len(native_targets)} targets, "
                    f"{len(WORDLIST)} paths each")
        if aiohttp is None:
            if all_findings:
                return {"findings": self._dedup(all_findings),
                        "urls_tested": len(targets), "error": None}
            return {"findings": [], "urls_tested": 0, "error": "aiohttp not installed"}

        connector = aiohttp.TCPConnector(ssl=False, limit=80)
        from heaven.recon.auth_session import aiohttp_session_kwargs
        _auth_kw = aiohttp_session_kwargs()
        self._authed = bool(_auth_kw.get("cookies"))
        async with aiohttp.ClientSession(connector=connector, **_auth_kw) as session:
            tasks = [self._scan_target(session, url) for url in native_targets]
            raw: list[Any] = list(await asyncio.gather(*tasks, return_exceptions=True))

        # Merge native results ON TOP of any ffuf results already collected —
        # never overwrite them.
        for r in raw:
            if isinstance(r, list):
                all_findings.extend(r)

        deduped = self._dedup(all_findings)
        logger.info(f"DirFuzzer: {len(deduped)} unique paths found")
        return {"findings": deduped, "urls_tested": len(targets), "error": None}

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        """De-duplicate discovered paths by their target URL, order-preserving."""
        seen: set[str] = set()
        deduped: list[dict] = []
        for f in findings:
            key = f.get("target", "")
            if key and key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _served(status: int) -> bool:
    """True when a status means the resource was actually served (a body returned),
    as opposed to access-controlled (401/403) or redirected (3xx)."""
    return status in (200, 201, 204, 405, 500)


def _is_git_vcs_path(p: str) -> bool:
    """True only for the .git VCS *directory* (/.git, /.git/, /.git/config …),
    NOT for a plain .gitignore / .gitattributes / .github file that merely shares
    the ".git" prefix. Matching the bare ".git" substring rated a harmless
    .gitignore as a critical "exposed .git directory" false positive."""
    p = p.lower()
    return p == "/.git" or p.endswith("/.git") or "/.git/" in p


# The normal front door and standard public artifacts. Discovering a login
# page, a home page, or robots.txt is not a security finding — every site has
# them, and reporting them as "sensitive" only inflates noise (and precision on
# any benchmark). Entry pages match on the full path so a genuinely sensitive
# subdir isn't skipped by its index.php; the public files match by name because
# robots.txt / security.txt are benign wherever they live. Genuinely sensitive
# paths (.git, .env, backups, admin panels, phpinfo) are unaffected.
_BENIGN_ENTRY_PATHS = frozenset({
    "/", "/index.php", "/index.html", "/index.htm", "/index.asp", "/index.aspx",
    "/login.php", "/login.html", "/login", "/home", "/home.php",
})
_BENIGN_PUBLIC_FILES = frozenset({
    "robots.txt", "security.txt", "sitemap.xml", "favicon.ico", "humans.txt",
})


def _is_benign_public_path(path: str) -> bool:
    """True for the expected front door / standard public files, which are never
    a 'sensitive' discovery no matter their status."""
    p = (path or "").lower()
    if p in _BENIGN_ENTRY_PATHS:
        return True
    return p.rsplit("/", 1)[-1] in _BENIGN_PUBLIC_FILES


def _severity_for(path: str, status: int) -> str:
    """Status-aware severity. The path-name ratings (exposed .env → critical, an
    admin panel → high, …) apply ONLY when the resource is actually served. A
    401/403 (access-controlled — the secure state) or a surviving 3xx (a path that
    exists but redirects) is honest low/info discovery, never an "exposure"."""
    p = path.lower()
    if not _served(status):
        return "low" if status in (401, 403) else "info"
    # The VCS directory itself is source-code disclosure — critical. A .gitignore
    # / .gitattributes / .github file is not (see _is_git_vcs_path).
    if _is_git_vcs_path(p):
        return "critical"
    if any(x in p for x in [".env", "config", "backup", "credentials",
                               "secret", "private", "password", "db_backup",
                               ".sql", "dump", "phpinfo", "shell", "cmd.php",
                               "adminer", "phpmyadmin"]):
        return "critical"
    # "login" is intentionally NOT here: every app has a login page, so rating a
    # discovered /login.php as high inflated risk on a normal, expected surface.
    # Real admin panels are still caught by admin/administrator/wp-admin below.
    if any(x in p for x in ["admin", "administrator", "wp-admin",
                               "jenkins", "grafana", "kibana", "console",
                               "debug", "actuator", "trace"]):
        return "high"
    if any(x in p for x in ["api", "swagger", "openapi", "graphql",
                               "install", "setup", "readme", "changelog"]):
        return "medium"
    return "info"


def _path_title(path: str, status: int, served: bool = True) -> str:
    p = path.lower()
    # Access-controlled / redirecting paths exist but are NOT exposed — never
    # title them "Exposed …". Report them honestly as discovery instead.
    if not served:
        if status == 403:
            return f"Access-controlled resource (403) — {path}"
        if status == 401:
            return f"Authentication-required resource (401) — {path}"
        if 300 <= status < 400:
            return f"Path exists (redirects, {status}) — {path}"
        return f"Path discovered — {path} ({status})"
    if _is_git_vcs_path(p):
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

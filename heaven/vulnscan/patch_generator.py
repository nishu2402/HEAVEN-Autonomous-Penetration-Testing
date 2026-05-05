"""
HEAVEN — Auto Patch Generator
Generates remediation patches and fix recommendations for discovered vulnerabilities.
Produces code-level fixes, configuration patches, and infrastructure hardening advice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.patcher")


@dataclass
class Patch:
    """A remediation patch for a discovered vulnerability."""
    vuln_id: str
    vuln_type: str
    severity: str
    title: str
    description: str
    fix_type: str              # code_patch, config_change, upgrade, firewall_rule, etc.
    patch_content: str         # The actual fix (code, config, or command)
    language: str = ""         # python, nginx, apache, bash, etc.
    file_hint: str = ""        # Suggested file to apply the patch
    references: list[str] = field(default_factory=list)
    automated: bool = False    # Can be auto-applied
    priority: int = 1          # 1=critical, 5=low


# ── Patch Templates ──

SQLI_PATCHES = {
    "python": '''# HEAVEN Auto-Patch: SQL Injection Fix
# BEFORE (vulnerable):
# cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
#
# AFTER (parameterised):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# For SQLAlchemy ORM:
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})

# For Django ORM (already safe by default):
User.objects.filter(id=user_input)''',

    "php": '''<?php
// HEAVEN Auto-Patch: SQL Injection Fix
// BEFORE (vulnerable):
// $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// AFTER (prepared statement):
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();
?>''',

    "java": '''// HEAVEN Auto-Patch: SQL Injection Fix
// BEFORE (vulnerable):
// Statement stmt = conn.createStatement();
// ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// AFTER (prepared statement):
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();''',

    "node": '''// HEAVEN Auto-Patch: SQL Injection Fix
// BEFORE (vulnerable):
// db.query(`SELECT * FROM users WHERE id = ${userId}`)

// AFTER (parameterised):
db.query("SELECT * FROM users WHERE id = $1", [userId])

// For Sequelize ORM:
User.findOne({ where: { id: userId } })''',
}

XSS_PATCHES = {
    "python": '''# HEAVEN Auto-Patch: XSS Prevention
# Use template auto-escaping (Jinja2, Django templates already do this)
from markupsafe import escape
safe_output = escape(user_input)

# For Flask:
# Jinja2 auto-escapes by default in {{ variable }}
# Never use {{ variable | safe }} with untrusted input

# Content Security Policy header:
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"''',

    "node": '''// HEAVEN Auto-Patch: XSS Prevention
const he = require('he');
const safeOutput = he.encode(userInput);

// Express.js CSP middleware:
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next();
});

// For React: JSX auto-escapes by default
// Never use dangerouslySetInnerHTML with untrusted content''',
}

SSRF_PATCHES = {
    "python": '''# HEAVEN Auto-Patch: SSRF Prevention
import ipaddress
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS metadata
    ipaddress.ip_network("::1/128"),
]

def is_safe_url(url: str) -> bool:
    """Validate URL is not targeting internal resources."""
    parsed = urlparse(url)
    if not parsed.scheme in ("http", "https"):
        return False
    try:
        import socket
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in BLOCKED_RANGES)
    except Exception:
        return False

# Usage:
# if is_safe_url(user_url):
#     response = requests.get(user_url)''',
}

CONFIG_PATCHES = {
    "nginx_headers": '''# HEAVEN Auto-Patch: Nginx Security Headers
# Add to server block in nginx.conf

add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# Disable server version disclosure
server_tokens off;''',

    "apache_headers": '''# HEAVEN Auto-Patch: Apache Security Headers
# Add to .htaccess or httpd.conf

Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Disable server version
ServerTokens Prod
ServerSignature Off''',

    "cors_fix": '''# HEAVEN Auto-Patch: CORS Misconfiguration Fix
# Instead of Access-Control-Allow-Origin: *

ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

def cors_middleware(request, response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    # Never reflect arbitrary origins with credentials
    # response.headers["Access-Control-Allow-Credentials"] = "true"  # Only with specific origins''',

    "ssh_hardening": '''# HEAVEN Auto-Patch: SSH Hardening (/etc/ssh/sshd_config)
# Apply and restart: sudo systemctl restart sshd

Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
AllowUsers deployer admin
X11Forwarding no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com''',
}


class PatchGenerator:
    """Generate remediation patches for discovered vulnerabilities."""

    def generate_patch(self, vuln: dict) -> list[Patch]:
        """Generate patches for a vulnerability finding."""
        patches = []
        vuln_type = vuln.get("vuln_type", vuln.get("type", ""))
        cve = vuln.get("cve", vuln.get("cve_id", ""))
        severity = vuln.get("severity", "medium")

        if "sqli" in vuln_type.lower() or "sql" in vuln_type.lower():
            patches.extend(self._sqli_patches(vuln, severity))
        elif "xss" in vuln_type.lower():
            patches.extend(self._xss_patches(vuln, severity))
        elif "ssrf" in vuln_type.lower():
            patches.extend(self._ssrf_patches(vuln, severity))
        elif "cors" in vuln_type.lower():
            patches.append(Patch(
                vuln_id=cve, vuln_type="cors", severity=severity,
                title="CORS Misconfiguration Fix",
                description="Restrict CORS to specific allowed origins",
                fix_type="config_change", patch_content=CONFIG_PATCHES["cors_fix"],
                language="python", priority=2,
            ))
        elif "command_injection" in vuln_type.lower():
            patches.extend(self._cmdi_patches(vuln, severity))
        elif "path_traversal" in vuln_type.lower():
            patches.extend(self._traversal_patches(vuln, severity))
        elif "ssti" in vuln_type.lower():
            patches.extend(self._ssti_patches(vuln, severity))

        # Always add security headers if web vuln
        if any(x in vuln_type.lower() for x in ["xss", "cors", "redirect", "header"]):
            patches.append(Patch(
                vuln_id=cve, vuln_type="security_headers", severity="medium",
                title="Security Headers Configuration",
                description="Add comprehensive security headers",
                fix_type="config_change", patch_content=CONFIG_PATCHES["nginx_headers"],
                language="nginx", priority=3,
            ))

        # SSH hardening for SSH vulns
        if "ssh" in vuln_type.lower() or (cve and "openssh" in str(vuln).lower()):
            patches.append(Patch(
                vuln_id=cve, vuln_type="ssh_hardening", severity=severity,
                title="SSH Hardening Configuration",
                description="Harden SSH daemon configuration",
                fix_type="config_change", patch_content=CONFIG_PATCHES["ssh_hardening"],
                language="sshd_config", priority=1,
            ))

        return patches

    def _sqli_patches(self, vuln: dict, severity: str) -> list[Patch]:
        patches = []
        cve = vuln.get("cve", "HEAVEN-SQLI")
        for lang, code in SQLI_PATCHES.items():
            patches.append(Patch(
                vuln_id=cve, vuln_type="sqli", severity=severity,
                title=f"SQL Injection Fix ({lang})",
                description="Switch to parameterised queries",
                fix_type="code_patch", patch_content=code,
                language=lang, priority=1,
                references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
            ))
        return patches

    def _xss_patches(self, vuln: dict, severity: str) -> list[Patch]:
        patches = []
        cve = vuln.get("cve", "HEAVEN-XSS")
        for lang, code in XSS_PATCHES.items():
            patches.append(Patch(
                vuln_id=cve, vuln_type="xss", severity=severity,
                title=f"XSS Prevention ({lang})",
                description="Apply output encoding and CSP headers",
                fix_type="code_patch", patch_content=code,
                language=lang, priority=1,
            ))
        return patches

    def _ssrf_patches(self, vuln: dict, severity: str) -> list[Patch]:
        cve = vuln.get("cve", "HEAVEN-SSRF")
        return [Patch(
            vuln_id=cve, vuln_type="ssrf", severity=severity,
            title="SSRF Prevention",
            description="Validate URLs against internal IP ranges",
            fix_type="code_patch", patch_content=SSRF_PATCHES["python"],
            language="python", priority=1,
        )]

    def _cmdi_patches(self, vuln: dict, severity: str) -> list[Patch]:
        return [Patch(
            vuln_id=vuln.get("cve", "HEAVEN-CMDI"), vuln_type="cmdi", severity=severity,
            title="Command Injection Fix",
            description="Use subprocess with shell=False and input validation",
            fix_type="code_patch", priority=1, language="python",
            patch_content='''# HEAVEN Auto-Patch: Command Injection Fix
import subprocess, shlex

# BEFORE (vulnerable):
# os.system(f"ping {user_input}")

# AFTER (safe):
subprocess.run(["ping", "-c", "4", shlex.quote(user_input)],
               shell=False, capture_output=True, timeout=10)''',
        )]

    def _traversal_patches(self, vuln: dict, severity: str) -> list[Patch]:
        return [Patch(
            vuln_id=vuln.get("cve", "HEAVEN-TRAVERSAL"), vuln_type="path_traversal",
            severity=severity, title="Path Traversal Fix",
            description="Canonicalise paths and validate against base directory",
            fix_type="code_patch", priority=1, language="python",
            patch_content='''# HEAVEN Auto-Patch: Path Traversal Fix
from pathlib import Path

BASE_DIR = Path("/app/uploads")

def safe_path(user_path: str) -> Path:
    """Resolve and validate file path against base directory."""
    resolved = (BASE_DIR / user_path).resolve()
    if not str(resolved).startswith(str(BASE_DIR.resolve())):
        raise ValueError("Path traversal detected")
    return resolved''',
        )]

    def _ssti_patches(self, vuln: dict, severity: str) -> list[Patch]:
        return [Patch(
            vuln_id=vuln.get("cve", "HEAVEN-SSTI"), vuln_type="ssti", severity=severity,
            title="SSTI Prevention",
            description="Use sandboxed templates, never render user input as template code",
            fix_type="code_patch", priority=1, language="python",
            patch_content='''# HEAVEN Auto-Patch: SSTI Prevention
# BEFORE (vulnerable):
# template = Template(user_input)
# result = template.render()

# AFTER (safe — use Jinja2 SandboxedEnvironment):
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(safe_template_string)
result = template.render(user_data=user_input)  # Pass as variable, not template''',
        )]

    def generate_all_patches(self, vulnerabilities: list[dict]) -> list[Patch]:
        """Generate patches for all discovered vulnerabilities."""
        all_patches = []
        for vuln in vulnerabilities:
            patches = self.generate_patch(vuln)
            all_patches.extend(patches)
        logger.info(f"Generated {len(all_patches)} remediation patches for {len(vulnerabilities)} vulnerabilities")
        return all_patches

    def format_report(self, patches: list[Patch]) -> str:
        """Format patches as a readable report."""
        lines = ["# HEAVEN — Auto-Generated Remediation Patches\n"]
        for i, p in enumerate(patches, 1):
            lines.append(f"## {i}. [{p.severity.upper()}] {p.title}")
            lines.append(f"**Vulnerability:** {p.vuln_id} ({p.vuln_type})")
            lines.append(f"**Fix Type:** {p.fix_type}")
            lines.append(f"\n```{p.language}\n{p.patch_content}\n```\n")
        return "\n".join(lines)

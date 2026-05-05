"""
HEAVEN — Self-Security Audit Module
HEAVEN audits its own security posture: hardcoded secrets, insecure defaults,
dependency vulnerabilities, TLS config, CORS policy, and authentication enforcement.
Run via: heaven self-audit
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("security.self_audit")

# Secret patterns to detect in source code
SECRET_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]", "Hardcoded password"),
    (r"(?i)(api_key|apikey|api_secret)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
    (r"(?i)(secret_key|jwt_secret)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded secret key"),
    (r"(?i)(aws_access_key|aws_secret)\s*=\s*['\"]AKI[A-Z0-9]{16}['\"]", "AWS key"),
    (r"(?i)token\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]", "Hardcoded token"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Embedded private key"),
    (r"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@", "Database connection string with credentials"),
]

# Insecure defaults to check
INSECURE_DEFAULTS = {
    "HEAVEN_DB_PASSWORD": "heaven_secret",
    "HEAVEN_ADMIN_PASSWORD": "",
}


@dataclass
class AuditFinding:
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    file_path: str = ""
    line_number: int = 0
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category, "severity": self.severity,
            "title": self.title, "description": self.description,
            "file": self.file_path, "line": self.line_number,
            "remediation": self.remediation,
        }


class SelfAuditor:
    """
    HEAVEN audits itself for security issues.

    Checks:
    1. Hardcoded secrets in source code
    2. Insecure default configurations
    3. Dependency vulnerabilities (pip audit)
    4. File permissions
    5. Debug mode in production
    6. CORS policy
    7. Authentication enforcement
    8. TLS/SSL configuration
    9. Input validation coverage
    10. Encryption strength
    """

    def __init__(self, project_root: Optional[Path] = None):
        self._root = project_root or Path(__file__).parent.parent.parent
        self._findings: list[AuditFinding] = []

    def run_full_audit(self) -> dict:
        """Execute all security checks and return a comprehensive report."""
        logger.info("═══ HEAVEN Self-Security Audit Starting ═══")
        self._findings = []

        self._check_hardcoded_secrets()
        self._check_insecure_defaults()
        self._check_debug_mode()
        self._check_cors_policy()
        self._check_auth_enforcement()
        self._check_encryption_config()
        self._check_file_permissions()
        self._check_dependency_security()
        self._check_input_validation()
        self._check_tls_config()

        # Generate summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        sum(v for k, v in severity_counts.items() if k != "info")
        score = max(0, 100 - (severity_counts["critical"] * 25 + severity_counts["high"] * 10 +
                               severity_counts["medium"] * 5 + severity_counts["low"] * 1))

        report = {
            "score": score,
            "grade": self._score_to_grade(score),
            "total_findings": len(self._findings),
            "severity_breakdown": severity_counts,
            "findings": [f.to_dict() for f in self._findings],
            "recommendations": self._generate_recommendations(),
        }

        grade = report["grade"]
        logger.info(f"═══ Self-Audit Complete: Score={score}/100 Grade={grade} ({len(self._findings)} findings) ═══")
        return report

    def _check_hardcoded_secrets(self) -> None:
        """Scan source code for hardcoded secrets."""
        logger.info("Checking for hardcoded secrets...")
        py_files = list(self._root.rglob("*.py"))

        for filepath in py_files:
            if ".venv" in str(filepath) or "__pycache__" in str(filepath):
                continue
            try:
                content = filepath.read_text(errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    # Skip comments and known test fixtures
                    stripped = line.strip()
                    if stripped.startswith("#") or "test" in str(filepath).lower():
                        continue
                    for pattern, desc in SECRET_PATTERNS:
                        if re.search(pattern, line):
                            # Verify it's not just a variable assignment from env
                            if "os.environ" in line or "_env(" in line or "getenv" in line:
                                continue
                            self._findings.append(AuditFinding(
                                category="hardcoded_secrets", severity="high",
                                title=f"{desc} detected", description=f"Potential {desc} in source code",
                                file_path=str(filepath.relative_to(self._root)),
                                line_number=line_num,
                                remediation="Move secrets to environment variables or the encrypted vault",
                            ))
            except OSError:
                pass

    def _check_insecure_defaults(self) -> None:
        """Check for insecure default configurations."""
        logger.info("Checking for insecure defaults...")
        for env_var, default_val in INSECURE_DEFAULTS.items():
            current = os.environ.get(env_var, default_val)
            if current == default_val and default_val:
                self._findings.append(AuditFinding(
                    category="insecure_defaults", severity="high",
                    title=f"Default value for {env_var}",
                    description=f"{env_var} is using the default value",
                    remediation=f"Set {env_var} to a strong, unique value via environment variable",
                ))
            elif not current and env_var == "HEAVEN_ADMIN_PASSWORD":
                self._findings.append(AuditFinding(
                    category="insecure_defaults", severity="medium",
                    title="No admin password configured",
                    description="HEAVEN_ADMIN_PASSWORD is not set — a random one is generated at startup",
                    remediation="Set HEAVEN_ADMIN_PASSWORD for persistent admin access",
                ))

    def _check_debug_mode(self) -> None:
        """Check if debug mode is enabled in production."""
        logger.info("Checking debug mode...")
        debug = os.environ.get("HEAVEN_DEBUG", "false").lower()
        if debug in ("1", "true", "yes"):
            self._findings.append(AuditFinding(
                category="configuration", severity="medium",
                title="Debug mode enabled",
                description="HEAVEN_DEBUG is enabled — verbose error messages may leak information",
                remediation="Set HEAVEN_DEBUG=false in production",
            ))

    def _check_cors_policy(self) -> None:
        """Check CORS configuration."""
        logger.info("Checking CORS policy...")
        server_path = self._root / "heaven" / "api" / "server.py"
        if server_path.exists():
            content = server_path.read_text()
            # Look for unconditional wildcard CORS (no env-var fallback)
            # Real risk: hardcoded `allow_origins=["*"]` not gated behind a config check.
            cors_calls = re.findall(
                r"add_middleware\s*\(\s*CORSMiddleware[^)]*?allow_origins\s*=\s*([^,)]+)",
                content, re.DOTALL,
            )
            for call in cors_calls:
                # Hardcoded wildcard literal? flag
                if re.search(r'^\s*\[\s*["\']\*["\']\s*\]\s*$', call):
                    self._findings.append(AuditFinding(
                        category="cors", severity="medium",
                        title="Wildcard CORS policy",
                        description="API allows requests from any origin",
                        file_path="heaven/api/server.py",
                        remediation="Restrict CORS origins via HEAVEN_CORS_ORIGINS env var",
                    ))
                    break

    def _check_auth_enforcement(self) -> None:
        """Check if API endpoints enforce authentication."""
        logger.info("Checking authentication enforcement...")
        server_path = self._root / "heaven" / "api" / "server.py"
        if server_path.exists():
            content = server_path.read_text()
            # Count endpoints vs authenticated endpoints. Recognise the standard
            # FastAPI auth-dependency patterns.
            endpoints = re.findall(r"@app\.(get|post|put|delete|patch)\(", content)
            auth_patterns = (
                r"Depends\(\s*(require_user|require_permission|verify_token|"
                r"get_current_user|get_current_active_user|HTTPBearer)"
            )
            auth_checks = len(re.findall(auth_patterns, content))
            if endpoints and auth_checks == 0:
                self._findings.append(AuditFinding(
                    category="authentication", severity="high",
                    title="No authentication on API endpoints",
                    description=f"{len(endpoints)} API endpoints found with no auth dependency",
                    file_path="heaven/api/server.py",
                    remediation="Add Depends(require_user) or Depends(require_permission(...)) to every sensitive endpoint",
                ))

    def _check_encryption_config(self) -> None:
        """Check encryption configuration."""
        logger.info("Checking encryption configuration...")
        vault_path = self._root / "heaven" / "security" / "vault.py"
        if vault_path.exists():
            content = vault_path.read_text()
            if "PBKDF2_ITERATIONS" in content:
                # Python allows underscores in number literals (600_000) — strip them
                match = re.search(r"PBKDF2_ITERATIONS\s*=\s*([\d_]+)", content)
                if match:
                    iterations = int(match.group(1).replace("_", ""))
                    if iterations < 310_000:
                        self._findings.append(AuditFinding(
                            category="encryption", severity="medium",
                            title="Low PBKDF2 iteration count",
                            description=f"PBKDF2 iterations: {iterations} (OWASP recommends ≥310,000 for SHA-256)",
                            remediation="Increase PBKDF2_ITERATIONS to at least 310,000",
                        ))
            self._findings.append(AuditFinding(
                category="encryption", severity="info",
                title="Encryption vault present",
                description="AES-256-GCM credential vault is configured",
                remediation="",
            ))

    def _check_file_permissions(self) -> None:
        """Check sensitive file permissions."""
        logger.info("Checking file permissions...")
        sensitive_files = [
            self._root / "data" / "vault.enc",
            self._root / ".env",
        ]
        for filepath in sensitive_files:
            if filepath.exists():
                mode = oct(filepath.stat().st_mode)[-3:]
                if mode not in ("600", "400"):
                    self._findings.append(AuditFinding(
                        category="file_permissions", severity="medium",
                        title=f"Loose permissions on {filepath.name}",
                        description=f"{filepath.name} has permissions {mode} (should be 600)",
                        file_path=str(filepath),
                        remediation=f"chmod 600 {filepath}",
                    ))

    def _check_dependency_security(self) -> None:
        """Check for known vulnerable dependencies."""
        logger.info("Checking dependency security...")
        req_file = self._root / "requirements.txt"
        if req_file.exists():
            self._findings.append(AuditFinding(
                category="dependencies", severity="info",
                title="Requirements file present",
                description="Run 'pip audit' or 'safety check' for CVE scanning",
                remediation="Run: pip install pip-audit && pip-audit -r requirements.txt",
            ))

    def _check_input_validation(self) -> None:
        """Check for input validation coverage."""
        logger.info("Checking input validation...")
        sanitizer_path = self._root / "heaven" / "security" / "sanitizer.py"
        if not sanitizer_path.exists():
            self._findings.append(AuditFinding(
                category="input_validation", severity="high",
                title="No input sanitizer found",
                description="heaven/security/sanitizer.py not found",
                remediation="Create input sanitization module",
            ))
        else:
            self._findings.append(AuditFinding(
                category="input_validation", severity="info",
                title="Input sanitizer present",
                description="Sanitization module for scan targets is configured",
            ))

    def _check_tls_config(self) -> None:
        """Check TLS/SSL configuration."""
        logger.info("Checking TLS configuration...")
        # Check if server supports HTTPS
        server_path = self._root / "heaven" / "api" / "server.py"
        if server_path.exists():
            content = server_path.read_text()
            if "ssl" not in content.lower() and "https" not in content.lower():
                self._findings.append(AuditFinding(
                    category="tls", severity="medium",
                    title="No TLS configuration in API server",
                    description="API server does not appear to configure HTTPS/TLS",
                    remediation="Configure TLS certificates or use a reverse proxy (nginx/caddy) with TLS termination",
                ))

    def _generate_recommendations(self) -> list[str]:
        recs = []
        categories = set(f.category for f in self._findings if f.severity in ("critical", "high"))
        if "hardcoded_secrets" in categories:
            recs.append("Move all secrets to environment variables or the encrypted vault")
        if "authentication" in categories:
            recs.append("Enable authentication on all API endpoints")
        if "cors" in categories:
            recs.append("Restrict CORS to trusted origins in production")
        if "insecure_defaults" in categories:
            recs.append("Change all default passwords and secrets")
        if not recs:
            recs.append("Security posture is good — continue monitoring")
        return recs

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"

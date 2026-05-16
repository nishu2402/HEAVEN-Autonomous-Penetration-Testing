"""
HEAVEN — Git Repository Secret Scanner
Scans repos for hardcoded secrets using regex patterns and Shannon entropy analysis.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.secrets")

# Secret detection patterns with high-confidence regexes
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (name, pattern, secret_type)
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "aws_key"),
    ("AWS Secret Key", r"""(?:aws_secret|secret_key|AWS_SECRET)['":\s=]+['"]*([A-Za-z0-9/+=]{40})['"]*""", "aws_key"),
    ("GitHub Token", r"gh[ps]_[0-9a-zA-Z]{36}", "github_token"),
    ("GitHub OAuth", r"gho_[0-9a-zA-Z]{36}", "github_token"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "google_api"),
    ("Stripe Secret", r"sk_live_[0-9a-zA-Z]{24,}", "stripe_key"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}", "stripe_key"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "slack_token"),
    ("Slack Webhook", r"hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[a-zA-Z0-9]{24}", "slack_token"),
    ("Private Key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("JWT Secret", r"""(?:jwt[_-]?secret|JWT_SECRET)['":\s=]+['"]([^'"]{8,})['"]\s""", "jwt_secret"),
    ("Database URL", r"(?:mysql|postgres|postgresql|mongodb)://[^\s'\"]{10,}", "database_url"),
    ("Password Assignment", r"""(?:password|passwd|pwd)['":\s=]+['"]([^'"]{8,})['"]""", "password"),
    ("Twilio Key", r"SK[0-9a-fA-F]{32}", "generic_secret"),
    ("SendGrid Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "generic_secret"),
    ("Heroku API", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "generic_secret"),
]

IGNORE_EXTENSIONS = {".jpg", ".png", ".gif", ".ico", ".svg", ".woff", ".ttf", ".eot", ".mp4", ".zip", ".tar", ".gz", ".pdf", ".exe", ".dll", ".so", ".pyc", ".class"}
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    pattern_name: str
    snippet: str
    entropy: float
    commit_hash: str = ""
    commit_date: str = ""
    author: str = ""


def scan_file(file_path: Path, base_dir: Optional[Path] = None) -> list[SecretFinding]:
    """Scan a single file for secrets."""
    findings: list[SecretFinding] = []
    if file_path.suffix in IGNORE_EXTENSIONS:
        return findings
    try:
        content = file_path.read_text(errors="replace")
    except Exception:
        return findings

    rel_path = str(file_path.relative_to(base_dir)) if base_dir else str(file_path)

    for line_num, line in enumerate(content.splitlines(), 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
            continue

        for name, pattern, sec_type in SECRET_PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                secret_text = match.group(0)
                entropy = shannon_entropy(secret_text)

                # Skip low-entropy matches for generic patterns
                if sec_type == "generic_secret" and entropy < 3.0:
                    continue
                # Skip common false positives
                if any(fp in secret_text.lower() for fp in ["example", "placeholder", "xxx", "test", "dummy", "sample"]):
                    continue

                snippet = line_stripped[:200]
                findings.append(SecretFinding(
                    file_path=rel_path, line_number=line_num,
                    secret_type=sec_type, pattern_name=name,
                    snippet=snippet, entropy=round(entropy, 2),
                ))
    return findings


def scan_git_history(repo_path: Path, max_commits: int = 500) -> list[SecretFinding]:
    """Scan git history for secrets in past commits."""
    findings: list[SecretFinding] = []
    try:
        result = subprocess.run(
            ["git", "log", f"--max-count={max_commits}", "--diff-filter=A", "--name-only", "--pretty=format:%H|%aI|%an"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return findings

        current_commit = ""
        current_date = ""
        current_author = ""

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "|" in line and len(line.split("|")) == 3:
                parts = line.split("|")
                current_commit = parts[0]
                current_date = parts[1]
                current_author = parts[2]
            else:
                file_path = repo_path / line
                if file_path.exists() and file_path.is_file():
                    file_findings = scan_file(file_path, repo_path)
                    for f in file_findings:
                        f.commit_hash = current_commit
                        f.commit_date = current_date
                        f.author = current_author
                    findings.extend(file_findings)

    except Exception as e:
        logger.debug(f"Git history scan error: {e}")

    return findings


async def scan_repository(repo_path: str, include_history: bool = True) -> list[SecretFinding]:
    """Scan a local or remote repository for secrets."""
    import shutil as _shutil
    loop = asyncio.get_running_loop()
    path = Path(repo_path)
    temp_dir = None

    is_remote = repo_path.startswith(("http://", "https://", "git@"))
    # 'git' is an external binary — without this guard a missing git raises an
    # uncaught FileNotFoundError on clone and aborts the whole scan pipeline.
    if (is_remote or include_history) and _shutil.which("git") is None:
        logger.warning("git binary not found on PATH — git-secrets scan skipped")
        return []

    try:
        # Clone remote repos
        if is_remote:
            temp_dir = tempfile.mkdtemp(prefix="heaven_repo_")
            path = Path(temp_dir)
            result = await loop.run_in_executor(None, lambda: subprocess.run(
                ["git", "clone", "--depth=50", repo_path, str(path)],
                capture_output=True, text=True, timeout=120,
            ))
            if result.returncode != 0:
                logger.error(f"Failed to clone {repo_path}: {result.stderr}")
                return []

        findings: list[SecretFinding] = []

        # Scan current files
        for root, dirs, files in os.walk(str(path)):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                file_path = Path(root) / fname
                file_findings = await loop.run_in_executor(None, scan_file, file_path, path)
                findings.extend(file_findings)

        # Scan git history
        if include_history and (path / ".git").exists():
            history_findings = await loop.run_in_executor(None, scan_git_history, path)
            findings.extend(history_findings)

        return findings

    finally:
        # Cleanup temp clone even on exceptions
        if temp_dir:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


async def scan_repositories(repos: Optional[list[str]] = None, **kwargs) -> dict[str, Any]:
    """Main entry point (called by orchestrator)."""
    if not repos:
        logger.info("No repositories specified — skipping secret scan")
        return {"secrets": [], "total": 0}

    all_findings: list[SecretFinding] = []
    for repo in repos:
        findings = await scan_repository(repo)
        all_findings.extend(findings)
        logger.info(f"  {repo}: {len(findings)} secrets found")

    by_type: dict[str, int] = {}
    for f in all_findings:
        by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1

    logger.info(f"Secret scan: {len(all_findings)} total secrets in {len(repos)} repos")

    return {
        "secrets": [
            {"file": f.file_path, "line": f.line_number, "type": f.secret_type,
             "pattern": f.pattern_name, "entropy": f.entropy,
             "snippet": f.snippet[:100], "commit": f.commit_hash[:8] if f.commit_hash else ""}
            for f in all_findings
        ],
        "total": len(all_findings),
        "by_type": by_type,
    }

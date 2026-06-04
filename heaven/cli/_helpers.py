"""
HEAVEN — CLI shared helpers
Pure helpers used across the heaven.cli subcommands. No click dependency.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

from heaven.utils.logger import HAS_RICH, get_logger

logger = get_logger("cli.helpers")


# Target validation regex — single-escaped (these are normal Python strings, not raw)
_IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
_HOST_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")
_URL_REGEX = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)


def _print(msg: str) -> None:
    """Print with Rich console if available, else plain print."""
    if HAS_RICH:
        from heaven.utils.logger import console
        if console:
            console.print(msg)
            return
    plain = re.sub(r"\[/?[^\]]+\]", "", msg)
    print(plain)


def _validate_target_string(t: str) -> tuple[bool, str]:
    """Return (is_valid, kind) where kind is 'ip' | 'host' | 'invalid'."""
    if _IP_REGEX.match(t):
        return True, "ip"
    if _HOST_REGEX.match(t) and "." in t:
        return True, "host"
    return False, "invalid"


def _verify_authorization(targets: dict, ack_flag: bool) -> bool:
    """
    Scope/authorization gate. Tool refuses to scan unless operator explicitly
    acknowledges they have written authorization for every target.

    Override mechanisms (priority order):
      1. --i-have-authorization flag (explicit per-run ack)
      2. HEAVEN_AUTHORIZED_SCOPE env var (newline/comma-separated allowed targets)
      3. Interactive confirm (TTY only)
    """
    all_targets = (
        list(targets.get("ips", []))
        + list(targets.get("urls", []))
        + list(targets.get("repositories", []))
        + list(targets.get("cloud_providers", []))
    )
    if targets.get("ad_domain"):
        all_targets.append(targets["ad_domain"])

    if not all_targets:
        return True  # Nothing to scan, nothing to authorize

    if ack_flag:
        logger.warning("Authorization acknowledged via --i-have-authorization flag")
        return True

    scope_env = os.environ.get("HEAVEN_AUTHORIZED_SCOPE", "").strip()
    if scope_env:
        allowed = {s.strip() for s in re.split(r"[,\n]", scope_env) if s.strip()}
        unauthorized = [t for t in all_targets if t not in allowed]
        if not unauthorized:
            logger.info(f"All {len(all_targets)} targets present in HEAVEN_AUTHORIZED_SCOPE")
            return True
        _print(f"[bold red]Authorization failure:[/bold red] {len(unauthorized)} target(s) not in HEAVEN_AUTHORIZED_SCOPE")
        for t in unauthorized:
            _print(f"  - {t}")
        return False

    if sys.stdin.isatty():
        _print("\n[bold yellow]⚠ AUTHORIZATION REQUIRED[/bold yellow]")
        _print("HEAVEN performs active vulnerability testing. Scanning systems without")
        _print("written authorization is illegal in most jurisdictions (CFAA in the US,")
        _print("Computer Misuse Act in the UK, and equivalent laws elsewhere).")
        _print("\nTargets you are about to scan:")
        for t in all_targets:
            _print(f"  - {t}")
        try:
            ans = input("\nDo you have written authorization to test ALL listed targets? [y/N]: ").strip().lower()
        except EOFError:
            return False
        if ans in ("y", "yes"):
            logger.warning(f"Authorization acknowledged interactively for {len(all_targets)} targets")
            return True
        _print("[red]Authorization not confirmed. Aborting.[/red]")
        return False

    _print("[bold red]Authorization required.[/bold red]")
    _print("Use --i-have-authorization, set HEAVEN_AUTHORIZED_SCOPE env var, or run interactively.")
    return False


def check_module_health() -> dict:
    """Probe every important module by importing it; report OK/DEGRADED per name."""
    checks = {
        "network_scanner": "heaven.recon.network_scanner",
        "web_crawler": "heaven.recon.web_crawler",
        "risk_model": "heaven.ml.risk_model",
        "nuclei_scanner": "heaven.vulnscan.nuclei_scanner",
        "attack_mapper": "heaven.mitre.attack_mapper",
        "evasion_engine": "heaven.recon.evasion_engine",
        "ai_brain": "heaven.ml.ai_brain",
    }
    results = {}
    for name, module in checks.items():
        try:
            __import__(module)
            results[name] = "OK"
        except Exception as e:
            results[name] = f"DEGRADED: {e}"
    return results


# ── Current-engagement context ────────────────────────────────────────────
# Git-branch-style sticky selection set via `heaven use <name>`, so operators
# stop retyping --engagement on every command. Stored per working directory
# (in ./.heaven/) so separate projects keep independent context.
#
# Resolution precedence used everywhere in the CLI:
#   explicit --engagement flag  >  HEAVEN_ENGAGEMENT env  >  `heaven use`  >  default
_CONTEXT_FILE = Path(".heaven") / "current_engagement"


def get_current_engagement() -> Optional[str]:
    """Return the engagement name set via `heaven use`, or None if unset."""
    try:
        if _CONTEXT_FILE.is_file():
            name = _CONTEXT_FILE.read_text(encoding="utf-8").strip()
            return name or None
    except OSError:
        pass
    return None


def set_current_engagement(name: str) -> Path:
    """Persist the current engagement for this working directory."""
    _CONTEXT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONTEXT_FILE.write_text(name.strip() + "\n", encoding="utf-8")
    return _CONTEXT_FILE


def clear_current_engagement() -> bool:
    """Remove the current-engagement context. True if one existed."""
    try:
        if _CONTEXT_FILE.is_file():
            _CONTEXT_FILE.unlink()
            return True
    except OSError:
        pass
    return False


def resolve_engagement_name(explicit: Optional[str] = None) -> Optional[str]:
    """Effective engagement *name* using the standard precedence.

    explicit flag > HEAVEN_ENGAGEMENT env > `heaven use` context > None.
    """
    if explicit:
        return explicit
    env = os.environ.get("HEAVEN_ENGAGEMENT")
    if env:
        return env
    return get_current_engagement()


def _engagement_db_path(name: Optional[str] = None) -> Path:
    """Resolve the engagement SQLite path.

    Precedence: explicit name > HEAVEN_ENGAGEMENT env > `heaven use` context
    > ./engagement.db default. A bare name maps to ./engagements/<name>.db
    (matching what `heaven engage init` creates).
    """
    if name:
        return Path("engagements") / f"{name}.db"
    env_path = os.environ.get("HEAVEN_ENGAGEMENT")
    if env_path:
        return Path(env_path)
    ctx = get_current_engagement()
    if ctx:
        return Path("engagements") / f"{ctx}.db"
    return Path("engagement.db")

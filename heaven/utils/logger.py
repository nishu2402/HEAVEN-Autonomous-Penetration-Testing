"""
HEAVEN — Structured Logging with Graceful Rich Fallback
Provides HUD-style terminal logging with severity coloring and structured JSON output.
Falls back to standard logging if Rich is not installed.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Optional

# Graceful Rich import — fallback to stdlib if not installed
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.theme import Theme

    HEAVEN_THEME = Theme({
        "info": "cyan",
        "warning": "yellow",
        "error": "red bold",
        "critical": "red on white bold",
        "success": "green bold",
        "scan": "magenta",
        "vuln": "red",
        "asset": "blue",
        "heaven": "bold cyan",
    })

    console = Console(theme=HEAVEN_THEME, stderr=True)
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False


class HeavenFormatter(logging.Formatter):
    """Custom formatter with JSON structured output for file logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage(),
        }
        # Attach extra fields if present
        for key in ("scan_id", "asset", "target", "vuln_id", "phase"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)


class PlainFormatter(logging.Formatter):
    """Coloured plain-text formatter for terminals without Rich."""

    COLORS = {
        "DEBUG": "\033[36m",     # cyan
        "INFO": "\033[32m",      # green
        "WARNING": "\033[33m",   # yellow
        "ERROR": "\033[31m",     # red
        "CRITICAL": "\033[41m",  # red bg
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        ts = datetime.now().strftime("%H:%M:%S")
        return f"{color}[{ts}] {record.levelname:8s}{self.RESET} {record.name}: {record.getMessage()}"


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_output: bool = False,
) -> logging.Logger:
    """Configure HEAVEN logging with Rich console (or fallback) and optional file output."""
    root_logger = logging.getLogger("heaven")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.handlers.clear()

    if HAS_RICH:
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
        )
        rich_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(rich_handler)
    else:
        # Fallback: coloured stderr handler
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(PlainFormatter())
        stream_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(stream_handler)

    # File handler (JSON structured)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(HeavenFormatter())
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the heaven namespace."""
    return logging.getLogger(f"heaven.{name}")


def log_scan_event(logger: logging.Logger, event: str, **kwargs: Any) -> None:
    """Log a structured scan event with extra context."""
    extra = {k: v for k, v in kwargs.items() if v is not None}
    if HAS_RICH:
        logger.info(f"[bold cyan]SCAN[/bold cyan] {event}", extra=extra)
    else:
        logger.info(f"SCAN {event}", extra=extra)


def log_vuln_found(logger: logging.Logger, cve: str, severity: str, target: str, **kwargs) -> None:
    """Log a vulnerability discovery with severity coloring."""
    if HAS_RICH:
        severity_colors = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high": "[red]HIGH[/red]",
            "medium": "[yellow]MEDIUM[/yellow]",
            "low": "[blue]LOW[/blue]",
            "info": "[dim]INFO[/dim]",
        }
        sev_display = severity_colors.get(severity.lower(), severity)
        logger.warning(
            f"[bold red]VULN[/bold red] {sev_display} {cve} on {target}",
            extra={"vuln_id": cve, "target": target, **kwargs},
        )
    else:
        logger.warning(f"VULN [{severity.upper()}] {cve} on {target}",
                       extra={"vuln_id": cve, "target": target, **kwargs})


def print_banner() -> None:
    """Print the HEAVEN ASCII banner."""
    try:
        from heaven import __banner__
        if console:
            console.print(__banner__, style="bold cyan")
        else:
            print(__banner__)
    except (ImportError, AttributeError):
        print("═══ HEAVEN Vulnerability Scanner ═══")

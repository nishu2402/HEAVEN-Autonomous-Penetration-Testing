"""HEAVEN — rich-click presentation layer.

Optional. When `rich-click` is installed, `apply_rich_click()` patches the
`click` module so every command renders with colourised, panel-grouped
``--help`` output, then loads HEAVEN's command/option groupings and theme.

If rich-click is absent the function is a no-op returning ``False`` and the
CLI falls back to plain Click — same commands, just less pretty. Nothing
here changes behaviour; it is purely presentation.
"""

from __future__ import annotations

from typing import Any

# Prog-name aliases HEAVEN can be invoked under. rich-click keys its
# COMMAND_GROUPS / OPTION_GROUPS on the resolved command path, which differs
# between the `heaven` entry point and `python -m heaven.main`. We register
# every alias so the grouped help renders no matter how it was launched.
_PROG_ALIASES = ("heaven", "python -m heaven.main", "main.py", "__main__.py")


# ── Top-level command grouping (fixes the flat 38-command alphabetical dump) ──
_ROOT_COMMAND_GROUPS = [
    {
        "name": "Scanning & Monitoring",
        "commands": ["scan", "resume", "pause", "replay", "watch", "sast"],
    },
    {
        "name": "Engagements & Findings",
        "commands": [
            "engage", "scope", "use", "findings", "show", "mark",
            "status", "diff", "coverage",
        ],
    },
    {
        "name": "Reporting & Tickets",
        "commands": [
            "report", "export", "tickets", "mitre-report",
            "kill-chain", "methodology",
        ],
    },
    {
        "name": "AI & Threat Intel",
        "commands": ["autonomous", "knowledge", "lateral", "exploitdb", "update"],
    },
    {
        "name": "Models",
        "commands": ["train-model", "train-priors"],
    },
    {
        "name": "Platform & Setup",
        "commands": [
            "init", "init-db", "serve", "doctor", "info",
            "self-audit", "completion",
        ],
    },
]


# ── Per-command option grouping (tames the big commands' flag walls) ──
_SCAN_OPTION_GROUPS = [
    {
        "name": "Targets",
        "options": ["--target", "--url", "--repo", "--cloud", "--ad-domain", "--ad-dc"],
    },
    {
        "name": "Scan profile",
        "options": [
            "--mode", "--ports", "--stealth", "--seed",
            "--iot", "--api-scan", "--container", "--mitre-map",
        ],
    },
    {
        "name": "Authorization & scope",
        "options": [
            "--i-have-authorization", "--engagement", "--use-scope",
            "--cookie-file", "--auth",
        ],
    },
    {
        "name": "Exploitation chaining",
        "options": ["--auto-prove", "--autonomous"],
    },
    {
        "name": "Output",
        "options": ["--output", "--output-file", "--watch-tail", "--skip-dep-check"],
    },
]

_WATCH_OPTION_GROUPS = [
    {"name": "Targets", "options": ["--target", "--url"]},
    {
        "name": "Schedule",
        "options": ["--interval", "--jitter", "--max-iterations", "--seed"],
    },
    {"name": "Behaviour", "options": ["--mode", "--heartbeat", "--auto-tickets"]},
    {
        "name": "Authorization",
        "options": ["--engagement", "--i-have-authorization"],
    },
]

# subcommand -> its option groups (keys get prefixed with every prog alias)
_SUBCOMMAND_OPTION_GROUPS = {
    "scan": _SCAN_OPTION_GROUPS,
    "watch": _WATCH_OPTION_GROUPS,
}


def _build_command_groups() -> dict[str, Any]:
    return {alias: _ROOT_COMMAND_GROUPS for alias in _PROG_ALIASES}


def _build_option_groups() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for alias in _PROG_ALIASES:
        for sub, groups in _SUBCOMMAND_OPTION_GROUPS.items():
            out[f"{alias} {sub}"] = groups
    return out


def apply_rich_click() -> bool:
    """Patch click for rich help + load HEAVEN's groups/theme.

    Returns True if rich-click was applied, False if it isn't installed.
    Safe to call once at import time before the subcommands are imported.
    """
    try:
        import rich_click
        from rich_click.patch import patch as _patch
    except Exception:
        return False

    # Make `import click` return rich-enhanced Command/Group/Option classes
    # everywhere downstream. Must run before the cli subcommands are imported.
    try:
        _patch()
    except Exception:
        return False

    cfg = rich_click.rich_click

    def _set(attr: str, value: Any) -> None:
        # Tolerate attribute renames across rich-click versions.
        if hasattr(cfg, attr):
            setattr(cfg, attr, value)

    # Markup mode. Modern rich-click (>=1.9) uses the single TEXT_MARKUP knob;
    # setting the pre-1.9 USE_RICH_MARKUP / USE_MARKDOWN pair on it emits a
    # PendingDeprecationWarning. Prefer the modern attr, fall back to the legacy
    # pair only when TEXT_MARKUP is unavailable (older rich-click).
    if hasattr(cfg, "TEXT_MARKUP"):
        _set("TEXT_MARKUP", "rich")
    else:
        _set("USE_RICH_MARKUP", True)
        _set("USE_MARKDOWN", False)

    # Layout
    _set("SHOW_ARGUMENTS", True)
    _set("GROUP_ARGUMENTS_OPTIONS", True)
    # The metavar column is shown by default on rich-click >=1.9 (metavar is part
    # of OPTIONS_TABLE_COLUMN_TYPES). Only nudge the legacy toggles — which are
    # now deprecated — on older versions that still expose them as the API.
    if not hasattr(cfg, "OPTIONS_TABLE_COLUMN_TYPES"):
        _set("SHOW_METAVARS_COLUMN", True)
        _set("APPEND_METAVARS_HELP", True)
    _set("COMMANDS_BEFORE_OPTIONS", True)
    _set("MAX_WIDTH", 100)

    # Theme — HEAVEN cyan/green accent
    _set("STYLE_OPTION", "bold cyan")
    _set("STYLE_ARGUMENT", "bold cyan")
    _set("STYLE_COMMAND", "bold cyan")
    _set("STYLE_SWITCH", "bold green")
    _set("STYLE_METAVAR", "cyan")
    _set("STYLE_OPTION_DEFAULT", "dim")
    _set("STYLE_REQUIRED_SHORT", "bold red")
    _set("STYLE_OPTIONS_PANEL_BORDER", "cyan")
    _set("STYLE_COMMANDS_PANEL_BORDER", "cyan")
    _set("STYLE_USAGE", "bold yellow")
    _set("STYLE_HELPTEXT", "")
    _set("STYLE_ERRORS_SUGGESTION", "yellow")

    # Groupings
    _set("COMMAND_GROUPS", _build_command_groups())
    _set("OPTION_GROUPS", _build_option_groups())

    _set(
        "FOOTER_TEXT",
        "Run [cyan]heaven <command> --help[/] for full options · "
        "always confirm written authorization before scanning.",
    )
    return True

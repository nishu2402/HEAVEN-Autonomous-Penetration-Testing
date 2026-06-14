"""HEAVEN — `heaven init` interactive first-time-setup wizard.

Asks the operator the bare minimum to bring HEAVEN to "ready":
  - HEAVEN_ADMIN_USERNAME       (optional; Web UI login name, defaults to "admin")
  - HEAVEN_ADMIN_PASSWORD       (mandatory; gates the Web UI)
  - HEAVEN_DB_PASSWORD          (mandatory; gates SQLite + optional Postgres)
  - HEAVEN_LLM_PROVIDER + key   (optional; enables Layers B/D/E/autonomous)
  - HEAVEN_NVD_API_KEY          (optional; 30x faster NVD ingestion)
  - HEAVEN_SHODAN_API_KEY       (optional; enables passive recon)
  - HEAVEN_AUTHORIZED_SCOPE     (optional; pre-authorize a target list)

Writes the result to .env in the current directory. Idempotent — if .env
already exists, offers to update individual keys.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print
from heaven.settings_catalog import SETTINGS

# Mandatory / non-API-key settings the wizard handles itself, followed by every
# catalogued key (in catalog order) so the written .env stays well-ordered and
# the wizard never drifts from `heaven config` / the web-UI Settings page.
_MANDATORY_ORDER = [
    "HEAVEN_ADMIN_USERNAME",
    "HEAVEN_ADMIN_PASSWORD",
    "HEAVEN_DB_PASSWORD",
    "HEAVEN_AUTHORIZED_SCOPE",
]
_ENV_KEYS_ORDER = _MANDATORY_ORDER + [s.key for s in SETTINGS]


def _load_env(path: Path) -> dict[str, str]:
    """Parse a .env file. Tolerant of comments + blank lines."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _write_env(path: Path, values: dict[str, str]) -> None:
    """Write a .env file preserving the documented key order. Unknown keys
    are appended in alphabetical order so we don't lose operator customisations."""
    lines: list[str] = [
        "# HEAVEN environment variables — written by `heaven init`",
        "# Do not commit this file. Add to .gitignore if not already there.",
        "",
    ]
    seen: set[str] = set()
    for k in _ENV_KEYS_ORDER:
        if k in values:
            lines.append(f"{k}={_quote(values[k])}")
            seen.add(k)
    remaining = sorted(set(values) - seen)
    if remaining:
        lines.append("")
        lines.append("# Custom keys (preserved from existing .env)")
        for k in remaining:
            lines.append(f"{k}={_quote(values[k])}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _quote(v: str) -> str:
    if not v:
        return ""
    if any(c in v for c in (" ", "#", "$", "\"", "'")):
        return '"' + v.replace('"', r'\"') + '"'
    return v


def _prompt(label: str, default: Optional[str] = None, *,
            hide: bool = False, allow_empty: bool = False) -> str:
    """Like click.prompt but with HEAVEN-aware defaults + skip-empty."""
    while True:
        suffix = f" [{default}]" if default and not hide else ""
        if hide:
            suffix = " (hidden)" if not default else " (hidden, press Enter to keep current)"
        v = click.prompt(label + suffix, default="", hide_input=hide, show_default=False)
        if v == "":
            if default is not None:
                return default
            if allow_empty:
                return ""
            _print("[yellow]Value required.[/yellow]")
            continue
        return v


@click.command(name="init")
@click.option("--env-file", default=".env", type=click.Path(),
              help="Where to write the env file. Default: .env in current directory.")
@click.option("--minimal", is_flag=True,
              help="Skip optional integration prompts (LLM, SIEM, ticketing). "
                   "Only asks for the two mandatory passwords.")
@click.option("--non-interactive", is_flag=True,
              help="Generate strong defaults for both passwords + leave optional "
                   "keys blank. For CI / unattended provisioning.")
def init_cmd(env_file: str, minimal: bool, non_interactive: bool) -> None:
    """Interactive first-time-setup wizard.

    Writes a .env file with the mandatory passwords + any optional API
    keys you want to configure (LLM, SIEM, ticketing, NVD, Shodan).
    Idempotent — re-running offers to update individual keys without
    overwriting the ones you've already set.
    """
    env_path = Path(env_file).resolve()
    existing = _load_env(env_path)

    _print("[bold cyan]🚀 HEAVEN first-time setup[/bold cyan]")
    if existing:
        _print(f"  [dim]Found existing {env_path} — updating in place[/dim]")
    else:
        _print(f"  [dim]Writing fresh {env_path}[/dim]")
    _print("")

    values = dict(existing)

    # ── Mandatory passwords ────────────────────────────────────────────
    _print("[bold]Required[/bold]")

    if non_interactive:
        admin = existing.get("HEAVEN_ADMIN_PASSWORD") or secrets.token_urlsafe(24)
        dbpw  = existing.get("HEAVEN_DB_PASSWORD") or secrets.token_urlsafe(24)
        values["HEAVEN_ADMIN_USERNAME"] = existing.get("HEAVEN_ADMIN_USERNAME", "admin")
        values["HEAVEN_ADMIN_PASSWORD"] = admin
        values["HEAVEN_DB_PASSWORD"] = dbpw
        _print(f"  HEAVEN_ADMIN_USERNAME = [green]{values['HEAVEN_ADMIN_USERNAME']}[/green]")
        _print(f"  HEAVEN_ADMIN_PASSWORD = [green]{admin}[/green] (generated)")
        _print(f"  HEAVEN_DB_PASSWORD    = [green]{dbpw}[/green] (generated)")
    else:
        # Admin username — what you'll log into the Web UI with and what the
        # header badge shows (so it's no longer a generic "admin").
        admin_user = _prompt(
            "Web UI admin username",
            default=existing.get("HEAVEN_ADMIN_USERNAME", "") or "admin",
        )
        values["HEAVEN_ADMIN_USERNAME"] = admin_user

        current_admin = existing.get("HEAVEN_ADMIN_PASSWORD", "")
        admin = _prompt(
            "Web UI admin password (24+ chars recommended)",
            default=current_admin or secrets.token_urlsafe(24),
            hide=True,
        )
        values["HEAVEN_ADMIN_PASSWORD"] = admin

        current_db = existing.get("HEAVEN_DB_PASSWORD", "")
        dbpw = _prompt(
            "Database password (used by SQLite + optional Postgres)",
            default=current_db or secrets.token_urlsafe(24),
            hide=True,
        )
        values["HEAVEN_DB_PASSWORD"] = dbpw

    if minimal or non_interactive:
        _write_env(env_path, values)
        _print(f"\n[green]Wrote[/green] {env_path}")
        _print("[dim]Re-run `heaven init` without --minimal to configure "
               "LLM / SIEM / ticketing.[/dim]")
        return

    # ── Optional: LLM for the AI layers ─────────────────────────────────
    _print("\n[bold]LLM for AI layers[/bold] (Layer B/D/E + autonomous loop)")
    _print("  [dim]Optional — HEAVEN runs fully without it ([cyan]--no-llm[/cyan]). "
           "Press Enter to skip.[/dim]")
    _print("  [dim]Get a key:  Gemini (free) https://aistudio.google.com/apikey"
           "  ·  Anthropic https://console.anthropic.com"
           "  ·  OpenAI https://platform.openai.com/api-keys[/dim]")
    provider = _prompt("Provider [anthropic/openai/gemini] (Enter to skip)",
                       default=existing.get("HEAVEN_LLM_PROVIDER", ""),
                       allow_empty=True).lower().strip()
    if provider in ("anthropic", "openai", "gemini"):
        values["HEAVEN_LLM_PROVIDER"] = provider
        key_var = {"anthropic": "ANTHROPIC_API_KEY",
                   "openai": "OPENAI_API_KEY",
                   "gemini": "GEMINI_API_KEY"}[provider]
        pip_pkg = {"anthropic": "anthropic",
                   "openai": "openai",
                   "gemini": "google-genai"}[provider]
        api_key = _prompt(f"{key_var}",
                          default=existing.get(key_var, ""),
                          hide=True, allow_empty=True)
        if api_key:
            values[key_var] = api_key
        # NOTE: don't print the ".[gemini]" extras form here — Rich (and the
        # plain-text fallback) both treat the square brackets as markup and
        # eat them, so it rendered as `pip install -e "."`. The plain package
        # name is unambiguous and is all the user needs.
        _print(f"  [dim]Install the SDK:  [cyan]pip install {pip_pkg}[/cyan][/dim]")

    # ── Optional: API keys & integrations (recon / alerting / SIEM / ticketing) ──
    # This is the wizard's API-key setup. It's driven by the shared settings
    # catalog so the wizard, `heaven config`, and the web-UI Settings page always
    # offer the EXACT same keys + help text + where-to-get links — change a key
    # in one place (heaven/settings_catalog.py) and all three update together.
    _print("\n[bold]API keys & integrations[/bold] "
           "[dim](all optional — press Enter to skip any)[/dim]")
    shown_group: Optional[str] = None
    for spec in SETTINGS:
        if spec.group == "AI / LLM":
            continue  # the LLM provider + key are configured in the section above
        if spec.group != shown_group:
            shown_group = spec.group
            _print(f"\n  [bold cyan]{spec.group}[/bold cyan]")
        # A descriptive line per key: what it unlocks + where to get it.
        hint = spec.help
        if spec.url:
            hint += f"   Get it: {spec.url}"
        _print(f"    [dim]{hint}[/dim]")
        v = _prompt(f"  {spec.label}", default=existing.get(spec.key, ""),
                    hide=spec.secret, allow_empty=True)
        if v:
            values[spec.key] = v

    _write_env(env_path, values)
    _print(f"\n[green]✓ Wrote[/green] {env_path}")

    # ── Helpful next-steps reminder ────────────────────────────────────
    # HEAVEN auto-loads .env from the working directory on every command, so
    # there's no `source .env` / `export` step — just run from this directory.
    is_default = env_path == (Path.cwd() / ".env").resolve()
    _print("\n[bold]Next steps:[/bold]")
    _print(f"  [dim]HEAVEN auto-loads {env_path.name} from this directory — "
           "no need to `source` or `export` it.[/dim]")
    if not is_default:
        _print(f"  [dim](custom path — pass [cyan]--config-file {env_path}[/cyan] "
               "or run from its directory)[/dim]")
    _print( "  1. Create your first engagement: [cyan]heaven engage init <name>[/cyan]")
    _print( "  2. Add a target with criticality: "
            "[cyan]heaven scope add <target> --criticality high[/cyan]")
    _print( "  3. Launch the UI:               [cyan]heaven serve[/cyan]")

    # ── Reminder about gitignore ───────────────────────────────────────
    gi = Path(".gitignore")
    if gi.exists() and ".env" not in gi.read_text(encoding="utf-8"):
        _print("\n[yellow]⚠ .env is not in your .gitignore — add it to avoid "
               "committing secrets.[/yellow]")


def register(cli: click.Group) -> None:
    # The existing `init-db` command (PostgreSQL schema init) is kept; this
    # adds the new `init` interactive wizard at the same group.
    cli.add_command(init_cmd)

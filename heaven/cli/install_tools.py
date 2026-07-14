"""HEAVEN — `heaven install-tools` command.

Installs the external security binaries HEAVEN shells out to (nmap, nuclei,
sqlmap, ffuf, searchsploit, semgrep, docker) using this host's package manager
so the scanner runs at full power. Idempotent — already-present tools are
skipped — and driven by the shared catalog in ``heaven.utils.tool_installer``,
so the tool list and install recipes stay in lock-step with ``heaven doctor``
and the web System-Health panel.
"""

from __future__ import annotations

import click

from heaven.cli._helpers import _print, emit_json, json_output
from heaven.utils.tool_installer import (
    TOOLS,
    InstallResult,
    ToolSpec,
    build_install_command,
    get_spec,
    install_hint,
    install_tools,
    is_present,
    missing_tools,
)

_STATUS_MARK = {
    "present": "[green]✓[/green]",
    "installed": "[green]✓[/green]",
    "planned": "[cyan]▸[/cyan]",
    "manual": "[yellow]·[/yellow]",
    "failed": "[red]✗[/red]",
}
_STATUS_WORD = {
    "present": "already installed",
    "installed": "installed",
    "planned": "would install",
    "manual": "manual install needed",
    "failed": "install failed",
}


@click.command(name="install-tools")
@click.argument("tools", nargs=-1)
@click.option("--yes", "-y", is_flag=True,
              help="Install without the confirmation prompt (for scripts/CI).")
@click.option("--dry-run", is_flag=True,
              help="Show what would be installed, without changing anything.")
def install_tools_cmd(tools: tuple[str, ...], yes: bool, dry_run: bool) -> None:
    """Install the external scanner binaries HEAVEN uses (full-power mode).

    With no arguments, installs every tool that is missing. Name specific tools
    to limit the scope:

        heaven install-tools                 # everything missing
        heaven install-tools sqlmap ffuf     # just these two
        heaven install-tools --dry-run       # preview the commands

    Each tool has an in-house fallback, so HEAVEN works without them — but with
    them installed you get real SQLi proof, content fuzzing, Exploit-DB lookup,
    SAST and template checks. Uses your package manager (brew / apt / dnf /
    pacman) or pip / go as appropriate.
    """
    as_json = json_output()

    # Resolve the requested subset (validate names) or default to all missing.
    if tools:
        specs: list[ToolSpec] = []
        unknown: list[str] = []
        for name in tools:
            spec = get_spec(name)
            (specs.append(spec) if spec else unknown.append(name))  # type: ignore[arg-type]
        if unknown:
            known = ", ".join(t.name for t in TOOLS)
            msg = f"Unknown tool(s): {', '.join(unknown)}. Known: {known}"
            if as_json:
                emit_json({"ok": False, "error": msg})
            else:
                _print(f"[red]✗[/red] {msg}")
            raise SystemExit(2)
    else:
        specs = missing_tools()

    # Nothing to do?
    pending = [s for s in specs if not is_present(s.name)]
    if not pending:
        if as_json:
            emit_json({"ok": True, "installed": [], "results":
                       [{"name": s.name, "status": "present"} for s in specs]})
        else:
            _print("[green]✓ All requested tools are already installed.[/green] "
                   "Run [cyan]heaven doctor[/cyan] to confirm.")
        return

    # Preview the plan.
    if not as_json:
        _print("[bold]HEAVEN — external tool install[/bold]")
        _print("")
        for s in pending:
            cmd = build_install_command(s)
            recipe = " ".join(cmd) if cmd else f"[yellow]manual: {install_hint(s)}[/yellow]"
            _print(f"  [cyan]{s.name:13}[/cyan] {s.purpose}")
            _print(f"  {'':13} [dim]{recipe}[/dim]")
        _print("")

    if dry_run:
        results = install_tools(pending, dry_run=True)
        _emit_results(results, as_json, dry_run=True)
        return

    # Confirm unless --yes (or --json, which is non-interactive by contract).
    if not yes and not as_json:
        if not click.confirm(f"Install {len(pending)} tool(s) now?", default=True):
            _print("[dim]Aborted — nothing was installed.[/dim]")
            return

    def _line(text: str) -> None:
        if not as_json:
            _print(f"[dim]{text}[/dim]")

    results = install_tools(pending, on_output=None if as_json else _line)
    _emit_results(results, as_json, dry_run=False)

    # Non-zero exit when something genuinely failed, so CI/install.sh can react.
    if any(r.status == "failed" for r in results):
        raise SystemExit(1)


def _emit_results(results: list[InstallResult], as_json: bool, *, dry_run: bool) -> None:
    if as_json:
        emit_json({
            "ok": all(r.ok for r in results),
            "dry_run": dry_run,
            "results": [
                {"name": r.name, "status": r.status,
                 "command": r.command, "detail": r.detail}
                for r in results
            ],
        })
        return

    _print("")
    _print("[bold]Result[/bold]")
    for r in results:
        mark = _STATUS_MARK.get(r.status, "·")
        word = _STATUS_WORD.get(r.status, r.status)
        extra = f"  [dim]{r.detail}[/dim]" if r.detail else ""
        _print(f"  {mark} {r.name:13} {word}{extra}")
    if any(r.status == "manual" for r in results):
        _print("")
        _print("[yellow]Some tools need a manual install[/yellow] — see the recipe above.")
    if any(r.status == "failed" for r in results):
        _print("")
        _print("[yellow]Some installs failed.[/yellow] Re-run with the recipe shown, "
               "then verify with [cyan]heaven doctor[/cyan].")
    else:
        _print("")
        _print("Verify with [cyan]heaven doctor[/cyan].")


def register(cli: click.Group) -> None:
    cli.add_command(install_tools_cmd)

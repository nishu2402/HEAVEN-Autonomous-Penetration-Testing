"""HEAVEN — `heaven install-tools` command.

Installs the external security binaries HEAVEN shells out to (nmap, nuclei,
sqlmap, ffuf, searchsploit, semgrep, docker) using this host's package manager
so the scanner runs at full power. Idempotent — already-present tools are
skipped — and driven by the shared catalog in ``heaven.utils.tool_installer``,
so the tool list and install recipes stay in lock-step with ``heaven doctor``
and the web System-Health panel.

It also arms the **Playwright Chromium** browser bundle (the one runtime
capability that is not a PATH binary), because a missing browser caps HEAVEN
below full power exactly like a missing scanner: without it the JS-rendered
SPA crawl and the XSS execution proof silently degrade. Folding it in here means
the single command operators already run for "full power" leaves nothing armed
only by a separate, easily-missed ``playwright install`` incantation.
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

# Names that select the Playwright browser bundle rather than a PATH binary, so
# `heaven install-tools browser` (or playwright / chromium) arms just the browser.
_BROWSER_ALIASES = {"browser", "playwright", "chromium", "playwright-chromium"}
_BROWSER_NAME = "playwright-chromium"

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


def _browser_present() -> tuple[bool, str]:
    """Authoritative (cache-bypassing) check of the Playwright browser bundle."""
    from heaven.utils.runtime_capabilities import _cached_chromium_status
    return _cached_chromium_status(use_cache=False)


def _browser_result(*, dry_run: bool, as_json: bool) -> InstallResult:
    """Arm (or preview / report) the Playwright Chromium bundle as an
    :class:`InstallResult`, so the browser slots into the same plan/preview/
    result rendering as the PATH tools."""
    cmd = ["playwright", "install", "chromium"]
    present, detail = _browser_present()
    if present:
        return InstallResult(_BROWSER_NAME, "present", detail=detail)
    if dry_run:
        return InstallResult(_BROWSER_NAME, "planned", command=cmd)
    from heaven.utils.runtime_capabilities import ensure_chromium
    sink = None if as_json else (lambda ln: _print(f"[dim]{ln}[/dim]"))
    ok, detail = ensure_chromium(on_output=sink)
    return InstallResult(_BROWSER_NAME, "installed" if ok else "failed",
                         command=cmd, detail=detail)


@click.command(name="install-tools")
@click.argument("tools", nargs=-1)
@click.option("--yes", "-y", is_flag=True,
              help="Install without the confirmation prompt (for scripts/CI).")
@click.option("--dry-run", is_flag=True,
              help="Show what would be installed, without changing anything.")
def install_tools_cmd(tools: tuple[str, ...], yes: bool, dry_run: bool) -> None:
    """Install the external scanner binaries HEAVEN uses (full-power mode).

    With no arguments, installs every tool that is missing AND arms the
    Playwright browser bundle. Name specific tools to limit the scope:

        heaven install-tools                 # everything missing + browser
        heaven install-tools sqlmap ffuf     # just these two
        heaven install-tools browser         # just the Playwright browser
        heaven install-tools --dry-run       # preview the commands

    Each tool has an in-house fallback, so HEAVEN works without them, but with
    them installed you get real SQLi proof, content fuzzing, Exploit-DB lookup,
    SAST and template checks. The browser bundle arms the JS-rendered SPA crawl
    and the XSS execution proof. Uses your package manager (brew / apt / dnf /
    pacman) or pip / go as appropriate.
    """
    as_json = json_output()

    # Split any browser aliases out of the requested names so `browser` /
    # `playwright` / `chromium` select the bundle instead of tripping the
    # unknown-tool check. With no arguments at all, both the missing tools AND
    # the browser are in scope (the "full power" default).
    requested = [t.lower() for t in tools]
    include_browser = (not tools) or any(t in _BROWSER_ALIASES for t in requested)
    tool_names = [t for t in tools if t.lower() not in _BROWSER_ALIASES]

    # Resolve the requested tool subset (validate names) or default to all missing.
    if tool_names:
        specs: list[ToolSpec] = []
        unknown: list[str] = []
        for name in tool_names:
            spec = get_spec(name)
            (specs.append(spec) if spec else unknown.append(name))  # type: ignore[arg-type]
        if unknown:
            known = ", ".join([*(t.name for t in TOOLS), "browser"])
            msg = f"Unknown tool(s): {', '.join(unknown)}. Known: {known}"
            if as_json:
                emit_json({"ok": False, "error": msg})
            else:
                _print(f"[red]✗[/red] {msg}")
            raise SystemExit(2)
    elif tools and not include_browser:
        # Names were given but every one resolved away (shouldn't happen) —
        # nothing to do rather than defaulting to "all missing".
        specs = []
    else:
        specs = missing_tools()

    pending = [s for s in specs if not is_present(s.name)]
    browser_missing = include_browser and not _browser_present()[0]

    # Nothing to do?
    if not pending and not browser_missing:
        prior = [{"name": s.name, "status": "present"} for s in specs]
        if include_browser:
            prior.append({"name": _BROWSER_NAME, "status": "present"})
        if as_json:
            emit_json({"ok": True, "installed": [], "results": prior})
        else:
            _print("[green]✓ All requested tools are already installed.[/green] "
                   "Run [cyan]heaven doctor[/cyan] to confirm.")
        return

    # Preview the plan.
    if not as_json:
        _print("[bold]HEAVEN · external tool install[/bold]")
        _print("")
        for s in pending:
            cmd = build_install_command(s)
            recipe = " ".join(cmd) if cmd else f"[yellow]manual: {install_hint(s)}[/yellow]"
            _print(f"  [cyan]{s.name:13}[/cyan] {s.purpose}")
            _print(f"  {'':13} [dim]{recipe}[/dim]")
        if browser_missing:
            _print(f"  [cyan]{_BROWSER_NAME:13}[/cyan] JS-rendered SPA crawl + XSS execution proof")
            _print(f"  {'':13} [dim]playwright install chromium[/dim]")
        _print("")

    if dry_run:
        results = install_tools(pending, dry_run=True)
        if browser_missing:
            results.append(_browser_result(dry_run=True, as_json=as_json))
        _emit_results(results, as_json, dry_run=True)
        return

    # Confirm unless --yes (or --json, which is non-interactive by contract).
    if not yes and not as_json:
        n = len(pending) + (1 if browser_missing else 0)
        if not click.confirm(f"Install {n} item(s) now?", default=True):
            _print("[dim]Aborted · nothing was installed.[/dim]")
            return

    def _line(text: str) -> None:
        if not as_json:
            _print(f"[dim]{text}[/dim]")

    results = install_tools(pending, on_output=None if as_json else _line)
    # Arm the browser last so its (potentially long) download runs after the
    # quick package installs and its live output isn't interleaved with theirs.
    if browser_missing:
        results.append(_browser_result(dry_run=False, as_json=as_json))
    _emit_results(results, as_json, dry_run=False)

    # Non-zero exit when something genuinely failed, so CI/install.sh can react.
    if any(r.status == "failed" for r in results):
        raise SystemExit(1)


def _emit_results(results: list[InstallResult], as_json: bool, *, dry_run: bool) -> None:
    if as_json:
        # Only a genuine "failed" makes the run not-ok. A tool with no
        # auto-install recipe on THIS host (status "manual" — e.g. nuclei on a
        # box that has neither Go nor a package for it) is a legitimate, reported
        # outcome, not a failure: a dry run installs nothing at all, and a real
        # run still exits 0 (it only raises on "failed") while handing back a
        # manual hint. Defining ok this way keeps it consistent with the exit
        # code and lets the safe `--dry-run` preview always report ok.
        emit_json({
            "ok": not any(r.status == "failed" for r in results),
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
        _print("[yellow]Some tools need a manual install[/yellow] · see the recipe above.")
    if any(r.status == "failed" for r in results):
        _print("")
        _print("[yellow]Some installs failed.[/yellow] Re-run with the recipe shown, "
               "then verify with [cyan]heaven doctor[/cyan].")
    else:
        _print("")
        _print("Verify with [cyan]heaven doctor[/cyan].")


def register(cli: click.Group) -> None:
    cli.add_command(install_tools_cmd)

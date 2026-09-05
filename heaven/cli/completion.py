"""HEAVEN — `heaven completion` shell tab-completion.

Click can generate completion scripts natively (via the `_HEAVEN_COMPLETE`
env var), but *installing* the result is the part that trips people up — the
syntax differs per shell and, for zsh, the completion directory has to be on
``fpath`` **before** ``compinit`` runs. Get that ordering wrong (very easy with
oh-my-zsh, which runs ``compinit`` for you) and pressing Tab silently does
nothing. That is the "Tab doesn't complete" problem this module fixes.

So the recommended path is a single, idempotent, do-it-for-me command::

    heaven completion --install         # auto-detects your shell, wires it up
    heaven completion --install zsh     # or name the shell explicitly
    heaven completion --uninstall       # clean removal
    heaven completion --install --dry-run   # preview, write nothing

`--install` writes the completion script to ``~/.config/heaven/`` and adds a
small guarded block to your shell rc (``~/.zshrc`` / ``~/.bashrc``) that sources
it — ensuring ``compinit`` has run first, so completion actually loads. Re-running
is safe (the block is replaced, not duplicated) and the rc is backed up first.

The lower-level forms still work for scripting / packagers::

    heaven completion zsh  > ~/.zsh/_heaven
    heaven completion bash > /etc/bash_completion.d/heaven
    heaven completion fish > ~/.config/fish/completions/heaven.fish
    heaven completion powershell > heaven-completion.ps1   # . it from $PROFILE

Windows/PowerShell is supported too (``--install`` auto-detects it); Click has no
native PowerShell backend, so HEAVEN ships a small argument-completer that reuses
Click's zsh_complete protocol under the hood.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 -- runs vetted CLI tools, no shell
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print


_SHELLS = ("bash", "zsh", "fish")            # Click's native completion backends
# PowerShell has no Click completion backend, so we emit its completer by hand
# (it reuses the proven zsh_complete protocol at runtime). Kept separate because
# the Click-driven raw-script / hint paths still only understand bash/zsh/fish.
_ALL_SHELLS = _SHELLS + ("powershell",)

# Guarded block markers — let us find/replace/remove HEAVEN's lines in an rc
# file without clobbering anything the user put around them. ``#`` is a comment
# in every target shell *and* in PowerShell, so the same markers work there too.
_MARK_START = "# >>> heaven completion >>>"
_MARK_END = "# <<< heaven completion <<<"


def _detect_shell() -> Optional[str]:
    """Best-effort shell detection for the one-command installer.

    Prefer the POSIX ``$SHELL`` (bash/zsh/fish). On Windows there is no ``$SHELL``
    and the interactive shell is PowerShell, so fall back to that.
    """
    shell = os.environ.get("SHELL", "")
    if shell:
        base = os.path.basename(shell).lower().strip()
        if base in _SHELLS:
            return base
    if os.name == "nt":
        return "powershell"
    return None


def _config_dir() -> Path:
    """Where HEAVEN stores its completion scripts (``~/.config/heaven``)."""
    return Path.home() / ".config" / "heaven"


def _powershell_exe() -> Optional[str]:
    """The PowerShell executable to drive — pwsh (7+) preferred, else 5.1."""
    return shutil.which("pwsh") or shutil.which("powershell")


def _script_path(shell: str) -> Path:
    """Standard install location for the generated completion script."""
    if shell == "fish":
        # fish auto-loads any file in this directory — no rc edit needed.
        return Path.home() / ".config" / "fish" / "completions" / "heaven.fish"
    if shell == "powershell":
        return _config_dir() / "completion.ps1"
    return _config_dir() / f"completion.{shell}"


def _ps_profile_path() -> Optional[str]:
    """Resolve PowerShell's ``CurrentUserAllHosts`` profile by asking PowerShell.

    Asking the shell itself is the only reliable way — the path differs by OS and
    edition (Windows PowerShell 5.1 → ``Documents\\WindowsPowerShell``, pwsh 7 →
    ``Documents\\PowerShell`` on Windows or ``~/.config/powershell`` on Unix).
    ``-NoProfile`` still populates ``$PROFILE`` (it only skips *loading* it).
    """
    exe = _powershell_exe()
    if not exe:
        return None
    try:
        proc = subprocess.run(  # nosec B603 -- resolved exe, fixed argv, no shell
            [exe, "-NoProfile", "-NonInteractive", "-Command",
             "$PROFILE.CurrentUserAllHosts"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    out = proc.stdout.strip()
    return out or None


def _rc_path(shell: str) -> Optional[str]:
    """The rc file to wire up for *shell*, or ``None`` when none is needed.

    fish needs no rc edit (it auto-loads the completions dir). For bash we
    prefer ``~/.bashrc`` but fall back to ``~/.bash_profile`` when that is the
    file the user actually has (common on macOS). PowerShell wires its
    ``$PROFILE`` (resolved by asking PowerShell itself).
    """
    home = Path.home()
    if shell == "zsh":
        return str(home / ".zshrc")
    if shell == "bash":
        bashrc = home / ".bashrc"
        profile = home / ".bash_profile"
        if not bashrc.exists() and profile.exists():
            return str(profile)
        return str(bashrc)
    if shell == "powershell":
        return _ps_profile_path()
    return None  # fish


def _rc_block(shell: str) -> str:
    """The guarded block to drop into the rc file (markers included).

    For zsh we make sure ``compdef`` exists (i.e. ``compinit`` has run) before
    sourcing — this is the exact ordering bug that otherwise makes Tab do
    nothing. Running ``compinit`` a second time is skipped when a framework
    (oh-my-zsh, prezto, …) already ran it.
    """
    spath = _script_path(shell)
    # Use $HOME so the rc line stays valid if the home path has spaces / moves.
    ref = str(spath).replace(str(Path.home()), "$HOME", 1)
    if shell == "zsh":
        body = (
            f'if [[ -f "{ref}" ]]; then\n'
            "  # Ensure the completion system is initialised (compinit defines\n"
            "  # compdef); skip if a framework already did it.\n"
            "  (( $+functions[compdef] )) || { autoload -Uz compinit && compinit -C; }\n"
            f'  source "{ref}"\n'
            "fi"
        )
    elif shell == "powershell":
        # PowerShell forward-slash paths work on every OS; $HOME is an automatic
        # variable, so this stays valid wherever the profile lives.
        body = f'if (Test-Path "{ref}") {{ . "{ref}" }}'
    else:  # bash
        body = (
            f'if [ -f "{ref}" ]; then\n'
            f'  . "{ref}"\n'
            "fi"
        )
    return (
        f"{_MARK_START}\n"
        "# HEAVEN CLI tab-completion — managed by `heaven completion --install`.\n"
        f"{body}\n"
        f"{_MARK_END}"
    )


def _install_hint(shell: str) -> str:
    """Manual one-line install instructions per shell (fallback path)."""
    if shell == "zsh":
        return (
            "mkdir -p ~/.zsh && heaven completion zsh > ~/.zsh/_heaven\n"
            "  Then add to ~/.zshrc (BEFORE compinit runs):\n"
            "  fpath=(~/.zsh $fpath); autoload -U compinit; compinit\n"
            "  — or just run: heaven completion --install"
        )
    if shell == "bash":
        return (
            "heaven completion bash > ~/.heaven-completion.bash\n"
            "  Then add to ~/.bashrc:  source ~/.heaven-completion.bash\n"
            "  — or just run: heaven completion --install"
        )
    if shell == "fish":
        return (
            "mkdir -p ~/.config/fish/completions && "
            "heaven completion fish > ~/.config/fish/completions/heaven.fish\n"
            "  — or just run: heaven completion --install"
        )
    if shell == "powershell":
        return (
            "heaven completion powershell > $HOME/.heaven-completion.ps1\n"
            "  Then add to your $PROFILE:  . $HOME/.heaven-completion.ps1\n"
            "  — or just run: heaven completion --install"
        )
    return ""


# PowerShell has no Click completion backend, so we ship a small native
# argument-completer. It reuses Click's zsh_complete protocol (the same one the
# bash/zsh/fish scripts use): set COMP_WORDS / COMP_CWORD, run `heaven`, and parse
# the newline-separated ``type / value / help`` triples it prints. Verified end to
# end against pwsh's TabExpansion2 engine.
_POWERSHELL_COMPLETER = r'''# HEAVEN CLI tab-completion for PowerShell.
Register-ArgumentCompleter -Native -CommandName heaven -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elems = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    if ([string]::IsNullOrEmpty($wordToComplete)) {
        # Completing a fresh word after a space: append an empty trailing word.
        $env:COMP_WORDS = ($elems -join ' ') + ' '
        $env:COMP_CWORD = $elems.Count
    } else {
        $env:COMP_WORDS = ($elems -join ' ')
        $env:COMP_CWORD = ($elems.Count - 1)
    }
    $env:_HEAVEN_COMPLETE = 'zsh_complete'
    try   { $lines = @(& heaven 2>$null) }
    finally {
        Remove-Item Env:_HEAVEN_COMPLETE, Env:COMP_WORDS, Env:COMP_CWORD `
            -ErrorAction SilentlyContinue
    }
    # zsh_complete emits triples: <type>\n<value>\n<help> (help '_' = none).
    for ($i = 0; ($i + 2) -lt $lines.Count; $i += 3) {
        $type = $lines[$i]; $value = $lines[$i + 1]; $help = $lines[$i + 2]
        if ($type -ne 'plain') { continue }
        $tip = if ($help -eq '_') { $value } else { $help }
        [System.Management.Automation.CompletionResult]::new(
            $value, $value, 'ParameterValue', $tip)
    }
}
'''


def _powershell_completer_script() -> str:
    """The native PowerShell argument-completer (dot-sourced from ``$PROFILE``)."""
    return _POWERSHELL_COMPLETER


def _generate_script(shell: str) -> str:
    """Return the completion script for *shell*.

    bash/zsh/fish are produced by Click itself (we re-invoke with the magic env
    var). PowerShell has no Click backend, so we emit a hand-written completer
    that reuses Click's zsh_complete protocol at runtime.
    """
    if shell == "powershell":
        return _powershell_completer_script()
    env = dict(os.environ)
    env["_HEAVEN_COMPLETE"] = f"{shell}_source"
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
            [sys.executable, "-m", "heaven.main"],
            env=env, capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        _print("[red]Completion script generation timed out.[/red]")
        sys.exit(2)
    if proc.returncode != 0 or not proc.stdout.strip():
        _print(f"[red]Could not generate the completion script[/red] "
               f"(exit {proc.returncode}).")
        if proc.stderr:
            _print(f"[dim]{proc.stderr[:500]}[/dim]")
        sys.exit(2)
    return proc.stdout


def _backup_path(rc: Path) -> Path:
    """Sibling ``<name>.heaven.bak`` — predictable even for dotfiles like
    ``.zshrc`` (``Path.with_suffix`` is unreliable on leading-dot names)."""
    return rc.parent / (rc.name + ".heaven.bak")


def _upsert_block(rc: Path, block: str, dry_run: bool) -> str:
    """Insert or refresh HEAVEN's guarded block in *rc*.

    Returns ``"added"`` / ``"updated"`` / ``"unchanged"``. The rc file is backed
    up to ``<name>.heaven.bak`` before any write.
    """
    text = rc.read_text(encoding="utf-8") if rc.exists() else ""
    block_norm = block.strip("\n")
    if _MARK_START in text and _MARK_END in text:
        i = text.index(_MARK_START)
        j = text.index(_MARK_END) + len(_MARK_END)
        rebuilt = text[:i] + block_norm + text[j:]
        action = "updated"
    else:
        prefix = text.rstrip("\n")
        rebuilt = (prefix + "\n\n" if prefix else "") + block_norm + "\n"
        action = "added"

    if rebuilt == text:
        return "unchanged"
    if dry_run:
        return action

    rc.parent.mkdir(parents=True, exist_ok=True)
    if rc.exists():
        shutil.copy2(rc, _backup_path(rc))
    rc.write_text(rebuilt, encoding="utf-8")
    return action


def _remove_block(rc: Path, dry_run: bool) -> bool:
    """Strip HEAVEN's guarded block from *rc*. True if a block was present."""
    if not rc.exists():
        return False
    text = rc.read_text(encoding="utf-8")
    if _MARK_START not in text or _MARK_END not in text:
        return False
    if dry_run:
        return True
    i = text.index(_MARK_START)
    j = text.index(_MARK_END) + len(_MARK_END)
    new = (text[:i].rstrip("\n") + "\n" + text[j:].lstrip("\n")).lstrip("\n")
    shutil.copy2(rc, _backup_path(rc))
    rc.write_text(new, encoding="utf-8")
    return True


def _do_install(shell: str, dry_run: bool) -> None:
    """Write the completion script and wire the shell rc — the one-command path."""
    tag = "[cyan]DRY-RUN[/cyan] " if dry_run else ""
    script = _generate_script(shell)
    spath = _script_path(shell)

    if dry_run:
        _print(f"{tag}would write completion script → [bold]{spath}[/bold]")
    else:
        spath.parent.mkdir(parents=True, exist_ok=True)
        spath.write_text(script, encoding="utf-8")
        _print(f"[green]✓[/green] wrote completion script → [bold]{spath}[/bold]")

    rc_str = _rc_path(shell)
    if rc_str is None:  # fish — the completions dir is auto-loaded, no rc edit
        _print(f"[green]✓[/green] fish auto-loads it from {spath}")
        if not dry_run:
            _print("\n[bold]Done![/bold] Open a new terminal (or run "
                   "[cyan]exec fish[/cyan]), then type [cyan]heaven [/cyan]and "
                   "press [bold]Tab[/bold].")
        return

    rc = Path(rc_str)
    action = _upsert_block(rc, _rc_block(shell), dry_run)
    if action == "unchanged":
        _print(f"[green]✓[/green] {rc} is already wired up (no change).")
    elif action == "updated":
        _print(f"{tag}[green]✓[/green] refreshed HEAVEN block in {rc}"
               + ("" if dry_run else f"  [dim](backup: {_backup_path(rc).name})[/dim]"))
    else:
        _print(f"{tag}[green]✓[/green] added HEAVEN block to {rc}"
               + ("" if dry_run else f"  [dim](backup: {_backup_path(rc).name})[/dim]"))

    if dry_run:
        _print("\n[dim]DRY-RUN · nothing was written. Drop --dry-run to apply.[/dim]")
        return

    if shell == "powershell":
        reload_cmd = ". $PROFILE"
    elif shell == "zsh":
        reload_cmd = "exec zsh"
    else:
        reload_cmd = f"source {rc}"
    _print("\n[bold]Done![/bold] Reload your shell to activate completion now:")
    _print(f"  [cyan]{reload_cmd}[/cyan]")
    _print("Then type [cyan]heaven [/cyan]and press [bold]Tab[/bold] · every "
           "command, subcommand and option will complete.")


def _do_uninstall(shell: str, dry_run: bool) -> None:
    """Remove the rc block and the installed completion script."""
    tag = "[cyan]DRY-RUN[/cyan] " if dry_run else ""
    rc_str = _rc_path(shell)
    spath = _script_path(shell)

    if rc_str is not None:
        rc = Path(rc_str)
        removed = _remove_block(rc, dry_run)
        if removed:
            _print(f"{tag}[green]✓[/green] "
                   f"{'would remove' if dry_run else 'removed'} HEAVEN block from {rc}")
        else:
            _print(f"[dim]No HEAVEN block found in {rc}.[/dim]")

    if spath.exists():
        if dry_run:
            _print(f"{tag}would remove {spath}")
        else:
            spath.unlink()
            _print(f"[green]✓[/green] removed {spath}")
    else:
        _print(f"[dim]No completion script at {spath}.[/dim]")

    if not dry_run:
        _print("\n[dim]Restart your shell to finish removing completion.[/dim]")


@click.command(name="completion")
@click.argument("shell", required=False,
                type=click.Choice(_ALL_SHELLS + ("pwsh",), case_sensitive=False))
@click.option("--install", "do_install", is_flag=True,
              help="Set up tab-completion for you: write the script and wire "
                   "your shell rc (recommended).")
@click.option("--uninstall", "do_uninstall", is_flag=True,
              help="Cleanly remove HEAVEN completion from your shell rc.")
@click.option("--dry-run", is_flag=True,
              help="With --install/--uninstall: show what would change, write nothing.")
@click.option("--install-hint", is_flag=True,
              help="Print the manual install one-liner instead of the script.")
def completion_cmd(shell: Optional[str], do_install: bool, do_uninstall: bool,
                   dry_run: bool, install_hint: bool) -> None:
    """Enable Tab-completion for the `heaven` command.

    The easy way: one command, auto-detects your shell, safe to re-run:

        heaven completion --install

    Then open a new terminal (or `exec zsh`) and press Tab after `heaven `.

    Other forms:

        heaven completion --install bash   # name the shell explicitly
        heaven completion --uninstall      # remove it again
        heaven completion zsh > file       # just emit the raw script
    """
    if do_install and do_uninstall:
        _print("[red]Choose one of --install or --uninstall, not both.[/red]")
        sys.exit(2)

    explicit = shell is not None
    if shell and shell.lower() == "pwsh":
        shell = "powershell"          # accept the common alias
    if not shell:
        shell = _detect_shell()
        if not shell:
            _print("[red]Could not auto-detect your shell from $SHELL.[/red]")
            _print("Pass one explicitly:")
            for s in _ALL_SHELLS:
                _print(f"  [cyan]heaven completion --install {s}[/cyan]")
            sys.exit(2)

    if do_uninstall:
        _do_uninstall(shell, dry_run)
        return

    if do_install:
        if not explicit:
            _print(f"[dim]Detected shell: {shell}[/dim]")
        _do_install(shell, dry_run)
        return

    if install_hint:
        _print(_install_hint(shell))
        return

    # No action flag. If a human is looking at a terminal and didn't ask for a
    # specific shell's raw script, guide them to the one-command path rather
    # than dumping a wall of shell code. A redirect/pipe (or an explicit shell
    # arg) still emits the script verbatim, so `heaven completion zsh > f` works.
    if sys.stdout.isatty() and not explicit:
        _print("[bold]Enable Tab-completion for the `heaven` command:[/bold]\n")
        _print(f"  [cyan]heaven completion --install[/cyan]   "
               f"[dim]# detected shell: {shell}[/dim]")
        _print("\nThat writes the completion script and wires your shell rc "
               "safely (backed up, idempotent).")
        _print("Preview first with [cyan]--dry-run[/cyan]; undo with "
               "[cyan]--uninstall[/cyan].")
        _print(f"\n[dim]To print the raw script instead: "
               f"heaven completion {shell}[/dim]")
        return

    # Emit the raw script (piped/redirected, or an explicit shell was named).
    sys.stdout.write(_generate_script(shell))
    sys.stdout.flush()
    print("", file=sys.stderr)
    print(f"# Installed automatically with:  heaven completion --install {shell}",
          file=sys.stderr)
    print("# Or install this script manually:", file=sys.stderr)
    for line in _install_hint(shell).splitlines():
        print(f"#   {line}", file=sys.stderr)


def register(cli: click.Group) -> None:
    cli.add_command(completion_cmd)

"""HEAVEN — `heaven completion` shell-completion installer.

Click supports completion natively via the `_HEAVEN_COMPLETE` env var,
but the syntax for installing the resulting script differs per shell
and is fiddly. This wrapper:

  - Detects the operator's shell (or accepts an explicit argument)
  - Emits the appropriate completion script to stdout
  - Prints the one-line install instruction the operator should run

Usage:
    heaven completion zsh > ~/.zsh/_heaven
    heaven completion bash > /etc/bash_completion.d/heaven
    heaven completion fish > ~/.config/fish/completions/heaven.fish
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 -- runs vetted CLI tools, no shell
import sys
from typing import Optional

import click

from heaven.cli._helpers import _print


_SHELLS = ("bash", "zsh", "fish")


def _detect_shell() -> Optional[str]:
    """Best-effort: read $SHELL and return the basename."""
    shell = os.environ.get("SHELL", "")
    if not shell:
        return None
    base = os.path.basename(shell).lower().strip()
    return base if base in _SHELLS else None


def _install_hint(shell: str) -> str:
    """Friendly one-line install instructions per shell."""
    if shell == "zsh":
        return (
            "mkdir -p ~/.zsh && heaven completion zsh > ~/.zsh/_heaven\n"
            "  Then add to ~/.zshrc:  fpath=(~/.zsh $fpath); autoload -U compinit; compinit"
        )
    if shell == "bash":
        return (
            "heaven completion bash > /tmp/heaven.bash\n"
            "  Then add to ~/.bashrc:  source /tmp/heaven.bash\n"
            "  Or system-wide: sudo cp /tmp/heaven.bash /etc/bash_completion.d/heaven"
        )
    if shell == "fish":
        return (
            "mkdir -p ~/.config/fish/completions && "
            "heaven completion fish > ~/.config/fish/completions/heaven.fish"
        )
    return ""


@click.command(name="completion")
@click.argument("shell", required=False,
                type=click.Choice(_SHELLS, case_sensitive=False))
@click.option("--install-hint", is_flag=True,
              help="Just print the install one-liner — don't emit the script.")
def completion_cmd(shell: Optional[str], install_hint: bool) -> None:
    """Emit a shell-completion script for HEAVEN.

    Examples — install for your current shell:

        heaven completion zsh  > ~/.zsh/_heaven
        heaven completion bash > /etc/bash_completion.d/heaven
        heaven completion fish > ~/.config/fish/completions/heaven.fish

    Or auto-detect your shell:

        heaven completion         # tries $SHELL, errors with hint if unknown
    """
    if not shell:
        shell = _detect_shell()
        if not shell:
            _print("[red]Could not auto-detect your shell.[/red]")
            _print("Pass one explicitly:")
            for s in _SHELLS:
                _print(f"  [cyan]heaven completion {s}[/cyan]")
            sys.exit(2)
        _print(f"[dim]# Auto-detected shell: {shell}[/dim]", )

    if install_hint:
        _print(_install_hint(shell))
        return

    # Click's built-in completion: re-invoke ourselves with the magic env var.
    # We use the shell-specific source variant so each shell gets the right syntax.
    env = dict(os.environ)
    env["_HEAVEN_COMPLETE"] = f"{shell}_source"

    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
            [sys.executable, "-m", "heaven.main"],
            env=env, capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        _print("[red]Completion script generation timed out.[/red]")
        sys.exit(2)

    if proc.returncode != 0:
        _print(f"[red]Click completion failed:[/red] exit {proc.returncode}")
        if proc.stderr:
            _print(f"[dim]{proc.stderr[:500]}[/dim]")
        sys.exit(2)

    # Click 8.x writes the script to stdout — pass through verbatim.
    sys.stdout.write(proc.stdout)
    sys.stdout.flush()

    # Print install hint to stderr so it doesn't pollute the script when piped.
    print("", file=sys.stderr)
    print(f"# Installation hint for {shell}:", file=sys.stderr)
    for line in _install_hint(shell).splitlines():
        print(f"#   {line}", file=sys.stderr)


def register(cli: click.Group) -> None:
    cli.add_command(completion_cmd)

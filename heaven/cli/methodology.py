"""HEAVEN — `heaven methodology` (browse OWASP / NIST / PTES mappings)."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from heaven.cli._helpers import _print


_DOCS_DIR = Path(__file__).resolve().parents[2] / "docs" / "methodology"


@click.group(name="methodology")
def methodology() -> None:
    """Show the OWASP / NIST / PTES mapping documents shipped with HEAVEN."""


@methodology.command("list")
def list_docs() -> None:
    """List the methodology documents available."""
    if not _DOCS_DIR.exists():
        _print(f"[red]Methodology docs not found at {_DOCS_DIR}[/red]")
        sys.exit(2)
    _print(f"[cyan]Methodology docs at[/cyan] {_DOCS_DIR}")
    for md in sorted(_DOCS_DIR.glob("*.md")):
        size_kb = md.stat().st_size // 1024
        _print(f"  - {md.stem:30}  ({size_kb} KiB)")
    _print("\n[dim]Use `heaven methodology show <name>` to print one.[/dim]")


@methodology.command("show")
@click.argument("name")
def show(name: str) -> None:
    """Print one methodology mapping doc to stdout.

    NAME is the filename stem, e.g. owasp_testing_guide, nist_800_115, ptes.
    """
    candidate = _DOCS_DIR / f"{name}.md"
    if not candidate.exists():
        _print(f"[red]Doc not found:[/red] {candidate}")
        _print("[dim]Available:[/dim]")
        for md in sorted(_DOCS_DIR.glob("*.md")):
            _print(f"  - {md.stem}")
        sys.exit(2)
    content = candidate.read_text(encoding="utf-8")
    # Try to render via Rich if available, else plain print
    try:
        from rich.markdown import Markdown
        from heaven.utils.logger import HAS_RICH, console
        if HAS_RICH and console:
            console.print(Markdown(content))
            return
    except Exception:
        pass
    print(content)


def register(cli: click.Group) -> None:
    cli.add_command(methodology)

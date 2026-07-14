"""HEAVEN — `heaven methodology` (browse OWASP / NIST / PTES mappings)."""

from __future__ import annotations

import json as _json
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


@methodology.command("coverage")
@click.option("--engagement", "-e", default=None,
              help="Engagement to overlay (default: the active engagement).")
@click.option("--standard", "-s", default=None,
              type=click.Choice(["owasp", "nist", "ptes"], case_sensitive=False),
              help="Limit output to one standard.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def coverage(engagement: str | None, standard: str | None, as_json: bool) -> None:
    """Live methodology coverage for an engagement.

    Shows each standard's automated-vs-manual coverage (computed from the
    mapping docs) and how many of those tests the engagement's real findings
    actually exercised — the same data the web Methodology page renders, so CLI
    and UI stay in sync.
    """
    from heaven import methodology as _m

    # Pull the engagement's findings for the live overlay (best-effort).
    findings: list[dict] = []
    eng_name = engagement or ""
    try:
        from heaven.cli._helpers import _engagement_db_path
        from heaven.engagement import EngagementStore, get_active_engagement
        eng_name = engagement or get_active_engagement() or ""
        store = EngagementStore(_engagement_db_path(engagement))
        findings = [
            {"vuln_type": f.vuln_type, "owasp": getattr(f, "owasp", "")}
            for f in store.list_findings(limit=10000)
        ]
    except Exception:
        findings = []

    built = _m.build(findings, _DOCS_DIR)
    built["engagement"]["name"] = eng_name

    stds = built["standards"]
    alias = {"owasp": "owasp_testing_guide", "nist": "nist_800_115", "ptes": "ptes"}
    if standard:
        stds = [s for s in stds if s["name"] == alias[standard.lower()]]

    if as_json:
        payload = {"engagement": built["engagement"],
                   "standards": [{"name": s["name"], "summary": s["summary"]} for s in stds]}
        print(_json.dumps(payload, indent=2))
        return

    eng = built["engagement"]
    label = eng_name or "(none)"
    _print(f"[bold cyan]Methodology coverage[/bold cyan]  ·  engagement: [bold]{label}[/bold]")
    _print(f"[dim]{eng['findings_total']} finding(s) · "
           f"{len(eng['modules_active'])} detector(s) active · "
           f"{len(eng['owasp_categories'])} OWASP categor(ies)[/dim]\n")

    for s in stds:
        summ = s["summary"]
        cov_pct = (100 * summ["covered"] // summ["total"]) if summ["total"] else 0
        _print(f"[bold]{s['meta_title']}[/bold] [dim]({s['subtitle']})[/dim]")
        _print(f"  Tests mapped      : {summ['total']}")
        _print(f"  Automated by HEAVEN: {summ['covered']}  ({cov_pct}%)"
               f"   [dim]auto {summ['automated']} · partial {summ['partial']} · manual {summ['manual']}[/dim]")
        _print(f"  Exercised here    : [green]{summ.get('exercised', 0)}[/green]"
               f"  [dim](rows whose detector produced a finding)[/dim]\n")

    if not findings:
        _print("[yellow]No findings in this engagement yet — run a scan to populate live coverage.[/yellow]")


def register(cli: click.Group) -> None:
    cli.add_command(methodology)

"""HEAVEN — `heaven knowledge` (cross-engagement memory inspector)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print


@click.group(name="knowledge")
def knowledge() -> None:
    """Inspect the cross-engagement knowledge graph (~/.heaven/knowledge.db)."""


@knowledge.command("stats")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write JSON stats to this path.")
def stats(output: Optional[str]) -> None:
    """Show aggregate counts + top-success techniques across all engagements."""
    from heaven.ai.knowledge_graph import get_knowledge_graph
    kg = get_knowledge_graph()
    s = kg.stats()
    _print(f"[bold]Knowledge graph stats[/bold] · DB: [cyan]{kg.db_path}[/cyan]")
    _print(f"  Target profiles seen:  {s['profiles']}")
    _print(f"  Total attempts:        {s['attempts']}")
    _print(f"  Successful attempts:   [green]{s['successes']}[/green]")
    if s["top_techniques"]:
        _print("\n[bold]Top techniques by success count:[/bold]")
        for t in s["top_techniques"]:
            rate = (t["successes"] / t["attempts"]) if t["attempts"] else 0
            _print(f"  {t['technique']:30}  "
                   f"{t['successes']:4d}/{t['attempts']:4d}  ({rate:.0%})")
    if output:
        Path(output).write_text(json.dumps(s, indent=2))
        _print(f"\n[green]Stats written:[/green] {output}")


@knowledge.command("rank")
@click.option("--os", default="", help="Target OS (linux/windows/macos)")
@click.option("--web-tech", default="", help="Comma-separated web stack labels")
@click.option("--ad-domain", default="")
@click.option("--cloud", default="", help="aws / gcp / azure")
@click.option("--ports", default="", help="Comma-separated open ports, e.g. 22,80,443")
@click.option("--top", type=int, default=10)
def rank(os: str, web_tech: str, ad_domain: str, cloud: str,
         ports: str, top: int) -> None:
    """Show Beta-smoothed posterior success-rate per technique for a target profile.

    Example:

        heaven knowledge rank --os linux --web-tech php,wordpress \\
                              --ports 22,80,443
    """
    from heaven.ai.knowledge_graph import TargetProfile, get_knowledge_graph
    try:
        port_ints = [int(p) for p in ports.split(",") if p.strip()]
    except ValueError:
        _print("[red]--ports must be comma-separated integers[/red]")
        sys.exit(2)

    profile = TargetProfile(
        os=os, web_tech=web_tech, ad_domain=ad_domain, cloud=cloud,
        open_ports_top=port_ints,
    )
    rankings = get_knowledge_graph().rank_techniques(profile, top_n=top)
    _print(f"[cyan]Profile fingerprint:[/cyan] {profile.fingerprint()}")
    if not rankings:
        _print("[yellow]No knowledge graph entries yet — run more scans first.[/yellow]")
        return
    _print("\n[bold]Technique rankings (Beta-smoothed posterior):[/bold]")
    for r in rankings:
        bar = "█" * int(r.posterior_success_rate * 20)
        _print(f"  {r.technique:30}  "
               f"{r.posterior_success_rate:.0%}  {bar}  "
               f"(n={r.evidence_count})")


def register(cli: click.Group) -> None:
    cli.add_command(knowledge)

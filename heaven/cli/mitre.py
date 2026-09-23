"""HEAVEN — MITRE-related CLI commands: `mitre-report` and `kill-chain`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print
from heaven.utils.logger import print_banner


@click.command(name="mitre-report")
@click.option("--engagement", help="Engagement name")
@click.option("--output", "-o", type=click.Path(), default="data/mitre_navigator.json",
              help="Navigator layer output path")
def mitre_report(engagement: Optional[str], output: str) -> None:
    """Generate MITRE ATT&CK Navigator heatmap layer from scan results."""
    print_banner()

    from heaven.engagement import EngagementStore
    from heaven.mitre.attack_mapper import MITREAttackMapper

    store = EngagementStore(_engagement_db_path(engagement))
    all_findings = store.list_findings(limit=10000)
    if not all_findings:
        _print("[yellow]No findings yet · run a scan first, then re-run "
               "heaven mitre-report.[/yellow]")
        return

    _print(f"[cyan]Mapping {len(all_findings)} finding(s) to MITRE ATT&CK...[/cyan]")

    # Feed the real engagement findings into the mapper. It keys on CWE first
    # (stored in a finding's evidence, e.g. "CWE-89") and falls back to the
    # vuln_type, so both signals are supplied.
    finding_dicts = [
        {"id": f.id, "title": f.title or f.vuln_type, "severity": f.severity,
         "vuln_type": f.vuln_type, "type": f.vuln_type,
         "cwe": (f.evidence or {}).get("cwe", "")}
        for f in all_findings
    ]
    mapper = MITREAttackMapper()
    mappings = mapper.map_all_findings(finding_dicts)
    mapped = sum(1 for m in mappings if m.techniques)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    mapper.export_navigator_layer(Path(output))
    _print(f"[green]Navigator layer exported to:[/green] {output}")
    _print(f"  Findings mapped to techniques: {mapped}/{len(all_findings)}")
    summary = mapper.get_tactic_coverage()
    _print(f"  Tactic coverage: {summary['coverage_pct']}%")


@click.command(name="kill-chain")
@click.option("--engagement", help="Engagement name")
@click.option("--output", "-o", type=click.Path(), help="Save report as JSON")
def kill_chain_cmd(engagement: Optional[str], output: Optional[str]) -> None:
    """Show Lockheed Cyber Kill Chain phase coverage for current findings."""
    from heaven.engagement import EngagementStore
    from heaven.mitre.kill_chain import KillChainAnalyzer
    store = EngagementStore(_engagement_db_path(engagement))
    all_findings = store.list_findings(limit=10000)
    if not all_findings:
        _print("[yellow]No findings yet · run a scan first.[/yellow]")
        return

    finding_dicts = [
        {"type": f.vuln_type, "vuln_type": f.vuln_type,
         "title": f.title or f.vuln_type, "severity": f.severity,
         "target": f.target, "cve_id": f.cve_id}
        for f in all_findings
    ]
    analyzer = KillChainAnalyzer()
    analyzer.ingest(finding_dicts)
    report = analyzer.report()
    path = analyzer.attack_path_summary()

    _print(f"\n[bold cyan]Cyber Kill Chain Coverage:[/bold cyan] "
           f"{report['coverage_score']}/100  ({report['phases_with_findings']}/7 phases)")
    _print("")
    for phase in report["phases"]:
        colour = "red" if phase["finding_count"] > 0 else "dim"
        _print(f"  [{colour}]{phase['phase']:25}[/{colour}] "
               f"{phase['finding_count']:4} finding(s)")
    if path:
        _print("\n[bold]Attacker workflow if these findings are chained:[/bold]")
        for step in path:
            phase_safe = step['phase'].replace("[", r"\[").replace("]", r"\]")
            title_safe = (step['representative_finding'] or "—").replace("[", r"\[").replace("]", r"\]")
            _print(f"  → \\[{phase_safe}] {title_safe} ({step['severity']})")

    if output:
        Path(output).write_text(json.dumps({
            "report": report, "attack_path": path,
            "mermaid": analyzer.to_mermaid(),
        }, indent=2))
        _print(f"\n[green]Report saved:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(mitre_report)
    cli.add_command(kill_chain_cmd)

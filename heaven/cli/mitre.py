"""HEAVEN — MITRE-related CLI commands: `mitre-report`, `kill-chain`, `mitre`."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, emit_json, json_output
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


@click.group(name="mitre")
def mitre_grp() -> None:
    """Refresh and query live MITRE ATT&CK data (TAXII 2.1)."""


def _embedded_technique_ids() -> set[str]:
    """Every ATT&CK technique ID referenced by the local finding→technique maps."""
    from heaven.mitre.attack_mapper import CWE_TO_ATTACK, VULN_TYPE_TO_ATTACK

    ids: set[str] = set()
    for table in (CWE_TO_ATTACK, VULN_TYPE_TO_ATTACK):
        for techs in table.values():
            for tech in techs:
                tid = tech.get("id", "")
                if tid:
                    ids.add(tid.split(".")[0])  # base technique, not sub-technique
    return ids


@mitre_grp.command(name="refresh")
@click.option("--force", is_flag=True,
              help="Ignore the 24h cache and fetch from the TAXII server now.")
@click.option("--check", is_flag=True,
              help="After fetching, verify the local finding→technique maps only "
                   "reference techniques that still exist in current ATT&CK.")
def refresh_cmd(force: bool, check: bool) -> None:
    """Fetch the latest ATT&CK dataset from MITRE's TAXII 2.1 server and cache it.

    Opt-in and offline-friendly: HEAVEN maps findings from a bundled table by
    default; this pulls the live catalogue so `heaven mitre technique` can answer
    from current data and `--check` can flag any locally-mapped technique that
    MITRE has since renamed or deprecated. Needs network + the `httpx` package.
    """
    from heaven.mitre.taxii_client import HAS_HTTPX, TAXIIClient

    if not HAS_HTTPX:
        _print("[yellow]· Live refresh needs the 'httpx' package.[/yellow] "
               "[dim]Install: pip install httpx[/dim]")
        _print("[dim]HEAVEN keeps working from its bundled ATT&CK table without it.[/dim]")
        raise SystemExit(1)

    async def _run() -> dict:
        client = TAXIIClient()
        data = await client.fetch_attack_data(force_refresh=force)
        parsed = client.parse_objects(data)
        # Persist a compact attack_id → {name, url} index next to the cache.
        index = {
            t.attack_id: {"name": t.name, "url": t.url}
            for t in parsed["techniques"] if t.attack_id
        }
        idx_path = client._cache_dir / "technique_index.json"
        idx_path.write_text(json.dumps(index, indent=2, sort_keys=True))
        return {
            "counts": {k: len(v) for k, v in parsed.items()},
            "offline": bool(data.get("offline")),
            "index_path": str(idx_path),
            "live_ids": {t.attack_id for t in parsed["techniques"] if t.attack_id},
        }

    result = asyncio.run(_run())
    counts = result["counts"]
    live_ids = result.pop("live_ids")

    stale: list[str] = []
    if check and live_ids:
        stale = sorted(_embedded_technique_ids() - live_ids)

    if json_output():
        emit_json({"counts": counts, "offline": result["offline"],
                   "index_path": result["index_path"],
                   "stale_local_techniques": stale})
        return

    if result["offline"] or not any(counts.values()):
        _print("[yellow]· Could not reach the TAXII server and no usable cache "
               "was found.[/yellow] [dim]HEAVEN continues on its bundled table.[/dim]")
        raise SystemExit(1)
    _print(f"[green]✓ ATT&CK refreshed[/green] · {counts['techniques']} techniques, "
           f"{counts['groups']} groups, {counts['malware']} malware")
    _print(f"  [dim]Technique index → {result['index_path']}[/dim]")
    if check:
        if stale:
            _print(f"[yellow]⚠ {len(stale)} locally-mapped technique(s) are not in "
                   f"current ATT&CK:[/yellow] {', '.join(stale)}")
        else:
            _print("[green]✓ Local finding→technique maps all match current ATT&CK.[/green]")


@mitre_grp.command(name="technique")
@click.argument("attack_id")
def technique_cmd(attack_id: str) -> None:
    """Show a technique (e.g. T1059) and the threat groups that use it, from live data."""
    from heaven.mitre.taxii_client import TAXIIClient

    attack_id = attack_id.strip().upper()

    async def _run() -> Optional[dict]:
        client = TAXIIClient()
        data = await client.fetch_attack_data()  # cache first, offline-friendly
        if not data.get("objects"):
            return None
        client.parse_objects(data)
        tech = client.get_technique(attack_id)
        if tech is None:
            return {"found": False}
        groups = client.get_groups_using_technique(tech.id)
        return {
            "found": True,
            "attack_id": tech.attack_id, "name": tech.name,
            "url": tech.url, "description": tech.description,
            "groups": [g.name for g in groups],
        }

    result = asyncio.run(_run())
    if result is None:
        _print("[yellow]· No ATT&CK data cached yet.[/yellow] "
               "[dim]Run: heaven mitre refresh[/dim]")
        raise SystemExit(1)
    if not result.get("found"):
        _print(f"[dim]No technique {attack_id} in the current ATT&CK dataset.[/dim]")
        raise SystemExit(1)
    if json_output():
        emit_json(result)
        return
    _print(f"[bold cyan]{result['attack_id']}[/bold cyan]  {result['name']}")
    if result["url"]:
        _print(f"  [dim]{result['url']}[/dim]")
    if result["description"]:
        _print(f"\n{result['description'][:600]}")
    if result["groups"]:
        _print(f"\n[bold]Threat groups using this technique[/bold] "
               f"({len(result['groups'])}): {', '.join(sorted(result['groups'])[:20])}")


def register(cli: click.Group) -> None:
    cli.add_command(mitre_report)
    cli.add_command(kill_chain_cmd)
    cli.add_command(mitre_grp)

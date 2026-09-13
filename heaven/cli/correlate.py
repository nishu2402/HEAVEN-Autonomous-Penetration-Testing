"""HEAVEN — `correlate` command.

Suggests combinations of findings that, taken together, elevate into a more
critical issue (e.g. local file inclusion + file upload → remote code
execution). Runs on the active engagement's stored findings, or on a JSON list
the operator supplies with ``--input`` (the same shape ``heaven findings
--format json`` emits), so a tester can feed in their own findings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


@click.command()
@click.option("--engagement", help="Engagement name (defaults to the active one)")
@click.option("--input", "input_path", type=click.Path(exists=True, dir_okay=False),
              help="Correlate findings from a JSON file (list, or {\"findings\": [...]}) "
                   "instead of the engagement store")
@click.option("--severity", type=click.Choice(["critical", "high"]),
              help="Only show combinations at or above this elevated severity")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]),
              default="table", help="Output format")
@click.option("--steps/--no-steps", "show_steps", default=True,
              help="Show the prerequisites and proof/exploit playbook for each "
                   "combination (table format only)")
def correlate(engagement: Optional[str], input_path: Optional[str],
              severity: Optional[str], fmt: str, show_steps: bool) -> None:
    """Suggest findings that combine into a more critical issue."""
    if json_output():
        fmt = "json"

    from heaven.vulnscan.correlation import CorrelationEngine

    if input_path:
        try:
            raw = json.loads(Path(input_path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            _print(f"[red]Could not read findings from {input_path}: {e}[/red]")
            sys.exit(1)
        findings = raw.get("findings", []) if isinstance(raw, dict) else raw
        if not isinstance(findings, list):
            _print("[red]Input must be a JSON list of findings, or "
                   "{\"findings\": [...]}.[/red]")
            sys.exit(1)
    else:
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement), create=False)
        findings = [f.__dict__ for f in store.list_findings(limit=2000)]

    summary = CorrelationEngine().summary(findings)
    combos = summary["combinations"]
    if severity:
        wanted = {"critical"} if severity == "critical" else {"critical", "high"}
        combos = [c for c in combos if c["combined_severity"] in wanted]

    if fmt == "json":
        print(json.dumps({**summary, "combinations": combos}, indent=2, default=str))
        return

    if not combos:
        _print("[green]No finding combinations elevate to a higher severity.[/green]")
        _print(f"[dim]Analysed {summary['total_input_findings']} finding(s).[/dim]")
        return

    _print(f"[bold]{len(combos)} combined risk(s)[/bold] from "
           f"{summary['total_input_findings']} finding(s) "
           f"([red]{summary['critical_combinations']} critical[/red]):\n")
    sev_color = {"critical": "bold red", "high": "red"}
    for c in combos:
        col = sev_color.get(c["combined_severity"], "yellow")
        conf_tag = ("[green]CONFIRMED[/green]" if c["confirmation"] == "Confirmed"
                    else "[yellow]POTENTIAL[/yellow]")
        _print(f"  [{col}]{c['combined_severity'].upper():8}[/{col}] {conf_tag} "
               f"{c['name']}")
        prio = c.get("priority")
        _print(f"    [dim]{c['id']} · conf {int(round(c['confidence'] * 100))}%"
               f"{(' · priority ' + str(int(round(prio))) + '/100') if prio else ''}"
               f"{(' · ' + c['phase']) if c.get('phase') else ''}"
               f"{(' · ' + c['cwe']) if c.get('cwe') else ''}"
               f"{(' · scope ' + ', '.join(c['scope'])) if c.get('scope') else ''}[/dim]")
        for comp in c["components"]:
            extra = []
            if comp.get("param"):
                extra.append(f"param {comp['param']}")
            if comp.get("port"):
                extra.append(f"port {comp['port']}")
            if comp.get("cve"):
                extra.append(str(comp["cve"]))
            extra_str = f"  ({' · '.join(extra)})" if extra else ""
            _print(f"      [dim]+[/dim] {comp['severity'].upper():8} "
                   f"{comp['title'] or comp['vuln_type']}{extra_str}")
        _print(f"    [dim]{c['rationale']}[/dim]")
        if show_steps:
            for pre in (c.get("prerequisites") or []):
                _print(f"    [dim]needs:[/dim] {pre}")
            steps = c.get("playbook") or []
            if steps:
                heading = ("Reproduce" if c["confirmation"] == "Confirmed"
                           else "Prove it")
                _print(f"    [bold]{heading}:[/bold]")
                for i, step in enumerate(steps, 1):
                    _print(f"      {i}. {step}")
        _print(f"    [dim]Fix: {c['recommendation']}[/dim]\n")

    # End-to-end attack paths: chains where each step yields a capability the
    # next consumes, ending in a concrete business impact.
    paths = summary.get("attack_paths") or []
    if paths:
        _print(f"[bold]{len(paths)} attack path(s)[/bold] "
               f"[dim](each step feeds the next):[/dim]")
        for p in paths:
            col = sev_color.get(p.get("severity"), "yellow")
            hosts = " → ".join(p.get("hosts") or [])
            _print(f"  [{col}]{str(p.get('severity','')).upper():8}[/{col}] "
                   f"{p.get('business_impact')} "
                   f"[dim]({p.get('length')} steps · conf "
                   f"{int(round((p.get('confidence') or 0) * 100))}%"
                   f"{(' · ' + hosts) if hosts else ''})[/dim]")
            for st in p.get("steps") or []:
                via = f"  [dim]{st['via']}[/dim]" if st.get("via") else ""
                _print(f"      {st.get('position')}. {st.get('name')}{via}")
        _print("")

    # "Break the chain" — highest-leverage single fixes.
    rem = summary.get("remediation") or {}
    top = rem.get("top_fix") or {}
    if top.get("chains_broken"):
        _print(f"[bold]Break the chain[/bold] [dim](fixing "
               f"{top.get('title')} alone breaks {top.get('chains_broken')} "
               f"combined risk(s)):[/dim]")
        for r in (rem.get("by_finding") or [])[:5]:
            if not r.get("chains_broken"):
                continue
            pb = (f", {r['paths_broken']} attack path(s)"
                  if r.get("paths_broken") else "")
            tgt = f" [dim]({r['target']})[/dim]" if r.get("target") else ""
            _print(f"  · {r['title']}{tgt} [dim]breaks {r['chains_broken']} "
                   f"combined risk(s){pb}[/dim]")
        cut = rem.get("path_cut") or []
        if cut:
            _print(f"  [dim]Sever every attack path by fixing: "
                   f"{', '.join(str(c.get('title')) for c in cut)}[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(correlate)

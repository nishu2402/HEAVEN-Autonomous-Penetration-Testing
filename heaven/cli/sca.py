"""HEAVEN — `heaven sca` (Software Composition Analysis via OSV.dev).

Parses dependency manifests / lockfiles under a path and cross-references every
pinned package against the OSV.dev advisory database. This finds
known-vulnerable *dependencies* — the class of vulnerability that HEAVEN's
inline CVE table and NVD's CPE search cannot cover, because OSV is the feed
purpose-built for language ecosystems (PyPI, npm, Go, Maven, …).

Findings are normalised to HEAVEN's finding shape and (with --engagement)
persisted alongside DAST/SAST findings so the whole picture lands in one report.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


@click.command(name="sca")
@click.argument("path", type=click.Path(exists=True))
@click.option("--engagement", default=None,
              help="Engagement to persist findings into (optional — without it, "
                   "results print to stdout only).")
@click.option("--output", "-o", type=click.Path(),
              help="Write the full JSON result to this path.")
@click.option("--max-files", type=int, default=200,
              help="Max manifests to parse when walking a directory. Default 200.")
def sca(path: str, engagement: Optional[str], output: Optional[str],
        max_files: int) -> None:
    """Audit a codebase's dependencies against OSV.dev.

    Examples:

        # Audit a project's dependencies
        heaven sca ./my-app

        # Persist into an engagement so it shows up in the report
        heaven sca ./my-app --engagement q1-pentest

        # Audit a single lockfile
        heaven sca ./requirements.txt -o sca.json
    """
    from heaven.devsecops.vuln_kb import enrich_finding
    from heaven.vulnscan.osv_client import OSVClient
    from heaven.vulnscan.sca_scanner import scan_path

    if not OSVClient().available:
        _print("[yellow]httpx not installed — OSV lookups need it.[/yellow]")
        _print("[dim]Install:[/dim] [cyan]pip install httpx[/cyan]")
        sys.exit(2)

    result = asyncio.run(scan_path(path, max_files=max_files))
    findings = [enrich_finding(f) for f in result.get("findings", [])]

    if json_output():
        print(json.dumps({**result, "findings": findings}, indent=2, default=str))
        return

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    _print(f"[bold]SCA results[/bold] · {result['packages']} package(s) across "
           f"{len(result['manifests'])} manifest(s)")
    _print(f"  Critical: {sev_counts.get('critical', 0)}  "
           f"High: {sev_counts.get('high', 0)}  "
           f"Medium: {sev_counts.get('medium', 0)}  "
           f"Low: {sev_counts.get('low', 0)}")
    _print(f"  Vulnerable dependencies: [bold]{len(findings)}[/bold]")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: (order.get(x["severity"], 5), -x.get("cvss", 0)))[:30]:
        e = f["evidence"]
        color = {"critical": "bold red", "high": "red",
                 "medium": "yellow", "low": "cyan"}.get(f["severity"], "dim")
        cve = f.get("cve_id") or e.get("osv_id", "")
        _print(f"  [{color}]{f['severity'][:4].upper():4}[/{color}] "
               f"cvss {f.get('cvss', 0):<4} {e['package']}@{e['installed_version']}  "
               f"{cve}  [dim]fix: {e.get('fixed_version') or '—'}[/dim]")
    if len(findings) > 30:
        _print(f"  [dim]… and {len(findings) - 30} more — pass --output for full JSON[/dim]")

    if not findings:
        _print("[green]No known-vulnerable dependencies found.[/green]")

    if engagement:
        from heaven.engagement import EngagementStore
        db_path = _engagement_db_path(engagement)
        if not db_path.exists():
            _print(f"[red]Engagement DB not found:[/red] {db_path}")
            sys.exit(2)
        store = EngagementStore(db_path)
        scan_id = f"sca-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(
            scan_id, name=f"SCA: {Path(path).name}", mode="sca",
            config={"path": str(Path(path).resolve()),
                    "manifests": result["manifests"]},
        )
        persisted = 0
        for f in findings:
            store.upsert_finding(scan_id, f)
            persisted += 1
        store.record_scan_complete(scan_id, {"findings_count": persisted})
        _print(f"\n[green]Persisted[/green] {persisted} finding(s) into engagement "
               f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")

    if output:
        Path(output).write_text(
            json.dumps({**result, "findings": findings}, indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(sca)

"""HEAVEN — `heaven sast` (static application security testing via Semgrep)."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


@click.group(name="sast")
def sast() -> None:
    """Static source-code analysis via Semgrep + HEAVEN's curated rule pack."""


@sast.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--engagement", default=None,
              help="Engagement to persist findings into (optional — without "
                   "it, results print to stdout only)")
@click.option("--extra-config", multiple=True,
              help="Extra Semgrep config (registry pack or local .yml). "
                   "Repeatable. Default = HEAVEN curated rules.")
@click.option("--no-builtin", is_flag=True,
              help="Skip HEAVEN's built-in rule pack — rely on --extra-config only.")
@click.option("--timeout", type=int, default=300,
              help="Hard cap on Semgrep runtime (seconds). Default 300.")
@click.option("--output", "-o", type=click.Path(),
              help="Write the full JSON result to this path.")
def scan(path: str, engagement: Optional[str],
         extra_config: tuple[str, ...], no_builtin: bool,
         timeout: int, output: Optional[str]) -> None:
    """Run Semgrep against a source path.

    Findings are normalised to HEAVEN's finding shape and (if --engagement is
    supplied) persisted alongside runtime DAST findings — so the SAST + DAST
    sides of the same vulnerability cluster in one report.

    Examples:

        # Scan a local repo with HEAVEN's curated rules
        heaven sast scan ./my-app --engagement q1-pentest

        # Add the OWASP Top 10 registry pack on top of HEAVEN's rules
        heaven sast scan ./my-app \\
            --engagement q1-pentest \\
            --extra-config p/owasp-top-ten \\
            --extra-config p/python

        # Just look — don't persist
        heaven sast scan ./src --output sast.json
    """
    from heaven.vulnscan.sast_runner import has_semgrep, run_sast, persist_findings

    if not has_semgrep():
        _print("[red]semgrep not installed.[/red]")
        _print("[dim]Install:[/dim] [cyan]pip install semgrep[/cyan]")
        sys.exit(2)

    result = asyncio.run(run_sast(
        path,
        extra_configs=list(extra_config),
        use_builtin_rules=not no_builtin,
        timeout_s=timeout,
    ))

    if not result.success:
        _print(f"[red]SAST failed:[/red] {result.error}")
        sys.exit(2)

    _print(f"[bold]SAST results[/bold] · semgrep {result.semgrep_version or '?'} · "
           f"{result.files_scanned} file(s) scanned in {result.duration_s:.1f}s")
    sev = result.severity_breakdown
    _print(f"  Critical: {sev.get('critical', 0)}  "
           f"High: {sev.get('high', 0)}  "
           f"Medium: {sev.get('medium', 0)}  "
           f"Low: {sev.get('low', 0)}")
    _print(f"  Total findings: [bold]{len(result.findings)}[/bold]")

    for f in result.findings[:25]:
        sev_color = {"critical": "bold red", "high": "red",
                     "medium": "yellow", "low": "cyan"}.get(f.severity, "dim")
        _print(f"  [{sev_color}]{f.severity[:4].upper():4}[/{sev_color}] "
               f"{f.file_path}:{f.line:<5}  {f.rule_id}")
    if len(result.findings) > 25:
        _print(f"  [dim]… and {len(result.findings) - 25} more — pass --output for full JSON[/dim]")

    if engagement:
        from heaven.engagement import EngagementStore
        db_path = _engagement_db_path(engagement)
        if not db_path.exists():
            _print(f"[red]Engagement DB not found:[/red] {db_path}")
            sys.exit(2)
        store = EngagementStore(db_path)
        scan_id = f"sast-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(
            scan_id, name=f"SAST: {Path(path).name}", mode="sast",
            config={"path": str(Path(path).resolve()),
                    "extra_configs": list(extra_config),
                    "builtin_rules": not no_builtin},
        )
        persisted = persist_findings(store, scan_id, result)
        store.record_scan_complete(scan_id, {
            "findings_count": persisted, "duration_s": result.duration_s,
        })
        _print(f"\n[green]Persisted[/green] {persisted} finding(s) into engagement "
               f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(sast)

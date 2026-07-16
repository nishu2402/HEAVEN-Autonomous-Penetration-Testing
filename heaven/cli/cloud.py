"""HEAVEN — `heaven cloud` credential-free cloud-misconfiguration commands.

    heaven cloud storage <target> [--name extra] [--engagement ENG]

``storage`` hunts for publicly exposed S3 / GCS / Azure Blob buckets whose names
are guessable from the target domain, and distinguishes a **listable** bucket
(critical) from one that merely exists (informational). No cloud credentials are
required — this is the external-tester's first move, complementing the
authenticated ``heaven.recon.cloud_enum`` account audit.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print
import logging
logger = logging.getLogger(__name__)



@click.group(name="cloud")
def cloud() -> None:
    """Cloud-misconfiguration checks (public buckets, metadata SSRF surface)."""


@cloud.command(name="storage")
@click.argument("target")
@click.option("--name", "names", multiple=True,
              help="Extra base name(s) to try (e.g. a company codename).")
@click.option("--provider", "providers", multiple=True,
              type=click.Choice(["s3", "gcs", "azure"]),
              help="Limit to specific providers (default: all).")
@click.option("--limit", default=60, type=int, show_default=True,
              help="Max candidate bucket names to probe.")
@click.option("--engagement", default=None, help="Persist findings to this engagement.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON result.")
def storage_cmd(target: str, names: tuple[str, ...], providers: tuple[str, ...],
                limit: int, engagement: Optional[str], output: Optional[str]) -> None:
    """Probe guessable S3/GCS/Azure buckets derived from TARGET for public exposure."""
    from heaven.vulnscan.cloud_scanner import CloudStorageScanner

    scanner = CloudStorageScanner(providers=list(providers) or None)
    _print(f"[cyan]Hunting public storage buckets for[/cyan] {target}")
    result = asyncio.run(scanner.scan(target, extra_names=list(names), limit=limit))
    if not result.success:
        _print(f"[red]Scan failed:[/red] {result.error}")
        raise SystemExit(1)

    _print(f"[dim]Probed {result.candidates_tried} candidate name(s).[/dim]")
    if not result.buckets:
        _print("[green]No exposed or discoverable buckets found.[/green]")
    for b in result.buckets:
        if b.state == "open":
            _print(f"  [red]{'OPEN':8}[/red] {b.provider:5} {b.bucket}  "
                   f"[dim]{b.detail}[/dim]")
        else:
            _print(f"  [yellow]{'exists':8}[/yellow] {b.provider:5} {b.bucket}  "
                   f"[dim]{b.detail}[/dim]")

    findings = result.to_findings()
    stored = _persist(engagement, findings)
    if stored:
        _print(f"\n[green]{stored} finding(s) stored in engagement '{engagement}'[/green]")
    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2))
        _print(f"[green]JSON written:[/green] {output}")


def _persist(engagement: Optional[str], findings: list[dict]) -> int:
    if not engagement or not findings:
        return 0
    try:
        import uuid

        from heaven.cli._helpers import _engagement_db_path
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        scan_id = f"cloud-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(scan_id, name="cloud/storage", mode="cloud")
        stored = 0
        for f in findings:
            try:
                store.upsert_finding(scan_id, f)
                stored += 1
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
        store.record_scan_complete(scan_id, {"findings": len(findings), "source": "cloud"})
        return stored
    except Exception as e:
        _print(f"[yellow]Could not persist findings: {e}[/yellow]")
        return 0


def register(cli: click.Group) -> None:
    cli.add_command(cloud)

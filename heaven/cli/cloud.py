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


@cloud.command(name="iam")
@click.option("--profile", default=None,
              help="AWS named profile to use (else the default credential chain).")
@click.option("--region", default=None, help="AWS region (default: us-east-1).")
@click.option("--engagement", default=None, help="Persist findings to this engagement.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON result.")
def iam_cmd(profile: Optional[str], region: Optional[str],
            engagement: Optional[str], output: Optional[str]) -> None:
    """Read-only IAM privilege audit of the authenticated AWS identity.

    Supply credentials the standard AWS way (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
    env vars, or a shared profile via --profile). HEAVEN never reads or logs the
    secret — boto3 resolves it — and every call is read-only (STS GetCallerIdentity
    + IAM List*/Get*). Reports over-privileged principals, missing MFA, stale
    access keys, root access keys and weak password policy.
    """
    from heaven.recon.cloud_iam import audit_aws_iam

    _print("[cyan]Auditing authenticated AWS IAM identity (read-only)…[/cyan]")
    result = audit_aws_iam(profile=profile, region=region)
    if not result.get("authenticated"):
        _print(f"[yellow]Not authenticated to AWS:[/yellow] "
               f"{result.get('skipped_reason', 'no valid credentials')}. "
               f"Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (or --profile) and retry.")
        raise SystemExit(1)

    _print(f"[green]Authenticated[/green] to account [bold]{result['account']}[/bold] "
           f"as {result['arn']} ([dim]{result['principal_type']}[/dim])")
    findings = result.get("findings", [])
    issues = [f for f in findings if f.get("vuln_type") != "cloud_iam_authenticated"]
    if not issues:
        _print("[green]No IAM privilege or hygiene issues found for this identity.[/green]")
    _sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for f in issues:
        c = _sev_color.get(f.get("severity", "info"), "dim")
        _print(f"  [{c}]{f.get('severity', 'info').upper():8}[/{c}] {f.get('title', '')}")

    stored = _persist(engagement, findings, name="cloud/iam")
    if stored:
        _print(f"\n[green]{stored} finding(s) stored in engagement '{engagement}'[/green]")
    if output:
        Path(output).write_text(json.dumps(result, indent=2, default=str))
        _print(f"[green]JSON written:[/green] {output}")


def _persist(engagement: Optional[str], findings: list[dict],
             name: str = "cloud/storage") -> int:
    if not engagement or not findings:
        return 0
    try:
        import uuid

        from heaven.cli._helpers import _engagement_db_path
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        scan_id = f"cloud-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(scan_id, name=name, mode="cloud")
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

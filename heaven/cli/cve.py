"""HEAVEN — `heaven cve` dynamic live CVE lookup.

    heaven cve <product> [version] [--vendor V] [--cpe CPE] [--json]
               [--engagement NAME]

Answers the "*the vulnerability is not in my local DB*" question at the command
line: it queries live authoritative feeds (NVD + CIRCL CVE Search) for any
product/version, merges + de-dupes them, enriches with EPSS + Exploit-DB, and
marks which CVEs a concrete version is actually confirmed to be affected by.
With ``--engagement`` the hits are persisted as findings so they land in the
report alongside the DAST/SAST/SCA results. Degrades gracefully offline.
"""

from __future__ import annotations

import asyncio
import json as _json
import sys
import uuid
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


@click.command(name="cve")
@click.argument("product")
@click.argument("version", required=False, default="")
@click.option("--vendor", default="", help="Vendor hint (improves CIRCL matching).")
@click.option("--cpe", default="", help="Exact CPE 2.3 string (overrides product/version).")
@click.option("--limit", default=25, type=int, show_default=True, help="Max CVEs to show.")
@click.option("--engagement", default=None,
              help="Persist the discovered CVEs as findings into this engagement.")
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON.")
def cve_cmd(product: str, version: str, vendor: str, cpe: str, limit: int,
            engagement: Optional[str], as_json: bool) -> None:
    """Look up live CVEs for PRODUCT (optionally at VERSION) from NVD + CIRCL."""
    from heaven.vulnscan.live_cve_feed import LiveCVEFeed

    feed = LiveCVEFeed()
    if not feed.available:
        _print("[yellow]Live CVE lookup needs httpx — install with "
               "`pip install httpx` (or the [recon] extra).[/yellow]")
        raise SystemExit(1)

    records = asyncio.run(feed.discover(product, version, vendor=vendor,
                                        cpe=cpe, max_results=limit))
    if as_json:
        print(_json.dumps({
            "product": product, "version": version,
            "total": len(records), "cves": [r.to_dict() for r in records],
        }, indent=2))
        return

    label = f"{product} {version}".strip()
    _print(f"[cyan]Live CVEs for[/cyan] {label} "
           f"[dim](sources: NVD + CIRCL · enriched: EPSS + Exploit-DB)[/dim]")
    if not records:
        _print("[green]No CVEs returned by the live feeds "
               "(or offline / not indexed).[/green]")
        return
    for r in records:
        colour = {"critical": "red", "high": "yellow", "medium": "white"}.get(
            r.severity, "dim")
        kev = " [red]KEV[/red]" if r.in_kev else ""
        poc = " [magenta]PoC[/magenta]" if r.exploit_available else ""
        epss = f" [dim]EPSS {r.epss:.0%}[/dim]" if r.epss else ""
        conf = "confirmed" if r.version_confirmed else "version-unverified"
        _print(f"  [{colour}]{r.severity:8}[/{colour}] {r.cve_id}  "
               f"CVSS {r.cvss:<4}{kev}{poc}{epss}  [dim]{conf}[/dim]")
        if r.title:
            _print(f"           [dim]{r.title[:90]}[/dim]")
    _print(f"\n[bold]{len(records)}[/bold] CVE(s) — "
           f"[dim]'confirmed' = a version range matched {version or 'the given version'}[/dim]")

    if engagement:
        _persist_cves(engagement, product, version, cpe, records)


def _persist_cves(engagement: str, product: str, version: str, cpe: str,
                  records: list) -> None:
    """Store discovered CVEs as findings in the engagement DB (mirrors `sca`)."""
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        sys.exit(2)
    target = cpe or f"{product} {version}".strip()
    findings = [r.to_finding(target, product, version) for r in records]
    if not findings:
        return
    store = EngagementStore(db_path)
    scan_id = f"cve-{uuid.uuid4().hex[:12]}"
    store.record_scan_start(
        scan_id, name=f"CVE lookup: {target}", mode="cve",
        config={"product": product, "version": version, "cpe": cpe},
    )
    persisted = 0
    for f in findings:
        store.upsert_finding(scan_id, f)
        persisted += 1
    store.record_scan_complete(scan_id, {"findings_count": persisted})
    _print(f"\n[green]Persisted[/green] {persisted} CVE finding(s) into engagement "
           f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")


def register(cli: click.Group) -> None:
    cli.add_command(cve_cmd)

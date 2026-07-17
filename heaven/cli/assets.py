"""HEAVEN — `assets` command: the host & service inventory view.

Shows the open ports, service versions and OS that the network scanner
discovered for an engagement — exactly as nmap observed them. An OS shown as
``(heuristic — unconfirmed)`` was inferred from a TTL, not a stack fingerprint,
and is flagged so a guess is never read as a confirmed fact.
"""

from __future__ import annotations

import json
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


def _collect_engagement_assets(engagement: Optional[str],
                               scan_id: Optional[str] = None) -> list[dict]:
    """Raw host assets from an engagement's persisted scan summaries."""
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement), create=False)
    scans = ([store.get_scan(scan_id)] if scan_id
             else store.list_scans(limit=200))
    raw: list[dict] = []
    for s in scans:
        if not s:
            continue
        blob = s.get("summary_json")
        if not blob:
            continue
        try:
            summ = json.loads(blob)
        except (ValueError, TypeError):
            continue
        raw.extend(a for a in (summ.get("assets") or []) if isinstance(a, dict))
    return raw


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--scan-id", help="Limit to a single scan id (default: whole engagement)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "markdown"]),
              default="table", help="Output format")
def assets(engagement: Optional[str], scan_id: Optional[str], fmt: str) -> None:
    """Show the host & service inventory (open ports, versions, OS)."""
    from heaven.devsecops.inventory import (
        inventory_totals,
        normalize_assets,
        render_markdown,
    )
    if json_output():
        fmt = "json"

    raw = _collect_engagement_assets(engagement, scan_id)
    inventory = normalize_assets(raw)

    if fmt == "json":
        print(json.dumps(
            {"assets": inventory, "totals": inventory_totals(inventory)},
            indent=2, default=str,
        ))
        return

    if not inventory:
        _print("[yellow]No host inventory yet.[/yellow] Run a network scan first, e.g. "
               "[cyan]heaven scan -m network -t <target> --i-have-authorization[/cyan]")
        return

    if fmt == "markdown":
        print(render_markdown(inventory, already_normalized=True))
        return

    tot = inventory_totals(inventory)
    _print(f"\n[bold]Host & Service Inventory[/bold]  [dim]— {tot['hosts']} host(s), "
           f"{tot['open_ports']} open port(s), {tot['distinct_services']} service(s)[/dim]")
    for h in inventory:
        os_txt = h.get("os_label") or "OS not determined"
        _print(f"\n[bold cyan]{h['host']}[/bold cyan]  [dim]{os_txt}[/dim]")
        if not h.get("ports"):
            _print("  [dim]No open ports observed.[/dim]")
            continue
        _print(f"  [dim]{'PORT':>7}  {'PROTO':5}  {'SERVICE':14}  VERSION[/dim]")
        for p in h["ports"]:
            ver = p.get("service_version") or ""
            _print(f"  {p['port']:>7}  {p.get('protocol','tcp'):5}  "
                   f"{(p.get('service') or '—')[:14]:14}  {ver}")
    _print("\n[dim]An OS marked '(heuristic — unconfirmed)' is a TTL guess, not a "
           "stack fingerprint.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(assets)

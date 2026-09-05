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
from heaven.utils.logger import get_logger

logger = get_logger("cli.assets")


def _collect_engagement_assets(engagement: Optional[str],
                               scan_id: Optional[str] = None,
                               all_scans: bool = False) -> list[dict]:
    """Raw host assets from an engagement's persisted scan summaries.

    Scoped to a single scan by default (the most recent one that produced
    assets) so two unrelated scans don't blend into one host table. Pass
    ``all_scans=True`` for the engagement-wide union, or ``scan_id`` to pin a
    specific scan.
    """
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement), create=False)
    scans = ([store.get_scan(scan_id)] if scan_id
             else store.list_scans(limit=200))  # newest first
    raw: list[dict] = []
    fallback: list[dict] = []  # newest asset-bearing scan, used only if none has ports
    result: Optional[list[dict]] = None
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
        found = [a for a in (summ.get("assets") or []) if isinstance(a, dict)]
        if not found:
            continue
        if all_scans or scan_id:
            raw.extend(found)
            continue
        # Default view: pick the most recent scan that actually found open ports.
        # A dead/mistyped host records a host row with zero ports; defaulting to
        # it made the inventory look empty even when an earlier scan had data.
        has_ports = any(a.get("open_ports") or a.get("ports") for a in found)
        if has_ports:
            result = found
            break
        if not fallback:
            fallback = found
    if result is None:
        result = raw if (all_scans or scan_id) else fallback
    # Overlay operator-set device names/types (the Assets manual override) so the
    # CLI inventory AND the CLI report path reflect them too — not only the web
    # report. Mirrors the web ``_collect_raw_assets`` overlay: this is the single
    # point where the CLI reads raw host assets, and best-effort so an old DB with
    # no ``host_labels`` table simply shows no manual labels rather than erroring.
    try:
        labels = store.get_host_labels()
        if labels:
            from heaven.devsecops.inventory import merge_host_labels
            merge_host_labels(result, labels)
    except Exception:
        logger.debug("suppressed non-fatal exception overlaying host labels",
                     exc_info=True)
    return result


def _collect_engagement_dns(engagement: Optional[str],
                            scan_id: Optional[str] = None) -> list[dict]:
    """Raw DNS enumeration records from an engagement's persisted scans.

    DNS records are keyed by domain, so merging every scan's records is
    well-defined (unlike the per-scan host table) — always engagement-wide.
    """
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
        raw.extend(d for d in (summ.get("dns_records") or []) if isinstance(d, dict))
    return raw


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--scan-id", help="Show a single scan id (default: the most recent scan)")
@click.option("--all", "all_scans", is_flag=True,
              help="Merge every scan in the engagement into one inventory")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "markdown"]),
              default="table", help="Output format")
def assets(engagement: Optional[str], scan_id: Optional[str],
           all_scans: bool, fmt: str) -> None:
    """Show the host & service inventory (open ports, versions, OS).

    Shows the most recent scan by default; use --scan-id to pin one or --all to
    merge every scan in the engagement.
    """
    from heaven.devsecops.dns_inventory import dns_totals, normalize_dns
    from heaven.devsecops.dns_inventory import render_markdown as render_dns_markdown
    from heaven.devsecops.inventory import (
        inventory_totals,
        normalize_assets,
        render_markdown,
    )
    if json_output():
        fmt = "json"

    raw = _collect_engagement_assets(engagement, scan_id, all_scans)
    inventory = normalize_assets(raw)
    dns_inv = normalize_dns(_collect_engagement_dns(engagement, scan_id))

    if fmt == "json":
        print(json.dumps(
            {"assets": inventory, "totals": inventory_totals(inventory),
             "dns": dns_inv, "dns_totals": dns_totals(dns_inv)},
            indent=2, default=str,
        ))
        return

    if not inventory and not dns_inv:
        _print("[yellow]No host inventory yet.[/yellow] Run a network scan first, e.g. "
               "[cyan]heaven scan -m network -t <target> --i-have-authorization[/cyan]"
               "\n[dim]DNS records appear here too — run [cyan]heaven dns <domain> "
               "--engagement <name>[/cyan].[/dim]")
        return

    if fmt == "markdown":
        parts = []
        if inventory:
            parts.append(render_markdown(inventory, already_normalized=True))
        if dns_inv:
            parts.append(render_dns_markdown(dns_inv, already_normalized=True))
        print("\n\n".join(p for p in parts if p))
        return

    if inventory:
        tot = inventory_totals(inventory)
        _print(f"\n[bold]Host & Service Inventory[/bold]  [dim] · {tot['hosts']} host(s), "
               f"{tot['open_ports']} open port(s), {tot['distinct_services']} service(s)[/dim]")
        for h in inventory:
            os_txt = h.get("os_label") or "OS not determined"
            _print(f"\n[bold cyan]{h['host']}[/bold cyan]  [dim]{os_txt}[/dim]")
            meta = []
            if h.get("device_name_label"):
                meta.append(f"Device: {h['device_name_label']}")
            if h.get("device_type_label"):
                meta.append(f"Type: {h['device_type_label']}")
            if h.get("mac_label"):
                meta.append(f"MAC: {h['mac_label']}")
            if meta:
                _print(f"  [dim]{'  ·  '.join(meta)}[/dim]")
            if not h.get("ports"):
                _print("  [dim]No open ports observed.[/dim]")
                continue
            _print(f"  [dim]{'PORT':>7}  {'PROTO':5}  {'SERVICE':14}  VERSION[/dim]")
            for p in h["ports"]:
                ver = p.get("service_version") or ""
                _print(f"  {p['port']:>7}  {p.get('protocol','tcp'):5}  "
                       f"{(p.get('service') or '—')[:14]:14}  {ver}")
        _print("\n[dim]An OS marked '(heuristic · unconfirmed)' is a TTL guess, not a "
               "stack fingerprint.[/dim]")

    if dns_inv:
        dtot = dns_totals(dns_inv)
        _print(f"\n[bold]DNS Enumeration[/bold]  [dim] · {dtot['domains']} domain(s), "
               f"{dtot['records']} record(s), {dtot['subdomains']} subdomain(s)[/dim]")
        for n in dns_inv:
            dnssec = "enabled" if (n.get("dnssec") or {}).get("enabled") else "not detected"
            wild = "  ·  wildcard DNS present" if n.get("wildcard") else ""
            _print(f"\n[bold cyan]{n['domain']}[/bold cyan]  [dim]DNSSEC: {dnssec}{wild}[/dim]")
            recs = n.get("records") or {}
            for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
                for val in recs.get(rt, []):
                    _print(f"  [dim]{rt:<5}[/dim] {val}")
            subs = n.get("subdomains") or []
            if subs:
                _print(f"  [bold]Subdomains ({len(subs)}):[/bold]")
                for s in subs:
                    addrs = ", ".join(s.get("addresses") or []) or "—"
                    _print(f"    [green]{s['name']}[/green]  [dim]{addrs}[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(assets)

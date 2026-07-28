"""HEAVEN — `dns` command: the DNS enumeration tool.

Enumerates a domain's DNS surface — A / AAAA / MX / NS / TXT / SOA / CNAME
records, resolvable subdomains, mail servers, nameservers, DNSSEC status — and
optionally the DNS security posture (zone transfer, SPF / DMARC / DKIM,
subdomain takeover). Everything is reported exactly as authoritative DNS returns
it; a subdomain is listed only because it actually resolved.

Results can be persisted into an engagement (``--engagement``) so they surface in
the web **Assets** view's DNS section and the DNS Enumeration section of reports.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


def _render_table(inv: list[dict], totals: dict) -> None:
    _print(f"\n[bold]DNS Enumeration[/bold]  [dim]— {totals['domains']} domain(s), "
           f"{totals['records']} record(s), {totals['subdomains']} subdomain(s), "
           f"{totals['mail_servers']} mail server(s)[/dim]")
    for n in inv:
        dnssec = "enabled" if (n.get("dnssec") or {}).get("enabled") else "not detected"
        wild = "  ·  wildcard DNS present" if n.get("wildcard") else ""
        _print(f"\n[bold cyan]{n['domain']}[/bold cyan]  "
               f"[dim]DNSSEC: {dnssec}{wild}[/dim]")
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


def _persist(engagement: str, records: list[dict], findings: list[dict]) -> None:
    """Persist enumeration + findings into the engagement store.

    Auto-creates the engagement when it does not exist yet: asking to save DNS
    results into ``--engagement acme`` means "put them there", so we create the
    store (with metadata) rather than refusing. An existing engagement is reused.
    """
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    is_new = not db_path.exists()
    store = EngagementStore(db_path)  # create=True — materialises the DB
    if is_new:
        store.create_engagement(engagement)
        _print(f"[dim]Created engagement[/dim] [cyan]{engagement}[/cyan] "
               f"[dim]({db_path})[/dim]")
    scan_id = f"dns-{uuid.uuid4().hex[:12]}"
    domains = ", ".join(r.get("domain", "") for r in records) or "DNS"
    store.record_scan_start(scan_id, name=f"DNS enumeration: {domains}", mode="dns")
    persisted = 0
    for f in findings:
        store.upsert_finding(scan_id, f)
        persisted += 1
    store.record_scan_complete(scan_id, {
        "dns_records": records,
        "assets": [],
        "findings_count": persisted,
    })
    _print(f"\n[green]Persisted[/green] {len(records)} domain record set(s) and "
           f"{persisted} finding(s) into engagement [cyan]{engagement}[/cyan] "
           f"(scan-id: {scan_id})")


@click.command()
@click.argument("domain")
@click.option("--no-subdomains", is_flag=True,
              help="Skip the common-subdomain brute-force enumeration")
@click.option("--no-security", is_flag=True,
              help="Records/subdomains only — skip the DNS security checks "
                   "(zone transfer, SPF/DMARC/DKIM, takeover)")
@click.option("--engagement",
              help="Persist results into this engagement (surfaces in Assets + reports)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "markdown"]),
              default="table", help="Output format")
def dns(domain: str, no_subdomains: bool, no_security: bool,
        engagement: Optional[str], fmt: str) -> None:
    """Enumerate DNS records & subdomains for a DOMAIN.

    Examples:

        heaven dns example.com

        heaven dns example.com --no-subdomains --format json

        heaven dns example.com --engagement acme-q3
    """
    from heaven.devsecops.dns_inventory import (
        dns_totals, normalize_dns, render_markdown,
    )
    from heaven.recon.dns_recon import dns_recon, enumerate_dns

    if json_output():
        fmt = "json"

    async def _run() -> tuple[dict, list[dict]]:
        rec = await enumerate_dns(domain, subdomains=not no_subdomains)
        findings: list[dict] = []
        if not no_security:
            sec = await dns_recon(domain)
            findings = sec.get("findings", [])
        return rec, findings

    rec, findings = asyncio.run(_run())
    inv = normalize_dns([rec]) if rec else []
    totals = dns_totals(inv)

    if fmt == "json":
        print(json.dumps({"dns": inv, "totals": totals, "findings": findings},
                         indent=2, default=str))
    elif fmt == "markdown":
        print(render_markdown(inv, already_normalized=True))
    else:
        if not inv:
            _print(f"[yellow]No DNS records resolved for[/yellow] {domain} "
                   "(is the domain valid / are you online?)")
        else:
            _render_table(inv, totals)
        if findings and fmt == "table":
            _print(f"\n[bold]DNS security issues:[/bold] {len(findings)}")
            for f in findings:
                sev = (f.get("severity") or "info").upper()
                _print(f"  [red]{sev:<8}[/red] {f.get('title', f.get('vuln_type'))}")

    if engagement and (inv or findings):
        _persist(engagement, inv, findings)


def register(cli: click.Group) -> None:
    cli.add_command(dns)

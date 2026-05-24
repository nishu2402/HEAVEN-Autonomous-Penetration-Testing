"""HEAVEN — `heaven tickets` (Jira / Linear ticketing integration)."""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


@click.group(name="tickets")
def tickets() -> None:
    """Push findings to Jira / Linear / other ticketing backends.

    Configured by env vars (see `heaven tickets status`). All backends are
    optional — `heaven tickets push` no-ops when none are configured.
    """


@tickets.command("status")
def status() -> None:
    """Show which ticketing backends are configured + how to configure."""
    from heaven.devsecops.alerting import JiraAlerter, LinearAlerter, TicketingDispatcher
    d = TicketingDispatcher()
    j, lin = JiraAlerter(), LinearAlerter()

    _print(f"[bold]Ticketing backends — configured: {len(d.configured_backends)}[/bold]")
    _print("")
    icon_j = "[green]✓[/green]" if j.configured else "[red]✗[/red]"
    _print(f"  {icon_j} Jira       {j.base_url or '(HEAVEN_JIRA_URL not set)'}")
    if j.configured:
        _print(f"      project: {j.project} · type: {j.issue_type} · user: {j.user}")
    else:
        _print("      Set: HEAVEN_JIRA_URL, HEAVEN_JIRA_USER, HEAVEN_JIRA_TOKEN, HEAVEN_JIRA_PROJECT")

    icon_l = "[green]✓[/green]" if lin.configured else "[red]✗[/red]"
    _print(f"  {icon_l} Linear     " + ("(token set)" if lin.token else "(HEAVEN_LINEAR_TOKEN not set)"))
    if lin.configured:
        _print(f"      team: {lin.team_id}")
    else:
        _print("      Set: HEAVEN_LINEAR_TOKEN, HEAVEN_LINEAR_TEAM_ID")


@tickets.command("push")
@click.argument("finding_id")
@click.option("--engagement", help="Engagement name (default: active)")
def push(finding_id: str, engagement: Optional[str]) -> None:
    """Push a single finding to every configured ticketing backend."""
    from heaven.devsecops.alerting import TicketingDispatcher
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        sys.exit(2)

    store = EngagementStore(db_path)
    f = store.get_finding(finding_id)
    if not f:
        _print(f"[red]Finding not found:[/red] {finding_id}")
        sys.exit(2)

    d = TicketingDispatcher()
    if not d.has_any:
        _print("[yellow]No ticketing backends configured.[/yellow]")
        _print("[dim]See: heaven tickets status[/dim]")
        sys.exit(2)

    finding_dict = {
        "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
        "title": f.title, "severity": f.severity, "confidence": f.confidence,
        "cve_id": f.cve_id,
    }
    result = asyncio.run(d.dispatch(finding_dict))
    for backend, r in result.items():
        if r.get("ok"):
            _print(f"  [green]✓[/green] {backend}: {r.get('key', '')} ({r.get('url', '')})")
        else:
            _print(f"  [red]✗[/red] {backend}: {r.get('error', 'unknown error')}")


@tickets.command("bulk")
@click.option("--engagement", help="Engagement name (default: active)")
@click.option("--severity",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="critical",
              help="Minimum severity to push (default: critical)")
@click.option("--status",
              type=click.Choice(["open", "verified"]), default="open",
              help="Only push findings with this status")
@click.option("--limit", type=int, default=50,
              help="Cap on how many findings to push in one go")
@click.option("--dry-run", is_flag=True,
              help="Show what would be pushed without actually creating tickets")
def bulk(engagement: Optional[str], severity: str, status: str,
         limit: int, dry_run: bool) -> None:
    """Bulk-push all matching findings to ticketing.

    Default: critical + open findings.
    """
    from heaven.devsecops.alerting import TicketingDispatcher
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        sys.exit(2)

    store = EngagementStore(db_path)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    keep_sev = {s for s, r in sev_rank.items() if r <= sev_rank[severity]}

    candidates = [
        f for f in store.list_findings(status=status, limit=limit * 4)
        if f.severity in keep_sev
    ][:limit]

    if not candidates:
        _print(f"[yellow]No matching findings (severity ≥ {severity}, status = {status}).[/yellow]")
        return

    d = TicketingDispatcher()
    if not d.has_any and not dry_run:
        _print("[yellow]No ticketing backends configured. Use --dry-run to preview.[/yellow]")
        _print("[dim]See: heaven tickets status[/dim]")
        sys.exit(2)

    _print(f"[cyan]Pushing {len(candidates)} finding(s) to "
           f"{', '.join(d.configured_backends) or '(none — dry-run)'}[/cyan]\n")

    async def _go() -> None:
        ok_count = 0
        fail_count = 0
        for f in candidates:
            line = f"  [{f.severity[:4].upper():4}] {f.vuln_type:20} {f.target[:50]}"
            if dry_run:
                _print(f"{line}  [dim](dry-run)[/dim]")
                continue
            finding_dict = {
                "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                "title": f.title, "severity": f.severity,
                "confidence": f.confidence, "cve_id": f.cve_id,
            }
            r = await d.dispatch(finding_dict)
            all_ok = all(v.get("ok") for v in r.values())
            backends = ", ".join(
                f"{k}={v.get('key', 'fail')}" for k, v in r.items()
            )
            if all_ok:
                ok_count += 1
                _print(f"{line}  [green]✓[/green]  {backends}")
            else:
                fail_count += 1
                _print(f"{line}  [red]✗[/red]  {backends}")
        if not dry_run:
            _print(f"\n[bold]Done.[/bold]  [green]{ok_count} ok[/green]  "
                   f"[red]{fail_count} failed[/red]")

    asyncio.run(_go())


def register(cli: click.Group) -> None:
    cli.add_command(tickets)

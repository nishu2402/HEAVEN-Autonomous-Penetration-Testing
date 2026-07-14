"""HEAVEN — `heaven status` system-wide overview command.

A single screen showing: HEAVEN version · LLM gateway state · SIEM
backends · ticketing backends · active engagement summary · last scan
· disk usage of the data dir. Useful for answering "what's the state
of my deployment?" without clicking around the Web UI.

Primary name is `heaven doctor` — the familiar "is my setup healthy?"
idiom (brew doctor / flutter doctor). `heaven sys-status` is kept as a
hidden, backward-compatible alias. Separately, `heaven status` (from
cli/scan.py) lists scans in an engagement. The Web UI equivalent of this
report is GET /api/dashboard.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import click

from heaven import __version__
from heaven.cli._helpers import (
    _engagement_db_path,
    _print,
    resolve_engagement_name,
)


def _run_status(engagement: Optional[str], fmt: str) -> None:
    """Shared implementation behind `heaven doctor` and the `sys-status` alias."""
    from heaven.cli._helpers import json_output
    if json_output():
        fmt = "json"
    report = _collect_status(engagement)
    if fmt == "json":
        print(json.dumps(report, indent=2, default=str))
        return
    _render_pretty(report)


@click.command(name="doctor")
@click.option("--engagement",
              help="Engagement to summarise (default: current `heaven use` / HEAVEN_ENGAGEMENT)")
@click.option("--format", "fmt", type=click.Choice(["pretty", "json"]),
              default="pretty", help="pretty (default) or json")
def doctor(engagement: Optional[str], fmt: str) -> None:
    """Diagnose the deployment: versions, integrations, engagement, disk.

    The "is everything wired up?" command. Reports HEAVEN + Python version,
    optional integrations (LLM / SIEM / ticketing), external tools on PATH,
    the active engagement's last scan, and data-dir disk usage.

    Machine-readable output for CI / health checks:

        heaven doctor --format json | jq .llm.available
    """
    _run_status(engagement, fmt)


@click.command(name="sys-status", hidden=True)
@click.option("--engagement", help="(alias of `heaven doctor`)")
@click.option("--format", "fmt", type=click.Choice(["pretty", "json"]),
              default="pretty")
def sys_status(engagement: Optional[str], fmt: str) -> None:
    """Deprecated alias for `heaven doctor` (kept for backward compatibility)."""
    _run_status(engagement, fmt)


def _collect_status(engagement: Optional[str]) -> dict:
    """Gather every piece of state that might interest an operator."""
    report: dict = {
        "version": __version__,
        "python": sys.version.split()[0],
    }

    # LLM gateway
    try:
        from heaven.ai import get_gateway
        gw = get_gateway()
        report["llm"] = {
            "available": gw.available,
            "provider": gw.provider or None,
            "model": gw.model or None,
            "init_error": gw._init_error,
        }
    except Exception as e:
        report["llm"] = {"available": False, "error": str(e)}

    # SIEM
    try:
        from heaven.devsecops.alerting import SIEMNotifier, WebhookAlerter
        notifier = SIEMNotifier()
        alerter = WebhookAlerter()
        report["siem"] = {
            "backends_active": list(notifier.configured_backends),
            "webhook_url_set": bool(alerter.webhook_url),
        }
    except Exception as e:
        report["siem"] = {"error": str(e)}

    # Ticketing
    try:
        from heaven.devsecops.alerting import TicketingDispatcher
        td = TicketingDispatcher()
        report["ticketing"] = {
            "configured_backends": list(td.configured_backends),
        }
    except Exception as e:
        report["ticketing"] = {"error": str(e)}

    # External tools — names from the shared catalog so `heaven doctor`,
    # `heaven install-tools` and the web System-Health panel never drift.
    from heaven.utils.tool_installer import tool_names
    report["external_tools"] = {name: shutil.which(name) is not None
                                for name in tool_names()}

    # Active engagement (flag > HEAVEN_ENGAGEMENT env > `heaven use` context)
    eng_name = resolve_engagement_name(engagement)
    if eng_name:
        report["engagement"] = _engagement_status(eng_name)
    else:
        report["engagement"] = {
            "active": None,
            "hint": "run `heaven use <name>`, set HEAVEN_ENGAGEMENT, or pass --engagement",
        }

    # Disk usage of data dir
    try:
        data_dir = Path(os.environ.get("HEAVEN_DATA_DIR", "data"))
        if data_dir.exists():
            total = sum(p.stat().st_size for p in data_dir.rglob("*") if p.is_file())
            report["data_dir"] = {
                "path": str(data_dir.resolve()),
                "size_mb": round(total / 1024 / 1024, 2),
            }
        else:
            report["data_dir"] = {"path": str(data_dir), "exists": False}
    except Exception as e:
        report["data_dir"] = {"error": str(e)}

    return report


def _engagement_status(name: str) -> dict:
    """Summarise one engagement: scope size, findings count, last scan."""
    try:
        from heaven.engagement import EngagementStore
        db_path = _engagement_db_path(name)
        if not db_path.exists():
            return {"name": name, "selector": name, "exists": False, "db_path": str(db_path)}
        store = EngagementStore(db_path)
        eng = store.get_engagement()
        stats = store.stats()
        scans = store.list_all_scans()
        last_scan = scans[0] if scans else None
        return {
            "name": eng.name if eng else name,
            # `selector` is the DB stem to pass to --engagement; `name` may be a
            # friendly display name ("demo (sample data)") that isn't a valid
            # store selector, so suggested commands must use `selector`.
            "selector": name,
            "client": eng.client if eng else "",
            "exists": True,
            "db_path": str(db_path),
            "scope_targets": stats.get("scope_targets", 0),
            "total_findings": stats.get("total_findings", 0),
            "scans_run": stats.get("scans_run", 0),
            "by_severity": dict(stats.get("by_severity") or {}),
            "last_scan": {
                "id": last_scan["id"][:8] if last_scan else None,
                "status": last_scan.get("status") if last_scan else None,
                "findings": last_scan.get("findings") if last_scan else None,
                "started_at": last_scan.get("started_at") if last_scan else None,
            } if last_scan else None,
        }
    except Exception as e:
        return {"name": name, "error": str(e)}


def _next_steps(report: dict) -> list[str]:
    """Turn the diagnostic into a guide: the single most useful next command(s)
    given what's already set up. Walks the happy path init → engage → scan →
    report so a brand-new operator is never left wondering 'now what?'."""
    eng = report.get("engagement", {})
    admin_set = bool(os.environ.get("HEAVEN_ADMIN_PASSWORD"))
    # Use the store selector (DB stem) for copy-paste commands, not the friendly
    # display name which can contain spaces/parens and isn't a valid --engagement.
    name = eng.get("selector") or eng.get("name") or "<name>"
    steps: list[str] = []
    # Missing scanner binaries cap HEAVEN below full power — offer the one-shot
    # installer first so the operator lands on a fully-capable setup.
    missing = [t for t, present in (report.get("external_tools") or {}).items() if not present]
    if missing:
        shown = ", ".join(missing[:3]) + ("…" if len(missing) > 3 else "")
        steps.append(f"[cyan]heaven install-tools[/cyan]  — install missing scanners ({shown})")
    if not admin_set:
        steps.append("[cyan]heaven init[/cyan]  — set the Web-UI admin password + optional API keys")
    if not eng.get("exists"):
        steps.append("[cyan]heaven engage init <name>[/cyan]  — create your first engagement")
        steps.append("[cyan]heaven scope add <target> --criticality high[/cyan]  — add an authorized target")
    elif (eng.get("total_findings") or 0) == 0:
        steps.append(
            f"[cyan]heaven scan -u <url> --engagement {name} --i-have-authorization[/cyan]"
            "  — run your first scan"
        )
    else:
        steps.append(f"[cyan]heaven report --engagement {name}[/cyan]  — generate a deliverable")
        steps.append("[cyan]heaven serve[/cyan]  — open the web dashboard")
    return steps


def _render_pretty(report: dict) -> None:
    """Human-friendly two-column layout."""
    v = report["version"]
    _print(f"[bold cyan]🛰  HEAVEN v{v}[/bold cyan]  ·  Python {report['python']}")
    _print("")

    # LLM
    llm = report.get("llm", {})
    if llm.get("available"):
        _print(f"  [green]✓ LLM[/green]        {llm['provider']} ({llm['model']})")
    else:
        err = llm.get("init_error") or llm.get("error") or "no API key set"
        _print(f"  [yellow]· LLM[/yellow]        not configured — {err}")

    # SIEM
    siem = report.get("siem", {})
    backends = siem.get("backends_active") or []
    if backends:
        _print(f"  [green]✓ SIEM[/green]       {', '.join(backends)}")
    elif siem.get("webhook_url_set"):
        _print("  [green]✓ Webhook[/green]    Slack/Teams URL set")
    else:
        _print("  [dim]· SIEM[/dim]       none configured")

    # Ticketing
    tickets = report.get("ticketing", {})
    tb = tickets.get("configured_backends") or []
    if tb:
        _print(f"  [green]✓ Tickets[/green]    {', '.join(tb)}")
    else:
        _print("  [dim]· Tickets[/dim]    no Jira / Linear configured")

    # External tools
    _print("")
    _print("[bold]External tools[/bold]")
    for tool, present in report.get("external_tools", {}).items():
        marker = "[green]✓[/green]" if present else "[yellow]·[/yellow]"
        status = "installed" if present else "not on PATH"
        _print(f"  {marker} {tool:10}  {status}")

    # Engagement
    _print("")
    eng = report.get("engagement", {})
    if not eng.get("exists"):
        _print("[bold]Engagement[/bold]")
        if "hint" in eng:
            _print(f"  [dim]· no active engagement — {eng['hint']}[/dim]")
        else:
            _print(f"  [yellow]· engagement '{eng.get('name','?')}' DB not found[/yellow]")
    else:
        _print(f"[bold]Engagement:[/bold] [cyan]{eng['name']}[/cyan]"
               + (f"  ({eng['client']})" if eng.get('client') else ""))
        _print(f"  Targets in scope: {eng['scope_targets']}")
        _print(f"  Findings:         {eng['total_findings']}")
        _print(f"  Scans run:        {eng['scans_run']}")
        by_sev = eng.get("by_severity") or {}
        if by_sev:
            parts = []
            if by_sev.get("critical"):
                parts.append(f"[bold red]{by_sev['critical']}C[/bold red]")
            if by_sev.get("high"):
                parts.append(f"[red]{by_sev['high']}H[/red]")
            if by_sev.get("medium"):
                parts.append(f"[yellow]{by_sev['medium']}M[/yellow]")
            if by_sev.get("low"):
                parts.append(f"[cyan]{by_sev['low']}L[/cyan]")
            if by_sev.get("info"):
                parts.append(f"[dim]{by_sev['info']}I[/dim]")
            if parts:
                _print("  By severity:      " + "  ".join(parts))
        ls = eng.get("last_scan")
        if ls:
            _print(f"  Last scan:        {ls['id']} · {ls['status']} · "
                   f"{ls['findings']} findings · {(ls['started_at'] or '')[:16]}")

    # Disk usage
    _print("")
    dd = report.get("data_dir", {})
    if dd.get("exists") is False:
        _print(f"[dim]Data dir:  {dd.get('path')} (not created yet)[/dim]")
    elif "size_mb" in dd:
        _print(f"[dim]Data dir:  {dd['path']} · {dd['size_mb']} MB[/dim]")

    # Contextual next step — make the diagnostic a guide, not a dead end.
    _print("")
    _print("[bold]Next step[/bold]")
    for line in _next_steps(report):
        _print(f"  → {line}")


def register(cli: click.Group) -> None:
    cli.add_command(doctor)
    cli.add_command(sys_status)  # hidden backward-compatible alias

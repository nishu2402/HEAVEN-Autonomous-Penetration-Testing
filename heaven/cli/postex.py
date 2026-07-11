"""HEAVEN — `heaven postex` advanced post-exploitation commands.

Three subcommands, all SSH-based, read-only, and authorization-gated:

    heaven postex enum  <host> --user <u> [--password / --key]  --i-have-authorization
    heaven postex loot  <host> --user <u> [--password / --key]  --i-have-authorization
    heaven postex full  <host> --user <u> [--password / --key]  --i-have-authorization

``enum`` runs the self-contained privilege-escalation enumeration engine;
``loot`` harvests reusable credentials (redacted in all output); ``full`` runs
the whole playbook (enum + loot + optional LLM prioritisation) and prints the
ATT&CK kill-chain. Findings can be persisted to the active engagement with
``--engagement``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print


def _auth_args(host: str, user: str, password: str, key: Optional[str],
               port: int, i_have_authorization: bool) -> dict:
    if not i_have_authorization:
        _print("[red]Post-exploitation requires --i-have-authorization[/red]")
        sys.exit(3)
    if not password and not key:
        _print("[red]Provide --password or --key[/red]")
        sys.exit(2)
    return {
        "host": host, "username": user, "password": password or None,
        "private_key": key, "port": port,
    }


def _persist_findings(engagement: Optional[str], findings: list[dict],
                      mode: str = "postex") -> int:
    """Store findings in the engagement DB under a fresh scan record."""
    if not engagement or not findings:
        return 0
    try:
        import uuid

        from heaven.cli._helpers import _engagement_db_path
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        scan_id = f"postex-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(scan_id, name=f"postex/{mode}", mode=mode)
        stored = 0
        for f in findings:
            try:
                store.upsert_finding(scan_id, f)
                stored += 1
            except Exception:
                continue
        store.record_scan_complete(
            scan_id, {"findings": len(findings), "source": "postex"})
        return stored
    except Exception as e:
        _print(f"[yellow]Could not persist findings: {e}[/yellow]")
        return 0


@click.group(name="postex")
def postex() -> None:
    """Advanced post-exploitation: privesc enum, loot harvest, full playbook."""


@postex.command(name="enum")
@click.argument("host")
@click.option("--user", "-u", required=True, help="SSH username on the target.")
@click.option("--password", "-p", default="", help="SSH password.")
@click.option("--key", type=click.Path(exists=True, dir_okay=False), default=None,
              help="SSH private key file.")
@click.option("--port", default=22, type=int, help="SSH port (default 22).")
@click.option("--os", "os_kind", type=click.Choice(["linux", "windows"]),
              default="linux", show_default=True,
              help="Target OS: 'linux' (SUID/sudo/caps) or 'windows' "
                   "(services/privileges/AlwaysInstallElevated).")
@click.option("--engagement", default=None, help="Persist findings to this engagement.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON result.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required — confirm written authorization for this host.")
def enum_cmd(host: str, user: str, password: str, key: Optional[str], port: int,
             os_kind: str, engagement: Optional[str], output: Optional[str],
             i_have_authorization: bool) -> None:
    """Enumerate privilege-escalation vectors on HOST (self-contained, no downloads)."""
    args = _auth_args(host, user, password, key, port, i_have_authorization)
    if os_kind == "windows":
        from heaven.postex import WindowsEnumEngine
        engine: object = WindowsEnumEngine(authorized=True)
    else:
        from heaven.postex import LinuxEnumEngine
        engine = LinuxEnumEngine(authorized=True)
    _print(f"[cyan]Enumerating {os_kind} privesc surface on[/cyan] {user}@{host}:{port}")
    result = asyncio.run(engine.enumerate(**args))  # type: ignore[attr-defined]
    if not result.success:
        _print(f"[red]Enumeration failed:[/red] {result.error}")
        sys.exit(1)

    f = result.facts
    if os_kind == "windows":
        _print(f"\n[bold]Host:[/bold] {f.hostname}  [dim]{f.os} · {f.build}[/dim]")
        _print(f"[bold]User:[/bold] {f.username} (admin={f.is_admin}, "
               f"integrity={f.integrity or '—'})  "
               f"privileges: {', '.join(f.privileges) or '—'}")
    else:
        _print(f"\n[bold]Host:[/bold] {f.hostname}  [dim]{f.os} · kernel {f.kernel}[/dim]")
        _print(f"[bold]User:[/bold] {f.username} (uid={f.uid}, root={f.is_root})  "
               f"groups: {', '.join(f.groups) or '—'}")
    if f.listening_ports:
        _print(f"[bold]Listening:[/bold] {', '.join(map(str, f.listening_ports))}")
    _print(f"\n[bold]Privilege-escalation vectors ({len(result.vectors)}):[/bold]")
    for v in result.vectors:
        colour = {"critical": "red", "high": "yellow"}.get(v["severity"], "white")
        flag = " [dim](needs manual confirm)[/dim]" if v.get("needs_manual_confirm") else ""
        _print(f"  [{colour}]{v['severity']:8}[/{colour}] {v['title']}{flag}")
        if v.get("abuse"):
            _print(f"           [dim]{v['abuse']}[/dim]")

    stored = _persist_findings(engagement, result.to_findings())
    if stored:
        _print(f"\n[green]{stored} finding(s) stored in engagement '{engagement}'[/green]")
    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2))
        _print(f"[green]JSON written:[/green] {output}")


@postex.command(name="loot")
@click.argument("host")
@click.option("--user", "-u", required=True, help="SSH username on the target.")
@click.option("--password", "-p", default="", help="SSH password.")
@click.option("--key", type=click.Path(exists=True, dir_okay=False), default=None,
              help="SSH private key file.")
@click.option("--port", default=22, type=int, help="SSH port (default 22).")
@click.option("--engagement", default=None, help="Persist findings to this engagement.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON result.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required — confirm written authorization for this host.")
def loot_cmd(host: str, user: str, password: str, key: Optional[str], port: int,
             engagement: Optional[str], output: Optional[str],
             i_have_authorization: bool) -> None:
    """Harvest reusable credentials from HOST. Secrets are redacted in all output."""
    args = _auth_args(host, user, password, key, port, i_have_authorization)
    from heaven.postex import LootHarvester
    _print(f"[cyan]Harvesting loot on[/cyan] {user}@{host}:{port}")
    result = asyncio.run(LootHarvester(authorized=True).harvest(**args))
    if not result.success:
        _print(f"[red]Loot harvest failed:[/red] {result.error}")
        sys.exit(1)

    _print(f"\n[bold]Loot ({len(result.items)} item(s)):[/bold]")
    for item in result.items:
        colour = {"critical": "red", "high": "yellow"}.get(item.severity, "white")
        _print(f"  [{colour}]{item.severity:8}[/{colour}] {item.category:20} "
               f"[dim]{item.secret_preview}[/dim]")
    n_creds = sum(len(i.credentials) for i in result.items)
    _print(f"\n[green]{n_creds} reusable credential(s) captured[/green] "
           f"[dim](plaintext kept in-memory only, never written to disk)[/dim]")

    stored = _persist_findings(engagement, result.to_findings())
    if stored:
        _print(f"[green]{stored} finding(s) stored in engagement '{engagement}'[/green]")
    if output:
        # to_dict() is already redacted — safe to write.
        Path(output).write_text(json.dumps(result.to_dict(), indent=2))
        _print(f"[green]JSON written (redacted):[/green] {output}")


@postex.command(name="full")
@click.argument("host")
@click.option("--user", "-u", required=True, help="SSH username on the target.")
@click.option("--password", "-p", default="", help="SSH password.")
@click.option("--key", type=click.Path(exists=True, dir_okay=False), default=None,
              help="SSH private key file.")
@click.option("--port", default=22, type=int, help="SSH port (default 22).")
@click.option("--os", "os_kind", type=click.Choice(["auto", "linux", "windows"]),
              default="auto", show_default=True,
              help="Target OS ('auto' probes it over SSH first).")
@click.option("--no-loot", is_flag=True, help="Skip credential harvesting.")
@click.option("--no-ai", is_flag=True, help="Skip the LLM prioritisation step.")
@click.option("--engagement", default=None, help="Persist findings to this engagement.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON result.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required — confirm written authorization for this host.")
def full_cmd(host: str, user: str, password: str, key: Optional[str], port: int,
             os_kind: str, no_loot: bool, no_ai: bool, engagement: Optional[str],
             output: Optional[str], i_have_authorization: bool) -> None:
    """Run the full post-exploitation playbook on HOST (enum + loot + AI + kill-chain)."""
    args = _auth_args(host, user, password, key, port, i_have_authorization)
    from heaven.postex import PostExSession
    session = PostExSession(
        args["host"], args["username"], password=args["password"],
        private_key=args["private_key"], port=args["port"], authorized=True,
        target_os=os_kind)
    _print(f"[cyan]Full post-exploitation playbook on[/cyan] {user}@{host}:{port}")
    report = asyncio.run(session.run_full_postex(
        enable_loot=not no_loot, ai_analysis=not no_ai))
    if not report.success:
        _print(f"[red]Post-exploitation failed:[/red] {report.error}")
        sys.exit(1)

    _print(f"\n[bold]{len(report.findings)} finding(s)[/bold], "
           f"{report.harvested_credentials} reusable credential(s)")
    _print("\n[bold]ATT&CK kill-chain:[/bold]")
    for step in report.kill_chain:
        techs = ", ".join(f"{t['id']} {t['name']}" for t in step["techniques"])
        _print(f"  [magenta]{step['tactic']:22}[/magenta] {techs}")

    ai = report.ai_analysis
    if ai and ai.get("available"):
        _print(f"\n[bold]AI prioritisation[/bold] [dim]({ai.get('provider')}/{ai.get('model')})[/dim]")
        if ai.get("top_vector"):
            _print(f"  Top path: [yellow]{ai['top_vector']}[/yellow]")
        if ai.get("rationale"):
            _print(f"  {ai['rationale']}")
        for step in ai.get("recommended_next_steps", [])[:5]:
            _print(f"    → {step}")
    elif not no_ai:
        _print("\n[dim]AI prioritisation skipped (no LLM key configured — set "
               "GEMINI_API_KEY to enable).[/dim]")

    stored = _persist_findings(engagement, report.findings)
    if stored:
        _print(f"\n[green]{stored} finding(s) stored in engagement '{engagement}'[/green]")
    if output:
        Path(output).write_text(json.dumps(report.to_dict(), indent=2))
        _print(f"[green]JSON written (redacted):[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(postex)

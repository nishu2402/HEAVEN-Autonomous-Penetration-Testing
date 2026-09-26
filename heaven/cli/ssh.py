"""HEAVEN — `ssh` command: the SSH transport crypto auditor.

A credential-free, read-only audit of an SSH server's advertised cryptography
(the same class of finding `ssh-audit` and commercial scanners report). It reads
the server identification string and the plaintext KEXINIT, then flags weak
host-key, key-exchange, cipher and MAC algorithms, and recognises an AWS Transfer
Family endpoint pinned to a superseded security policy. Everything is backed by
the algorithm names the server itself advertised, so the audit is deterministic
and false-positive-free.

Results can be persisted into an engagement (``--engagement``) so they surface in
the web findings view and reports, exactly like ``heaven dns``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output

_SEV_COLOR = {"critical": "red", "high": "red", "medium": "yellow",
              "low": "cyan", "info": "dim"}


def _render_table(res: dict, host: str, port: int) -> None:
    if not res.get("reachable"):
        _print(f"[yellow]No SSH service reachable on[/yellow] {host}:{port} "
               f"[dim]({res.get('error') or 'no response'})[/dim]")
        return
    _print(f"\n[bold]SSH Crypto Audit[/bold]  [dim]· {host}:{port}[/dim]")
    _print(f"  [dim]banner  [/dim] {res.get('banner') or '—'}")
    if res.get("software"):
        _print(f"  [dim]software[/dim] {res['software']}")
    for label, key in (("kex", "kex"), ("host-keys", "host_keys"),
                       ("ciphers", "ciphers"), ("macs", "macs")):
        vals = res.get(key) or []
        if vals:
            _print(f"  [dim]{label:<9}[/dim] {', '.join(vals)}")
    findings = res.get("findings") or []
    if not findings:
        _print("\n[green]No weak SSH algorithms advertised.[/green] "
               "[dim]The server offers only modern crypto.[/dim]")
        return
    _print(f"\n[bold]Weak crypto ({len(findings)}):[/bold]")
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        color = _SEV_COLOR.get(sev, "white")
        _print(f"  [{color}]{sev.upper():<8}[/{color}] {f.get('title')}")
        _print(f"           [dim]{f.get('description', '').strip()}[/dim]")


def _persist(engagement: str, host: str, port: int, res: dict) -> None:
    """Persist the SSH audit + findings into the engagement store.

    Auto-creates the engagement if it does not exist yet (asking to save into
    ``--engagement acme`` means "put them there"), mirroring ``heaven dns``.
    """
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    is_new = not db_path.exists()
    store = EngagementStore(db_path)
    if is_new:
        store.create_engagement(engagement)
        _print(f"[dim]Created engagement[/dim] [cyan]{engagement}[/cyan] "
               f"[dim]({db_path})[/dim]")
    scan_id = f"ssh-{uuid.uuid4().hex[:12]}"
    store.record_scan_start(scan_id, name=f"SSH crypto audit: {host}:{port}",
                            mode="ssh")
    findings = res.get("findings") or []
    for f in findings:
        store.upsert_finding(scan_id, f)
    store.record_scan_complete(scan_id, {
        "assets": [], "findings_count": len(findings),
        "ssh_audit": {"banner": res.get("banner"), "software": res.get("software"),
                      "kex": res.get("kex"), "host_keys": res.get("host_keys"),
                      "ciphers": res.get("ciphers"), "macs": res.get("macs")},
    })
    _print(f"\n[green]Persisted[/green] {len(findings)} finding(s) into engagement "
           f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")


@click.command()
@click.argument("host")
@click.option("--port", "-p", default=22, show_default=True, type=int,
              help="SSH / SFTP port")
@click.option("--engagement",
              help="Persist results into this engagement (surfaces in findings + reports)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]),
              default="table", help="Output format")
def ssh(host: str, port: int, engagement: Optional[str], fmt: str) -> None:
    """Audit an SSH/SFTP server's advertised cryptography (credential-free).

    Examples:

        heaven ssh scanme.nmap.org

        heaven ssh 10.0.0.5 --port 2222 --format json

        heaven ssh sftp.example.com --engagement acme-q3
    """
    from heaven.vulnscan.ssh_audit import scan_ssh

    if json_output():
        fmt = "json"

    res = asyncio.run(scan_ssh(host, port))

    if fmt == "json":
        print(json.dumps(res, indent=2, default=str))
    else:
        _render_table(res, host, port)

    if engagement and res.get("reachable"):
        _persist(engagement, host, port, res)


def register(cli: click.Group) -> None:
    cli.add_command(ssh)

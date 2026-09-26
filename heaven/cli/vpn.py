"""HEAVEN — `vpn` command: the OpenVPN control-channel exposure probe.

A read-only, unauthenticated check for an OpenVPN server whose control channel
answers packets without ``tls-auth`` / ``tls-crypt``. It sends a genuine
``P_CONTROL_HARD_RESET_CLIENT_V2``; a server hard-reset reply is positive proof
that the control channel is unauthenticated (a hardened server silently drops the
packet). The reply opcode is the evidence, so the finding is deterministic and
false-positive-free. No exploit payload is ever sent.

Results can be persisted into an engagement (``--engagement``), exactly like
``heaven dns`` and ``heaven ssh``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


def _render_table(res: dict, host: str, port: int, proto: str) -> None:
    _print(f"\n[bold]OpenVPN Control-Channel Check[/bold]  "
           f"[dim]· {host}:{port} ({proto})[/dim]")
    op = res.get("response_opcode")
    if not res.get("openvpn_detected"):
        _print("  [dim]No OpenVPN control-channel response.[/dim] "
               "[dim]Either no OpenVPN here, or tls-auth/tls-crypt is enabled "
               "(hardened: the server drops unauthenticated packets).[/dim]")
        return
    _print(f"  [green]OpenVPN detected[/green] [dim](reply opcode {op})[/dim]")
    findings = res.get("findings") or []
    if not findings:
        _print("  [green]Control channel does not answer unauthenticated packets.[/green]")
        return
    _print(f"\n[bold]Findings ({len(findings)}):[/bold]")
    for f in findings:
        sev = (f.get("severity") or "info").upper()
        _print(f"  [yellow]{sev:<8}[/yellow] {f.get('title')}")
        _print(f"           [dim]{f.get('description', '').strip()}[/dim]")


def _persist(engagement: str, host: str, port: int, res: dict) -> None:
    """Persist the OpenVPN probe + findings into the engagement store.

    Auto-creates the engagement if needed, mirroring ``heaven dns`` / ``heaven ssh``.
    """
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    is_new = not db_path.exists()
    store = EngagementStore(db_path)
    if is_new:
        store.create_engagement(engagement)
        _print(f"[dim]Created engagement[/dim] [cyan]{engagement}[/cyan] "
               f"[dim]({db_path})[/dim]")
    scan_id = f"vpn-{uuid.uuid4().hex[:12]}"
    store.record_scan_start(scan_id, name=f"OpenVPN control-channel check: {host}:{port}",
                            mode="vpn")
    findings = res.get("findings") or []
    for f in findings:
        store.upsert_finding(scan_id, f)
    store.record_scan_complete(scan_id, {
        "assets": [], "findings_count": len(findings),
        "openvpn": {"detected": res.get("openvpn_detected"),
                    "response_opcode": res.get("response_opcode")},
    })
    _print(f"\n[green]Persisted[/green] {len(findings)} finding(s) into engagement "
           f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")


@click.command()
@click.argument("host")
@click.option("--port", "-p", default=1194, show_default=True, type=int,
              help="OpenVPN port")
@click.option("--proto", type=click.Choice(["udp", "tcp", "both"]),
              default="both", show_default=True, help="Transport to probe")
@click.option("--engagement",
              help="Persist results into this engagement (surfaces in findings + reports)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]),
              default="table", help="Output format")
def vpn(host: str, port: int, proto: str, engagement: Optional[str],
        fmt: str) -> None:
    """Check an OpenVPN server for an unauthenticated control channel.

    Examples:

        heaven vpn vpn.example.com

        heaven vpn 10.0.0.1 --proto udp --format json

        heaven vpn vpn.example.com --engagement acme-q3
    """
    from heaven.vulnscan.vpn_scanner import scan_openvpn

    if json_output():
        fmt = "json"

    res = asyncio.run(scan_openvpn(host, port, proto))

    if fmt == "json":
        print(json.dumps(res, indent=2, default=str))
    else:
        _render_table(res, host, port, proto)

    if engagement and res.get("findings"):
        _persist(engagement, host, port, res)


def register(cli: click.Group) -> None:
    cli.add_command(vpn)

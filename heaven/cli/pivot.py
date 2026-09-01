"""HEAVEN — `heaven pivot` (single / double network pivoting over SSH jumps)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print


def _parse_jump(spec: str, key: Optional[str]) -> "object":
    """Parse user[:pass]@host[:port] into a JumpSpec."""
    from heaven.postex.pivot import JumpSpec
    if "@" not in spec:
        raise click.BadParameter(f"jump '{spec}' must be user[:pass]@host[:port]")
    creds, _, hostport = spec.rpartition("@")
    if ":" in creds:
        user, password = creds.split(":", 1)
    else:
        user, password = creds, ""
    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostport, 22
    return JumpSpec(host=host, port=port, username=user, password=password,
                    key_path=key or "")


@click.command(name="pivot")
@click.option("--jump", "jumps", multiple=True, required=True,
              help="Jump host as user[:pass]@host[:port]. Repeat for a double "
                   "pivot (first is the foothold, each next tunnels through it).")
@click.option("--key", type=click.Path(exists=True, dir_okay=False), default=None,
              help="SSH private key for jump auth (applied to all jumps).")
@click.option("--target", "-t", "targets", multiple=True,
              help="Host to scan THROUGH the pivot (repeatable). Reaches subnets "
                   "only the last jump can route to.")
@click.option("--ports", default="21,22,23,25,80,139,445,3306,3389,8080",
              help="Comma-separated ports to connect-scan through the pivot.")
@click.option("--socks", is_flag=True,
              help="Start a local SOCKS proxy over the tunnel and keep it open.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the JSON result to this path.")
@click.option("--i-have-authorization", is_flag=True,
              help="Required. Pivoting tunnels into networks behind the foothold.")
def pivot(jumps: tuple[str, ...], key: Optional[str], targets: tuple[str, ...],
          ports: str, socks: bool, output: Optional[str],
          i_have_authorization: bool) -> None:
    """Tunnel through authorized SSH jump host(s) and scan hosts behind them.

    Example — single pivot, scan an internal host reachable only via the foothold:

        heaven pivot --jump msfadmin:msfadmin@192.168.0.162 \\
            -t 10.1.1.20 --ports 22,445,3389 --i-have-authorization

    Example — double pivot:

        heaven pivot --jump user:pw@10.0.0.5 --jump user:pw@192.168.5.230 \\
            -t 192.168.35.100 --i-have-authorization
    """
    if not i_have_authorization:
        _print("[red]Pivoting requires --i-have-authorization[/red]")
        sys.exit(3)

    from heaven.postex.pivot import run_pivot
    jump_specs = [_parse_jump(j, key) for j in jumps]
    port_list = [int(p) for p in ports.split(",") if p.strip().isdigit()]

    _print(f"[cyan]Pivot[/cyan] via {len(jump_specs)} hop(s): "
           + " -> ".join(j.label() for j in jump_specs))

    result = asyncio.run(run_pivot(
        authorized=True, jumps=jump_specs,
        targets=list(targets) or None, ports=port_list, socks=socks))

    if not result["established"]:
        _print(f"[red]Pivot failed:[/red] {'; '.join(result['errors']) or 'unknown'}")
        sys.exit(1)

    _print(f"[green]Pivot established:[/green] {' -> '.join(result['chain'])}")
    if result.get("socks_port"):
        _print(f"[green]SOCKS proxy:[/green] socks5://127.0.0.1:{result['socks_port']}")
    reachable = [r for r in result["reachable"] if r["open"]]
    if reachable:
        _print(f"\n[bold]{len(reachable)} open port(s) reached through the pivot:[/bold]")
        for r in reachable:
            safe_banner = r["banner"][:50].replace("[", r"\[")
            _print(f"  [green]{r['host']}:{r['port']:<6}[/green] {safe_banner}")
    elif targets:
        _print("\n[dim]No open ports found on the given targets through the pivot.[/dim]")
    if result.get("errors"):
        _print(f"[dim]{len(result['errors'])} error(s)[/dim]")

    if output:
        Path(output).write_text(json.dumps(result, indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(pivot)

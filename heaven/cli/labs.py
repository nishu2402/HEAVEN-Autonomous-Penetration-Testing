"""HEAVEN — `heaven labs`: the lab-matrix ledger (what proves what).

Prints, per scan mode, the reproducible vulnerable lab that proves its
detectors live, and the honest status of each. ``--check`` runs the same
validation the test does, so an operator can confirm no mode claims a
capability nothing proves.
"""

from __future__ import annotations

import json as _json

import click

from heaven.cli._helpers import _print

_STATUS_STYLE = {
    "green": "[green]green[/green]",
    "partial": "[yellow]partial[/yellow]",
    "needs-lab": "[cyan]needs-lab[/cyan]",
    "needs-hardware": "[magenta]needs-hardware[/magenta]",
    "needs-agent": "[magenta]needs-agent[/magenta]",
}


@click.command(name="labs")
@click.option("--check", is_flag=True,
              help="Validate the matrix (no mode claims an unproven capability) "
                   "and exit non-zero on any violation.")
@click.option("--json", "as_json", is_flag=True, help="Emit the matrix as JSON.")
def labs(check: bool, as_json: bool) -> None:
    """Show the lab matrix: the ledger tying every scan mode to the real
    vulnerable lab that proves it, with an honest per-mode status."""
    from heaven import labs as lab_matrix

    if check:
        issues = lab_matrix.validate()
        if not issues:
            _print("[green]Lab matrix OK[/green] · every mode's status is backed "
                   "by a real lab or an honest gate.")
            return
        _print(f"[red]{len(issues)} lab-matrix violation(s):[/red]")
        for i in issues:
            _print(f"  [red]•[/red] {i.where}: {i.problem}")
        raise SystemExit(1)

    if as_json:
        # Plain stdout (not the rich console) so the payload stays parseable.
        print(_json.dumps({
            "rows": lab_matrix.matrix_rows(),
            "exploit_labs": lab_matrix.EXPLOIT_LABS,
            "summary": lab_matrix.status_summary(),
        }, indent=2))
        return

    _print("[bold]HEAVEN lab matrix[/bold] "
           "[dim]— a mode earns 10/10 only when green against a real lab[/dim]\n")
    for row in lab_matrix.matrix_rows():
        status = _STATUS_STYLE.get(row["status"], row["status"])
        _print(f"[bold cyan]{row['mode']:10}[/bold cyan] {status}  "
               f"[dim]{row['lab']}[/dim]")
        _print(f"             proves: {row['proves']}")
        if row["note"]:
            _print(f"             [dim]note: {row['note']}[/dim]")
        if row["target"]:
            _print(f"             [dim]target: {row['target']}[/dim]")
        _print("")

    summary = lab_matrix.status_summary()
    parts = [f"{_STATUS_STYLE.get(k, k)}={v}" for k, v in summary.items() if v]
    _print("[bold]Summary:[/bold] " + "  ".join(parts))
    _print("\n[bold]Exploit corpus · proving lab per exploit:[/bold]")
    for eid, lab in lab_matrix.EXPLOIT_LABS.items():
        _print(f"  [cyan]{eid:26}[/cyan] [dim]{lab}[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(labs)

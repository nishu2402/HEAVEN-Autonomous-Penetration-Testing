"""HEAVEN — `heaven self-audit` command (security self-check of the installation)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print
from heaven.utils.logger import print_banner


@click.command(name="self-audit")
@click.option("--output", "-o", type=click.Path(), help="Output report file path")
def self_audit(output: Optional[str]) -> None:
    """Run security self-audit on HEAVEN installation."""
    print_banner()
    _print("[cyan]Running HEAVEN self-security audit...[/cyan]")

    from heaven.security.self_audit import SelfAuditor
    auditor = SelfAuditor()
    report = auditor.run_full_audit()

    score = report["score"]
    grade = report["grade"]
    _print(f"\n[bold]Security score: {score}/100 (grade: {grade})[/bold]")

    sev = report["severity_breakdown"]
    _print(f"  Critical: {sev.get('critical', 0)}  High: {sev.get('high', 0)}  "
           f"Medium: {sev.get('medium', 0)}  Low: {sev.get('low', 0)}")

    for rec in report.get("recommendations", []):
        _print(f"  → {rec}")

    if output:
        Path(output).write_text(json.dumps(report, indent=2))
        _print(f"\n  Full report written to: {output}")


def register(cli: click.Group) -> None:
    cli.add_command(self_audit)

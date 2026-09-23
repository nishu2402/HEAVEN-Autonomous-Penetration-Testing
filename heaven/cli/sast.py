"""HEAVEN — `heaven sast` (static application security testing via Semgrep)."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print
from heaven.utils.logger import get_logger

logger = get_logger("cli.sast")


class _DefaultSubcommandGroup(click.Group):
    """A group that falls back to its ``scan`` subcommand.

    So ``heaven sast ./src`` behaves like ``heaven sast scan ./src`` — matching
    the sibling ``heaven sca ./src`` — while the explicit ``heaven sast scan ...``
    form, ``heaven sast --help`` and ``heaven sast`` (bare) all keep working
    unchanged. The fallback only fires when the first token is a value (not an
    option) that is not already a known subcommand.
    """

    _DEFAULT = "scan"

    def resolve_command(self, ctx, args):  # type: ignore[override]
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            if args and not args[0].startswith("-") and self._DEFAULT in self.commands:
                return super().resolve_command(ctx, [self._DEFAULT, *args])
            raise


@click.group(name="sast", cls=_DefaultSubcommandGroup)
def sast() -> None:
    """Static source-code analysis via Semgrep + HEAVEN's curated rule pack.

    Pass a source path directly (``heaven sast ./my-app``) or use the explicit
    ``heaven sast scan ./my-app`` form; both run the same analysis.
    """


@sast.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--engagement", default=None,
              help="Engagement to persist findings into (optional, without "
                   "it, results print to stdout only)")
@click.option("--extra-config", multiple=True,
              help="Extra Semgrep config (registry pack or local .yml). "
                   "Repeatable. Default = HEAVEN curated rules.")
@click.option("--no-builtin", is_flag=True,
              help="Skip HEAVEN's built-in rule pack, rely on --extra-config only.")
@click.option("--native", "native", is_flag=True,
              help="Use HEAVEN's dependency-free native SAST engine instead of "
                   "Semgrep (multi-language patterns + secret scanning).")
@click.option("--no-secrets", "no_secrets", is_flag=True,
              help="Skip the always-on native secret scan.")
@click.option("--timeout", type=int, default=300,
              help="Hard cap on Semgrep runtime (seconds). Default 300.")
@click.option("--output", "-o", type=click.Path(),
              help="Write the full JSON result to this path.")
def scan(path: str, engagement: Optional[str],
         extra_config: tuple[str, ...], no_builtin: bool,
         native: bool, no_secrets: bool,
         timeout: int, output: Optional[str]) -> None:
    """Run Semgrep against a source path.

    Findings are normalised to HEAVEN's finding shape and (if --engagement is
    supplied) persisted alongside runtime DAST findings, so the SAST + DAST
    sides of the same vulnerability cluster in one report.

    Examples:

        # Scan a local repo with HEAVEN's curated rules
        heaven sast scan ./my-app --engagement q1-pentest

        # Add the OWASP Top 10 registry pack on top of HEAVEN's rules
        heaven sast scan ./my-app \\
            --engagement q1-pentest \\
            --extra-config p/owasp-top-ten \\
            --extra-config p/python

        # Just look, don't persist
        heaven sast scan ./src --output sast.json
    """
    from heaven.vulnscan.sast_runner import has_semgrep, run_sast, persist_findings

    use_native = native or not has_semgrep()
    if native and has_semgrep():
        _print("[dim]Using HEAVEN's native SAST engine (--native).[/dim]")
    elif not has_semgrep():
        _print("[yellow]semgrep not installed · falling back to HEAVEN's native "
               "SAST engine.[/yellow] [dim](pip install semgrep for deeper "
               "dataflow analysis.)[/dim]")

    if use_native:
        from heaven.vulnscan.native_sast import run_native_sast
        result = run_native_sast(path, include_secrets=not no_secrets)
    else:
        result = asyncio.run(run_sast(
            path,
            extra_configs=list(extra_config),
            use_builtin_rules=not no_builtin,
            timeout_s=timeout,
            fallback_native=True,
        ))
        # Always layer the native secret scan on top of Semgrep — its default
        # packs miss most hardcoded credentials.
        if not no_secrets and result.success:
            _merge_native_secrets(result, path)

    if not result.success:
        _print(f"[red]SAST failed:[/red] {result.error}")
        sys.exit(2)

    engine = "native" if use_native else f"semgrep {result.semgrep_version or '?'}"
    _print(f"[bold]SAST results[/bold] · {engine} · "
           f"{result.files_scanned} file(s) scanned in {result.duration_s:.1f}s")
    sev = result.severity_breakdown
    _print(f"  Critical: {sev.get('critical', 0)}  "
           f"High: {sev.get('high', 0)}  "
           f"Medium: {sev.get('medium', 0)}  "
           f"Low: {sev.get('low', 0)}")
    _print(f"  Total findings: [bold]{len(result.findings)}[/bold]")

    for f in result.findings[:25]:
        sev_color = {"critical": "bold red", "high": "red",
                     "medium": "yellow", "low": "cyan"}.get(f.severity, "dim")
        _print(f"  [{sev_color}]{f.severity[:4].upper():4}[/{sev_color}] "
               f"{f.file_path}:{f.line:<5}  {f.rule_id}")
    if len(result.findings) > 25:
        _print(f"  [dim]… and {len(result.findings) - 25} more · pass --output for full JSON[/dim]")

    if engagement:
        from heaven.engagement import EngagementStore
        db_path = _engagement_db_path(engagement)
        if not db_path.exists():
            # Auto-create rather than abort, matching `heaven scan`. Aborting
            # here (the old sys.exit(2)) discarded a completed SAST run just
            # because the engagement name was new — the same "it ran but saved
            # nothing" trap the scan CLI already fixed.
            db_path.parent.mkdir(parents=True, exist_ok=True)
            _print(f"[cyan]Creating engagement:[/cyan] {engagement}")
        store = EngagementStore(db_path)
        try:
            store.create_engagement(name=engagement)
        except Exception:  # noqa: BLE001 — already exists / best-effort
            logger.debug(
                "engagement create was a no-op / already exists", exc_info=True)
        scan_id = f"sast-{uuid.uuid4().hex[:12]}"
        store.record_scan_start(
            scan_id, name=f"SAST: {Path(path).name}", mode="sast",
            config={"path": str(Path(path).resolve()),
                    "extra_configs": list(extra_config),
                    "builtin_rules": not no_builtin},
        )
        persisted = persist_findings(store, scan_id, result)
        store.record_scan_complete(scan_id, {
            "findings_count": persisted, "duration_s": result.duration_s,
        })
        _print(f"\n[green]Persisted[/green] {persisted} finding(s) into engagement "
               f"[cyan]{engagement}[/cyan] (scan-id: {scan_id})")

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, default=str))
        _print(f"\n[green]JSON written:[/green] {output}")


def _merge_native_secrets(result, path: str) -> None:
    """Append native secret findings not already reported (dedup by file+line)."""
    try:
        from heaven.vulnscan.native_sast import run_native_sast
        native = run_native_sast(path, include_secrets=True)
    except Exception:
        return
    have = {(f.file_path, f.line) for f in result.findings}
    added = 0
    for f in native.findings:
        if f.rule_id != "heaven.native.hardcoded-secret":
            continue
        if (f.file_path, f.line) in have:
            continue
        result.findings.append(f)
        added += 1
    if added:
        _print(f"[dim]+ {added} hardcoded-secret finding(s) from the native "
               f"secret scan.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(sast)

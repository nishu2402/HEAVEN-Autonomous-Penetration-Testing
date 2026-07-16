"""HEAVEN — `heaven replay <scan-id>`: deterministic re-execution of a scan.

Different from `resume`: `resume` continues an *interrupted* scan from its
last checkpoint, `replay` re-executes a *completed* scan from scratch with
the same seed so the same findings should be produced. Used to:
  - Verify a finding is reproducible before putting it in a report.
  - Diff results across HEAVEN versions (did the new version regress?).
  - Provide a reviewer with a deterministic re-run for audit.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print
from heaven.config import get_config
import logging
logger = logging.getLogger(__name__)



@click.command()
@click.argument("scan_id")
@click.option("--engagement", help="Engagement name")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Re-confirm authorization for the replayed scan")
@click.option("--new-engagement", default="",
              help="If set, persist the replay into a separate engagement DB "
                   "so original findings are preserved for comparison.")
def replay(scan_id: str, engagement: Optional[str],
           i_have_authorization: bool, new_engagement: str) -> None:
    """Replay a completed scan deterministically (uses the stored --seed)."""
    from heaven.engagement import EngagementStore
    from heaven.orchestrator import build_full_scan
    from heaven.utils.seeding import set_seed

    if not i_have_authorization:
        _print("[red]Replay requires --i-have-authorization[/red]")
        sys.exit(3)

    store = EngagementStore(_engagement_db_path(engagement))
    # list_scans() (SELECT *) carries config_json + mode; list_all_scans() drops
    # them, which would leave every replay with an empty config → no targets.
    all_scans = store.list_scans(limit=1000)
    target_scan = next((s for s in all_scans if s["id"].startswith(scan_id)), None)
    if not target_scan:
        _print(f"[red]Scan not found:[/red] {scan_id}")
        sys.exit(2)

    config_json = target_scan.get("config_json") or "{}"
    original_config = json.loads(config_json)
    targets = original_config.get("targets") or {}
    seed = original_config.get("seed")

    if seed is None:
        _print(
            "[yellow]Warning: the original scan had no --seed set, so this replay "
            "is NOT guaranteed deterministic. Findings may differ.[/yellow]"
        )
    else:
        set_seed(int(seed))
        _print(f"[cyan]Replaying scan[/cyan] {target_scan['id'][:8]} with seed={seed}")

    if not targets.get("ips") and not targets.get("urls"):
        _print("[red]Original scan has no targets in its stored config. Cannot replay.[/red]")
        sys.exit(2)

    # Optionally persist into a SEPARATE engagement DB so the original findings
    # remain untouched for diffing
    if new_engagement:
        store = EngagementStore(_engagement_db_path(new_engagement))
        store.create_engagement(
            name=new_engagement,
            client=f"replay of {scan_id[:8]}",
        )

    cfg = get_config()
    # Reproduce the original scan's focused mode (not a blanket FULL run) so the
    # replay exercises the same modules. Stealth level rides inside ``targets``
    # (targets["stealth_level"]), so it is preserved automatically.
    from heaven.config import ScanMode
    try:
        _replay_mode = ScanMode(target_scan.get("mode")
                                or original_config.get("mode") or "full")
    except ValueError:
        _replay_mode = ScanMode.FULL
    orch = build_full_scan(targets, cfg, checkpoint_store=store,
                           scan_mode=_replay_mode)

    if store:
        store.record_scan_start(
            orch.scan_id, name=f"replay of {target_scan['id'][:8]}",
            mode=target_scan.get("mode", ""),
            config={"targets": targets, "seed": seed,
                    "replayed_from": target_scan["id"]},
        )

    def progress_callback(progress):
        _print(
            f"  [{progress.phase.value}] {progress.progress_pct:.0f}% — {progress.current_task}"
        )

    orch.on_progress(progress_callback)
    try:
        summary = asyncio.run(orch.run())
    except KeyboardInterrupt:
        _print("\n[yellow]Replay aborted.[/yellow]")
        sys.exit(0)

    _print(f"\n[green]Replay complete in {summary['elapsed_seconds']}s[/green]")
    _print(f"  Tasks: {summary['completed']}/{summary['total_tasks']} (failed: {summary['failed']})")

    new_scan_id = summary.get("scan_id", orch.scan_id)
    for f in summary.get("vulnerabilities", []) + summary.get("findings", []):
        try:
            store.upsert_finding(new_scan_id, f)
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
    store.record_scan_complete(new_scan_id, summary)
    _print(f"  [dim]Replayed scan saved as[/dim] [cyan]{new_scan_id[:8]}[/cyan]")
    _print(
        "  [dim]Diff: [/dim][cyan]heaven findings --engagement <name>[/cyan] for both."
    )


def register(cli: click.Group) -> None:
    cli.add_command(replay)

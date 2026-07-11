"""HEAVEN — `heaven update` (refresh Nuclei templates + CVE feeds + ExploitDB CSV).

Run this on a schedule (or manually before a big engagement) so HEAVEN
uses the latest detection rules and CVE knowledge.

What it refreshes:
  - Nuclei template repository  (~10 MB, ~5s)
  - NVD recent-CVE delta         (small daily JSONL append, ~10s)
  - ExploitDB CSV mirror         (~5 MB, ~30s — cached in data/cache/)

Honest scope:
  - Does NOT update HEAVEN's own code (pull the latest source / reinstall with
    `git pull && pip install -e .`, or grab the newest GitHub Release)
  - Does NOT update the trained NVD CVSS model (use `heaven train-model`)
  - Each step degrades gracefully if the corresponding tool isn't installed
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import click

from heaven.cli._helpers import _print


@dataclass
class UpdateSummary:
    nuclei_updated: bool = False
    nuclei_template_count: int = 0
    nvd_new_cves: int = 0
    exploitdb_updated: bool = False
    exploitdb_entry_count: int = 0
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nuclei_updated": self.nuclei_updated,
            "nuclei_template_count": self.nuclei_template_count,
            "nvd_new_cves": self.nvd_new_cves,
            "exploitdb_updated": self.exploitdb_updated,
            "exploitdb_entry_count": self.exploitdb_entry_count,
            "duration_s": round(self.duration_s, 1),
            "errors": self.errors,
        }


def _update_nuclei() -> tuple[bool, str, int]:
    """Run `nuclei -update-templates`. Reports new template count."""
    if not shutil.which("nuclei"):
        return False, "nuclei binary not on PATH", 0
    try:
        proc = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            return False, f"nuclei exit {proc.returncode}: {proc.stderr[:200]}", 0
        tdir = Path.home() / "nuclei-templates"
        count = sum(1 for _ in tdir.rglob("*.yaml")) if tdir.exists() else 0
        return True, "OK", count
    except subprocess.TimeoutExpired:
        return False, "nuclei update timed out after 120s", 0
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", 0


async def _update_nvd_delta() -> tuple[bool, str, int]:
    """Append the last 7 days of new CVEs to the local NVD cache."""
    try:
        from heaven.ml.nvd_pipeline import NVDPipeline
    except Exception as e:
        return False, f"nvd_pipeline not importable: {e}", 0
    try:
        pipeline = NVDPipeline()
        delta = getattr(pipeline, "download_recent", None)
        if delta is None:
            return False, "NVDPipeline.download_recent not implemented yet", 0
        n = await delta(days=7)
        return True, "OK", int(n or 0)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", 0


async def _update_exploitdb() -> tuple[bool, str, int]:
    """Refresh the ExploitDB CSV mirror cached in data/cache/.

    Both `refresh_csv_mirror` (new) and `_ensure_csv_cache` (older) are
    optional — newer builds have one, older builds the other. getattr +
    Any-typed handle keeps mypy quiet across both.
    """
    try:
        import heaven.vulnscan.exploitdb_client as edb  # noqa: F401
    except Exception as e:
        return False, f"exploitdb_client not importable: {e}", 0

    refresh: Any = getattr(edb, "refresh_csv_mirror", None)
    if refresh is not None:
        try:
            n = await refresh()
            return True, "OK", int(n or 0)
        except Exception as e:
            return False, f"{type(e).__name__}: {e}", 0

    ensure: Any = getattr(edb, "_ensure_csv_cache", None)
    if ensure is None:
        return False, "no refresh_csv_mirror / _ensure_csv_cache in this build", 0
    try:
        n = await asyncio.to_thread(ensure)
        return True, "OK", int(n or 0)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", 0


@click.command(name="update")
@click.option("--skip-nuclei", is_flag=True, help="Don't refresh Nuclei templates.")
@click.option("--skip-nvd", is_flag=True, help="Don't fetch new NVD CVEs.")
@click.option("--skip-exploitdb", is_flag=True, help="Don't refresh ExploitDB CSV.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the JSON summary to this path.")
def update_cmd(skip_nuclei: bool, skip_nvd: bool, skip_exploitdb: bool,
               output: Optional[str]) -> None:
    """Refresh detection rules + CVE knowledge.

    Examples:

        heaven update                         # all updaters
        heaven update --skip-exploitdb        # skip the slow CSV download
        heaven update --output update.json    # for CI / cron logging
    """
    t0 = time.time()
    summary = UpdateSummary()

    _print("[bold cyan]🔄 HEAVEN update[/bold cyan]")

    if skip_nuclei:
        _print("  [dim]Nuclei:    skipped[/dim]")
    else:
        _print("  Nuclei templates: refreshing…")
        ok, msg, count = _update_nuclei()
        summary.nuclei_updated = ok
        summary.nuclei_template_count = count
        if ok:
            _print(f"  [green]✓ Nuclei:[/green] {count} template(s) installed")
        else:
            _print(f"  [yellow]⚠ Nuclei:[/yellow] {msg}")
            summary.errors.append(f"nuclei: {msg}")

    if skip_nvd:
        _print("  [dim]NVD:       skipped[/dim]")
    else:
        _print("  NVD delta:  fetching last 7 days…")
        ok, msg, count = asyncio.run(_update_nvd_delta())
        summary.nvd_new_cves = count
        if ok:
            _print(f"  [green]✓ NVD:[/green] {count} new CVE(s) appended")
        else:
            _print(f"  [yellow]⚠ NVD:[/yellow] {msg}")
            summary.errors.append(f"nvd: {msg}")

    if skip_exploitdb:
        _print("  [dim]ExploitDB: skipped[/dim]")
    else:
        _print("  ExploitDB CSV: refreshing mirror…")
        ok, msg, count = asyncio.run(_update_exploitdb())
        summary.exploitdb_updated = ok
        summary.exploitdb_entry_count = count
        if ok:
            _print(f"  [green]✓ ExploitDB:[/green] {count} entries cached")
        else:
            _print(f"  [yellow]⚠ ExploitDB:[/yellow] {msg}")
            summary.errors.append(f"exploitdb: {msg}")

    summary.duration_s = time.time() - t0
    _print(f"\n[bold]Update complete[/bold] in {summary.duration_s:.1f}s")
    if summary.errors:
        _print(f"  [yellow]{len(summary.errors)} step(s) had issues — see logs above[/yellow]")

    if output:
        Path(output).write_text(json.dumps(summary.to_dict(), indent=2))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(update_cmd)

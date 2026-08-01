#!/usr/bin/env python3
"""Render HEAVEN's REAL startup banner + CLI dashboard through a Rich recording
console and export each as an SVG (rasterised to PNG by svg2png.mjs).

The captured version string is whatever ``heaven.__version__`` currently is, so
this stays correct across releases with no edits. Run under the project venv:

    OUT=docs/screenshots ./venv/bin/python scripts/screenshots/capture_terminal.py

Outputs <OUT>/banner.svg and <OUT>/dashboard.svg.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("OUT", REPO / "docs" / "screenshots"))
OUT.mkdir(parents=True, exist_ok=True)

# Isolate: never touch the user's real data/.env while importing the CLI.
os.environ.setdefault("HEAVEN_DATA_DIR", tempfile.mkdtemp(prefix="heaven-shots-"))

from rich.console import Console  # noqa: E402

import heaven  # noqa: E402
import heaven.utils.logger as hlog  # noqa: E402

print(f"heaven.__version__ = {heaven.__version__}", file=sys.stderr)


def _record(width: int) -> Console:
    """A Rich console that records output for save_svg and prints nowhere."""
    return Console(record=True, width=width, theme=hlog.HEAVEN_THEME,
                   file=open(os.devnull, "w"))


# ── Startup banner (gradient box) — banner interior is 66 cols → console 72 ──
rec = _record(72)
hlog.console = rec
hlog.print_banner()
rec.save_svg(str(OUT / "banner.svg"), title="")
print(f"wrote {OUT / 'banner.svg'}", file=sys.stderr)

# ── CLI dashboard (command centre) — wide layout → console 118 ──
import heaven.cli._dashboard as dash  # noqa: E402

# Stub the active-engagement lookup so no stale "Active engagement" line leaks in.
dash.get_current_engagement = lambda: None
rec2 = _record(118)
hlog.console = rec2
dash.show_dashboard()
rec2.save_svg(str(OUT / "dashboard.svg"), title="")
print(f"wrote {OUT / 'dashboard.svg'}", file=sys.stderr)

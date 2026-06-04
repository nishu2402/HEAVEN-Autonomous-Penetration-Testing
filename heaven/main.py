"""
HEAVEN — CLI entry-point shim.

The real CLI lives in the heaven.cli subpackage. This file exists only to
preserve the `heaven = heaven.main:cli` entry point declared in pyproject.toml
and the `python -m heaven.main` invocation path.
"""

from __future__ import annotations

from heaven.cli import cli

__all__ = ["cli"]


if __name__ == "__main__":
    # Pin prog_name so `python -m heaven.main` behaves identically to the
    # `heaven` entry point: consistent "heaven" usage text, and — crucially —
    # Click's shell-completion hook resolves the right _HEAVEN_COMPLETE var
    # (the `heaven completion` command spawns this module to emit the script).
    cli(prog_name="heaven")

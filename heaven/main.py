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
    cli()

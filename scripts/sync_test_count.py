#!/usr/bin/env python3
"""Keep the README's decorative test-count numbers in sync with reality.

The primary Tests badge is a **live** GitHub Actions status badge (never stale),
but the README also prints the test count in a few decorative spots (the capsule
banner, the typing SVG, the summary table, the project-structure line and the
footer). This script counts tests via ``pytest --collect-only`` and rewrites
those numbers so they can never silently drift.

Usage
-----
    python scripts/sync_test_count.py          # rewrite README to the real count
    python scripts/sync_test_count.py --check  # exit 1 if stale (for CI)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# Each pattern captures the number as group 1 and a fixed marker as group 2, so
# the substitution only ever touches the test-count numbers.
# NOTE: the capsule banner number is preceded by a URL-encoded space (`%20`),
# whose own "20" would be swallowed by a leading `\d+` — so anchor it with a
# lookbehind for `%20` instead of matching the separator.
_PATTERNS = (
    r"(?<=%20)(\d+)(%20Tests)",     # capsule-render banner (URL-encoded space)
    r"(\d+)(\+Tests)",              # readme-typing-svg
    r"(\d+)( passing, 0 skipped)",  # Project Summary table
    r"(\d+)( pytest tests)",        # Project Structure
    r"(\d+)( tests · )",            # footer
)


def count_tests() -> int:
    """Return the number of collected tests (respects pyproject ``testpaths``)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    m = re.search(r"(\d+) tests? collected", proc.stdout)
    if not m:
        sys.stderr.write("could not parse test count from pytest output:\n")
        sys.stderr.write(proc.stdout[-500:] + "\n")
        raise SystemExit(2)
    return int(m.group(1))


def sync_text(text: str, n: int) -> str:
    for pat in _PATTERNS:
        text = re.sub(pat, lambda m: f"{n}{m.group(2)}", text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    n = count_tests()
    original = README.read_text()
    updated = sync_text(original, n)
    if original == updated:
        print(f"README test count already in sync ({n}).")
        return 0
    if check:
        sys.stderr.write(
            f"README test count is stale — actual is {n}. "
            f"Run: python scripts/sync_test_count.py\n"
        )
        return 1
    README.write_text(updated)
    print(f"README test count synced to {n}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

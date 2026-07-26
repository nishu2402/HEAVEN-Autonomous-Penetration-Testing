#!/usr/bin/env python3
"""Keep the README's decorative count numbers in sync with reality.

The primary Tests badge is a **live** GitHub Actions status badge (never stale),
but the README also prints two counts in a few decorative spots:

* the **test count** — the Project Summary table, the Project Structure listing
  and the footer stat-line (also the hero poster's alt-text);
* the **module count** — the shields.io badge, the Project Summary table, the
  Project Structure listing and the footer stat-line.

Both are derived mechanically here — tests via ``pytest --collect-only`` and
modules via ``find heaven -name '*.py'`` (i.e. every Python module in the
``heaven/`` package; this equals mypy's source-file count) — and rewritten in
place, so a reviewer who clones the repo and counts gets exactly the printed
number and neither can silently drift.

Usage
-----
    python scripts/sync_test_count.py          # rewrite README to the real counts
    python scripts/sync_test_count.py --check  # exit 1 if stale (for CI)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# Test-count spots. Each captures the number as group 1 and a fixed trailing
# marker as group 2, so the substitution only ever touches the count number.
_TEST_PATTERNS = (
    r"(\d+)( tests \(pytest matrix)",  # Project Summary table
    r"(\d+)( pytest tests)",           # Project Structure listing
    r"(\d+)( tests · )",               # footer stat-line + hero poster alt-text
)

# Module-count spots where the number comes FIRST (marker is group 2).
_MODULE_PATTERNS_NUM_FIRST = (
    r"(\d+)( modules\))",              # Project Structure listing
    r"(\d+)( modules · )",             # footer stat-line
)
# Module-count spots where the number comes LAST (fixed prefix is group 1).
_MODULE_PATTERNS_NUM_LAST = (
    r"(Modules-)(\d+)",                # shields.io badge
    r"(\*\*Modules\*\* \| )(\d+)",     # Project Summary table
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


def count_modules() -> int:
    """Return the number of Python modules in the ``heaven/`` package.

    This is the project's long-standing definition — substantive modules only,
    excluding package-marker ``__init__.py`` files — so the printed figure is
    reproducible via ``find heaven -name '*.py' ! -name __init__.py | wc -l``.
    """
    return sum(1 for p in (ROOT / "heaven").rglob("*.py") if p.name != "__init__.py")


def sync_text(text: str, tests: int, modules: int) -> str:
    for pat in _TEST_PATTERNS:
        text = re.sub(pat, lambda m: f"{tests}{m.group(2)}", text)
    for pat in _MODULE_PATTERNS_NUM_FIRST:
        text = re.sub(pat, lambda m: f"{modules}{m.group(2)}", text)
    for pat in _MODULE_PATTERNS_NUM_LAST:
        text = re.sub(pat, lambda m: f"{m.group(1)}{modules}", text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    tests = count_tests()
    modules = count_modules()
    original = README.read_text()
    updated = sync_text(original, tests, modules)
    if original == updated:
        print(f"README counts already in sync (tests={tests}, modules={modules}).")
        return 0
    if check:
        sys.stderr.write(
            f"README counts are stale — actual tests={tests}, modules={modules}. "
            f"Run: python scripts/sync_test_count.py\n"
        )
        return 1
    README.write_text(updated)
    print(f"README counts synced (tests={tests}, modules={modules}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

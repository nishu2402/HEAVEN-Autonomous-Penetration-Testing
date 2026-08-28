#!/usr/bin/env python3
"""Keep the README's decorative count numbers in sync with reality.

The primary Tests badge is a **live** GitHub Actions status badge (never stale),
but the README also prints four counts in a few decorative spots:

* the **test count** — the Project Summary table, the Project Structure listing,
  the footer stat-line (also the hero poster's alt-text) and the Development
  section's `pytest tests/` quick-command comment;
* the **module count** — the shields.io badge, the Project Summary table, the
  Project Structure listing and the footer stat-line;
* the **API-route count** — the hero poster's alt-text, the Project Structure
  listing and the footer stat-line;
* the **CLI-command count** — the shields.io badge, the "What is HEAVEN" list,
  the Project Summary table, the CLI-reference line, the Project Structure
  listing and the footer stat-line (also the hero poster's alt-text).

All four are derived mechanically here — tests via ``pytest --collect-only``,
modules via ``find heaven -name '*.py'`` (i.e. every Python module in the
``heaven/`` package; this equals mypy's source-file count), API routes by
statically parsing ``heaven/api/server.py`` for the ``@app.<method>("/api/…")``
decorators (deduped by ``(method, path)``, so the two conditionally-registered
``/api/auth/login`` branches count once and WebSocket endpoints are included),
and CLI commands by introspecting the root Click group (exactly what
``heaven --help`` lists) — and rewritten in place, so a reviewer who clones the
repo and counts gets exactly the printed number and none can silently drift.

The hero poster SVGs (``docs/assets/heaven-poster*.svg``) are hand-authored
design artefacts with positionally-placed text, but their three
mechanically-derived counts (tests, CLI commands, API routes) are **also** kept
in sync here — both in the stat block (anchored by each ``<text>`` node's design
x-coordinate) and in the accessibility ``aria-label`` — so the marketing poster
can no longer silently drift from the code the way it used to. The poster's two
hand-set figures (UI pages, scan modes) have no collector and are left untouched.

Usage
-----
    python scripts/sync_test_count.py          # rewrite README + posters to real counts
    python scripts/sync_test_count.py --check  # exit 1 if any is stale (for CI)
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SERVER = ROOT / "heaven" / "api" / "server.py"
POSTERS = (
    ROOT / "docs" / "assets" / "heaven-poster.svg",
    ROOT / "docs" / "assets" / "heaven-poster-light.svg",
)

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "websocket"}

# Test-count spots. Each captures the number as group 1 and a fixed trailing
# marker as group 2, so the substitution only ever touches the count number.
_TEST_PATTERNS = (
    r"(\d+)( tests \(pytest matrix)",  # Project Summary table
    r"(\d+)( pytest tests)",           # Project Structure listing
    r"(\d+)( tests · )",               # footer stat-line + hero poster alt-text
    r"(\d+)( tests\))",                # Development section quick-command comment
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

# API-route spots where the number comes FIRST (marker is group 2).
_ROUTE_PATTERNS = (
    r"(\d+)( API routes)",             # hero poster alt-text + footer stat-line
    r"(\d+)( routes\))",               # Project Structure listing "(NN routes)"
    r"(\d+)( RBAC-protected routes)",  # What-is-HEAVEN + Summary table + REST API
)
# API-route spots where the number comes LAST (fixed prefix is group 1).
_ROUTE_PATTERNS_NUM_LAST = (
    r"(API-FastAPI_)(\d+)",            # shields.io API badge
)

# CLI-command spots where the number comes FIRST (marker is group 2).
_CLI_PATTERNS = (
    r"(\d+)( CLI commands)",           # hero poster alt-text + footer stat-line
    r"(\d+)( commands for scriptable)",  # "What is HEAVEN" bullet
    r"(\d+)( commands\. Run)",         # CLI-reference line ("NN commands. Run …")
    r"(\d+)( commands\))",             # Project Structure listing "(NN commands)"
)
# CLI-command spots where the number comes LAST (fixed prefix is group 1).
_CLI_PATTERNS_NUM_LAST = (
    r"(CLI_Commands-)(\d+)",           # shields.io CLI badge
    r"(\*\*CLI Commands\*\* \| )(\d+)",  # Project Summary table
)

# ── Hero poster (SVG) ────────────────────────────────────────────────────────
# The poster's aria-label lists the same counts with comma separators (not the
# README's middots), and the stat block prints each figure as a bare number in a
# positionally-placed <text> node anchored by its design x-coordinate. Only the
# three collected counts are synced; UI-pages/scan-modes are hand-set.
_POSTER_ARIA = (
    (r"(\d+)( tests, )", "tests"),
    (r"(\d+)( CLI commands, )", "cli"),
    (r"(\d+)( API routes, )", "routes"),
)
_POSTER_TEXT_ANCHORS = (   # (design x-coord of the stat's <text> node, count key)
    ("155", "tests"),
    ("349", "cli"),
    ("543", "routes"),
)


def sync_poster(text: str, values: dict[str, int]) -> str:
    """Rewrite the three collected counts in a hero-poster SVG, in place.

    Touches only the count digits — in the aria-label and in each stat's
    x-anchored ``<text>`` node — leaving the design, the ML R² and the hand-set
    UI-pages/scan-modes figures untouched.
    """
    for pat, key in _POSTER_ARIA:
        text = re.sub(pat, lambda m, v=values[key]: f"{v}{m.group(2)}", text)
    for x, key in _POSTER_TEXT_ANCHORS:
        pat = rf'(<text x="{x}"\s+y="426"[^>]*>)(\d+)(</text>)'
        text = re.sub(pat, lambda m, v=values[key]: f"{m.group(1)}{v}{m.group(3)}", text)
    return text


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


def count_routes() -> int:
    """Return the number of distinct ``/api/*`` routes on the FastAPI app.

    Parsed statically from ``heaven/api/server.py`` (no import, no env, no app
    build), so it is deterministic and reproducible. Each ``@app.<method>(path)``
    decorator on a route handler contributes one ``(method, path)`` pair; the set
    dedupes the two conditionally-registered ``/api/auth/login`` branches to one,
    and WebSocket endpoints are counted (the app is a "REST + WebSocket API").
    Only ``/api/*`` paths count — the SPA catch-all and ``/favicon.ico`` do not.
    """
    tree = ast.parse(SERVER.read_text())
    routes: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not (isinstance(fn, ast.Attribute)
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id == "app"
                    and fn.attr in _ROUTE_METHODS):
                continue
            if not dec.args:
                continue
            first = dec.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.startswith("/api/"):
                    routes.add((fn.attr, first.value))
    return len(routes)


def count_cli_commands() -> int:
    """Return the number of top-level ``heaven <command>`` subcommands.

    Introspected straight from the root Click group — the very object the CLI
    exposes — so it equals what ``heaven --help`` lists and cannot drift from the
    registered command set. ``click`` is a base dependency, so the import always
    resolves in any environment that can run the test suite.
    """
    from heaven.cli import cli
    commands = getattr(cli, "commands", None)
    if commands is None:  # click-absent fallback shim — not the real CLI
        sys.stderr.write(
            "could not introspect CLI commands — is 'click' installed?\n"
        )
        raise SystemExit(2)
    return len(commands)


def sync_text(text: str, tests: int, modules: int, routes: int, cli_commands: int) -> str:
    for pat in _TEST_PATTERNS:
        text = re.sub(pat, lambda m: f"{tests}{m.group(2)}", text)
    for pat in _MODULE_PATTERNS_NUM_FIRST:
        text = re.sub(pat, lambda m: f"{modules}{m.group(2)}", text)
    for pat in _MODULE_PATTERNS_NUM_LAST:
        text = re.sub(pat, lambda m: f"{m.group(1)}{modules}", text)
    for pat in _ROUTE_PATTERNS:
        text = re.sub(pat, lambda m: f"{routes}{m.group(2)}", text)
    for pat in _ROUTE_PATTERNS_NUM_LAST:
        text = re.sub(pat, lambda m: f"{m.group(1)}{routes}", text)
    for pat in _CLI_PATTERNS:
        text = re.sub(pat, lambda m: f"{cli_commands}{m.group(2)}", text)
    for pat in _CLI_PATTERNS_NUM_LAST:
        text = re.sub(pat, lambda m: f"{m.group(1)}{cli_commands}", text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    tests = count_tests()
    modules = count_modules()
    routes = count_routes()
    cli_commands = count_cli_commands()
    counts = f"tests={tests}, modules={modules}, routes={routes}, cli={cli_commands}"
    poster_values = {"tests": tests, "cli": cli_commands, "routes": routes}

    # Every doc surface that prints a derived count, with its rewrite transform.
    targets: list[tuple[Path, str]] = [
        (README, sync_text(README.read_text(), tests, modules, routes, cli_commands)),
    ]
    for poster in POSTERS:
        targets.append((poster, sync_poster(poster.read_text(), poster_values)))

    stale = [(path, updated) for path, updated in targets
             if path.read_text() != updated]
    if not stale:
        print(f"Docs counts already in sync ({counts}).")
        return 0
    names = ", ".join(p.relative_to(ROOT).as_posix() for p, _ in stale)
    if check:
        sys.stderr.write(
            f"Docs counts are stale in: {names} — actual {counts}. "
            f"Run: python scripts/sync_test_count.py\n"
        )
        return 1
    for path, updated in stale:
        path.write_text(updated)
    print(f"Docs counts synced ({counts}) → {names}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

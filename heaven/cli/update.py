"""HEAVEN — `heaven update`: bring this HEAVEN install up to date.

Two things get refreshed, in order:

  1. HEAVEN's own code — a genuine self-update for the standard git-checkout
     install (``git clone`` + ``scripts/install.sh``, which does an *editable*
     ``pip install -e .``). Because the install is editable, a fast-forward
     ``git pull`` makes the new Python live on your very next ``heaven`` command
     with no reinstall. HEAVEN re-runs ``pip install -e .`` only when the
     dependencies changed, and rebuilds the web UI only when the frontend
     changed (its built ``heaven-ui/dist/`` is gitignored, so a plain pull would
     otherwise leave the UI stale).
  2. Detection knowledge — Nuclei templates, the NVD recent-CVE delta, and the
     ExploitDB CSV mirror.

Honest scope & safety (load-bearing — no fabrication, never destroys work):
  - The self-update needs a git checkout installed editable (the installer's
    default). A release tarball / Docker image / non-editable pip install can't
    be updated in place — HEAVEN says so and points you at the right step
    instead of pretending it worked.
  - It NEVER discards uncommitted work: a dirty tree is refused (use ``--force``
    to stash → pull → un-stash, non-destructively), and it only ever
    *fast-forwards* — never a merge, rebase, or ``reset --hard``.
  - It reports the real version it moved to and never claims success on a failed
    pull.
  - Each detection-data step degrades gracefully when its tool isn't installed.

Examples:
    heaven update                 # code (if behind) + detection data
    heaven update --check         # dry-run: is a newer version available?
    heaven update --code-only     # just the self-update
    heaven update --data-only     # just Nuclei/NVD/ExploitDB (pre-2.1 behavior)
    heaven update --force         # update even with local changes (auto-stash)
    heaven update --skip-ui       # don't rebuild the web UI
    heaven update --output u.json # write a JSON summary (CI / cron)
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess  # nosec B404 -- runs vetted CLI tools (git/pip/npm), never a shell
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import click

from heaven.cli._helpers import _print

# ══════════════════════════════════════════════════════════════════════════
#  Self-update core (git-checkout aware).  Pure, subprocess-thin functions so
#  the whole flow is unit-testable by monkeypatching `_run_git` / `_pip_reinstall`
#  / `_ui_rebuild` — no network and no real git needed in tests.
# ══════════════════════════════════════════════════════════════════════════

_VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)
# Touching any of these (or a requirements*.txt) means dependencies/entry points
# may have changed → re-run the editable install so they actually land.
_DEP_FILES = ("pyproject.toml", "setup.py", "setup.cfg")


def _parse_version(text: str) -> str:
    """Pull ``__version__`` out of a ``heaven/__init__.py`` blob (any source)."""
    m = _VERSION_RE.search(text or "")
    return m.group(1) if m else ""


def _root_from_pkg_file(pkg_file: str) -> Optional[Path]:
    """The editable-checkout root for a given ``heaven/__init__.py`` path.

    Returns ``None`` when it is not an updatable git checkout — e.g. HEAVEN was
    installed from a release tarball or lives in ``site-packages`` (non-editable
    pip). We require BOTH a ``.git`` dir and a ``pyproject.toml`` at the root so
    we never try to ``git pull`` something that isn't the HEAVEN repo.
    """
    try:
        root = Path(pkg_file).resolve().parent.parent
    except Exception:  # noqa: BLE001 — a weird __file__ just means "not updatable"
        return None
    if (root / ".git").is_dir() and (root / "pyproject.toml").is_file():
        return root
    return None


def find_repo_root() -> Optional[Path]:
    """Locate the git checkout backing this (editable) install, or ``None``."""
    try:
        import heaven
        pkg_file = heaven.__file__
    except Exception:  # noqa: BLE001
        return None
    if not pkg_file:
        return None
    return _root_from_pkg_file(pkg_file)


def _git_available() -> bool:
    return shutil.which("git") is not None


def _run_git(root: Path, *args: str, timeout: int = 60) -> tuple[int, str, str]:
    """Run a git subcommand in ``root``. Returns ``(returncode, stdout, stderr)``.

    Never raises: a timeout or spawn failure is folded into a non-zero return so
    callers can report it honestly instead of crashing the update.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 -- fixed 'git' argv, no shell
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"git {' '.join(args)} timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"{type(e).__name__}: {e}"


@dataclass
class UpdateCheck:
    """Result of asking 'is a newer HEAVEN available, and can I take it?'."""
    is_git: bool = False
    reason: str = ""              # why not updatable (non-git etc.)
    branch: str = ""
    upstream: str = ""           # e.g. "origin/main"
    remote: str = "origin"
    current_version: str = ""
    latest_version: str = ""
    current_sha: str = ""
    remote_sha: str = ""
    behind: int = 0              # commits we are behind upstream
    ahead: int = 0               # local commits not yet pushed
    dirty: bool = False
    dirty_files: list[str] = field(default_factory=list)
    remote_reachable: bool = True
    available: bool = False      # behind > 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_git": self.is_git,
            "reason": self.reason,
            "branch": self.branch,
            "upstream": self.upstream,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "current_sha": self.current_sha,
            "remote_sha": self.remote_sha,
            "behind": self.behind,
            "ahead": self.ahead,
            "dirty": self.dirty,
            "dirty_files": self.dirty_files,
            "remote_reachable": self.remote_reachable,
            "available": self.available,
            "error": self.error,
        }


def _read_local_version(root: Path) -> str:
    try:
        return _parse_version((root / "heaven" / "__init__.py").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return ""


def _inspect_repo(root: Path) -> UpdateCheck:
    """Local-only facts about the checkout (no network): branch, upstream, HEAD,
    version, and whether the working tree is dirty."""
    c = UpdateCheck(is_git=True)

    rc, branch, _ = _run_git(root, "rev-parse", "--abbrev-ref", "HEAD")
    c.branch = branch if rc == 0 else ""

    rc, up, _ = _run_git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if rc == 0 and up:
        c.upstream = up
        c.remote = up.split("/", 1)[0]
    else:
        # No upstream configured (rare) — fall back to origin/<branch>.
        c.upstream = f"origin/{c.branch}" if c.branch else "origin/main"
        c.remote = "origin"

    rc, sha, _ = _run_git(root, "rev-parse", "HEAD")
    c.current_sha = sha[:12] if rc == 0 else ""
    c.current_version = _read_local_version(root)

    rc, out, _ = _run_git(root, "status", "--porcelain")
    files = [ln for ln in out.splitlines() if ln.strip()] if rc == 0 else []
    c.dirty = bool(files)
    # Porcelain lines are "XY <path>"; strip the 3-char status prefix for display.
    c.dirty_files = [ln[3:] if len(ln) > 3 else ln for ln in files]
    return c


def check_for_update(root: Path, *, fetch: bool = True) -> UpdateCheck:
    """Fetch the remote and report whether a newer version is available.

    ``fetch=False`` skips the network hop (uses the already-known remote ref) —
    handy for tests and offline re-checks.
    """
    if not _git_available():
        return UpdateCheck(is_git=False, reason="git is not installed / not on PATH")

    c = _inspect_repo(root)

    if fetch:
        rc, _, err = _run_git(root, "fetch", "--quiet", "--tags", c.remote, timeout=120)
        if rc != 0:
            c.remote_reachable = False
            c.error = err or "git fetch failed (offline?)"
            return c

    rc, rsha, _ = _run_git(root, "rev-parse", c.upstream)
    c.remote_sha = rsha[:12] if rc == 0 else ""

    # left-right count of `upstream...HEAD`: left = behind, right = ahead.
    rc, counts, _ = _run_git(root, "rev-list", "--left-right", "--count", f"{c.upstream}...HEAD")
    if rc == 0 and counts:
        parts = counts.replace("\t", " ").split()
        if len(parts) == 2:
            c.behind = int(parts[0]) if parts[0].isdigit() else 0
            c.ahead = int(parts[1]) if parts[1].isdigit() else 0

    # The version we'd move to — read straight from the fetched remote file so
    # we can show a real "vX → vY" before touching anything.
    rc, txt, _ = _run_git(root, "show", f"{c.upstream}:heaven/__init__.py")
    c.latest_version = _parse_version(txt) if rc == 0 else ""

    c.available = c.behind > 0
    return c


@dataclass
class CodeUpdateResult:
    applied: bool = False
    from_version: str = ""
    to_version: str = ""
    from_sha: str = ""
    to_sha: str = ""
    pip_reinstalled: bool = False
    ui_rebuilt: bool = False
    stashed: bool = False
    stash_restored: bool = True
    notes: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "from_sha": self.from_sha,
            "to_sha": self.to_sha,
            "pip_reinstalled": self.pip_reinstalled,
            "ui_rebuilt": self.ui_rebuilt,
            "stashed": self.stashed,
            "stash_restored": self.stash_restored,
            "notes": self.notes,
            "error": self.error,
        }


def _pip_reinstall(root: Path) -> tuple[bool, str]:
    """Re-run the editable install so changed dependencies / entry points land."""
    try:
        proc = subprocess.run(  # nosec B603 -- sys.executable + fixed pip argv, no shell
            [sys.executable, "-m", "pip", "install", "-e", str(root), "-q"],
            capture_output=True, text=True, timeout=900,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "pip install failed")[:300]
        return True, "OK"
    except subprocess.TimeoutExpired:
        return False, "pip install timed out after 900s"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def _ui_rebuild(root: Path) -> tuple[bool, str]:
    """Rebuild the web UI (its built ``dist/`` is gitignored, so a pull leaves it
    stale). Best-effort: needs npm + Node 22.22+."""
    ui = root / "heaven-ui"
    if not ui.is_dir():
        return False, "heaven-ui/ not present"
    if shutil.which("npm") is None:
        return (False, "npm not on PATH — rebuild later: "
                       "cd heaven-ui && npm install --legacy-peer-deps && npm run build")
    try:
        inst = subprocess.run(  # nosec B603 B607 -- fixed npm argv, no shell
            ["npm", "install", "--legacy-peer-deps"],
            cwd=str(ui), capture_output=True, text=True, timeout=900,
        )
        if inst.returncode != 0:
            return False, "npm install failed: " + (inst.stderr or inst.stdout or "")[:200]
        bld = subprocess.run(  # nosec B603 B607 -- fixed npm argv, no shell
            ["npm", "run", "build"],
            cwd=str(ui), capture_output=True, text=True, timeout=900,
        )
        if bld.returncode != 0 or not (ui / "dist" / "index.html").is_file():
            return False, "npm run build failed: " + (bld.stderr or bld.stdout or "")[:200]
        return True, "OK"
    except subprocess.TimeoutExpired:
        return False, "UI rebuild timed out"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def _changed_paths(root: Path, old_sha: str, new_ref: str = "HEAD") -> list[str]:
    rc, out, _ = _run_git(root, "diff", "--name-only", old_sha, new_ref)
    return [ln for ln in out.splitlines() if ln.strip()] if rc == 0 else []


def _needs_pip_reinstall(paths: list[str]) -> bool:
    for p in paths:
        base = p.rsplit("/", 1)[-1]
        if base in _DEP_FILES or base.startswith("requirements"):
            return True
    return False


def _needs_ui_rebuild(paths: list[str]) -> bool:
    # Frontend source changed — but the built dist/ isn't tracked, so ignore it.
    return any(
        p.startswith("heaven-ui/") and not p.startswith("heaven-ui/dist/")
        for p in paths
    )


def apply_code_update(root: Path, check: UpdateCheck, *, force: bool = False,
                      skip_ui: bool = False) -> CodeUpdateResult:
    """Fast-forward the checkout to the fetched remote, then reinstall / rebuild
    only what actually changed. Never merges, rebases, or resets hard."""
    res = CodeUpdateResult(
        from_version=check.current_version,
        to_version=check.current_version,
        from_sha=check.current_sha,
    )

    if not check.available:
        res.notes.append("already up to date")
        return res
    if check.dirty and not force:
        res.error = "uncommitted local changes — refusing to overwrite them (use --force to auto-stash)"
        return res

    old_sha = check.current_sha or "HEAD"

    # --force: preserve local changes non-destructively around the pull.
    if check.dirty and force:
        rc, _, err = _run_git(root, "stash", "push", "--include-untracked",
                              "-m", "heaven-update-autostash")
        if rc != 0:
            res.error = f"could not stash local changes: {err}"
            return res
        res.stashed = True

    # Fast-forward ONLY — never a merge commit, rebase, or history rewrite.
    rc, _, err = _run_git(root, "merge", "--ff-only", check.upstream, timeout=120)
    if rc != 0:
        res.error = (f"fast-forward failed ({err or 'the branch has diverged'}). "
                     "Resolve manually, e.g. git -C <repo> pull --rebase")
        if res.stashed:  # give the user their changes back before bailing out
            pc, _, _ = _run_git(root, "stash", "pop")
            res.stash_restored = pc == 0
        return res

    res.applied = True
    rc, sha, _ = _run_git(root, "rev-parse", "HEAD")
    res.to_sha = sha[:12] if rc == 0 else ""
    res.to_version = _read_local_version(root) or check.latest_version

    changed = _changed_paths(root, old_sha, "HEAD")
    if _needs_pip_reinstall(changed):
        ok, msg = _pip_reinstall(root)
        res.pip_reinstalled = ok
        res.notes.append("dependencies changed — reinstalled"
                         if ok else f"pip reinstall failed: {msg}")
    if _needs_ui_rebuild(changed):
        if skip_ui:
            res.notes.append("web UI changed — skipped rebuild (--skip-ui); run: "
                             "cd heaven-ui && npm install --legacy-peer-deps && npm run build")
        else:
            ok, msg = _ui_rebuild(root)
            res.ui_rebuilt = ok
            res.notes.append("web UI rebuilt" if ok else f"web UI rebuild skipped: {msg}")

    if res.stashed:
        pc, _, perr = _run_git(root, "stash", "pop")
        res.stash_restored = pc == 0
        if pc != 0:
            res.notes.append("your local changes are safe in `git stash` "
                             f"(pop conflicted): {perr[:120]}")

    return res


def _non_git_message(indent: str = "  ") -> str:
    return "\n".join([
        f"{indent}This HEAVEN wasn't installed as an editable git checkout, so it",
        f"{indent}can't self-update its code in place. To get the newest version:",
        f"{indent}  • git checkout:  cd <HEAVEN dir> && git pull && ./scripts/install.sh",
        f"{indent}  • Docker:        docker pull <image>:latest, then recreate the container",
        f"{indent}  • Release / zip: download the latest from the GitHub Releases page",
    ])


# ══════════════════════════════════════════════════════════════════════════
#  Detection-data refresh (Nuclei / NVD / ExploitDB) — the pre-2.1 behavior.
# ══════════════════════════════════════════════════════════════════════════


def _update_nuclei() -> tuple[bool, str, int]:
    """Run `nuclei -update-templates`. Reports new template count."""
    if not shutil.which("nuclei"):
        return False, "nuclei binary not on PATH", 0
    try:
        proc = subprocess.run(  # nosec B603 B607 -- fixed argv on PATH, no shell
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
        n = await pipeline.download_recent(days=7)
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


# ══════════════════════════════════════════════════════════════════════════
#  Summary + CLI command
# ══════════════════════════════════════════════════════════════════════════


@dataclass
class UpdateSummary:
    # code self-update
    code_checked: bool = False
    code_updated: bool = False
    from_version: str = ""
    to_version: str = ""
    code_note: str = ""
    pip_reinstalled: bool = False
    ui_rebuilt: bool = False
    # detection data
    nuclei_updated: bool = False
    nuclei_template_count: int = 0
    nvd_new_cves: int = 0
    exploitdb_updated: bool = False
    exploitdb_entry_count: int = 0
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code_checked": self.code_checked,
            "code_updated": self.code_updated,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "code_note": self.code_note,
            "pip_reinstalled": self.pip_reinstalled,
            "ui_rebuilt": self.ui_rebuilt,
            "nuclei_updated": self.nuclei_updated,
            "nuclei_template_count": self.nuclei_template_count,
            "nvd_new_cves": self.nvd_new_cves,
            "exploitdb_updated": self.exploitdb_updated,
            "exploitdb_entry_count": self.exploitdb_entry_count,
            "duration_s": round(self.duration_s, 1),
            "errors": self.errors,
        }


def _render_check(c: UpdateCheck) -> None:
    """Human-readable output for `heaven update --check`."""
    if not c.is_git:
        _print(f"  [yellow]{c.reason or 'not an updatable git checkout'}[/yellow]")
        _print(_non_git_message())
        return
    if not c.remote_reachable:
        _print(f"  [yellow]Couldn't reach the remote:[/yellow] {c.error}")
        _print("  [dim]Check your network / proxy and try again.[/dim]")
        return
    if c.available:
        _print(f"  [bold green]Update available:[/bold green] "
               f"v{c.current_version or '?'} → v{c.latest_version or '?'} "
               f"({c.behind} commit(s) behind {c.upstream})")
        if c.dirty:
            _print(f"  [yellow]Note:[/yellow] {len(c.dirty_files)} uncommitted change(s) ·  "
                   "`heaven update` will hold back unless you pass --force.")
        _print("  Run [bold]heaven update[/bold] to apply.")
    else:
        _print(f"  [green]You're on the latest version[/green] (v{c.current_version or '?'}).")
        if c.ahead:
            _print(f"  [dim]({c.ahead} local commit(s) ahead of {c.upstream}.)[/dim]")


def _self_update(summary: UpdateSummary, *, force: bool, skip_ui: bool) -> None:
    """Run the code self-update, recording results into ``summary``."""
    summary.code_checked = True
    root = find_repo_root()
    if root is None:
        _print("  [yellow]⚠ Code:[/yellow] not an editable git checkout · can't self-update in place.")
        _print(_non_git_message(indent="    "))
        summary.code_note = "not an updatable git checkout"
        summary.errors.append("code: not an updatable git checkout")
        return

    _print("  HEAVEN code: checking remote…")
    c = check_for_update(root)

    if not c.is_git:
        _print(f"  [yellow]⚠ Code:[/yellow] {c.reason}")
        summary.code_note = c.reason
        summary.errors.append(f"code: {c.reason}")
        return
    if not c.remote_reachable:
        _print(f"  [yellow]⚠ Code:[/yellow] couldn't reach the remote ({c.error}) · skipping self-update.")
        summary.code_note = f"remote unreachable: {c.error}"
        summary.errors.append(f"code: {c.error}")
        return

    summary.from_version = c.current_version
    summary.to_version = c.current_version

    if not c.available:
        _print(f"  [green]✓ Code:[/green] already up to date (v{c.current_version or '?'})")
        summary.code_note = "up to date"
        return
    if c.dirty and not force:
        _print(f"  [yellow]⚠ Code:[/yellow] v{c.latest_version or '?'} is available, but you have "
               f"{len(c.dirty_files)} uncommitted change(s) — not overwriting them.")
        for f_ in c.dirty_files[:8]:
            _print(f"      [dim]· {f_}[/dim]")
        if len(c.dirty_files) > 8:
            _print(f"      [dim]· …and {len(c.dirty_files) - 8} more[/dim]")
        _print("      Commit/stash them, or re-run with [bold]--force[/bold] (auto-stash).")
        summary.code_note = "held back: uncommitted local changes"
        summary.errors.append("code: uncommitted local changes (use --force)")
        return

    _print(f"  HEAVEN code: v{c.current_version or '?'} → v{c.latest_version or '?'} "
           f"({c.behind} commit(s)) — updating…")
    res = apply_code_update(root, c, force=force, skip_ui=skip_ui)
    summary.from_version = res.from_version
    summary.to_version = res.to_version
    summary.pip_reinstalled = res.pip_reinstalled
    summary.ui_rebuilt = res.ui_rebuilt

    if res.applied:
        summary.code_updated = True
        summary.code_note = "updated"
        _print(f"  [green]✓ Code updated:[/green] v{res.from_version or '?'} → v{res.to_version or '?'}")
        for n in res.notes:
            _print(f"      [dim]· {n}[/dim]")
        _print("      [dim]The new version is active on your next `heaven` command.[/dim]")
    else:
        summary.code_note = res.error or "not applied"
        _print(f"  [yellow]⚠ Code:[/yellow] {res.error or 'update did not apply'}")
        for n in res.notes:
            _print(f"      [dim]· {n}[/dim]")
        summary.errors.append(f"code: {res.error or 'not applied'}")


def _refresh_detection_data(summary: UpdateSummary, skip_nuclei: bool,
                            skip_nvd: bool, skip_exploitdb: bool) -> None:
    """Refresh Nuclei templates + NVD delta + ExploitDB CSV."""
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


@click.command(name="update")
@click.option("--check", "check_only", is_flag=True,
              help="Dry-run: report whether a newer version is available; change nothing.")
@click.option("--code-only", is_flag=True,
              help="Only self-update HEAVEN's code (skip the detection-data refresh).")
@click.option("--data-only", is_flag=True,
              help="Only refresh detection data (skip the code self-update).")
@click.option("--force", is_flag=True,
              help="Update code even with uncommitted local changes (auto-stash, non-destructive).")
@click.option("--skip-ui", is_flag=True,
              help="Don't rebuild the web UI even if the frontend changed.")
@click.option("--skip-nuclei", is_flag=True, help="Don't refresh Nuclei templates.")
@click.option("--skip-nvd", is_flag=True, help="Don't fetch new NVD CVEs.")
@click.option("--skip-exploitdb", is_flag=True, help="Don't refresh ExploitDB CSV.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the JSON summary to this path.")
def update_cmd(check_only: bool, code_only: bool, data_only: bool, force: bool,
               skip_ui: bool, skip_nuclei: bool, skip_nvd: bool, skip_exploitdb: bool,
               output: Optional[str]) -> None:
    """Update HEAVEN: its own code (git self-update) and its detection data.

    Examples:

        heaven update                    # code (if behind) + Nuclei/NVD/ExploitDB
        heaven update --check            # is a newer version available?
        heaven update --code-only        # just the self-update
        heaven update --data-only        # just detection data (the old behavior)
        heaven update --force            # update despite local changes (auto-stash)
        heaven update --output u.json    # for CI / cron logging
    """
    t0 = time.time()

    # ── --check: dry-run, report availability, change nothing ──────────────
    if check_only:
        _print("[bold cyan]🔄 HEAVEN update · checking for a newer version[/bold cyan]")
        root = find_repo_root()
        if root is None:
            _print("  [yellow]Not an editable git checkout · can't self-update in place.[/yellow]")
            _print(_non_git_message())
            return
        c = check_for_update(root)
        _render_check(c)
        if output:
            Path(output).write_text(json.dumps(c.to_dict(), indent=2))
            _print(f"\n[green]JSON written:[/green] {output}")
        return

    if code_only and data_only:
        _print("[yellow]--code-only and --data-only are mutually exclusive; doing both.[/yellow]")
        code_only = data_only = False

    do_code = not data_only
    do_data = not code_only

    summary = UpdateSummary()
    _print("[bold cyan]🔄 HEAVEN update[/bold cyan]")

    if do_code:
        _self_update(summary, force=force, skip_ui=skip_ui)
    if do_data:
        _refresh_detection_data(summary, skip_nuclei, skip_nvd, skip_exploitdb)

    summary.duration_s = time.time() - t0
    _print(f"\n[bold]Update complete[/bold] in {summary.duration_s:.1f}s")
    if summary.code_updated:
        _print(f"  [green]HEAVEN is now v{summary.to_version or '?'}[/green] ·  "
               "active on your next `heaven` command.")
    if summary.errors:
        _print(f"  [yellow]{len(summary.errors)} step(s) had issues · see above[/yellow]")

    if output:
        Path(output).write_text(json.dumps(summary.to_dict(), indent=2))
        _print(f"\n[green]JSON written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(update_cmd)

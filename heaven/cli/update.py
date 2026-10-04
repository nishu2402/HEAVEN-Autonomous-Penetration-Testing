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
import os
import re
import shutil
import socket
import subprocess  # nosec B404 # runs vetted CLI tools (git/pip/npm), never a shell
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

# Tracked files that HEAVEN's OWN build regenerates deterministically. A fresh
# `git clone && ./scripts/install.sh` (and the updater's own UI rebuild) used to
# run `npm install`, which rewrites the tracked lockfile — so a just-installed
# tree shows up "dirty" on these through no user action, which then made every
# self-update refuse ("uncommitted changes"). That is the trap essentially every
# user hits once. These are safe to reset to HEAD before a fast-forward because
# the post-update rebuild regenerates them from source (package.json), so no real
# work is lost. NEVER add a hand-edited source file here — only machine-generated
# build artifacts that happen to be tracked. Builds now prefer `npm ci` (see
# `_ui_rebuild` / install.sh), which never writes the lockfile, so new installs
# stop generating this phantom dirt at the source; this list is the bridge for
# trees already dirtied by an older `npm install`.
_REGENERABLE_TRACKED = frozenset({
    "heaven-ui/package-lock.json",
})


def _porcelain_path(line: str) -> str:
    """Extract the path from a ``git status --porcelain`` line, tolerant of the
    leading space our :func:`_run_git` strips off the first entry.

    Porcelain v1 lines are ``XY <path>`` (two single-char status columns then a
    space). Because ``_run_git`` runs ``.strip()`` on the whole blob, the FIRST
    line can arrive with its leading space removed (``M <path>`` instead of
    `` M <path>``), so a fixed ``line[3:]`` slice ate the first character of that
    path. Strip a leading run of status chars followed by a space instead, which
    is correct whether or not that leading space survived.
    """
    return re.sub(r"^[ MADRCUT?!]{1,2} ", "", line)


def _classify_dirty(files: list[str]) -> tuple[list[str], list[str]]:
    """Split dirty paths into ``(regenerable_artifacts, blocking_user_edits)``.

    Regenerable artifacts are machine-generated files the build itself rewrites
    and can safely reset+regenerate; everything else is treated as genuine work
    that must never be overwritten without an explicit ``--force``.
    """
    regen: list[str] = []
    blocking: list[str] = []
    for f in files:
        (regen if f in _REGENERABLE_TRACKED else blocking).append(f)
    return regen, blocking


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
        proc = subprocess.run(  # nosec B603 B607 # fixed 'git' argv, no shell
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"git {' '.join(args)} timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"{type(e).__name__}: {e}"


# ── Pre-flight remote reachability ───────────────────────────────────────────
# git cannot bound its own TCP connect on every platform: `http.connectTimeout`
# is a libcurl option only some builds honor (on macOS git 2.54 it is ignored, so
# a dead host hangs ~21-75s on the kernel's SYN timeout before `git fetch` gives
# up). That is exactly the long opaque hang users hit when GitHub is blocked by a
# firewall/VPN or the box is offline. So before the real fetch we do ONE short,
# bounded TCP connect to the remote host and, if it fails, report an honest,
# classified, actionable message in seconds instead. The probe FAILS OPEN (treats
# the remote as reachable) whenever it can't be sure — behind a proxy, a local
# path remote, or on any probe glitch — so it can never block a legitimate update;
# it only short-circuits a genuinely unreachable network.

DEFAULT_CONNECT_TIMEOUT_S = 6.0
_PROXY_ENV_KEYS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                   "ALL_PROXY", "all_proxy")
_SCHEME_DEFAULT_PORT = {"https": 443, "http": 80, "ssh": 22, "git": 9418}


def _connect_timeout_s() -> float:
    """Per-probe TCP connect budget (seconds). Override with
    ``HEAVEN_UPDATE_CONNECT_TIMEOUT``; clamped to a sane 1-30s window."""
    try:
        return max(1.0, min(30.0, float(
            os.environ.get("HEAVEN_UPDATE_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT_S))))
    except (TypeError, ValueError):
        return DEFAULT_CONNECT_TIMEOUT_S


def _parse_remote_endpoint(url: str) -> Optional[tuple[str, int, str]]:
    """``(host, port, scheme)`` to TCP-probe for a git remote URL, or ``None`` when
    it is a local path / unparseable (then the probe is skipped and git just tries).

    Handles ``https`` / ``http`` / ``ssh`` / ``git`` URLs and the scp-like
    ``git@host:owner/repo.git`` form, stripping any embedded credentials.
    """
    url = (url or "").strip()
    if not url:
        return None
    if "://" not in url:
        # scp-like `[user@]host:path`. Distinguish from a local path (`/repo`,
        # `./x`) and a Windows drive (`C:\repo`): the part before the first colon
        # must have no slash AND either carry a `user@` or look like a hostname
        # (contain a dot), which a bare drive letter never does.
        head = url.split(":", 1)[0]
        if ":" in url and "/" not in head and ("@" in head or "." in head):
            host = head.split("@", 1)[-1]
            if host:
                return host, 22, "ssh"
        return None
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return None
        scheme = (parts.scheme or "").lower()
        port = parts.port or _SCHEME_DEFAULT_PORT.get(scheme, 443)
        return host, int(port), scheme or "https"
    except Exception:  # noqa: BLE001 — unparseable URL → skip the probe
        return None


def _probe_tcp(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """One bounded TCP connect. Returns ``(reachable, reason_if_not)`` with the
    failure classified so the message can tell network-down from DNS from a block.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except socket.gaierror:
        return False, f"DNS lookup for {host} failed"
    except (socket.timeout, TimeoutError):
        return False, f"connection to {host}:{port} timed out after {timeout:.0f}s"
    except ConnectionRefusedError:
        return False, f"{host}:{port} refused the connection"
    except OSError as e:  # no route to host, network down, etc.
        return False, f"{host}:{port} unreachable ({e.strerror or type(e).__name__})"


def _proxy_configured(root: Path) -> bool:
    """A proxy routes git's traffic, so a direct TCP probe would wrongly report the
    remote unreachable. Detect one (env vars or git's own ``http.proxy``) and skip
    the probe when present."""
    if any(os.environ.get(k) for k in _PROXY_ENV_KEYS):
        return True
    rc, out, _ = _run_git(root, "config", "--get", "http.proxy")
    return rc == 0 and bool(out.strip())


def _remote_endpoint(root: Path, remote: str) -> Optional[tuple[str, int, str]]:
    """Resolve the ``remote``'s URL (via git) into a probe endpoint, or ``None``."""
    rc, url, _ = _run_git(root, "remote", "get-url", remote)
    if rc != 0 or not url:
        rc, url, _ = _run_git(root, "config", "--get", f"remote.{remote}.url")
    return _parse_remote_endpoint(url if rc == 0 else "")


def _preflight_remote(root: Path, remote: str) -> tuple[bool, str, str]:
    """Fast reachability pre-check before the slow ``git fetch``.

    Returns ``(reachable, reason, host)``. Fails OPEN (``reachable=True``) whenever
    it can't be sure, so it never blocks a real update; it only short-circuits a
    genuinely dead network with an honest, classified message.
    """
    try:
        if _proxy_configured(root):
            return True, "", ""
        ep = _remote_endpoint(root, remote)
        if ep is None:
            return True, "", ""
        host, port, _scheme = ep
        ok, reason = _probe_tcp(host, port, _connect_timeout_s())
        return ok, reason, host
    except Exception:  # noqa: BLE001 — a probe glitch must never block an update
        return True, "", ""


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
    # `dirty_files` split by whether it actually blocks an update. Machine
    # generated build artifacts (see _REGENERABLE_TRACKED) are reset+regenerated,
    # so only `dirty_blocking` (genuine edits) holds a plain update back.
    dirty_regenerable: list[str] = field(default_factory=list)
    dirty_blocking: list[str] = field(default_factory=list)
    remote_reachable: bool = True
    remote_host: str = ""        # host we probed/fetched from (for honest messages)
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
            "dirty_regenerable": self.dirty_regenerable,
            "dirty_blocking": self.dirty_blocking,
            "remote_reachable": self.remote_reachable,
            "remote_host": self.remote_host,
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
    # Porcelain lines are "XY <path>"; strip the status prefix (see _porcelain_path
    # for why a fixed slice is wrong for the first, leading-space-stripped line).
    c.dirty_files = [_porcelain_path(ln) for ln in files]
    c.dirty_regenerable, c.dirty_blocking = _classify_dirty(c.dirty_files)
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
        # Fail fast on a dead network: a bounded TCP probe (seconds) before the
        # fetch, which can otherwise hang ~21s+ on a blocked host (see the
        # pre-flight helpers above). Fails open, so a reachable remote always
        # proceeds to the real fetch, which still surfaces auth/other errors.
        reachable, reason, host = _preflight_remote(root, c.remote)
        c.remote_host = host
        if not reachable:
            c.remote_reachable = False
            c.error = reason or "remote unreachable"
            return c
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
        proc = subprocess.run(  # nosec B603 # sys.executable + fixed pip argv, no shell
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
        return (False, "npm not on PATH, rebuild later: "
                       "cd heaven-ui && npm ci --legacy-peer-deps && npm run build")
    try:
        # Prefer `npm ci`: it installs strictly from package-lock.json and never
        # rewrites it, so the rebuild leaves the tree clean and the NEXT update is
        # not blocked by a lockfile the build itself changed. Fall back to
        # `npm install` only when there is no lockfile or the lock has drifted out
        # of sync with package.json (npm ci refuses that) so an install still
        # succeeds — Layer-2 dirty handling then covers the resulting phantom dirt.
        used_ci = (ui / "package-lock.json").is_file()
        inst = subprocess.run(  # nosec B603 B607 # fixed npm argv, no shell
            ["npm", "ci", "--legacy-peer-deps"] if used_ci
            else ["npm", "install", "--legacy-peer-deps"],
            cwd=str(ui), capture_output=True, text=True, timeout=900,
        )
        if inst.returncode != 0 and used_ci:
            inst = subprocess.run(  # nosec B603 B607 # fixed npm argv, no shell
                ["npm", "install", "--legacy-peer-deps"],
                cwd=str(ui), capture_output=True, text=True, timeout=900,
            )
        if inst.returncode != 0:
            return False, "npm install failed: " + (inst.stderr or inst.stdout or "")[:200]
        bld = subprocess.run(  # nosec B603 B607 # fixed npm argv, no shell
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

    # Only *genuine* edits block. Machine-generated build artifacts the build
    # itself rewrote (the npm lockfile) are neither the user's work nor a reason
    # to refuse: we reset them to HEAD just below and the post-update rebuild
    # regenerates them. This is what unblocks the "just installed → every update
    # refused" trap without ever discarding real work.
    blocking = list(check.dirty_blocking)
    regen = list(check.dirty_regenerable)
    if blocking and not force:
        res.error = "uncommitted local changes, refusing to overwrite them (use --force to auto-stash)"
        return res

    old_sha = check.current_sha or "HEAD"

    # Reset only the allowlisted regenerable artifacts so the fast-forward is
    # clean. Safe: they are rebuilt from source (package.json) right after.
    for f in regen:
        rc, _, err = _run_git(root, "checkout", "--", f)
        if rc == 0:
            res.notes.append(f"reset auto-generated {f} (the build regenerates it after update)")
        else:
            res.notes.append(f"note: could not reset {f}: {err[:120]}")

    # --force with genuine edits still present: preserve them non-destructively
    # around the pull. (Regenerable artifacts were reset above, so a lockfile no
    # longer lands in the stash to conflict on pop.)
    if blocking and force:
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
        res.notes.append("dependencies changed, reinstalled"
                         if ok else f"pip reinstall failed: {msg}")
    if _needs_ui_rebuild(changed):
        if skip_ui:
            res.notes.append("web UI changed, skipped rebuild (--skip-ui); run: "
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
        proc = subprocess.run(  # nosec B603 B607 # fixed argv on PATH, no shell
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
        host = c.remote_host or "the remote"
        _print(f"  [yellow]Couldn't reach {host}:[/yellow] {c.error}")
        _print("  [dim]Usually a network, firewall, or proxy issue on this machine, not a[/dim]")
        _print("  [dim]HEAVEN fault. Check connectivity (or set HTTPS_PROXY behind a proxy),[/dim]")
        _print("  [dim]then try again.[/dim]")
        return
    if c.available:
        _print(f"  [bold green]Update available:[/bold green] "
               f"v{c.current_version or '?'} → v{c.latest_version or '?'} "
               f"({c.behind} commit(s) behind {c.upstream})")
        if c.dirty_blocking:
            _print(f"  [yellow]Note:[/yellow] {len(c.dirty_blocking)} uncommitted change(s) ·  "
                   "`heaven update` will hold back unless you pass --force.")
        elif c.dirty_regenerable:
            _print(f"  [dim]({len(c.dirty_regenerable)} auto-generated build file(s) will be "
                   "refreshed automatically — no action needed.)[/dim]")
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
        host = c.remote_host or "the remote"
        _print(f"  [yellow]⚠ Code:[/yellow] couldn't reach {host} ({c.error}) · skipping self-update.")
        _print("      [dim]Usually a network/firewall/VPN issue on this machine, not a HEAVEN fault:[/dim]")
        _print("      [dim]· confirm you're online and GitHub isn't blocked here[/dim]")
        _print("      [dim]· behind a proxy? set HTTPS_PROXY=http://host:port and re-run[/dim]")
        _print("      [dim]· private repo? make sure git can authenticate (gh auth login / SSH key)[/dim]")
        _print(f"      [dim]· once connected, update manually: git -C {root} pull --ff-only[/dim]")
        summary.code_note = f"remote unreachable: {c.error}"
        summary.errors.append(f"code: {c.error}")
        return

    summary.from_version = c.current_version
    summary.to_version = c.current_version

    if not c.available:
        _print(f"  [green]✓ Code:[/green] already up to date (v{c.current_version or '?'})")
        summary.code_note = "up to date"
        return
    if c.dirty_blocking and not force:
        _print(f"  [yellow]⚠ Code:[/yellow] v{c.latest_version or '?'} is available, but you have "
               f"{len(c.dirty_blocking)} uncommitted change(s): not overwriting them.")
        for f_ in c.dirty_blocking[:8]:
            _print(f"      [dim]· {f_}[/dim]")
        if len(c.dirty_blocking) > 8:
            _print(f"      [dim]· …and {len(c.dirty_blocking) - 8} more[/dim]")
        _print("      Commit/stash them, or re-run with [bold]--force[/bold] (auto-stash).")
        summary.code_note = "held back: uncommitted local changes"
        summary.errors.append("code: uncommitted local changes (use --force)")
        return

    _print(f"  HEAVEN code: v{c.current_version or '?'} → v{c.latest_version or '?'} "
           f"({c.behind} commit(s)): updating…")
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

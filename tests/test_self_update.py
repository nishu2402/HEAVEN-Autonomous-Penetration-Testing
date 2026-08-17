"""`heaven update` self-updater — code path is git-checkout aware and, above all,
never destroys uncommitted work.

The whole flow is exercised without a network or a real git repo by monkeypatching
the thin `_run_git` seam with a `FakeGit` that records every invocation and mutates
an on-disk `heaven/__init__.py` on a fast-forward merge (mirroring what a real
`git merge --ff-only` does to the working tree). That lets us assert the honest
contract:

  * up-to-date  → nothing changes;
  * behind + clean → fast-forwards and reports the real vX → vY bump;
  * behind + dirty → REFUSED, no mutating git command issued;
  * `--force` → stash → pull → stash-pop, non-destructive;
  * diverged (ff-only fails) → honest error, nothing applied;
  * pip reinstall only when a dependency file changed; UI rebuild only when the
    frontend changed;
  * a `reset --hard` is NEVER issued in any scenario.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from heaven.cli import update as U


# ── fixtures / fakes ─────────────────────────────────────────────────────────

def _mk_repo(tmp_path: Path, version: str = "2.0.0") -> Path:
    """A minimal fake editable checkout: heaven/__init__.py + pyproject + .git."""
    (tmp_path / "heaven").mkdir(parents=True, exist_ok=True)
    (tmp_path / "heaven" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "heaven-pentest"\n')
    (tmp_path / ".git").mkdir(exist_ok=True)
    return tmp_path


class FakeGit:
    """A record-and-replay stand-in for :func:`heaven.cli.update._run_git`."""

    def __init__(self, *, dirty_files=None, behind=0, ahead=0, current="2.0.0",
                 latest="2.1.0", ff_ok=True, fetch_ok=True, changed=None,
                 upstream="origin/main", branch="main"):
        self.calls: list[tuple[str, ...]] = []
        self.dirty_files = list(dirty_files or [])
        self.behind = behind
        self.ahead = ahead
        self.current = current
        self.latest = latest
        self.ff_ok = ff_ok
        self.fetch_ok = fetch_ok
        self.changed = list(changed) if changed is not None else []
        self.upstream = upstream
        self.branch = branch
        self.merged = False

    def __call__(self, root, *args, timeout=60):
        self.calls.append(tuple(args))
        a = list(args)

        if a[:2] == ["rev-parse", "--abbrev-ref"] and a[-1] == "HEAD":
            return 0, self.branch, ""
        if a[:2] == ["rev-parse", "--abbrev-ref"] and "@{u}" in a:
            return (0, self.upstream, "") if self.upstream else (1, "", "no upstream")
        if a[:1] == ["rev-parse"] and a[-1] == "HEAD":
            return 0, ("bbbbbbbbbbbbcccc" if self.merged else "aaaaaaaaaaaadddd"), ""
        if a[:1] == ["rev-parse"]:                      # rev-parse <upstream>
            return 0, "cccccccccccceeee", ""
        if a[:1] == ["status"]:
            return 0, "\n".join(f" M {f}" for f in self.dirty_files), ""
        if a[:1] == ["fetch"]:
            return (0, "", "") if self.fetch_ok else (1, "", "Could not resolve host github.com")
        if a[:1] == ["rev-list"]:
            return 0, f"{self.behind}\t{self.ahead}", ""
        if a[:1] == ["show"]:                           # show upstream:heaven/__init__.py
            return 0, f'__version__ = "{self.latest}"\n', ""
        if a[:1] == ["merge"]:
            if self.ff_ok:
                self.merged = True
                # A real ff-only merge advances the working tree; mirror that so
                # the post-merge version read reflects the new release.
                (Path(root) / "heaven" / "__init__.py").write_text(
                    f'__version__ = "{self.latest}"\n')
                return 0, "", ""
            return 1, "", "fatal: Not possible to fast-forward, aborting."
        if a[:2] == ["stash", "push"]:
            return 0, "Saved working directory", ""
        if a[:2] == ["stash", "pop"]:
            return 0, "Dropped stash", ""
        if a[:1] == ["diff"]:
            return 0, "\n".join(self.changed), ""
        return 0, "", ""

    # convenience assertions
    def issued(self, *prefix) -> bool:
        return any(c[:len(prefix)] == tuple(prefix) for c in self.calls)


@pytest.fixture(autouse=True)
def _no_real_subprocess(monkeypatch):
    """Guarantee no test ever shells out to a real pip/ui build."""
    monkeypatch.setattr(U, "_git_available", lambda: True)
    monkeypatch.setattr(U, "_pip_reinstall", lambda root: (True, "OK (stub)"))
    monkeypatch.setattr(U, "_ui_rebuild", lambda root: (True, "OK (stub)"))


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_parse_version_reads_dunder():
    assert U._parse_version('__version__ = "2.3.4"\nx = 1\n') == "2.3.4"
    assert U._parse_version("no version here") == ""


def test_root_from_pkg_file_requires_git_and_pyproject(tmp_path):
    (tmp_path / "heaven").mkdir()
    (tmp_path / "heaven" / "__init__.py").write_text("")
    pkg_file = str(tmp_path / "heaven" / "__init__.py")
    # No .git, no pyproject → not updatable.
    assert U._root_from_pkg_file(pkg_file) is None
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text("")
    assert U._root_from_pkg_file(pkg_file) == tmp_path.resolve()


def test_needs_pip_reinstall_only_on_dependency_files():
    assert U._needs_pip_reinstall(["pyproject.toml"])
    assert U._needs_pip_reinstall(["requirements-dev.txt"])
    assert U._needs_pip_reinstall(["heaven/x.py", "setup.cfg"])
    assert not U._needs_pip_reinstall(["heaven/foo.py", "README.md"])
    assert not U._needs_pip_reinstall([])


def test_needs_ui_rebuild_only_on_frontend_source():
    assert U._needs_ui_rebuild(["heaven-ui/src/App.jsx"])
    assert U._needs_ui_rebuild(["heaven/x.py", "heaven-ui/package.json"])
    # The built output is gitignored — never a trigger on its own.
    assert not U._needs_ui_rebuild(["heaven-ui/dist/index.html"])
    assert not U._needs_ui_rebuild(["heaven/api/server.py"])


# ── check_for_update ─────────────────────────────────────────────────────────

def test_check_reports_up_to_date(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.1.0")
    monkeypatch.setattr(U, "_run_git", FakeGit(behind=0, current="2.1.0", latest="2.1.0"))
    c = U.check_for_update(root)
    assert c.is_git and c.remote_reachable
    assert c.behind == 0 and c.available is False
    assert c.current_version == "2.1.0"


def test_check_reports_available(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    monkeypatch.setattr(U, "_run_git", FakeGit(behind=3, current="2.0.0", latest="2.2.0"))
    c = U.check_for_update(root)
    assert c.available is True and c.behind == 3
    assert c.current_version == "2.0.0" and c.latest_version == "2.2.0"


def test_check_offline_is_honest_not_a_crash(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    monkeypatch.setattr(U, "_run_git", FakeGit(fetch_ok=False, behind=3))
    c = U.check_for_update(root)
    assert c.remote_reachable is False
    assert c.available is False        # we never claim an update when we couldn't fetch
    assert "resolve host" in c.error.lower() or c.error


def test_check_without_git_binary(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path)
    monkeypatch.setattr(U, "_git_available", lambda: False)
    c = U.check_for_update(root)
    assert c.is_git is False and "git" in c.reason.lower()


# ── apply_code_update ────────────────────────────────────────────────────────

def test_apply_clean_fast_forwards_and_reports_version(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=2, current="2.0.0", latest="2.1.0", changed=["heaven/foo.py"])
    monkeypatch.setattr(U, "_run_git", fake)
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c)
    assert res.applied is True
    assert res.from_version == "2.0.0" and res.to_version == "2.1.0"
    assert res.pip_reinstalled is False and res.ui_rebuilt is False
    assert fake.issued("merge", "--ff-only")
    assert not fake.issued("stash", "push")   # clean tree → no stash needed


def test_apply_refuses_dirty_without_force_and_touches_nothing(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=2, dirty_files=["heaven/orchestrator.py", "README.md"])
    monkeypatch.setattr(U, "_run_git", fake)
    c = U.check_for_update(root)
    assert c.dirty is True
    res = U.apply_code_update(root, c, force=False)
    assert res.applied is False
    assert "uncommitted" in res.error.lower()
    # The load-bearing guarantee: no mutating git command was ever issued.
    assert not fake.issued("merge", "--ff-only")
    assert not fake.issued("stash", "push")


def test_force_stashes_pulls_and_pops_nondestructively(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=1, latest="2.1.0", dirty_files=["heaven/x.py"],
                   changed=["heaven/x.py"])
    monkeypatch.setattr(U, "_run_git", fake)
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c, force=True)
    assert res.applied is True and res.stashed is True and res.stash_restored is True
    # order matters: stash BEFORE merge, pop AFTER.
    seq = [c0[0] for c0 in fake.calls]
    assert seq.index("stash") < seq.index("merge")
    assert fake.issued("stash", "pop")


def test_apply_diverged_ff_only_fails_is_honest(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=2, ff_ok=False, changed=["heaven/x.py"])
    monkeypatch.setattr(U, "_run_git", fake)
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c)
    assert res.applied is False
    assert "fast-forward" in res.error.lower()


def test_apply_reinstalls_only_when_dependencies_changed(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=1, latest="2.1.0", changed=["pyproject.toml", "heaven/x.py"])
    monkeypatch.setattr(U, "_run_git", fake)
    spy = {"n": 0}
    monkeypatch.setattr(U, "_pip_reinstall", lambda r: (spy.__setitem__("n", spy["n"] + 1), (True, "OK"))[1])
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c)
    assert res.applied is True and res.pip_reinstalled is True and spy["n"] == 1


def test_apply_rebuilds_ui_only_when_frontend_changed(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=1, latest="2.1.0", changed=["heaven-ui/src/App.jsx"])
    monkeypatch.setattr(U, "_run_git", fake)
    spy = {"n": 0}
    monkeypatch.setattr(U, "_ui_rebuild", lambda r: (spy.__setitem__("n", spy["n"] + 1), (True, "OK"))[1])
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c)
    assert res.ui_rebuilt is True and spy["n"] == 1
    # …but not when --skip-ui is passed.
    spy["n"] = 0
    fake2 = FakeGit(behind=1, latest="2.1.0", changed=["heaven-ui/src/App.jsx"])
    monkeypatch.setattr(U, "_run_git", fake2)
    c2 = U.check_for_update(_mk_repo(tmp_path, "2.0.0"))
    res2 = U.apply_code_update(root, c2, skip_ui=True)
    assert res2.ui_rebuilt is False and spy["n"] == 0


def test_up_to_date_apply_is_a_noop(tmp_path, monkeypatch):
    root = _mk_repo(tmp_path, "2.1.0")
    fake = FakeGit(behind=0, current="2.1.0", latest="2.1.0")
    monkeypatch.setattr(U, "_run_git", fake)
    c = U.check_for_update(root)
    res = U.apply_code_update(root, c)
    assert res.applied is False
    assert not fake.issued("merge", "--ff-only")


def test_never_issues_a_hard_reset(tmp_path, monkeypatch):
    """Across every scenario the updater must never `git reset --hard`."""
    scenarios = [
        FakeGit(behind=2, changed=["heaven/x.py"]),                       # clean apply
        FakeGit(behind=2, dirty_files=["a.py"]),                          # refused
        FakeGit(behind=1, dirty_files=["a.py"], changed=["heaven/x.py"]),  # forced
        FakeGit(behind=2, ff_ok=False, changed=["heaven/x.py"]),         # diverged
    ]
    forces = [False, False, True, False]
    for fake, force in zip(scenarios, forces):
        monkeypatch.setattr(U, "_run_git", fake)
        c = U.check_for_update(_mk_repo(tmp_path / str(id(fake)), "2.0.0"))
        U.apply_code_update(tmp_path / str(id(fake)), c, force=force)
        assert not any("reset" in " ".join(call) for call in fake.calls), fake.calls


# ── CLI wiring (smoke) ───────────────────────────────────────────────────────

def test_cli_check_is_readonly(tmp_path, monkeypatch):
    """`heaven update --check` must never issue a mutating git command."""
    from click.testing import CliRunner
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=2, current="2.0.0", latest="2.1.0")
    monkeypatch.setattr(U, "find_repo_root", lambda: root)
    monkeypatch.setattr(U, "_run_git", fake)
    res = CliRunner().invoke(U.update_cmd, ["--check"])
    assert res.exit_code == 0, res.output
    assert not fake.issued("merge", "--ff-only")
    assert not fake.issued("stash", "push")


def test_cli_code_only_applies_without_touching_data(tmp_path, monkeypatch):
    from click.testing import CliRunner
    root = _mk_repo(tmp_path, "2.0.0")
    fake = FakeGit(behind=1, current="2.0.0", latest="2.1.0", changed=["heaven/x.py"])
    monkeypatch.setattr(U, "find_repo_root", lambda: root)
    monkeypatch.setattr(U, "_run_git", fake)
    # If the data path were reached it would try real network calls; assert it
    # isn't by making them explode.
    monkeypatch.setattr(U, "_refresh_detection_data",
                        lambda *a, **k: pytest.fail("data refresh ran under --code-only"))
    res = CliRunner().invoke(U.update_cmd, ["--code-only"])
    assert res.exit_code == 0, res.output
    assert fake.issued("merge", "--ff-only")

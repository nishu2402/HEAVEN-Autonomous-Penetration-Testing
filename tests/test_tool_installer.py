"""Tests for the external-tool catalog + installer and the `heaven install-tools`
command.

These NEVER trigger a real package install: the executing paths are either
``dry_run=True`` (plans a command without running it) or exercise the
already-present / unknown-tool branches. The one non-dry-run install test forces
``is_present`` True so ``install_tools`` short-circuits before any subprocess.
"""

from __future__ import annotations

import os
import sys
import time

import pytest

from heaven.utils import tool_installer as ti


# ── Catalog integrity ─────────────────────────────────────────────────────────
def test_catalog_covers_the_documented_tools():
    names = ti.tool_names()
    for expected in ("nmap", "nuclei", "sqlmap", "ffuf", "searchsploit", "semgrep", "docker"):
        assert expected in names
    # Every spec is usable in the UI/CLI: it has a purpose and at least one recipe.
    for spec in ti.TOOLS:
        assert spec.purpose
        assert spec.url or spec.brew or spec.apt or spec.pip or spec.go


def test_install_hint_is_always_actionable():
    for spec in ti.TOOLS:
        hint = ti.install_hint(spec)
        assert hint and hint != "see project docs"


def test_darwin_docker_hint_is_not_apt(monkeypatch):
    """On macOS with NO package manager, the docker hint stays platform-correct —
    never suggests apt, and always includes the official docs URL."""
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    # No package manager detected → fall through to the platform-aware fallback.
    monkeypatch.setattr(ti.shutil, "which", lambda _cmd: None)
    hint = ti.install_hint(ti.get_spec("docker"))
    assert "apt" not in hint
    assert "docker.com" in hint


def test_docker_auto_installs_via_brew_on_macos(monkeypatch):
    """Regression: docker must be auto-installable on macOS (it previously had no
    brew formula in the catalog, so `heaven install-tools` marked it 'manual')."""
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "brew")
    cmd = ti.build_install_command(ti.get_spec("docker"))
    assert cmd == ["brew", "install", "docker"]


def test_every_tool_auto_installs_on_a_brew_host(monkeypatch):
    """With Homebrew present, every catalog tool resolves to a real install
    command — no tool is left 'manual' on a standard macOS/Linuxbrew box."""
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "brew")
    for spec in ti.TOOLS:
        cmd = ti.build_install_command(spec)
        assert cmd is not None, f"{spec.name} has no auto-install command on a brew host"


# ── Command construction ──────────────────────────────────────────────────────
def test_build_command_prefers_brew_on_macos(monkeypatch):
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "brew")
    cmd = ti.build_install_command(ti.get_spec("sqlmap"))
    assert cmd == ["brew", "install", "sqlmap"]


def test_build_command_uses_sudo_apt_on_debian(monkeypatch):
    monkeypatch.setattr(ti.sys, "platform", "linux")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "apt-get")
    cmd = ti.build_install_command(ti.get_spec("sqlmap"))
    assert cmd == ["sudo", "apt-get", "install", "-y", "sqlmap"]


def test_build_command_pip_fallback_when_no_manager(monkeypatch):
    monkeypatch.setattr(ti, "_pkg_manager", lambda: None)
    cmd = ti.build_install_command(ti.get_spec("semgrep"))
    assert cmd[:3] == [sys.executable, "-m", "pip"]
    assert cmd[-1] == "semgrep"


def test_build_command_none_when_manual_only(monkeypatch):
    """A spec with only a docs URL (no manager recipe, no pip/go) → no
    auto-command, so it is correctly reported 'manual' rather than silently
    skipped."""
    manual_only = ti.ToolSpec(name="somewidget", purpose="example",
                              url="https://example.com/install")
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "brew")
    # No pip/go recipe and no matching brew formula → None (manual).
    monkeypatch.setattr(ti.shutil, "which", lambda _cmd: None)
    assert ti.build_install_command(manual_only) is None


# ── install_tools ─────────────────────────────────────────────────────────────
def test_dry_run_plans_without_executing(monkeypatch):
    # Force sqlmap "missing" so a command is planned; everything else present.
    monkeypatch.setattr(ti, "is_present", lambda name: name != "sqlmap")
    results = ti.install_tools([ti.get_spec("sqlmap")], dry_run=True)
    assert len(results) == 1
    r = results[0]
    assert r.status == "planned" and r.ok
    assert r.command and r.command[-1] == "sqlmap"


def test_present_tool_is_skipped_no_subprocess(monkeypatch):
    monkeypatch.setattr(ti, "is_present", lambda _name: True)
    # If this tried to run a subprocess it would fail in CI; it must not.
    results = ti.install_tools([ti.get_spec("nmap")])
    assert [r.status for r in results] == ["present"]


def test_manual_status_when_no_command(monkeypatch):
    monkeypatch.setattr(ti, "is_present", lambda _name: False)
    monkeypatch.setattr(ti, "build_install_command", lambda _spec: None)
    results = ti.install_tools([ti.get_spec("docker")])
    assert results[0].status == "manual"
    assert results[0].detail  # carries the manual-install URL/hint


def test_missing_tools_reflects_path(monkeypatch):
    monkeypatch.setattr(ti, "is_present", lambda name: name != "ffuf")
    missing = [s.name for s in ti.missing_tools()]
    assert missing == ["ffuf"]


# ── CLI ───────────────────────────────────────────────────────────────────────
def test_cli_registered_and_help():
    from click.testing import CliRunner

    from heaven.main import cli

    r = CliRunner().invoke(cli, ["install-tools", "--help"])
    assert r.exit_code == 0, r.output
    assert "install" in r.output.lower()
    assert "--dry-run" in r.output and "--yes" in r.output


def test_cli_unknown_tool_errors_without_installing():
    from click.testing import CliRunner

    from heaven.main import cli

    r = CliRunner().invoke(cli, ["install-tools", "definitely-not-a-tool"])
    assert r.exit_code == 2
    assert "Unknown tool" in r.output


def test_cli_dry_run_is_safe_and_reports_ok():
    """`--json install-tools --dry-run` never installs and always returns ok.

    Works whether the host has every tool (returns the all-present payload) or
    some missing (returns dry-run plans) — either way, ok is True and nothing is
    installed.
    """
    import json

    from click.testing import CliRunner

    from heaven.main import cli

    r = CliRunner().invoke(cli, ["--json", "install-tools", "--dry-run"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload["ok"] is True
    # No result may be "installed" — dry-run only plans or reports present.
    for res in payload.get("results", []):
        assert res["status"] in ("planned", "present")


# ── Windows package managers ──────────────────────────────────────────────────
def test_build_command_uses_winget_on_windows(monkeypatch):
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "winget")
    cmd = ti.build_install_command(ti.get_spec("nmap"))
    assert cmd[:4] == ["winget", "install", "-e", "--id"]
    assert "Insecure.Nmap" in cmd
    # winget must run fully non-interactively or it can block on an agreement.
    assert "--disable-interactivity" in cmd
    assert "--accept-package-agreements" in cmd


def test_build_command_uses_scoop_on_windows(monkeypatch):
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "scoop")
    assert ti.build_install_command(ti.get_spec("ffuf")) == ["scoop", "install", "ffuf"]


def test_build_command_uses_choco_on_windows(monkeypatch):
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "choco")
    assert ti.build_install_command(ti.get_spec("docker")) == \
        ["choco", "install", "-y", "docker-desktop"]


def test_windows_pip_fallback_for_sqlmap(monkeypatch):
    """sqlmap has no Windows-manager recipe → pip, which works everywhere."""
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "winget")
    cmd = ti.build_install_command(ti.get_spec("sqlmap"))
    assert cmd[:3] == [sys.executable, "-m", "pip"]
    assert cmd[-1] == "sqlmap"


def test_windows_hint_uses_winget_not_apt(monkeypatch):
    monkeypatch.setattr(ti.sys, "platform", "win32")
    # Keep shutil off its Windows codepath while sys.platform is forced to win32.
    monkeypatch.setattr(ti.shutil, "which", lambda _cmd: None)
    hint = ti.install_hint(ti.get_spec("nmap"))
    assert "winget" in hint
    assert "apt" not in hint


# ── Hang guards — the "stuck install" fix ─────────────────────────────────────
def test_noninteractive_sudo_adds_dash_n(monkeypatch):
    """Without a TTY, sudo must fail fast (-n) instead of blocking on a password."""
    monkeypatch.setattr(ti.sys.stdin, "isatty", lambda: False)
    assert ti._noninteractive_sudo(["sudo", "apt-get", "install", "-y", "nmap"]) == \
        ["sudo", "-n", "apt-get", "install", "-y", "nmap"]


def test_interactive_sudo_is_left_alone(monkeypatch):
    """With a real TTY, sudo keeps its normal prompt so the operator can auth."""
    monkeypatch.setattr(ti.sys.stdin, "isatty", lambda: True)
    cmd = ["sudo", "apt-get", "install", "-y", "nmap"]
    assert ti._noninteractive_sudo(cmd) == cmd


def test_non_sudo_command_is_untouched():
    assert ti._noninteractive_sudo(["brew", "install", "nmap"]) == ["brew", "install", "nmap"]


def test_install_timeout_env_override(monkeypatch):
    monkeypatch.setenv("HEAVEN_TOOL_INSTALL_TIMEOUT", "42")
    assert ti._install_timeout() == 42
    monkeypatch.setenv("HEAVEN_TOOL_INSTALL_TIMEOUT", "not-a-number")
    assert ti._install_timeout() == 900   # bad value → safe default
    monkeypatch.setenv("HEAVEN_TOOL_INSTALL_TIMEOUT", "0")
    assert ti._install_timeout() == 900   # non-positive → safe default


def test_install_env_is_noninteractive():
    env = ti._install_env()
    assert env["DEBIAN_FRONTEND"] == "noninteractive"   # apt never prompts
    assert env["HOMEBREW_NO_AUTO_UPDATE"] == "1"         # no slow brew self-update


@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX `sh`/`sleep` shell")
def test_run_install_times_out_instead_of_hanging(monkeypatch):
    """The core guard against a 'stuck install': a command that would block
    forever is killed at the timeout. 1s cap + a 30s sleep → the watchdog must
    fire, keeping the test fast and deterministic."""
    monkeypatch.setenv("HEAVEN_TOOL_INSTALL_TIMEOUT", "1")
    monkeypatch.setattr(ti, "is_present", lambda _n: False)
    start = time.time()
    result = ti._run_install(ti.get_spec("nmap"), ["sh", "-c", "sleep 30"], None)
    elapsed = time.time() - start
    assert result.status == "failed"
    assert "timed out" in result.detail
    assert elapsed < 15   # must not wait the full 30s

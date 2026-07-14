"""Tests for the external-tool catalog + installer and the `heaven install-tools`
command.

These NEVER trigger a real package install: the executing paths are either
``dry_run=True`` (plans a command without running it) or exercise the
already-present / unknown-tool branches. The one non-dry-run install test forces
``is_present`` True so ``install_tools`` short-circuits before any subprocess.
"""

from __future__ import annotations

import sys

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
    """On macOS, docker has no brew formula for the daemon → hint is the URL, not apt."""
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    # No package manager detected → fall through to the platform-aware fallback.
    monkeypatch.setattr(ti.shutil, "which", lambda _cmd: None)
    hint = ti.install_hint(ti.get_spec("docker"))
    assert "apt" not in hint
    assert "docker.com" in hint


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
    """docker has no pip/go recipe → no auto-command when no OS manager applies."""
    monkeypatch.setattr(ti.sys, "platform", "darwin")
    monkeypatch.setattr(ti, "_pkg_manager", lambda: "brew")  # no brew formula for docker
    assert ti.build_install_command(ti.get_spec("docker")) is None


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

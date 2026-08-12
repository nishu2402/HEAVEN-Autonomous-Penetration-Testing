"""`heaven completion` — shell tab-completion end to end.

Two things are proven here:

* the **option-completion fix** — rich-click's ``patch()`` introduces a second
  ``click.core.Option`` class, so Click's own completion loop
  (``isinstance(param, Option)``) used to match zero options and option/flag
  names silently never completed. ``apply_rich_click`` now skips patching while
  completion is running, restoring native completion. The subprocess tests
  exercise the *real* completion path (``_HEAVEN_COMPLETE=...``);
* the **one-command installer** (``heaven completion --install``) — the rc-block
  upsert is idempotent, backed up, and cleanly removable, so a user goes from
  "Tab does nothing" to working completion without hand-editing dotfiles.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from heaven.cli import completion as C
from heaven.cli._richconfig import _shell_completion_active, apply_rich_click


# ── the rich-click completion guard (root cause of "options don't complete") ──

def test_shell_completion_active_detects_complete_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("_") and k.endswith("_COMPLETE"):
            monkeypatch.delenv(k, raising=False)
    assert _shell_completion_active() is False
    monkeypatch.setenv("_HEAVEN_COMPLETE", "zsh_complete")
    assert _shell_completion_active() is True


def test_apply_rich_click_skipped_during_completion(monkeypatch):
    # With completion active, patching is skipped so Click keeps its native
    # class identity — the precise condition that makes option completion work.
    monkeypatch.setenv("_HEAVEN_COMPLETE", "zsh_complete")
    assert apply_rich_click() is False


# ── end-to-end completion through the real Click machinery (subprocess) ──

def _complete(words: str, cword: int) -> list[str]:
    env = dict(os.environ)
    env["_HEAVEN_COMPLETE"] = "zsh_complete"
    env["COMP_WORDS"] = words
    env["COMP_CWORD"] = str(cword)
    proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
        [sys.executable, "-m", "heaven.main"],
        env=env, capture_output=True, text=True, timeout=90,
    )
    return proc.stdout.splitlines()


def test_completion_completes_subcommands():
    assert "scan" in _complete("heaven sc", 1)


def test_completion_completes_options():
    # The bug this session fixed: options never completed under rich-click.
    lines = _complete("heaven scan --e", 2)
    assert "--evade" in lines
    assert "--engagement" in lines


def test_completion_completes_choice_values():
    # `--stealth <TAB>` should offer the Choice() values.
    assert "paranoid" in _complete("heaven scan --stealth ", 3)


# ── installer: rc-block upsert / remove (idempotent, safe, reversible) ──

def test_rc_block_zsh_guards_compinit():
    blk = C._rc_block("zsh")
    assert C._MARK_START in blk and C._MARK_END in blk
    # The compinit/compdef guard is what avoids the fpath-ordering trap.
    assert "compinit" in blk and "compdef" in blk


def test_upsert_block_is_idempotent(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("# existing\nalias x=1\n", encoding="utf-8")
    blk = C._rc_block("zsh")
    assert C._upsert_block(rc, blk, dry_run=False) == "added"
    assert C._upsert_block(rc, blk, dry_run=False) == "unchanged"
    text = rc.read_text(encoding="utf-8")
    assert text.count(C._MARK_START) == 1      # never duplicated
    assert "alias x=1" in text                 # user's own lines preserved
    assert (tmp_path / ".zshrc.heaven.bak").exists()   # backed up before write


def test_remove_block_restores_original(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("# existing\nalias x=1\n", encoding="utf-8")
    C._upsert_block(rc, C._rc_block("zsh"), dry_run=False)
    assert C._remove_block(rc, dry_run=False) is True
    text = rc.read_text(encoding="utf-8")
    assert C._MARK_START not in text
    assert "alias x=1" in text
    # A second removal is a no-op (nothing left to strip).
    assert C._remove_block(rc, dry_run=False) is False


def test_dry_run_writes_nothing(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("orig\n", encoding="utf-8")
    assert C._upsert_block(rc, C._rc_block("zsh"), dry_run=True) == "added"
    assert rc.read_text(encoding="utf-8") == "orig\n"


def test_do_install_writes_script_and_wires_rc(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".zshrc").write_text("# rc\n", encoding="utf-8")
    C._do_install("zsh", dry_run=False)
    assert (tmp_path / ".config" / "heaven" / "completion.zsh").exists()
    assert C._MARK_START in (tmp_path / ".zshrc").read_text(encoding="utf-8")


def test_do_install_fish_needs_no_rc(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    C._do_install("fish", dry_run=False)
    # fish auto-loads this directory — no rc edit required.
    assert (tmp_path / ".config" / "fish" / "completions" / "heaven.fish").exists()


# ── PowerShell (Windows): hand-rolled completer + $PROFILE wiring ─────────────

def test_powershell_is_a_supported_install_shell():
    assert "powershell" in C._ALL_SHELLS


def test_powershell_script_is_native_argument_completer():
    # No Click backend for PowerShell — we emit our own completer that reuses
    # Click's zsh_complete protocol at runtime. Generated without a subprocess.
    script = C._generate_script("powershell")
    assert "Register-ArgumentCompleter" in script
    assert "-CommandName heaven" in script
    assert "zsh_complete" in script          # the reused resolution protocol


def test_rc_block_powershell_dotsources_the_script():
    blk = C._rc_block("powershell")
    assert C._MARK_START in blk and C._MARK_END in blk
    assert "Test-Path" in blk and ". \"" in blk      # guarded dot-source
    assert "completion.ps1" in blk


def test_detect_shell_prefers_powershell_on_windows(monkeypatch):
    monkeypatch.delenv("SHELL", raising=False)
    monkeypatch.setattr(C.os, "name", "nt")
    assert C._detect_shell() == "powershell"


def test_do_install_powershell_writes_script_and_wires_profile(tmp_path, monkeypatch):
    # Point $PROFILE at a temp file so the test never depends on a real
    # PowerShell being installed (the only place we'd shell out to pwsh).
    monkeypatch.setenv("HOME", str(tmp_path))
    profile = tmp_path / "Documents" / "PowerShell" / "profile.ps1"
    monkeypatch.setattr(C, "_ps_profile_path", lambda: str(profile))
    C._do_install("powershell", dry_run=False)
    assert (tmp_path / ".config" / "heaven" / "completion.ps1").exists()
    assert C._MARK_START in profile.read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
def test_powershell_completion_live_end_to_end(tmp_path):
    """Install into a throwaway $HOME, then drive pwsh's real completion engine.

    Proves the shipped completer, loaded exactly as a user's profile loads it,
    returns candidates. Skipped where pwsh (or the `heaven` binary) is absent.
    """
    heaven_dir = os.path.dirname(sys.executable)
    heaven_bin = os.path.join(
        heaven_dir, "heaven.exe" if os.name == "nt" else "heaven")
    if not os.path.exists(heaven_bin):
        pytest.skip("heaven console-script not present next to the interpreter")

    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["USERPROFILE"] = str(tmp_path)          # Windows home
    env["PATH"] = heaven_dir + os.pathsep + env.get("PATH", "")

    # Wire completion into this throwaway HOME's PowerShell profile.
    subprocess.run(  # nosec B603 -- fixed argv, no shell
        [sys.executable, "-m", "heaven.main", "--quiet",
         "completion", "--install", "powershell"],
        env=env, capture_output=True, text=True, timeout=60, check=True,
    )
    # Auto-load the profile (no -NoProfile) and query the completion engine.
    ps = (
        "$l = 'heaven sc';"
        "(TabExpansion2 -inputScript $l -cursorColumn $l.Length)"
        ".CompletionMatches | ForEach-Object { $_.CompletionText }"
    )
    proc = subprocess.run(  # nosec B603 -- resolved via which(), fixed argv
        [shutil.which("pwsh"), "-Command", ps],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert "scan" in proc.stdout, proc.stderr

"""Regression tests for CLI ↔ web engagement-store unification.

Before the fix, `heaven demo` / the web UI wrote engagement DBs under
``<data_dir>/engagements/`` while the CLI (`findings`, `use`, …) read from a
bare ``./engagements/`` and a separate active-engagement pointer — so
``heaven demo`` then ``heaven findings`` showed nothing. These tests lock in the
dual-directory resolution + web-pointer fallback + pointer sync.
"""
from __future__ import annotations

import pytest

from heaven.cli import _helpers


def test_resolve_prefers_canonical_over_legacy(tmp_path, monkeypatch):
    canonical = tmp_path / "data" / "engagements"
    legacy = tmp_path / "engagements"
    canonical.mkdir(parents=True)
    legacy.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical, legacy])

    # Only the legacy dir has it → resolve to the legacy file (backward compat).
    (legacy / "acme.db").write_text("x")
    assert _helpers._resolve_engagement_name("acme") == legacy / "acme.db"

    # Once it also exists in the canonical dir, that wins.
    (canonical / "acme.db").write_text("y")
    assert _helpers._resolve_engagement_name("acme") == canonical / "acme.db"

    # A brand-new engagement lands in the canonical dir (web-visible).
    assert _helpers._resolve_engagement_name("fresh") == canonical / "fresh.db"


def test_engagement_path_falls_back_to_web_active_pointer(tmp_path, monkeypatch):
    """With no --engagement, env, or `heaven use` context, resolution honours the
    pointer the web UI / `heaven demo` set — the core demo→findings fix."""
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    (canonical / "demo.db").write_text("x")

    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    monkeypatch.setattr(_helpers, "get_current_engagement", lambda: None)
    monkeypatch.setattr(_helpers, "_engagement_dirs",
                        lambda: [canonical, tmp_path / "engagements"])
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "get_active_engagement", lambda: "demo")

    assert _helpers._engagement_db_path() == canonical / "demo.db"


def test_explicit_name_beats_active_pointer(tmp_path, monkeypatch):
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs",
                        lambda: [canonical, tmp_path / "engagements"])
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "get_active_engagement", lambda: "demo")

    # Explicit name must win over the web pointer.
    assert _helpers._engagement_db_path("acme") == canonical / "acme.db"


def test_resolve_name_falls_back_to_web_pointer(tmp_path, monkeypatch):
    """`resolve_engagement_name` (used by `heaven doctor`/`status`) must honour the
    web/demo active pointer too, so name-based readers agree with the DB-path
    resolver — after `heaven demo`, `heaven doctor` should report the demo
    engagement instead of "no active engagement"."""
    monkeypatch.chdir(tmp_path)  # no ./.heaven/current_engagement context
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "get_active_engagement", lambda: "demo")

    assert _helpers.resolve_engagement_name() == "demo"
    # An explicit name still wins over the pointer.
    assert _helpers.resolve_engagement_name("acme") == "acme"


def test_set_current_engagement_syncs_web_pointer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen: dict[str, str] = {}
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "set_active_engagement",
                        lambda name: seen.__setitem__("name", name))

    _helpers.set_current_engagement("acme")

    # CLI `heaven use` also updates the web UI's active-engagement pointer.
    assert seen.get("name") == "acme"
    assert (tmp_path / ".heaven" / "current_engagement").read_text().strip() == "acme"


def test_open_read_rejects_unknown_name_without_creating_db(tmp_path, monkeypatch, capsys):
    """A read command given a typo'd --engagement must fail loudly (exit 2) and
    never leave an empty <name>.db behind. Before the fix, the read opened a
    create=True store, which materialised a stray DB and then silently returned
    "no findings", hiding the typo and polluting data/engagements/."""
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    with pytest.raises(SystemExit) as excinfo:
        _helpers._open_engagement_read("typo-name")

    assert excinfo.value.code == 2
    assert not (canonical / "typo-name.db").exists()  # no stray DB
    # The guidance goes to stderr so stdout stays clean for piping.
    assert "No engagement named 'typo-name'" in capsys.readouterr().err


def test_open_read_opens_existing_engagement(tmp_path, monkeypatch):
    """A real engagement opens read-only without error."""
    from heaven.engagement import EngagementStore
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    EngagementStore(canonical / "real.db")  # create=True materialises the DB

    store = _helpers._open_engagement_read("real")
    assert store.db_path == canonical / "real.db"


def test_open_read_default_is_unguarded_and_leaves_no_file(tmp_path, monkeypatch):
    """With no name / env / pointer, the bare default engagement is allowed to be
    absent (a fresh install reads empty) and still no file is created on disk."""
    monkeypatch.chdir(tmp_path)  # ./engagement.db resolves under tmp_path
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    monkeypatch.setattr(_helpers, "get_current_engagement", lambda: None)
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "get_active_engagement", lambda: None)

    store = _helpers._open_engagement_read(None)  # must not raise
    assert not store.db_path.exists()  # create=False → nothing materialised


@pytest.mark.parametrize("bad", [
    "../../../escaped",
    "../sibling",
    "sub/dir",
    "back\\slash",
    "/tmp/absolute",
    "has\x00nul",
    "..",
    ".",
    "",
    "   ",
])
def test_resolve_rejects_unsafe_names_without_escaping_dir(tmp_path, monkeypatch, bad):
    """A bare engagement name becomes ``engagements/<name>.db``, so a traversal,
    separator, NUL or absolute path must be rejected (exit 2) before it can place
    a DB outside the data dir. This is the single choke point every auto-create
    command (`engage init`, `scan --engagement`, dns/sca/ssh/vpn/...) flows
    through, so one guard closes the hole for all of them."""
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])

    with pytest.raises(SystemExit) as excinfo:
        _helpers._resolve_engagement_name(bad)
    assert excinfo.value.code == 2
    # Nothing was written anywhere under the sandbox parent.
    assert list(tmp_path.rglob("*.db")) == []


@pytest.mark.parametrize("ok", [
    "acme", "client-v1.2_prod", "2026-q4-retest", "a.b.c", "UPPER_case-9",
])
def test_resolve_accepts_safe_names(tmp_path, monkeypatch, ok):
    """Ordinary names (dashes, underscores, single dots, digits) still resolve."""
    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])

    assert _helpers._resolve_engagement_name(ok) == canonical / f"{ok}.db"


def test_engage_init_rejects_traversal_end_to_end(tmp_path, monkeypatch):
    """`heaven engage init ../../x` exits 2 and creates no DB anywhere: the
    command-layer proof that the resolver guard reaches the real entry point."""
    from click.testing import CliRunner
    from heaven.cli import engage as engage_cli

    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    result = CliRunner().invoke(engage_cli.engage_init, ["../../../escaped"])
    assert result.exit_code == 2
    assert list(tmp_path.rglob("*.db")) == []


def test_engage_rename_rejects_traversal_target(tmp_path, monkeypatch):
    """`engage rename good ../../evil` is refused (exit 2) and leaves the original
    DB untouched. Covers the rename target, which the resolver does not see
    (rename builds the new path itself)."""
    from click.testing import CliRunner
    from heaven.cli import engage as engage_cli
    from heaven.engagement import EngagementStore

    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    monkeypatch.setattr(engage_cli, "get_current_engagement", lambda: None)
    import heaven.engagement as eng
    monkeypatch.setattr(eng, "get_active_engagement", lambda: None)
    EngagementStore(canonical / "good.db")  # materialise the source

    result = CliRunner().invoke(engage_cli.engage_rename, ["good", "../../evil"])
    assert result.exit_code == 2
    assert (canonical / "good.db").exists()  # untouched
    assert list(tmp_path.rglob("evil*.db")) == []


def test_status_cmd_typo_engagement_errors_without_stray_db(tmp_path, monkeypatch):
    """`heaven status --engagement <typo>` must error (exit 2) and leave no stray
    DB, like `findings`/`coverage`/`diff`. Before the fix it opened a create=True
    store, materialising a junk <typo>.db and then reporting "No scans found",
    which hid the typo and polluted data/engagements/."""
    from click.testing import CliRunner
    from heaven.cli import scan as scan_cli

    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(_helpers, "_engagement_dirs", lambda: [canonical])
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    result = CliRunner().invoke(scan_cli.status_cmd, ["--engagement", "no-such-eng"])
    assert result.exit_code == 2
    assert list(tmp_path.rglob("*.db")) == []


def test_status_cmd_json_emits_valid_json(tmp_path, monkeypatch):
    """`heaven --json status` emits a parseable JSON object (engagement + scans)
    to stdout, so a CI consumer can pipe it to jq. The human table goes to the
    log channel; the JSON channel must stay clean. Resolution is pinned via
    HEAVEN_ENGAGEMENT (an absolute DB path) so the assertion does not depend on
    ambient engagement dirs."""
    import json as _json
    from click.testing import CliRunner
    from heaven.cli import scan as scan_cli
    from heaven.engagement import EngagementStore

    db = tmp_path / "real.db"
    EngagementStore(db)  # real engagement, zero scans
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))
    # Force JSON mode on the command's own reference (robust even if another test
    # in the suite reloaded heaven.cli._helpers, which would otherwise leave the
    # global flag on a different module object than status_cmd reads).
    monkeypatch.setattr(scan_cli, "json_output", lambda: True)

    result = CliRunner().invoke(scan_cli.status_cmd, [])
    assert result.exit_code == 0
    payload = _json.loads(result.output)  # must parse, nothing but JSON on stdout
    assert payload["engagement"] == "real"
    assert payload["scans"] == []


def test_resume_typo_engagement_errors_without_stray_db(tmp_path, monkeypatch):
    """`heaven resume --engagement <typo>` has nothing to resume, so it must error
    (exit 2) before materialising a stray <typo>.db (same stray-DB class as
    `status`/`findings`). The guard fires right after the authorization check."""
    from click.testing import CliRunner
    from heaven.cli import scan as scan_cli

    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(scan_cli, "_engagement_db_path",
                        lambda name=None: canonical / f"{name}.db")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    result = CliRunner().invoke(
        scan_cli.resume, ["--engagement", "no-such-eng", "--i-have-authorization"])
    assert result.exit_code == 2
    assert not (canonical / "no-such-eng.db").exists()


def test_replay_typo_engagement_errors_without_stray_db(tmp_path, monkeypatch):
    """`heaven replay <id> --engagement <typo>` has no scan to replay, so it must
    error (exit 2) before materialising a stray <typo>.db."""
    from click.testing import CliRunner
    from heaven.cli import replay as replay_mod

    canonical = tmp_path / "data" / "engagements"
    canonical.mkdir(parents=True)
    monkeypatch.setattr(replay_mod, "_engagement_db_path",
                        lambda name=None: canonical / f"{name}.db")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    result = CliRunner().invoke(
        replay_mod.replay, ["some-scan-id", "--engagement", "no-such-eng",
                            "--i-have-authorization"])
    assert result.exit_code == 2
    assert not (canonical / "no-such-eng.db").exists()

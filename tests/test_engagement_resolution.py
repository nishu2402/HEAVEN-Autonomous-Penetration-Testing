"""Regression tests for CLI ↔ web engagement-store unification.

Before the fix, `heaven demo` / the web UI wrote engagement DBs under
``<data_dir>/engagements/`` while the CLI (`findings`, `use`, …) read from a
bare ``./engagements/`` and a separate active-engagement pointer — so
``heaven demo`` then ``heaven findings`` showed nothing. These tests lock in the
dual-directory resolution + web-pointer fallback + pointer sync.
"""
from __future__ import annotations

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

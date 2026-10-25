"""Phase 0 — bug-bounty operating profile + program-scope importer.

Covers the orthogonal profile overlay (heaven.profiles), the out-of-scope
exclusion support added to feedback.ScopeGuard, and the program-scope importer
(engagement.import_program_scope). Each check asserts the intended behaviour AND
that benign / pentest inputs are left exactly as they were (no silent widening).
"""

from __future__ import annotations

import json
from pathlib import Path

from heaven.config import HeavenConfig, Profile
from heaven.engagement import EngagementStore
from heaven.feedback import ScopeGuard
from heaven.profiles import (
    apply_profile,
    scope_entries_to_targets,
    settings_for,
)


# ─────────────────────────────────────────────────────────────────────────────
# Profile overlay
# ─────────────────────────────────────────────────────────────────────────────

def test_bugbounty_profile_tunes_knobs():
    cfg = HeavenConfig()
    before_rpm = cfg.security.rate_limit_rpm
    settings = apply_profile(cfg, Profile.BUGBOUNTY)
    # Polite throttle, routable OOB, breadth recon, submission report.
    assert cfg.security.rate_limit_rpm < before_rpm
    assert settings.oob_routable is True
    assert settings.recon_breadth is True
    assert settings.strict_scope is True
    assert settings.default_export_format == "bugbounty"
    assert cfg.profile is Profile.BUGBOUNTY


def test_pentest_profile_is_a_noop():
    cfg = HeavenConfig()
    before_rpm = cfg.security.rate_limit_rpm
    settings = apply_profile(cfg, Profile.PENTEST)
    # Nothing the operator did not ask for is changed.
    assert cfg.security.rate_limit_rpm == before_rpm
    assert settings.oob_routable is False
    assert settings.recon_breadth is False
    assert settings.default_export_format == "markdown"
    assert cfg.profile is Profile.PENTEST


def test_settings_for_unknown_falls_back_to_pentest():
    assert settings_for(Profile.PENTEST) == settings_for(Profile.PENTEST)


# ─────────────────────────────────────────────────────────────────────────────
# ScopeGuard out-of-scope exclusions
# ─────────────────────────────────────────────────────────────────────────────

def test_scopeguard_excludes_exact_and_subtree():
    sg = ScopeGuard({
        "domains": ["example.com"],
        "exclude": ["blog.example.com", "*.sandbox.example.com"],
    })
    # In-scope wildcard is honoured.
    assert sg.allows("www.example.com") is True
    assert sg.allows_subdomains("example.com") is True
    # An excluded exact host is denied even though the wildcard would allow it.
    assert sg.allows("blog.example.com") is False
    # An excluded subtree is denied for any child, and subdomain enumeration of
    # the excluded zone is refused.
    assert sg.allows("api.sandbox.example.com") is False
    assert sg.allows_subdomains("sandbox.example.com") is False


def test_scopeguard_without_exclude_is_unchanged():
    # Backward compatibility: no exclude bucket means identical old behaviour.
    sg = ScopeGuard({"domains": ["example.com"]})
    assert sg.allows("www.example.com") is True
    assert sg.allows("blog.example.com") is True
    assert sg.allows("other.org") is False


# ─────────────────────────────────────────────────────────────────────────────
# scope_entries_to_targets
# ─────────────────────────────────────────────────────────────────────────────

def _store(tmp_path: Path, name: str = "prog") -> EngagementStore:
    store = EngagementStore(tmp_path / f"{name}.db")
    store.create_engagement(name=name)
    return store


def test_scope_entries_to_targets_buckets(tmp_path):
    store = _store(tmp_path)
    store.add_scope("*.example.com", kind="domain", in_scope=True)
    store.add_scope("https://api.example.com", kind="url", in_scope=True)
    store.add_scope("10.0.0.0/24", kind="cidr", in_scope=True)
    store.add_scope("bare.example.com", kind="host", in_scope=True)
    store.add_scope("blog.example.com", kind="host", in_scope=False)

    tgt = scope_entries_to_targets(store.list_scope(in_scope_only=False))
    # Wildcard seeds both a domain (ScopeGuard) and an https URL (recon).
    assert "example.com" in tgt["domains"]
    assert "https://example.com" in tgt["urls"]
    assert "https://api.example.com" in tgt["urls"]
    assert "https://bare.example.com" in tgt["urls"]
    assert "10.0.0.0/24" in tgt["ips"]
    # Out-of-scope entry becomes an exclusion, never a target.
    assert "blog.example.com" in tgt["exclude"]
    assert "blog.example.com" not in tgt["urls"]


def test_seeded_targets_pass_scopeguard_including_exclusions(tmp_path):
    store = _store(tmp_path)
    store.add_scope("*.example.com", kind="domain", in_scope=True)
    store.add_scope("secret.example.com", kind="host", in_scope=False)
    tgt = scope_entries_to_targets(store.list_scope(in_scope_only=False))
    sg = ScopeGuard(tgt)
    assert sg.allows("app.example.com") is True
    assert sg.allows("secret.example.com") is False


# ─────────────────────────────────────────────────────────────────────────────
# import_program_scope
# ─────────────────────────────────────────────────────────────────────────────

def test_import_program_scope_text(tmp_path):
    store = _store(tmp_path)
    f = tmp_path / "scope.txt"
    f.write_text(
        "# in scope\n"
        "*.example.com\n"
        "https://api.example.com\n"
        "!dev.example.com\n"
        "# out of scope\n"
        "blog.example.com\n"
    )
    res = store.import_program_scope(f)
    assert res == {"in_scope": 2, "out_of_scope": 2}

    entries = {e.target: e for e in store.list_scope(in_scope_only=False)}
    assert entries["*.example.com"].kind == "domain"
    assert entries["*.example.com"].in_scope is True
    assert entries["dev.example.com"].in_scope is False   # the ! prefix
    assert entries["blog.example.com"].in_scope is False   # the section marker


def test_import_program_scope_hackerone_json(tmp_path):
    store = _store(tmp_path)
    f = tmp_path / "h1.json"
    f.write_text(json.dumps([
        {"asset_identifier": "*.hacker.one", "asset_type": "WILDCARD",
         "eligible_for_submission": True},
        {"asset_identifier": "secret.hacker.one",
         "eligible_for_submission": False},
    ]))
    res = store.import_program_scope(f)
    assert res == {"in_scope": 1, "out_of_scope": 1}
    entries = {e.target: e for e in store.list_scope(in_scope_only=False)}
    assert entries["*.hacker.one"].in_scope is True
    assert entries["secret.hacker.one"].in_scope is False


def test_import_program_scope_simple_dict_json(tmp_path):
    store = _store(tmp_path)
    f = tmp_path / "scope.json"
    f.write_text(json.dumps({
        "in_scope": ["*.app.io", "https://portal.app.io"],
        "out_of_scope": ["status.app.io"],
    }))
    res = store.import_program_scope(f)
    assert res == {"in_scope": 2, "out_of_scope": 1}


def test_import_scope_file_still_in_scope_only(tmp_path):
    # Regression: the plain importer is unchanged (every line in-scope, int count).
    store = _store(tmp_path)
    f = tmp_path / "plain.txt"
    f.write_text("example.com\n10.0.0.1\n# comment\nhttps://x.example.com\n")
    n = store.import_scope_file(f)
    assert n == 3
    assert all(e.in_scope for e in store.list_scope(in_scope_only=False))


def test_malformed_json_degrades_to_text(tmp_path):
    # A broken JSON body must not raise; it falls back to line parsing.
    store = _store(tmp_path)
    f = tmp_path / "broken.json"
    f.write_text("{ this is not valid json\nexample.com\n")
    res = store.import_program_scope(f)
    # The one parseable non-brace line is taken as an in-scope target.
    assert res["in_scope"] >= 1

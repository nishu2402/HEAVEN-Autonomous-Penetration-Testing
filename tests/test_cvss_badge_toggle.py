"""Opt-in CVSS v4.0 severity badge (HEAVEN_CVSS_BADGE_VERSION).

The badge stays on HEAVEN's calibrated v3.1 band by default. An operator can flip
the whole product to badge on the raw CVSS v4.0 score with one env var, accepting
that v4.0 rescores some low-impact classes higher by design. These tests pin both
directions and the safe fallbacks.
"""

from __future__ import annotations

from heaven.utils import cvss


def _band(finding: dict) -> str:
    f = dict(finding)
    cvss.reconcile_severity(f)
    return f["severity"]


# A verbose-error-style finding: calibrated v3.1 base 3.7 (Low), v4.0 base 6.3
# (Medium) — the exact low-end class where the two standards' bands diverge.
_VERBOSE = {
    "vuln_type": "verbose_errors", "severity": "low",
    "cvss_base": 3.7, "cvss4_base": 6.3, "confidence": 0.9,
    "evidence": {"cvss_base": 3.7, "cvss4_base": 6.3},
}


def test_default_badges_on_calibrated_v31(monkeypatch):
    monkeypatch.delenv("HEAVEN_CVSS_BADGE_VERSION", raising=False)
    assert cvss.cvss_badge_version() == "3.1"
    assert cvss.badge_base_score(_VERBOSE) == 3.7
    assert _band(_VERBOSE) == "low"


def test_opt_in_badges_on_raw_v40(monkeypatch):
    monkeypatch.setenv("HEAVEN_CVSS_BADGE_VERSION", "4.0")
    assert cvss.cvss_badge_version() == "4.0"
    assert cvss.badge_base_score(_VERBOSE) == 6.3
    assert _band(_VERBOSE) == "medium"


def test_v40_toggle_accepts_bare_4(monkeypatch):
    monkeypatch.setenv("HEAVEN_CVSS_BADGE_VERSION", "4")
    assert cvss.cvss_badge_version() == "4.0"


def test_falls_back_to_objective_when_no_v4_score(monkeypatch):
    monkeypatch.setenv("HEAVEN_CVSS_BADGE_VERSION", "4.0")
    no_v4 = {"vuln_type": "xss", "severity": "high", "cvss_base": 7.5, "evidence": {}}
    # No v4.0 base on the finding -> the badge falls back to the objective base.
    assert cvss.badge_base_score(no_v4) == cvss.objective_base_score(no_v4)
    assert _band(no_v4) == "high"


def test_garbage_value_is_safe_default(monkeypatch):
    monkeypatch.setenv("HEAVEN_CVSS_BADGE_VERSION", "banana")
    assert cvss.cvss_badge_version() == "3.1"
    assert _band(_VERBOSE) == "low"


def test_setting_is_registered_in_catalog():
    from heaven.settings_catalog import SETTINGS
    spec = next((s for s in SETTINGS if s.key == "HEAVEN_CVSS_BADGE_VERSION"), None)
    assert spec is not None
    assert spec.secret is False
    assert "4.0" in spec.choices and "3.1" in spec.choices

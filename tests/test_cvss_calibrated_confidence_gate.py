"""Calibrated confidence gates the severity band for no-CVE findings.

Open item from the 2026-09-28 live audit (``live-target-fp-audit``): the
additive ML calibrator (``evidence.calibrated_confidence``, written by
``vulnscan/calibration.py``) was computed and shown but never fed back into
severity/confirmation resolution. So a class finding whose *adjudicated*
``confidence`` cleared the bar (>=0.5) but whose *calibrated* probability landed
in lead territory (sub-0.40) still inherited the full hot class band and read as
Confirmed, over-claiming a weak signal.

``is_unconfirmed_finding`` now treats a no-CVE finding with sub-0.40 calibrated
confidence as unconfirmed, so:

  * ``reconcile_severity`` caps its CVSS number to the detector's own band and
    never escalates it up to the hotter class band;
  * ``confirmation_status`` reports it Potential, keeping it out of the
    confirmed-risk headline.

Crucially this is scoped so HEAVEN's "severity = impact if true" model is
preserved: a CVE-backed finding keeps its published impact band (likelihood is
carried by Confirmed/Potential, not by capping the number), and an actively
validated finding stays Confirmed.
"""
from __future__ import annotations

import copy

from heaven.utils.cvss import (
    confirmation_status,
    is_unconfirmed_finding,
    reconcile_severity,
)


def _api_broken_auth(*, severity: str, calibrated: float | None, raw: float = 0.7):
    """A no-CVE class finding whose curated class base (8.1 == High) sits above a
    deliberately lower detector label, so a cap/escalation is observable."""
    ev: dict = {"typical_cvss": 8.1}
    if calibrated is not None:
        ev["calibrated_confidence"] = calibrated
    return {
        "vuln_type": "api_broken_auth",
        "title": "Broken authentication on /api/v1/users",
        "target": "https://api.example.com/v1/users",
        "severity": severity,
        "confidence": raw,
        "typical_cvss": 8.1,
        "evidence": ev,
    }


# ── the core predicate ──────────────────────────────────────────────────────

def test_sub040_calibrated_no_cve_is_unconfirmed():
    f = _api_broken_auth(severity="medium", calibrated=0.30)
    assert is_unconfirmed_finding(f) is True


def test_calibrated_at_or_above_040_is_not_unconfirmed():
    # The honesty layer's lead floor is 0.40; a finding the calibrator still
    # rates above it keeps its band (this is the conservative boundary).
    f = _api_broken_auth(severity="medium", calibrated=0.45)
    assert is_unconfirmed_finding(f) is False


def test_absent_calibration_leaves_behaviour_unchanged():
    # No calibrated value present (pre-calibration / unit construction) -> the new
    # branch never fires; only the long-standing raw-confidence rule applies.
    f = _api_broken_auth(severity="medium", calibrated=None, raw=0.7)
    assert is_unconfirmed_finding(f) is False


# ── severity-band effect via reconcile_severity ───────────────────────────────

def test_low_calibrated_finding_is_not_escalated_to_hot_class_band():
    """Pre-fix a Medium-labelled no-CVE finding with an 8.1 class base was
    realigned UP to High. A sub-0.40 calibrated read now caps it to its own band
    instead of inflating a weak signal."""
    f = _api_broken_auth(severity="medium", calibrated=0.30)
    out = reconcile_severity(copy.deepcopy(f))
    assert out["severity"] == "medium"               # NOT escalated to high
    assert out["cvss_base"] <= 6.9                    # capped to the medium band


def test_above_floor_finding_still_follows_its_class_base():
    """The gate is specifically the sub-0.40 boundary: an above-floor finding
    still realigns up to its class base exactly as before (no silent miss)."""
    f = _api_broken_auth(severity="medium", calibrated=0.45)
    out = reconcile_severity(copy.deepcopy(f))
    assert out["severity"] == "high"


# ── confirmation status (the confirmed-risk headline) ─────────────────────────

def test_low_calibrated_no_cve_reads_potential():
    f = _api_broken_auth(severity="medium", calibrated=0.30)
    assert confirmation_status(f) == "Potential"


def test_above_floor_no_cve_reads_confirmed():
    f = _api_broken_auth(severity="medium", calibrated=0.45)
    assert confirmation_status(f) == "Confirmed"


# ── guard 1: a published CVE keeps its impact band (severity = impact if true) ─

def test_banner_cve_is_not_demoted_by_low_calibrated_confidence():
    """A banner-matched CVE is Potential (its likelihood is unproven) but its
    *impact* band is authoritative: a Critical RCE stays Critical, never pulled
    down to a Low number just because the banner match calibrates low."""
    f = {
        "vuln_type": "vulnerable_service",
        "title": "Apache httpd 2.4.49 path traversal",
        "target": "10.0.0.5:443",
        "severity": "critical",
        "confidence": 0.9,
        "cve": "CVE-2021-41773",
        "cvss_base": 9.8,
        "evidence": {"calibrated_confidence": 0.28},
    }
    assert is_unconfirmed_finding(f) is False          # CVE guard: not unconfirmed
    out = reconcile_severity(copy.deepcopy(f))
    assert out["severity"] == "critical"               # impact preserved
    assert out["cvss_base"] == 9.8                      # number not capped down
    assert confirmation_status(f) == "Potential"        # likelihood still honest


# ── guard 2: an actively validated finding stays Confirmed ────────────────────

def test_validated_poc_stays_confirmed():
    """Active validation is ground truth; the calibrator lifts a validated PoC
    well above the floor, and confirmation never demotes it regardless."""
    f = {
        "vuln_type": "sqli",
        "title": "SQL injection on id parameter",
        "target": "https://app.example.com/item?id=1",
        "severity": "high",
        "confidence": 0.9,
        "validated": True,
        "evidence": {"calibrated_confidence": 0.94, "proof_output": "5.7.44-log"},
    }
    assert confirmation_status(f) == "Confirmed"
    assert is_unconfirmed_finding(f) is False


# ── additive invariant: the adjudicated confidence is never mutated ───────────

def test_adjudicated_confidence_is_never_overwritten():
    f = _api_broken_auth(severity="medium", calibrated=0.30)
    reconcile_severity(f)
    assert f["confidence"] == 0.7                       # untouched by the cap


# ── restructure regressions: the long-standing raw/marker rules still hold ────

def test_marker_titled_finding_is_unconfirmed_even_with_a_cve():
    # An "indicator / possible / potential"-worded title stays unconfirmed even
    # when a CVE is attached (marker check precedes the CVE guard).
    f = {"vuln_type": "possible_rce", "title": "Possible RCE indicator",
         "cve": "CVE-2020-0001", "confidence": 0.9, "evidence": {}}
    assert is_unconfirmed_finding(f) is True


def test_low_raw_confidence_with_cve_is_not_unconfirmed():
    # A CVE-backed finding is authoritative for impact: a low *raw* confidence
    # does not make it unconfirmed (long-standing behaviour, preserved).
    f = {"vuln_type": "vulnerable_service", "title": "svc",
         "cve": "CVE-2020-0002", "confidence": 0.3, "evidence": {}}
    assert is_unconfirmed_finding(f) is False


def test_low_raw_confidence_without_cve_is_unconfirmed():
    f = {"vuln_type": "weak_signal", "title": "svc", "confidence": 0.3,
         "evidence": {}}
    assert is_unconfirmed_finding(f) is True

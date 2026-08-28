"""CVSS v4.0 upgrade (dual-version, v4.0-first).

HEAVEN presents CVSS v4.0 as the current standard alongside CVSS v3.1. These
tests pin the contract:

  * the core scorer routes v4.0 vectors to the reference library and keeps the
    in-house v3.1 formula for v3.1 vectors, and reports each vector's version;
  * every knowledge-base class has a faithful, scoreable v4.0 vector, and
    ``enrich_finding`` stamps a v4.0 companion score/vector plus ``cvss_version``
    on every finding WITHOUT changing the calibrated severity badge (which stays
    driven by the v3.1 score, so nothing re-bands);
  * feeds prefer a published v4.0 score (NVD ``cvssMetricV40``, OSV ``CVSS_V4``);
  * the ML feature parser accepts a v4.0 vector so a v4.0 finding still scores;
  * the contextual scorer adjusts a v4.0-anchored finding with v4.0 metrics.
"""
import copy

import pytest

from heaven.devsecops.vuln_kb import (
    _CVSS4_VECTOR_BY_KEY,
    _CVSS_VECTOR_BY_KEY,
    canonical_severity,
    cvss4_vector_for,
    cvss_vector_for,
    enrich_finding,
)
from heaven.ml.feature_engine import parse_cvss_vector
from heaven.utils import cvss

try:
    from cvss import CVSS4  # noqa: F401
    _HAS_CVSS_LIB = True
except Exception:  # pragma: no cover
    _HAS_CVSS_LIB = False

pytestmark = pytest.mark.skipif(not _HAS_CVSS_LIB, reason="cvss library required")


# ── core scorer ─────────────────────────────────────────────────────────────

def test_version_detection():
    assert cvss.cvss_version_of("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == "4.0"
    assert cvss.cvss_version_of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.1"
    assert cvss.cvss_version_of("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.0"
    assert cvss.cvss_version_of("AV:N/AC:L") == ""
    assert cvss.cvss_version_of("") == ""


def test_v40_and_v31_route_to_the_right_scorer():
    # A known FIRST v4.0 example scores via the reference library.
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    assert cvss.base_score_from_vector(v4) == 10.0
    # v3.1 still uses the in-house formula (unchanged).
    v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss.base_score_from_vector(v3) == 9.8


def test_malformed_v40_vector_degrades_to_zero():
    assert cvss.base_score_from_vector("CVSS:4.0/nonsense") == 0.0


# ── knowledge base: faithful, scoreable v4.0 per class ──────────────────────

def test_every_class_has_a_scoreable_v40_vector():
    # Same key set as the v3.1 table, and every non-empty vector scores in range.
    assert set(_CVSS4_VECTOR_BY_KEY) == set(_CVSS_VECTOR_BY_KEY)
    for key, vec in _CVSS4_VECTOR_BY_KEY.items():
        if not vec:  # posture_ok is intentionally blank
            continue
        assert vec.startswith("CVSS:4.0/"), key
        score = cvss.base_score_from_vector(vec)
        assert 0.0 <= score <= 10.0, (key, vec, score)
        # A class scores zero in v4.0 only when it is an informational, no-impact
        # posture entry — and then its v3.1 counterpart is zero too (parity).
        v31_score = cvss.base_score_from_vector(_CVSS_VECTOR_BY_KEY[key])
        if score == 0.0:
            assert v31_score == 0.0, (key, "v4.0 zero but v3.1 non-zero")
        else:
            assert v31_score > 0.0, (key, "v4.0 non-zero but v3.1 zero")


def test_v40_vectors_are_genuinely_per_class():
    # Not a flat constant: the distinct v4.0 scores span a real range.
    scores = {cvss.base_score_from_vector(v) for v in _CVSS4_VECTOR_BY_KEY.values() if v}
    assert len(scores) >= 15
    assert min(scores) < 4.0 and max(scores) == 10.0


def test_cvss_vector_for_defaults_v31_and_v40_on_request():
    assert cvss_vector_for("sql_injection").startswith("CVSS:3.1/")
    assert cvss_vector_for("sql_injection", version="4.0").startswith("CVSS:4.0/")
    assert cvss4_vector_for("sql_injection").startswith("CVSS:4.0/")
    # Aliases resolve in both tables.
    assert cvss4_vector_for("sqli").startswith("CVSS:4.0/")


# ── enrich stamps the v4.0 companion, badge stays v3.1-calibrated ───────────

def test_enrich_stamps_v40_companion_without_changing_badge():
    base = {"target": "http://h/x", "vuln_type": "lfi", "title": "LFI",
            "severity": "critical", "confidence": 0.9, "evidence": {}}
    badge_before = canonical_severity(copy.deepcopy(base))
    out = enrich_finding(copy.deepcopy(base))
    # The badge is the calibrated (v3.1) severity — unchanged by the upgrade.
    assert out["severity"] == badge_before == "high"
    # A v4.0 companion is present and scored.
    assert out["cvss4_vector"].startswith("CVSS:4.0/")
    assert out["cvss4_base"] == pytest.approx(cvss.base_score_from_vector(out["cvss4_vector"]), abs=0.05)
    # The primary vector driving the badge stays v3.1, recorded in cvss_version.
    assert out["cvss_vector"].startswith("CVSS:3.1/")
    assert out["cvss_version"] == "3.1"


def test_enrich_keeps_published_v40_as_primary():
    out = enrich_finding({
        "target": "h:22", "vuln_type": "vulnerable_service", "title": "regreSSHion",
        "severity": "high", "cvss_base": 9.3, "cve_id": "CVE-2024-6387",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "evidence": {},
    })
    assert out["cvss_version"] == "4.0"
    assert out["cvss4_vector"].startswith("CVSS:4.0/")
    assert out["cvss4_base"] > 0


def test_v40_companion_never_re_bands_the_badge():
    # XXE's v4.0 score is lower than its v3.1 band by design; the badge must not
    # follow the v4.0 number down.
    out = enrich_finding({"target": "http://h/x", "vuln_type": "xxe", "title": "XXE",
                          "severity": "high", "confidence": 0.9, "evidence": {}})
    assert out["severity"] == "high"
    assert out["cvss4_base"] < 7.0  # v4.0 rates it Medium; badge stays High


# ── feeds prefer published v4.0 ─────────────────────────────────────────────

def test_nvd_prefers_v40_and_keeps_companions():
    from heaven.vulnscan.nvd_client import parse_cvss_metrics
    r = parse_cvss_metrics({
        "cvssMetricV40": [{"cvssData": {
            "baseScore": 9.3, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}],
        "cvssMetricV31": [{"cvssData": {
            "baseScore": 8.1,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "baseSeverity": "HIGH"}],
    })
    assert r["cvss_version"] == "4.0"
    assert r["cvss_base"] == 9.3
    assert r["cvss4_base"] == 9.3 and r["cvss31_base"] == 8.1


def test_nvd_falls_back_to_v31_when_no_v40():
    from heaven.vulnscan.nvd_client import parse_cvss_metrics
    r = parse_cvss_metrics({"cvssMetricV31": [{"cvssData": {
        "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "baseSeverity": "HIGH"}]})
    assert r["cvss_version"] == "3.1"
    assert r["cvss_base"] == 7.5 and r["cvss4_base"] == 0.0


def test_osv_prefers_cvss_v4_over_v3():
    from heaven.vulnscan.osv_client import _parse_severity
    rec = {"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
    ]}
    vector, score, label = _parse_severity(rec)
    assert vector.startswith("CVSS:4.0/")
    assert score == 10.0 and label == "critical"


# ── ML feature parser accepts v4.0 ──────────────────────────────────────────

def test_feature_parser_reads_v40_vector():
    feats = parse_cvss_vector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
    assert feats["attack_vector"] == 1.0
    assert feats["conf_impact"] == 1.0 and feats["integ_impact"] == 1.0
    assert feats["scope_changed"] == 1.0  # subsequent-system impact == v3 Scope:Changed


def test_feature_parser_folds_attack_requirements_into_complexity():
    at_present = parse_cvss_vector(
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert at_present["attack_complexity"] <= 0.5


def test_feature_parser_still_reads_short_code_v31():
    feats = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert feats["attack_vector"] == 1.0 and feats["scope_changed"] == 1.0


# ── v4.0 contextual scoring ─────────────────────────────────────────────────

def test_v40_contextual_adjusts_with_v40_metrics():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    f = {"vuln_type": "cve", "severity": "critical", "cvss_base": 9.3,
         "cvss_vector": v4, "evidence": {}}
    # KEV + internet-facing keeps it high; internal + low-criticality lowers it.
    hot = cvss.contextual_score({**f, "in_kev": True}, criticality="high", exposure="external")
    cold = cvss.contextual_score(dict(f), criticality="low", exposure="internal")
    assert hot >= cold
    assert 0 < cold < hot <= 10.0


# ── coherent display: every CVSS number shows its own band ──────────────────

def test_cvss_with_band_labels_score_and_passes_through_blank():
    from heaven.devsecops.compliance_report import _cvss_with_band
    assert _cvss_with_band("6.3") == "6.3 (Medium)"
    assert _cvss_with_band("3.7") == "3.7 (Low)"
    assert _cvss_with_band("9.8") == "9.8 (Critical)"
    # Non-numeric and zero pass through untouched (no "(None)" noise).
    assert _cvss_with_band("—") == "—"
    assert _cvss_with_band("0.0") == "0.0"


def test_report_card_labels_v40_band_and_keeps_low_badge():
    # verbose_errors is the low-end case: v4.0 bands Medium while the badge is
    # Low. The card must label the v4.0 number with its own band and NOT let the
    # badge follow the v4.0 lift.
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    f = enrich_finding({"target": "http://h/x", "vuln_type": "verbose_errors",
                        "title": "Verbose errors", "severity": "low",
                        "confidence": 0.9, "evidence": {}})
    assert f["severity"] == "low"
    card = ComplianceReportGenerator()._finding_card(1, f)
    assert "6.3 (Medium)" in card   # v4.0 score carries its own band
    assert "3.7 (Low)" in card      # v3.1 score carries its own band


def test_sarif_emits_v40_band_alongside_score():
    from heaven.devsecops.ci_export import findings_to_sarif
    f = enrich_finding({"target": "http://h/x", "vuln_type": "verbose_errors",
                        "title": "Verbose errors", "severity": "low",
                        "confidence": 0.9, "evidence": {}})
    props = findings_to_sarif([f])["runs"][0]["results"][0]["properties"]
    assert props["cvss-v4"] == "6.3"
    assert props["cvss-v4-severity"] == "medium"
    assert props["severity"] == "low"  # badge stays calibrated

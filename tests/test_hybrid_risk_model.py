"""Tests for the hybrid CVSS risk model: the description/type fallback model
(heaven.ml.desc_model) and the routing in heaven.ml.risk_model.

The trained description-model artifact is gitignored (trained from a large
external dataset), so artifact-dependent assertions are skipped when it is not
present — the routing/degradation logic is exercised regardless.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.ml.desc_model import (
    FLAG_NAMES, DescriptionRiskModel, build_feature_row, derive_flags, get_desc_model,
)
from heaven.ml.risk_model import _has_cvss_signal, score_vulnerabilities


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── flag derivation ───────────────────────────────────────────────────────────

def test_derive_flags_from_vuln_type():
    assert derive_flags({"vuln_type": "sql_injection"})["Flag_SQLi"] == 1
    assert derive_flags({"vuln_type": "reflected_xss"})["Flag_XSS"] == 1
    assert derive_flags({"vuln_type": "rce"})["Flag_RCE"] == 1
    assert derive_flags({"vuln_type": "command_injection"})["Flag_RCE"] == 1
    assert derive_flags({"vuln_type": "path_traversal"})["Flag_Directory_Traversal"] == 1


def test_derive_flags_from_text_backstop():
    # vuln_type unknown, but the title/evidence names the class
    f = {"vuln_type": "web_issue", "title": "Buffer overflow in parser",
         "evidence": {"description": "denial of service via crafted packet"}}
    flags = derive_flags(f)
    assert flags["Flag_Buffer_Overflow"] == 1
    assert flags["Flag_DoS"] == 1


def test_derive_flags_none_for_benign():
    flags = derive_flags({"vuln_type": "info_disclosure", "title": "Server banner"})
    assert sum(flags.values()) == 0


# ── feature row + clipping ────────────────────────────────────────────────────

def test_build_feature_row_order_and_clip():
    feats = FLAG_NAMES + ["Word_Count", "Char_Length"]
    clip = {"Word_Count": [7.0, 200.0], "Char_Length": [53.0, 1600.0]}
    # a tiny title → word/char below the clip floor → clamped up to the floor
    row = build_feature_row({"vuln_type": "sqli", "title": "x"}, feats, clip)
    assert len(row) == len(feats)
    wc = row[feats.index("Word_Count")]
    cl = row[feats.index("Char_Length")]
    assert wc == 7.0 and cl == 53.0  # clamped to the floor
    assert row[feats.index("Flag_SQLi")] == 1.0


# ── CVSS-signal routing ───────────────────────────────────────────────────────

def test_has_cvss_signal():
    assert _has_cvss_signal({"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert _has_cvss_signal({"cvss_base": 7.5})
    assert _has_cvss_signal({"evidence": {"cvss_score": 9.8}})
    assert not _has_cvss_signal({"vuln_type": "sqli", "title": "SQLi"})
    assert not _has_cvss_signal({"cvss_base": 0})       # 0 is not a real score
    assert not _has_cvss_signal({"cvss_base": "n/a"})   # non-numeric ignored


# ── unavailable model degrades cleanly ────────────────────────────────────────

def test_desc_model_predict_zero_when_unavailable():
    m = DescriptionRiskModel.__new__(DescriptionRiskModel)
    m._model = None
    m._feature_names = []
    m._clip = {}
    m._meta = {}
    assert m.available is False
    assert m.predict({"vuln_type": "sqli"}) == 0.0


def test_score_vulnerabilities_runs_and_tags_model():
    findings = [
        {"vuln_type": "sqli", "title": "SQLi in login", "severity": "high"},
        {"vuln_type": "sqli", "title": "SQLi",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "critical"},
    ]
    out = _run(score_vulnerabilities(findings=findings))
    assert out["scored"] == 2
    for f in out["risk_scores"]:
        assert f["cvss_model"] in ("vector", "description")
        assert 0.0 <= f["predicted_cvss_score"] <= 10.0
        assert f["risk_band"] in ("critical", "high", "medium", "low")
    # a finding carrying a real vector must always use the vector model
    vec_finding = next(f for f in out["risk_scores"] if f.get("cvss_vector"))
    assert vec_finding["cvss_model"] == "vector"
    assert "hybrid" in out["metrics"]


# ── artifact-dependent (skipped when the trained model is absent) ──────────────

_HAS_DESC = get_desc_model().available


@pytest.mark.skipif(not _HAS_DESC, reason="description model artifact not present")
def test_desc_model_sensible_ordering_when_present():
    """The text model reads the finding's description and must order clearly
    different severities sensibly: code execution (critical) outranks a reflected
    XSS or a plain DoS (medium). Every prediction stays in the CVSS range."""
    m = get_desc_model()
    rce = m.predict({"vuln_type": "rce", "title": "Remote code execution in file upload handler"})
    cmdi = m.predict({"vuln_type": "command_injection", "title": "OS command injection in ping tool"})
    xss = m.predict({"vuln_type": "reflected_xss", "title": "Reflected XSS in search box"})
    dos = m.predict({"vuln_type": "dos", "title": "Denial of service via crafted request"})
    for v in (rce, cmdi, xss, dos):
        assert 0.0 < v <= 10.0
    # the two code-execution findings clearly outrank the medium-severity ones
    assert min(rce, cmdi) > max(xss, dos)


@pytest.mark.skipif(not _HAS_DESC, reason="description model artifact not present")
def test_hybrid_routes_unscored_to_description():
    out = _run(score_vulnerabilities(findings=[
        {"vuln_type": "sql_injection", "title": "SQLi in login form", "severity": "high"},
    ]))
    assert out["risk_scores"][0]["cvss_model"] == "description"
    assert out["metrics"]["hybrid"]["scored_by_description"] == 1


@pytest.mark.skipif(not _HAS_DESC, reason="description model artifact not present")
def test_hybrid_keeps_vector_model_for_unflagged_types():
    """A no-vector finding OUTSIDE the seven description-model classes (e.g. SSRF)
    must use the vector model's curated vector, not the description model's flat
    generic prediction — otherwise its severity would be understated."""
    out = _run(score_vulnerabilities(findings=[
        {"vuln_type": "ssrf", "title": "SSRF in webhook fetch", "severity": "high"},
        {"vuln_type": "default_credentials", "title": "Default admin creds", "severity": "critical"},
    ]))
    for f in out["risk_scores"]:
        assert f["cvss_model"] == "vector"
        assert f["predicted_cvss_score"] >= 7.0  # not understated to a generic ~4


@pytest.mark.skipif(not _HAS_DESC, reason="description model artifact not present")
def test_desc_model_reports_band_accuracy():
    """The description model exposes severity-band accuracy — the metric that
    reflects HEAVEN's real use (does the score land in the right CVSS band?),
    a fairer read than R² on a target whose same-class scores span a wide range.
    Both the real-finding (``cv_*``) and the deployment (``deploy_*``) populations
    are reported; the deployment figures are the ones HEAVEN actually runs on."""
    m = get_desc_model().get_metrics()
    for exact, within1 in (
        (m["cv_band_exact"], m["cv_band_within1"]),
        (m["deploy_band_exact"], m["deploy_band_within1"]),
    ):
        assert exact is not None and within1 is not None
        # within-one-band must be very high and never below exact-band agreement.
        assert 0.0 < exact <= within1 <= 1.0
        assert within1 >= 0.90


@pytest.mark.skipif(not _HAS_DESC, reason="description model artifact not present")
def test_desc_model_trained_on_real_finding_population():
    """The model must train on the population HEAVEN actually scores — real
    (non-zero-score) findings — not on all labelled CVEs (which include ~22k
    trivially-predictable score-0 informational entries that inflate R²)."""
    m = get_desc_model().get_metrics()
    assert m.get("training_population") == "nonzero_cvss"
    # deployment R²/MAE are the honest, use-relevant figures and must be present.
    assert m["deploy_r2"] is not None and m["deploy_mae"] is not None
    assert 0.0 < m["deploy_r2"] < 0.95   # honest, not a leakage 0.999
    assert 0.0 < m["deploy_mae"] < 2.0


# ── denial-of-service vector is availability-oriented (not a data-breach vector) ─

def test_denial_of_service_vector_is_availability_impact():
    """A generic Denial of Service must resolve to an AVAILABILITY-impact CVSS
    vector (A:H, C:N/I:N) — not a confidentiality/integrity breach vector. This
    guards the regression where a DoS finding was scored with C:H/I:H/A:N."""
    from heaven.utils.cvss import base_score_from_vector, parse_vector
    from heaven.devsecops.vuln_kb import cvss_vector_for

    for alias in ("denial_of_service", "dos", "ddos"):
        vec = cvss_vector_for(alias)
        assert vec, f"{alias} has no curated CVSS vector"
        parts = parse_vector(vec)
        assert parts.get("A") == "H", f"{alias} should have High availability impact"
        assert parts.get("C") == "N" and parts.get("I") == "N", \
            f"{alias} must not claim confidentiality/integrity impact"
        assert base_score_from_vector(vec) >= 7.0  # confirmed network DoS is High

    # A GraphQL-specific DoS keeps its own (lower, partial-availability) vector.
    assert cvss_vector_for("graphql_dos") != cvss_vector_for("denial_of_service")

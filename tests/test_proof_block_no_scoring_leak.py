"""The proof/evidence block must not surface scoring internals as "Observed".

``_proof_blocks`` synthesises an honest evidence block for a finding that
carries no HTTP transaction. ``enrich_finding`` and the ML risk model inject
scoring/calibration keys (predicted_cvss_score, priority_score, risk_band,
calibrated_confidence, calibration, cvss4_base, …) into a finding's evidence,
and those are already rendered in the finding's metadata table. Showing them
again inside the proof block presents scoring noise where the reader expects
the actual security observation, so they must be excluded from the synthesised
"Observed" lines while any genuine observed evidence is preserved.

Reconstructed from the real certifiedhacker.com scan, whose thin posture
findings (no_hsts, tls_sha1, …) stored only scoring metadata in evidence_json.
"""

from __future__ import annotations

from heaven.devsecops.compliance_report import ComplianceReportGenerator

_SCORING_TOKENS = (
    "predicted_cvss", "priority_score", "priority score",
    "risk_band", "risk band", "calibrated_confidence", "calibrated confidence",
    "calibration", "cvss4_base", "cvss4 base", "typical_cvss", "objective_base",
)


def _gen() -> ComplianceReportGenerator:
    # The proof resolver needs no constructor state, so avoid a full build.
    return ComplianceReportGenerator.__new__(ComplianceReportGenerator)


def test_scoring_only_evidence_never_appears_as_proof():
    # A thin posture finding that carries ONLY scoring/calibration internals.
    f = {
        "vuln_type": "no_hsts",
        "target": "https://www.certifiedhacker.com",
        "severity": "medium",
        "evidence": {
            "predicted_cvss_score": 4.0,
            "priority_score": 1.98,
            "risk_band": "low",
            "calibrated_confidence": 0.975,
            "calibration": {"raw": 0.97, "source": "validated_poc",
                            "corroboration": 0, "model": "priors.v1"},
            "cvss4_base": 4.0,
        },
    }
    blocks = _gen()._proof_blocks(f)
    assert blocks, "every finding must get at least one proof block"
    joined = " ".join(text for _, _, text in blocks).lower()
    for tok in _SCORING_TOKENS:
        assert tok not in joined, f"scoring internal leaked into proof: {tok!r}"


def test_posture_observed_proof_renders_and_scoring_stripped():
    # C2: posture detectors now attach a concrete `observed` proof string, so the
    # proof block shows the real security fact (not the generic fallback) while
    # C1 still keeps the calibration/scoring internals out of it.
    f = {
        "vuln_type": "no_hsts",
        "target": "www.certifiedhacker.com:443",
        "severity": "medium",
        "evidence": {
            "observed": ("The HTTPS response from www.certifiedhacker.com:443 "
                         "carried no Strict-Transport-Security header, so a browser "
                         "will honour a plaintext-HTTP downgrade of this origin."),
            "strict_transport_security": "absent",
            # scoring internals the calibration step injects:
            "predicted_cvss_score": 4.0, "risk_band": "low",
            "calibrated_confidence": 0.975,
        },
    }
    blocks = _gen()._proof_blocks(f)
    joined = " ".join(text for _, _, text in blocks).lower()
    assert "strict-transport-security header" in joined, \
        "the concrete observed proof must be shown"
    for tok in _SCORING_TOKENS:
        assert tok not in joined, f"scoring internal leaked into proof: {tok!r}"


def test_real_observed_evidence_survives_alongside_scoring():
    # A finding that carries BOTH real observed evidence and scoring metadata:
    # the observation must be shown, the scoring must be stripped.
    f = {
        "vuln_type": "spf_analysis",
        "target": "certifiedhacker.com",
        "severity": "medium",
        "evidence": {
            "spf_record": "v=spf1 a mx ptr include:bluehost.com ?all",
            "issues": ["SPF uses '?all' (neutral), provides no protection"],
            "predicted_cvss_score": 6.1,
            "priority_score": 3.05,
            "risk_band": "medium",
            "calibrated_confidence": 0.965,
        },
    }
    blocks = _gen()._proof_blocks(f)
    joined = " ".join(text for _, _, text in blocks).lower()
    assert "v=spf1" in joined or "spf_record" in joined, \
        "genuine observed evidence must be preserved in the proof block"
    for tok in _SCORING_TOKENS:
        assert tok not in joined, f"scoring internal leaked into proof: {tok!r}"

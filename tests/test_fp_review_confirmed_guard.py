"""The advisory LLM FP reviewer must never override a hard confirmation (FP Audit 16).

``FPReviewer.apply`` nudges confidence and may suppress a *Potential* finding on
a ``keep=false`` verdict. But a finding established by direct observation / active
validation (``is_confirmed_finding``) can carry a moderate confidence that lands
inside the 0.40-0.70 review band (e.g. a directly-observed misconfiguration at
0.55). The reviewer is advisory, so it must not flip such a finding to
false_positive, nor demote its confidence below the deterministic score, on an
LLM opinion of a truncated evidence blob. It records the dissent and nothing more.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from heaven.ai.fp_review import FPReviewer, FPReviewVerdict


def _confirmed(conf: float = 0.55) -> dict:
    # Directly-observed misconfiguration: is_confirmed_finding -> True, and conf
    # >= 0.5 keeps it out of the no-CVE "unconfirmed" bucket.
    return {
        "vuln_type": "security_misconfiguration",
        "title": "Directory listing enabled on /backups/",
        "confidence": conf,
        "evidence": {"observed": "Index of /backups"},
    }


def _potential(conf: float = 0.55) -> dict:
    # Banner-inferred CVE with no active validation: is_confirmed_finding -> False.
    return {
        "vuln_type": "cve",
        "title": "Apache 2.4.49 affected by CVE-2021-41773",
        "confidence": conf,
        "cve": "CVE-2021-41773",
        "source": "nvd",
        "evidence": {},
    }


def test_confirmed_finding_not_suppressed_on_keep_false():
    f = _confirmed(0.55)
    FPReviewer.apply(f, FPReviewVerdict(keep=False, confidence_delta=-0.3,
                                        reasoning="looks like noise to me"))
    # The dissent is recorded ...
    assert f["llm_review_kept"] is False
    # ... but the confirmed finding is NOT flipped to a false positive.
    assert f.get("suppressed") is not True
    assert f.get("result") != "false_positive"
    # ... and its confidence is not demoted below the deterministic score.
    assert f["confidence"] == 0.55


def test_potential_finding_still_suppressed_on_keep_false():
    f = _potential(0.55)
    FPReviewer.apply(f, FPReviewVerdict(keep=False, confidence_delta=-0.3,
                                        reasoning="coincidental banner match"))
    assert f["suppressed"] is True
    assert f["result"] == "false_positive"
    assert f["confidence"] == pytest.approx(0.25)


def test_confirmed_finding_can_still_be_raised():
    f = _confirmed(0.55)
    FPReviewer.apply(f, FPReviewVerdict(keep=True, confidence_delta=0.2,
                                        reasoning="evidence is solid"))
    assert f["confidence"] == pytest.approx(0.75)
    assert f.get("suppressed") is not True


def test_confirmed_finding_negative_delta_clamped():
    f = _confirmed(0.60)
    FPReviewer.apply(f, FPReviewVerdict(keep=True, confidence_delta=-0.4,
                                        reasoning="still fine but less sure"))
    # A negative nudge on a confirmed finding is clamped to zero, so a
    # directly-observed finding is never demoted below the leads threshold by
    # an advisory pass.
    assert f["confidence"] == 0.60

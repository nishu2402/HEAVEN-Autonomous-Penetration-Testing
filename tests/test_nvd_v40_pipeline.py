"""The training pipeline must learn from CVSS v4.0-only CVEs, not discard them.

Modern CVEs increasingly ship a CVSS v4.0 score and no v3.x score. The trainer
reads the v3.x metric first (v3.1 is still on the large majority of CVEs and is
one coherent scale), but when a CVE carries only a v4.0 metric it now folds that
onto the same 13-feature v3.x shape the model expects instead of dropping the row
outright. These tests pin that behaviour and the v4.0 -> v3.x recast it relies on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pandas")

from heaven.ml.nvd_pipeline import NVDPipeline


def _cve_v31(cid: str, base: float) -> dict:
    return {
        "cve": {
            "id": cid,
            "published": "2026-01-02T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": base, "attackVector": "NETWORK",
                        "attackComplexity": "LOW", "privilegesRequired": "NONE",
                        "userInteraction": "NONE", "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH", "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                    },
                }],
            },
        },
    }


def _cve_v40_only(cid: str, base: float) -> dict:
    return {
        "cve": {
            "id": cid,
            "published": "2026-02-02T00:00:00.000",
            "metrics": {
                "cvssMetricV40": [{
                    "cvssData": {
                        "baseScore": base, "attackVector": "NETWORK",
                        "attackComplexity": "LOW", "attackRequirements": "NONE",
                        "privilegesRequired": "NONE", "userInteraction": "NONE",
                        "vulnConfidentialityImpact": "HIGH",
                        "vulnIntegrityImpact": "HIGH",
                        "vulnAvailabilityImpact": "HIGH",
                        "subConfidentialityImpact": "NONE",
                        "subIntegrityImpact": "NONE",
                        "subAvailabilityImpact": "NONE",
                    },
                }],
            },
        },
    }


def _cve_no_metric(cid: str) -> dict:
    return {"cve": {"id": cid, "published": "2026-03-02T00:00:00.000", "metrics": {}}}


def test_parse_dataset_keeps_v40_only_cves(tmp_path: Path) -> None:
    jsonl = tmp_path / "mini.jsonl"
    rows = [_cve_v31("CVE-2026-0001", 9.8),
            _cve_v40_only("CVE-2026-0002", 8.7),
            _cve_no_metric("CVE-2026-0003")]
    jsonl.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    X, y, feats = NVDPipeline().parse_dataset(jsonl)

    # The v3.1 row and the v4.0-only row are both learned from; the metric-less
    # CVE is the only one dropped.
    assert len(y) == 2
    assert 9.8 in set(y)          # v3.1 label preserved
    assert 8.7 in set(y)          # v4.0-only label recovered (was silently dropped)
    assert X.shape[1] == 13


def test_v4_recast_folds_subsequent_impact_and_requirements() -> None:
    shaped = NVDPipeline._v4_to_v3_shaped({
        "attackVector": "NETWORK", "attackComplexity": "LOW",
        "attackRequirements": "PRESENT", "privilegesRequired": "NONE",
        "userInteraction": "PASSIVE",
        "vulnConfidentialityImpact": "LOW", "vulnIntegrityImpact": "NONE",
        "vulnAvailabilityImpact": "NONE",
        "subConfidentialityImpact": "HIGH", "subIntegrityImpact": "NONE",
        "subAvailabilityImpact": "NONE",
        "baseScore": 6.9,
    })
    # AT:Present reads as extra complexity, a subsequent-system hit is Scope:Changed,
    # and each impact takes the stronger of the vulnerable/subsequent systems.
    assert shaped["attackComplexity"] == "HIGH"
    assert shaped["scope"] == "CHANGED"
    assert shaped["confidentialityImpact"] == "HIGH"   # max(LOW vuln, HIGH sub)
    assert shaped["userInteraction"] == "REQUIRED"     # any interaction != NONE
    assert shaped["baseScore"] == 6.9


def test_v4_recast_empty_when_no_score() -> None:
    assert NVDPipeline._v4_to_v3_shaped({}) == {}
    assert NVDPipeline._v4_to_v3_shaped({"attackVector": "NETWORK"}) == {}

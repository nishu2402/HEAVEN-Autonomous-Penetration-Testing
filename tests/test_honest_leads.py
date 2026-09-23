"""Tests for the honest-lead channel + calibrated confidence.

These lock in the two invariants the feature exists to guarantee:

1. A substantiated signal that does not reach the finding bar is NOT dropped
   silently — it becomes a lead, in its own table, never counted as a finding.
2. Calibration is additive: a finding's calibrated probability is stamped on
   evidence without ever overwriting its adjudicated ``confidence``, and a
   banner-only match never calibrates as strongly as a validated proof.
"""

from __future__ import annotations

import pytest

from heaven.engagement import EngagementStore, extract_leads
from heaven.vulnscan.calibration import (
    calibrated_confidence,
    calibration_source,
    stamp_calibration,
)


@pytest.fixture()
def store(tmp_path):
    s = EngagementStore(tmp_path / "eng.db")
    s.create_engagement(name="t")
    return s


# ── calibration ─────────────────────────────────────────────────────────────

def test_calibration_is_additive():
    f = {"vuln_type": "xss", "confidence": 0.8, "evidence": {"signals": ["reflected"]}}
    stamp_calibration(f)
    assert f["confidence"] == 0.8  # never overwritten
    assert "calibrated_confidence" in f["evidence"]
    assert f["evidence"]["calibration"]["source"]


def test_validated_calibrates_higher_than_banner():
    validated = {"vuln_type": "sqli", "confidence": 0.9, "validated": True,
                 "evidence": {"signals": ["union_confirmed", "error_only_on_payload"],
                              "validation_result": "confirmed"}}
    banner = {"vuln_type": "vulnerable_service", "confidence": 0.9,
              "cve": "CVE-2007-2447", "evidence": {}}
    p_val, _ = calibrated_confidence(validated)
    p_ban, _ = calibrated_confidence(banner)
    assert calibration_source(validated) == "validated_poc"
    assert calibration_source(banner) == "banner_version"
    assert p_val > p_ban  # a proof is more certain than a version match


def test_calibration_never_raises_on_garbage():
    p, audit = calibrated_confidence({"confidence": "not-a-number"})
    assert 0.0 <= p <= 1.0
    assert "raw" in audit


# ── extract_leads ───────────────────────────────────────────────────────────

def test_suppressed_with_substance_becomes_lead():
    raw = [
        {"target": "http://x/?id=1", "vuln_type": "sqli", "suppressed": True,
         "fp_check_reasons": ["above_baseline_noise"], "confidence": 0.3,
         "evidence": {"signals": ["time_based"], "param": "id"}},
    ]
    leads = extract_leads(raw)
    assert len(leads) == 1
    assert "baseline" in leads[0]["reason"].lower()


def test_pure_noise_is_not_a_lead():
    raw = [{"target": "http://x/", "vuln_type": "sqli", "suppressed": True}]
    assert extract_leads(raw) == []


def test_confirmed_finding_is_not_a_lead():
    raw = [{"target": "http://x/?q=1", "vuln_type": "xss", "confidence": 0.9,
            "evidence": {"signals": ["reflected"]}}]  # not suppressed
    assert extract_leads(raw) == []


def test_leads_dedup_by_identity():
    c = {"target": "http://x/?id=1", "vuln_type": "sqli", "suppressed": True,
         "confidence": 0.3, "evidence": {"param": "id", "signals": ["time_based"]}}
    leads = extract_leads([dict(c), dict(c), dict(c)])
    assert len(leads) == 1


# ── leads store ─────────────────────────────────────────────────────────────

def test_lead_never_counts_as_a_finding(store):
    store.upsert_finding("s1", {"target": "http://x/", "vuln_type": "xss",
                                "title": "XSS", "severity": "high",
                                "confidence": 0.8, "evidence": {"signals": ["reflected"]}})
    store.record_lead("s1", {"target": "http://x/?id=1", "vuln_type": "sqli",
                             "title": "Maybe SQLi", "confidence": 0.3,
                             "evidence": {"param": "id", "signals": ["time_based"]}})
    assert store.count_findings() == 1
    assert store.count_leads() == 1
    # A lead id is not retrievable as a finding.
    leads = store.get_leads()
    assert store.get_finding(leads[0]["id"]) is None


def test_lead_dedup_bumps_seen_count(store):
    payload = {"target": "http://x/?q=1", "vuln_type": "ssti", "title": "SSTI?",
               "confidence": 0.3, "evidence": {"param": "q", "signals": ["fuzz_anomaly"]}}
    lid1 = store.record_lead("s1", dict(payload))
    lid2 = store.record_lead("s1", dict(payload))
    assert lid1 == lid2
    assert store.count_leads() == 1
    assert store.get_leads()[0]["seen_count"] == 2


def test_lead_promote_dismiss(store):
    lid = store.record_lead("s1", {"target": "http://x/?id=1", "vuln_type": "sqli",
                                   "title": "Maybe", "confidence": 0.3,
                                   "evidence": {"param": "id", "signals": ["time_based"]}})
    assert store.count_leads(status="open") == 1
    assert store.set_lead_status(lid, "dismissed") is True
    assert store.count_leads(status="open") == 0
    assert store.count_leads(status="dismissed") == 1
    with pytest.raises(ValueError):
        store.set_lead_status(lid, "bogus")


def test_lead_carries_honest_reason_and_next_step(store):
    lid = store.record_lead("s1", {
        "target": "http://x/?id=1", "vuln_type": "sqli", "title": "Maybe SQLi",
        "confidence": 0.3, "fp_check_reasons": ["not_reproducible"],
        "evidence": {"param": "id", "signals": ["time_based"]},
    })
    lead = store.get_leads()[0]
    assert lead["id"] == lid
    assert "reproduce" in lead["reason"].lower()
    assert lead["next_step"]  # a concrete manual step, never blank
    assert 0.0 <= lead["calibrated_confidence"] <= 1.0


def test_persisted_finding_carries_calibrated_confidence(store):
    store.upsert_finding("s1", {"target": "http://x/?q=1", "vuln_type": "xss",
                                "title": "XSS", "severity": "high",
                                "confidence": 0.8, "evidence": {"signals": ["reflected"]}})
    f = store.list_findings(limit=10)[0]
    assert "calibrated_confidence" in f.evidence
    assert f.confidence == pytest.approx(0.8)  # adjudicated value preserved


def test_leads_table_created_on_existing_db(tmp_path):
    # A store opened twice (simulating an upgrade) still has the leads table.
    db = tmp_path / "eng.db"
    EngagementStore(db).create_engagement(name="t")
    s2 = EngagementStore(db)
    assert s2.count_leads() == 0  # no crash → table exists

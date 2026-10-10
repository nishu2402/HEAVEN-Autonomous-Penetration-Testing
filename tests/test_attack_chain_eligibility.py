"""Regression: the attack-chain engine must not resurrect rejected findings.

``AttackChainEngine.ingest_findings`` used to turn every vulnerability into a
graph node with no eligibility filter, so a finding HEAVEN's FP-suppression layer
had already rejected (``suppressed=True`` / ``result="false_positive"``), or a
merely informational observation, could still appear as a node in a reported
attack chain. The correlation engine excludes exactly these; the attack-chain
engine now applies the same gate, so both reason over the clean finding set.
"""

from __future__ import annotations

from heaven.vulnscan.attack_chain import AttackChainEngine, _finding_is_eligible


def _node_vuln_types(engine):
    # Reconstruct which vuln types made it into the graph from node descriptions
    # and vulnerability tokens.
    return [n.vulnerability.lower() for n in engine.nodes]


def test_suppressed_and_false_positive_findings_are_excluded():
    engine = AttackChainEngine()
    engine.ingest_findings({"vulnerabilities": [
        {"vuln_type": "sqli", "host": "a", "severity": "high",
         "confidence": 0.9},                                   # clean  → kept
        {"vuln_type": "sqli", "host": "b", "severity": "high",
         "confidence": 0.9, "suppressed": True},               # rejected → dropped
        {"vuln_type": "ssrf", "host": "c", "severity": "high",
         "confidence": 0.9, "result": "false_positive"},       # rejected → dropped
        {"vuln_type": "xss", "host": "d", "severity": "high",
         "confidence": 0.9, "status": "false_positive"},       # rejected → dropped
    ]})
    hosts = {n.host for n in engine.nodes}
    assert hosts == {"a"}, [(n.host, n.vulnerability) for n in engine.nodes]


def test_info_severity_finding_is_excluded():
    engine = AttackChainEngine()
    engine.ingest_findings({"vulnerabilities": [
        {"vuln_type": "sqli", "host": "a", "severity": "info", "confidence": 0.9},
        {"vuln_type": "sqli", "host": "b", "severity": "informational", "confidence": 0.9},
        {"vuln_type": "sqli", "host": "c", "severity": "low", "confidence": 0.9},
    ]})
    hosts = {n.host for n in engine.nodes}
    assert hosts == {"c"}, [(n.host, n.vulnerability) for n in engine.nodes]


def test_finding_without_severity_is_still_accepted():
    # Findings that legitimately carry no severity field must pass through, as
    # before — the gate only drops explicitly info/none severities.
    engine = AttackChainEngine()
    engine.ingest_findings({"vulnerabilities": [
        {"vuln_type": "command_injection", "host": "a", "confidence": 0.9},
    ]})
    assert len(engine.nodes) == 1


def test_suppressed_secret_is_excluded():
    engine = AttackChainEngine()
    engine.ingest_findings({"secrets": [
        {"type": "aws_key", "file": "keep.py"},
        {"type": "aws_key", "file": "drop.py", "suppressed": True},
    ]})
    files = {n.host for n in engine.nodes}  # secret nodes use file as host
    assert files == {"keep.py"}, files


def test_eligibility_predicate_units():
    assert _finding_is_eligible({"severity": "high"}) is True
    assert _finding_is_eligible({"severity": "high", "suppressed": True}) is False
    assert _finding_is_eligible({"severity": "high", "result": "false_positive"}) is False
    assert _finding_is_eligible({"severity": "high", "status": "false_positive"}) is False
    assert _finding_is_eligible({"severity": "info"}) is False
    assert _finding_is_eligible({"severity": "none"}) is False
    assert _finding_is_eligible({}) is True          # no severity → allowed
    assert _finding_is_eligible("not a dict") is False

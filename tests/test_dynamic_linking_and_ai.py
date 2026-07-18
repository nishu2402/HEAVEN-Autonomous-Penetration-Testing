"""
HEAVEN — regression tests for the dynamic-linking + AI batch.

Covers the user-reported gaps:

* **Scan mode dispatch** — network reconnaissance runs for WEB/API/NETWORK (not
  only NETWORK) and receives the host parsed from a URL target, so the Host &
  Service Inventory populates for any host-based mode.
* **Attack-chain planner** — always returns grounded chains built from the real
  findings, even with no LLM key.
* **Knowledge graph** — a completed scan's findings populate the cross-engagement
  memory (previously nothing wrote to it, so it was permanently empty).
* **OWASP Top 10 coverage** — the report maps every finding to its OWASP-2021
  category dynamically (finding's enriched category first, keyword fallback).
* **Cyber Kill Chain** — real scanner vuln_types map to phases via substring
  aliases instead of dumping into the Reconnaissance default.
* **Dynamic CVE linking** — the report links each CVE to its live NVD record.
"""

from __future__ import annotations

import tempfile

from heaven.config import ScanMode, get_config
from heaven.orchestrator import build_full_scan


# ── Scan-mode dispatch + URL→host inventory ──────────────────────────────────

def _net_task(mode: ScanMode):
    targets = {"ips": [], "urls": ["https://app.example.com/login"], "repositories": [],
               "cloud_providers": [], "ports": "1-1024", "stealth_level": "normal"}
    orch = build_full_scan(targets, get_config(), scan_mode=mode)
    for t in orch.tasks.values():
        if t.name == "Network Reconnaissance":
            return t
    return None


def test_network_recon_runs_for_web_and_api_and_network():
    for mode in (ScanMode.WEB, ScanMode.API, ScanMode.NETWORK, ScanMode.FULL):
        assert _net_task(mode) is not None, f"network recon missing in {mode}"


def test_network_recon_not_in_email_mode():
    assert _net_task(ScanMode.EMAIL) is None


def test_network_recon_gets_host_parsed_from_url():
    t = _net_task(ScanMode.WEB)
    assert t.kwargs.get("targets") == ["app.example.com"]


# ── Attack-chain planner: deterministic, LLM-free ────────────────────────────

def test_deterministic_planner_builds_chains_from_findings():
    from heaven.ai.attack_chain_planner import build_deterministic_plans
    findings = [
        {"target": "https://a/x", "vuln_type": "sql_injection", "severity": "critical", "confidence": 0.9},
        {"target": "https://a/p", "vuln_type": "idor", "severity": "high", "confidence": 0.7},
    ]
    out = build_deterministic_plans(findings)
    assert not out.no_chain_possible
    assert out.plans
    p = out.plans[0]
    assert p.steps and 0.0 < p.estimated_success <= 0.9
    assert p.mitre_tactics


def test_deterministic_planner_no_findings():
    from heaven.ai.attack_chain_planner import build_deterministic_plans
    out = build_deterministic_plans([])
    assert out.no_chain_possible


def test_deterministic_planner_info_only_findings_yield_no_chain():
    from heaven.ai.attack_chain_planner import build_deterministic_plans
    # A finding with no offensive class → no chain, but an explicit explanation.
    out = build_deterministic_plans([{"target": "a", "vuln_type": "totally_unknown_class"}])
    assert out.no_chain_possible and out.reasoning


# ── Knowledge graph population ───────────────────────────────────────────────

def test_record_findings_to_knowledge_populates(monkeypatch):
    import heaven.ai.knowledge_graph as kg
    tmp = tempfile.mkdtemp()
    graph = kg.KnowledgeGraph(db_path=__import__("pathlib").Path(tmp) / "k.db")
    findings = [
        {"target": "10.0.0.5", "vuln_type": "sql_injection", "severity": "critical",
         "confidence": 0.9, "validated": True, "id": "f1"},
        {"target": "10.0.0.5", "vuln_type": "xss", "severity": "medium", "confidence": 0.5, "id": "f2"},
    ]
    assets = [{"host": "10.0.0.5", "ip": "10.0.0.5", "os": "Linux",
               "open_ports": [{"port": 22, "service": "ssh", "product": "OpenSSH"}]}]
    n = kg.record_findings_to_knowledge(findings, assets, engagement_name="t", graph=graph)
    assert n == 2
    stats = graph.stats()
    assert stats["attempts"] == 2 and stats["successes"] == 1  # only the validated one


# ── OWASP Top 10 dynamic coverage ────────────────────────────────────────────

def test_owasp_coverage_maps_findings_dynamically():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    findings = [
        {"vuln_type": "sql_injection", "title": "SQLi", "severity": "critical",
         "owasp": "A03:2021 Injection"},
        {"vuln_type": "missing_security_headers", "title": "No CSP", "severity": "low"},
        {"vuln_type": "ssl_weak_cipher", "title": "Weak TLS", "severity": "medium"},
        {"vuln_type": "ssrf", "title": "SSRF", "severity": "high"},
    ]
    html = gen._owasp_coverage(findings)
    # A03 (from enriched field), A05 (headers), A02 (tls), A10 (ssrf) all present.
    for cid in ("A03:2021", "A05:2021", "A02:2021", "A10:2021"):
        assert cid in html
    assert "Findings present" in html


def test_report_links_cve_to_nvd():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    html = gen.generate_html_report(
        [{"vuln_type": "vulnerable_service", "title": "Apache", "severity": "critical",
          "cve_id": "CVE-2021-41773", "confidence": 0.9}],
        engagement_name="t",
    )
    assert "nvd.nist.gov/vuln/detail/CVE-2021-41773" in html


# ── Kill chain substring mapping ─────────────────────────────────────────────

def test_kill_chain_maps_real_vuln_types_to_phases():
    from heaven.mitre.kill_chain import KillChainAnalyzer, KillChainPhase
    kc = KillChainAnalyzer()
    kc.ingest([
        {"vuln_type": "sql_injection", "title": "SQLi", "severity": "critical"},
        {"vuln_type": "missing_security_headers", "title": "No CSP", "severity": "low"},
        {"vuln_type": "vulnerable_service", "title": "Old Apache", "severity": "high"},
    ])
    cov = kc._coverage
    # Not everything piled into Reconnaissance: exploitation, delivery and
    # weaponization all have findings.
    assert cov[KillChainPhase.EXPLOITATION].findings
    assert cov[KillChainPhase.DELIVERY].findings
    assert cov[KillChainPhase.WEAPONIZATION].findings
    assert kc.coverage_score() > 14  # more than a single phase

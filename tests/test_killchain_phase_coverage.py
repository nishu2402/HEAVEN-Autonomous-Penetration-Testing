"""Cyber Kill Chain — real phase coverage.

The reported gap: many of the ``vuln_type`` slugs HEAVEN's scanners actually
emit (``cmdi``, ``missing_authentication``, ``database_exposed``,
``docker_api_exposed``, ``kubelet_exposed``, ``perimeter_defense``,
``unsupported_software``, ``telnet``, ``smtp_open_relay`` …) were absent from
``VULN_KILLCHAIN_MAP``, so those findings fell through to the default
Reconnaissance bucket and the Weaponization / Installation / Command-&-Control
phases stayed structurally dark.

These tests lock the fix: each real slug resolves to its correct phase(s), and a
realistic finding set lights every reachable phase — not just Recon.
"""
from __future__ import annotations

from heaven.mitre.kill_chain import (
    KillChainAnalyzer,
    KillChainPhase,
    analyze_findings,
)


def _phases_for(vuln_type: str) -> set[KillChainPhase]:
    """Which phases a single finding of this class lights up."""
    an = KillChainAnalyzer()
    an.ingest([{"vuln_type": vuln_type, "severity": "high", "target": "10.0.0.1"}])
    return {p for p, cov in an._coverage.items() if cov.findings}


# ── The previously-unmapped real scanner slugs now resolve correctly ─────────

def test_command_injection_slug_hits_exploitation_and_installation():
    phases = _phases_for("cmdi")
    assert KillChainPhase.EXPLOITATION in phases
    assert KillChainPhase.INSTALLATION in phases
    # It must NOT be a lone Recon default.
    assert phases != {KillChainPhase.RECONNAISSANCE}


def test_missing_authentication_is_exploitation_not_recon_default():
    phases = _phases_for("missing_authentication")
    assert KillChainPhase.EXPLOITATION in phases
    assert phases != {KillChainPhase.RECONNAISSANCE}


def test_database_exposed_is_actions_on_objectives():
    phases = _phases_for("database_exposed")
    assert KillChainPhase.ACTIONS_ON_OBJECTIVES in phases


def test_docker_api_exposed_lights_command_and_control():
    # "docker" key matches the docker_api_exposed / docker_socket_exposed slugs
    # by substring — the C2 phase an exposed control plane enables.
    phases = _phases_for("docker_api_exposed")
    assert KillChainPhase.COMMAND_AND_CONTROL in phases


def test_kubelet_exposed_lights_command_and_control():
    phases = _phases_for("kubelet_exposed")
    assert KillChainPhase.COMMAND_AND_CONTROL in phases


def test_unsupported_software_fills_weaponization():
    phases = _phases_for("unsupported_software")
    assert KillChainPhase.WEAPONIZATION in phases
    assert KillChainPhase.EXPLOITATION in phases


def test_telnet_cleartext_is_delivery_and_exploitation():
    phases = _phases_for("telnet")
    assert KillChainPhase.DELIVERY in phases
    assert KillChainPhase.EXPLOITATION in phases


def test_smtp_open_relay_is_delivery():
    phases = _phases_for("smtp_open_relay")
    assert KillChainPhase.DELIVERY in phases


def test_perimeter_defense_is_recon_context():
    phases = _phases_for("perimeter_defense")
    assert phases == {KillChainPhase.RECONNAISSANCE}


# ── Substring resolver still catches the many concrete detector variants ─────

def test_substring_resolver_maps_variant_slugs():
    # e.g. "blind_sql_injection", "ssl_weak_cipher", "missing_security_headers"
    assert KillChainPhase.EXPLOITATION in _phases_for("blind_sql_injection")
    assert KillChainPhase.DELIVERY in _phases_for("ssl_weak_cipher")
    assert KillChainPhase.DELIVERY in _phases_for("missing_security_headers")


# ── A realistic finding set lights every reachable phase, not just Recon ─────

def test_realistic_findings_cover_all_seven_phases():
    findings = [
        {"vuln_type": "open_port", "severity": "info", "target": "10.0.0.1"},         # Recon
        {"vuln_type": "unsupported_software", "severity": "high", "target": "10.0.0.1"},  # Weaponization
        {"vuln_type": "spf_missing", "severity": "medium", "target": "example.com"},   # Delivery
        {"vuln_type": "cmdi", "severity": "critical", "target": "10.0.0.1"},          # Exploitation + Installation
        {"vuln_type": "docker_api_exposed", "severity": "high", "target": "10.0.0.1"},  # C2
        {"vuln_type": "database_exposed", "severity": "high", "target": "10.0.0.1"},   # Actions on Objectives
    ]
    report = analyze_findings(findings)
    assert report["phases_with_findings"] == 7, report
    assert report["coverage_score"] == 100
    # Every phase individually non-empty.
    empty = [p["phase"] for p in report["phases"] if p["finding_count"] == 0]
    assert not empty, f"dark phases: {empty}"


def test_unmapped_slug_still_defaults_to_recon_not_crash():
    # An unknown vuln_type must degrade gracefully to Recon (never raise).
    phases = _phases_for("totally_unknown_zzz_class")
    assert phases == {KillChainPhase.RECONNAISSANCE}


# ── Backdoor / bindshell findings light Installation + Command-&-Control ──────

def _phases_for_finding(finding: dict) -> set[KillChainPhase]:
    an = KillChainAnalyzer()
    an.ingest([finding])
    return {p for p, cov in an._coverage.items() if cov.findings}


def test_backdoor_service_lights_installation_and_c2():
    """A vsftpd/UnrealIRCd command-execution backdoor classifies as a generic
    ``vulnerable_service`` (Weaponization + Exploitation); the backdoor language
    must ALSO light Installation + Command & Control — otherwise the C2 phase
    stays dark on Metasploitable, a host defined by its backdoors."""
    phases = _phases_for_finding({
        "vuln_type": "vulnerable_service", "severity": "critical",
        "target": "192.168.0.162",
        "title": "vsftpd 2.3.4 backdoor command execution", "cve": "CVE-2011-2523",
    })
    assert KillChainPhase.COMMAND_AND_CONTROL in phases
    assert KillChainPhase.INSTALLATION in phases
    assert KillChainPhase.EXPLOITATION in phases   # from the vuln_type mapping


def test_bindshell_lights_c2_even_with_unknown_type():
    phases = _phases_for_finding({
        "vuln_type": "unknown", "severity": "critical", "target": "192.168.0.162",
        "title": "Metasploitable root shell (bindshell on 1524)",
    })
    assert KillChainPhase.COMMAND_AND_CONTROL in phases
    assert KillChainPhase.INSTALLATION in phases


def test_ordinary_finding_does_not_gain_spurious_c2():
    """The backdoor augmentation must be evidence-gated: a plain header/cleartext
    finding must NOT be promoted to Command & Control."""
    for f in (
        {"vuln_type": "missing_security_headers", "severity": "low",
         "target": "10.0.0.1", "title": "Missing X-Frame-Options header"},
        {"vuln_type": "cleartext_service", "severity": "high",
         "target": "10.0.0.1", "title": "Cleartext Service Exposed: Telnet (port 23)"},
    ):
        assert KillChainPhase.COMMAND_AND_CONTROL not in _phases_for_finding(f), f

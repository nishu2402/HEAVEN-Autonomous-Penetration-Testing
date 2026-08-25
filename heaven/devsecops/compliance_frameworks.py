"""HEAVEN — finding-mapped compliance frameworks.

A pen test does not, by itself, prove compliance — but the findings it produces
map onto the *technical* controls of the major compliance regimes, and an
operator or auditor wants that mapping laid out honestly: which controls this
engagement produced evidence against, and which it did not observe.

This module is the single source of truth for that mapping. Each framework lists
its controls (a remote/technical assessment can only speak to the technical
ones; governance / physical / policy controls are listed so the matrix is honest,
and simply show "Not observed"). A finding is bucketed onto a control by matching
the finding's **semantic signals** — derived from its OWASP-2025 category, its
CWE, and vuln_type/title keywords — against the tags each control covers. Nothing
is fabricated: a control lights up only when a real finding carries a signal the
control genuinely concerns.

Frameworks:
  hipaa      — HIPAA Security Rule (45 CFR §164.308/.312 technical safeguards)
  uk_gdpr    — UK GDPR Article 32 (security of processing)
  eu_gdpr    — EU GDPR Article 32 (security of processing)
  pci_dss    — PCI DSS v4.0 (12 requirements)
  iso_27001  — ISO/IEC 27001:2022 Annex A (technological controls)
  soc2       — SOC 2 Trust Services Criteria (CC6/CC7/CC8)
  nist_csf   — NIST CSF 2.0 (functions / categories)

Kept dependency-free (stdlib only) so both the report generators and the API can
import it without a cycle. Reuses ``frameworks.owasp_2025_id`` for the OWASP
crosswalk so this module and the OWASP matrix speak one vocabulary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from heaven.devsecops import frameworks as _fw


# ── Semantic signal extraction (finding → tags) ──────────────────────────────
# A small, stable tag vocabulary shared by every framework so a finding buckets
# the same way everywhere. Each tag names a technical concern a control can be
# about.

# OWASP-2025 ordinal → tag.
_OWASP_TAG: dict[str, str] = {
    "A01": "access_control",
    "A02": "misconfig",
    "A03": "supply_chain",
    "A04": "crypto",
    "A05": "injection",
    "A06": "insecure_design",
    "A07": "auth",
    "A08": "integrity",
    "A09": "logging",
    "A10": "error_handling",
}

# Exact CWE → tag(s). Only weaknesses whose class is unambiguous are mapped, so a
# CWE never over-claims a control it doesn't concern.
_CWE_TAG: dict[str, tuple[str, ...]] = {
    "CWE-319": ("crypto", "transport_encryption"),
    "CWE-311": ("crypto", "transport_encryption"),
    "CWE-326": ("crypto",), "CWE-327": ("crypto",), "CWE-295": ("crypto", "transport_encryption"),
    "CWE-1104": ("supply_chain",), "CWE-937": ("supply_chain",), "CWE-1035": ("supply_chain",),
    "CWE-798": ("auth",), "CWE-259": ("auth",), "CWE-521": ("auth",), "CWE-522": ("auth",),
    "CWE-287": ("auth",), "CWE-384": ("auth",), "CWE-613": ("auth",),
    "CWE-306": ("access_control", "auth"), "CWE-862": ("access_control",),
    "CWE-863": ("access_control",), "CWE-352": ("access_control",), "CWE-639": ("access_control",),
    "CWE-22": ("access_control",), "CWE-918": ("access_control",), "CWE-284": ("access_control",),
    "CWE-79": ("injection",), "CWE-89": ("injection",), "CWE-78": ("injection",),
    "CWE-94": ("injection",), "CWE-90": ("injection",), "CWE-91": ("injection",),
    "CWE-643": ("injection",), "CWE-611": ("injection",), "CWE-74": ("injection",),
    "CWE-200": ("info_disclosure",), "CWE-209": ("info_disclosure", "error_handling"),
    "CWE-215": ("info_disclosure",), "CWE-548": ("info_disclosure", "misconfig"),
    "CWE-16": ("misconfig",), "CWE-942": ("misconfig", "access_control"),
    "CWE-1021": ("misconfig",), "CWE-693": ("misconfig",), "CWE-614": ("misconfig",),
    "CWE-1004": ("misconfig",), "CWE-16-config": ("misconfig",),
    "CWE-502": ("integrity",), "CWE-345": ("integrity",), "CWE-353": ("integrity",),
    "CWE-778": ("logging",), "CWE-223": ("logging",), "CWE-532": ("logging", "info_disclosure"),
    "CWE-400": ("exposure",), "CWE-770": ("exposure",), "CWE-406": ("exposure",),
    "CWE-755": ("error_handling",), "CWE-248": ("error_handling",),
}

# vuln_type / title keyword → tag(s). The fallback for findings with no CWE/OWASP.
_KEYWORD_TAG: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("tls", "ssl", "cipher", "certificate", "cleartext", "starttls",
      "plaintext", "unencrypted", "no_forward_secrecy", "hsts"),
     ("crypto", "transport_encryption")),
    (("sqli", "sql_injection", "xss", "command_injection", "rce", "code_injection",
      "ssti", "template_injection", "ldap_injection", "xpath", "nosql", "crlf",
      "injection"), ("injection",)),
    (("idor", "broken_access", "access_control", "path_traversal",
      "directory_traversal", "lfi", "rfi", "ssrf", "cors", "csrf", "bola",
      "unauthorized", "mass_assignment"), ("access_control",)),
    (("auth", "credential", "default_cred", "weak_password", "password", "session",
      "jwt", "lockout", "mfa", "login"), ("auth",)),
    (("misconfig", "security_header", "missing_header", "clickjack",
      "directory_listing", "cookie", "default_page", "exposed_admin",
      "dangerous_http_method", "trace"), ("misconfig",)),
    (("cve", "vulnerable", "outdated", "eol", "unsupported", "end_of_life",
      "dependency", "component", "nuclei"), ("supply_chain",)),
    (("telnet", "rdp", "exposed_database", "database_exposed", "snmp", "ftp",
      "ipmi", "smb", "port_open", "cleartext_service", "exposed_service",
      "exposed_rdp"), ("exposure",)),
    (("logging", "monitoring", "audit"), ("logging",)),
    (("verbose_error", "stack_trace", "error_message", "unhandled_exception",
      "verbose_errors"), ("error_handling", "info_disclosure")),
    (("deserial", "integrity", "unsigned", "tamper", "cache_poison",
      "request_smuggling"), ("integrity",)),
    (("info_disclosure", "information_disclosure", "version_disclosure", "banner",
      "disclosure"), ("info_disclosure",)),
    (("open_redirect", "insecure_design", "business_logic", "race_condition"),
     ("insecure_design",)),
)

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def finding_signals(finding: dict[str, Any]) -> set[str]:
    """The set of technical concern-tags a finding carries.

    Derived from (in order, all merged): its OWASP-2025 category, its CWE, and
    keyword matches on vuln_type/type/title. Empty when nothing recognisable —
    that finding then buckets to no control (honest, not forced).
    """
    tags: set[str] = set()

    cid = _fw.owasp_2025_id(str(finding.get("owasp") or finding.get("owasp_category") or ""))
    if cid:
        tag = _OWASP_TAG.get(cid.split(":")[0])
        if tag:
            tags.add(tag)

    m = _CWE_RE.search(str(finding.get("cwe") or ""))
    if m and m.group(0).upper() in _CWE_TAG:
        tags.update(_CWE_TAG[m.group(0).upper()])

    hay = (f"{finding.get('vuln_type', '')} {finding.get('type', '')} "
           f"{finding.get('title', '')}").lower()
    for keys, tgs in _KEYWORD_TAG:
        if any(k in hay for k in keys):
            tags.update(tgs)

    # Transport encryption is a specialisation of crypto — imply the parent so a
    # crypto control still lights for a cleartext finding.
    if "transport_encryption" in tags:
        tags.add("crypto")
    return tags


# ── Framework model ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ComplianceFramework:
    """One compliance regime: its controls + how findings map onto them."""
    id: str
    title: str
    subtitle: str
    reference: str
    controls: tuple[tuple[str, str], ...]          # (control_id, name), in order
    control_tags: dict[str, tuple[str, ...]]       # control_id → tags it covers

    def control_name(self, control_id: str) -> str:
        for cid, name in self.controls:
            if cid == control_id:
                return name
        return control_id


def controls_for_finding(fw: ComplianceFramework, finding: dict[str, Any]) -> list[str]:
    """The framework control ids one finding provides evidence against.

    A control matches when any tag it covers is in the finding's signals. Returns
    control ids in the framework's own display order.
    """
    sigs = finding_signals(finding)
    if not sigs:
        return []
    out: list[str] = []
    for cid, _name in fw.controls:
        covered = fw.control_tags.get(cid, ())
        if any(t in sigs for t in covered):
            out.append(cid)
    return out


def covered_controls(fw: ComplianceFramework,
                     findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """``{control_id: [findings mapped to it]}`` for every control (may be empty)."""
    buckets: dict[str, list[dict[str, Any]]] = {cid: [] for cid, _ in fw.controls}
    for f in findings:
        for cid in controls_for_finding(fw, f):
            buckets[cid].append(f)
    return buckets


# ── The registry ─────────────────────────────────────────────────────────────


def _gdpr(fw_id: str, title: str, reference: str) -> ComplianceFramework:
    """UK GDPR and EU GDPR share Article 32's technical sub-requirements."""
    controls = (
        ("Art.32(1)(a)", "Pseudonymisation & encryption of personal data"),
        ("Art.32(1)(b)-C", "Ongoing confidentiality of processing systems"),
        ("Art.32(1)(b)-I", "Ongoing integrity of processing systems"),
        ("Art.32(1)(b)-A", "Ongoing availability & resilience of systems"),
        ("Art.32(1)(d)", "Process for regularly testing & evaluating security"),
        ("Art.25", "Data protection by design & by default"),
        ("Art.5(1)(f)", "Integrity & confidentiality principle"),
    )
    control_tags = {
        "Art.32(1)(a)": ("crypto", "transport_encryption"),
        "Art.32(1)(b)-C": ("access_control", "auth", "exposure", "info_disclosure"),
        "Art.32(1)(b)-I": ("integrity", "injection"),
        "Art.32(1)(b)-A": ("exposure", "supply_chain"),
        "Art.32(1)(d)": ("misconfig", "supply_chain", "insecure_design"),
        "Art.25": ("insecure_design", "misconfig"),
        "Art.5(1)(f)": ("access_control", "crypto", "info_disclosure"),
    }
    return ComplianceFramework(
        id=fw_id, title=title, subtitle="Article 32: Security of processing",
        reference=reference, controls=controls, control_tags=control_tags)


_HIPAA = ComplianceFramework(
    id="hipaa", title="HIPAA Security Rule",
    subtitle="45 CFR §164: technical and administrative safeguards",
    reference="https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
    controls=(
        ("§164.308(a)(1)", "Security Management Process (risk analysis & management)"),
        ("§164.308(a)(5)", "Security Awareness & Training (malware / log-in / passwords)"),
        ("§164.312(a)(1)", "Access Control"),
        ("§164.312(b)", "Audit Controls"),
        ("§164.312(c)(1)", "Integrity"),
        ("§164.312(d)", "Person or Entity Authentication"),
        ("§164.312(e)(1)", "Transmission Security"),
    ),
    control_tags={
        "§164.308(a)(1)": ("supply_chain", "injection", "misconfig", "insecure_design",
                           "info_disclosure"),
        "§164.308(a)(5)": ("auth",),
        "§164.312(a)(1)": ("access_control", "exposure"),
        "§164.312(b)": ("logging",),
        "§164.312(c)(1)": ("integrity",),
        "§164.312(d)": ("auth",),
        "§164.312(e)(1)": ("transport_encryption", "crypto"),
    },
)

_PCI = ComplianceFramework(
    id="pci_dss", title="PCI DSS v4.0.1",
    subtitle="Payment Card Industry Data Security Standard: 12 requirements",
    reference="https://www.pcisecuritystandards.org/",
    controls=(
        ("Req 1", "Install & maintain network security controls"),
        ("Req 2", "Apply secure configurations to all components"),
        ("Req 3", "Protect stored account data"),
        ("Req 4", "Protect cardholder data with strong cryptography in transit"),
        ("Req 5", "Protect systems & networks from malicious software"),
        ("Req 6", "Develop & maintain secure systems & software"),
        ("Req 7", "Restrict access by business need to know"),
        ("Req 8", "Identify users & authenticate access"),
        ("Req 9", "Restrict physical access to cardholder data"),
        ("Req 10", "Log & monitor all access"),
        ("Req 11", "Test security of systems & networks regularly"),
        ("Req 12", "Support information security with policies & programs"),
    ),
    control_tags={
        "Req 1": ("exposure",),
        "Req 2": ("misconfig", "auth"),
        "Req 3": ("crypto",),
        "Req 4": ("transport_encryption", "crypto"),
        "Req 6": ("supply_chain", "injection", "insecure_design"),
        "Req 7": ("access_control",),
        "Req 8": ("auth",),
        "Req 10": ("logging",),
        "Req 11": ("misconfig", "supply_chain"),
        # Req 5 (anti-malware), Req 9 (physical), Req 12 (policy) can't be
        # evidenced by an external technical scan — listed, naturally unobserved.
    },
)

_ISO = ComplianceFramework(
    id="iso_27001", title="ISO/IEC 27001:2022",
    subtitle="Annex A: technological controls (Amd 1:2024)",
    reference="https://www.iso.org/standard/27001",
    controls=(
        ("A.5.15", "Access control"),
        ("A.8.3", "Information access restriction"),
        ("A.8.5", "Secure authentication"),
        ("A.8.8", "Management of technical vulnerabilities"),
        ("A.8.9", "Configuration management"),
        ("A.8.15", "Logging"),
        ("A.8.16", "Monitoring activities"),
        ("A.8.20", "Networks security"),
        ("A.8.24", "Use of cryptography"),
        ("A.8.26", "Application security requirements"),
    ),
    control_tags={
        "A.5.15": ("access_control",),
        "A.8.3": ("access_control", "info_disclosure"),
        "A.8.5": ("auth",),
        "A.8.8": ("supply_chain", "injection", "misconfig"),
        "A.8.9": ("misconfig",),
        "A.8.15": ("logging",),
        "A.8.16": ("logging",),
        "A.8.20": ("exposure",),
        "A.8.24": ("crypto", "transport_encryption"),
        "A.8.26": ("injection", "insecure_design", "integrity"),
    },
)

_SOC2 = ComplianceFramework(
    id="soc2", title="SOC 2",
    subtitle="Trust Services Criteria (2017, rev. 2022)",
    reference="https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
    controls=(
        ("CC6.1", "Logical access security controls"),
        ("CC6.6", "Boundary protection from external threats"),
        ("CC6.7", "Restricted transmission & movement of data"),
        ("CC6.8", "Prevention/detection of unauthorized software"),
        ("CC7.1", "Detection of configuration & vulnerability changes"),
        ("CC7.2", "Monitoring for anomalies & security events"),
        ("CC8.1", "Change management"),
    ),
    control_tags={
        "CC6.1": ("access_control", "auth"),
        "CC6.6": ("exposure", "transport_encryption"),
        "CC6.7": ("transport_encryption", "crypto"),
        "CC6.8": ("supply_chain",),
        "CC7.1": ("misconfig", "supply_chain"),
        "CC7.2": ("logging", "error_handling"),
        "CC8.1": ("integrity", "insecure_design"),
    },
)

_CSF = ComplianceFramework(
    id="nist_csf", title="NIST CSF 2.0",
    subtitle="Cybersecurity Framework: functions and categories",
    reference="https://www.nist.gov/cyberframework",
    controls=(
        ("ID.RA", "Risk Assessment (vulnerabilities identified)"),
        ("PR.AA", "Identity Management, Authentication & Access Control"),
        ("PR.DS", "Data Security"),
        ("PR.PS", "Platform Security (configuration & patching)"),
        ("PR.IR", "Technology Infrastructure Resilience"),
        ("DE.CM", "Continuous Monitoring"),
        ("DE.AE", "Adverse Event Analysis"),
    ),
    control_tags={
        "ID.RA": ("supply_chain", "injection", "misconfig", "insecure_design"),
        "PR.AA": ("access_control", "auth"),
        "PR.DS": ("crypto", "transport_encryption"),
        "PR.PS": ("misconfig", "supply_chain"),
        "PR.IR": ("exposure",),
        "DE.CM": ("logging",),
        "DE.AE": ("logging", "error_handling"),
    },
)


_CYBER_ESSENTIALS = ComplianceFramework(
    id="cyber_essentials", title="Cyber Essentials",
    subtitle="NCSC: five technical controls",
    reference="https://www.ncsc.gov.uk/cyberessentials/overview",
    controls=(
        ("CE-1", "Firewalls & internet gateways"),
        ("CE-2", "Secure configuration"),
        ("CE-3", "Security update management"),
        ("CE-4", "User access control"),
        ("CE-5", "Malware protection"),
    ),
    control_tags={
        "CE-1": ("exposure",),
        "CE-2": ("misconfig",),
        "CE-3": ("supply_chain",),
        "CE-4": ("access_control", "auth"),
        # CE-5 (anti-malware) can't be evidenced by an external technical scan —
        # listed, naturally unobserved.
    },
)

_CYBER_ESSENTIALS_PLUS = ComplianceFramework(
    id="cyber_essentials_plus", title="Cyber Essentials Plus",
    subtitle="NCSC: five controls, hands-on audit",
    reference="https://www.ncsc.gov.uk/cyberessentials/overview",
    controls=(
        ("CE+ 1", "Firewalls & internet gateways"),
        ("CE+ 2", "Secure configuration"),
        ("CE+ 3", "Security update management"),
        ("CE+ 4", "User access control"),
        ("CE+ 5", "Malware protection"),
    ),
    control_tags={
        "CE+ 1": ("exposure",),
        "CE+ 2": ("misconfig",),
        "CE+ 3": ("supply_chain",),
        "CE+ 4": ("access_control", "auth"),
    },
)

_CIS = ComplianceFramework(
    id="cis_controls_v8", title="CIS Controls v8.1",
    subtitle="Center for Internet Security: 18 controls",
    reference="https://www.cisecurity.org/controls",
    controls=(
        ("CIS 1", "Inventory & control of enterprise assets"),
        ("CIS 2", "Inventory & control of software assets"),
        ("CIS 3", "Data protection"),
        ("CIS 4", "Secure configuration of assets & software"),
        ("CIS 5", "Account management"),
        ("CIS 6", "Access control management"),
        ("CIS 7", "Continuous vulnerability management"),
        ("CIS 8", "Audit log management"),
        ("CIS 9", "Email & web browser protections"),
        ("CIS 10", "Malware defenses"),
        ("CIS 11", "Data recovery"),
        ("CIS 12", "Network infrastructure management"),
        ("CIS 13", "Network monitoring & defense"),
        ("CIS 14", "Security awareness & skills training"),
        ("CIS 15", "Service provider management"),
        ("CIS 16", "Application software security"),
        ("CIS 17", "Incident response management"),
        ("CIS 18", "Penetration testing"),
    ),
    control_tags={
        "CIS 1": ("exposure",),
        "CIS 2": ("supply_chain",),
        "CIS 3": ("crypto", "transport_encryption", "info_disclosure"),
        "CIS 4": ("misconfig",),
        "CIS 5": ("auth",),
        "CIS 6": ("access_control",),
        "CIS 7": ("supply_chain", "misconfig"),
        "CIS 8": ("logging",),
        "CIS 9": ("misconfig",),
        "CIS 12": ("exposure",),
        "CIS 13": ("logging",),
        "CIS 16": ("injection", "insecure_design", "integrity"),
        # CIS 10/11/14/15/17/18 are governance / process controls an external
        # technical scan cannot evidence — listed, naturally unobserved.
    },
)


FRAMEWORKS: dict[str, ComplianceFramework] = {
    "hipaa": _HIPAA,
    "uk_gdpr": _gdpr("uk_gdpr", "UK GDPR",
                     "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/"),
    "eu_gdpr": _gdpr("eu_gdpr", "EU GDPR", "https://gdpr-info.eu/art-32-gdpr/"),
    "pci_dss": _PCI,
    "iso_27001": _ISO,
    "soc2": _SOC2,
    "nist_csf": _CSF,
    "cyber_essentials": _CYBER_ESSENTIALS,
    "cyber_essentials_plus": _CYBER_ESSENTIALS_PLUS,
    "cis_controls_v8": _CIS,
}

# Display order for the registry listing (named-first, then commercial regimes).
_ORDER = ("hipaa", "uk_gdpr", "eu_gdpr", "pci_dss", "iso_27001", "soc2",
          "nist_csf", "cyber_essentials", "cyber_essentials_plus", "cis_controls_v8")


def get_framework(fw_id: str) -> ComplianceFramework | None:
    """The framework for an id (case-insensitive), or ``None`` if unknown."""
    return FRAMEWORKS.get((fw_id or "").strip().lower())


def is_compliance_framework(fw_id: str) -> bool:
    return (fw_id or "").strip().lower() in FRAMEWORKS


def list_frameworks() -> list[dict[str, Any]]:
    """Registry summary for the UI selector (id/title/subtitle/reference/count)."""
    out = []
    for fid in _ORDER:
        fw = FRAMEWORKS[fid]
        out.append({
            "id": fw.id, "title": fw.title, "subtitle": fw.subtitle,
            "reference": fw.reference, "controls_total": len(fw.controls),
        })
    return out


# ── Live coverage overlay + downloadable deliverables ────────────────────────
# The dedicated Compliance page (the control-coverage analogue of the Methodology
# page) and its HTML / Markdown / JSON / PDF downloads all build on ONE coverage
# model, so the interactive view and every export agree by construction.

from html import escape as _esc  # noqa: E402

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
             "informational": 4}


def _finding_ref(f: dict[str, Any]) -> dict[str, str]:
    """Compact, serialisable identity for one finding (for the control overlay)."""
    return {
        "id": str(f.get("id") or ""),
        "title": str(f.get("title") or f.get("vuln_type") or f.get("type") or "Finding"),
        "severity": str(f.get("severity") or "info").lower(),
        "target": str(f.get("target") or f.get("host") or f.get("url") or ""),
        "vuln_type": str(f.get("vuln_type") or f.get("type") or ""),
    }


def coverage_for(fw_id: str, findings: list[dict[str, Any]],
                 eng_name: str = "") -> dict[str, Any] | None:
    """Live control-coverage model for one framework, or ``None`` if unknown.

    Every control lists the DISTINCT findings that provide evidence of a gap
    against it (deduped by identity, worst-severity first). This is an honest
    control-coverage view — a control is "Findings present" only when a real
    finding carries a signal it concerns — **not** an attestation of compliance.
    """
    fw = get_framework(fw_id)
    if fw is None:
        return None
    buckets = covered_controls(fw, findings)
    controls_out: list[dict[str, Any]] = []
    covered = 0
    distinct_ids: set[str] = set()
    for cid, cname in fw.controls:
        hits = buckets.get(cid, [])
        # Dedup by identity, worst-severity first.
        seen: set[str] = set()
        refs: list[dict[str, str]] = []
        for h in hits:
            ref = _finding_ref(h)
            key = ref["id"] or f"{ref['vuln_type']}|{ref['target']}|{ref['title']}"
            if key in seen:
                continue
            seen.add(key)
            distinct_ids.add(key)
            refs.append(ref)
        refs.sort(key=lambda r: (_SEV_RANK.get(r.get("severity", "info"), 4),
                                 r.get("title", "")))
        if refs:
            covered += 1
        controls_out.append({
            "id": cid, "name": cname,
            "status": "Findings present" if refs else "Not observed",
            "count": len(refs), "findings": refs,
            "tags": list(fw.control_tags.get(cid, ())),
        })
    return {
        "id": fw.id, "title": fw.title, "subtitle": fw.subtitle,
        "reference": fw.reference, "engagement": eng_name,
        "controls_total": len(fw.controls), "controls_covered": covered,
        "findings_total": len(distinct_ids), "controls": controls_out,
    }


def _now_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")


def _coverage_intro(cov: dict[str, Any]) -> str:
    return (f"{cov['controls_covered']} of {cov['controls_total']} controls have at "
            f"least one finding providing evidence of a gap. This is a control-"
            f"coverage view, NOT an attestation of compliance.")


def render_coverage_html(cov: dict[str, Any]) -> str:
    """One framework's live control-coverage matrix as printable HTML."""
    eng = cov.get("engagement", "")

    def _refs_html(c: dict[str, Any]) -> str:
        refs = c.get("findings") or []
        if not refs:
            return "<span class='muted'>—</span>"
        return "<ul class='refs'>" + "".join(
            f"<li><span class='sev sev-{_esc(r.get('severity', 'info'))}'>"
            f"{_esc((r.get('severity') or 'info').upper())}</span> "
            f"{_esc(r.get('title') or r.get('vuln_type') or 'Finding')}"
            f"{' · <code>' + _esc(r['target']) + '</code>' if r.get('target') else ''}</li>"
            for r in refs) + "</ul>"

    body = ""
    for c in cov.get("controls", []):
        hit = c.get("count", 0) > 0
        body += (
            f"<tr class='{'hit' if hit else ''}'>"
            f"<td class='mono'>{_esc(c.get('id', ''))}</td>"
            f"<td>{_esc(c.get('name', ''))}</td>"
            f"<td>{_esc(c.get('status', ''))}</td>"
            f"<td class='num'>{c.get('count', 0)}</td>"
            f"<td>{_refs_html(c)}</td></tr>")

    title = cov.get("title", "")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} — Compliance coverage · {_esc(eng)}</title>
<style>
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
   color:#1a1f29;background:#f4f6f9;margin:0;line-height:1.55;font-size:14px;}}
 .page{{background:#fff;max-width:900px;margin:24px auto;padding:40px 48px;box-shadow:0 1px 4px rgba(0,0,0,.08);}}
 h1{{font-size:26px;margin:0 0 4px;}} h2{{font-size:18px;border-bottom:2px solid #4f46e5;padding-bottom:6px;}}
 table{{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0;}}
 th{{background:#f0f3f8;text-align:left;padding:7px 9px;border:1px solid #e3e7ee;color:#33405a;}}
 td{{padding:7px 9px;border:1px solid #e3e7ee;vertical-align:top;overflow-wrap:anywhere;}}
 td.num{{text-align:center;}} tr.hit{{background:#eef4ff;}}
 .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;}} .muted{{color:#5b6472;}}
 .kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0;}}
 .kpi{{flex:1;min-width:120px;border:1px solid #e3e7ee;border-radius:10px;padding:12px;text-align:center;background:#fcfdff;}}
 .kpi .n{{font-size:26px;font-weight:800;}} .kpi .l{{font-size:11px;color:#5b6472;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;}}
 .refs{{margin:0;padding-left:16px;}} .refs li{{margin:2px 0;}}
 .sev{{display:inline-block;padding:0 6px;border-radius:4px;font-size:10px;font-weight:700;color:#fff;}}
 .sev-critical{{background:#b00020;}} .sev-high{{background:#e2571e;}} .sev-medium{{background:#b8860b;}}
 .sev-low{{background:#2b6cb0;}} .sev-info,.sev-informational{{background:#5b6472;}}
 .toolbar{{position:fixed;top:16px;right:16px;}} .btn{{background:#4f46e5;color:#fff;border:0;border-radius:8px;padding:9px 15px;font-weight:600;cursor:pointer;}}
 .disclaimer{{border-left:3px solid #b8860b;background:#fffbf0;padding:10px 14px;margin:14px 0;font-size:12.5px;}}
 @media print{{body{{background:#fff;}} .page{{box-shadow:none;margin:0;max-width:none;padding:0;}} .no-print{{display:none;}} tr{{page-break-inside:avoid;}}}}
</style></head><body>
 <div class="toolbar no-print"><button class="btn" onclick="window.print()">🖨 Print / Save as PDF</button></div>
 <div class="page">
  <h1>{_esc(title)} — Compliance coverage</h1>
  <p class="muted">{_esc(cov.get('subtitle', ''))} &nbsp;·&nbsp; Engagement: <strong>{_esc(eng or '—')}</strong>
     &nbsp;·&nbsp; Generated {_esc(_now_utc())}</p>
  <div class="disclaimer"><strong>Coverage view, not an attestation.</strong>
   {_esc(_coverage_intro(cov))}</div>
  <div class="kpis">
   <div class="kpi"><div class="n">{cov.get('controls_total', 0)}</div><div class="l">Controls</div></div>
   <div class="kpi"><div class="n">{cov.get('controls_covered', 0)}</div><div class="l">With findings</div></div>
   <div class="kpi"><div class="n">{cov.get('findings_total', 0)}</div><div class="l">Findings mapped</div></div>
  </div>
  <table><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Count</th>
   <th>Findings providing evidence</th></tr>{body}</table>
  <p class="muted" style="margin-top:24px;font-size:12px">Generated by HEAVEN
   Autonomous Penetration-Testing Platform. A control is marked "Findings present"
   only when a real finding carries a signal it concerns.</p>
 </div>
</body></html>"""


def render_coverage_markdown(cov: dict[str, Any]) -> str:
    lines = [
        f"# {cov.get('title', '')}: Compliance coverage",
        "",
        f"*{cov.get('subtitle', '')}* · Engagement: **{cov.get('engagement') or '—'}** "
        f"· Generated {_now_utc()}",
        "",
        f"> **Coverage view, not an attestation of compliance.** {_coverage_intro(cov)}",
        "",
        f"- Controls: **{cov.get('controls_total', 0)}**",
        f"- Controls with findings: **{cov.get('controls_covered', 0)}**",
        f"- Distinct findings mapped: **{cov.get('findings_total', 0)}**",
        "",
        "| Control | Requirement | Status | Count | Findings providing evidence |",
        "|---|---|---|---|---|",
    ]
    for c in cov.get("controls", []):
        refs = c.get("findings") or []
        ref_txt = "; ".join(
            f"{(r.get('severity') or 'info').upper()} {r.get('title') or r.get('vuln_type')}"
            f"{' (' + r['target'] + ')' if r.get('target') else ''}"
            for r in refs) or "—"
        name = str(c.get("name", "")).replace("|", "\\|")
        ref_txt = ref_txt.replace("|", "\\|")
        lines.append(f"| {c.get('id', '')} | {name} | {c.get('status', '')} "
                     f"| {c.get('count', 0)} | {ref_txt} |")
    lines.append("")
    lines.append("_Generated by HEAVEN Autonomous Penetration-Testing Platform._")
    return "\n".join(lines)


def render_coverage_pdf(cov: dict[str, Any]) -> bytes:
    """One framework's live control-coverage matrix as a PDF (reportlab)."""
    from heaven.devsecops.coverage_pdf import MatrixSection, render_matrix_pdf

    def _refs_text(c: dict[str, Any]) -> str:
        refs = c.get("findings") or []
        if not refs:
            return "—"
        return "; ".join(
            f"{(r.get('severity') or 'info').upper()} "
            f"{r.get('title') or r.get('vuln_type') or 'Finding'}"
            f"{' (' + r['target'] + ')' if r.get('target') else ''}"
            for r in refs)

    rows = []
    highlight = []
    for c in cov.get("controls", []):
        rows.append([c.get("id", ""), c.get("name", ""), c.get("status", ""),
                     str(c.get("count", 0)), _refs_text(c)])
        highlight.append(c.get("count", 0) > 0)
    section = MatrixSection(
        heading="Control coverage",
        columns=["Control", "Requirement", "Status", "Count",
                 "Findings providing evidence"],
        rows=rows, highlight=highlight,
        col_ratios=[0.12, 0.28, 0.14, 0.08, 0.38])

    return render_matrix_pdf(
        title=f"{cov.get('title', '')}: Compliance coverage",
        subtitle=cov.get("subtitle", ""),
        meta_lines=[f"Engagement: {cov.get('engagement') or '—'}  ·  "
                    f"Generated {_now_utc()}"],
        intro="Coverage view, not an attestation of compliance. "
              + _coverage_intro(cov),
        kpis=[(cov.get("controls_total", 0), "Controls"),
              (cov.get("controls_covered", 0), "With findings"),
              (cov.get("findings_total", 0), "Findings mapped")],
        sections=[section],
        footer="Generated by HEAVEN Autonomous Penetration-Testing Platform. A "
               "control is marked 'Findings present' only when a real finding "
               "carries a signal it concerns.")

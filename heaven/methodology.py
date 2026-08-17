"""HEAVEN — methodology coverage (single source of truth for CLI / API / UI).

The docs under ``docs/methodology/*.md`` map every control or test of an
industry standard to the HEAVEN detector module that provides evidence for it.
Two families are covered by the exact same machinery:

  • **Pen-test methodologies** — OWASP WSTG, NIST SP 800-115, PTES — mapped
    per test ID.
  • **Compliance / control frameworks** — Cyber Essentials (+ Plus),
    ISO/IEC 27001:2022, PCI DSS v4.0.1, CIS Controls v8.1, NIST CSF 2.0,
    SOC 2 — mapped per control, with governance/physical controls a remote
    scanner cannot evidence honestly marked ``(organizational)`` / ``(manual)``.

Historically the web UI just dumped that Markdown, so the page was static — the
same reference table regardless of what you actually scanned.

This module turns those docs into *live* data:

1. :func:`parse_standard` reads a doc into a structured coverage matrix
   (categories → rows, each row classified automated / partial / manual). The
   summary counts are **computed from the rows**, so they can never drift from
   the detailed mapping the way a hand-written summary table can.

2. :func:`overlay_findings` joins the ACTIVE ENGAGEMENT's real findings onto
   that matrix. Every doc row names the detector that covers it
   (``heaven.vulnscan.injection_scanner`` …); we map each finding's
   ``vuln_type`` to the same detector token, so a row lights up **only** when
   the detector it lists actually produced a finding in this engagement. No
   fabricated coverage — a row is "exercised" iff its own scanner fired.

CLI (``heaven methodology coverage``), the API (``/api/methodology``) and the
React page all consume this one module, so the three stay in sync by
construction.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Optional
import logging
logger = logging.getLogger(__name__)


DOCS_DIR = Path(__file__).resolve().parent.parent / "docs" / "methodology"

# Human-facing metadata per doc stem (title + short subtitle for the UI selector).
STANDARD_META: dict[str, dict[str, str]] = {
    # Pen-test methodologies (per-test-ID coverage).
    "owasp_testing_guide": {"title": "OWASP Testing Guide", "sub": "WSTG v4.2"},
    "nist_800_115": {"title": "NIST SP 800-115", "sub": "Technical assessment"},
    "ptes": {"title": "PTES", "sub": "Execution standard"},
    # Compliance / control frameworks (per-control coverage — a control lights
    # up when the HEAVEN detector that provides external evidence for it fired).
    "cyber_essentials": {"title": "Cyber Essentials", "sub": "NCSC v3.3 · 5 controls"},
    "cyber_essentials_plus": {"title": "Cyber Essentials Plus", "sub": "NCSC v3.3 · hands-on audit"},
    "iso_27001": {"title": "ISO/IEC 27001:2022", "sub": "Annex A · Amd 1:2024"},
    "pci_dss": {"title": "PCI DSS v4.0.1", "sub": "12 requirements"},
    "cis_controls_v8": {"title": "CIS Controls v8.1", "sub": "18 safeguards"},
    "nist_csf": {"title": "NIST CSF 2.0", "sub": "6 functions"},
    "soc2": {"title": "SOC 2", "sub": "TSC 2017 (rev. 2022)"},
}

# ── Finding → detector module token ──────────────────────────────────────────
# Each finding vuln_type maps to the detector module(s) that produce it. The
# tokens are the module *basenames* exactly as they appear inside the doc
# coverage cells (`heaven.vulnscan.injection_scanner`, `.../ssl_scanner.py`),
# so a plain substring test lights the right rows. Aliases (sqli, cmdi …) are
# included so display-form vuln types resolve too. Unmapped types simply don't
# light a row — that is honest, not a bug.
VULN_MODULE: dict[str, tuple[str, ...]] = {
    # Injection family
    "sql_injection": ("injection_scanner",),
    "sqli": ("injection_scanner",),
    "xss": ("injection_scanner",),
    "xss_stored": ("injection_scanner",),
    "html_injection": ("injection_scanner",),
    "file_inclusion": ("injection_scanner", "safe_validator"),
    "path_traversal": ("injection_scanner", "safe_validator"),
    "verbose_errors": ("injection_scanner", "web_crawler"),
    # Advanced / server-side
    "rce": ("advanced_attacks",),
    "command_injection": ("advanced_attacks",),
    "cmdi": ("advanced_attacks",),
    "os_command_injection": ("advanced_attacks",),
    "code_injection": ("advanced_attacks",),
    "xxe": ("advanced_attacks",),
    "ssti": ("advanced_attacks",),
    "cors_misconfig": ("advanced_attacks",),
    "open_redirect": ("advanced_attacks",),
    "crlf_injection": ("advanced_attacks",),
    "request_smuggling": ("advanced_attacks",),
    "host_header_injection": ("advanced_attacks",),
    "jwt_weak_secret": ("advanced_attacks",),
    "jwt_none_algorithm": ("advanced_attacks",),
    # SSRF
    "ssrf": ("safe_validator",),
    "ssrf_cloud_metadata": ("safe_validator",),
    # AuthZ / AuthN
    "idor": ("idor_scanner",),
    "auth_bypass": ("auth_scanner",),
    "default_credentials": ("auth_scanner",),
    # Transport / crypto
    "weak_tls": ("ssl_scanner",),
    "certificate_issue": ("ssl_scanner",),
    "no_forward_secrecy": ("ssl_scanner",),
    "hsts_missing": ("ssl_scanner",),
    "smtp_no_starttls": ("ssl_scanner",),
    # Headers / cookies / config (parsed by the crawler)
    "missing_security_headers": ("web_crawler",),
    "security_misconfig": ("web_crawler",),
    "csp_missing": ("web_crawler",),
    "csp_unsafe_inline": ("web_crawler",),
    "x_content_type_missing": ("web_crawler",),
    "referrer_policy_missing": ("web_crawler",),
    "permissions_policy_missing": ("web_crawler",),
    "cookie_no_httponly": ("web_crawler",),
    "insecure_cookie": ("web_crawler",),
    "clickjacking": ("web_crawler",),
    "dangerous_http_method": ("web_crawler",),
    "info_disclosure": ("web_crawler",),
    "version_disclosure": ("adaptive_intel", "web_crawler"),
    # Content discovery
    "directory_listing": ("dir_fuzzer",),
    "sensitive_file_exposure": ("dir_fuzzer",),
    "secret_exposure": ("dir_fuzzer",),
    # API
    "graphql_introspection": ("api_scanner",),
    "graphql_dos": ("api_scanner",),
    "no_rate_limit": ("api_scanner",),
    # Infra / cloud / container
    "docker_socket_exposed": ("container_scanner",),
    "exposed_storage_bucket": ("cloud_enum",),
    "exposed_database": ("network_scanner",),
    "exposed_rdp": ("network_scanner",),
    # DNS / email
    "dns_info": ("dns_recon",),
    "spf_missing": ("dns_recon",),
    "dmarc_missing": ("dns_recon",),
    "dkim_missing": ("dns_recon",),
    "dnssec_missing": ("dns_recon",),
    "subdomain_takeover": ("dns_recon",),
    # Anomaly
    "format_string": ("anomaly_probe",),
    # ── Vulnerability & patch management (CVE / EOL / dependencies) ───────────
    # These light the "security update management" / "vulnerability management"
    # controls the compliance frameworks (Cyber Essentials, ISO 27001 A.8.8,
    # PCI 6/11, CIS 7) hinge on. Every slug here is emitted by a real scanner.
    "vulnerable_service": ("cve_mapper",),
    "potential_vulnerable_service": ("cve_mapper",),
    "nuclei": ("cve_mapper",),
    "unsupported_software": ("eol_scanner",),
    "vulnerable_dependency": ("sca_scanner",),
    # ── Network boundary / exposed services (firewalls & segmentation) ───────
    "telnet": ("network_exposure",),
    "cleartext_service": ("network_exposure",),
    "database_exposed": ("network_exposure",),
    "ipmi_exposed": ("network_exposure",),
    "snmp_exposed": ("network_exposure",),
    "snmp_default_community": ("network_exposure",),
    "snmp_amplification": ("network_exposure",),
    "ssh_hardening": ("network_exposure",),
    # ── Content & config exposure (secure configuration) ─────────────────────
    "sensitive_file": ("dir_fuzzer", "exposure_scanner"),
    "exposed_secret": ("dir_fuzzer", "exposure_scanner"),
    "security_headers": ("web_crawler",),
    # ── Broken access control (authorization) ────────────────────────────────
    "broken_access_control": ("access_control", "idor_scanner"),
    "bola": ("access_control", "api_scanner"),
    "mass_assignment": ("access_control", "api_scanner"),
    "race_condition": ("access_control",),
    # ── Injection aliases the scanners actually emit ─────────────────────────
    "sqli_confirmed": ("injection_scanner",),
    "lfi": ("injection_scanner", "safe_validator"),
    "rfi": ("injection_scanner", "safe_validator"),
    "cors": ("advanced_attacks",),
    # ── API security ─────────────────────────────────────────────────────────
    "api_actuator_exposed": ("api_scanner",),
    "api_broken_auth": ("api_scanner",),
    "api_key_leakage": ("api_scanner",),
    "graphql_batching": ("api_scanner",),
    "graphql_complexity": ("api_scanner",),
    # ── CMS ──────────────────────────────────────────────────────────────────
    "wordpress_version_disclosure": ("cms_scanner",),
    "wordpress_user_enumeration": ("cms_scanner",),
    # ── Cloud / container / k8s (secure configuration of cloud estate) ───────
    "docker_api_exposed": ("container_scanner",),
    "cadvisor_exposed": ("container_scanner",),
    "etcd_exposed": ("container_scanner",),
    "kubelet_exposed": ("container_scanner",),
    "registry_exposed": ("container_scanner",),
    "privileged_container": ("container_scanner",),
    "dangerous_mount": ("container_scanner",),
    "k8s_secrets_exposed": ("container_scanner",),
    "azure_ad_tenant_exposed": ("azure_tenant",),
    "adfs_idp_signon_enabled": ("azure_tenant",),
    "federation_sts_exposed": ("azure_tenant",),
    # ── Email / DNS hardening ────────────────────────────────────────────────
    "smtp_open_relay": ("dns_recon",),
    "mta_sts_missing": ("dns_recon",),
    "spf_analysis": ("dns_recon",),
    "dmarc_analysis": ("dns_recon",),
    "mx_enumeration": ("dns_recon",),
    # ── Wireless management-plane exposure ───────────────────────────────────
    "wireless_mgmt_exposed": ("wireless_posture",),
    "wireless_mgmt_unauthenticated": ("wireless_posture",),
}

# Open-ended finding families whose exact slug is generated at runtime (e.g.
# SAST emits ``sast_<rule>``), so a fixed dict can't enumerate them. Matched by
# prefix only after an exact ``VULN_MODULE`` lookup misses — each maps to a
# single real detector, so there is no over-claim.
_PREFIX_MODULE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sast_", ("sast_runner",)),
    ("wordpress_", ("cms_scanner",)),
    ("graphql_", ("api_scanner",)),
    ("api_", ("api_scanner",)),
    ("snmp", ("network_exposure",)),
    ("ics_", ("iot_scanner",)),
    ("iot_", ("iot_scanner",)),
)


# ── Real emitters discovered by reading the detector source ──────────────────
# The historical VULN_MODULE above under-mapped HEAVEN's real coverage: several
# scanners that run on every web scan (``web_fuzzer``, ``misconfig_scanner``,
# ``auth_scanner``, ``anomaly_probe``) emit confirmation-based findings whose
# vuln_type slugs were never mapped to a module token — so their findings lit no
# methodology row. Every slug below was verified against the ``_finding(...)`` /
# ``category=`` call that actually produces it; each maps ONLY to the module that
# genuinely emits it, so nothing is over-claimed. Merged as a UNION into
# VULN_MODULE (extending, never replacing, the historical tuples).
_ADDITIONAL_EMITTERS: dict[str, tuple[str, ...]] = {
    # heaven.vulnscan.web_fuzzer — HTTP methods, verb tampering, host header,
    # 403/auth bypass, cache poisoning, smuggling, HPP, deserialization, etc.
    "xst_trace_enabled": ("web_fuzzer",),
    "http_trace_enabled": ("web_fuzzer",),
    "dangerous_http_method": ("web_fuzzer",),
    "dangerous_methods_allowed": ("web_fuzzer",),
    "method_override_accepted": ("web_fuzzer",),
    "http_parameter_pollution": ("web_fuzzer",),
    "content_type_confusion": ("web_fuzzer",),
    "hidden_parameter_discovered": ("web_fuzzer", "param_miner"),
    "403_bypass_ip_header": ("web_fuzzer",),
    "403_bypass_path_manipulation": ("web_fuzzer",),
    "cache_poisoning_unkeyed_header": ("web_fuzzer",),
    "web_cache_deception": ("web_fuzzer",),
    "http_smuggling_indicator": ("web_fuzzer", "advanced_attacks"),
    "http_smuggling_te_obfuscation": ("web_fuzzer", "advanced_attacks"),
    "insecure_deserialization": ("web_fuzzer",),
    "xxe_entity_expansion": ("web_fuzzer", "anomaly_probe", "safe_validator"),
    "xml_accepted": ("web_fuzzer",),
    "ssi_injection": ("web_fuzzer",),
    "smtp_header_injection": ("web_fuzzer",),
    # heaven.vulnscan.misconfig_scanner — CORS, cookies, headers, redirect, JWT,
    # server-banner, GraphQL, plus the new client/session config probes.
    "cors_misconfig": ("misconfig_scanner", "safe_validator", "advanced_attacks"),
    "insecure_cookie": ("misconfig_scanner", "auth_scanner"),
    "jwt_alg_none": ("misconfig_scanner",),
    "jwt_weak_secret": ("misconfig_scanner", "advanced_attacks"),
    "missing_security_headers": ("misconfig_scanner", "web_crawler"),
    "server_version_disclosure": ("misconfig_scanner", "auth_scanner", "adaptive_intel"),
    "open_redirect": ("misconfig_scanner", "safe_validator", "advanced_attacks", "auth_scanner"),
    "graphql_introspection": ("misconfig_scanner", "api_scanner"),
    "clickjacking": ("misconfig_scanner", "web_crawler"),
    "permissive_crossdomain_policy": ("misconfig_scanner",),
    "password_autocomplete_enabled": ("misconfig_scanner",),
    "sensitive_cache_control": ("misconfig_scanner",),
    "session_token_in_url": ("misconfig_scanner",),
    "padding_oracle": ("misconfig_scanner",),
    "long_session_timeout": ("misconfig_scanner",),
    # heaven.vulnscan.auth_scanner — lockout, CSRF, session fixation, password
    # policy, session-id entropy, cookies, OAuth, registration/logout surrogates.
    "account_lockout_detected": ("auth_scanner",),
    "no_account_lockout": ("auth_scanner",),
    "lockout_inconclusive": ("auth_scanner",),
    "cookie_no_httponly": ("auth_scanner", "misconfig_scanner"),
    "cookie_no_samesite": ("auth_scanner", "misconfig_scanner"),
    "cookie_no_secure": ("auth_scanner", "misconfig_scanner"),
    "csp_unsafe_eval": ("auth_scanner",),
    "csp_unsafe_inline": ("auth_scanner", "web_crawler"),
    "csrf_missing_token": ("auth_scanner", "advanced_attacks"),
    "oauth_open_redirect": ("auth_scanner",),
    "oauth_state_reflected": ("auth_scanner",),
    "session_fixation": ("auth_scanner",),
    "technology_disclosure": ("auth_scanner", "adaptive_intel"),
    "weak_http_auth_credentials": ("auth_scanner",),
    "weak_login_credentials": ("auth_scanner",),
    "weak_password_policy": ("auth_scanner",),
    "weak_session_id": ("auth_scanner",),
    "open_registration": ("auth_scanner",),
    "weak_registration_policy": ("auth_scanner",),
    "weak_logout": ("auth_scanner",),
    "security_question_reset": ("auth_scanner",),
    "alt_channel_auth_weakness": ("auth_scanner", "api_scanner"),
    # heaven.vulnscan.anomaly_probe — LDAP/XPath/NoSQL/SSTI/XXE injection,
    # WebSocket/CSWSH, host-header, prototype pollution, format string, etc.
    "ldap_injection": ("anomaly_probe", "advanced_attacks"),
    "xpath_injection": ("anomaly_probe",),
    "nosql_injection": ("anomaly_probe",),
    "ssti": ("anomaly_probe", "advanced_attacks"),
    "xxe": ("anomaly_probe", "safe_validator", "advanced_attacks"),
    "prototype_pollution": ("anomaly_probe",),
    "websocket_cleartext": ("anomaly_probe",),
    "websocket_hijacking": ("anomaly_probe",),
    "host_header_injection": ("anomaly_probe", "web_fuzzer", "advanced_attacks"),
    "ip_restriction_bypass": ("anomaly_probe", "web_fuzzer"),
    "format_string": ("anomaly_probe",),
    "command_injection": ("anomaly_probe", "advanced_attacks", "injection_scanner"),
    "buffer_overflow": ("anomaly_probe",),
    "integer_overflow": ("anomaly_probe",),
    # heaven.vulnscan.client_audit — static analysis of HTML + inline/linked JS.
    "source_comment_disclosure": ("client_audit",),
    "dom_xss_sink": ("client_audit", "injection_scanner"),
    "insecure_postmessage": ("client_audit",),
    "sensitive_browser_storage": ("client_audit",),
    "cross_site_script_inclusion": ("client_audit",),
    "css_injection": ("client_audit",),
    "client_resource_manipulation": ("client_audit",),
    "flash_crossdomain": ("client_audit", "misconfig_scanner"),
    # heaven.vulnscan.injection_scanner — stored XSS (inject + refetch).
    "xss_stored": ("injection_scanner",),
    # request smuggling is emitted by both the fuzzer and advanced_attacks.
    "request_smuggling": ("web_fuzzer", "advanced_attacks"),
    # architecture inventory surrogate (INFO-10).
    "architecture_map": ("adaptive_intel", "inventory"),
    # heaven.recon.firewall_detector — perimeter firewall / IDS-IPS / tarpit / WAF
    # classification from filtered-vs-closed tallies. Real, confirmation-based
    # emitter that was never mapped, so its evidence lit NO methodology row. Lights
    # the ruleset-review / identifying-defenses / network-monitoring controls
    # (NIST 800-115 §3.3, PTES defenses, CIS CSC-13, NIST CSF DE.CM, SOC 2 CC7.2).
    "perimeter_defense": ("firewall_detector",),
}
# UNION-merge into VULN_MODULE (dedup, order-preserving) so historical mappings
# are extended, never lost.
for _vt, _toks in _ADDITIONAL_EMITTERS.items():
    VULN_MODULE[_vt] = tuple(dict.fromkeys(VULN_MODULE.get(_vt, ()) + _toks))


def modules_for_vuln(vuln_type: str) -> tuple[str, ...]:
    """Detector module token(s) that produce a given finding vuln_type."""
    if not vuln_type:
        return ()
    vt = vuln_type.strip().lower()
    exact = VULN_MODULE.get(vt)
    if exact:
        return exact
    for prefix, toks in _PREFIX_MODULE:
        if vt.startswith(prefix):
            return toks
    return ()


# ── Doc parsing ──────────────────────────────────────────────────────────────

_CODE_RE = re.compile(r"`[^`]+`")
_MODULE_RE = re.compile(r"heaven[./][\w./]+")
_TESTID_RE = re.compile(r"(WSTG-[A-Z]+-\d+|§[\d.]+)")
_CATCODE_RE = re.compile(r"\(([A-Z]{3,5})\)\s*$")


def _split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _is_sep(line: str) -> bool:
    return bool(line) and "-" in line and re.fullmatch(r"\s*\|?[\s:|-]+\|?\s*", line) is not None


def _classify(coverage: str) -> str:
    """automated | partial | manual, from a doc coverage cell."""
    cell = coverage.strip()
    low = cell.lower()
    has_code = bool(_CODE_RE.search(coverage) or _MODULE_RE.search(coverage))
    manual_lead = low.startswith("(manual") or low.startswith("manual") or low == "(manual)"
    if manual_lead:
        return "partial" if has_code else "manual"
    if has_code:
        return "partial" if "partial" in low else "automated"
    return "manual"


def _row_id(item: str, index: int) -> str:
    m = _TESTID_RE.search(item)
    if m:
        return m.group(1)
    stripped = _CODE_RE.sub(lambda mm: mm.group(0)[1:-1], item).strip()
    return stripped or f"row-{index}"


def parse_standard(name: str, text: str) -> dict[str, Any]:
    """Parse one methodology doc into a structured, row-classified matrix."""
    lines = text.replace("\r\n", "\n").split("\n")
    meta = STANDARD_META.get(name, {"title": name, "sub": ""})

    title = name
    intro_parts: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("# ") and title == name:
            title = lines[i][2:].strip()
            i += 1
            break
        i += 1
    # Intro = prose until the first '## '.
    while i < len(lines) and not lines[i].startswith("## "):
        if lines[i].strip():
            intro_parts.append(lines[i].strip())
        i += 1

    # Jump to the '## Detailed mapping' section.
    detail_start = None
    for j, ln in enumerate(lines):
        if ln.startswith("## ") and "detailed mapping" in ln.lower():
            detail_start = j + 1
            break

    categories: list[dict[str, Any]] = []
    if detail_start is not None:
        k = detail_start
        cur: Optional[dict[str, Any]] = None
        while k < len(lines):
            ln = lines[k]
            if ln.startswith("## "):
                break  # next top-level section ends the detailed mapping
            if ln.startswith("### "):
                ctitle = ln[4:].strip()
                cm = _CATCODE_RE.search(ctitle)
                cur = {
                    "code": cm.group(1) if cm else ctitle.split()[0],
                    "title": ctitle,
                    "note": "",
                    "rows": [],
                }
                categories.append(cur)
                k += 1
                continue
            # Table inside a category: header, separator, then rows.
            if cur is not None and ln.strip().startswith("|") and k + 1 < len(lines) and _is_sep(lines[k + 1]):
                header = _split_row(ln)
                ncols = len(header)
                k += 2
                idx = 0
                while k < len(lines) and lines[k].strip().startswith("|"):
                    cells = _split_row(lines[k])
                    if len(cells) >= 2:
                        item = cells[0]
                        coverage = cells[-1]
                        description = cells[1] if ncols >= 3 else ""
                        cur["rows"].append({
                            "id": _row_id(item, idx),
                            "item": item,
                            "description": description,
                            "coverage": coverage,
                            "status": _classify(coverage),
                        })
                        idx += 1
                    k += 1
                continue
            # Prose note for table-less categories (e.g. Business Logic).
            if cur is not None and ln.strip() and not ln.startswith("|"):
                cur["note"] = (cur["note"] + " " + ln.strip()).strip()
            k += 1

    summary = _summarise(categories)
    return {
        "name": name,
        "title": title,
        "subtitle": meta["sub"],
        "meta_title": meta["title"],
        "intro": " ".join(intro_parts),
        "categories": categories,
        "summary": summary,
    }


def _summarise(categories: Iterable[dict[str, Any]]) -> dict[str, int]:
    total = automated = partial = manual = 0
    for c in categories:
        for r in c["rows"]:
            total += 1
            st = r["status"]
            if st == "automated":
                automated += 1
            elif st == "partial":
                partial += 1
            else:
                manual += 1
    return {
        "total": total,
        "automated": automated,
        "partial": partial,
        "manual": manual,
        # "covered" = anything HEAVEN touches automatically (automated + partial)
        "covered": automated + partial,
    }


def load_standards(docs_dir: Optional[Path] = None) -> list[dict[str, Any]]:
    """Parse every methodology doc found in ``docs_dir`` (sorted by stem)."""
    d = docs_dir or DOCS_DIR
    if not d.exists():
        return []
    out = []
    for md in sorted(d.glob("*.md")):
        if md.stem == "README":
            continue
        try:
            out.append(parse_standard(md.stem, md.read_text(encoding="utf-8")))
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
            continue
    # Stable, meaningful order: the three pen-test methodologies first, then the
    # compliance/control frameworks, then anything else alphabetically.
    order = {
        "owasp_testing_guide": 0, "nist_800_115": 1, "ptes": 2,
        "cyber_essentials": 3, "cyber_essentials_plus": 4, "iso_27001": 5,
        "pci_dss": 6, "cis_controls_v8": 7, "nist_csf": 8, "soc2": 9,
    }
    out.sort(key=lambda s: (order.get(s["name"], 99), s["name"]))
    return out


# ── Live engagement overlay ──────────────────────────────────────────────────

def _finding_vuln_type(f: Any) -> str:
    if isinstance(f, dict):
        return str(f.get("vuln_type") or f.get("type") or "")
    return str(getattr(f, "vuln_type", "") or getattr(f, "type", "") or "")


def _finding_owasp(f: Any) -> str:
    from heaven.devsecops import frameworks as _fw
    if isinstance(f, dict):
        given = str(f.get("owasp") or "")
    else:
        given = str(getattr(f, "owasp", "") or "")
    if given:
        # Upgrade any legacy 2021 tag to its canonical 2025 label.
        return _fw.normalize_owasp(given) or given
    # Fall back to the KB taxonomy so the OWASP-category stat is populated even
    # when a stored finding didn't persist its own owasp string.
    try:
        from heaven.devsecops.vuln_kb import lookup
        kb = str((lookup(_finding_vuln_type(f)) or {}).get("owasp", ""))
        return _fw.normalize_owasp(kb) or kb
    except Exception:
        return ""


def module_counts(findings: Iterable[Any]) -> dict[str, int]:
    """Detector token → number of active-engagement findings it produced."""
    counts: dict[str, int] = {}
    for f in findings:
        for tok in modules_for_vuln(_finding_vuln_type(f)):
            counts[tok] = counts.get(tok, 0) + 1
    return counts


def overlay_findings(standards: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    """Annotate parsed standards in-place with per-row engagement coverage.

    Returns a compact engagement summary. A row is marked ``exercised`` iff a
    detector token it names produced at least one finding in this engagement.
    """
    counts = module_counts(findings)
    active_tokens = set(counts)

    for std in standards:
        rows_exercised = 0
        covered_exercised = 0
        for cat in std["categories"]:
            cat_ex = 0
            for row in cat["rows"]:
                cov = row["coverage"]
                hit = sum(counts[t] for t in active_tokens if t in cov)
                row["exercised"] = hit > 0
                row["exercised_count"] = hit
                if hit > 0:
                    rows_exercised += 1
                    cat_ex += 1
                    if row["status"] in ("automated", "partial"):
                        covered_exercised += 1
            cat["exercised"] = cat_ex
        std["summary"]["exercised"] = rows_exercised
        std["summary"]["exercised_covered"] = covered_exercised

    vuln_types = sorted({_finding_vuln_type(f) for f in findings if _finding_vuln_type(f)})
    owasp_cats = sorted({_finding_owasp(f) for f in findings if _finding_owasp(f)})
    return {
        "findings_total": len(findings),
        "vuln_types": vuln_types,
        "owasp_categories": owasp_cats,
        "modules_active": sorted(active_tokens),
        "module_counts": counts,
    }


def build(findings: Optional[list[Any]] = None,
          docs_dir: Optional[Path] = None) -> dict[str, Any]:
    """Full payload: parsed standards + (optional) live engagement overlay."""
    standards = load_standards(docs_dir)
    engagement = overlay_findings(standards, findings or [])
    return {"standards": standards, "engagement": engagement}

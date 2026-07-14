"""HEAVEN — methodology coverage (single source of truth for CLI / API / UI).

The three methodology docs (``docs/methodology/*.md``) map every OWASP WSTG /
NIST SP 800-115 / PTES test to the HEAVEN detector module that automates it.
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

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs" / "methodology"

# Human-facing metadata per doc stem (title + short subtitle for the UI selector).
STANDARD_META: dict[str, dict[str, str]] = {
    "owasp_testing_guide": {"title": "OWASP Testing Guide", "sub": "WSTG v4.2"},
    "nist_800_115": {"title": "NIST SP 800-115", "sub": "Technical assessment"},
    "ptes": {"title": "PTES", "sub": "Execution standard"},
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
}


def modules_for_vuln(vuln_type: str) -> tuple[str, ...]:
    """Detector module token(s) that produce a given finding vuln_type."""
    if not vuln_type:
        return ()
    return VULN_MODULE.get(vuln_type.strip().lower(), ())


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
            continue
    # Stable, meaningful order: OWASP, NIST, PTES, then anything else.
    order = {"owasp_testing_guide": 0, "nist_800_115": 1, "ptes": 2}
    out.sort(key=lambda s: (order.get(s["name"], 99), s["name"]))
    return out


# ── Live engagement overlay ──────────────────────────────────────────────────

def _finding_vuln_type(f: Any) -> str:
    if isinstance(f, dict):
        return str(f.get("vuln_type") or f.get("type") or "")
    return str(getattr(f, "vuln_type", "") or getattr(f, "type", "") or "")


def _finding_owasp(f: Any) -> str:
    if isinstance(f, dict):
        given = str(f.get("owasp") or "")
    else:
        given = str(getattr(f, "owasp", "") or "")
    if given:
        return given
    # Fall back to the KB taxonomy so the OWASP-category stat is populated even
    # when a stored finding didn't persist its own owasp string.
    try:
        from heaven.devsecops.vuln_kb import lookup
        return str((lookup(_finding_vuln_type(f)) or {}).get("owasp", ""))
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

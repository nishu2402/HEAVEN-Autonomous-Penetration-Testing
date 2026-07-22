"""HEAVEN — End-of-Life / unsupported software detector.

Professional infrastructure health-checks consistently flag *unsupported
software* as a high-risk finding (CWE-1104): operating systems and components
past their vendor end-of-life date receive no further security patches, so any
vulnerability discovered after that date stays permanently exploitable.

This module turns the discovered host/service inventory (product + version + OS,
as produced by network reconnaissance) into concrete EOL findings. It is
**deterministic and evidence-based**: a finding fires only on a positive product
match, and — for version-gated rules — only when the detected version is at or
below the last supported release. Every finding carries the vendor EOL date as
proof, never a guess. Products with no clean vendor EOL policy (rolling-release
servers, etc.) are deliberately excluded to avoid false positives; their risk is
handled by the CVE mapper instead.

EOL dates reflect published vendor lifecycles. They are conservative: where an
Extended Security Update (ESU) path exists, the finding says so.
"""

from __future__ import annotations

import re
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.eol")


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict) -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": "",
        "evidence": evidence,
        "source": "eol_scanner",
    }


def _parse_version(text: str) -> Optional[tuple[int, ...]]:
    """Extract the first dotted-numeric version from ``text`` as a tuple."""
    m = re.search(r"(\d+(?:\.\d+){0,3})", text or "")
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None


def _lt(version: tuple[int, ...], cutoff: tuple[int, ...]) -> bool:
    """version < cutoff with tuple padding (2.2 < 2.4, 8.0 < 8.1)."""
    n = max(len(version), len(cutoff))
    v = version + (0,) * (n - len(version))
    c = cutoff + (0,) * (n - len(cutoff))
    return v < c


# ── OS end-of-life table (regex on the OS guess → date + note) ───────────────
# Ordered most-specific first; the first match wins.
_OS_EOL: list[tuple[str, str, str, str]] = [
    (r"windows\s+xp", "2014-04-08", "high",
     "Windows XP has been unsupported since 2014."),
    (r"windows\s+vista", "2017-04-11", "high",
     "Windows Vista has been unsupported since 2017."),
    (r"windows\s+7", "2020-01-14", "high",
     "Windows 7 reached end of support on 2020-01-14 (ESU ended 2023)."),
    (r"windows\s+8(\.1)?", "2023-01-10", "high",
     "Windows 8/8.1 reached end of support on 2023-01-10."),
    (r"windows\s+10", "2025-10-14", "medium",
     "Windows 10 reached end of support on 2025-10-14. Move to Windows 11 or "
     "enrol eligible devices in Extended Security Updates (ESU)."),
    (r"windows\s+server\s+2003", "2015-07-14", "high",
     "Windows Server 2003 has been unsupported since 2015."),
    (r"windows\s+server\s+2008", "2020-01-14", "high",
     "Windows Server 2008/2008 R2 reached end of support on 2020-01-14."),
    (r"windows\s+server\s+2012", "2023-10-10", "high",
     "Windows Server 2012/2012 R2 reached end of support on 2023-10-10."),
]

# ── Product end-of-life table ────────────────────────────────────────────────
# Each rule: (display, product-regex, version_cutoff or None, eol_date, severity, note)
# version_cutoff None → the product is EOL regardless of version.
_PRODUCT_EOL: list[tuple[str, str, Optional[tuple[int, ...]], str, str, str]] = [
    ("Microsoft Silverlight", r"silverlight", None, "2021-10-12", "medium",
     "Microsoft Silverlight reached end of support on 2021-10-12 and receives no "
     "further updates."),
    ("Adobe Flash Player", r"flash\s*player|shockwave\s*flash", None, "2020-12-31",
     "high", "Adobe Flash Player reached end of life on 2020-12-31 and is blocked "
     "by modern browsers."),
    ("Apache httpd 2.2", r"apache", (2, 4), "2017-12-31", "medium",
     "Apache httpd branches before 2.4 are end-of-life and receive no security "
     "fixes."),
    ("PHP", r"\bphp\b", (8, 1), "2025-12-31", "medium",
     "PHP versions before 8.1 have reached end of security support. Upgrade to a "
     "supported 8.x branch."),
    ("MySQL", r"\bmysql\b", (8, 0), "2023-10-31", "medium",
     "MySQL branches before 8.0 (e.g. 5.7) reached end of life in 2023."),
    ("OpenSSL", r"openssl", (3, 0), "2023-09-11", "medium",
     "OpenSSL 1.0.2/1.1.0/1.1.1 are all end-of-life; upgrade to the 3.x LTS line."),
    ("Microsoft IIS 6.0", r"iis[/ ]?6\b|microsoft-iis/6", None, "2015-07-14",
     "high", "IIS 6.0 shipped with Windows Server 2003 and is unsupported."),
]


def _os_finding(host: str, os_guess: str) -> Optional[dict]:
    low = os_guess.lower()
    for pattern, eol_date, severity, note in _OS_EOL:
        if re.search(pattern, low):
            return _finding(
                host, "unsupported_software", severity,
                f"Unsupported Operating System: {os_guess}",
                "The host is running an operating system that has passed its "
                f"vendor end-of-life date ({eol_date}). {note} End-of-life systems "
                "receive no security patches, so any newly disclosed vulnerability "
                "remains exploitable indefinitely. Plan decommissioning/upgrade, or "
                "purchase extended support and isolate the host in the interim.",
                0.85,
                {"product": os_guess, "kind": "operating_system",
                 "eol_date": eol_date, "cwe": "CWE-1104"})
    return None


def _product_findings(target: str, product: str, version: str,
                      banner: str) -> list[dict]:
    hay = f"{product} {version} {banner}".lower()
    out: list[dict] = []
    for display, pattern, cutoff, eol_date, severity, note in _PRODUCT_EOL:
        if not re.search(pattern, hay):
            continue
        detected_ver = ""
        if cutoff is not None:
            # Prefer the structured version field, fall back to the banner text.
            v = _parse_version(version) or _parse_version(banner)
            if v is None or not _lt(v, cutoff):
                continue
            detected_ver = ".".join(str(x) for x in v)
        out.append(_finding(
            target, "unsupported_software", severity,
            f"Unsupported / End-of-Life Software: {display}"
            + (f" {detected_ver}" if detected_ver else ""),
            f"{note} End-of-life software receives no security patches; treat this "
            "as a proof-of-concept for the wider estate and inventory/upgrade all "
            "affected instances.",
            0.8,
            {"product": display, "detected_version": detected_ver,
             "kind": "software_component", "eol_date": eol_date,
             "cwe": "CWE-1104"}))
    return out


async def scan_eol_from_net(net_data: dict) -> dict:
    """Analyse a network-recon result for end-of-life OS and software.

    ``net_data`` is the ``scan_network`` dict (``{"hosts": [...]}``). Returns the
    standard scanner result shape.
    """
    hosts = net_data.get("hosts", []) if isinstance(net_data, dict) else []
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for host in hosts:
        ip = host.get("ip") or host.get("host") or ""
        if not ip:
            continue
        os_guess = str(host.get("os_guess") or "")
        if os_guess:
            osf = _os_finding(ip, os_guess)
            if osf:
                key = (ip, "os", os_guess.lower())
                if key not in seen:
                    seen.add(key)
                    findings.append(osf)
        for p in host.get("open_ports", []):
            port = p.get("port", "")
            product = str(p.get("product") or "")
            version = str(p.get("version") or "")
            banner = str(p.get("banner") or "")
            if not (product or banner):
                continue
            for f in _product_findings(f"{ip}:{port}", product, version, banner):
                prod = f["evidence"]["product"]
                key = (ip, prod.lower(), f["evidence"].get("detected_version", ""))
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

    logger.info("EOL scan → %d unsupported-software finding(s) across %d host(s)",
                len(findings), len(hosts))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}

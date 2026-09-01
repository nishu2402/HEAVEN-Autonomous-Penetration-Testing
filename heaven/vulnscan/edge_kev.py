"""HEAVEN — Internet-facing edge/VPN appliance KEV fingerprint.

The remote-access edge (Citrix NetScaler/Gateway, Ivanti Connect Secure, FortiOS
SSL-VPN, Palo Alto GlobalProtect, Microsoft Exchange/OWA, F5 BIG-IP) is the single
most-abused external entry point in real-world intrusions — each family has
CVE(s) on CISA's Known-Exploited-Vulnerabilities (KEV) catalog. HEAVEN's general
product→CVE pipeline only fires when a dotted version is disclosed in a header,
which these appliances usually do not do; they are recognised instead by
distinctive cookies, server strings and login paths.

This module fingerprints the appliance FAMILY from those signals and surfaces the
actively-exploited CVEs known for it, so a perimeter scan flags the exposure
immediately and points the tester at the exact patches to verify. It is careful
not to over-claim: recognising the family is not proof the box is unpatched, so
the finding is framed as an exposure to verify (medium, "confirm patch level")
unless a concrete vulnerable version is actually observed. Everything is a
read-only GET of the login surface — no exploit payload is ever sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from heaven.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EdgeSignature:
    family: str                       # human label
    vuln_type: str                    # taxonomy key
    server_regex: Optional[str] = None
    header_signatures: list[tuple[str, str]] = field(default_factory=list)  # (header, regex)
    cookie_regexes: list[str] = field(default_factory=list)
    body_regexes: list[str] = field(default_factory=list)
    probe_paths: list[str] = field(default_factory=list)
    version_header: Optional[str] = None  # header that carries a concrete version
    kev: list[dict] = field(default_factory=list)   # [{cve, name, cvss}]
    remediation: str = ""


# Curated, conservative KEV set — only CVEs confidently known to be
# actively-exploited (CISA KEV) for each family. Version-independent: presence of
# the family surfaces the list to verify; a confirmed vulnerable version would be
# matched by the standard CVE pipeline separately.
_SIGNATURES: list[EdgeSignature] = [
    EdgeSignature(
        family="Citrix NetScaler ADC / Gateway",
        vuln_type="edge_citrix_netscaler",
        server_regex=r"(?i)\bnetscaler\b",
        header_signatures=[("via", r"(?i)ns-cache"), ("x-citrix-application", r".+")],
        cookie_regexes=[r"(?i)\bNSC_", r"(?i)\bNSC_AAAC", r"(?i)\bcitrix_ns_id"],
        body_regexes=[r"(?i)Citrix (Gateway|Access Gateway|NetScaler)",
                      r"/vpn/index\.html", r"/logon/LogonPoint"],
        probe_paths=["/vpn/index.html", "/logon/LogonPoint/tmindex.html"],
        kev=[
            {"cve": "CVE-2019-19781", "name": "Citrix ADC/Gateway path traversal RCE (Shitrix)", "cvss": 9.8},
            {"cve": "CVE-2023-3519", "name": "NetScaler ADC/Gateway unauth RCE", "cvss": 9.8},
            {"cve": "CVE-2023-4966", "name": "NetScaler session-token disclosure (Citrix Bleed)", "cvss": 9.4},
        ],
        remediation=("Upgrade NetScaler ADC/Gateway to a fixed build, and after "
                     "patching Citrix Bleed (CVE-2023-4966) terminate all active "
                     "and persistent sessions. Restrict management interfaces from "
                     "the internet."),
    ),
    EdgeSignature(
        family="Ivanti Connect Secure / Pulse Secure VPN",
        vuln_type="edge_ivanti_pulse",
        header_signatures=[("ncp-version", r".+")],
        cookie_regexes=[r"(?i)\bDSID", r"(?i)\bDSSignInURL", r"(?i)\bDSLastAccess"],
        body_regexes=[r"(?i)Pulse Secure", r"(?i)Ivanti", r"/dana-na/"],
        probe_paths=["/dana-na/auth/url_default/welcome.cgi", "/dana-na/nc/nc_gina_ver.txt"],
        kev=[
            {"cve": "CVE-2023-46805", "name": "Ivanti Connect Secure auth bypass", "cvss": 8.2},
            {"cve": "CVE-2024-21887", "name": "Ivanti Connect Secure command injection", "cvss": 9.1},
            {"cve": "CVE-2024-21893", "name": "Ivanti Connect Secure SSRF", "cvss": 8.2},
        ],
        remediation=("Apply Ivanti's patches, run the external Integrity Checker "
                     "Tool, and factory-reset any appliance suspected compromised. "
                     "Remove the appliance's web UI from untrusted networks."),
    ),
    EdgeSignature(
        family="Fortinet FortiOS SSL-VPN",
        vuln_type="edge_fortinet_fortios",
        cookie_regexes=[r"(?i)\bSVPNCOOKIE", r"(?i)\bSVPNNETWORKCOOKIE"],
        body_regexes=[r"(?i)fortinet", r"(?i)FortiGate", r"/remote/login", r"/remote/fgt_lang"],
        probe_paths=["/remote/login", "/remote/fgt_lang?lang=en"],
        kev=[
            {"cve": "CVE-2018-13379", "name": "FortiOS SSL-VPN path traversal (credential leak)", "cvss": 9.8},
            {"cve": "CVE-2022-40684", "name": "FortiOS/FortiProxy auth bypass", "cvss": 9.8},
            {"cve": "CVE-2023-27997", "name": "FortiOS SSL-VPN heap overflow RCE (XORtigate)", "cvss": 9.8},
            {"cve": "CVE-2024-21762", "name": "FortiOS SSL-VPN out-of-bounds write RCE", "cvss": 9.8},
        ],
        remediation=("Upgrade FortiOS to a fixed release, rotate all VPN and admin "
                     "credentials (CVE-2018-13379 leaks them), and disable SSL-VPN "
                     "web mode if unused."),
    ),
    EdgeSignature(
        family="Palo Alto Networks GlobalProtect / PAN-OS",
        vuln_type="edge_paloalto_globalprotect",
        server_regex=r"(?i)PanWeb Server|\bPAN\b",
        body_regexes=[r"(?i)GlobalProtect", r"/global-protect/login\.esp",
                      r"/sslmgr", r"(?i)Palo Alto Networks"],
        probe_paths=["/global-protect/login.esp", "/php/login.php"],
        kev=[
            {"cve": "CVE-2024-3400", "name": "PAN-OS GlobalProtect command injection", "cvss": 10.0},
        ],
        remediation=("Upgrade PAN-OS to a fixed release, apply the GlobalProtect "
                     "threat-prevention mitigation, and review device logs for "
                     "exploitation of CVE-2024-3400."),
    ),
    EdgeSignature(
        family="Microsoft Exchange / Outlook Web Access",
        vuln_type="edge_microsoft_exchange",
        header_signatures=[("x-owa-version", r".+"), ("x-feexchange", r".+")],
        body_regexes=[r"/owa/auth", r"(?i)Outlook Web App", r"/ecp/"],
        probe_paths=["/owa/", "/autodiscover/autodiscover.xml"],
        version_header="x-owa-version",
        kev=[
            {"cve": "CVE-2021-26855", "name": "Exchange SSRF (ProxyLogon)", "cvss": 9.8},
            {"cve": "CVE-2021-34473", "name": "Exchange RCE (ProxyShell)", "cvss": 9.8},
            {"cve": "CVE-2022-41040", "name": "Exchange SSRF (ProxyNotShell)", "cvss": 8.8},
            {"cve": "CVE-2022-41082", "name": "Exchange RCE (ProxyNotShell)", "cvss": 8.8},
        ],
        remediation=("Apply the latest Exchange Cumulative + Security Update, and "
                     "hunt for webshells in the OAB/ECP virtual directories if the "
                     "server was internet-facing while unpatched."),
    ),
    EdgeSignature(
        family="F5 BIG-IP",
        vuln_type="edge_f5_bigip",
        header_signatures=[("x-wa-info", r".+")],
        cookie_regexes=[r"(?i)\bBIGipServer", r"(?i)\bF5_ST", r"(?i)\bLastMRH_Session"],
        body_regexes=[r"(?i)BIG-?IP", r"/tmui/", r"(?i)F5 Networks"],
        probe_paths=["/tmui/login.jsp", "/mgmt/shared/authn/login"],
        kev=[
            {"cve": "CVE-2020-5902", "name": "BIG-IP TMUI RCE", "cvss": 9.8},
            {"cve": "CVE-2022-1388", "name": "BIG-IP iControl REST auth bypass RCE", "cvss": 9.8},
            {"cve": "CVE-2023-46747", "name": "BIG-IP Configuration utility unauth RCE", "cvss": 9.8},
        ],
        remediation=("Upgrade to a fixed BIG-IP release, restrict the TMUI / "
                     "iControl REST management interface to a management network, "
                     "and apply F5's mitigations."),
    ),
]


def _headers_lower(headers: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        out[str(k).lower()] = str(v)
    return out


def _cookie_blob(headers: Mapping[str, str]) -> str:
    # aiohttp/requests may collapse Set-Cookie; scan whatever the header carries.
    parts = []
    for k, v in headers.items():
        if str(k).lower() == "set-cookie":
            parts.append(str(v))
    return " ; ".join(parts)


def _match_signature(sig: EdgeSignature, headers_l: dict[str, str],
                     cookie_blob: str, body: str) -> tuple[bool, list[str]]:
    """Return (matched, [reasons]). A single distinctive signal is enough."""
    reasons: list[str] = []
    server = headers_l.get("server", "")
    if sig.server_regex and re.search(sig.server_regex, server):
        reasons.append(f"Server: {server}")
    for hname, rgx in sig.header_signatures:
        val = headers_l.get(hname, "")
        if val and re.search(rgx, val):
            reasons.append(f"{hname}: {val}")
    for rgx in sig.cookie_regexes:
        if re.search(rgx, cookie_blob):
            reasons.append(f"cookie~{rgx}")
    if body:
        for rgx in sig.body_regexes:
            if re.search(rgx, body):
                reasons.append(f"body~{rgx}")
    return (bool(reasons), reasons)


def _finding(sig: EdgeSignature, target: str, reasons: list[str],
             version: str = "") -> dict:
    kev_names = "; ".join(f"{k['cve']} ({k['name']})" for k in sig.kev)
    if version:
        sev, conf, verb = "high", 0.7, (
            f"discloses version {version}. Confirm it is not affected by")
    else:
        sev, conf, verb = "medium", 0.6, (
            "was fingerprinted at the perimeter. Its patch level could not be read "
            "from the response, so verify it is not affected by")
    return {
        "target": target,
        "vuln_type": sig.vuln_type,
        "severity": sev,
        "title": f"Internet-facing {sig.family} exposed (KEV appliance)",
        "description": (
            f"An internet-facing {sig.family} {verb} these actively-exploited "
            f"(CISA KEV) vulnerabilities: {kev_names}. Edge/VPN appliances are the "
            f"most common initial-access vector in real intrusions; an unpatched "
            f"one here is a likely breach path."),
        "confidence": conf,
        "remediation": sig.remediation,
        "mitre_technique": "T1190 · Exploit Public-Facing Application",
        "evidence": {"family": sig.family, "fingerprint": reasons,
                     "kev_cves": [k["cve"] for k in sig.kev],
                     "kev": sig.kev, "version": version,
                     "note": ("appliance family fingerprinted; verify the patch "
                              "level against these KEV CVEs")},
        # Left empty on purpose: the family is fingerprinted, not a specific CVE
        # confirmed. The KEV CVEs to verify are carried in the evidence + prose.
        "cve_id": "",
        "source": "edge_kev",
    }


def match_edge_kev_headers(headers: Mapping[str, str], *, target: str = "",
                           body: str = "") -> list[dict]:
    """Zero-extra-request matcher: fingerprint an edge appliance from a response's
    headers/cookies (and optional body). Returns at most one finding per family."""
    if not headers and not body:
        return []
    headers_l = _headers_lower(headers or {})
    cookie_blob = _cookie_blob(headers) or headers_l.get("set-cookie", "")
    findings: list[dict] = []
    for sig in _SIGNATURES:
        matched, reasons = _match_signature(sig, headers_l, cookie_blob, body)
        if matched:
            version = ""
            if sig.version_header:
                version = headers_l.get(sig.version_header, "")
            findings.append(_finding(sig, target or "edge", reasons, version))
    return findings


async def scan_edge_appliances(urls: list[str], *, session: Any = None,
                               max_hosts: int = 32, timeout: float = 8.0) -> dict:
    """Active (read-only) edge-appliance fingerprint. Fetches each host's root and
    a few well-known appliance login paths, fingerprints the family, and surfaces
    its KEV CVEs. Bounded and safe — plain GETs, no exploit payloads."""
    try:
        import aiohttp
    except Exception:
        return {"findings": [], "total": 0}
    if not urls:
        return {"findings": [], "total": 0}

    import urllib.parse

    # One origin per host (scheme+netloc), capped.
    origins: dict[str, str] = {}
    for u in urls:
        try:
            p = urllib.parse.urlparse(u if "://" in u else f"http://{u}")
            if not p.netloc:
                continue
            origins.setdefault(p.netloc, f"{p.scheme}://{p.netloc}")
        except Exception:
            continue
        if len(origins) >= max_hosts:
            break

    own = session is None
    if own:
        connector = aiohttp.TCPConnector(ssl=False, limit=16)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-EdgeKEV/1.0)"})

    findings: list[dict] = []
    seen_family: set[tuple[str, str]] = set()  # (netloc, family) dedup
    try:
        for netloc, base in origins.items():
            # Collect candidate paths across all families plus the root.
            paths = ["/"]
            for sig in _SIGNATURES:
                paths.extend(sig.probe_paths)
            # De-dup while preserving order, bounded.
            seen_paths: set[str] = set()
            ordered = [p for p in paths if not (p in seen_paths or seen_paths.add(p))]
            for path in ordered[:16]:
                url = base + path
                try:
                    async with session.get(url, ssl=False, allow_redirects=False) as resp:
                        headers = {k: v for k, v in resp.headers.items()}
                        body = ""
                        try:
                            raw = await resp.content.read(8192)
                            body = raw.decode("utf-8", "ignore")
                        except Exception:
                            body = ""
                except Exception:
                    continue
                for f in match_edge_kev_headers(headers, target=netloc, body=body):
                    fam = f["evidence"]["family"]
                    if (netloc, fam) in seen_family:
                        continue
                    seen_family.add((netloc, fam))
                    findings.append(f)
    finally:
        if own and session is not None:
            try:
                await session.close()
            except Exception:
                pass

    if findings:
        logger.info("Edge-KEV scan → %d appliance exposure(s) across %d host(s)",
                    len(findings), len(origins))
    return {"findings": findings, "vulnerabilities": [], "total": len(findings)}

"""HEAVEN — Wireless-infrastructure configuration review (network-reachable).

This module is **not** an RF/Wi-Fi scanner. Sniffing 802.11, cracking WPA
handshakes or enumerating SSIDs needs a local radio in monitor mode — hardware
a remote autonomous scanner does not have, and faking it would be dishonest.

What a network-reachable assessment *can* legitimately do is review the
management plane of wireless infrastructure that is exposed on the IP network:
access-point / home-router / WLAN-controller web admin panels. An exposed (and
especially an *unauthenticated*) controller is a real, high-impact finding — it
governs every client on the wireless network.

All probes are strictly READ-ONLY GETs. No credentials are submitted, no
configuration is changed. Findings are vendor-fingerprinted to keep the
false-positive rate low: a generic 200 or a non-wireless device never matches.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.wireless")

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Common HTTP(S) management ports for AP / router / WLAN-controller web UIs.
_MGMT_PORTS: list[tuple[str, int]] = [
    ("http", 80), ("https", 443), ("http", 8080), ("https", 8443),
]

# Distinctive vendor/product tokens that identify a wireless-infrastructure
# management interface. Matched (case-insensitive) against the response title,
# the ``Server`` header and any ``WWW-Authenticate`` realm. Kept specific — a
# bare "router" or "login" never matches, so a random web app is not flagged.
_WIRELESS_FINGERPRINTS: list[tuple[str, str]] = [
    ("unifi", "Ubiquiti UniFi controller"),
    ("ubiquiti", "Ubiquiti wireless device"),
    ("airos", "Ubiquiti airOS radio"),
    ("edgeos", "Ubiquiti EdgeOS device"),
    ("arubaos", "Aruba WLAN controller"),
    ("aruba networks", "Aruba WLAN device"),
    ("routeros", "MikroTik RouterOS"),
    ("mikrotik", "MikroTik wireless device"),
    ("zonedirector", "Ruckus ZoneDirector controller"),
    ("ruckus", "Ruckus WLAN device"),
    ("meraki", "Cisco Meraki dashboard"),
    ("aironet", "Cisco Aironet access point"),
    ("wireless lan controller", "Cisco Wireless LAN Controller"),
    ("dd-wrt", "DD-WRT wireless router"),
    ("openwrt", "OpenWrt wireless router"),
    ("luci", "OpenWrt LuCI interface"),
    ("tp-link", "TP-Link wireless router"),
    ("netgear", "Netgear wireless router"),
    ("tenda", "Tenda wireless router"),
    ("draytek", "DrayTek wireless router"),
    ("engenius", "EnGenius wireless device"),
]


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, **extra: Any) -> dict[str, Any]:
    f = {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "scanner": "wireless_posture",
    }
    f.update(extra)
    return f


def _match_vendor(haystacks: list[str]) -> Optional[str]:
    hay = " ".join(h.lower() for h in haystacks if h)
    for token, label in _WIRELESS_FINGERPRINTS:
        if token in hay:
            return label
    return None


async def _probe_host(session, host: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_vendor = False
    for scheme, port in _MGMT_PORTS:
        if seen_vendor:
            break  # one confirmed panel per host is enough — avoid duplicates
        url = f"{scheme}://{host}:{port}/"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=6), ssl=False,
                allow_redirects=True,
            ) as resp:
                server = resp.headers.get("Server", "")
                realm = resp.headers.get("WWW-Authenticate", "")
                body = (await resp.text(errors="ignore"))[:8000]
                status = resp.status
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
            continue

        # Extract <title> for fingerprinting.
        title = ""
        low = body.lower()
        s = low.find("<title")
        if s != -1:
            e = low.find("</title>", s)
            if e != -1:
                title = body[low.find(">", s) + 1:e].strip()

        vendor = _match_vendor([title, server, realm, body[:2000]])
        if not vendor:
            continue
        seen_vendor = True

        # 401/403 with a matching realm ⇒ auth is enforced (exposure only).
        # A 200 landing on the admin UI ⇒ the panel is reachable without a login.
        if status in (401, 403):
            findings.append(_finding(
                target=f"{host}:{port}",
                vuln_type="wireless_mgmt_exposed",
                severity="medium",
                title=f"Wireless management interface exposed: {vendor}",
                description=(
                    f"The {vendor} web management interface is reachable on the network "
                    f"at {url} (authentication is enforced — HTTP {status}). Wireless "
                    "controller/AP admin planes should not be exposed to untrusted "
                    "networks even when authenticated; combined with weak or default "
                    "credentials this is a full-network-takeover path."),
                confidence=0.8,
                evidence={"url": url, "status": status, "server": server,
                          "title": title[:120]},
                remediation=(
                    "Restrict the wireless management interface to a dedicated "
                    "management VLAN / VPN. Change default credentials and enforce "
                    "MFA where supported. Never expose the controller to the WAN."),
                cwe="CWE-284",
                owasp="A05:2021 Security Misconfiguration",
                mitre="T1133 — External Remote Services",
            ))
        elif status == 200:
            findings.append(_finding(
                target=f"{host}:{port}",
                vuln_type="wireless_mgmt_unauthenticated",
                severity="high",
                title=f"Unauthenticated wireless management interface: {vendor}",
                description=(
                    f"The {vendor} web management interface at {url} returned its admin "
                    "UI with HTTP 200 and no authentication challenge. If the landing "
                    "page grants configuration access without a login, an attacker on "
                    "this network controls the wireless infrastructure. Confirm whether "
                    "the UI is actually usable before authenticating."),
                confidence=0.6,
                evidence={"url": url, "status": 200, "server": server,
                          "title": title[:120]},
                remediation=(
                    "Require authentication on the management interface, restrict it to "
                    "a management VLAN/VPN, and change any default credentials."),
                cwe="CWE-306",
                owasp="A07:2021 Identification and Authentication Failures",
                mitre="T1133 — External Remote Services",
            ))
    return findings


async def scan_wireless_posture(targets: Optional[list[str]] = None,
                                **kwargs: Any) -> dict[str, Any]:
    """Review network-reachable wireless-infrastructure management planes.

    ``targets`` are host/IP strings (URLs are reduced to their hostname). Returns
    ``{"findings": [...], "hosts_checked": N}`` or ``{"skipped": ...}``.
    """
    hosts = targets or kwargs.get("ips", [])
    # Reduce any URL targets to bare hostnames.
    from urllib.parse import urlparse
    norm: list[str] = []
    for t in hosts:
        t = str(t).strip()
        if not t:
            continue
        if "://" in t:
            t = urlparse(t).hostname or t
        norm.append(t.split("/")[0])
    norm = sorted(set(norm))
    if not norm:
        return {"skipped": True, "reason": "no host targets"}
    if not HAS_AIOHTTP:
        logger.warning("aiohttp not installed — wireless posture review unavailable")
        return {"skipped": True, "reason": "aiohttp unavailable"}

    findings: list[dict[str, Any]] = []
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *[_probe_host(session, h) for h in norm], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    logger.info(f"Wireless posture review: {len(findings)} finding(s) across {len(norm)} host(s)")
    return {"findings": findings, "hosts_checked": len(norm)}

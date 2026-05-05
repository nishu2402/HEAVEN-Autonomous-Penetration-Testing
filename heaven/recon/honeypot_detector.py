"""
HEAVEN — Honeypot & CTF Trap Detector
Intelligent detection of honeypots, CTF challenges, and deception systems.
Uses banner analysis, timing heuristics, port profiles, and known signatures.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("recon.honeypot")

# Known honeypot banner signatures
HONEYPOT_SIGNATURES = {
    "cowrie": [r"SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2", r"cowrie"],
    "kippo": [r"SSH-2\.0-OpenSSH_5\.1p1 Debian-5", r"kippo"],
    "dionaea": [r"dionaea", r"220 DiskStation"],
    "conpot": [r"Siemens, SIMATIC", r"conpot"],
    "glastopf": [r"glastopf", r"Blog Comments"],
    "honeyd": [r"honeyd"],
    "elastichoney": [r"elastichoney"],
    "mailoney": [r"mailoney"],
    "opencanary": [r"opencanary"],
    "t-pot": [r"T-Pot"],
}

# CTF flag patterns
CTF_FLAG_PATTERNS = [
    r"(?:flag|CTF|ctf)\{[^}]+\}",
    r"(?:FLAG|flag)=[A-Za-z0-9+/=]{10,}",
    r"picoCTF\{", r"HTB\{", r"THM\{", r"DUCTF\{",
    r"(?:challenge|puzzle|solve)\s+(?:me|this)",
]

# Typical honeypot port profiles
HONEYPOT_PORT_PROFILES = [
    {21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5900},  # All common ports
    {22, 23, 80, 102, 502, 443, 47808},  # Industrial SCADA honeypot
    {22, 80, 443, 2222, 8080, 8443},  # Web honeypot
]


@dataclass
class HoneypotAnalysis:
    """Result of honeypot analysis for a single host."""
    host: str
    score: float = 0.0  # 0 = definitely real, 1 = definitely honeypot
    is_honeypot: bool = False
    is_ctf: bool = False
    indicators: list[str] = field(default_factory=list)
    weights: dict[str, float] = field(default_factory=dict)


def analyze_banners(host: str, port_results: list[dict]) -> tuple[float, list[str]]:
    """Check service banners against known honeypot signatures."""
    score = 0.0
    indicators = []

    for port_info in port_results:
        banner = port_info.get("banner", "")
        if not banner:
            continue

        # Check known honeypot signatures
        for hp_name, patterns in HONEYPOT_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, banner, re.IGNORECASE):
                    score += 0.4
                    indicators.append(f"Banner matches {hp_name} signature on port {port_info.get('port')}")

        # Check CTF flags
        for pat in CTF_FLAG_PATTERNS:
            if re.search(pat, banner):
                score += 0.3
                indicators.append(f"CTF flag pattern in banner on port {port_info.get('port')}")

        # Check for suspiciously old versions (common in honeypots)
        old_version_patterns = [
            (r"SSH-2\.0-OpenSSH_[345]\.", "Very old SSH version"),
            (r"Apache/1\.", "Apache 1.x (EOL)"),
            (r"Microsoft-IIS/[56]\.", "IIS 5/6 (very old)"),
            (r"vsftpd 2\.3\.4", "Known backdoored vsftpd"),
        ]
        for pat, desc in old_version_patterns:
            if re.search(pat, banner):
                score += 0.15
                indicators.append(f"{desc} on port {port_info.get('port')}")

    return min(score, 1.0), indicators


def analyze_timing(response_times: list[float]) -> tuple[float, list[str]]:
    """Analyze response time patterns — real services vary, honeypots are uniform."""
    score = 0.0
    indicators = []

    if len(response_times) < 3:
        return 0.0, []

    stdev = statistics.stdev(response_times)
    mean = statistics.mean(response_times)

    # Very uniform response times suggest fake services
    if stdev < 0.5 and mean < 10.0 and len(response_times) > 5:
        score += 0.2
        indicators.append(f"Suspiciously uniform response times (σ={stdev:.2f}ms)")

    # All services responding very fast (< 1ms) — unusual for real systems
    if mean < 1.0 and len(response_times) > 10:
        score += 0.15
        indicators.append(f"All services respond in <1ms (avg={mean:.2f}ms)")

    return min(score, 0.4), indicators


def analyze_port_profile(open_ports: set[int], total_scanned: int) -> tuple[float, list[str]]:
    """Analyze the open port profile for honeypot characteristics."""
    score = 0.0
    indicators = []

    port_count = len(open_ports)

    # Too many open ports relative to scan range
    if total_scanned > 100:
        ratio = port_count / total_scanned
        if ratio > 0.5:
            score += 0.3
            indicators.append(f"Abnormally high open port ratio: {ratio:.0%} ({port_count}/{total_scanned})")
        elif ratio > 0.3:
            score += 0.15
            indicators.append(f"High open port ratio: {ratio:.0%}")

    # Match against known honeypot port profiles
    for profile in HONEYPOT_PORT_PROFILES:
        overlap = open_ports & profile
        if len(overlap) >= len(profile) * 0.8:
            score += 0.2
            indicators.append(f"Port profile matches honeypot pattern ({len(overlap)}/{len(profile)} match)")

    # Unusual combination: both Linux and Windows services
    linux_ports = open_ports & {22, 111, 2049, 6379}
    windows_ports = open_ports & {135, 139, 445, 3389}
    if len(linux_ports) >= 2 and len(windows_ports) >= 2:
        score += 0.25
        indicators.append("Mixed Linux/Windows services on same host")

    return min(score, 0.5), indicators


def analyze_service_consistency(port_results: list[dict]) -> tuple[float, list[str]]:
    """Check for OS/service version inconsistencies."""
    score = 0.0
    indicators = []

    os_hints = set()
    for p in port_results:
        banner = p.get("banner", "")
        if "Ubuntu" in banner or "Debian" in banner:
            os_hints.add("linux")
        if "Windows" in banner or "Microsoft" in banner:
            os_hints.add("windows")
        if "FreeBSD" in banner:
            os_hints.add("freebsd")

    if len(os_hints) > 1:
        score += 0.3
        indicators.append(f"Conflicting OS indicators: {os_hints}")

    # Check for identical banners across different service types
    banners = [p.get("banner", "") for p in port_results if p.get("banner")]
    if len(banners) > 3:
        unique = set(banners)
        if len(unique) == 1:
            score += 0.2
            indicators.append("All services return identical banners")

    return min(score, 0.4), indicators


async def analyze_host(host: str, port_results: list[dict], total_scanned: int = 1024) -> HoneypotAnalysis:
    """Perform full honeypot analysis on a host."""
    analysis = HoneypotAnalysis(host=host)

    # 1. Banner analysis
    banner_score, banner_indicators = analyze_banners(host, port_results)
    analysis.weights["banners"] = banner_score
    analysis.indicators.extend(banner_indicators)

    # 2. Timing analysis
    times = [p.get("response_time_ms", 0) for p in port_results if p.get("response_time_ms")]
    timing_score, timing_indicators = analyze_timing(times)
    analysis.weights["timing"] = timing_score
    analysis.indicators.extend(timing_indicators)

    # 3. Port profile analysis
    open_ports = {p["port"] for p in port_results if p.get("state") == "open"}
    profile_score, profile_indicators = analyze_port_profile(open_ports, total_scanned)
    analysis.weights["port_profile"] = profile_score
    analysis.indicators.extend(profile_indicators)

    # 4. Service consistency
    consistency_score, consistency_indicators = analyze_service_consistency(port_results)
    analysis.weights["consistency"] = consistency_score
    analysis.indicators.extend(consistency_indicators)

    # Calculate weighted composite score
    weights = {"banners": 0.35, "timing": 0.15, "port_profile": 0.25, "consistency": 0.25}
    analysis.score = sum(
        analysis.weights.get(k, 0) * w for k, w in weights.items()
    )
    analysis.score = min(analysis.score, 1.0)
    analysis.is_honeypot = analysis.score >= 0.5

    # CTF detection
    for p in port_results:
        banner = p.get("banner", "")
        for pat in CTF_FLAG_PATTERNS:
            if re.search(pat, banner):
                analysis.is_ctf = True
                break

    if analysis.is_honeypot:
        logger.warning(f"⚠ Honeypot detected: {host} (score={analysis.score:.2f})")
    if analysis.is_ctf:
        logger.warning(f"🚩 CTF target detected: {host}")

    return analysis


async def check_honeypots(scan_id: str = "", **kwargs) -> dict[str, Any]:
    """Main entry point (called by orchestrator after network scan)."""
    # This would normally read results from DB; for now return structure
    logger.info("Honeypot detection analysis running...")
    return {"analyzed": 0, "honeypots_detected": 0, "ctfs_detected": 0, "results": []}

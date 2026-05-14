"""
HEAVEN — CTF Flag Extractor & Solver
Automatically identifies CTF environments, extracts flags from banners/responses,
and provides structured answers. Cross-platform.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("recon.ctf")

# Comprehensive CTF flag patterns
FLAG_PATTERNS = [
    # Standard CTF formats
    (r"(flag\{[^}]+\})", "generic"),
    (r"(CTF\{[^}]+\})", "generic"),
    (r"(ctf\{[^}]+\})", "generic"),
    # Platform-specific
    (r"(picoCTF\{[^}]+\})", "picoCTF"),
    (r"(HTB\{[^}]+\})", "HackTheBox"),
    (r"(THM\{[^}]+\})", "TryHackMe"),
    (r"(DUCTF\{[^}]+\})", "DownUnderCTF"),
    (r"(CSAW\{[^}]+\})", "CSAW"),
    (r"(TUCTF\{[^}]+\})", "TUCTF"),
    (r"(utflag\{[^}]+\})", "UTCTF"),
    (r"(bctf\{[^}]+\})", "BCTF"),
    (r"(defcon\{[^}]+\})", "DEFCON"),
    (r"(google\{[^}]+\})", "GoogleCTF"),
    (r"(SECCON\{[^}]+\})", "SECCON"),
    (r"(MetaCTF\{[^}]+\})", "MetaCTF"),
    (r"(justCTF\{[^}]+\})", "justCTF"),
    (r"(RITSEC\{[^}]+\})", "RITSEC"),
    # Base64-encoded flags
    (r"([A-Za-z0-9+/]{20,}={0,2})", "base64_candidate"),
    # Hex-encoded flags
    (r"((?:0x)?[0-9a-fA-F]{32,})", "hex_candidate"),
    # Hash-like values (MD5, SHA)
    (r"FLAG[=:\s]+([a-fA-F0-9]{32})", "md5_flag"),
    (r"FLAG[=:\s]+([a-fA-F0-9]{40})", "sha1_flag"),
    (r"FLAG[=:\s]+([a-fA-F0-9]{64})", "sha256_flag"),
]


@dataclass
class CapturedFlag:
    """A captured CTF flag with metadata."""
    flag: str
    platform: str = "unknown"
    source: str = ""          # Where it was found
    source_type: str = ""     # banner, http_response, file, header
    host: str = ""
    port: int = 0
    decoded_value: str = ""   # If it was encoded
    confidence: float = 1.0


@dataclass
class CTFAnalysis:
    """Complete CTF analysis results."""
    is_ctf_environment: bool = False
    flags: list[CapturedFlag] = field(default_factory=list)
    ctf_indicators: list[str] = field(default_factory=list)
    platform_guess: str = "unknown"


class CTFFlagExtractor:
    """Extract and decode CTF flags from all scan data."""

    def __init__(self):
        self.captured_flags: list[CapturedFlag] = []
        self.seen_flags: set[str] = set()

    def extract_from_text(self, text: str, source: str = "",
                          host: str = "", port: int = 0,
                          source_type: str = "unknown") -> list[CapturedFlag]:
        """Extract CTF flags from arbitrary text content."""
        flags = []

        for pattern, platform in FLAG_PATTERNS:
            if platform in ("base64_candidate", "hex_candidate"):
                continue  # Handle these separately
            for match in re.finditer(pattern, text, re.IGNORECASE):
                flag_text = match.group(1)
                if flag_text in self.seen_flags:
                    continue
                self.seen_flags.add(flag_text)
                flag = CapturedFlag(
                    flag=flag_text, platform=platform,
                    source=source, source_type=source_type,
                    host=host, port=port,
                )
                flags.append(flag)
                logger.info(f"🚩 FLAG CAPTURED: {flag_text} (platform={platform}, source={source})")

        # Try decoding base64 strings for hidden flags
        b64_flags = self._extract_encoded_flags(text, source, host, port, source_type)
        flags.extend(b64_flags)

        self.captured_flags.extend(flags)
        return flags

    def extract_from_banners(self, host: str, port_results: list[dict]) -> list[CapturedFlag]:
        """Extract flags from service banners."""
        flags = []
        for p in port_results:
            banner = p.get("banner", "")
            if banner:
                found = self.extract_from_text(
                    banner, source=f"{host}:{p.get('port', 0)}",
                    host=host, port=p.get("port", 0),
                    source_type="banner",
                )
                flags.extend(found)
        return flags

    def extract_from_http_response(self, url: str, headers: dict,
                                    body: str, host: str = "") -> list[CapturedFlag]:
        """Extract flags from HTTP response headers and body."""
        flags = []

        # Check response headers
        for header_name, header_value in headers.items():
            found = self.extract_from_text(
                str(header_value), source=f"{url} (header: {header_name})",
                host=host, source_type="http_header",
            )
            flags.extend(found)

        # Check response body
        found = self.extract_from_text(
            body, source=url, host=host, source_type="http_response",
        )
        flags.extend(found)

        # Check HTML comments for hidden flags
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        for comment in comments:
            found = self.extract_from_text(
                comment, source=f"{url} (HTML comment)",
                host=host, source_type="html_comment",
            )
            flags.extend(found)

        # Check JavaScript for embedded flags
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE)
        for script in scripts:
            found = self.extract_from_text(
                script, source=f"{url} (JavaScript)",
                host=host, source_type="javascript",
            )
            flags.extend(found)

        return flags

    def _extract_encoded_flags(self, text: str, source: str,
                                host: str, port: int,
                                source_type: str) -> list[CapturedFlag]:
        """Try to decode base64/hex encoded flags."""
        flags = []

        # Base64 candidates
        b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
        for b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                for pattern, platform in FLAG_PATTERNS:
                    if platform in ("base64_candidate", "hex_candidate"):
                        continue
                    if re.search(pattern, decoded, re.IGNORECASE):
                        flag_match = re.search(pattern, decoded, re.IGNORECASE)
                        if flag_match is None:
                            continue
                        flag_text = flag_match.group(1)
                        if flag_text not in self.seen_flags:
                            self.seen_flags.add(flag_text)
                            flags.append(CapturedFlag(
                                flag=flag_text, platform=platform,
                                source=source, source_type=f"{source_type}_base64",
                                host=host, port=port, decoded_value=decoded,
                            ))
                            logger.info(f"🚩 ENCODED FLAG DECODED: {flag_text} (base64)")
            except Exception:
                pass

        # Hex candidates
        hex_matches = re.findall(r"(?:0x)?([0-9a-fA-F]{32,})", text)
        for hex_str in hex_matches:
            try:
                decoded = binascii.unhexlify(hex_str).decode("utf-8", errors="replace")
                for pattern, platform in FLAG_PATTERNS:
                    if platform in ("base64_candidate", "hex_candidate"):
                        continue
                    if re.search(pattern, decoded, re.IGNORECASE):
                        flag_match = re.search(pattern, decoded, re.IGNORECASE)
                        if flag_match is None:
                            continue
                        flag_text = flag_match.group(1)
                        if flag_text not in self.seen_flags:
                            self.seen_flags.add(flag_text)
                            flags.append(CapturedFlag(
                                flag=flag_text, platform=platform,
                                source=source, source_type=f"{source_type}_hex",
                                host=host, port=port, decoded_value=decoded,
                            ))
                            logger.info(f"🚩 ENCODED FLAG DECODED: {flag_text} (hex)")
            except Exception:
                pass

        return flags

    def detect_ctf_environment(self, host_results: list[dict]) -> CTFAnalysis:
        """Analyze scan results to determine if target is a CTF environment."""
        analysis = CTFAnalysis()
        indicators = []

        for host in host_results:
            ports = host.get("open_ports", [])
            for p in ports:
                banner = p.get("banner", "")

                # CTF platform signatures
                ctf_signatures = [
                    (r"(?:capture|ctf|challenge)", "CTF keyword in banner"),
                    (r"(?:HTB|HackTheBox)", "HackTheBox signature"),
                    (r"(?:TryHackMe|THM)", "TryHackMe signature"),
                    (r"(?:root@|kali|parrot)", "Offensive OS indicator"),
                    (r"(?:Metasploitable|DVWA|WebGoat|Juice.?Shop)", "Vulnerable-by-design app"),
                    (r"vulnhub", "VulnHub signature"),
                ]
                for pat, desc in ctf_signatures:
                    if re.search(pat, banner, re.IGNORECASE):
                        indicators.append(f"{desc} on {host.get('host')}:{p.get('port')}")

            # Unusually many services = lab/CTF
            if len(ports) > 20:
                indicators.append(f"Unusually high port count ({len(ports)}) — possible lab")

        analysis.ctf_indicators = indicators
        analysis.is_ctf_environment = len(indicators) >= 2
        analysis.flags = self.captured_flags

        if analysis.is_ctf_environment:
            logger.info(f"🎯 CTF environment detected — {len(indicators)} indicators, {len(self.captured_flags)} flags captured")

        return analysis

    def summary(self) -> dict[str, Any]:
        """Return a summary of all captured flags."""
        return {
            "total_flags": len(self.captured_flags),
            "flags": [
                {
                    "flag": f.flag,
                    "platform": f.platform,
                    "source": f.source,
                    "source_type": f.source_type,
                    "host": f.host,
                    "port": f.port,
                    "decoded": f.decoded_value if f.decoded_value else None,
                }
                for f in self.captured_flags
            ],
            "platforms": list(set(f.platform for f in self.captured_flags)),
        }

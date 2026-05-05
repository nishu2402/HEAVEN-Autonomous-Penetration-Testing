"""
HEAVEN — Input Sanitizer & Rate Limiter
Validates and sanitizes all scan targets to prevent self-exploitation.
Blocks scanning of reserved/private ranges unless explicitly allowed.
Rate limiting per user/API key.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

from heaven.utils.logger import get_logger

logger = get_logger("security.sanitizer")


# Reserved/dangerous IP ranges that should never be scanned by default
BLOCKED_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),        # This network
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),          # IPv6 multicast
]

# Localhost patterns that could cause self-exploitation
LOCALHOST_PATTERNS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "127.0.0.0/8", "0177.0.0.1", "0x7f000001",
    "2130706433", "127.1", "127.0.1",
]

# Dangerous URL schemes
BLOCKED_SCHEMES = {"file", "ftp", "gopher", "dict", "ldap", "tftp"}

# Max target limits
MAX_IPS_PER_SCAN = 65536
MAX_URLS_PER_SCAN = 10000
MAX_PORT_RANGE = 65535

# SQL/command injection patterns in target inputs
INJECTION_PATTERNS = [
    r"[;|&`$]",               # Command injection
    r"(?i)(union\s+select|drop\s+table|insert\s+into)",  # SQL injection
    r"<script",               # XSS
    r"\.\./",                 # Path traversal
    r"%00",                   # Null byte
]


@dataclass
class SanitizationResult:
    valid: bool = True
    sanitized_value: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class InputSanitizer:
    """
    Validates and sanitizes all user-supplied scan inputs.
    Prevents SSRF against HEAVEN's own infrastructure.
    """

    def __init__(self, allow_private: bool = True, allow_localhost: bool = False):
        self._allow_private = allow_private
        self._allow_localhost = allow_localhost

    def sanitize_ip(self, ip_str: str) -> SanitizationResult:
        result = SanitizationResult(sanitized_value=ip_str.strip())
        # Check for injection
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, ip_str):
                result.valid = False
                result.errors.append(f"Injection pattern detected in IP input: {pattern}")
                return result
        try:
            if "/" in ip_str:
                network = ipaddress.ip_network(ip_str.strip(), strict=False)
                if network.num_addresses > MAX_IPS_PER_SCAN:
                    result.valid = False
                    result.errors.append(f"Network too large: {network.num_addresses} addresses (max {MAX_IPS_PER_SCAN})")
                    return result
                ip_obj = network.network_address
            else:
                ip_obj = ipaddress.ip_address(ip_str.strip())

            # Check localhost
            if not self._allow_localhost and ip_obj.is_loopback:
                result.valid = False
                result.errors.append("Localhost scanning is disabled for security")
                return result
            # Check private ranges
            if not self._allow_private and ip_obj.is_private:
                result.valid = False
                result.errors.append("Private range scanning is disabled")
                return result
            # Check blocked ranges
            for blocked in BLOCKED_RANGES:
                if ip_obj in blocked:
                    result.valid = False
                    result.errors.append(f"IP {ip_str} is in blocked range {blocked}")
                    return result

        except ValueError:
            result.valid = False
            result.errors.append(f"Invalid IP address: {ip_str}")
        return result

    def sanitize_url(self, url: str) -> SanitizationResult:
        result = SanitizationResult(sanitized_value=url.strip())
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, url.split("?")[0]):  # Check base URL only
                result.valid = False
                result.errors.append(f"Injection pattern in URL: {pattern}")
                return result
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                result.sanitized_value = f"https://{url}"
                parsed = urlparse(result.sanitized_value)
                result.warnings.append("No scheme specified — defaulting to HTTPS")
            if parsed.scheme in BLOCKED_SCHEMES:
                result.valid = False
                result.errors.append(f"Blocked URL scheme: {parsed.scheme}")
                return result
            if not parsed.hostname:
                result.valid = False
                result.errors.append("URL has no hostname")
                return result
            hostname = parsed.hostname.lower()
            if not self._allow_localhost:
                if hostname in LOCALHOST_PATTERNS or hostname == "localhost":
                    result.valid = False
                    result.errors.append("Localhost URLs are blocked for security")
                    return result
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_loopback:
                        result.valid = False
                        result.errors.append("Loopback IP in URL is blocked")
                        return result
                except ValueError:
                    pass  # Not an IP — that's fine
        except Exception as e:
            result.valid = False
            result.errors.append(f"Invalid URL: {e}")
        return result

    def sanitize_port_range(self, port_range: str) -> SanitizationResult:
        result = SanitizationResult(sanitized_value=port_range.strip())
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, port_range):
                result.valid = False
                result.errors.append("Injection pattern in port range")
                return result
        try:
            if "-" in port_range:
                parts = port_range.split("-")
                start, end = int(parts[0]), int(parts[1])
                if not (0 <= start <= MAX_PORT_RANGE and 0 <= end <= MAX_PORT_RANGE):
                    result.valid = False
                    result.errors.append(f"Port range out of bounds: {start}-{end}")
                if start > end:
                    result.valid = False
                    result.errors.append(f"Invalid port range: start ({start}) > end ({end})")
            else:
                port = int(port_range)
                if not (0 <= port <= MAX_PORT_RANGE):
                    result.valid = False
                    result.errors.append(f"Port out of range: {port}")
        except ValueError:
            result.valid = False
            result.errors.append(f"Invalid port range format: {port_range}")
        return result

    def sanitize_targets(self, targets: dict) -> dict:
        """Sanitize all targets in a scan configuration."""
        errors = []
        warnings = []
        sanitized = {}

        # IPs
        safe_ips = []
        for ip in targets.get("ips", []):
            r = self.sanitize_ip(ip)
            if r.valid:
                safe_ips.append(r.sanitized_value)
            else:
                errors.extend(r.errors)
            warnings.extend(r.warnings)
        sanitized["ips"] = safe_ips

        # URLs
        safe_urls = []
        for url in targets.get("urls", []):
            r = self.sanitize_url(url)
            if r.valid:
                safe_urls.append(r.sanitized_value)
            else:
                errors.extend(r.errors)
            warnings.extend(r.warnings)
        sanitized["urls"] = safe_urls

        # Port range
        port_range = targets.get("ports", "1-1024")
        r = self.sanitize_port_range(port_range)
        if r.valid:
            sanitized["ports"] = r.sanitized_value
        else:
            errors.extend(r.errors)
            sanitized["ports"] = "1-1024"

        # Pass through other fields
        for key in targets:
            if key not in ("ips", "urls", "ports"):
                sanitized[key] = targets[key]

        sanitized["_validation"] = {"errors": errors, "warnings": warnings, "valid": len(errors) == 0}
        if errors:
            logger.warning(f"Target sanitization: {len(errors)} errors found")
        return sanitized


class RateLimiter:
    """Token bucket rate limiter per user/API key."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self._max_requests = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._buckets[key]
        # Remove expired entries
        self._buckets[key] = [t for t in bucket if now - t < self._window]
        if len(self._buckets[key]) >= self._max_requests:
            logger.warning(f"Rate limit exceeded for {key}")
            return False
        self._buckets[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.time()
        active = [t for t in self._buckets.get(key, []) if now - t < self._window]
        return max(0, self._max_requests - len(active))

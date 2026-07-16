"""
HEAVEN — Evasion Engine
Advanced IDS/IPS/WAF/Honeypot evasion techniques for stealth scanning.
Implements packet-level obfuscation, timing randomisation, and fingerprint masking.
Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, replace
from enum import Enum

from heaven.utils.logger import get_logger

logger = get_logger("evasion")

# All evasion randomness (timing jitter, User-Agent rotation, scan-order shuffling,
# decoy generation) is drawn from a CSPRNG rather than the default Mersenne-Twister.
# Predictable PRNG patterns can be fingerprinted by IDS/WAF anomaly detection, so an
# os.urandom-backed source makes the scanner harder to profile — and it satisfies
# HEAVEN's own SAST rule `heaven.python.weak-random-for-crypto`.
_rng = secrets.SystemRandom()


class StealthLevel(str, Enum):
    """Scan stealth profile — higher = slower but harder to detect."""
    AGGRESSIVE = "aggressive"    # Fast, no evasion (lab use)
    NORMAL = "normal"            # Moderate throttle
    STEALTH = "stealth"          # Slow + randomised timing
    PARANOID = "paranoid"        # Maximum evasion, very slow


@dataclass
class EvasionProfile:
    """Active evasion configuration applied to all scan operations."""
    stealth_level: StealthLevel = StealthLevel.NORMAL

    # Timing evasion
    min_delay_ms: float = 0.0
    max_delay_ms: float = 0.0
    jitter_pct: float = 0.0            # Random ± percentage on delays

    # Connection evasion
    source_port_randomise: bool = False
    ttl_randomise: bool = False
    tcp_window_mask: bool = False       # Mask TCP window size to avoid OS fingerprint

    # HTTP evasion
    rotate_user_agents: bool = True
    randomise_headers: bool = True
    fragment_requests: bool = False

    # Banner grab evasion
    banner_delay_ms: float = 0.0       # Delay before banner read (avoids IDS trigger)
    close_gracefully: bool = True

    # Decoy and fragmentation
    max_concurrent: int = 500
    scan_order: str = "random"         # random, sequential, reverse

    # Honeypot avoidance
    auto_skip_honeypots: bool = True
    honeypot_threshold: float = 0.5

    def to_dict(self) -> dict:
        return {
            "stealth": self.stealth_level.value,
            "delay_range": f"{self.min_delay_ms}-{self.max_delay_ms}ms",
            "jitter": f"{self.jitter_pct}%",
            "ua_rotation": self.rotate_user_agents,
            "max_concurrent": self.max_concurrent,
            "scan_order": self.scan_order,
            "honeypot_skip": self.auto_skip_honeypots,
        }


# ── Stealth Profiles ──

STEALTH_PROFILES: dict[StealthLevel, EvasionProfile] = {
    StealthLevel.AGGRESSIVE: EvasionProfile(
        stealth_level=StealthLevel.AGGRESSIVE,
        min_delay_ms=0, max_delay_ms=0, jitter_pct=0,
        max_concurrent=1000, scan_order="sequential",
        rotate_user_agents=False, randomise_headers=False,
        auto_skip_honeypots=False,
    ),
    StealthLevel.NORMAL: EvasionProfile(
        stealth_level=StealthLevel.NORMAL,
        min_delay_ms=10, max_delay_ms=50, jitter_pct=20,
        max_concurrent=500, scan_order="random",
        source_port_randomise=True, banner_delay_ms=100,
    ),
    StealthLevel.STEALTH: EvasionProfile(
        stealth_level=StealthLevel.STEALTH,
        min_delay_ms=100, max_delay_ms=500, jitter_pct=40,
        max_concurrent=50, scan_order="random",
        source_port_randomise=True, ttl_randomise=True,
        tcp_window_mask=True, banner_delay_ms=500,
        randomise_headers=True, fragment_requests=True,
    ),
    StealthLevel.PARANOID: EvasionProfile(
        stealth_level=StealthLevel.PARANOID,
        min_delay_ms=500, max_delay_ms=3000, jitter_pct=60,
        max_concurrent=10, scan_order="random",
        source_port_randomise=True, ttl_randomise=True,
        tcp_window_mask=True, banner_delay_ms=2000,
        randomise_headers=True, fragment_requests=True,
    ),
}


def get_profile(level: StealthLevel = StealthLevel.NORMAL) -> EvasionProfile:
    """Get a pre-configured evasion profile."""
    return STEALTH_PROFILES[level]


def resolve_stealth_level(level: str | StealthLevel) -> StealthLevel:
    """Coerce a stealth-level string (case-insensitive) or enum to a StealthLevel.

    The whole tool passes stealth around as a plain string ("paranoid" / "stealth"
    / "normal" / "aggressive") — from the CLI ``--stealth`` choice and the web
    launcher's 1-4 selector. This is the one place that turns that string into the
    typed enum; an unknown/empty value falls back to NORMAL so a stray config can
    never crash a scan.
    """
    if isinstance(level, StealthLevel):
        return level
    try:
        return StealthLevel(str(level).strip().lower())
    except ValueError:
        return StealthLevel.NORMAL


def profile_for(level: str | StealthLevel) -> EvasionProfile:
    """Return the fully-configured evasion profile for a stealth level string/enum.

    ALWAYS prefer this over ``EvasionProfile(stealth_level=...)`` when you have a
    level and want it to actually take effect. The bare constructor only sets the
    ``stealth_level`` label and leaves every timing/concurrency/fragmentation field
    at its zero default — i.e. *no evasion at all* — which silently defeats stealth
    mode regardless of which level was selected. Returns a fresh copy so callers
    (notably the long-lived API server that runs many scans per process) can never
    mutate the shared ``STEALTH_PROFILES`` template.
    """
    return replace(get_profile(resolve_stealth_level(level)))


class EvasionEngine:
    """Stateful wrapper around EvasionProfile for scanner integration."""

    def __init__(self, profile: EvasionProfile):
        self.profile = profile

    async def apply_evasion_delay(self) -> None:
        await evasion_delay(self.profile)

    def get_http_headers(self, target_host: str = "") -> dict[str, str]:
        return build_evasive_headers(self.profile, target_host)


# ── Timing Evasion ──

async def evasion_delay(profile: EvasionProfile) -> None:
    """Apply randomised inter-request delay based on evasion profile."""
    if profile.max_delay_ms <= 0:
        return
    base = _rng.uniform(profile.min_delay_ms, profile.max_delay_ms)
    jitter = base * (profile.jitter_pct / 100.0) * _rng.uniform(-1, 1)
    delay_ms = max(0, base + jitter)
    await asyncio.sleep(delay_ms / 1000.0)


# ── User-Agent Rotation ──

USER_AGENTS = [
    # Chrome (Windows, macOS, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Bots (for blending into normal traffic)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


def get_random_user_agent() -> str:
    """Return a random realistic User-Agent string."""
    return _rng.choice(USER_AGENTS)


def build_evasive_headers(profile: EvasionProfile, target_host: str = "") -> dict[str, str]:
    """Build HTTP headers designed to avoid WAF/IDS detection."""
    headers = {
        "User-Agent": get_random_user_agent() if profile.rotate_user_agents else USER_AGENTS[0],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": _rng.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.5"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": "1",
    }

    if profile.randomise_headers:
        # Add realistic browser headers in random order
        optional_headers = {
            "Sec-Fetch-Dest": _rng.choice(["document", "empty", "image"]),
            "Sec-Fetch-Mode": _rng.choice(["navigate", "cors", "no-cors"]),
            "Sec-Fetch-Site": _rng.choice(["none", "same-origin", "cross-site"]),
            "Sec-Ch-Ua-Platform": _rng.choice(['"Windows"', '"macOS"', '"Linux"']),
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": _rng.choice(["no-cache", "max-age=0"]),
        }
        # Include random subset
        for key, val in optional_headers.items():
            if _rng.random() > 0.3:
                headers[key] = val

    if target_host:
        headers["Host"] = target_host

    return headers


# ── Port Scan Order Randomisation ──

def randomise_scan_targets(ports: list[int], hosts: list[str], profile: EvasionProfile) -> list[tuple[str, int]]:
    """Generate scan target order based on evasion profile."""
    targets = [(h, p) for h in hosts for p in ports]

    if profile.scan_order == "random":
        _rng.shuffle(targets)
    elif profile.scan_order == "reverse":
        targets.reverse()
    # "sequential" = default order

    return targets


# ── IDS Signature Evasion for Payloads ──

class PayloadObfuscator:
    """Obfuscate vulnerability test payloads to bypass WAF/IDS pattern matching."""

    @staticmethod
    def sqli_obfuscate(payload: str) -> list[str]:
        """Generate multiple SQLi payload variants to evade signature detection."""
        variants = [payload]  # Original

        # Case alternation: ' AND '1'='1 → ' aNd '1'='1
        case_alt = ""
        for i, c in enumerate(payload):
            case_alt += c.upper() if i % 2 else c.lower()
        variants.append(case_alt)

        # Comment insertion: AND → A/**/ND
        commented = payload.replace("AND", "A/**/ND").replace("OR", "O/**/R")
        variants.append(commented)

        # URL encoding of spaces: ' AND ' → '%20AND%20'
        url_encoded = payload.replace(" ", "%20")
        variants.append(url_encoded)

        # Double URL encoding
        double_encoded = payload.replace("'", "%2527").replace(" ", "%2520")
        variants.append(double_encoded)

        # Tab/newline substitution for spaces
        tab_variant = payload.replace(" ", "\t")
        variants.append(tab_variant)

        # Inline comment variant: ' AND/*comment*/1=1
        inline = payload.replace(" AND ", "/**/AND/**/").replace(" OR ", "/**/OR/**/")
        variants.append(inline)

        # Unicode variant
        unicode_variant = payload.replace("'", "\u0027").replace(" ", "\u0020")
        variants.append(unicode_variant)

        return list(set(variants))

    @staticmethod
    def xss_obfuscate(payload: str) -> list[str]:
        """Generate XSS payload variants for WAF bypass."""
        variants = [payload]

        # Mixed-case tag variation for WAF bypass
        case_variant = payload.replace("<s", "<S").replace("<i", "<I").replace("<a", "<A")
        variants.append(case_variant)

        # HTML entity encoding
        html_entities = payload.replace("<", "&lt;").replace(">", "&gt;")
        variants.append(html_entities)

        # Event handler variants
        if "<img" in payload.lower():
            variants.append(payload.replace("onerror", "OnErRoR"))
            variants.append(payload.replace("<img", "<IMG"))

        # SVG-based bypass
        variants.append(payload.replace("<img", "<svg").replace("onerror", "onload"))

        # JavaScript protocol variants
        variants.append(payload.replace("javascript:", "jAvAsCrIpT:"))
        variants.append(payload.replace("javascript:", "&#106;avascript:"))

        return list(set(variants))

    @staticmethod
    def ssrf_obfuscate(url: str) -> list[str]:
        """Generate SSRF URL variants to bypass allowlists/denylists."""
        variants = [url]

        # IP address encoding variants for 127.0.0.1
        if "127.0.0.1" in url:
            variants.append(url.replace("127.0.0.1", "0x7f000001"))        # Hex
            variants.append(url.replace("127.0.0.1", "2130706433"))        # Decimal
            variants.append(url.replace("127.0.0.1", "0177.0.0.1"))       # Octal
            variants.append(url.replace("127.0.0.1", "127.1"))            # Short form
            variants.append(url.replace("127.0.0.1", "127.0.1"))          # Another short
            variants.append(url.replace("127.0.0.1", "0"))                # Zero
            variants.append(url.replace("127.0.0.1", "[::1]"))            # IPv6
            variants.append(url.replace("127.0.0.1", "localhost"))

        # AWS metadata endpoint variants
        if "169.254.169.254" in url:
            variants.append(url.replace("169.254.169.254", "0xa9fea9fe"))
            variants.append(url.replace("169.254.169.254", "2852039166"))
            variants.append(url.replace("169.254.169.254", "[::ffff:169.254.169.254]"))

        # URL encoding
        variants.append(url.replace("://", "%3A%2F%2F"))

        # Double URL encoding
        variants.append(url.replace("://", "%253A%252F%252F"))

        # DNS rebinding placeholder
        variants.append(url.replace("127.0.0.1", "spoofed.burpcollaborator.net"))

        return list(set(variants))

    @staticmethod
    def path_traversal_obfuscate(payload: str) -> list[str]:
        """Generate path traversal variants."""
        variants = [payload]
        variants.append(payload.replace("../", "..\\"))
        variants.append(payload.replace("../", "..%2f"))
        variants.append(payload.replace("../", "%2e%2e%2f"))
        variants.append(payload.replace("../", "%2e%2e/"))
        variants.append(payload.replace("../", "..%252f"))
        variants.append(payload.replace("../", "....//"))
        variants.append(payload.replace("../", "..;/"))  # Tomcat bypass
        return list(set(variants))


# ── Network-Level Evasion ──

def randomise_source_port() -> int:
    """Generate a random high source port to avoid fingerprinting."""
    return _rng.randint(49152, 65535)


def randomise_ttl() -> int:
    """Generate a realistic TTL value to mask OS fingerprint."""
    return _rng.choice([64, 128, 255, 60, 62, 63, 126, 127])


def generate_decoy_ips(count: int = 5) -> list[str]:
    """Generate plausible decoy IP addresses for scan obfuscation.
    Note: These are used for logging/display — actual IP spoofing requires raw sockets + root."""
    decoys = []
    for _ in range(count):
        # Generate IPs in common private and public ranges
        first_octet = _rng.choice([10, 172, 192, 203, 198])
        if first_octet == 10:
            ip = f"10.{_rng.randint(0,255)}.{_rng.randint(0,255)}.{_rng.randint(1,254)}"
        elif first_octet == 172:
            ip = f"172.{_rng.randint(16,31)}.{_rng.randint(0,255)}.{_rng.randint(1,254)}"
        elif first_octet == 192:
            ip = f"192.168.{_rng.randint(0,255)}.{_rng.randint(1,254)}"
        else:
            ip = f"{first_octet}.0.{_rng.randint(0,255)}.{_rng.randint(1,254)}"
        decoys.append(ip)
    return decoys


# ── Honeypot Evasion Decision Engine ──

class HoneypotEvasionEngine:
    """Decides whether to continue scanning a target based on honeypot indicators."""

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.flagged_hosts: dict[str, float] = {}  # host → honeypot score
        self.skipped_count = 0

    def record_score(self, host: str, score: float, indicators: list[str]) -> None:
        """Record a honeypot score for a host."""
        self.flagged_hosts[host] = score
        if score >= self.threshold:
            self.skipped_count += 1
            logger.warning(
                f"🛡️ EVASION: Skipping {host} (honeypot score={score:.2f}) — "
                f"indicators: {', '.join(indicators[:3])}"
            )

    def should_scan(self, host: str) -> bool:
        """Check if a host should be scanned (not flagged as honeypot)."""
        score = self.flagged_hosts.get(host, 0.0)
        return score < self.threshold

    def get_safe_targets(self, hosts: list[str]) -> list[str]:
        """Filter out honeypot-flagged hosts from target list."""
        safe = [h for h in hosts if self.should_scan(h)]
        skipped = len(hosts) - len(safe)
        if skipped:
            logger.info(f"🛡️ Filtered {skipped} honeypot targets, {len(safe)} safe targets remaining")
        return safe

    def summary(self) -> dict:
        return {
            "total_flagged": len(self.flagged_hosts),
            "total_skipped": self.skipped_count,
            "threshold": self.threshold,
            "flagged_hosts": {h: round(s, 2) for h, s in self.flagged_hosts.items() if s >= self.threshold},
        }

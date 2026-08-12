"""
HEAVEN — Async TCP/UDP Network Scanner
High-concurrency port scanning with service fingerprinting, banner grabbing,
OS detection heuristics, evasion engine integration, and CTF flag capture.
Uses asyncio with semaphore throttling.
Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import ipaddress
import os
import shutil
import subprocess  # nosec B404 -- fixed argv, no shell (see _nmap_sudo_prefix)
import sys
import time
import xml.etree.ElementTree as ET  # nosec B405 -- only ET.ParseError (a type) is used; all parsing goes through defusedxml below
from dataclasses import dataclass, field
from typing import Any, Optional

# nmap output is ours (we ran the subprocess), but parse it through defusedxml
# anyway — defence in depth costs nothing and a compromised/mitm'd nmap binary
# or a crafted scan target can't turn XML parsing into an XXE on this host.
# ET is still imported for its ParseError type below.
from defusedxml.ElementTree import fromstring as _safe_xml_fromstring

from heaven.recon.evasion_engine import EvasionEngine, profile_for
from heaven.utils.logger import get_logger

logger = get_logger("recon.network")

# Well-known service fingerprints
SERVICE_FINGERPRINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
    # Shared-hosting / cPanel & WHM control-plane ports — extremely common on
    # web hosts (Bluehost, HostGator, etc.) and a real admin-login attack
    # surface. Previously unlabelled, so a scan of a cPanel host showed them (if
    # at all) as generic "unknown".
    2077: "cpanel-webdav", 2078: "cpanel-webdav-ssl",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2095: "webmail", 2096: "webmail-ssl", 2222: "ssh-alt",
}

# UDP probe payloads for common services
UDP_PROBES: dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS version query
    123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 24 + b"\x00\x00\x00\x00\x00\x00\x00\x00",  # NTP
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",  # NetBIOS
}


@dataclass
class PortResult:
    """Result of scanning a single port."""
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = ""
    product: str = ""       # nmap product name, e.g. "OpenSSH", "Apache httpd"
    version: str = ""       # nmap version string, e.g. "8.9p1"
    banner: str = ""        # product + version + extrainfo (human summary)
    extrainfo: str = ""     # nmap extrainfo, e.g. "Ubuntu Linux; protocol 2.0"
    cpe: str = ""
    ttl: int = 0
    response_time_ms: float = 0.0
    fingerprint: dict = field(default_factory=dict)


@dataclass
class HostResult:
    """Aggregated scan result for a host."""
    host: str
    is_alive: bool = False
    open_ports: list[PortResult] = field(default_factory=list)
    os_guess: str = ""
    # How the OS was determined and how much to trust it:
    #   "nmap"      → nmap -O TCP/IP stack fingerprint (authoritative)
    #   "heuristic" → inferred from a single TTL value (indicative only)
    #   ""          → not determined
    os_source: str = ""
    os_accuracy: int = 0    # nmap's own 0-100 confidence for the osmatch
    ttl: int = 0
    scan_time_ms: float = 0.0
    honeypot_indicators: list[str] = field(default_factory=list)
    # ── Layer-2 / device identity ─────────────────────────────────────────────
    # Every value comes straight from nmap and is blank when nmap did not observe
    # it — never fabricated (same contract as os_guess).
    #   mac_address        : from the ARP <address addrtype="mac"> reply. Only
    #                        present when the target is on the SAME local subnet
    #                        AND the scan had raw-socket privileges; empty for any
    #                        routed / remote host (there is no MAC to see).
    #   mac_vendor         : OUI manufacturer nmap resolved for that MAC.
    #   device_name        : the host's name — NetBIOS/SMB computer name (a
    #                        machine's own advertised name) or a reverse-DNS PTR.
    #   device_name_source : "netbios" | "ptr"  (how device_name was learned)
    #   device_type        : device role — nmap -O <osclass type> (fingerprinted)
    #                        or a conservative MAC-vendor category.
    #   device_type_source : "nmap" | "mac-vendor"
    mac_address: str = ""
    mac_vendor: str = ""
    device_name: str = ""
    device_name_source: str = ""
    device_type: str = ""
    device_type_source: str = ""
    # ── Perimeter-defence signal ──────────────────────────────────────────────
    # Port-state tallies used to tell a firewall (drops probes → many 'filtered')
    # apart from a normal host (refuses probes → 'closed'/RST). Both come straight
    # from the nmap parse (0 in the pure-Python connect path, which can't observe
    # the distinction). ``perimeter`` holds the PerimeterVerdict.to_dict() once
    # scan_network has classified the host.
    filtered_ports: int = 0
    closed_ports: int = 0
    perimeter: dict = field(default_factory=dict)


def parse_port_range(port_spec: str) -> list[int]:
    """
    Parse a port specification into a sorted, deduplicated list of valid ports.

    Accepts:
        "80"             -> [80]
        "22,80,443"      -> [22, 80, 443]
        "1-1024"         -> [1, 2, ..., 1024]
        "22,80,1000-1010"-> mix of singles and ranges

    Rules:
        - Ports must be 1..65535. Anything outside is rejected with ValueError.
        - Reversed ranges ("1000-22") are normalized.
        - Whitespace tolerated. Empty parts ("80,,443") tolerated.
        - Duplicates collapsed.
        - "*" or "all" expands to [1..65535] (use with caution).

    Raises:
        ValueError on malformed input or out-of-range ports.
    """
    if not port_spec or not isinstance(port_spec, str):
        raise ValueError("port_spec must be a non-empty string")

    spec = port_spec.strip().lower()
    if spec in ("*", "all"):
        return list(range(1, 65536))

    ports: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue  # tolerate empty segments
        if "-" in part:
            try:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}") from e
            if lo > hi:
                lo, hi = hi, lo
            if lo < 1 or hi > 65535:
                raise ValueError(f"Port range '{part}' outside 1-65535")
            # Cap range expansion to avoid memory blow-up on something like 1-1000000
            if hi - lo > 65535:
                raise ValueError(f"Port range '{part}' too large")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError as e:
                raise ValueError(f"Invalid port '{part}': {e}") from e
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} outside 1-65535")
            ports.add(p)

    if not ports:
        raise ValueError(f"port_spec '{port_spec}' produced no valid ports")
    return sorted(ports)


def guess_os_from_ttl(ttl: int) -> str:
    """Heuristic OS detection based on initial TTL values."""
    if ttl <= 0:
        return "unknown"
    elif ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device/Solaris"
    return "unknown"


# ── OS-fingerprinting privileges ────────────────────────────────────────────
# nmap's -O (TCP/IP stack fingerprint) and its SYN/UDP scans (-sS/-sU) all need
# raw-socket access. Running -O unprivileged makes nmap abort the whole scan
# ("requires root privileges … QUITTING!"), so we only add those flags when we
# are *certain* we have the privileges — as root/Administrator directly, or via
# passwordless sudo. When we can't, we fall back to service/TTL heuristics that
# are always labelled unconfirmed, never presented as a real fingerprint.

@functools.lru_cache(maxsize=1)
def _have_admin_privileges() -> bool:
    """True when this process can run privileged nmap scans without sudo:
    root on POSIX, or an elevated (Administrator) token on Windows."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        try:
            return geteuid() == 0
        except OSError:
            return False
    try:  # Windows: no geteuid — check for an elevated token
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — any failure = assume unprivileged
        return False


@functools.lru_cache(maxsize=1)
def _nmap_sudo_prefix() -> tuple[str, ...]:
    """Return the argv prefix that gives nmap raw-socket privileges via sudo,
    or ``()`` when sudo shouldn't/can't be used.

    Policy comes from ``HEAVEN_NMAP_SUDO``:
        auto (default) — use ``sudo -n nmap`` only when passwordless sudo works
        always         — always prepend ``sudo -n``
        never          — never use sudo

    ``sudo -n`` never prompts: it fails immediately if a password would be
    required, so this neither blocks nor handles a credential. Cached per
    process (the answer can't change mid-run).
    """
    policy = os.environ.get("HEAVEN_NMAP_SUDO", "auto").strip().lower()
    if policy == "never" or _have_admin_privileges():
        return ()  # disabled, or already privileged so sudo is unnecessary
    sudo = shutil.which("sudo")
    if not sudo:
        return ()
    if policy == "always":
        return (sudo, "-n")
    # auto: confirm passwordless sudo actually works, without ever prompting.
    try:
        probe = subprocess.run(  # nosec B603 -- fixed argv, no shell
            [sudo, "-n", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return (sudo, "-n") if probe.returncode == 0 else ()
    except (OSError, subprocess.SubprocessError):
        return ()


@functools.lru_cache(maxsize=1)
def scan_capability() -> dict:
    """Report whether nmap can run *privileged* scans on this host, and — when it
    can't — the exact, platform-correct one-time command to enable them.

    SYN (``-sS``), UDP (``-sU``) and OS fingerprinting (``-O``) all need raw
    sockets. When those are unavailable HEAVEN still finds open ports via a TCP
    connect scan and infers the OS from TTL/service heuristics (always labelled
    unconfirmed), so the scan degrades honestly rather than failing. This exposes
    that state to the CLI/web/report so the operator sees *why* results are
    limited and *how* to unlock the rest — instead of a silent quality drop.

    ``remedy`` is empty when already privileged. Cached: the answer (root token /
    passwordless-sudo availability / platform) can't change mid-process.
    """
    root = _have_admin_privileges()
    via_sudo = bool(_nmap_sudo_prefix())
    capable = root or via_sudo
    if capable:
        remedy = ""
    elif sys.platform == "darwin":
        # macOS has no `setcap`; raw sockets require root. Passwordless sudo for
        # nmap + HEAVEN_NMAP_SUDO=always is the no-per-run-prompt path, and
        # `sudo heaven …` is the zero-setup fallback.
        remedy = (
            "macOS needs root for raw sockets — run `sudo heaven scan …`, or set "
            "up passwordless sudo for nmap and export HEAVEN_NMAP_SUDO=always"
        )
    elif sys.platform.startswith("win"):
        remedy = "run your terminal as Administrator, then re-run the scan"
    else:  # Linux / other *nix: grant nmap the capability once, no per-scan sudo.
        remedy = (
            "grant nmap raw-socket capability once (no sudo per scan): "
            "sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "
            "$(command -v nmap)"
        )
    return {
        "raw_capable": capable,
        "method": "root" if root else ("sudo" if via_sudo else "unprivileged"),
        "os_scan": capable,
        "syn_scan": capable,
        "udp_scan": capable,
        "remedy": remedy,
    }


_PRIVILEGE_HINT_LOGGED = False


def _log_privilege_hint_once() -> None:
    """Tell the operator, exactly once per run, how to unlock authoritative OS
    fingerprinting instead of the heuristic fallback."""
    global _PRIVILEGE_HINT_LOGGED
    if _PRIVILEGE_HINT_LOGGED:
        return
    _PRIVILEGE_HINT_LOGGED = True
    logger.info(
        "nmap OS fingerprinting (-O) and SYN/UDP scans need raw-socket "
        "privileges; running unprivileged, so OS is inferred from service/TTL "
        "heuristics and labelled 'unconfirmed'. To enable: %s",
        scan_capability()["remedy"],
    )


def _os_name_from_cpe(cpe: str) -> str:
    """Map an OS-level CPE (``cpe:/o:…`` / ``cpe:2.3:o:…``) to a friendly OS
    name. Returns '' for application CPEs or anything we can't confidently map —
    we never guess an OS we didn't actually see evidence for."""
    c = cpe.lower()
    # OS part marker differs by CPE form: URI is `cpe:/o:…`, 2.3 is `cpe:2.3:o:…`
    if "/o:" not in c and ":o:" not in c:
        return ""
    if "microsoft:windows" in c or "microsoft" in c or "windows" in c:
        return "Windows"
    if "linux" in c:
        return "Linux"
    if "apple:mac" in c or "mac_os" in c or "macos" in c or "apple:iphone" in c:
        return "macOS"
    if "freebsd" in c:
        return "FreeBSD"
    if "openbsd" in c:
        return "OpenBSD"
    if "netbsd" in c:
        return "NetBSD"
    if "cisco:ios" in c or ":o:cisco" in c:
        return "Cisco IOS"
    if "solaris" in c or "sunos" in c:
        return "Solaris"
    if "vmware:esxi" in c or "esxi" in c:
        return "VMware ESXi"
    return ""


def _os_from_service_evidence(ostypes: list[str], os_cpes: list[str]) -> str:
    """Infer the OS from nmap's *service-detection* evidence — the ``ostype``
    attribute and OS-level CPEs that ``-sV`` reports without needing root.

    This is a real, observed signal (e.g. an OpenSSH banner advertising Ubuntu),
    far more specific than a TTL bucket, but it reflects what the *service*
    claims rather than a stack fingerprint — so callers still label it as an
    unconfirmed heuristic. Returns '' when there's no evidence at all.
    """
    from collections import Counter

    names = [o.strip() for o in ostypes if o and o.strip()]
    for cpe in os_cpes:
        name = _os_name_from_cpe(cpe)
        if name:
            names.append(name)
    if not names:
        return ""
    return Counter(names).most_common(1)[0][0]


# Conservative OUI-vendor → device-type map. Keyed on a lowercased fragment of
# the vendor string nmap resolves from the MAC's OUI. The OUI is a real,
# manufacturer-assigned identifier, but it names the *maker*, not a proven device
# role — so callers label anything derived here "(per MAC vendor)" and never as a
# stack fingerprint. Deliberately small and high-signal: an unrecognised vendor
# returns '' rather than a guess. Order matters (most-specific fragment first).
_MAC_VENDOR_DEVICE_TYPES: list[tuple[str, str]] = [
    ("raspberry pi", "single-board computer"),
    ("hikvision", "IP camera"),
    ("dahua", "IP camera"),
    ("axis communications", "IP camera"),
    ("ubiquiti", "network equipment"),
    ("mikrotik", "network equipment"),
    ("juniper", "network equipment"),
    ("aruba", "network equipment"),
    ("fortinet", "network equipment"),
    ("palo alto", "network equipment"),
    ("netgear", "network equipment"),
    ("tp-link", "network equipment"),
    ("d-link", "network equipment"),
    ("cisco", "network equipment"),
    ("brother", "printer"),
    ("lexmark", "printer"),
    ("xerox", "printer"),
    ("epson", "printer"),
    ("espressif", "IoT device"),
    ("nest labs", "IoT device"),
    ("philips lighting", "IoT device"),
    ("signify", "IoT device"),
    ("sonos", "media device"),
    ("roku", "media device"),
    ("vmware", "virtual machine"),
    ("apple", "Apple device"),
]


def _device_type_from_mac_vendor(vendor: str) -> str:
    """Map a MAC OUI vendor to a conservative device category; '' when unknown.

    A real, manufacturer-assigned signal — but a hint about the *maker*, so the
    caller labels it "(per MAC vendor)" and never as a fingerprint. An
    unrecognised vendor returns '' (we never guess a role we didn't see evidence
    for).
    """
    v = (vendor or "").strip().lower()
    if not v:
        return ""
    for frag, dtype in _MAC_VENDOR_DEVICE_TYPES:
        if frag in v:
            return dtype
    return ""


def _netbios_name_from_script(script_id: str, output: str) -> str:
    """Pull a device / computer name out of an nmap host-script's output; '' when
    none is present.

    Handles the two default host scripts that advertise a machine's own name:
    ``nbstat`` (``NetBIOS name: WIN-ABC123``) and ``smb-os-discovery``
    (``NetBIOS computer name: WIN-ABC`` / ``Computer name: host.example.com``).
    Any other script, or output we can't confidently parse, yields '' — a name is
    never invented. The result is trimmed of a trailing NetBIOS/AD suffix.
    """
    import re

    sid = (script_id or "").lower()
    text = output or ""
    if sid == "nbstat":
        m = re.search(r"NetBIOS name:\s*([^,\n<]+)", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    if sid == "smb-os-discovery":
        for pat in (r"NetBIOS computer name:\s*([^\n\x00]+)",
                    r"Computer name:\s*([^\n\x00]+)"):
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1).strip().rstrip(".")
    return ""


def _build_nmap_port_spec(ports: list[int]) -> str:
    """
    Convert a sorted list of port numbers into a compact nmap port spec string.
    Contiguous runs become ranges (e.g. [1,2,3,80] → '1-3,80') to keep the
    command line short without accidentally scanning ports outside the requested set.
    """
    if not ports:
        return ""
    sorted_ports = sorted(set(ports))
    segments: list[str] = []
    run_start = sorted_ports[0]
    run_end = sorted_ports[0]
    for p in sorted_ports[1:]:
        if p == run_end + 1:
            run_end = p
        else:
            segments.append(str(run_start) if run_start == run_end else f"{run_start}-{run_end}")
            run_start = run_end = p
    segments.append(str(run_start) if run_start == run_end else f"{run_start}-{run_end}")
    return ",".join(segments)


def _nmap_timing_args(stealth_level: str) -> list[str]:
    """
    Return nmap timing and rate flags for the requested stealth level.
    Lower stealth = slower + quieter. Higher stealth = faster + noisier.

    Two properties matter as much as speed here:

    * **Every level must actually finish.** The old paranoid floor of
      ``--min-rate 10`` (10 packets/sec) meant a real port range could never
      complete inside the scan's time budget — the whole host was cancelled and
      returned ZERO ports, so a paranoid scan produced *different* (empty)
      results than a normal one against the same target. The floors below keep
      the progressively-quieter ``-T`` templates (which provide the real IDS
      evasion: parallelism caps, longer timeouts, scan delay) while guaranteeing
      even paranoid sweeps a full range in bounded time.
    * **Determinism.** ``--max-retries 1`` drops open ports on any lossy hop, so
      the same target yields a different port set run-to-run. Every level now
      retries at least twice (loud, a lab-only profile, stays at 1) so repeated
      scans of one host converge on the same result.
    """
    return {
        "paranoid":   ["-T1", "--min-rate", "100",  "--max-retries", "2"],
        "stealth":    ["-T2", "--min-rate", "300",  "--max-retries", "2"],
        "normal":     ["-T4", "--min-rate", "800",  "--max-retries", "3"],
        "aggressive": ["-T4", "--min-rate", "3000", "--max-retries", "2"],
        "loud":       ["-T5", "--min-rate", "8000", "--max-retries", "1"],
    }.get(stealth_level, ["-T4", "--min-rate", "800", "--max-retries", "3"])


def _nmap_evasion_args(raw_capable: bool) -> list[str]:
    """Firewall/IDS-evasion nmap flags for an AUTHORIZED re-probe of a filtered
    host — the standard nmap techniques for getting probes past a simple packet
    filter (RFC-legal, the same ones ``nmap`` documents).

    Raw-socket-gated: packet fragmentation (``-f``), padding (``--data-length``)
    and decoys (``-D``) only affect nmap's *raw* SYN/UDP scans, so they are added
    only when we can run privileged. An unprivileged connect scan can still spoof
    a trusted source port, which defeats naive port-based ACLs on most platforms.
    Nothing here spoofs the source IP address or forges credentials — it only
    reshapes our own probes so a default-drop filter is more likely to pass them.
    """
    if not raw_capable:
        return ["--source-port", "53"]
    return [
        "-f",                    # fragment IP headers so signature filters miss them
        "--data-length", "24",   # pad probes past fixed-length-packet heuristics
        "--source-port", "53",   # source from DNS/53 — frequently allowed outbound
        "-D", "RND:5",           # 5 random decoys obscure which source is the scanner
    ]


# Ports whose services typically greet with a banner the instant a connection
# opens — worth a short read to capture a version string in the pure-Python
# (no-nmap) path. HTTP-family ports get a minimal HEAD request instead.
_BANNER_READ_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379, 11211, 27017,
})
_HTTP_LIKE_PORTS: frozenset[int] = frozenset({
    80, 591, 2082, 2086, 2095, 8000, 8008, 8080, 8081, 8888,
})


async def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Best-effort, READ-ONLY banner grab from a known-open TCP port.

    Returns a short, cleaned banner string, or '' when nothing was offered.
    Never writes anything except a single benign HTTP ``HEAD`` on web-like
    ports, so it's safe to run against any authorized target.
    """
    read_timeout = min(3.0, max(1.0, timeout))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=read_timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return ""
    data = b""
    try:
        if port in _HTTP_LIKE_PORTS:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: HEAVEN\r\n\r\n".encode()
            )
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await writer.drain()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            data = await asyncio.wait_for(reader.read(256), timeout=read_timeout)
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await writer.wait_closed()
    text = data.decode("utf-8", "replace").strip()
    if port in _HTTP_LIKE_PORTS and text:
        # Surface just the Server header (or the status line) rather than a wall
        # of HTML — that's the version-bearing part.
        server = status = ""
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif line.upper().startswith("HTTP/") and not status:
                status = line.strip()
        text = server or status or text.splitlines()[0]
    return text[:200]


async def _python_connect_scan(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    stealth_level: str = "normal",
) -> list[PortResult]:
    """Pure-Python TCP connect scan — the no-nmap fallback.

    Guarantees a full-range sweep still genuinely covers *every* requested port
    (not just a handful) when nmap isn't installed, instead of the scanner
    returning nothing. Every result is a REAL observation: a port is reported
    ``open`` only when the OS completed a TCP handshake to it; the service name
    comes from the well-known port map and any banner is read live from the
    socket. No port, state, service or banner is ever invented — the honest
    trade-off vs nmap is no ``-sV`` version depth or ``-O`` OS fingerprint.
    """
    if not ports:
        return []
    profile = profile_for(stealth_level)
    concurrency = min(1000, max(50, profile.max_concurrent if profile else 500))
    sem = asyncio.Semaphore(concurrency)
    connect_timeout = min(3.0, max(0.4, timeout))

    async def _probe(port: int) -> Optional[int]:
        async with sem:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=connect_timeout,
                )
            except (OSError, asyncio.TimeoutError):
                return None
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await writer.wait_closed()
            return port

    probed = await asyncio.gather(*[_probe(p) for p in ports])
    open_ports = sorted(p for p in probed if p is not None)

    # Banner-grab only the (few) open ports — cheap, and adds real version data.
    banners: dict[int, str] = {}
    grab = [p for p in open_ports if p in _BANNER_READ_PORTS or p in _HTTP_LIKE_PORTS]
    if grab:
        grabbed = await asyncio.gather(
            *[_grab_banner(host, p, connect_timeout) for p in grab]
        )
        banners = {p: b for p, b in zip(grab, grabbed) if b}

    return [
        PortResult(
            host=host, port=port, protocol="tcp", state="open",
            service=SERVICE_FINGERPRINTS.get(port, ""),
            banner=banners.get(port, ""),
        )
        for port in open_ports
    ]


async def _connect_scan_fallback(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    stealth_level: str = "normal",
) -> list[PortResult]:
    """Reliable connect-scan recovery for when nmap comes back with no open ports.

    Runs in two stages so a live host is fully covered while a genuinely dead /
    silent one is ruled out fast — important because this may run per-host inside
    a CIDR sweep:

    1. Probe the curated high-value service ports first (FTP/SSH/SMTP/HTTP/SMB/
       DB/…). These answer in a couple of seconds; an open one proves the host is
       alive. If NONE answer we stop and report nothing, so a dead or fully
       silent host never pays for a full-range sweep and no port is invented.
    2. Only once the host has proven itself alive do we sweep the *rest* of the
       requested range, so a genuinely-open uncommon port is never missed.

    Every result is a real completed TCP handshake — no port, service or banner is
    ever fabricated. This is what keeps a live, service-rich box (a full
    ``-sV -sC`` sweep of which nmap could not finish in its host-timeout) from
    being reported as "0 findings".
    """
    if not ports:
        return []
    port_set = set(ports)
    common = sorted(port_set & _ALWAYS_PROBE_PORTS)
    if not common:
        # The caller asked for a range with no high-value port in it — just scan
        # exactly what was requested (still bounded by the connect scanner).
        return await _python_connect_scan(
            host, ports, timeout=timeout, stealth_level=stealth_level)

    found = await _python_connect_scan(
        host, common, timeout=timeout, stealth_level=stealth_level)
    if not found:
        # No high-value service answered → treat the host as dead / empty rather
        # than spending the budget connect-scanning every port of a silent box.
        return []

    remaining = sorted(port_set - set(common))
    if remaining:
        found += await _python_connect_scan(
            host, remaining, timeout=timeout, stealth_level=stealth_level)

    # De-duplicate on port (common and remaining are disjoint, but be defensive)
    # and return in stable ascending order.
    by_port: dict[int, PortResult] = {}
    for pr in found:
        by_port.setdefault(pr.port, pr)
    return [by_port[p] for p in sorted(by_port)]


def _parse_nmap_xml(stdout: bytes, host: str) -> Optional[dict]:
    """Parse nmap ``-oX`` output into open ports + OS evidence.

    Returns a dict with ``ports`` (list[PortResult]), ``probe_confirmed`` (bool),
    and ``os_guess`` / ``os_source`` / ``os_accuracy`` / ``ttl``. Returns ``None``
    when the XML cannot be parsed — which is precisely how a *crashed* nmap is told
    apart from a clean scan that simply found nothing: a crash (e.g. the nmap 7.9x
    ``-sC``/NSE ``lua_status(L) == LUA_YIELD`` SIGABRT) emits only a truncated,
    unclosed document, whereas a live host with no open ports emits valid XML with
    an empty port list. The caller uses that distinction to retry without ``-sC``
    instead of silently reporting zero ports.
    """
    try:
        xml_root = _safe_xml_fromstring(stdout)
    except ET.ParseError as e:
        logger.debug(f"nmap XML parse error for {host}: {e}")
        return None

    # ── Host liveness ─────────────────────────────────────────────────────────
    # With -Pn nmap always reports state="up" reason="user-set" (we told it to skip
    # discovery), so "up" alone no longer proves reachability. Trust a real probe
    # reason (echo-reply / syn-ack / arp-response …); otherwise liveness defers to
    # "did any port actually respond?" (decided by the caller from the port list).
    status = xml_root.find(".//status")
    _status_up = status is not None and status.get("state") == "up"
    probe_confirmed = _status_up and (status.get("reason") or "") not in ("", "user-set")

    # nmap ran out of its --host-timeout before finishing this host: the scan is
    # INCOMPLETE, so an empty (or short) port list is "didn't get to look", not a
    # confirmed "nothing open". nmap marks it on the <host> element as
    # timedout="true". The caller uses this to fall back to the built-in connect
    # scanner instead of accepting 0 ports on a host that is plainly alive — the
    # exact failure a full 1-65535 `-sV -sC` sweep hits on a slow / heavily
    # firewalled / emulated target.
    host_elem = xml_root.find(".//host")
    host_timed_out = bool(
        host_elem is not None and (host_elem.get("timedout") or "").lower() == "true"
    )

    # ── Device identity: MAC (ARP), device name (NetBIOS/SMB, then PTR) ────────
    # All strictly observed; each stays '' when nmap didn't report it.
    mac_address = ""
    mac_vendor = ""
    for addr in xml_root.findall(".//address"):
        if addr.get("addrtype") == "mac":
            mac_address = (addr.get("addr") or "").strip().upper()
            mac_vendor = (addr.get("vendor") or "").strip()
            break

    device_name = ""
    device_name_source = ""
    # NetBIOS / SMB computer name — the machine's own advertised name, the
    # strongest device-name signal. nmap surfaces it under <hostscript>.
    for script in xml_root.findall(".//hostscript/script"):
        name = _netbios_name_from_script(script.get("id", ""), script.get("output", ""))
        if name:
            device_name = name
            device_name_source = "netbios"
            break
    # Reverse-DNS PTR (works remotely, weaker than a self-advertised name). Only a
    # type="PTR" name is a discovered fact; type="user" is just the target we were
    # given echoed back, so it is ignored.
    if not device_name:
        for hn in xml_root.findall(".//hostnames/hostname"):
            if (hn.get("type") or "") != "PTR":
                continue
            nm = (hn.get("name") or "").strip()
            if nm:
                device_name = nm
                device_name_source = "ptr"
                break

    # ── Perimeter-defence tallies ─────────────────────────────────────────────
    # 'filtered' = no response (a firewall silently dropped the probe); 'closed'
    # = a TCP RST (the host is reachable, the port is just shut). The ratio of
    # the two is the primary firewall signal (see firewall_detector). nmap lists
    # a handful of ports individually and collapses the bulk into <extraports>.
    filtered_count = 0
    closed_count = 0
    for xp in xml_root.findall(".//ports/extraports"):
        st = (xp.get("state") or "").lower()
        try:
            cnt = int(xp.get("count") or 0)
        except (ValueError, TypeError):
            cnt = 0
        if st == "filtered":
            filtered_count += cnt
        elif st == "closed":
            closed_count += cnt

    # ── Open ports + service info ─────────────────────────────────────────────
    ports: list[PortResult] = []
    os_evidence_types: list[str] = []
    os_evidence_cpes: list[str] = []
    for port_elem in xml_root.findall(".//port"):
        state_elem = port_elem.find("state")
        _pstate = state_elem.get("state") if state_elem is not None else None
        if _pstate == "filtered":
            filtered_count += 1
        elif _pstate == "closed":
            closed_count += 1
        if _pstate != "open":
            continue

        # Malformed nmap XML can carry portid="" — int("") raises ValueError and
        # would abort parsing the remaining ports.
        try:
            portid = int(port_elem.get("portid") or 0)
        except (ValueError, TypeError):
            continue
        protocol = port_elem.get("protocol", "tcp")

        svc = port_elem.find("service")
        service = svc.get("name", "")    if svc is not None else ""
        product = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        extra   = svc.get("extrainfo", "") if svc is not None else ""
        ostype  = svc.get("ostype", "")    if svc is not None else ""
        if ostype:
            os_evidence_types.append(ostype)

        banner_parts = [p for p in [product, version, extra] if p]
        banner = " ".join(banner_parts)

        # First app-level CPE is the port's; collect OS-level CPEs (cpe:/o:…)
        # separately as OS evidence.
        cpe = ""
        for cpe_elem in port_elem.findall(".//cpe"):
            txt = (cpe_elem.text or "").strip()
            if not txt:
                continue
            low = txt.lower()
            if "/o:" in low or ":o:" in low:  # OS-level CPE
                os_evidence_cpes.append(txt)
            elif not cpe:
                cpe = txt

        # Collect NSE script output into fingerprint dict
        script_output: dict = {}
        for script in port_elem.findall(".//script"):
            sid = script.get("id", "")
            out = script.get("output", "")
            if sid and out:
                script_output[sid] = out[:500]

        ports.append(PortResult(
            host=host, port=portid, protocol=protocol, state="open",
            service=service, product=product, version=version, banner=banner,
            extrainfo=extra, cpe=cpe, fingerprint=script_output,
        ))

    # ── OS detection (three honestly-labelled tiers) ──────────────────────────
    # 1. nmap -O TCP/IP stack fingerprint → authoritative (needs raw sockets).
    # 2. service-detection evidence (ostype / OS CPEs from -sV) → real but
    #    service-claimed, so marked heuristic. Works fully unprivileged.
    # 3. a single TTL value → coarsest guess, also heuristic.
    os_guess = ""
    os_source = ""
    os_accuracy = 0
    ttl = 0
    os_match = xml_root.find(".//osmatch")
    if os_match is not None and os_match.get("name"):
        os_guess = os_match.get("name", "")
        os_source = "nmap"
        try:
            os_accuracy = int(os_match.get("accuracy") or 0)
        except (ValueError, TypeError):
            os_accuracy = 0
    if not os_guess:
        svc_os = _os_from_service_evidence(os_evidence_types, os_evidence_cpes)
        if svc_os:
            os_guess = svc_os
            os_source = "heuristic"
    if not os_guess:
        for dist in xml_root.findall(".//distance"):
            try:
                ttl_val = int(dist.get("value", 0))
            except (ValueError, TypeError):
                ttl_val = 0
            if ttl_val:
                os_guess = guess_os_from_ttl(ttl_val)
                os_source = "heuristic"
                ttl = ttl_val

    # ── Device type ────────────────────────────────────────────────────────────
    # nmap -O classifies the device (general purpose / router / printer / webcam
    # …) inside <osclass type="…"> — authoritative, but needs raw sockets. When
    # that's absent, fall back to a conservative category from the MAC's OUI
    # vendor (labelled 'mac-vendor'); an unknown vendor leaves it blank.
    device_type = ""
    device_type_source = ""
    osclass = xml_root.find(".//osclass")
    if osclass is not None:
        dt = (osclass.get("type") or "").strip()
        if dt:
            device_type = dt
            device_type_source = "nmap"
    if not device_type and mac_vendor:
        cat = _device_type_from_mac_vendor(mac_vendor)
        if cat:
            device_type = cat
            device_type_source = "mac-vendor"

    return {
        "ports": ports,
        "probe_confirmed": probe_confirmed,
        "os_guess": os_guess,
        "os_source": os_source,
        "os_accuracy": os_accuracy,
        "ttl": ttl,
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "device_name": device_name,
        "device_name_source": device_name_source,
        "device_type": device_type,
        "device_type_source": device_type_source,
        "filtered_count": filtered_count,
        "closed_count": closed_count,
        "host_timed_out": host_timed_out,
    }


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    semaphore: Optional[asyncio.Semaphore] = None,
    include_udp: bool = False,
    udp_ports: Optional[list[int]] = None,
    stealth_level: str = "normal",
    host_timeout: str = "30m",
    evade: bool = False,
) -> HostResult:
    """
    Full-spectrum nmap scan: all ports, service detection, default NSE scripts,
    OS fingerprinting, and UDP probes when requested.

    ``evade`` adds firewall/IDS-evasion flags (packet fragmentation, padding, a
    trusted source port, decoys — see :func:`_nmap_evasion_args`) for an
    authorized re-probe of a host whose ports are being silently filtered.
    Uses stealth-level-aware timing so the same function works from
    ghost-mode recon through loud exploitation-support scans.

    ``host_timeout`` is passed straight to nmap's ``--host-timeout`` — a targeted
    re-probe of a *known* short port list (e.g. the passive-OSINT confirmation
    step) sets a small value like ``"20s"`` so nmap self-terminates on a
    firewalled host instead of retrying for the full 30-minute default.
    """
    sem = semaphore or asyncio.Semaphore(50)
    host_result = HostResult(host=host)
    start = time.time()

    port_str = _build_nmap_port_spec(ports)
    timing = _nmap_timing_args(stealth_level)

    # Decide privileges once: -O / -sS / -sU all need raw sockets, and running
    # any of them unprivileged makes nmap abort the ENTIRE scan (losing the port
    # data too). Elevate through passwordless sudo when it's available; when it
    # isn't, drop those flags and rely on the honestly-labelled service/TTL OS
    # heuristics instead of killing the scan.
    sudo_prefix = list(_nmap_sudo_prefix())
    raw_capable = _have_admin_privileges() or bool(sudo_prefix)
    if not raw_capable:
        _log_privilege_hint_once()

    # ── nmap command ──────────────────────────────────────────────────────────
    # -sV  : service / version detection
    # -sC  : run default NSE scripts (banner grab, vuln checks, auth testing)
    # -Pn  : treat the host as ONLINE — skip host discovery (ping). This is the
    #        single most important flag for INTERNAL / enterprise targets: hosts
    #        behind a firewall, Windows machines (ICMP echo blocked by default),
    #        and hardened Linux boxes routinely drop nmap's discovery probes, so
    #        without -Pn nmap declares them "down" and scans ZERO ports — the
    #        classic "I know it's vulnerable but the scan found nothing" symptom.
    #        The scan already required explicit authorization for these targets,
    #        so we scan them directly. --host-timeout below bounds the worst case
    #        (a genuinely dead address in a CIDR range) so this can't hang.
    # -O   : OS fingerprinting     (raw sockets — added only when raw_capable)
    # -sS/-sU : SYN + UDP scanning  (raw sockets — added only when raw_capable)
    # -oX  : XML output → stdout for parsing
    # --host-timeout : abort per-host after this long (prevents hangs on firewalled hosts)
    os_flag = ["-O"] if raw_capable else []

    if include_udp and udp_ports and raw_capable:
        udp_str = _build_nmap_port_spec(udp_ports[:100])
        scan_flags = ["-sS", "-sU"]
        port_args = ["-p", f"T:{port_str},U:{udp_str}"]
    else:
        if include_udp and udp_ports and not raw_capable:
            logger.debug(
                "UDP/SYN scan needs raw sockets we don't have — "
                "scanning TCP (connect) only for %s", host,
            )
        scan_flags = []
        port_args = ["-p", port_str]

    # Firewall/IDS-evasion flags for an authorized re-probe of a filtered host.
    evasion = _nmap_evasion_args(raw_capable) if evade else []

    cmd = [
        *sudo_prefix, "nmap", "-sV", "-sC", "-Pn", *os_flag, *scan_flags, *port_args,
        "-oX", "-", "--host-timeout", host_timeout, *timing, *evasion, host,
    ]

    # nmap's default-script engine (-sC / NSE) ABORTS the whole scan on some nmap
    # builds — notably the 7.9x Lua/nsock assertion "lua_status(L) == LUA_YIELD"
    # (SIGABRT) — emitting a truncated XML document and therefore ZERO ports, which
    # silently turns a scan of a live, service-rich host into "0 findings". Guard
    # against it: if the first attempt crashes or yields no parseable ports, retry
    # WITHOUT -sC so the full port + service-version inventory is still captured
    # (only the default-script output is lost). A clean scan that genuinely found no
    # open ports (valid XML, exit 0) is NOT retried.
    attempts = [cmd]
    if "-sC" in cmd:
        attempts.append([c for c in cmd if c != "-sC"])

    parsed: Optional[dict] = None
    nmap_ran = False
    async with sem:
        logger.debug(f"nmap: {' '.join(cmd)}")
        try:
            for idx, attempt in enumerate(attempts):
                proc = await asyncio.create_subprocess_exec(
                    *attempt,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                nmap_ran = True
                # A real asyncio subprocess always exposes returncode after
                # communicate(); default to 0 (success) so a test double that omits
                # it is treated as a clean run rather than crashing the scan.
                rc = getattr(proc, "returncode", 0)

                if stderr:
                    err_text = stderr.decode(errors="replace").strip()
                    if err_text and "WARNING" not in err_text and "Note:" not in err_text:
                        logger.debug(f"nmap stderr ({host}): {err_text[:300]}")

                parsed = _parse_nmap_xml(stdout, host) if stdout else None
                got_ports = bool(parsed and parsed["ports"])
                # A clean run (valid XML, normal exit) that found no ports is a real
                # "nothing open" result, not a crash — accept it and stop.
                clean = parsed is not None and rc in (0, None)
                if got_ports or clean:
                    break
                # Abnormal: nmap crashed / emitted unparseable output AND found no
                # ports. Retry the next (no -sC) attempt if one remains.
                if idx + 1 < len(attempts):
                    logger.warning(
                        "nmap exited %s for %s with no parseable results — likely "
                        "the -sC/NSE crash on this nmap build; retrying with service "
                        "detection only (-sV, no -sC).", rc, host,
                    )

            if parsed is not None:
                host_result.open_ports = parsed["ports"]
                # A port that answered proves the host is genuinely reachable — the
                # honest liveness signal under -Pn, where "up" is just our own flag.
                host_result.is_alive = parsed["probe_confirmed"] or bool(parsed["ports"])
                host_result.filtered_ports = parsed.get("filtered_count", 0)
                host_result.closed_ports = parsed.get("closed_count", 0)
                host_result.os_guess = parsed["os_guess"]
                host_result.os_source = parsed["os_source"]
                host_result.os_accuracy = parsed["os_accuracy"]
                host_result.ttl = parsed["ttl"]
                host_result.mac_address = parsed.get("mac_address", "")
                host_result.mac_vendor = parsed.get("mac_vendor", "")
                host_result.device_name = parsed.get("device_name", "")
                host_result.device_name_source = parsed.get("device_name_source", "")
                host_result.device_type = parsed.get("device_type", "")
                host_result.device_type_source = parsed.get("device_type_source", "")

            # nmap came back with NO open ports — but on a host we were explicitly
            # told to scan we cannot take that at face value. It happens for three
            # very different reasons, and every one otherwise turns a live,
            # service-rich box into a silent "0 findings" report:
            #   • nmap CRASHED and emitted unparseable XML (parsed is None) — e.g.
            #     the nmap 7.9x -sC/NSE `lua_status(L) == LUA_YIELD` SIGABRT;
            #   • nmap ran out of its --host-timeout mid-sweep (host_timed_out) —
            #     a full 1-65535 `-sV -sC` scan of a slow / heavily-filtered /
            #     emulated host never finishes, so nmap returns a *clean*, valid
            #     XML that reports zero ports because it never got to scan them;
            #   • nmap finished but its scan technique was silently filtered, or it
            #     saw the host refuse probes (closed_count > 0) yet missed the
            #     genuinely-open ports (ephemeral-port exhaustion, transient drops).
            # Cross-check all of them with the built-in concurrent TCP connect
            # scanner. On an unprivileged host (macOS has no raw sockets, so nmap
            # is itself doing a *serial* connect scan) our concurrent scanner is
            # both faster and more reliable. It never invents a port — every result
            # is a completed handshake — probes the high-value service ports first
            # so a genuinely-dead host is ruled out in a couple of seconds, and
            # only sweeps the full range once the host has proven itself alive. So
            # it costs nothing on the happy path (skipped the instant nmap DID find
            # a port) and stays safe inside a CIDR sweep. Banners grabbed for the
            # standard service ports still feed the CVE fingerprinter, so recovered
            # ports keep their version-based findings even without nmap's -sV.
            host_timed_out = bool(parsed and parsed.get("host_timed_out"))
            # Recover when nmap found NOTHING (crash / silent-filter) OR when its
            # scan was cut short by the host-timeout (INCOMPLETE — it may have
            # found some ports but missed others it never reached). In the latter
            # case we UNION the connect-scan result with nmap's, so a partial nmap
            # is completed rather than trusted as final, and nmap's richer -sV
            # entries are always kept.
            if nmap_ran and (not host_result.open_ports or host_timed_out or parsed is None):
                if parsed is None:
                    logger.warning(
                        "nmap produced no usable output for %s (crash / parse "
                        "failure) — recovering with the built-in TCP connect "
                        "scanner.", host,
                    )
                elif host_timed_out:
                    logger.warning(
                        "nmap hit its --host-timeout on %s (a full-range -sV -sC "
                        "sweep can't finish on a slow / heavily-filtered host) — "
                        "completing the inventory with the built-in TCP connect "
                        "scanner.", host,
                    )
                recovered = await _connect_scan_fallback(
                    host, ports, timeout=timeout, stealth_level=stealth_level,
                )
                # Keep nmap's own (version-rich) ports; add only ports it missed.
                known = {p.port for p in host_result.open_ports}
                added = [p for p in recovered if p.port not in known]
                if added:
                    host_result.open_ports = sorted(
                        host_result.open_ports + added, key=lambda p: p.port)
                    host_result.is_alive = True
                    # nmap had written these off as filtered/refused (or never
                    # reached them); correct the closed tally so the perimeter
                    # classifier / inventory don't describe a wide-open box as
                    # locked down.
                    host_result.closed_ports = max(
                        0, host_result.closed_ports - len(added))
                    logger.info(
                        "  ↳ connect-scan recovery found %d open port(s) on %s "
                        "that nmap missed: %s", len(added), host,
                        ", ".join(str(p.port) for p in added),
                    )

        except FileNotFoundError:
            # No nmap on PATH — fall back to the built-in pure-Python TCP connect
            # scanner so a full-range sweep still genuinely covers every requested
            # port (real handshakes only) instead of returning nothing. Service
            # versions / OS fingerprinting need nmap; install it for that depth.
            logger.warning(
                "nmap not found — using the built-in TCP connect scanner for %s "
                "(install nmap for -sV/-sC/-O depth: apt install nmap / brew install nmap)",
                host,
            )
            fallback_ports = await _python_connect_scan(
                host, ports, timeout=timeout, stealth_level=stealth_level,
            )
            host_result.open_ports = fallback_ports
            if fallback_ports:
                host_result.is_alive = True

    # Honeypot heuristic: too many open ports is suspicious
    open_count = len(host_result.open_ports)
    if open_count > 50:
        host_result.honeypot_indicators.append(
            f"Suspiciously high open port count: {open_count}"
        )
    _check_service_consistency(host_result)

    host_result.scan_time_ms = (time.time() - start) * 1000
    return host_result


async def _evasion_reprobe(
    host: str,
    ports: list[int],
    *,
    timeout: float,
    sem: Optional[asyncio.Semaphore],
    stealth_level: str,
) -> list[PortResult]:
    """Authorized firewall/IDS-evasion re-probe of a filtered host's high-value
    ports — the "still get findings through the perimeter" step.

    Runs TWO independent probes and merges them, because a packet-filter that
    drops one path often lets the other through:

    * an nmap evasion scan (``evade=True`` → fragmentation / padding / trusted
      source port / decoys), and
    * a pure-Python TCP connect scan, which rides the OS network stack and so
      presents a completely different packet signature.

    Timing is bumped to at least ``stealth`` (slower, lower parallelism) so an
    IPS that started rate-blocking has cooled down. Bounded by a short per-host
    nmap ``--host-timeout`` and the small high-value port set the caller passes.
    Returns the union of open ports discovered; never raises.
    """
    if not ports:
        return []
    bumped = "stealth" if stealth_level in ("normal", "aggressive", "loud") else stealth_level
    found: dict[int, PortResult] = {}
    try:
        r = await scan_host(
            host, ports, timeout=max(timeout, 3.0), semaphore=sem,
            stealth_level=bumped, evade=True, host_timeout="60s",
        )
        for p in r.open_ports:
            found[p.port] = p
    except Exception:
        logger.debug("evasion nmap re-probe failed for %s", host, exc_info=True)
    try:
        for p in await _python_connect_scan(
            host, ports, timeout=max(timeout, 3.0), stealth_level=bumped,
        ):
            found.setdefault(p.port, p)
    except Exception:
        logger.debug("evasion connect re-probe failed for %s", host, exc_info=True)
    return list(found.values())


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR notation and hostname targets to individual IPs."""
    expanded: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses <= 65536:  # Safety limit
                expanded.extend(str(ip) for ip in network.hosts())
            else:
                logger.warning(f"Network too large: {target} ({network.num_addresses} hosts) — skipping")
        except ValueError:
            expanded.append(target)  # Hostname or single IP
    return expanded


# A range bigger than this many addresses (e.g. a CIDR /27 or wider, or a large
# explicit list) is discovered-first: we sweep for live hosts and only deep-scan
# those. A single host or a small explicit list is scanned directly with -Pn —
# the operator named it, so we trust it's up even behind a firewall. This is what
# stops "scan 192.168.1.0/24" from spending its whole budget full-scanning ~250
# dead addresses and returning nothing.
_DISCOVERY_THRESHOLD = 16

# Ports probed during the fast liveness sweep — the services most likely to be
# open on a live host. A host answering a TCP connect on ANY of these is "up".
_LIVENESS_PROBE_PORTS: tuple[int, ...] = (
    80, 443, 22, 445, 3389, 8080, 139, 135, 53, 21, 23, 25, 110, 143,
    3306, 5432, 1433, 8443, 8000, 8888, 5900, 111, 993, 995, 6379, 27017,
    # cPanel / WHM / webmail control-plane + alt-SSH — common on shared-hosting
    # targets and a live-host signal in their own right.
    2082, 2083, 2086, 2087, 2095, 2096, 2222,
)

# High-value ports ALWAYS folded into the requested scan range so a flaky /
# rate-limited / narrowed run can never silently drop the web, database,
# mail-transport, directory or cPanel surface — the direct structural fix for the
# "1-65535 scan came back without 80/443/3306" class of miss. Union-only: it can
# add coverage, never remove it, and is a no-op when the caller already asked for
# the full range.
_ALWAYS_PROBE_PORTS: frozenset[int] = frozenset(_LIVENESS_PROBE_PORTS) | frozenset({
    465, 587, 389, 636, 993, 995,           # mail submission / LDAP(S) / secure mail
    1521, 9200, 5984, 11211, 9042, 9300,    # Oracle / ES / CouchDB / memcached / Cassandra
    2077, 2078, 8443, 10000,                # cPanel WebDAV / https-alt / Webmin
})


async def _nmap_ping_sweep(
    raw_targets: list[str], expanded: list[str],
) -> Optional[list[str]]:
    """Discover live hosts with a single ``nmap -sn`` sweep (no port scan).

    With raw-socket privileges nmap uses ICMP echo/timestamp + ARP (on a LAN) +
    TCP SYN to 443/80, which catches hosts that a bare TCP-connect probe would
    miss; unprivileged it TCP-connects to 80/443. Returns the list of responding
    addresses, or ``None`` when nmap is unavailable / the sweep failed so the
    caller can fall back to the pure-Python probe.
    """
    if not shutil.which("nmap"):
        return None
    sudo_prefix = list(_nmap_sudo_prefix())
    # -sn host-discovery only · -n no DNS · -T4 fast. Pass the RAW targets so
    # nmap expands the CIDR itself (far more efficient than 254 argv entries).
    cmd = [*sudo_prefix, "nmap", "-sn", "-n", "-T4", "-oX", "-", *raw_targets]
    # Bound the sweep: ~0.5s/host, floor 60s, ceiling 5min. Discovery is cheap.
    sweep_timeout = max(60.0, min(300.0, len(expanded) * 0.5))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(), timeout=sweep_timeout,
        )
    except (asyncio.TimeoutError, OSError, ValueError) as e:
        logger.debug(f"nmap -sn discovery unavailable, falling back: {e}")
        return None
    if not stdout:
        return None
    try:
        root = _safe_xml_fromstring(stdout)
    except (ET.ParseError, ValueError) as e:
        logger.debug(f"nmap -sn XML parse failed, falling back: {e}")
        return None
    live: list[str] = []
    for host_el in root.findall(".//host"):
        st = host_el.find("status")
        if st is None or st.get("state") != "up":
            continue
        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if addr:
            live.append(addr)
    return live


async def _tcp_ping_sweep(hosts: list[str], timeout: float = 2.0) -> list[str]:
    """Pure-Python liveness fallback: a host is live if it accepts a TCP connect
    on any common port. No raw sockets required, so it works on a minimal install
    with no nmap. Probes run highly concurrently, so a /24 sweeps in seconds."""
    sem = asyncio.Semaphore(500)
    probe_timeout = min(1.5, max(0.4, timeout))

    async def _port_open(host: str, port: int) -> bool:
        try:
            fut = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(fut, timeout=probe_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _alive(host: str) -> Optional[str]:
        async with sem:
            outcomes = await asyncio.gather(
                *[_port_open(host, p) for p in _LIVENESS_PROBE_PORTS]
            )
            return host if any(outcomes) else None

    results = await asyncio.gather(*[_alive(h) for h in hosts])
    return [h for h in results if h]


async def _discover_live_hosts(
    raw_targets: list[str], expanded: list[str], timeout: float = 2.0,
) -> list[str]:
    """Return the subset of *expanded* that responds to a fast liveness sweep.
    Prefers nmap ``-sn`` (catches ICMP/ARP-only hosts); falls back to a
    concurrent TCP-connect probe when nmap is absent."""
    live = await _nmap_ping_sweep(raw_targets, expanded)
    if live is None:
        live = await _tcp_ping_sweep(expanded, timeout=timeout)
    # nmap may report addresses in a slightly different form; keep any host we
    # actually intended to scan, plus any extra live address nmap surfaced.
    expanded_set = set(expanded)
    ordered = [h for h in expanded if h in set(live)]
    extra = [h for h in live if h not in expanded_set]
    return ordered + extra


async def scan_network(
    targets: list[str],
    port_range: str = "1-65535",
    timeout: float = 2.0,
    include_udp: bool = False,
    stealth_level: str = "normal",
    time_budget: Optional[float] = None,
    passive_enrich: bool = True,
    evade: bool = False,
    **kwargs,
) -> dict[str, Any]:
    """
    Main entry point: scan multiple hosts across specified port ranges.
    Integrates evasion engine, honeypot avoidance, and CTF flag extraction.
    Called by the orchestrator. Cross-platform: Linux, macOS, Windows.

    ``time_budget`` (seconds) bounds the deep-scan phase: hosts still in flight
    when it elapses are stopped and whatever finished is returned, so a large
    sweep yields partial results instead of being hard-cancelled with nothing.
    """
    if not targets:
        logger.info("No network targets specified — skipping network scan")
        return {"hosts": [], "total_open_ports": 0}

    # Resolve the FULL evasion profile (timing + concurrency) for this level up
    # front — this can't fail (same module, no I/O) so stealth always takes
    # effect even if the optional honeypot/CTF add-ons below are unavailable.
    profile = profile_for(stealth_level)
    engine = EvasionEngine(profile)

    # Pre-init so a NON-ImportError failure below (e.g. a runtime bug in the
    # honeypot module) degrades gracefully instead of raising NameError later.
    hp_engine = None
    ctf = None
    try:
        from heaven.recon.evasion_engine import HoneypotEvasionEngine
        from heaven.recon.ctf_extractor import CTFFlagExtractor
        from heaven.recon.honeypot_detector import analyze_host as hp_analyze

        hp_engine = HoneypotEvasionEngine(threshold=profile.honeypot_threshold)
        ctf = CTFFlagExtractor()
    except Exception as e:
        logger.warning(f"Honeypot/CTF evasion modules unavailable — continuing without: {e}")

    # Expand CIDR targets → individual addresses.
    expanded_targets = expand_targets(targets)
    ports = parse_port_range(port_range)

    # Fold in the high-value always-probe superset (web / DB / mail / LDAP /
    # cPanel). Union-only — this can add coverage but never removes a requested
    # port, and is a no-op when the caller already asked for the full range.
    _requested = set(ports)
    _missing = sorted(p for p in _ALWAYS_PROBE_PORTS if p not in _requested)
    if _missing:
        ports = sorted(_requested | set(_missing))
        logger.debug(
            "Folded %d high-value port(s) into the scan range for coverage: %s",
            len(_missing), _missing,
        )

    concurrency = profile.max_concurrent if profile else 500
    sem = asyncio.Semaphore(concurrency)

    # ── Bound nmap's per-host --host-timeout to the deep-scan budget ───────────
    # A full 1-65535 `-sV -sC` sweep of a slow / heavily-filtered / emulated host
    # never finishes. Left at the 30-min default, nmap would still be running when
    # the orchestrator's time_budget fired: the scan_host coroutine would be
    # CANCELLED mid-nmap and its result DISCARDED — the "scan sits for minutes and
    # then reports 0 findings" bug. Cap the per-host nmap deadline WELL below the
    # budget so nmap always yields in time for the built-in connect-scan recovery
    # to run AND for the host to finish (and be kept) inside the budget. Reserve
    # scales with the port count (the connect sweep is the only thing that must
    # still fit after nmap gives up). Direct callers (time_budget=None) keep the
    # generous 30-min default.
    if time_budget and time_budget > 0:
        _connect_reserve = min(400.0, 45.0 + (len(ports) / max(1, concurrency)) * timeout * 1.3)
        # Ceiling: a legitimately-reachable host finishes an unprivileged connect
        # scan of the full range well inside a few minutes (closed ports RST
        # instantly); a host that is still unfinished past this is being silently
        # filtered, and the connect-scan recovery — a strict superset of what
        # unprivileged nmap can see, and far faster — will complete it. Capping
        # here turns the "sits for many minutes on a filtered/emulated host" wait
        # into a bounded one without losing coverage. Quieter stealth profiles
        # legitimately need longer, so scale the ceiling by the packet-rate factor.
        _stealth_ceiling = {
            "paranoid": 4.0, "stealth": 2.0, "normal": 1.0,
            "aggressive": 1.0, "loud": 1.0,
        }.get(str(stealth_level).strip().lower(), 1.0)
        _nmap_ceiling = 240.0 * _stealth_ceiling
        _nmap_host_secs = int(max(60.0, min(_nmap_ceiling, time_budget - _connect_reserve)))
        nmap_host_timeout = f"{_nmap_host_secs}s"
    else:
        nmap_host_timeout = "30m"

    # ── Host-discovery sweep for broad ranges ─────────────────────────────────
    # A /24 expands to 254 addresses, most of them dead. Under -Pn (which we use
    # so firewalled hosts aren't skipped) nmap would faithfully full-scan every
    # one of them — so a "scan 192.168.1.0/24" spent its entire deadline on dead
    # air and returned nothing, the exact "it's vulnerable but shows nothing"
    # symptom. For a broad range we first sweep for live hosts (fast, cheap) and
    # only deep-scan the ones that answer. A single host / small explicit list
    # skips discovery — the operator named it, so we trust -Pn to reach it.
    discovery: Optional[dict[str, Any]] = None
    if len(expanded_targets) > _DISCOVERY_THRESHOLD:
        _range_size = len(expanded_targets)
        live = await _discover_live_hosts(targets, expanded_targets, timeout=timeout)
        discovery = {"range_size": _range_size, "hosts_up": len(live)}
        logger.info(
            f"Host discovery: {len(live)}/{_range_size} address(es) responded — "
            f"deep-scanning the live host(s)"
        )
        expanded_targets = live
        if not expanded_targets:
            logger.warning(
                "Host discovery found no live hosts in the range. If you know a "
                "specific host is up but hardened, scan it directly (e.g. "
                "`heaven scan -t <ip>`) to force a full -Pn scan."
            )

    logger.info(
        f"Scanning {len(expanded_targets)} host(s) × {len(ports)} ports "
        f"(stealth={stealth_level}, concurrency={concurrency}, platform={sys.platform})"
    )

    # Randomise scan order if evasion profile requires it
    if profile and profile.scan_order == "random":
        import random
        random.shuffle(expanded_targets)

    honeypots_skipped = 0

    async def _scan_and_analyze(host: str) -> Optional[HostResult]:
        """Deep-scan one host, then run honeypot avoidance + CTF extraction.
        Returns the HostResult to keep, or ``None`` when the host is skipped
        (unparseable result or a detected honeypot)."""
        nonlocal honeypots_skipped
        await engine.apply_evasion_delay()

        result = await scan_host(
            host, ports, timeout=timeout, semaphore=sem,
            include_udp=include_udp, stealth_level=stealth_level, evade=evade,
            host_timeout=nmap_host_timeout,
        )
        if not isinstance(result, HostResult):
            return None

        # Honeypot analysis
        if hp_engine and profile and profile.auto_skip_honeypots and result.open_ports:
            port_dicts = [{
                "port": p.port, "banner": p.banner, "state": p.state,
                "service": p.service, "response_time_ms": p.response_time_ms,
            } for p in result.open_ports]

            hp_result = await hp_analyze(host, port_dicts, len(ports))
            hp_engine.record_score(host, hp_result.score, hp_result.indicators)

            if hp_result.is_honeypot:
                result.honeypot_indicators.extend(hp_result.indicators)
                honeypots_skipped += 1
                logger.warning(f"🛡️ HONEYPOT SKIPPED: {host} (score={hp_result.score:.2f})")
                return None  # Skip honeypot targets entirely

        # CTF flag extraction from banners
        if ctf and result.open_ports:
            port_dicts = [{
                "port": p.port, "banner": p.banner, "state": p.state,
            } for p in result.open_ports]
            flags = ctf.extract_from_banners(host, port_dicts)
            if flags:
                logger.info(f"🚩 {len(flags)} CTF flags captured from {host}")

        if result.open_ports:
            logger.info(
                f"  {result.host}: {len(result.open_ports)} open ports "
                f"(OS: {result.os_guess}, {result.scan_time_ms:.0f}ms)"
            )
        return result

    # Deep-scan every host CONCURRENTLY, bounded by the stealth profile's
    # concurrency (via the shared semaphore inside scan_host). The previous
    # sequential loop scanned one host at a time regardless of that limit, so a
    # multi-host range crawled and blew past the task deadline. When a
    # ``time_budget`` is set, hosts still running when it elapses are stopped and
    # the finished ones are still returned — partial results beat none.
    host_results: list[HostResult] = []
    timed_out = 0
    scan_futures = [asyncio.ensure_future(_scan_and_analyze(h)) for h in expanded_targets]
    if scan_futures:
        if time_budget and time_budget > 0:
            done, pending = await asyncio.wait(scan_futures, timeout=time_budget)
            for fut in pending:
                fut.cancel()
            timed_out = len(pending)
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
                logger.warning(
                    f"Network deep-scan time budget ({time_budget:.0f}s) reached — "
                    f"returning {len(done)} finished host(s); {len(pending)} still in "
                    f"flight were stopped. Narrow the port range or target fewer hosts."
                )
            finished = done
        else:
            await asyncio.gather(*scan_futures, return_exceptions=True)
            finished = set(scan_futures)
        for fut in finished:
            if fut.cancelled():
                continue
            exc = fut.exception()
            if exc is not None:
                logger.debug(f"host scan raised: {exc}")
                continue
            res = fut.result()
            if isinstance(res, HostResult):
                host_results.append(res)

    # ── Adaptive perimeter-defence pass ───────────────────────────────────────
    # The most common "the box is vulnerable but the scan found nothing" cause is
    # a firewall silently dropping probes. Here we classify each host's perimeter
    # from the port-state tallies the scan already collected and — for a host
    # whose ports are being *filtered* (a firewall / active IPS) — run ONE
    # bounded, authorized evasion re-probe of its high-value ports so results
    # still come back. A normal host (ports refused with RST) is classified
    # "none", triggers no re-probe, and costs nothing.
    perimeter_hosts: dict[str, dict] = {}
    try:
        from heaven.recon.firewall_detector import classify_perimeter
    except Exception:  # pragma: no cover - detector import is best-effort
        classify_perimeter = None  # type: ignore[assignment]
    if classify_perimeter is not None and host_results:
        reprobe_ports = sorted(set(ports) & _ALWAYS_PROBE_PORTS) or ports[:200]
        reprobe_budget = 30.0 if not time_budget else max(10.0, time_budget * 0.5)
        reprobe_deadline = time.time() + reprobe_budget
        reprobed = 0
        _MAX_REPROBE_HOSTS = 5
        for h in host_results:
            reachable = h.is_alive or (h.filtered_ports + h.closed_ports) > 0
            rts = [p.response_time_ms for p in h.open_ports if p.response_time_ms]
            verdict = classify_perimeter(
                h.host,
                open_count=len(h.open_ports),
                filtered_count=h.filtered_ports,
                closed_count=h.closed_ports,
                total_probed=len(ports),
                reachable=reachable,
                response_times_ms=rts,
            )
            if (verdict.evasion_recommended and not evade
                    and reprobed < _MAX_REPROBE_HOSTS
                    and time.time() < reprobe_deadline and reprobe_ports):
                reprobed += 1
                logger.info(
                    "🧱 Perimeter defence on %s (%s) — evasion re-probing %d "
                    "high-value port(s) [fragmented / trusted source-port / decoys].",
                    h.host, verdict.posture, len(reprobe_ports),
                )
                recovered = await _evasion_reprobe(
                    h.host, reprobe_ports, timeout=timeout, sem=sem,
                    stealth_level=stealth_level,
                )
                existing = {p.port for p in h.open_ports}
                added = [p for p in recovered if p.port not in existing]
                if added:
                    h.open_ports.extend(added)
                    h.open_ports.sort(key=lambda p: p.port)
                    h.is_alive = True
                    logger.info(
                        "  ↳ evasion re-probe recovered %d port(s) through the "
                        "perimeter on %s: %s", len(added), h.host,
                        ", ".join(str(p.port) for p in added),
                    )
                    verdict = classify_perimeter(
                        h.host,
                        open_count=len(h.open_ports),
                        filtered_count=max(0, h.filtered_ports - len(added)),
                        closed_count=h.closed_ports,
                        total_probed=len(ports),
                        reachable=True,
                        response_times_ms=[p.response_time_ms for p in h.open_ports
                                           if p.response_time_ms],
                    )
                    verdict.indicators.append(
                        f"Evasion re-probe recovered {len(added)} port(s) the initial "
                        "scan could not see — the perimeter was filtering them."
                    )
                    verdict.evidence["recovered_ports"] = [p.port for p in added]
            h.perimeter = verdict.to_dict() if verdict.detected else {}
            if verdict.detected:
                perimeter_hosts[h.host] = h.perimeter

    total_open = sum(len(h.open_ports) for h in host_results)

    logger.info(
        f"Network scan complete: {total_open} open ports across {len(host_results)} hosts "
        f"(honeypots skipped: {honeypots_skipped})"
    )

    output: dict[str, Any] = {
        "hosts": [_host_to_dict(h) for h in host_results],
        "total_open_ports": total_open,
        "total_hosts": len(host_results),
        "alive_hosts": sum(1 for h in host_results if h.is_alive),
        "honeypots_skipped": honeypots_skipped,
        "hosts_timed_out": timed_out,
        "discovery": discovery,
        "platform": sys.platform,
        # Whether this run could do SYN/UDP/OS scans, and (if not) how to enable
        # them — so the CLI/report can be honest about scan depth on this host.
        "scan_privilege": scan_capability(),
        # Perimeter-defence verdicts (firewall / IDS-IPS / tarpit) for hosts where
        # one was detected, plus whether an evasion re-probe recovered ports. Empty
        # hosts map ⇒ nothing detected. Consumed by build_perimeter_findings and
        # the inventory/report "Perimeter Defenses" note.
        "perimeter": {"detected": bool(perimeter_hosts), "hosts": perimeter_hosts},
    }

    if ctf:
        output["ctf"] = ctf.summary()
    if hp_engine:
        output["evasion"] = hp_engine.summary()

    # ── Passive OSINT enrichment ──────────────────────────────────────────────
    # Cross-reference each PUBLIC target against Shodan's key-less InternetDB so
    # a port/service the active run missed (timeout, rate-limit, flaky nmap) is
    # still surfaced — merged into the very same host dicts every downstream
    # stage reads (inventory, exposed-DB, EOL, CVE mapping). Passively-observed
    # ports are re-probed read-only to confirm and are labelled honestly; a
    # private target, an offline network, or HEAVEN_NO_PASSIVE_INTEL=1 make this
    # a silent no-op.
    if passive_enrich:
        try:
            from heaven.recon.passive_intel import (
                _ENRICH_TOTAL_BUDGET,
                enrich_hosts,
            )
            # enrich_hosts mutates the host dicts (and appends any public-only
            # host) IN PLACE, so even if this backstop fires mid-pass the ports
            # merged so far are already recorded. The backstop sits just above the
            # module's own internal deadline and comfortably inside the
            # orchestrator's network-task slack, so enrichment can never overrun
            # the scan's hard timeout and take the active results down with it.
            try:
                await asyncio.wait_for(
                    enrich_hosts(output["hosts"], stealth_level=stealth_level,
                                 targets=targets),
                    timeout=_ENRICH_TOTAL_BUDGET + 10.0,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Passive OSINT enrichment hit its time backstop — keeping "
                    "whatever merged so far and continuing.")
            # Recompute totals unconditionally: the host dicts were mutated in
            # place, so this is correct whether enrichment finished or was bounded.
            output["total_open_ports"] = sum(
                len(h.get("open_ports", [])) for h in output["hosts"])
            output["total_hosts"] = len(output["hosts"])
            output["alive_hosts"] = sum(
                1 for h in output["hosts"] if h.get("is_alive") or h.get("open_ports"))
        except Exception as e:  # noqa: BLE001 - enrichment must never break a scan
            logger.debug("passive OSINT enrichment skipped: %s", e)

    return output


# ── Internal helpers ──

def _extract_version(banner: str, service: str) -> str:
    """Extract version string from a service banner."""
    import re
    patterns = {
        "ssh": r"SSH-\d+\.\d+-(\S+)",
        "ftp": r"220[- ].*?(\d+\.\d+[\.\d]*)",
        "smtp": r"220.*?(\d+\.\d+[\.\d]*)",
        "http": r"Server:\s*(.+?)(?:\r|\n)",
        "mysql": r"(\d+\.\d+\.\d+)",
        "postgresql": r"PostgreSQL\s+(\d+\.\d+)",
        "redis": r"redis_version:(\d+\.\d+\.\d+)",
    }
    pattern = patterns.get(service)
    if pattern:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_http_server(response: str) -> str:
    """Extract Server header from HTTP response."""
    import re
    match = re.search(r"Server:\s*(.+?)(?:\r|\n)", response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


# nmap-product fragment (lowercased) → (NVD vendor, NVD product). Only
# well-established CPE identifiers are listed; an unrecognised product yields no
# CPE — we never guess a vendor. Order matters: most-specific fragment first
# (e.g. "apache tomcat" before "apache httpd", "mariadb" before "mysql").
_CPE_PRODUCTS: list[tuple[str, str, str]] = [
    ("openssh", "openbsd", "openssh"),
    ("pure-ftpd", "pureftpd", "pure-ftpd"),
    ("proftpd", "proftpd", "proftpd"),
    ("apache tomcat", "apache", "tomcat"),
    ("apache httpd", "apache", "http_server"),
    ("openresty", "openresty", "openresty"),
    ("nginx", "nginx", "nginx"),
    ("lighttpd", "lighttpd", "lighttpd"),
    ("microsoft iis", "microsoft", "internet_information_services"),
    ("mariadb", "mariadb", "mariadb"),
    ("mysql", "mysql", "mysql"),
    ("postgresql", "postgresql", "postgresql"),
    ("mongodb", "mongodb", "mongodb"),
    ("elasticsearch", "elastic", "elasticsearch"),
    ("memcached", "memcached", "memcached"),
    ("redis", "redis", "redis"),
    ("exim", "exim", "exim"),
    ("postfix", "postfix", "postfix"),
    ("dovecot", "dovecot", "dovecot"),
    ("isc bind", "isc", "bind"),
    ("php", "php", "php"),
]


def _cpe_version(version: str) -> str:
    """First version token if it looks like a version, else the '*' wildcard."""
    tokens = (version or "").split()
    tok = tokens[0] if tokens else ""
    return tok if any(ch.isdigit() for ch in tok) else "*"


def _generate_cpe(product: str, version: str = "") -> str:
    """Derive a CPE 2.3 identifier from nmap's own product + version.

    A CPE is just the canonical, structured restatement of a product/version nmap
    already observed (e.g. "nginx 1.29.8" → ``cpe:2.3:a:nginx:nginx:1.29.8``) —
    nothing here is fetched or guessed. nmap emits a ``<cpe>`` for many matches but
    omits it for newer versions, leaving the column blank; this fills that gap for
    the products whose NVD vendor is well-established. An unknown product, or a
    bare service name with no product, returns '' — we never invent a vendor.
    """
    prod = (product or "").strip().lower()
    if not prod:
        return ""
    for frag, vendor, cpe_product in _CPE_PRODUCTS:
        if frag in prod:
            return f"cpe:2.3:a:{vendor}:{cpe_product}:{_cpe_version(version)}:*:*:*:*:*:*:*"
    return ""


def _check_service_consistency(host: HostResult) -> None:
    """Check for suspicious service/OS inconsistencies (honeypot indicator)."""
    services = {p.service for p in host.open_ports if p.service}
    # Windows-only services on Linux-detected host
    if host.os_guess == "Linux/Unix":
        windows_services = services & {"msrpc", "netbios-ssn", "microsoft-ds"}
        if len(windows_services) > 1:
            host.honeypot_indicators.append(
                f"Windows services on Linux host: {windows_services}"
            )


def _service_version(product: str, version: str, extrainfo: str) -> str:
    """Build a clean 'product version (extrainfo)' string from nmap fields.

    nmap splits a service banner into product / version / extrainfo; the raw
    ``version`` field alone drops the product name (so "8.9p1" instead of
    "OpenSSH 8.9p1"). This recombines them for display without inventing
    anything — an empty result simply means nmap reported no version data.
    """
    core = " ".join(p for p in (product.strip(), version.strip()) if p)
    extra = extrainfo.strip()
    if core and extra:
        return f"{core} ({extra})"
    return core or (f"({extra})" if extra else "")


def _host_to_dict(host: HostResult) -> dict:
    """Convert HostResult to serialisable dict."""
    return {
        "host": host.host,
        "ip": host.host,  # alias so orchestrator service-task injection finds the right key
        "is_alive": host.is_alive,
        "os_guess": host.os_guess,
        "os_source": host.os_source,
        "os_accuracy": host.os_accuracy,
        # Device identity — blank unless nmap actually observed it (MAC needs a
        # same-subnet privileged scan; device type/name from -O / NetBIOS / PTR).
        "mac_address": host.mac_address,
        "mac_vendor": host.mac_vendor,
        "device_name": host.device_name,
        "device_name_source": host.device_name_source,
        "device_type": host.device_type,
        "device_type_source": host.device_type_source,
        "scan_time_ms": round(host.scan_time_ms, 1),
        "honeypot_indicators": host.honeypot_indicators,
        # Perimeter-defence signal (empty {} when nothing was inferred). Carries
        # the firewall/IDS verdict + the port-state tallies it was derived from so
        # the report/inventory can explain thin results and recommend evasion.
        "perimeter": host.perimeter,
        "filtered_ports": host.filtered_ports,
        "closed_ports": host.closed_ports,
        "open_ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                # nmap leaves the service name blank on ports it can't identify by
                # banner even when the port number is a well-known one; fall back to
                # the conventional label so a known port is never shown unnamed. A
                # port with no conventional label (e.g. 26) honestly stays blank.
                "service": p.service or SERVICE_FINGERPRINTS.get(p.port, ""),
                "product": p.product,
                "version": p.version,
                "service_version": _service_version(p.product, p.version, p.extrainfo),
                "banner": p.banner[:200] if p.banner else "",
                # Prefer nmap's own CPE; when nmap omits one, derive it from the
                # product/version nmap did report (never fabricated — see _generate_cpe).
                "cpe": p.cpe or _generate_cpe(p.product, p.version),
                "response_time_ms": round(p.response_time_ms, 1),
            }
            for p in host.open_ports
        ],
    }

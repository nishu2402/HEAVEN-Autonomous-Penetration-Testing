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
import errno
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
    # ── NetBIOS node-status (UDP/137) enrichment ──────────────────────────────
    # Populated from a best-effort NBSTAT query on a LAN target — the real,
    # observed name table a Windows host answers even when its TCP ports
    # (135/139/445/3389) are firewall-filtered. Carries computer_name / workgroup
    # / mac_address / file_sharing / is_domain_controller. Empty off-LAN or when
    # the host did not answer. Never fabricated.
    netbios: dict = field(default_factory=dict)


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


def _egress_nmap() -> tuple[list[str], bool]:
    """Egress adjustment for an nmap invocation: ``(proxychains_prefix,
    force_connect)``. Under a proxy/Tor egress nmap must run a TCP *connect*
    scan (raw SYN/UDP/OS can't traverse a proxy) wrapped in proxychains so its
    TCP exits via the egress. Returns ``([], False)`` for off / WireGuard tunnel
    modes — a tunnel carries raw nmap transparently, so nothing changes."""
    try:
        from heaven.net import egress as _egress
        if _egress.nmap_forces_connect_scan():
            return _egress.proxychains_prefix(), True
    except Exception:  # noqa: BLE001 — egress must never break the scan
        logger.debug("egress nmap adjustment skipped", exc_info=True)
    return [], False


_egress_block_warned = False


def _egress_port_scan_blocked() -> bool:
    """Fail-closed: under a proxy/Tor egress with the kill-switch on and no
    proxychains, a port scan would leak the real IP — so skip it (nuclei + HTTP
    checks still route via the proxy; use WireGuard for full coverage). Warns
    once so the operator understands why the port scan is empty."""
    global _egress_block_warned
    try:
        from heaven.net import egress as _egress
        if _egress.port_scan_blocked():
            if not _egress_block_warned:
                _egress_block_warned = True
                logger.warning(
                    "Egress kill-switch: proxy/Tor mode without proxychains — "
                    "SKIPPING the network port scan so it can't leak your real "
                    "IP. Install proxychains-ng, or use WireGuard tunnel mode, "
                    "or disable the kill-switch to allow a direct port scan.")
            return True
    except Exception:  # noqa: BLE001 — egress must never break the scan
        logger.debug("egress port-scan guard skipped", exc_info=True)
    return False


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


def _friendly_windows_from_cpe(c: str) -> str:
    """Friendly, VERSION-PRESERVING Windows name from a lowercased OS CPE.

    The Microsoft product token encodes the exact release
    (``windows_10`` / ``windows_server_2008`` / ``windows_xp`` …). Collapsing it
    to a bare "Windows" was what stopped the EOL scanner recognising an
    end-of-life release, so map the token back to its human name and keep the
    version. Falls back to bare "Windows" only when the token is unversioned.
    """
    import re as _re
    m = _re.search(r"microsoft:(windows[a-z0-9_.]*)", c)
    token = (m.group(1) if m else "windows").replace(".", "_")
    server = "_server_" in token or token.startswith("windows_server")
    ver = _re.search(r"(\d{4}|\d+(?:\.\d+)?)", token)
    if server:
        return f"Windows Server {ver.group(1)}" if ver else "Windows Server"
    named = {"xp": "Windows XP", "vista": "Windows Vista"}
    for key, label in named.items():
        if key in token:
            return label
    if ver:
        return f"Windows {ver.group(1)}"
    return "Windows"


def _os_name_from_cpe(cpe: str) -> str:
    """Map an OS-level CPE (``cpe:/o:…`` / ``cpe:2.3:o:…``) to a friendly OS
    name. Returns '' for application CPEs or anything we can't confidently map —
    we never guess an OS we didn't actually see evidence for.

    Windows CPEs keep their release (``windows_10`` → "Windows 10") so an
    end-of-life OS is recognised by the EOL scanner instead of being flattened to
    a generic, unmatchable "Windows"."""
    c = cpe.lower()
    # OS part marker differs by CPE form: URI is `cpe:/o:…`, 2.3 is `cpe:2.3:o:…`
    if "/o:" not in c and ":o:" not in c:
        return ""
    if "microsoft:windows" in c or "microsoft" in c or "windows" in c:
        return _friendly_windows_from_cpe(c)
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


# Conservative open-port → device-role map. A device's ROLE is strongly implied by
# the services it exposes — a box answering 3389/445 is a Windows host, one on
# 9100/515/631 is a printer, 502/102/44818 is an industrial controller. This is a
# real observed signal (the ports actually answered), but it infers a role rather
# than fingerprinting the stack, so callers label anything derived here
# "(inferred from services)" and never as an nmap fingerprint. Ordered
# most-specific first; the first rule whose ports are all present (for an "all"
# rule) or any port is present (for an "any" rule) wins.
#   (label, {ports}, mode)  where mode is "any" (one port suffices) or
#   "all" (every listed port must be open — a stronger, less ambiguous signal).
_SERVICE_DEVICE_TYPES: list[tuple[str, set[int], str]] = [
    ("industrial control system", {502}, "any"),       # Modbus
    ("industrial control system", {102}, "any"),        # Siemens S7
    ("industrial control system", {44818, 2222}, "any"),  # EtherNet/IP
    ("industrial control system", {20000}, "any"),      # DNP3
    ("industrial control system", {47808}, "any"),      # BACnet
    ("printer", {9100}, "any"),                          # JetDirect raw print
    ("printer", {515}, "any"),                           # LPD
    ("printer", {631}, "any"),                           # IPP
    ("IP camera", {554}, "any"),                          # RTSP
    ("IoT device", {1883}, "any"),                        # MQTT
    ("IoT device", {5683}, "any"),                        # CoAP
    ("hypervisor", {902}, "any"),                         # VMware ESXi
    ("database server", {3306}, "any"),                   # MySQL
    ("database server", {5432}, "any"),                   # PostgreSQL
    ("database server", {1433}, "any"),                   # MSSQL
    ("database server", {27017}, "any"),                  # MongoDB
    ("mail server", {25, 143}, "any"),                    # SMTP/IMAP
    ("DNS server", {53}, "any"),
    ("Windows host", {3389}, "any"),                      # RDP
    ("Windows host", {445}, "any"),                       # SMB
    ("Windows host", {135}, "any"),                       # MSRPC
    ("Windows host", {139}, "any"),                       # NetBIOS session
    ("Windows host", {5985}, "any"),                      # WinRM (HTTP)
    ("Windows host", {5986}, "any"),                      # WinRM (HTTPS)
    ("Windows host", {47001}, "any"),                     # WinRM listener
    ("Windows host", {5357}, "any"),                      # WSDAPI / Function Discovery
    ("network equipment", {161, 23}, "all"),              # SNMP + telnet mgmt
]


def _device_type_from_services(ports: list[int]) -> str:
    """Infer a device ROLE from the set of open ports; '' when nothing is
    conclusive.

    A real, observed signal (these ports actually answered) but an inference
    about the device's role, not a stack fingerprint — the caller labels it
    "(inferred from services)" so it is never read as an nmap classification. A
    port set that matches nothing high-signal returns '' (we never guess a role we
    can't back with a service)."""
    open_set = {int(p) for p in ports if isinstance(p, int) or str(p).isdigit()}
    if not open_set:
        return ""
    for label, need, mode in _SERVICE_DEVICE_TYPES:
        if mode == "all":
            if need <= open_set:
                return label
        elif need & open_set:
            return label
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


def _os_from_smb_script(script_id: str, output: str) -> str:
    """Pull a precise OS string out of an nmap ``smb-os-discovery`` host script.

    This NSE script runs under ``-sC`` **without root** and reports the host's
    OWN, SMB-advertised operating system — e.g. ``OS: Windows 10 Pro 19041
    (Windows 10 Pro 6.3)``. That is far more specific than the generic "Windows"
    a TTL bucket or a version-less OS CPE yields, and it is exactly what the EOL
    scanner needs to recognise an end-of-life release (Windows 10, Server 2012,
    …). We read the ``OS:`` line first, then fall back to the ``OS CPE:`` line.
    Anything we can't confidently parse yields '' — the OS is never invented.
    """
    import re
    sid = (script_id or "").lower()
    text = output or ""
    if sid != "smb-os-discovery":
        return ""
    m = re.search(r"^\s*OS:\s*([^\n\x00]+)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        os_str = m.group(1).strip()
        # Drop a trailing "(Windows … 6.3)" build-number parenthetical and an
        # "Unknown"/"-" placeholder some hosts return.
        os_str = re.sub(r"\s*\([^)]*\)\s*$", "", os_str).strip()
        if os_str and os_str.lower() not in ("unknown", "-"):
            return os_str
    m = re.search(r"^\s*OS CPE:\s*(cpe:[^\n\x00]+)", text,
                  re.IGNORECASE | re.MULTILINE)
    if m:
        return _os_name_from_cpe(m.group(1).strip())
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


# Trusted source ports a naive port-based ACL frequently permits inbound: DNS
# (53), Kerberos (88) and HTTP (80). Sourcing a probe from one slips past a
# filter that only allows "replies" to those services.
_EVASION_SOURCE_PORTS = ("53", "88", "80")


def _nmap_evasion_args(raw_capable: bool, *, intensity: str = "standard") -> list[str]:
    """Firewall/IDS-evasion nmap flags for an AUTHORIZED re-probe of a filtered
    host — the standard nmap techniques for getting probes past a packet filter
    (RFC-legal, the same ones ``nmap`` documents).

    ``intensity`` selects how aggressive the reshaping is:

    * ``"standard"`` — fragmentation, a trusted source port, light padding and a
      handful of decoys. The default; effective against simple stateful filters.
    * ``"aggressive"`` — smaller MTU fragmentation, heavier randomised padding and
      a larger decoy cloud, for a filter that resisted the standard pass.

    Raw-socket-gated: packet fragmentation (``-f`` / ``--mtu``), padding
    (``--data-length``) and decoys (``-D``) only affect nmap's *raw* SYN/UDP
    scans, so they are added only when we can run privileged. An unprivileged
    connect scan can still source from a trusted port, which defeats naive
    port-based ACLs on most platforms. Nothing here spoofs the source IP address
    or forges credentials — it only reshapes our own probes so a default-drop
    filter is more likely to pass them.
    """
    if not raw_capable:
        # The only reshaping an OS-stack connect scan can do is choose its source
        # port; 53 is the single most widely allowed. (The technique ladder in
        # _evasion_reprobe rotates the others across attempts.)
        return ["--source-port", "53"]
    if intensity == "aggressive":
        return [
            "--mtu", "16",           # fragment into 16-byte chunks (below -f's 8*n)
            "--data-length", "50",   # heavier padding past fixed-length heuristics
            "--source-port", "53",   # source from DNS/53 — frequently allowed
            "-D", "RND:10",          # 10 random decoys bury the real source
            "--randomize-hosts",     # non-linear host order across a sweep
        ]
    return [
        "-f",                    # fragment IP headers so signature filters miss them
        "--data-length", "24",   # pad probes past fixed-length-packet heuristics
        "--source-port", "53",   # source from DNS/53 — frequently allowed outbound
        "-D", "RND:6",           # 6 random decoys obscure which source is the scanner
    ]


def _nmap_technique_args(scan_type: str, raw_capable: bool) -> Optional[list[str]]:
    """nmap flags for a non-SYN firewall-mapping scan technique, or ``None`` when
    the technique needs raw sockets we don't have.

    These are the classic techniques for characterising and slipping past a
    firewall that a plain SYN/connect scan can't see through:

    * ``"ack"`` (``-sA``) — an ACK probe is never "open/closed", only
      ``unfiltered`` vs ``filtered``. It maps *which ports a stateful firewall
      lets through* and tells a stateful filter (all filtered) apart from a
      stateless one (some unfiltered), without ever completing a handshake.
    * ``"fin"`` (``-sF``) / ``"null"`` (``-sN``) / ``"xmas"`` (``-sX``) — probes
      with no SYN flag sail past a filter (or a stateless ACL) that only blocks
      SYN packets; a closed port answers RST, an open|filtered port stays silent,
      so a genuinely-open port that a SYN scan showed as "filtered" is revealed.

    All are raw-socket-only; unprivileged returns ``None`` (the caller falls back
    to the connect-based techniques).
    """
    if not raw_capable:
        return None
    return {
        "ack": ["-sA"],
        "fin": ["-sF"],
        "null": ["-sN"],
        "xmas": ["-sX"],
    }.get(scan_type)


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


async def _connect_probe_states(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    stealth_level: str = "normal",
) -> tuple[list[PortResult], int, int]:
    """State-aware TCP-connect probe: returns ``(open_ports, filtered, closed)``.

    A plain connect scan only reports what's *open*. This variant also classifies
    the unopened ports the way nmap does — the crucial firewall signal — by
    reading WHY each connect failed:

    * ``ConnectionRefusedError`` (a TCP RST) → the port is **closed**; the host is
      reachable and simply has nothing listening. This is the *no-firewall*
      signature.
    * a timeout, or an unreachable/host-down ``OSError`` → the probe was silently
      **dropped**; that is the packet-filter (``filtered``) signature.

    So on a host that answers nothing on TCP yet is clearly up (it replied to
    NBSTAT / ARP), a wall of ``filtered`` vs almost no ``closed`` is exactly what
    lets :func:`classify_perimeter` say "packet-filtering firewall" — and it now
    works even when nmap timed out before emitting its own tallies. Real
    observations only; nothing is invented.
    """
    if not ports:
        return [], 0, 0
    profile = profile_for(stealth_level)
    concurrency = min(1000, max(50, profile.max_concurrent if profile else 500))
    sem = asyncio.Semaphore(concurrency)
    connect_timeout = min(3.0, max(0.4, timeout))
    OPEN, FILTERED, CLOSED = 0, 1, 2

    async def _probe(port: int) -> tuple[int, int]:
        async with sem:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=connect_timeout,
                )
            except asyncio.TimeoutError:
                return port, FILTERED
            except ConnectionRefusedError:
                return port, CLOSED
            except OSError as e:
                # ECONNRESET is also a RST (closed); ENETUNREACH/EHOSTUNREACH and
                # the rest are drops from this vantage point (filtered/unreachable).
                if e.errno == errno.ECONNRESET:
                    return port, CLOSED
                return port, FILTERED
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await writer.wait_closed()
            return port, OPEN

    outcomes = await asyncio.gather(*[_probe(p) for p in ports])
    open_nums = sorted(p for p, st in outcomes if st == OPEN)
    filtered = sum(1 for _p, st in outcomes if st == FILTERED)
    closed = sum(1 for _p, st in outcomes if st == CLOSED)

    banners: dict[int, str] = {}
    grab = [p for p in open_nums if p in _BANNER_READ_PORTS or p in _HTTP_LIKE_PORTS]
    if grab:
        grabbed = await asyncio.gather(
            *[_grab_banner(host, p, connect_timeout) for p in grab])
        banners = {p: b for p, b in zip(grab, grabbed) if b}
    open_ports = [
        PortResult(host=host, port=port, protocol="tcp", state="open",
                   service=SERVICE_FINGERPRINTS.get(port, ""),
                   banner=banners.get(port, ""))
        for port in open_nums
    ]
    return open_ports, filtered, closed


async def _connect_scan_fallback(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    stealth_level: str = "normal",
    assume_up: bool = False,
) -> list[PortResult]:
    """Reliable connect-scan recovery for when nmap comes back with no open ports.

    Runs in two stages so a live host is fully covered while a genuinely dead /
    silent one is ruled out fast — important because this may run per-host inside
    a CIDR sweep:

    1. Probe the curated high-value service ports first (FTP/SSH/SMTP/HTTP/SMB/
       DB/…). These answer in a couple of seconds; an open one proves the host is
       alive. If NONE answer, and ``assume_up`` is False, we stop and report
       nothing, so a dead or fully silent host never pays for a full-range sweep
       and no port is invented.
    2. Once the host has proven itself alive — or the caller passed ``assume_up``
       because it already KNOWS the host is up (a focused scan of explicitly-named
       targets) — we sweep the *rest* of the requested range, so a genuinely-open
       uncommon port is never missed. Without this, a hardened host that answers
       only on an uncommon port (e.g. a filtered Windows box exposing solely
       5357/wsdapi) would be reported as "0 open ports / 0 findings" despite a
       live, open service.

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
    if not found and not assume_up:
        # No high-value service answered and we have no independent proof this
        # host is up → treat it as dead / empty rather than spending the budget
        # connect-scanning every port of a silent box. This fast bail is what
        # keeps a wide CIDR sweep affordable. A focused scan of named targets
        # passes assume_up=True so this bail is skipped and the requested band is
        # always completed (see stage 2 above).
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


async def _nmap_service_scan(
    host: str,
    ports: list[int],
    *,
    stealth_level: str = "normal",
    host_timeout: str = "120s",
    evade: bool = False,
    connect_scan: bool = False,
    context_ports: Optional[list[int]] = None,
) -> dict[int, PortResult]:
    """Targeted nmap ``-sV -sC`` on a KNOWN-SHORT list of already-open ports.

    This is the enrichment counterpart to the connect-scan fallback. Once the
    open ports are known — from a full-range ``-sV -sC`` sweep that hit its
    ``--host-timeout`` (or crashed) on a slow / heavily-filtered / emulated host,
    with the ports recovered by the built-in connect scanner — a version scan of
    *just those ports* finishes in seconds where the full-range sweep never could,
    and restores the service / product / version / CPE / NSE detail that drives
    the inventory columns and CVE mapping (which keys off product/version/banner).

    ``connect_scan`` forces a TCP connect scan (``-sT``) instead of nmap's default
    (which is a raw SYN scan when HEAVEN runs nmap privileged, via passwordless
    sudo / root). The enrichment always targets ports already proven open by a real
    TCP handshake, so a connect scan is the faithful match — and it is REQUIRED for
    ports that answer a full connect but not a bare SYN (e.g. the dynamic RPC ports
    on a filtered / emulated host, which a SYN scan reports as filtered).

    ``context_ports`` are scanned alongside ``ports`` but never returned as targets
    to merge — they give nmap the context it needs to identify the real targets.
    The canonical case is rpcbind (111): without it in the same scan, nmap cannot
    resolve a dynamically-assigned RPC port to its program (status / nlockmgr /
    mountd …) and leaves it ``unknown``.

    Returns ``{port: PortResult}`` for the ports nmap could parse (each PortResult
    already carries service/product/version/extrainfo/cpe/banner/fingerprint —
    see :func:`_parse_nmap_xml`). Best-effort: returns ``{}`` when nmap is absent,
    crashes, or identifies nothing. Never raises. Does NOT acquire the host
    semaphore — the caller (``scan_host``) already holds its slot.
    """
    if not ports:
        return {}
    if _egress_port_scan_blocked():  # fail-closed under an un-wrappable proxy egress
        return {}
    scan_ports = sorted(set(ports) | set(context_ports or []))
    port_str = _build_nmap_port_spec(scan_ports)
    if not port_str:
        return {}
    timing = _nmap_timing_args(stealth_level)
    sudo_prefix = list(_nmap_sudo_prefix())
    # Egress: proxychains-wrap + force connect scan under a proxy/Tor mode.
    proxy_prefix, force_connect = _egress_nmap()
    if force_connect:
        sudo_prefix = []
    evasion = (
        _nmap_evasion_args(_have_admin_privileges() or bool(sudo_prefix))
        if evade else []
    )
    scan_type = ["-sT"] if (connect_scan or force_connect) else []
    # -sV ONLY (deliberately no -sC). Service/version/CPE — everything the
    # inventory columns and CVE mapping need — comes from -sV; the default-script
    # engine (-sC / NSE) is the slow, occasionally-crashing half and adds nothing
    # to those fields, so leaving it out keeps this enrichment fast (~20-30s on a
    # ~30-port list) and reliable enough to finish inside its bounded host-timeout
    # even on a loaded machine. The primary full-range scan already carries NSE
    # output for anything it reached.
    cmd = [
        *proxy_prefix, *sudo_prefix, "nmap", *scan_type, "-sV", "-Pn", "-p", port_str,
        "-oX", "-", "--host-timeout", host_timeout, *timing, *evasion, host,
    ]
    parsed: Optional[dict] = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await proc.communicate()
        parsed = _parse_nmap_xml(stdout, host) if stdout else None
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        logger.debug("targeted -sV enrichment failed for %s", host, exc_info=True)
        return {}

    if not parsed:
        return {}
    return {p.port: p for p in parsed["ports"]}


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
    # strongest device-name signal. nmap surfaces it under <hostscript>. The same
    # smb-os-discovery script also carries the host's own precise OS string, which
    # we mine here (unprivileged, machine-advertised) for the OS-detection tiers
    # below — without it a Windows 10/Server box reads as a generic "Windows".
    smb_os = ""
    for script in xml_root.findall(".//hostscript/script"):
        _sid, _out = script.get("id", ""), script.get("output", "")
        if not device_name:
            name = _netbios_name_from_script(_sid, _out)
            if name:
                device_name = name
                device_name_source = "netbios"
        if not smb_os:
            smb_os = _os_from_smb_script(_sid, _out)
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
    # 1.5 smb-os-discovery — the host's OWN SMB-advertised OS (precise, needs no
    #     root). Used when nmap's -O fingerprint is absent; more specific than the
    #     service/TTL tiers below, so a Windows 10/Server release is recognised.
    if not os_guess and smb_os:
        os_guess = smb_os
        os_source = "heuristic"
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


def _merge_recovered_ports(
        host_result: HostResult, recovered: list, ctx: str) -> list[int]:
    """Union newly-discovered open ports into ``host_result``.

    Adds only ports not already present (never removes or overwrites nmap's own
    version-rich entries), marks the host alive, and corrects the closed-port tally
    the perimeter classifier reads. ``ctx`` labels the log line. Returns the sorted
    list of port numbers actually added (empty when nothing new was found) so the
    caller can target follow-up enrichment at exactly the new ports.
    """
    if not recovered:
        return []
    known = {p.port for p in host_result.open_ports}
    added = [p for p in recovered if p.port not in known]
    if not added:
        return []
    host_result.open_ports = sorted(
        host_result.open_ports + added, key=lambda p: p.port)
    host_result.is_alive = True
    host_result.closed_ports = max(0, host_result.closed_ports - len(added))
    logger.info(
        "  ↳ %s found %d open port(s) on %s: %s", ctx, len(added),
        host_result.host, ", ".join(str(p.port) for p in added))
    return sorted(p.port for p in added)


async def _enrich_versionless_ports(
    host_result: HostResult,
    host: str,
    host_timeout: str,
    stealth_level: str,
    evade: bool,
    only_ports: Optional[list[int]] = None,
    context_ports: Optional[list[int]] = None,
    connect_scan: bool = False,
) -> None:
    """Fill service/product/version/CPE for the open ports the connect scanner
    recovered without version data, via a targeted :func:`_nmap_service_scan`.

    Merges nmap's real detection onto each matching port IN PLACE (nmap wins over
    the bare connect-scan banner; NSE fingerprints are merged). Every port was
    already proven open by a real handshake, so nothing is fabricated. No-op when
    no open port is missing version data. When ``only_ports`` is given, the scan is
    scoped to just those ports (used for the second pass over the freshly-swept
    ephemeral/high band, so the service band isn't needlessly re-probed).

    ``connect_scan`` and ``context_ports`` are passed straight through to
    :func:`_nmap_service_scan` (the ephemeral/high-band pass forces ``-sT`` and
    hands nmap the rpcbind port so dynamic RPC services resolve). The merge is
    restricted to the targeted (needy) ports, so context ports are never touched.
    """
    scope = set(only_ports) if only_ports is not None else None
    needy = [p.port for p in host_result.open_ports
             if not p.product and not p.version
             and (scope is None or p.port in scope)]
    if not needy:
        return
    needy_set = set(needy)
    enriched = await _nmap_service_scan(
        host, needy, stealth_level=stealth_level,
        host_timeout=host_timeout, evade=evade,
        connect_scan=connect_scan, context_ports=context_ports)
    filled = 0
    for pr in host_result.open_ports:
        if pr.port not in needy_set:
            continue
        e = enriched.get(pr.port)
        if e is None:
            continue
        if e.service:
            pr.service = e.service
        if e.product:
            pr.product = e.product
        if e.version:
            pr.version = e.version
        if e.extrainfo:
            pr.extrainfo = e.extrainfo
        if e.banner:
            pr.banner = e.banner
        if e.cpe:
            pr.cpe = e.cpe
        if e.fingerprint:
            pr.fingerprint = {**pr.fingerprint, **e.fingerprint}
        if e.product or e.version:
            filled += 1
    if filled:
        logger.info(
            "  ↳ targeted -sV enrichment identified %d service version(s) on %s "
            "the full-range sweep could not finish", filled, host)


def _nmap_wait_budget(host_timeout: str, *, margin: float = 60.0) -> float:
    """Seconds to wait on an nmap subprocess before force-killing it.

    nmap's own ``--host-timeout`` normally fires first; this is a
    belt-and-suspenders upper bound so a wedged nmap (stuck in startup, DNS, or a
    version probe) can never hang the scan — directly honouring "nothing hangs".
    Derived from ``host_timeout`` plus a margin for version-detection wrap-up and
    the final XML flush."""
    secs = 120.0
    try:
        v = host_timeout.strip().lower()
        if v.endswith("ms"):
            secs = float(v[:-2]) / 1000.0
        elif v.endswith("s"):
            secs = float(v[:-1])
        elif v.endswith("m"):
            secs = float(v[:-1]) * 60.0
        elif v.endswith("h"):
            secs = float(v[:-1]) * 3600.0
        elif v:
            secs = float(v)
    except (ValueError, AttributeError):
        secs = 120.0
    return max(30.0, secs + margin)


async def _terminate_proc(proc: "asyncio.subprocess.Process") -> None:
    """Best-effort terminate → kill of a subprocess that overran its budget, so no
    orphaned nmap lingers and the caller is never blocked waiting on it."""
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except (asyncio.TimeoutError, ProcessLookupError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):  # noqa: BLE001 — reap, never raise
            await proc.wait()


async def _nmap_udp_scan(
    host: str,
    ports: list[int],
    *,
    stealth_level: str,
    host_timeout: str,
    evade: bool,
) -> tuple[Optional[list[PortResult]], bool]:
    """Privileged UDP scan via ``nmap -sU -sV``.

    Returns ``(open_udp_ports, timed_out)``:

    * ``(None, False)`` — nmap could not run (proxy egress that can't carry raw
      UDP, no nmap on PATH, or unparseable XML). The caller falls back to the
      pure-Python probe scanner.
    * ``(None, True)``  — the nmap process overran its hard wall-clock budget and
      was killed. Also a full fall-back, but flagged as incomplete.
    * ``(ports, False)`` — authoritative result (``ports`` may be empty: nmap
      finished and that is genuinely all that is open).
    * ``(ports, True)``  — nmap hit its ``--host-timeout`` before finishing;
      ``ports`` holds whatever it confirmed open so far and the caller supplements
      the rest with the bounded pure-Python probes (never a silent zero on a slow
      or heavily-filtered host)."""
    proxy_prefix, force_connect = _egress_nmap()
    if force_connect:
        # Raw UDP can't traverse a proxy — let the caller use the probe scanner.
        return None, False
    sudo_prefix = list(_nmap_sudo_prefix())
    port_str = _build_nmap_port_spec(ports)
    if not port_str:
        return [], False
    timing = _nmap_timing_args(stealth_level)
    evasion = _nmap_evasion_args(True, intensity="standard") if evade else []
    cmd = [
        *proxy_prefix, *sudo_prefix, "nmap", "-sU", "-sV", "-Pn",
        "-p", port_str, "-oX", "-", "--host-timeout", host_timeout, *timing,
        *evasion, host,
    ]
    logger.debug("nmap (udp): %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_nmap_wait_budget(host_timeout))
    except asyncio.TimeoutError:
        # nmap ignored its own --host-timeout (wedged) — kill it and fall back.
        await _terminate_proc(proc)
        logger.debug("nmap -sU exceeded its wall-clock budget for %s — "
                     "falling back to pure-Python UDP probes", host)
        return None, True
    parsed = _parse_nmap_xml(stdout, host)
    if not parsed:
        return None, False
    # _parse_nmap_xml already keeps only state=="open" ports; select the UDP ones.
    udp = [p for p in parsed["ports"] if p.protocol == "udp"]
    return udp, bool(parsed.get("host_timed_out"))


async def _udp_service_scan(
    host: str,
    udp_ports: Optional[list[int]],
    *,
    timeout: float = 2.0,
    stealth_level: str = "normal",
    raw_capable: bool = False,
    host_timeout: str = "120s",
    evade: bool = False,
) -> list[PortResult]:
    """Scan UDP ports and return the genuinely-open ones as ``PortResult`` objects
    (``protocol="udp"``). Privileged hosts use nmap ``-sU`` (authoritative state +
    version); everyone else uses the pure-Python service-probe scanner, which only
    reports a port open when a real service answers. ``udp_ports`` defaults to the
    curated common-UDP set when not given."""
    from heaven.recon.udp_scanner import COMMON_UDP_PORTS, scan_udp_ports

    ports = sorted(set(udp_ports)) if udp_ports else list(COMMON_UDP_PORTS)
    if not ports:
        return []

    confirmed: list[PortResult] = []
    if raw_capable:
        try:
            nmap_ports, timed_out = await _nmap_udp_scan(
                host, ports, stealth_level=stealth_level,
                host_timeout=host_timeout, evade=evade)
        except FileNotFoundError:
            nmap_ports, timed_out = None, False  # no nmap on PATH
        except Exception:  # noqa: BLE001
            logger.debug("nmap -sU failed for %s — using pure-Python UDP probes",
                         host, exc_info=True)
            nmap_ports, timed_out = None, False
        if nmap_ports is not None and not timed_out:
            return nmap_ports  # nmap finished — authoritative UDP state
        # nmap was unavailable or ran out of time: keep whatever it confirmed and
        # fill the rest with the bounded pure-Python probes so a slow / heavily
        # filtered host still gets its responsive UDP services caught, instead of
        # a silent zero. The probe scanner reports open only on a real reply, so
        # merging never invents a port.
        confirmed = list(nmap_ports or [])

    seen = {p.port for p in confirmed}
    remaining = [p for p in ports if p not in seen]
    if not remaining:
        return confirmed

    profile = profile_for(stealth_level)
    concurrency = min(256, max(32, profile.max_concurrent // 4)) if profile else 128
    out = await scan_udp_ports(
        host, remaining, timeout=max(1.0, timeout), concurrency=concurrency)
    for p in out.get("open", []):
        confirmed.append(PortResult(
            host=host, port=int(p["port"]), protocol="udp", state="open",
            service=p.get("service", ""), banner=p.get("banner", ""),
        ))
    return confirmed


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    semaphore: Optional[asyncio.Semaphore] = None,
    include_udp: bool = False,
    udp_ports: Optional[list[int]] = None,
    stealth_level: str = "normal",
    host_timeout: str = "30m",
    enrich_host_timeout: str = "120s",
    ephemeral_enrich_host_timeout: str = "60s",
    evade: bool = False,
    evade_intensity: str = "standard",
    focused: bool = False,
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

    ``enrich_host_timeout`` bounds the follow-up targeted ``-sV`` service scan that
    runs on a DEGRADED host: when the full-range sweep hits its host-timeout (or
    crashes) and the connect scanner recovers the ports version-less, a ``-sV`` of
    just those (now known, short) ports restores service/version/CPE/NSE — the
    inventory columns and CVE inputs — in seconds. Bounded so it always fits inside
    the caller's deep-scan budget (see ``scan_network``).

    ``ephemeral_enrich_host_timeout`` bounds the SECOND targeted ``-sV`` that
    fingerprints the freshly-swept ephemeral/high band (dynamic RPC/OS ports). It
    runs after a short settle so the completion-sweep flood can't starve it, and is
    kept shorter than ``enrich_host_timeout`` because that port list is tiny.
    """
    sem = semaphore or asyncio.Semaphore(50)
    host_result = HostResult(host=host)
    start = time.time()

    # Fail-closed: skip the port scan entirely if a proxy egress can't carry it
    # (no proxychains + kill-switch on) rather than leak the real IP.
    if _egress_port_scan_blocked():
        return host_result

    port_str = _build_nmap_port_spec(ports)
    timing = _nmap_timing_args(stealth_level)

    # ── Fast curated preflight ─────────────────────────────────────────────────
    # Probe the high-value ports (web / DB / SMB / RDP / WinRM / WSDAPI / AD …)
    # with a quick TCP-connect scan BEFORE nmap. On a heavily-filtered host nmap's
    # own -sV -sC scan grinds until its --host-timeout — and if the caller's time
    # budget fires first, nmap is CANCELLED and the connect-scan recovery below
    # never runs, so the host's one open high port (the reproduced Windows-7
    # "5357/wsdapi only" case) is lost entirely. This preflight captures those
    # obvious services in ~2s regardless of how long nmap takes or whether it is
    # cancelled; nmap then enriches them with -sV, and _merge keeps nmap's richer
    # entries. Real handshakes only — nothing invented. Skipped under proxy egress
    # (fail-closed above already returned) and best-effort (never raises).
    preflight: list[PortResult] = []
    preflight_filtered = 0
    preflight_closed = 0
    curated_preflight = sorted(set(ports) & _ALWAYS_PROBE_PORTS)
    if curated_preflight:
        try:
            preflight, preflight_filtered, preflight_closed = await _connect_probe_states(
                host, curated_preflight, timeout=timeout, stealth_level=stealth_level)
        except Exception:  # noqa: BLE001 — preflight is best-effort insurance
            logger.debug("curated preflight probe failed for %s", host, exc_info=True)

    # Decide privileges once: -O / -sS / -sU all need raw sockets, and running
    # any of them unprivileged makes nmap abort the ENTIRE scan (losing the port
    # data too). Elevate through passwordless sudo when it's available; when it
    # isn't, drop those flags and rely on the honestly-labelled service/TTL OS
    # heuristics instead of killing the scan.
    sudo_prefix = list(_nmap_sudo_prefix())
    raw_capable = _have_admin_privileges() or bool(sudo_prefix)
    # Network egress (proxy/Tor): force a proxychains-wrapped TCP connect scan;
    # raw SYN/UDP/OS scans can't traverse a proxy, and a connect scan needs no
    # root (so drop sudo — mixing sudo with proxychains loses the LD_PRELOAD).
    proxy_prefix, force_connect = _egress_nmap()
    if force_connect:
        raw_capable = False
        sudo_prefix = []
    if not raw_capable and not force_connect:
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
    # Explicit -sT under proxy egress; otherwise nmap picks connect automatically
    # when it lacks raw privileges.
    connect_flag = ["-sT"] if force_connect else []

    # UDP is handled by a DEDICATED pass AFTER the TCP scan (see _udp_service_scan
    # below), never merged into this command. Two reasons: (1) it keeps UDP out of
    # the TCP degraded-recovery logic, which assumes a TCP-only port set; (2) it
    # lets UDP work UNPRIVILEGED via HEAVEN's pure-Python service probes — nmap's
    # -sU needs raw sockets most operators don't have, so an inline -sU silently
    # did nothing for them. The dedicated pass uses nmap -sU when root is available
    # and the pure-Python probes otherwise, so UDP services are actually found.
    scan_flags: list[str] = []
    port_args = ["-p", port_str]

    # Firewall/IDS-evasion flags for an authorized re-probe of a filtered host.
    evasion = _nmap_evasion_args(raw_capable, intensity=evade_intensity) if evade else []

    cmd = [
        *proxy_prefix, *sudo_prefix, "nmap", "-sV", "-sC", "-Pn",
        *os_flag, *connect_flag, *scan_flags, *port_args,
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

            # Fold in the curated preflight result. If nmap timed out / was
            # cancelled before reaching the host's one open high port, this is
            # where that port survives — merged so nmap's richer -sV entries win
            # for any port both saw. A preflight hit also proves the host is up.
            if preflight:
                added_pf = _merge_recovered_ports(
                    host_result, preflight, "curated preflight")
                if host_result.open_ports:
                    host_result.is_alive = True
                if added_pf:
                    logger.debug(
                        "preflight captured %d high-value port(s) on %s nmap "
                        "missed/never reached: %s", len(added_pf), host,
                        ", ".join(str(p) for p in added_pf))
            # Backfill the perimeter tallies from the state-aware preflight when
            # nmap emitted none (it timed out / crashed before finishing). Without
            # this the firewall classifier goes blind on exactly the heavily-
            # filtered host it exists to flag: a wall of curated ports that timed
            # out (filtered) with almost none refused (closed) is the packet-filter
            # signature. Only backfill when nmap gave nothing, so a completed nmap's
            # richer full-range tallies always win.
            if (host_result.filtered_ports == 0 and host_result.closed_ports == 0
                    and (preflight_filtered or preflight_closed)):
                host_result.filtered_ports = preflight_filtered
                host_result.closed_ports = preflight_closed

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
            degraded = nmap_ran and (
                not host_result.open_ports or host_timed_out or parsed is None)
            if degraded:
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

                # ORDER MATTERS. Recover + `-sV`-ENRICH the SERVICE band FIRST, then
                # sweep the ephemeral/high band. The full-range completion sweep
                # floods the target with tens of thousands of short-lived connections,
                # which leaves a fragile / emulated / rate-limited host (and the
                # scanner's own local ephemeral-port pool) unresponsive long enough to
                # STARVE a follow-up `-sV` — every probe dropped, 0 versions returned.
                # That is exactly the "ports show up but Service/Version/CVE are blank"
                # symptom. Every CVE-bearing service lives in the service band (plus
                # the curated high-value ports), so we version-scan it while the host
                # is still healthy; the ephemeral/high band is only dynamic RPC / OS
                # ports with no CVE surface, so those legitimately stay version-less.
                port_set = set(ports)
                service_ports = sorted(
                    p for p in port_set
                    if p <= _SERVICE_PORT_CEILING or p in _ALWAYS_PROBE_PORTS)
                ephemeral_ports = sorted(port_set - set(service_ports))
                # A request confined to the high range has no separate flood band —
                # recover + enrich it directly (it's small, so it can't flood).
                if not service_ports:
                    service_ports, ephemeral_ports = ephemeral_ports, []

                if service_ports:
                    # common-first: on a wide sweep this bails cheaply on a dead
                    # host (no full sweep), so it stays safe per-host inside a CIDR
                    # range. On a FOCUSED scan of named hosts we already know the
                    # host is up, so assume_up=True forces the requested service
                    # band to be completed even when only an uncommon port is open
                    # — otherwise a hardened host (e.g. Windows filtered down to
                    # 5357/wsdapi) would come back as "0 open ports".
                    recovered = await _connect_scan_fallback(
                        host, service_ports, timeout=timeout,
                        stealth_level=stealth_level, assume_up=focused)
                    _merge_recovered_ports(
                        host_result, recovered, "connect-scan recovery")

                # Enrich the version-less open ports NOW — before the ephemeral flood
                # — while the host is still responsive.
                if host_result.open_ports:
                    await _enrich_versionless_ports(
                        host_result, host, enrich_host_timeout,
                        stealth_level, evade)

                # Completion sweep of the ephemeral/high band for a full inventory,
                # but ONLY once the host proved alive in the service band (a dead host
                # answered nothing → skip the expensive sweep). Runs AFTER the
                # service-band enrichment so its flood can't starve THAT `-sV`.
                if host_result.open_ports and ephemeral_ports:
                    rest = await _python_connect_scan(
                        host, ephemeral_ports, timeout=timeout,
                        stealth_level=stealth_level)
                    newly = _merge_recovered_ports(
                        host_result, rest, "ephemeral-range sweep")
                    # Fingerprint the freshly-discovered high ports too — but only
                    # after a short settle so the flood (and the local port pool) has
                    # drained; a `-sV` fired immediately after the flood is starved
                    # just like the first pass. Scoped to just the new ports (a
                    # handful of dynamic RPC/OS services). Two things make these
                    # resolve where the primary sweep couldn't: a forced connect scan
                    # (`-sT` — they answer a full handshake but not a bare SYN on a
                    # filtered/emulated host), and handing nmap the rpcbind port(s) as
                    # context so a dynamic RPC port maps to its program (status /
                    # nlockmgr / mountd …) instead of staying `unknown`.
                    if newly:
                        if _ENRICH_SETTLE_SECONDS > 0:
                            await asyncio.sleep(_ENRICH_SETTLE_SECONDS)
                        rpc_ctx = sorted({
                            p.port for p in host_result.open_ports
                            if p.port == 111 or p.service == "rpcbind"})
                        await _enrich_versionless_ports(
                            host_result, host, ephemeral_enrich_host_timeout,
                            stealth_level, evade, only_ports=newly,
                            context_ports=rpc_ctx, connect_scan=True)

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

    # ── UDP service scan ───────────────────────────────────────────────────────
    # Opt-in (include_udp). Real UDP services — DNS, DHCP, TFTP, NTP, SNMP,
    # NetBIOS, RPC/portmap, IKE, SIP, mDNS, SSDP, syslog, RADIUS … — are invisible
    # to the TCP sweep above, so a full assessment must probe them separately. This
    # pass uses nmap -sU (authoritative state + -sV version) when we have raw
    # sockets, and HEAVEN's pure-Python service-probe scanner otherwise — the
    # latter reports a UDP port open ONLY when a service actually answers a real
    # protocol probe, so a responsive UDP service is caught at any privilege level
    # with no invented "open" from silence. Never breaks the host scan.
    if include_udp:
        try:
            udp_results = await _udp_service_scan(
                host, udp_ports, timeout=timeout, stealth_level=stealth_level,
                raw_capable=raw_capable, host_timeout=enrich_host_timeout,
                evade=evade,
            )
        except Exception:  # noqa: BLE001 — UDP scan is additive; never fatal
            logger.debug("UDP service scan failed for %s", host, exc_info=True)
            udp_results = []
        if udp_results:
            existing = {(p.port, p.protocol) for p in host_result.open_ports}
            added_udp = 0
            for up in udp_results:
                if (up.port, up.protocol) not in existing:
                    host_result.open_ports.append(up)
                    existing.add((up.port, up.protocol))
                    added_udp += 1
            if added_udp:
                host_result.is_alive = True
                logger.info("  %s: %d open UDP service(s)", host, added_udp)

    # ── NetBIOS (UDP/137) enrichment ───────────────────────────────────────────
    # A hardened Windows host filters every classic TCP port yet still answers an
    # NBSTAT node-status query on the LAN — recovering its computer name, work-
    # group/domain, MAC and Server-service state without root or an open TCP port.
    # This is the direct fix for "live Windows box → OS not determined, 0 ports":
    # a positive NBSTAT reply is itself a Windows signal, so we confirm the OS,
    # learn the hostname, and note that file sharing (SMB) is running behind the
    # firewall. Best-effort, LAN-only, never overwrites a stronger nmap fact.
    try:
        from heaven.recon.netbios import nbstat as _nbstat
        nb = await _nbstat(host, timeout=min(4.0, max(2.0, timeout)))
    except Exception:  # noqa: BLE001 — enrichment must never break a scan
        nb = None
    if nb is not None:
        host_result.netbios = nb.to_dict()
        host_result.is_alive = True  # it answered us — it is genuinely up
        if nb.computer_name and not host_result.device_name:
            host_result.device_name = nb.computer_name
            host_result.device_name_source = "netbios"
        if nb.mac_address and not host_result.mac_address:
            host_result.mac_address = nb.mac_address
        # NBSTAT is a Windows/SMB-stack protocol: a reply confirms Windows. Only
        # UPGRADE from nothing / a bare TTL guess — never override a specific
        # nmap -O or service-CPE OS (which may carry the exact release).
        if not host_result.os_guess or host_result.os_source in ("", "heuristic"):
            if "windows" not in host_result.os_guess.lower():
                host_result.os_guess = "Windows"
            if not host_result.os_source or host_result.os_source == "heuristic":
                host_result.os_source = "netbios"
        if not host_result.device_type:
            host_result.device_type = ("domain controller"
                                       if nb.is_domain_controller else "Windows host")
            host_result.device_type_source = "netbios"

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

    Runs an escalating LADDER of independent techniques and merges them, because a
    packet-filter that drops one probe signature often lets another through. Each
    rung presents a completely different packet signature to the filter:

    1. **Standard nmap evasion** — fragmentation + light padding + a trusted
       source port (53) + a decoy cloud (``evade=True``).
    2. **Pure-Python connect scan** — rides the OS TCP stack, so it looks like a
       normal client connection rather than an nmap probe; slips past filters that
       target nmap's raw-packet fingerprint.
    3. **Aggressive nmap evasion** (only if the earlier rungs found nothing, and
       only when raw-capable) — smaller-MTU fragmentation, heavier randomised
       padding and a larger decoy cloud, for a filter that resisted the standard
       pass.

    Timing is bumped to at least ``stealth`` (slower, lower parallelism) so an
    IPS that started rate-blocking has cooled down. Bounded by a short per-host
    nmap ``--host-timeout`` and the small high-value port set the caller passes.
    Returns the union of open ports discovered; never raises.
    """
    if not ports:
        return []
    bumped = "stealth" if stealth_level in ("normal", "aggressive", "loud") else stealth_level
    found: dict[int, PortResult] = {}

    # Rung 1 — standard nmap evasion (fragment / pad / source-port 53 / decoys).
    try:
        r = await scan_host(
            host, ports, timeout=max(timeout, 3.0), semaphore=sem,
            stealth_level=bumped, evade=True, host_timeout="60s",
        )
        for p in r.open_ports:
            found[p.port] = p
    except Exception:
        logger.debug("evasion nmap re-probe (standard) failed for %s", host, exc_info=True)

    # Rung 2 — pure-Python connect scan (different, OS-stack packet signature).
    try:
        for p in await _python_connect_scan(
            host, ports, timeout=max(timeout, 3.0), stealth_level=bumped,
        ):
            found.setdefault(p.port, p)
    except Exception:
        logger.debug("evasion connect re-probe failed for %s", host, exc_info=True)

    # Rung 3 — aggressive nmap evasion, only when the cheaper rungs found nothing
    # and we can run privileged (fragmentation/decoys need raw sockets to matter).
    raw_capable = _have_admin_privileges() or bool(_nmap_sudo_prefix())
    if not found and raw_capable:
        try:
            logger.info(
                "  ↳ escalating evasion on %s: aggressive fragmentation "
                "(--mtu 16) + heavy padding + 10-decoy cloud", host)
            r = await scan_host(
                host, ports, timeout=max(timeout, 3.0), semaphore=sem,
                stealth_level=bumped, evade=True, evade_intensity="aggressive",
                host_timeout="90s",
            )
            for p in r.open_ports:
                found.setdefault(p.port, p)
        except Exception:
            logger.debug(
                "evasion nmap re-probe (aggressive) failed for %s", host, exc_info=True)

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
    # Windows / Active-Directory surface. A HARDENED Windows host (Windows
    # Firewall on, File & Printer sharing off) silently FILTERS 135/139/445/3389
    # yet still answers on its management/discovery ports — most often
    # 5357/wsdapi (Function Discovery, on by default), WinRM (5985/5986), and the
    # AD control plane on a domain controller. Without these in the liveness set a
    # live-but-firewalled Windows box (the classic internal-engagement target)
    # reads as "down / 0 open ports". 5357 is the single most common survivor.
    5357, 5985, 5986, 88, 3268,
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
    # Windows / AD / remote-management ports that routinely survive on a host
    # whose SMB/RDP are firewalled. This is the structural fix for the reproduced
    # "live Windows 7 shows 0 open ports" miss: 5357/wsdapi is the box's ONLY open
    # port, so it MUST be probed common-first, never left to the slow full sweep.
    5357, 5985, 5986, 47001, 2869,          # WSDAPI / WinRM(HTTP,HTTPS,listener) / UPnP
    88, 464, 3268, 3269, 593, 9389,         # Kerberos / kpasswd / Global Catalog / RPC-HTTP / AD Web Services
    47808, 102, 502,                        # BACnet / S7 / Modbus (OT controllers also silently filter)
})

# The upper bound of the "service band": ports at or below this (plus the curated
# high-value ports above) are where real, CVE-bearing services live. When a
# degraded scan (nmap timed out / crashed) is recovered by the connect scanner, the
# service band is recovered AND -sV-enriched FIRST — before the full-range
# completion sweep floods the target and starves the follow-up version scan (see
# scan_host). Ports above this that aren't curated high-value ports are treated as
# ephemeral / dynamic (RPC, OS) ports; they're fingerprinted by a SECOND targeted
# -sV that runs only AFTER the completion sweep has settled (see below).
# A scan of at most this many hosts is treated as FOCUSED: when nmap degrades
# (host-timeout / crash) on such a host we complete the requested port band with
# the connect scanner even if no curated high-value port answered, because the
# operator explicitly named these hosts and a "0 open ports" result on a live but
# hardened host (only an uncommon port open) is a false negative, not a saving.
# Above this count the scan is a wide sweep, where the fast dead-host bail is kept
# so peak sockets and time stay bounded across hundreds of hosts.
_FOCUSED_HOST_MAX = 16

_SERVICE_PORT_CEILING = 10000

# After the ephemeral/high-band completion sweep floods the target, the host (and
# the scanner's own local ephemeral-port pool, which fills with TIME_WAIT entries)
# needs a moment to recover before a SECOND targeted -sV on the freshly-discovered
# high ports can succeed — fired immediately, its probes are dropped exactly like
# the starved first pass. This settle is paid only on the degraded path, and only
# when the flood actually discovered new high ports worth fingerprinting.
_ENRICH_SETTLE_SECONDS = 12.0


async def _nmap_ping_sweep(
    raw_targets: list[str], expanded: list[str],
    mac_out: Optional[dict[str, tuple[str, str]]] = None,
) -> Optional[list[str]]:
    """Discover live hosts with a single ``nmap -sn`` sweep (no port scan).

    With raw-socket privileges nmap uses ICMP echo/timestamp + ARP (on a LAN) +
    TCP SYN to 443/80, which catches hosts that a bare TCP-connect probe would
    miss; unprivileged it TCP-connects to 80/443. Returns the list of responding
    addresses, or ``None`` when nmap is unavailable / the sweep failed so the
    caller can fall back to the pure-Python probe.

    When ``mac_out`` is supplied it is filled with ``{ip: (mac, vendor)}`` for
    every host whose ARP reply carried a MAC — the on-LAN layer-2 fact the later
    ``-Pn`` service scan can't observe, so it isn't lost. Nothing is fabricated:
    only a MAC nmap actually reported is recorded.
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
        mac = ""
        mac_vendor = ""
        for a in host_el.findall("address"):
            atype = a.get("addrtype")
            if atype in ("ipv4", "ipv6") and not addr:
                addr = a.get("addr", "")
            elif atype == "mac":
                mac = (a.get("addr") or "").strip().upper()
                mac_vendor = (a.get("vendor") or "").strip()
        if addr:
            live.append(addr)
            if mac and mac_out is not None:
                mac_out[addr] = (mac, mac_vendor)
    return live


def _sweep_socket_cap() -> int:
    """Ceiling on concurrent liveness sockets, kept safely under the process's
    file-descriptor budget. Each host fans out to every liveness port at once, so
    a host-only bound would let peak sockets reach hosts x ports (~16.5k for a
    /16) — enough to exhaust a default FD limit (macOS 256, many Linux 1024) or
    the ~16k local ephemeral-port range, at which point every connect errors and
    live hosts are silently misread as dead. Cap concurrent connections at a
    quarter of the FD soft limit, clamped to a sane [64, 500]."""
    try:
        import resource  # POSIX only; Windows falls through to the default.
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft and soft > 0:
            return max(64, min(500, soft // 4))
    except Exception:
        logger.debug("FD-limit probe unavailable; using default sweep cap", exc_info=True)
    return 500


async def _tcp_ping_sweep(hosts: list[str], timeout: float = 2.0) -> list[str]:
    """Pure-Python liveness fallback: a host is live if it accepts a TCP connect
    on any common port. No raw sockets required, so it works on a minimal install
    with no nmap. Probes run highly concurrently, so a /24 sweeps in seconds.

    Concurrency is bounded on the *scarce* resource — open sockets — by one global
    semaphore acquired around each connect, so peak file descriptors stay at
    :func:`_sweep_socket_cap` no matter how wide the range or how many liveness
    ports fan out. A per-host bound gates how many hosts are in flight (so we do
    not queue millions of pending probes for a big CIDR) without inflating the
    socket count."""
    conn_cap = _sweep_socket_cap()
    conn_sem = asyncio.Semaphore(conn_cap)
    host_sem = asyncio.Semaphore(max(16, conn_cap // 2))
    probe_timeout = min(1.5, max(0.4, timeout))

    async def _port_open(host: str, port: int) -> bool:
        async with conn_sem:
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
        async with host_sem:
            outcomes = await asyncio.gather(
                *[_port_open(host, p) for p in _LIVENESS_PROBE_PORTS]
            )
            return host if any(outcomes) else None

    results = await asyncio.gather(*[_alive(h) for h in hosts])
    return [h for h in results if h]


async def _discover_live_hosts(
    raw_targets: list[str], expanded: list[str], timeout: float = 2.0,
    mac_out: Optional[dict[str, tuple[str, str]]] = None,
) -> list[str]:
    """Return the subset of *expanded* that responds to a fast liveness sweep.
    Prefers nmap ``-sn`` (catches ICMP/ARP-only hosts); falls back to a
    concurrent TCP-connect probe when nmap is absent.

    When ``mac_out`` is supplied the nmap path fills it with ``{ip: (mac,
    vendor)}`` from the ARP replies, so a LAN scan keeps the MAC the later
    ``-Pn`` service scan can't see."""
    # Fail-closed: liveness probes (ICMP/ARP/raw SYN, and the TCP fallback) can't
    # be forced through a proxy — skip discovery rather than leak the real IP.
    if _egress_port_scan_blocked():
        return []
    live = await _nmap_ping_sweep(raw_targets, expanded, mac_out=mac_out)
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
    udp_ports: Optional[str] = None,
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

    # Resolve the UDP port list once (only when a UDP scan was requested). A
    # pure-Python unprivileged sweep is bounded so it stays feasible; an explicit
    # spec is honoured up to that bound. Privileged nmap -sU can take the full set.
    udp_port_list: Optional[list[int]] = None
    if include_udp:
        from heaven.recon.udp_scanner import _have_raw_udp, resolve_udp_ports
        _udp_cap = 4096 if _have_raw_udp() else 1024
        udp_port_list = resolve_udp_ports(udp_ports, ports, max_ports=_udp_cap)
        logger.info(
            "UDP scan enabled — probing %d UDP port(s) per host (%s)",
            len(udp_port_list),
            "nmap -sU" if _have_raw_udp() else "pure-Python service probes",
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
        # Reserve for the targeted -sV enrichment that runs AFTER the connect-scan
        # recovery on a degraded host (a full-range sweep couldn't finish, so the
        # recovered ports are version-less). The port list is tiny, so this is
        # small and bounded; scale it by the stealth factor (quieter = slower
        # probes). Carving it out of the budget keeps the whole scan_host — primary
        # nmap + connect scan + enrichment — finishing INSIDE time_budget so its
        # result is kept, never the cancelled-and-discarded case.
        _enrich_secs = int(max(30.0, min(180.0, 120.0 * _stealth_ceiling)))
        # The SECOND -sV pass fingerprints the freshly-swept ephemeral/high band (a
        # tiny port list, but dynamic RPC ports need nmap's full version-intensity
        # RPC grind, which is slow on a fragile / emulated host — ~2min — so it gets
        # a generous ceiling). Reserve BOTH passes plus the inter-pass settle so the
        # whole scan_host still finishes inside budget. This lowers the PRIMARY nmap
        # ceiling, which is fine: a healthy host finishes a full-range -sV -sC well
        # inside it, and a slow host that would blow past it degrades to the connect
        # scan + enrichment anyway — so the reserve just makes that handoff earlier.
        _ephemeral_enrich_secs = int(max(45.0, min(150.0, 130.0 * _stealth_ceiling)))
        _enrich_reserve = (
            float(_enrich_secs) + _ENRICH_SETTLE_SECONDS + float(_ephemeral_enrich_secs))
        _nmap_ceiling = 240.0 * _stealth_ceiling
        _nmap_host_secs = int(max(
            60.0, min(_nmap_ceiling, time_budget - _connect_reserve - _enrich_reserve)))
        nmap_host_timeout = f"{_nmap_host_secs}s"
        enrich_host_timeout = f"{_enrich_secs}s"
        ephemeral_enrich_host_timeout = f"{_ephemeral_enrich_secs}s"
    else:
        nmap_host_timeout = "30m"
        enrich_host_timeout = "120s"
        ephemeral_enrich_host_timeout = "60s"

    # ── Host-discovery sweep for broad ranges ─────────────────────────────────
    # A /24 expands to 254 addresses, most of them dead. Under -Pn (which we use
    # so firewalled hosts aren't skipped) nmap would faithfully full-scan every
    # one of them — so a "scan 192.168.1.0/24" spent its entire deadline on dead
    # air and returned nothing, the exact "it's vulnerable but shows nothing"
    # symptom. For a broad range we first sweep for live hosts (fast, cheap) and
    # only deep-scan the ones that answer. A single host / small explicit list
    # skips discovery — the operator named it, so we trust -Pn to reach it.
    discovery: Optional[dict[str, Any]] = None
    # {ip: (mac, vendor)} captured from the discovery ARP sweep — the on-LAN MAC
    # the later -Pn service scan can't observe. Threaded into the host results
    # below so the Assets view / report show it.
    discovered_macs: dict[str, tuple[str, str]] = {}
    if len(expanded_targets) > _DISCOVERY_THRESHOLD:
        _range_size = len(expanded_targets)
        live = await _discover_live_hosts(targets, expanded_targets, timeout=timeout,
                                          mac_out=discovered_macs)
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

    # A small, explicitly-named target set is a FOCUSED scan: on the nmap-degrade
    # path we complete the requested band even when only uncommon ports are open,
    # rather than reporting a live-but-hardened host as "0 open ports". A wide
    # sweep keeps the fast dead-host bail so it stays bounded (see scan_host).
    focused_scan = len(expanded_targets) <= _FOCUSED_HOST_MAX

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
            include_udp=include_udp, udp_ports=udp_port_list,
            stealth_level=stealth_level, evade=evade,
            host_timeout=nmap_host_timeout, enrich_host_timeout=enrich_host_timeout,
            ephemeral_enrich_host_timeout=ephemeral_enrich_host_timeout,
            focused=focused_scan,
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

    # Device-identity enrichment (MAC + device type) — after all scanning, so the
    # ARP cache is fully populated by our own traffic and every port is known.
    _enrich_device_identity(host_results, discovered_macs)

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


def _enrich_device_identity(
    host_results: list[HostResult],
    discovered_macs: Optional[dict[str, tuple[str, str]]] = None,
) -> None:
    """Fill MAC + device type from real observed signals the port scan missed.

    Runs once after scanning, IN PLACE, and never overwrites a value nmap already
    proved. Three honest sources, best-first:

    1. **MAC from the discovery ARP sweep** (``discovered_macs``) — nmap's own ARP
       reply + OUI vendor, dropped by the ``-Pn`` service scan; re-attached here.
    2. **MAC from the OS ARP cache** — for any on-LAN host still blank, the
       neighbour entry our scan traffic populated (real, same-segment fact).
    3. **Device type from services** — when neither an nmap ``-O`` osclass nor a
       MAC-vendor category set one, infer the role from the open ports (labelled
       ``service-heuristic`` → "(inferred from services)").

    A newly-learned MAC also backfills a MAC-vendor device type when the role is
    still unknown. Nothing is fabricated: a routed host with no MAC stays blank.
    """
    discovered_macs = discovered_macs or {}
    # Read the OS ARP cache once (cheap) only if some host still lacks a MAC and
    # might be on-link — avoids a subprocess when discovery already covered them.
    _arp_cache: Optional[dict[str, str]] = None

    for h in host_results:
        # 1 + 2 — MAC (only when nmap didn't already report one for this host).
        if not h.mac_address:
            dm = discovered_macs.get(h.host)
            if dm:
                h.mac_address, vend = dm[0], dm[1]
                if vend and not h.mac_vendor:
                    h.mac_vendor = vend
            else:
                if _arp_cache is None:
                    from heaven.recon import arp_cache as _ac
                    _arp_cache = _ac.read_arp_cache()
                mac = _arp_cache.get(h.host, "")
                if mac:
                    h.mac_address = mac.upper()
                    if not h.mac_vendor:
                        from heaven.recon import arp_cache as _ac
                        h.mac_vendor = _ac.vendor_for_mac(mac)

        # A MAC-vendor device type, now that a MAC may have just arrived.
        if not h.device_type and h.mac_vendor:
            cat = _device_type_from_mac_vendor(h.mac_vendor)
            if cat:
                h.device_type = cat
                h.device_type_source = "mac-vendor"

        # 3 — Service/port-derived role, the last-resort honest inference.
        if not h.device_type:
            role = _device_type_from_services([p.port for p in h.open_ports])
            if role:
                h.device_type = role
                h.device_type_source = "service-heuristic"


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
        # NetBIOS node-status facts (empty {} off-LAN or no reply). The honest
        # unprivileged win on a firewalled Windows host: name / workgroup / MAC.
        "netbios": host.netbios,
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

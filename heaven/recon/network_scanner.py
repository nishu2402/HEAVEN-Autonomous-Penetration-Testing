"""
HEAVEN — Async TCP/UDP Network Scanner
High-concurrency port scanning with service fingerprinting, banner grabbing,
OS detection heuristics, evasion engine integration, and CTF flag capture.
Uses asyncio with semaphore throttling.
Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import asyncio
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
    """
    return {
        "paranoid":   ["-T1", "--min-rate", "10",    "--max-retries", "3"],
        "stealth":    ["-T2", "--min-rate", "100",   "--max-retries", "2"],
        "normal":     ["-T4", "--min-rate", "1000",  "--max-retries", "2"],
        "aggressive": ["-T4", "--min-rate", "5000",  "--max-retries", "1"],
        "loud":       ["-T5", "--min-rate", "10000", "--max-retries", "1"],
    }.get(stealth_level, ["-T4", "--min-rate", "1000", "--max-retries", "2"])


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    semaphore: Optional[asyncio.Semaphore] = None,
    include_udp: bool = False,
    udp_ports: Optional[list[int]] = None,
    stealth_level: str = "normal",
) -> HostResult:
    """
    Full-spectrum nmap scan: all ports, service detection, default NSE scripts,
    OS fingerprinting, and UDP probes when requested.
    Uses stealth-level-aware timing so the same function works from
    ghost-mode recon through loud exploitation-support scans.
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

    cmd = [
        *sudo_prefix, "nmap", "-sV", "-sC", "-Pn", *os_flag, *scan_flags, *port_args,
        "-oX", "-", "--host-timeout", "30m", *timing, host,
    ]

    async with sem:
        logger.debug(f"nmap: {' '.join(cmd)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                try:
                    xml_root = _safe_xml_fromstring(stdout)

                    # ── Host liveness ─────────────────────────────────────────
                    # With -Pn nmap always reports state="up" reason="user-set"
                    # (we told it to skip discovery), so "up" alone no longer
                    # proves the host is reachable. Trust a real probe reason
                    # (echo-reply / syn-ack / arp-response …); otherwise defer
                    # liveness to "did any port actually respond?" — set below
                    # once the open-port list is parsed. This keeps alive_hosts
                    # honest instead of counting every scanned address as alive.
                    status = xml_root.find(".//status")
                    _status_up = status is not None and status.get("state") == "up"
                    _probe_confirmed = (
                        _status_up and (status.get("reason") or "") not in ("", "user-set")
                    )
                    if _probe_confirmed:
                        host_result.is_alive = True

                    # ── Open ports + service info ─────────────────────────────
                    # Service-detection OS evidence (nmap's `ostype` attr + any
                    # OS-level CPEs) gathered as we go — this needs no raw-socket
                    # privileges and feeds the heuristic OS fallback below.
                    os_evidence_types: list[str] = []
                    os_evidence_cpes: list[str] = []
                    for port_elem in xml_root.findall(".//port"):
                        state_elem = port_elem.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue

                        # Malformed nmap XML can carry portid="" — int("") raises
                        # ValueError and would abort parsing the remaining ports.
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

                        # First app-level CPE is the port's; collect OS-level
                        # CPEs (cpe:/o:…) separately as OS evidence.
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

                        pr = PortResult(
                            host=host,
                            port=portid,
                            protocol=protocol,
                            state="open",
                            service=service,
                            product=product,
                            version=version,
                            banner=banner,
                            extrainfo=extra,
                            cpe=cpe,
                            fingerprint=script_output,
                        )
                        host_result.open_ports.append(pr)

                    # Any port that answered proves the host is genuinely
                    # reachable — the honest liveness signal under -Pn, where the
                    # "up" status itself is just our forced flag (see above).
                    if host_result.open_ports:
                        host_result.is_alive = True

                    # ── OS detection (three honestly-labelled tiers) ──────────
                    # 1. nmap -O TCP/IP stack fingerprint → authoritative, with
                    #    its own confidence (needs raw sockets; see above).
                    # 2. service-detection evidence (ostype / OS CPEs from -sV) →
                    #    a real observed signal, but what the service claims, so
                    #    marked heuristic. Works fully unprivileged.
                    # 3. a single TTL value → coarsest guess, also heuristic.
                    # Tiers 2-3 are never presented as a confirmed OS.
                    os_match = xml_root.find(".//osmatch")
                    if os_match is not None and os_match.get("name"):
                        host_result.os_guess = os_match.get("name", "")
                        host_result.os_source = "nmap"
                        try:
                            host_result.os_accuracy = int(os_match.get("accuracy") or 0)
                        except (ValueError, TypeError):
                            host_result.os_accuracy = 0
                    if not host_result.os_guess:
                        svc_os = _os_from_service_evidence(os_evidence_types, os_evidence_cpes)
                        if svc_os:
                            host_result.os_guess = svc_os
                            host_result.os_source = "heuristic"
                    if not host_result.os_guess:
                        # Fallback: infer from TTL in host element
                        host_elem = xml_root.find(".//host")
                        if host_elem is not None:
                            # nmap reports TTL in <distance> under <os>; try host ttl attr
                            ttl_val = 0
                            for dist in xml_root.findall(".//distance"):
                                try:
                                    ttl_val = int(dist.get("value", 0))
                                except ValueError:
                                    pass
                            if ttl_val:
                                host_result.os_guess = guess_os_from_ttl(ttl_val)
                                host_result.os_source = "heuristic"
                                host_result.ttl = ttl_val

                except ET.ParseError as e:
                    logger.error(f"nmap XML parse error for {host}: {e}")

            if stderr:
                err_text = stderr.decode(errors="replace").strip()
                if err_text and "WARNING" not in err_text and "Note:" not in err_text:
                    logger.debug(f"nmap stderr ({host}): {err_text[:300]}")

        except FileNotFoundError:
            logger.error(
                "nmap not found. Install it: apt install nmap  /  brew install nmap"
            )
            
    # Honeypot heuristic: too many open ports is suspicious
    open_count = len(host_result.open_ports)
    if open_count > 50:
        host_result.honeypot_indicators.append(
            f"Suspiciously high open port count: {open_count}"
        )
    _check_service_consistency(host_result)

    host_result.scan_time_ms = (time.time() - start) * 1000
    return host_result


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


async def scan_network(
    targets: list[str],
    port_range: str = "1-65535",
    timeout: float = 2.0,
    include_udp: bool = False,
    stealth_level: str = "normal",
    **kwargs,
) -> dict[str, Any]:
    """
    Main entry point: scan multiple hosts across specified port ranges.
    Integrates evasion engine, honeypot avoidance, and CTF flag extraction.
    Called by the orchestrator. Cross-platform: Linux, macOS, Windows.
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

    # Expand CIDR targets
    expanded_targets = expand_targets(targets)
    ports = parse_port_range(port_range)

    concurrency = profile.max_concurrent if profile else 500
    sem = asyncio.Semaphore(concurrency)

    logger.info(
        f"Scanning {len(expanded_targets)} hosts × {len(ports)} ports "
        f"(stealth={stealth_level}, concurrency={concurrency}, platform={sys.platform})"
    )

    # Randomise scan order if evasion profile requires it
    if profile and profile.scan_order == "random":
        import random
        random.shuffle(expanded_targets)

    host_results = []
    total_open = 0
    honeypots_skipped = 0

    for host in expanded_targets:
        await engine.apply_evasion_delay()

        result = await scan_host(
            host, ports, timeout=timeout, semaphore=sem,
            include_udp=include_udp, stealth_level=stealth_level,
        )

        if not isinstance(result, HostResult):
            continue

        # Run honeypot analysis on results
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
                continue  # Skip honeypot targets entirely

        # Extract CTF flags from banners
        if ctf and result.open_ports:
            port_dicts = [{
                "port": p.port, "banner": p.banner, "state": p.state,
            } for p in result.open_ports]
            flags = ctf.extract_from_banners(host, port_dicts)
            if flags:
                logger.info(f"🚩 {len(flags)} CTF flags captured from {host}")

        host_results.append(result)
        total_open += len(result.open_ports)
        if result.open_ports:
            logger.info(
                f"  {result.host}: {len(result.open_ports)} open ports "
                f"(OS: {result.os_guess}, {result.scan_time_ms:.0f}ms)"
            )

    logger.info(
        f"Network scan complete: {total_open} open ports across {len(host_results)} hosts "
        f"(honeypots skipped: {honeypots_skipped})"
    )

    output = {
        "hosts": [_host_to_dict(h) for h in host_results],
        "total_open_ports": total_open,
        "total_hosts": len(host_results),
        "alive_hosts": sum(1 for h in host_results if h.is_alive),
        "honeypots_skipped": honeypots_skipped,
        "platform": sys.platform,
        # Whether this run could do SYN/UDP/OS scans, and (if not) how to enable
        # them — so the CLI/report can be honest about scan depth on this host.
        "scan_privilege": scan_capability(),
    }

    if ctf:
        output["ctf"] = ctf.summary()
    if hp_engine:
        output["evasion"] = hp_engine.summary()

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


def _generate_cpe(service: str, version: str) -> str:
    """Generate a CPE 2.3 string from service and version info."""
    if not service or not version:
        return ""
    service_map = {
        "ssh": "openssh", "http": "apache", "nginx": "nginx",
        "mysql": "mysql", "postgresql": "postgresql", "redis": "redis",
    }
    vendor = service_map.get(service.lower(), service.lower())
    ver = version.split(" ")[0]  # Take first version token
    return f"cpe:2.3:a:{vendor}:{service}:{ver}:*:*:*:*:*:*:*"


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
        "scan_time_ms": round(host.scan_time_ms, 1),
        "honeypot_indicators": host.honeypot_indicators,
        "open_ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "product": p.product,
                "version": p.version,
                "service_version": _service_version(p.product, p.version, p.extrainfo),
                "banner": p.banner[:200] if p.banner else "",
                "cpe": p.cpe,
                "response_time_ms": round(p.response_time_ms, 1),
            }
            for p in host.open_ports
        ],
    }

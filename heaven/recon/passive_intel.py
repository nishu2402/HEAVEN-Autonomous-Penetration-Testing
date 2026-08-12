"""HEAVEN — Passive internet-scan intelligence (key-less OSINT enrichment).

Cross-references a **public** target against Shodan's free, key-less InternetDB
(``https://internetdb.shodan.io/{ip}``) so HEAVEN never misses a port, service or
CVE that is *already publicly visible* — even when a single active nmap run
flakes, is rate-limited, or times out (the exact class of miss where an
authenticated Shodan record shows 80/443 + MySQL/PostgreSQL but the scan came
back without them).

This is **passive OSINT**: it reads data Shodan already collected; it does not
scan the target. Anything it contributes is clearly labelled as passively
observed (``source="passive:internetdb"``, ``state="passive-observed"``) unless a
subsequent *active, read-only* re-probe confirms it (``source="passive+active"``,
``state="open"``). Nothing here fabricates a finding or over-claims confirmation.

Design contract
---------------
* **Public IPs only.** InternetDB has nothing for RFC1918 / loopback / reserved
  space, so private targets short-circuit to ``{}`` — no wasted call, no FP.
* **Always-on, kill-switchable.** Enrichment runs by default; set
  ``HEAVEN_NO_PASSIVE_INTEL=1`` (or ``true``/``yes``/``on``) to disable it
  entirely for OPSEC-silent engagements.
* **Graceful.** Any network/parse error, a 404 (host unknown to Shodan), a
  missing ``aiohttp`` — all degrade to ``{}`` and the scan proceeds exactly as it
  would have without enrichment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from typing import Any, Optional

from heaven.utils.logger import get_logger

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:  # pragma: no cover - aiohttp is a runtime dep
    _AIOHTTP = False

logger = get_logger("recon.passive_intel")

_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_LOOKUP_TIMEOUT = 8.0
_CACHE_TTL = 900.0  # 15 minutes — a host's public surface doesn't change fast
_CACHE: dict[str, tuple[float, dict]] = {}

# ── Enrichment time budgets ───────────────────────────────────────────────────
# The re-probe touches the target, so it is hard-bounded twice: nmap's own
# --host-timeout makes it self-terminate on a firewalled host (no orphaned
# process), and an asyncio backstop guarantees the coroutine returns. The whole
# enrichment pass has a global deadline so passive merging — which touches only
# Shodan's public dataset, never the target — always completes for every host
# while re-probing runs only while budget remains. All comfortably inside the
# orchestrator's network-task slack, so enrichment can NEVER blow the scan's
# timeout and take the (already-collected, active) results down with it.
_REPROBE_NMAP_TIMEOUT = "20s"   # passed to nmap --host-timeout for the re-probe
_REPROBE_BUDGET = 25.0          # asyncio backstop around one host's re-probe
_ENRICH_TOTAL_BUDGET = 45.0     # global wall-clock deadline for the whole pass

# Stealth profiles for which we must NOT emit any extra active traffic: the
# passive port still merges, it just stays "passive-observed" (never re-probed).
_NO_REPROBE_STEALTH = frozenset({"paranoid", "stealth"})

# Conventional service label for a bare port number — used only to *label* a
# passively-observed port so downstream detectors (exposed-DB, cleartext, CVE
# mapping) can key on a service name. Never invents a version.
_PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle-tns", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9042: "cassandra", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2095: "cpanel-webmail", 2096: "cpanel-webmail-ssl", 2222: "ssh-alt",
}

# Product-name fragment (as it appears in a CPE) → the conventional port(s) it
# runs on, so a host-level CPE from InternetDB can be associated with the matching
# open port and carry a real product+version into the EOL / CVE stages.
_PRODUCT_DEFAULT_PORTS: list[tuple[str, tuple[int, ...]]] = [
    ("mysql", (3306,)), ("mariadb", (3306,)),
    ("postgresql", (5432,)), ("postgres", (5432,)),
    ("mongodb", (27017,)), ("redis", (6379,)),
    ("elasticsearch", (9200,)), ("couchdb", (5984,)),
    ("memcached", (11211,)), ("cassandra", (9042,)),
    ("openssh", (22,)),
    ("vsftpd", (21,)), ("proftpd", (21,)), ("pure-ftpd", (21,)),
    ("exim", (25,)), ("postfix", (25,)),
    ("http_server", (80, 443)), ("apache", (80, 443)), ("httpd", (80, 443)),
    ("nginx", (80, 443)), ("iis", (80, 443)), ("openresty", (80, 443)),
    ("lighttpd", (80, 443)),
]


def passive_intel_enabled() -> bool:
    """False only when the operator explicitly opted out via the kill-switch."""
    return os.environ.get("HEAVEN_NO_PASSIVE_INTEL", "").strip().lower() not in (
        "1", "true", "yes", "on",
    )


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _normalize(raw: Any) -> dict:
    """Coerce the InternetDB JSON body into a predictable, typed shape."""
    if not isinstance(raw, dict):
        return {}
    ports = sorted({p for p in raw.get("ports", []) if isinstance(p, int)})
    return {
        "ip": str(raw.get("ip") or ""),
        "ports": ports,
        "cpes": [c for c in raw.get("cpes", []) if isinstance(c, str)],
        "hostnames": [h for h in raw.get("hostnames", []) if isinstance(h, str)],
        "tags": [t for t in raw.get("tags", []) if isinstance(t, str)],
        "vulns": [v for v in raw.get("vulns", []) if isinstance(v, str)],
    }


async def _resolve_ip(host: str) -> str:
    """Resolve a hostname to a single IP (read-only DNS). Passes IPs through."""
    h = (host or "").strip().strip("[]")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h  # already an IP literal
    except ValueError:
        pass
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(h, None)
        for info in infos:
            addr = info[4][0]
            if addr:
                return str(addr)
    except Exception as e:  # noqa: BLE001 - DNS failure is non-fatal
        logger.debug("passive_intel DNS resolve failed for %s: %s", h, e)
    return ""


async def lookup(ip: str, *, session: Any = None, timeout: float = _LOOKUP_TIMEOUT) -> dict:
    """Return the normalized InternetDB record for a public IP, or ``{}``.

    Cached per-IP for :data:`_CACHE_TTL`. Never raises: 404 / offline / parse
    error / disabled all yield ``{}``.
    """
    if not _AIOHTTP or not passive_intel_enabled():
        return {}
    if not _is_public_ip(ip):
        return {}

    now = time.time()
    cached = _CACHE.get(ip)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    url = _INTERNETDB_URL.format(ip=ip)
    data: dict = {}
    own_session = session is None
    try:
        sess = session or aiohttp.ClientSession()
        try:
            async with sess.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    data = _normalize(raw)
                elif resp.status == 404:
                    data = {}  # host simply isn't in Shodan's dataset
                else:
                    logger.debug("InternetDB %s → HTTP %s", ip, resp.status)
        finally:
            if own_session:
                await sess.close()
    except Exception as e:  # noqa: BLE001 - passive enrichment is best-effort
        logger.debug("InternetDB lookup failed for %s: %s", ip, e)
        data = {}

    _CACHE[ip] = (now, data)
    return data


def _parse_cpe(cpe: str) -> tuple[str, str]:
    """Extract ``(product, version)`` from a CPE 2.3 URI. '' when absent."""
    # cpe:2.3:a:vendor:product:version:...  OR  cpe:/a:vendor:product:version
    parts = cpe.replace("cpe:/", "cpe:2.3:").split(":")
    # parts: ['cpe', '2.3', part, vendor, product, version, ...]
    product = parts[4].strip() if len(parts) > 4 else ""
    version = parts[5].strip() if len(parts) > 5 else ""
    if version in ("*", "-", ""):
        version = ""
    product = product.replace("_", " ").strip()
    return product, version


def _cpe_port_map(cpes: list[str]) -> dict[int, tuple[str, str]]:
    """Associate each host-level CPE with the conventional port(s) it runs on."""
    out: dict[int, tuple[str, str]] = {}
    for cpe in cpes:
        product, version = _parse_cpe(cpe)
        if not product:
            continue
        # Normalise spaces back to underscores so a CPE product like
        # "http_server" (rendered "http server" by _parse_cpe) still matches the
        # underscore fragments below.
        low = product.lower().replace(" ", "_")
        for frag, ports in _PRODUCT_DEFAULT_PORTS:
            if frag in low:
                for port in ports:
                    # First specific match wins; don't overwrite a set entry.
                    out.setdefault(port, (product, version))
                break
    return out


def _cpe_strings_by_port(cpes: list[str]) -> dict[int, str]:
    """Associate each host-level CPE *string* with the conventional port(s) it runs
    on, so a passively-observed or corroborated port can carry the real,
    Shodan-observed CPE (not a derived one). First specific match per port wins."""
    out: dict[int, str] = {}
    for cpe in cpes:
        product, _ = _parse_cpe(cpe)
        if not product:
            continue
        low = product.lower().replace(" ", "_")
        for frag, ports in _PRODUCT_DEFAULT_PORTS:
            if frag in low:
                for port in ports:
                    out.setdefault(port, cpe)
                break
    return out


def _passive_port(port: int, product: str, version: str, cpe: str = "") -> dict:
    """Build an honestly-labelled passive-observed port dict."""
    service = _PORT_SERVICE.get(port, "")
    sv = " ".join(p for p in (product, version) if p).strip()
    return {
        "port": port,
        "protocol": "tcp",
        "state": "passive-observed",
        "source": "passive:internetdb",
        "service": service,
        "product": product,
        "version": version,
        "service_version": sv,
        "cpe": cpe,
        "banner": "",
        "response_time_ms": 0.0,
    }


async def _reprobe_ports(host: str, ports: list[int], stealth_level: str) -> dict[int, dict]:
    """Targeted, read-only re-scan of *specific* ports. Returns ``{port: dict}``
    for those that actually answered — the honest confirmation step.

    Hard-bounded two ways so a firewalled host that silently drops probes can
    never delay (let alone hang) the scan: nmap's own ``--host-timeout`` makes it
    self-terminate, and an outer :func:`asyncio.wait_for` is the backstop. On
    either bound we simply return ``{}`` and the ports keep their honest
    ``passive-observed`` label — nothing is fabricated, nothing hangs."""
    if not ports:
        return {}
    try:
        from heaven.recon.network_scanner import _host_to_dict, scan_host
    except Exception:  # pragma: no cover - import guard
        return {}
    try:
        res = await asyncio.wait_for(
            scan_host(host, sorted(ports), stealth_level=stealth_level,
                      host_timeout=_REPROBE_NMAP_TIMEOUT),
            timeout=_REPROBE_BUDGET,
        )
    except Exception as e:  # noqa: BLE001 - best-effort (incl. asyncio timeout)
        logger.debug("passive re-probe bounded-out for %s: %s", host, e)
        return {}
    try:
        hd = _host_to_dict(res)
    except Exception:  # pragma: no cover - defensive
        return {}
    confirmed: dict[int, dict] = {}
    for p in hd.get("open_ports", []):
        try:
            confirmed[int(p["port"])] = p
        except (KeyError, TypeError, ValueError):
            continue
    return confirmed


def _existing_ports(host_dict: dict) -> set[int]:
    out: set[int] = set()
    for p in host_dict.get("open_ports", []) or []:
        try:
            out.add(int(p.get("port")))
        except (TypeError, ValueError):
            continue
    return out


async def _enrich_one(host_dict: dict, query_ip: str, info: dict, *,
                      reprobe: bool, stealth_level: str) -> int:
    """Merge one InternetDB record into one host dict. Returns #ports added.

    Merge order is deliberate: every newly-discovered port is recorded as
    ``passive-observed`` **first**, then an optional read-only re-probe UPGRADES
    the ones it can actively confirm. So even if the re-probe is skipped, times
    out, or is cancelled by the outer budget, the host's public surface is
    already captured — enrichment can only ever ADD coverage, never lose it (the
    exact failure that let a firewalled host's slow re-probe sink the whole
    scan's active results).
    """
    active_ports = _existing_ports(host_dict)
    passive_ports = [p for p in info.get("ports", []) if p not in active_ports]
    cpe_by_port = _cpe_port_map(info.get("cpes", []))
    cpe_str_by_port = _cpe_strings_by_port(info.get("cpes", []))

    # Corroborate ports we already found actively with the public record — and,
    # where the active scan left a field blank, backfill it from the public CPE
    # (real Shodan-observed data, never fabricated; active data is never overwritten).
    reported = set(info.get("ports", []))
    for p in host_dict.get("open_ports", []) or []:
        try:
            pnum = int(p.get("port"))
        except (TypeError, ValueError):
            continue
        if pnum not in reported:
            continue
        p["corroborated_by"] = "internetdb"
        prod, ver = cpe_by_port.get(pnum, ("", ""))
        if prod and not (p.get("product") or "").strip():
            p["product"] = prod
        if ver and not (p.get("version") or "").strip():
            p["version"] = ver
        cpe_str = cpe_str_by_port.get(pnum, "")
        if cpe_str and not (p.get("cpe") or "").strip():
            p["cpe"] = cpe_str
        if not (p.get("service_version") or "").strip():
            sv = " ".join(x for x in (p.get("product", ""), p.get("version", "")) if x).strip()
            if sv:
                p["service_version"] = sv

    # 1) Merge EVERY new port immediately as passive-observed — no target traffic,
    #    so this is instant and unconditional. This is what guarantees the surface
    #    lands even when the active re-probe below can't run or complete.
    ports_list = host_dict.setdefault("open_ports", [])
    passive_index: dict[int, dict] = {}
    for port in passive_ports:
        prod, ver = cpe_by_port.get(port, ("", ""))
        pd = _passive_port(port, prod, ver, cpe_str_by_port.get(port, ""))
        ports_list.append(pd)
        passive_index[port] = pd

    # 2) Read-only, hard-bounded re-probe that UPGRADES the passive labels it can
    #    confirm (passive-observed → passive+active/open with real nmap data).
    if passive_ports and reprobe:
        confirmed = await _reprobe_ports(
            host_dict.get("host") or host_dict.get("ip") or query_ip,
            passive_ports, stealth_level,
        )
        for port, active in confirmed.items():
            pd = passive_index.get(port)
            if pd is None:
                continue
            prod, ver = cpe_by_port.get(port, ("", ""))
            pd.update(active)                       # richer active service data
            pd["source"] = "passive+active"
            pd["state"] = active.get("state") or "open"
            pd["corroborated_by"] = "internetdb"
            # Backfill product/version from the CPE only where active came back bare.
            if prod and not (pd.get("product") or "").strip():
                pd["product"] = prod
            if ver and not (pd.get("version") or "").strip():
                pd["version"] = ver
            if not (pd.get("service_version") or "").strip():
                pd["service_version"] = " ".join(
                    x for x in (pd.get("product", ""), pd.get("version", "")) if x).strip()

    # Host-level passive metadata for the CVE mapper (Phase 4) + reference.
    if info.get("vulns"):
        existing = {c for c in host_dict.get("passive_cves", []) if isinstance(c, str)}
        merged = existing | {v for v in info["vulns"] if _CVE_RE.match(v)}
        host_dict["passive_cves"] = sorted(merged)
    if info.get("cpes"):
        host_dict["passive_cpes"] = info["cpes"]
    if info.get("hostnames"):
        host_dict.setdefault("passive_hostnames", info["hostnames"])
    return len(passive_ports)


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _host_key(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if not v.startswith("[") and v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v.lower()


async def enrich_hosts(hosts: list[dict], *, reprobe: bool = True,
                       stealth_level: str = "normal",
                       targets: Optional[list[str]] = None) -> list[dict]:
    """Merge public InternetDB intelligence into a list of scan host dicts.

    Mutates and returns ``hosts``. For each host (and each explicitly-requested
    ``target`` that produced no active host dict at all) it resolves the IP,
    looks the IP up in InternetDB, and merges any additional ports/CPEs/CVEs —
    re-probing the new ports read-only to confirm them when the stealth profile
    permits. A no-op when disabled, offline, or the target isn't public.
    """
    if not hosts and not targets:
        return hosts
    if not passive_intel_enabled() or not _AIOHTTP:
        return hosts
    do_reprobe = reprobe and stealth_level not in _NO_REPROBE_STEALTH

    by_key: dict[str, dict] = {}
    for h in hosts:
        k = _host_key(h.get("host") or h.get("ip") or "")
        if k:
            by_key[k] = h

    # Every host we should try to enrich: the ones we scanned + any requested
    # target that came back with nothing (the worst-case "scan reached zero").
    candidates: list[str] = list(by_key.keys())
    for t in targets or []:
        k = _host_key(t)
        if k and k not in by_key and k not in candidates:
            candidates.append(k)

    # Global wall-clock deadline for the whole pass. Passive MERGING (which never
    # touches the target) always runs for every candidate; the active RE-PROBE is
    # only attempted while budget remains, so a large host list can't let the
    # re-probes run away — the surface still lands, just labelled passive.
    deadline = time.monotonic() + _ENRICH_TOTAL_BUDGET
    total_added = 0
    for key in candidates:
        query_ip = await _resolve_ip(key)
        if not query_ip or not _is_public_ip(query_ip):
            continue
        info = await lookup(query_ip)
        if not info or not (info.get("ports") or info.get("vulns")):
            continue

        host_dict = by_key.get(key)
        if host_dict is None:
            # The active scan produced no result for this public target — create
            # a minimal, honestly-labelled host so its public surface isn't lost.
            host_dict = {
                "host": key, "ip": key, "is_alive": True,
                "os_guess": "", "os_source": "", "os_accuracy": 0,
                "scan_time_ms": 0.0, "honeypot_indicators": [],
                "open_ports": [],
            }
            hosts.append(host_dict)
            by_key[key] = host_dict

        added = await _enrich_one(
            host_dict, query_ip, info,
            reprobe=do_reprobe and time.monotonic() < deadline,
            stealth_level=stealth_level,
        )
        if added:
            host_dict["is_alive"] = True
        total_added += added

    if total_added:
        logger.info(
            "Passive OSINT enrichment: +%d port(s) merged from public "
            "internet-scan data across %d host(s)", total_added, len(candidates),
        )
    return hosts

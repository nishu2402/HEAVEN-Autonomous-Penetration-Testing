"""
Host & Service Inventory — the open-ports / service-version / OS view.

Single source of truth for turning the raw network-scan ``assets`` (host dicts
produced by :func:`heaven.recon.network_scanner._host_to_dict`) into a clean,
deduplicated inventory that the CLI, the web API/UI and every report format all
render identically.

Everything here is derived straight from nmap output — no port, service,
version or OS value is invented. An unconfirmed OS (inferred from a single TTL
rather than an nmap ``-O`` stack fingerprint) is always labelled as indicative
only; it is never presented as a confirmed operating system. That labelling is
the whole point: an operator must be able to tell a proven fact from a guess.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from typing import Any, Optional
from urllib.parse import urlparse


def looks_like_ip(value: str) -> bool:
    """True when ``value`` is an IPv4/IPv6 literal (not a hostname)."""
    v = (value or "").strip()
    if not v:
        return False
    # Strip an IPv6 bracket/zone or a bare ``[::1]`` literal before checking.
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    v = v.split("%", 1)[0]
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# Resolved-IP cache so a report / assets render never re-resolves the same host,
# and so a single unresolvable host costs one bounded lookup, not one per row.
_IP_CACHE: dict[str, str] = {}
_IP_CACHE_LOCK = threading.Lock()


def _dns_resolution_enabled() -> bool:
    """Whether render-time host→IP resolution may run.

    A bare DNS A-record lookup of the *target* is core inventory data (not the
    passive-OSINT enrichment governed by ``HEAVEN_NO_PASSIVE_INTEL``), so it is on
    by default. Set ``HEAVEN_NO_DNS_RESOLVE=1`` on an air-gapped / offline host to
    turn it off and keep the inventory purely to what the scan already captured.
    """
    return (os.environ.get("HEAVEN_NO_DNS_RESOLVE") or "").strip().lower() not in (
        "1", "true", "yes", "on")


def resolve_host_ip(host: str, timeout: float = 2.0) -> str:
    """Best-effort A-record IP for a hostname; '' when it can't be resolved.

    An IP literal returns itself. Resolution is cached and runs in a daemon
    thread with a hard timeout so an unreachable DNS server can never hang a
    report render (the daemon thread is abandoned and dies with the process).
    """
    h = (host or "").strip().lower()
    if not h:
        return ""
    if looks_like_ip(h):
        return h
    with _IP_CACHE_LOCK:
        if h in _IP_CACHE:
            return _IP_CACHE[h]
    if not _dns_resolution_enabled():
        with _IP_CACHE_LOCK:
            _IP_CACHE[h] = ""
        return ""

    import socket
    result: dict[str, str] = {}

    def _worker() -> None:
        try:
            result["ip"] = socket.gethostbyname(h)
        except Exception:
            result["ip"] = ""

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    ip = result.get("ip", "")
    with _IP_CACHE_LOCK:
        _IP_CACHE[h] = ip
    return ip


def host_key(target: str) -> str:
    """Reduce any target to a bare host/IP (no scheme, path or port).

    Collapses ``https://10.0.0.5:8443/admin`` and ``10.0.0.5`` to the same
    key so every port and finding on one machine lands in a single inventory
    row.
    """
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        host = (urlparse(t).hostname or "").strip()
        if host:
            return host.lower()
        # urlparse failed to find a host — fall through to manual stripping.
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]          # drop any path
    # Strip a trailing :port, but keep bracketed IPv6 literals intact.
    if t.startswith("["):
        return t.lower()
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t.lower()


def service_version_str(port: dict) -> str:
    """Human 'product version (extrainfo)' for a port dict; '' if unknown.

    Prefers a pre-computed ``service_version`` (the scanner already builds one),
    then reconstructs from product/version/extrainfo, then falls back to the raw
    banner. Returns '' when nmap reported no version data at all.
    """
    sv = (port.get("service_version") or "").strip()
    if sv:
        return sv
    product = (port.get("product") or "").strip()
    version = (port.get("version") or "").strip()
    extra = (port.get("extrainfo") or "").strip()
    core = " ".join(p for p in (product, version) if p)
    if core and extra:
        return f"{core} ({extra})"
    if core:
        return core
    if extra:
        return f"({extra})"
    return (port.get("banner") or "").strip()


def os_label(host: dict) -> str:
    """OS string with an honest confidence suffix; '' when undetermined.

    * nmap ``-O`` match  → ``"Linux 5.x (fingerprinted, 98%)"``
    * TTL heuristic      → ``"Linux/Unix (heuristic — unconfirmed)"``
    * unknown provenance → the bare guess

    The suffix is deliberately loud for the heuristic case so a TTL guess is
    never mistaken for a confirmed operating system.
    """
    os_guess = (host.get("os") or host.get("os_guess") or "").strip()
    if not os_guess:
        return ""
    source = (host.get("os_source") or "").strip()
    if source == "nmap":
        acc = host.get("os_accuracy") or 0
        try:
            acc = int(acc)
        except (ValueError, TypeError):
            acc = 0
        return f"{os_guess} (fingerprinted, {acc}%)" if acc else f"{os_guess} (fingerprinted)"
    if source == "heuristic":
        return f"{os_guess} (heuristic, unconfirmed)"
    return os_guess


def device_name_label(host: dict) -> str:
    """Device / computer name with an honest source suffix; '' when unknown.

    A NetBIOS/SMB name is the machine's own advertised name (authoritative, no
    suffix); a reverse-DNS PTR is a weaker DNS-side signal; a passive hostname
    came from public OSINT rather than our scan. The suffix keeps those distinct
    so a PTR or OSINT value is never read as the host's real computer name.
    """
    name = (host.get("device_name") or "").strip()
    if not name:
        return ""
    return {
        "netbios": name,
        "ptr": f"{name} (reverse DNS)",
        "passive": f"{name} (passive OSINT)",
        "manual": f"{name} (operator-set)",
    }.get((host.get("device_name_source") or "").strip(), name)


def device_type_label(host: dict) -> str:
    """Device type/role with an honest confidence suffix; '' when undetermined.

    * nmap ``-O`` osclass → ``"router (fingerprinted)"``
    * MAC-vendor category → ``"network equipment (per MAC vendor)"``
    * unknown provenance  → the bare value

    Mirrors :func:`os_label`: a MAC-vendor category is a maker-derived hint, never
    a stack fingerprint, and the suffix says so.
    """
    dtype = (host.get("device_type") or "").strip()
    if not dtype:
        return ""
    src = (host.get("device_type_source") or "").strip()
    if src == "nmap":
        return f"{dtype} (fingerprinted)"
    if src == "mac-vendor":
        return f"{dtype} (per MAC vendor)"
    if src == "service-heuristic":
        return f"{dtype} (inferred from services)"
    if src == "manual":
        return f"{dtype} (operator-set)"
    return dtype


def mac_label(host: dict) -> str:
    """``"AA:BB:CC:… (Vendor)"`` for a host's MAC; '' when none was observed."""
    mac = (host.get("mac_address") or "").strip()
    if not mac:
        return ""
    vendor = (host.get("mac_vendor") or "").strip()
    return f"{mac} ({vendor})" if vendor else mac


# ── internal ────────────────────────────────────────────────────────────────

_OS_SOURCE_RANK = {"": 0, "heuristic": 1, "nmap": 2}
# How much to trust each device-name / device-type source (higher = better). An
# operator-set value ("manual") outranks everything — the human is authoritative.
# A service-heuristic type is a role inferred from open ports, weaker than a
# MAC-vendor maker hint, which is weaker than an nmap -O classification.
_DEVICE_NAME_RANK = {"": 0, "passive": 1, "ptr": 2, "netbios": 3, "manual": 4}
_DEVICE_TYPE_RANK = {"": 0, "service-heuristic": 1, "mac-vendor": 2, "nmap": 3,
                     "manual": 4}


def _port_dict(p: Any) -> Optional[dict]:
    """Normalise one open-port entry (int or dict) to a canonical dict."""
    if isinstance(p, int):
        return {"port": p, "protocol": "tcp", "state": "open", "service": "",
                "product": "", "version": "", "service_version": "", "cpe": "",
                "banner": "", "source": "active", "corroborated_by": ""}
    if not isinstance(p, dict):
        return None
    try:
        port = int(p.get("port"))
    except (ValueError, TypeError):
        return None
    return {
        "port": port,
        "protocol": (p.get("protocol") or "tcp").lower(),
        "state": p.get("state") or "open",
        "service": p.get("service") or "",
        "product": p.get("product") or "",
        "version": p.get("version") or "",
        "service_version": service_version_str(p),
        "cpe": p.get("cpe") or "",
        "banner": (p.get("banner") or "")[:200],
        # Provenance: 'active' (nmap proof), 'passive:internetdb' (public
        # internet-scan data, unconfirmed from our vantage) or 'passive+active'
        # (public-data lead that a read-only re-probe then confirmed).
        "source": p.get("source") or "active",
        "corroborated_by": p.get("corroborated_by") or "",
    }


def _port_richness(pd: dict) -> int:
    """Higher = more informative; used to keep the best of two dup ports."""
    score = 0
    if pd.get("service_version"):
        score += 2
    if pd.get("service"):
        score += 1
    if pd.get("cpe"):
        score += 1
    # An actively-confirmed port outranks a merely passively-observed one for the
    # same (port, protocol): prefer proof over public-data hearsay when merging.
    if (pd.get("state") or "open") != "passive-observed":
        score += 3
    if pd.get("corroborated_by"):
        score += 1
    return score


def _merge_os(node: dict, asset: dict) -> None:
    """Keep the most authoritative OS seen for a host (nmap > heuristic > bare)."""
    guess = (asset.get("os_guess") or asset.get("os") or "").strip()
    if not guess:
        return
    source = (asset.get("os_source") or "").strip()
    if _OS_SOURCE_RANK.get(source, 0) >= _OS_SOURCE_RANK.get(node.get("os_source", ""), 0):
        node["os"] = guess
        node["os_source"] = source
        try:
            node["os_accuracy"] = int(asset.get("os_accuracy") or 0)
        except (ValueError, TypeError):
            node["os_accuracy"] = 0


def _merge_device_identity(node: dict, asset: dict) -> None:
    """Keep the most authoritative MAC / device name / device type for a host.

    A single host can appear as several raw asset dicts (an active nmap row, a
    passive-OSINT row, a re-probe); this folds them into the one best-supported
    value for each field, ranked by source trust (NetBIOS name > reverse-DNS PTR >
    passive hostname; nmap osclass > MAC-vendor category). Nothing is invented — a
    field only ever fills from a value some scan actually carried.
    """
    # MAC (+ vendor): first non-empty wins; a later vendor backfills a blank one.
    mac = (asset.get("mac_address") or "").strip()
    if mac and not node.get("mac_address"):
        node["mac_address"] = mac
    ven = (asset.get("mac_vendor") or "").strip()
    if ven and not node.get("mac_vendor"):
        node["mac_vendor"] = ven

    # Device name — take the higher-ranked source; fill a blank from any source.
    name = (asset.get("device_name") or "").strip()
    if name:
        cur = _DEVICE_NAME_RANK.get(node.get("device_name_source", ""), 0)
        new = _DEVICE_NAME_RANK.get((asset.get("device_name_source") or "").strip(), 0)
        if not node.get("device_name") or new > cur:
            node["device_name"] = name
            node["device_name_source"] = (asset.get("device_name_source") or "").strip()
    # Passive OSINT hostname (Shodan) — weakest source; only fills a still-blank
    # name (a later active PTR/NetBIOS row outranks it and overwrites above).
    if not node.get("device_name"):
        for h in (asset.get("passive_hostnames") or []):
            if isinstance(h, str) and h.strip():
                node["device_name"] = h.strip()
                node["device_name_source"] = "passive"
                break

    # Device type — take the higher-ranked source; fill a blank from any source.
    dtype = (asset.get("device_type") or "").strip()
    if dtype:
        cur = _DEVICE_TYPE_RANK.get(node.get("device_type_source", ""), 0)
        new = _DEVICE_TYPE_RANK.get((asset.get("device_type_source") or "").strip(), 0)
        if not node.get("device_type") or new > cur:
            node["device_type"] = dtype
            node["device_type_source"] = (asset.get("device_type_source") or "").strip()


def merge_host_labels(assets: Optional[list], labels: Optional[dict]) -> list[dict]:
    """Overlay operator-set device labels onto raw host asset dicts, in place.

    ``labels`` is ``{bare_host: {device_name, device_type, notes}}`` from
    :meth:`heaven.engagement.EngagementStore.get_host_labels`. For every asset
    whose host matches a label, the operator's name/type are written with
    ``*_source='manual'`` so :func:`normalize_assets` ranks them above any
    scan-inferred value. Applied at the single point both the Assets view and the
    report read raw assets, so a manually-set name/type shows up everywhere.
    Returns the (same) list for convenience; a no-op when there are no labels.
    """
    if not assets or not labels:
        return assets or []
    for a in assets:
        if not isinstance(a, dict):
            continue
        lbl = labels.get(host_key(a.get("ip") or a.get("host") or ""))
        if not lbl:
            continue
        if lbl.get("device_name"):
            a["device_name"] = lbl["device_name"]
            a["device_name_source"] = "manual"
        if lbl.get("device_type"):
            a["device_type"] = lbl["device_type"]
            a["device_type_source"] = "manual"
    return assets


def normalize_assets(assets: Optional[list]) -> list[dict]:
    """Merge raw host asset dicts into a clean per-host inventory.

    Each returned row is::

        {host, ip, os, os_source, os_accuracy, os_label, alive, port_count,
         honeypot_indicators, ports: [{port, protocol, service, version,
         service_version, product, cpe, state, banner}, ...]}

    Hosts are deduplicated by bare host/IP; ports by ``(port, protocol)``,
    keeping the most informative duplicate. Sorted by open-port count desc.
    """
    hosts: dict[str, dict] = {}
    for a in assets or []:
        if not isinstance(a, dict):
            continue
        key = host_key(a.get("ip") or a.get("host") or "")
        if not key:
            continue
        node = hosts.get(key)
        if node is None:
            node = {"host": key, "ip": key, "hostname": "", "os": "", "os_source": "",
                    "os_accuracy": 0, "alive": False, "ports": {},
                    "honeypot_indicators": [],
                    "mac_address": "", "mac_vendor": "",
                    "device_name": "", "device_name_source": "",
                    "device_type": "", "device_type_source": "",
                    "web_components": {}}
            hosts[key] = node
        # Capture a real IP whenever an asset supplies one, so a hostname target
        # (a website / webapp scan) still records the address it resolved to.
        aip = (a.get("ip") or "").strip()
        if aip and looks_like_ip(aip):
            node["ip"] = aip
        # Preserve a hostname label separately: when an asset carries both a name
        # and an IP the dedup key is the IP, but the row should still show the
        # domain that was scanned (not just the address).
        rawhost = host_key(a.get("host") or "")
        if rawhost and not looks_like_ip(rawhost) and not node.get("hostname"):
            node["hostname"] = rawhost
        _merge_os(node, a)
        _merge_device_identity(node, a)
        node["alive"] = node["alive"] or bool(a.get("is_alive"))
        for raw in (a.get("open_ports") or a.get("ports") or []):
            pd = _port_dict(raw)
            if pd is None:
                continue
            pk = (pd["port"], pd["protocol"])
            existing = node["ports"].get(pk)
            if existing is None or _port_richness(pd) > _port_richness(existing):
                node["ports"][pk] = pd
        for ind in (a.get("honeypot_indicators") or []):
            if ind and ind not in node["honeypot_indicators"]:
                node["honeypot_indicators"].append(ind)
        # Web-tier components disclosed in HTTP headers (PHP/OpenSSL/…), keyed by
        # (service, version) so the same PHP seen on several URLs is listed once.
        for wc in (a.get("web_components") or []):
            if not isinstance(wc, dict):
                continue
            svc = (wc.get("service") or "").strip().lower()
            ver = (wc.get("version") or "").strip()
            if not svc or not ver:
                continue
            node["web_components"].setdefault((svc, ver), wc)

    out: list[dict] = []
    for node in hosts.values():
        # Prefer the hostname as the display label when one was captured (a
        # website/webapp scan keyed by its resolved IP still shows its domain).
        hostname = node.pop("hostname", "")
        if hostname:
            node["host"] = hostname
        # When the host is a hostname (website / webapp target) and no scan
        # supplied a numeric address, resolve its A record so the report and the
        # Assets view show the IP too — not just the domain.
        if not looks_like_ip(node["ip"]):
            resolved = resolve_host_ip(node["host"])
            if resolved:
                node["ip"] = resolved
        ports = sorted(node["ports"].values(), key=lambda x: (x["port"], x["protocol"]))
        node = dict(node)
        node["ports"] = ports
        node["port_count"] = len(ports)
        node["web_components"] = sorted(
            node["web_components"].values(),
            key=lambda w: ((w.get("product") or w.get("service") or ""),
                           w.get("version") or ""),
        )
        node["alive"] = node["alive"] or bool(ports)
        node["os_label"] = os_label(node)
        node["device_name_label"] = device_name_label(node)
        node["device_type_label"] = device_type_label(node)
        node["mac_label"] = mac_label(node)
        out.append(node)
    out.sort(key=lambda n: (-n["port_count"], n["host"]))
    return out


def inventory_totals(inventory: list[dict]) -> dict:
    """Roll-up counts for headline strips / report summaries."""
    total_ports = sum(len(h.get("ports", [])) for h in inventory)
    services = {
        (p.get("service") or "").lower()
        for h in inventory for p in h.get("ports", [])
        if p.get("service")
    }
    os_identified = sum(1 for h in inventory if h.get("os"))
    # A host counts as "identified" once we have any device fact beyond its IP —
    # a MAC, a device name, or a device type.
    devices_identified = sum(
        1 for h in inventory
        if h.get("mac_address") or h.get("device_name") or h.get("device_type")
    )
    return {
        "hosts": len(inventory),
        "hosts_alive": sum(1 for h in inventory if h.get("alive")),
        "open_ports": total_ports,
        "distinct_services": len(services),
        "os_identified": os_identified,
        "devices_identified": devices_identified,
    }


def port_source_label(p: dict) -> str:
    """Human provenance label for one port; '' for a plain active finding.

    So a reader can always tell a proven, actively-scanned port from one merged
    out of public internet-scan data — and never mistake the latter for the
    former.
    """
    source = (p.get("source") or "active").lower()
    if source == "passive:internetdb":
        return "passive (public OSINT, unconfirmed)"
    if source == "passive+active":
        return "active (OSINT-corroborated)"
    if p.get("corroborated_by"):
        return "active + OSINT"
    return "active"


def render_markdown(assets: Optional[list], *, already_normalized: bool = False) -> str:
    """Render the inventory as a Markdown section. '' when there is nothing.

    Used verbatim by the CLI and by the Markdown report export so a written
    report and a terminal view always agree.
    """
    inv = assets if already_normalized else normalize_assets(assets)
    if not inv:
        return ""
    tot = inventory_totals(inv)
    has_passive = any(
        (p.get("source") or "").startswith("passive")
        for h in inv for p in h.get("ports", [])
    )
    note = (
        f"{tot['hosts']} host(s), {tot['open_ports']} open port(s), "
        f"{tot['distinct_services']} distinct service(s). Ports, service versions "
        "and OS are reported exactly as observed by nmap; an OS marked "
        "*(heuristic, unconfirmed)* is a TTL guess, not a stack fingerprint."
    )
    if has_passive:
        note += (
            " The **Source** column records provenance: *active* ports were "
            "proven by direct scan; *passive (public OSINT, unconfirmed)* ports "
            "come from Shodan's public internet-scan data and could not be "
            "confirmed from the scan origin; *OSINT-corroborated* ports were seen "
            "in public data and then confirmed by a read-only re-probe."
        )
    lines = ["## Host & Service Inventory", "", note, ""]
    for h in inv:
        os_txt = h.get("os_label") or "OS not determined"
        header = [f"### {h['host']}"]
        # Show the resolved IP when the host is a name (website/webapp target) and
        # it differs from the address — so the reader sees exactly what was hit.
        if h.get("ip") and looks_like_ip(h["ip"]) and h["ip"] != h["host"]:
            header.append(f"**IP:** {h['ip']}")
        header.append(f"**OS:** {os_txt}")
        if h.get("device_name_label"):
            header.append(f"**Device:** {h['device_name_label']}")
        if h.get("device_type_label"):
            header.append(f"**Type:** {h['device_type_label']}")
        if h.get("mac_label"):
            header.append(f"**MAC:** {h['mac_label']}")
        lines.append("  \n".join(header))
        lines.append("")
        for wc in (h.get("web_components") or []):
            src = wc.get("source_header")
            src_txt = f" (web, `{src}` header)" if src else " (web)"
            lines.append(
                f"- **{wc.get('product') or wc.get('service')} "
                f"{wc.get('version')}**{src_txt}"
            )
        if h.get("web_components"):
            lines.append("")
        if not h.get("ports"):
            if not h.get("web_components"):
                lines.append("_No open ports observed._")
                lines.append("")
            continue
        lines.append("| Port | Proto | Service | Version | CPE | Source |")
        lines.append("| ---- | ----- | ------- | ------- | --- | ------ |")
        for p in h["ports"]:
            lines.append(
                f"| {p['port']} | {p['protocol']} | {p.get('service') or '—'} "
                f"| {p.get('service_version') or '—'} | {p.get('cpe') or '—'} "
                f"| {port_source_label(p)} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

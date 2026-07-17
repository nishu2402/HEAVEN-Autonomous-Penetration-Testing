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

from typing import Any, Optional
from urllib.parse import urlparse


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
        return f"{os_guess} (heuristic — unconfirmed)"
    return os_guess


# ── internal ────────────────────────────────────────────────────────────────

_OS_SOURCE_RANK = {"": 0, "heuristic": 1, "nmap": 2}


def _port_dict(p: Any) -> Optional[dict]:
    """Normalise one open-port entry (int or dict) to a canonical dict."""
    if isinstance(p, int):
        return {"port": p, "protocol": "tcp", "state": "open", "service": "",
                "product": "", "version": "", "service_version": "", "cpe": "",
                "banner": ""}
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
            node = {"host": key, "ip": key, "os": "", "os_source": "",
                    "os_accuracy": 0, "alive": False, "ports": {},
                    "honeypot_indicators": []}
            hosts[key] = node
        _merge_os(node, a)
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

    out: list[dict] = []
    for node in hosts.values():
        ports = sorted(node["ports"].values(), key=lambda x: (x["port"], x["protocol"]))
        node = dict(node)
        node["ports"] = ports
        node["port_count"] = len(ports)
        node["alive"] = node["alive"] or bool(ports)
        node["os_label"] = os_label(node)
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
    return {
        "hosts": len(inventory),
        "hosts_alive": sum(1 for h in inventory if h.get("alive")),
        "open_ports": total_ports,
        "distinct_services": len(services),
        "os_identified": os_identified,
    }


def render_markdown(assets: Optional[list], *, already_normalized: bool = False) -> str:
    """Render the inventory as a Markdown section. '' when there is nothing.

    Used verbatim by the CLI and by the Markdown report export so a written
    report and a terminal view always agree.
    """
    inv = assets if already_normalized else normalize_assets(assets)
    if not inv:
        return ""
    tot = inventory_totals(inv)
    lines = [
        "## Host & Service Inventory",
        "",
        f"{tot['hosts']} host(s), {tot['open_ports']} open port(s), "
        f"{tot['distinct_services']} distinct service(s). Ports, service versions "
        "and OS are reported exactly as observed by nmap; an OS marked "
        "*(heuristic — unconfirmed)* is a TTL guess, not a stack fingerprint.",
        "",
    ]
    for h in inv:
        os_txt = h.get("os_label") or "OS not determined"
        lines.append(f"### {h['host']}  \n**OS:** {os_txt}")
        lines.append("")
        if not h.get("ports"):
            lines.append("_No open ports observed._")
            lines.append("")
            continue
        lines.append("| Port | Proto | Service | Version | CPE |")
        lines.append("| ---- | ----- | ------- | ------- | --- |")
        for p in h["ports"]:
            lines.append(
                f"| {p['port']} | {p['protocol']} | {p.get('service') or '—'} "
                f"| {p.get('service_version') or '—'} | {p.get('cpe') or '—'} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

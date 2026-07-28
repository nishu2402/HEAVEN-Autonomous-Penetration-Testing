"""
DNS Enumeration Inventory — the records / subdomains / mail-infrastructure view.

Single source of truth for turning the raw per-domain DNS enumeration dicts
(produced by :func:`heaven.recon.dns_recon.enumerate_dns`) into a clean,
deduplicated inventory that the CLI, the web API/UI and every report format all
render identically — the exact counterpart of :mod:`heaven.devsecops.inventory`
for the host/service view.

Everything here is derived straight from authoritative DNS answers — no record,
subdomain or mail server is invented. A subdomain appears only because it
actually resolved.
"""

from __future__ import annotations

from typing import Any, Optional

# Canonical order records are presented in (most operationally useful first).
RECORD_ORDER: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def _clean_domain(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def normalize_dns(records: Optional[list]) -> list[dict]:
    """Merge raw per-domain DNS enumeration dicts into a clean inventory.

    Each returned row is::

        {domain, records: {A: [...], ...}, a, aaaa, cname, txt, soa,
         nameservers: [...], mail_servers: [{priority, host}, ...],
         subdomains: [{name, addresses: [...]}, ...], dnssec: {...},
         wildcard: bool, resolver, record_count}

    Domains are deduplicated (case-insensitively); records, subdomains, mail
    servers and nameservers are each merged and deduplicated. Sorted by domain.
    """
    by_domain: dict[str, dict] = {}
    for r in records or []:
        if not isinstance(r, dict):
            continue
        domain = _clean_domain(r.get("domain"))
        if not domain:
            continue
        node = by_domain.get(domain)
        if node is None:
            node = {"domain": domain, "records": {}, "nameservers": [],
                    "mail_servers": [], "subdomains": {}, "dnssec": {},
                    "wildcard": False, "soa": "", "resolver": ""}
            by_domain[domain] = node

        # Merge the record dict, deduping values while preserving order.
        for rtype, vals in (r.get("records") or {}).items():
            if not isinstance(vals, list):
                continue
            existing = node["records"].setdefault(str(rtype).upper(), [])
            for v in vals:
                if v not in existing:
                    existing.append(v)

        for ns in r.get("nameservers") or []:
            ns = str(ns).rstrip(".")
            if ns and ns not in node["nameservers"]:
                node["nameservers"].append(ns)

        seen_mx = {m["host"] for m in node["mail_servers"]}
        for m in r.get("mail_servers") or []:
            if isinstance(m, dict) and m.get("host") and m["host"] not in seen_mx:
                node["mail_servers"].append(
                    {"priority": m.get("priority"), "host": m["host"]})
                seen_mx.add(m["host"])

        for s in r.get("subdomains") or []:
            if not isinstance(s, dict):
                continue
            name = _clean_domain(s.get("name"))
            if not name:
                continue
            addrs = [str(a) for a in (s.get("addresses") or [])]
            slot = node["subdomains"].get(name)
            if slot is None:
                node["subdomains"][name] = {"name": name, "addresses": list(dict.fromkeys(addrs))}
            else:
                for a in addrs:
                    if a not in slot["addresses"]:
                        slot["addresses"].append(a)

        # Scalar fields: keep the first non-empty value seen.
        if r.get("dnssec") and not node["dnssec"]:
            node["dnssec"] = r["dnssec"]
        node["wildcard"] = node["wildcard"] or bool(r.get("wildcard"))
        if r.get("soa") and not node["soa"]:
            node["soa"] = str(r["soa"])
        if r.get("resolver") and not node["resolver"]:
            node["resolver"] = str(r["resolver"])

    out: list[dict] = []
    for node in by_domain.values():
        node = dict(node)
        node["subdomains"] = sorted(node["subdomains"].values(), key=lambda s: s["name"])
        node["record_count"] = sum(len(v) for v in node["records"].values())
        node["a"] = node["records"].get("A", [])
        node["aaaa"] = node["records"].get("AAAA", [])
        node["cname"] = node["records"].get("CNAME", [])
        node["txt"] = node["records"].get("TXT", [])
        out.append(node)
    out.sort(key=lambda n: n["domain"])
    return out


def dns_totals(inventory: list[dict]) -> dict:
    """Roll-up counts for headline strips / report summaries."""
    return {
        "domains": len(inventory),
        "records": sum(n.get("record_count", 0) for n in inventory),
        "subdomains": sum(len(n.get("subdomains", [])) for n in inventory),
        "mail_servers": sum(len(n.get("mail_servers", [])) for n in inventory),
        "nameservers": sum(len(n.get("nameservers", [])) for n in inventory),
        "dnssec_enabled": sum(1 for n in inventory if (n.get("dnssec") or {}).get("enabled")),
    }


def _md_cell(value: Any) -> str:
    """Escape a value so it can't break a Markdown table cell."""
    return str(value).replace("|", r"\|").replace("\n", " ").strip()


def render_markdown(records: Optional[list], *, already_normalized: bool = False) -> str:
    """Render the DNS enumeration as a Markdown section. '' when nothing found.

    Used verbatim by the CLI and the Markdown report export so a written report
    and a terminal view always agree.
    """
    inv = records if already_normalized else normalize_dns(records)
    if not inv:
        return ""
    tot = dns_totals(inv)
    lines = [
        "## DNS Enumeration",
        "",
        f"{tot['domains']} domain(s), {tot['records']} DNS record(s), "
        f"{tot['subdomains']} resolved subdomain(s), {tot['mail_servers']} mail "
        f"server(s). Records are reported exactly as returned by authoritative "
        f"DNS; a subdomain is listed only because it actually resolved.",
        "",
    ]
    for n in inv:
        lines.append(f"### {n['domain']}")
        dnssec = (n.get("dnssec") or {}).get("enabled")
        meta = f"**DNSSEC:** {'enabled' if dnssec else 'not detected'}"
        if n.get("wildcard"):
            meta += "  ·  **Wildcard DNS:** present"
        lines.append(meta)
        lines.append("")

        recs = n.get("records") or {}
        if any(recs.get(rt) for rt in RECORD_ORDER):
            lines.append("| Type | Record |")
            lines.append("| ---- | ------ |")
            for rt in RECORD_ORDER:
                for val in recs.get(rt, []):
                    lines.append(f"| {rt} | {_md_cell(val)} |")
            lines.append("")

        subs = n.get("subdomains") or []
        if subs:
            lines.append(f"**Subdomains discovered ({len(subs)}):**")
            lines.append("")
            lines.append("| Subdomain | Addresses |")
            lines.append("| --------- | --------- |")
            for s in subs:
                addrs = ", ".join(s.get("addresses") or []) or "—"
                lines.append(f"| {_md_cell(s['name'])} | {_md_cell(addrs)} |")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"

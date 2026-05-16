"""
HEAVEN — DNS Reconnaissance Module
Zone transfer (AXFR/IXFR), DNSSEC validation, subdomain takeover detection,
PTR record enumeration, SOA analysis, DNS cache snooping, wildcard detection,
CNAME chain analysis, and DNS-over-HTTPS (DoH) fallback.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("dns_recon")


def _dedup(findings: list[dict]) -> list[dict]:
    """Deduplicate findings by (target, vuln_type)."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    import dns.rdatatype
    import dns.name
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# ── Subdomain takeover: dangling CNAME fingerprints ───────────────────────────
# (service → response pattern that indicates unclaimed resource)
_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github.io":              ["There isn't a GitHub Pages site here",
                               "For root URLs (4xx)"],
    "s3.amazonaws.com":       ["NoSuchBucket", "The specified bucket does not exist"],
    "s3-website":             ["NoSuchBucket", "404"],
    "bitbucket.io":           ["Repository not found"],
    "heroku":                 ["No such app", "herokucdn.com"],
    "ghost.io":               ["Used placeholder"],
    "surge.sh":               ["project not found"],
    "netlify":                ["Not Found", "netlify"],
    "wordpress.com":          ["Do you want to register"],
    "shopify":                ["Sorry, this shop is currently unavailable"],
    "tumblr":                 ["Whatever you were looking for doesn't live here"],
    "zendesk":                ["Help Center Closed"],
    "desk":                   ["Please try again or"],
    "fastly":                 ["Fastly error: unknown domain"],
    "azure-api.net":          ["RestError"],
    "cloudfront.net":         ["The request could not be satisfied"],
    "trafficmanager.net":     ["404"],
    "azurewebsites.net":      ["Microsoft Azure App Service"],
    "azurefd.net":            ["404"],
    "amazonaws.com":          ["NoSuchBucket", "InvalidBucketName"],
    "elasticbeanstalk.com":   ["NoSuchApplication"],
    "readthedocs.io":         ["unknown", "no project"],
    "statuspage.io":          ["Status page not found"],
    "uservoice.com":          ["This UserVoice subdomain"],
    "freshdesk.com":          ["May be taken or retired"],
    "teamwork.com":           ["Oops - We didn't find your site"],
}

# ── DMARC/SPF analysis patterns ───────────────────────────────────────────────
_SPF_PATTERNS = {
    "open_relay": re.compile(r"\+all"),
    "soft_fail":  re.compile(r"~all"),
    "no_policy":  re.compile(r"^\s*$"),
}


def _finding(domain: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float = 0.90,
             evidence: Optional[dict] = None) -> dict:
    return {
        "target": domain,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "evidence": evidence or {},
        "source": "dns_recon",
    }


def _resolve(name: str, rdtype: str, nameservers: Optional[list[str]] = None,
             timeout: float = 5.0) -> list[str]:
    """Synchronous DNS query returning a list of string rdata values."""
    if not HAS_DNSPYTHON:
        try:
            if rdtype == "A":
                return [str(r[4][0]) for r in socket.getaddrinfo(name, None, socket.AF_INET)]
        except Exception:
            return []
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        if nameservers:
            resolver.nameservers = nameservers
        answers = resolver.resolve(name, rdtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


# ── Zone Transfer (AXFR) ───────────────────────────────────────────────────────

def _attempt_zone_transfer(domain: str, ns_host: str,
                            timeout: float = 10.0) -> Optional[list[str]]:
    """
    Attempt an AXFR zone transfer from a specific nameserver.
    Returns list of record strings if successful, None otherwise.
    """
    if not HAS_DNSPYTHON:
        return None
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(ns_host, domain, timeout=timeout, lifetime=timeout)
        )
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain}. {rdataset.ttl} "
                                   f"{dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
        return records
    except Exception:
        return None


async def _scan_zone_transfer(domain: str) -> list[dict]:
    """Check all NS records for zone transfer vulnerability."""
    findings: list[dict] = []
    ns_records = _resolve(domain, "NS")
    if not ns_records:
        return findings

    loop = asyncio.get_running_loop()
    for ns in ns_records:
        ns_clean = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_clean)
        except Exception:
            continue

        records = await loop.run_in_executor(
            None, _attempt_zone_transfer, domain, ns_ip
        )
        if records:
            findings.append(_finding(
                domain, "zone_transfer", "critical",
                f"DNS Zone Transfer Allowed from {ns_clean}",
                f"Nameserver {ns_clean} ({ns_ip}) allowed AXFR zone transfer. "
                f"The entire DNS zone ({len(records)} records) is publicly readable. "
                f"This reveals internal hostnames, IPs, mail servers, and infrastructure layout.",
                confidence=0.99,
                evidence={
                    "nameserver": ns_clean,
                    "ns_ip": ns_ip,
                    "record_count": len(records),
                    "sample_records": records[:20],
                },
            ))
    return findings


# ── DNSSEC Validation ──────────────────────────────────────────────────────────

def _check_dnssec(domain: str) -> dict:
    """Check if DNSSEC is deployed and properly configured."""
    if not HAS_DNSPYTHON:
        return {"enabled": False, "error": "dnspython not installed"}

    try:
        # Check for DS record (delegation signer — indicates DNSSEC at registrar)
        ds_records = _resolve(domain, "DS")
        # Check for DNSKEY record
        dnskey_records = _resolve(domain, "DNSKEY")
        # Check for RRSIG (signature) on A record
        rrsig_records = _resolve(domain, "RRSIG")

        enabled = bool(ds_records or dnskey_records or rrsig_records)
        return {
            "enabled": enabled,
            "ds_present": bool(ds_records),
            "dnskey_present": bool(dnskey_records),
            "rrsig_present": bool(rrsig_records),
            "ds_records": ds_records[:3],
        }
    except Exception as e:
        return {"enabled": False, "error": str(e)}


# ── Subdomain Takeover ─────────────────────────────────────────────────────────

async def _check_subdomain_takeover(subdomain: str) -> Optional[dict]:
    """
    Check if a subdomain CNAME points to an unclaimed external service.
    Returns a finding dict if vulnerable, None otherwise.
    """
    cname_chain = _resolve(subdomain, "CNAME")
    if not cname_chain:
        return None

    final_cname = cname_chain[-1].rstrip(".")

    for service, patterns in _TAKEOVER_FINGERPRINTS.items():
        if service in final_cname:
            # Fetch the subdomain and look for the unclaimed-resource fingerprint.
            # Try HTTP first, then HTTPS. Only use the actual response body —
            # never use str(exception) as the body because error messages may
            # contain the service name and trigger false positives.
            import urllib.request
            body = ""
            for scheme in ("http", "https"):
                try:
                    req = urllib.request.Request(
                        f"{scheme}://{subdomain}",
                        headers={"User-Agent": "HEAVEN-TakeoverScanner/2.0"},
                    )
                    with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 — scheme limited to http/https
                        body = resp.read(8192).decode("utf-8", errors="ignore")
                    break  # Use first successful fetch
                except Exception:
                    continue

            for pattern in patterns:
                if pattern.lower() in body.lower():
                    return _finding(
                        subdomain, "subdomain_takeover", "critical",
                        f"Subdomain Takeover — {service}",
                        f"{subdomain} → CNAME → {final_cname} ({service}) shows "
                        f"unclaimed resource indicator: '{pattern}'. "
                        f"An attacker can register this resource and serve malicious content "
                        f"from {subdomain} (same origin as the main domain).",
                        confidence=0.92,
                        evidence={
                            "subdomain": subdomain,
                            "cname": final_cname,
                            "service": service,
                            "fingerprint": pattern,
                        },
                    )
    return None


# ── Wildcard Detection ────────────────────────────────────────────────────────

def _detect_wildcard(domain: str) -> bool:
    """Check if DNS wildcards are configured (*. resolves to anything)."""
    test_name = f"heaven-wildcard-{int(time.time())}.{domain}"
    results = _resolve(test_name, "A")
    return bool(results)


# ── SPF / DMARC / DKIM Analysis ───────────────────────────────────────────────

async def _scan_email_security(domain: str) -> list[dict]:
    """Full SPF, DMARC, DKIM analysis."""
    findings: list[dict] = []

    # ── SPF ──────────────────────────────────────────────────────────────────
    spf_records = _resolve(domain, "TXT")
    spf = next((r for r in spf_records if "v=spf1" in r.lower()), "")
    if not spf:
        findings.append(_finding(
            domain, "spf_missing", "high",
            "SPF Record Missing",
            f"No SPF record found for {domain}. Attackers can spoof emails from "
            f"this domain, enabling phishing and fraud.",
            confidence=0.99,
        ))
    elif "+all" in spf:
        findings.append(_finding(
            domain, "spf_open_relay", "critical",
            "SPF Record Allows All Senders (+all)",
            f"SPF record for {domain} ends with '+all', meaning ANY server can "
            f"legitimately send email as this domain. Effectively useless.",
            confidence=0.99,
            evidence={"spf": spf},
        ))
    elif "~all" in spf:
        findings.append(_finding(
            domain, "spf_soft_fail", "medium",
            "SPF Uses SoftFail (~all) Instead of HardFail (-all)",
            "Softfail allows unauthorized senders but marks them as suspicious. "
            "Many mail servers still deliver softfail messages. Use '-all' instead.",
            confidence=0.95,
            evidence={"spf": spf},
        ))

    # Check for too many DNS lookups (>10 = SPF PermError)
    lookup_count = spf.count("include:") + spf.count("a:") + spf.count("mx") + spf.count("ptr")
    if lookup_count > 8:
        findings.append(_finding(
            domain, "spf_too_many_lookups", "medium",
            f"SPF Record Has Too Many DNS Lookups ({lookup_count})",
            "SPF evaluation requires >10 DNS lookups. This causes PermError and "
            "effectively disables SPF for many mail servers.",
            confidence=0.88,
            evidence={"spf": spf, "lookup_count": lookup_count},
        ))

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_records = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), "")
    if not dmarc:
        findings.append(_finding(
            domain, "dmarc_missing", "high",
            "DMARC Record Missing",
            f"No DMARC policy for {domain}. Emails can bypass SPF/DKIM checks "
            f"without any policy enforcement.",
            confidence=0.99,
        ))
    else:
        policy_match = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
        policy = policy_match.group(1).lower() if policy_match else "none"
        if policy == "none":
            findings.append(_finding(
                domain, "dmarc_policy_none", "high",
                "DMARC Policy Is 'none' — No Enforcement",
                "DMARC p=none means failing messages are reported but not rejected. "
                "Attackers can still spoof this domain. Change to p=quarantine or p=reject.",
                confidence=0.97,
                evidence={"dmarc": dmarc, "policy": policy},
            ))
        pct_match = re.search(r"pct=(\d+)", dmarc, re.IGNORECASE)
        pct = int(pct_match.group(1)) if pct_match else 100
        if pct < 100:
            findings.append(_finding(
                domain, "dmarc_partial_rollout", "medium",
                f"DMARC Applies to Only {pct}% of Mail",
                f"DMARC pct={pct} means only {pct}% of failing emails are actioned. "
                f"Set pct=100 for full enforcement.",
                confidence=0.90,
                evidence={"dmarc": dmarc, "pct": pct},
            ))

    # ── DKIM ──────────────────────────────────────────────────────────────────
    common_selectors = [
        "default", "google", "mail", "email", "smtp", "dkim",
        "k1", "k2", "s1", "s2", "selector1", "selector2",
        "mandrill", "sendgrid", "mailgun", "postmark", "ses",
    ]
    dkim_found = []
    for sel in common_selectors:
        records = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if records:
            dkim_found.append((sel, records[0]))

    if not dkim_found:
        findings.append(_finding(
            domain, "dkim_not_found", "medium",
            "No DKIM Record Found (Common Selectors)",
            "Could not find DKIM records for common selectors. Without DKIM, "
            "email integrity cannot be verified and spoofing is easier.",
            confidence=0.65,
        ))
    else:
        for sel, record in dkim_found:
            key_match = re.search(r"p=([A-Za-z0-9+/=]+)", record)
            if key_match:
                key_b64 = key_match.group(1)
                key_bits = len(key_b64) * 6 // 8 * 8   # approximate
                if key_bits < 1024:
                    findings.append(_finding(
                        domain, "dkim_weak_key", "high",
                        f"DKIM Key Too Short (selector: {sel}, ~{key_bits} bits)",
                        f"DKIM key for selector '{sel}' appears to be <1024 bits. "
                        f"Keys shorter than 1024 bits are factorizable. Upgrade to 2048 bits.",
                        confidence=0.75,
                        evidence={"selector": sel, "approx_bits": key_bits},
                    ))

    return findings


# ── PTR Record Enumeration ─────────────────────────────────────────────────────

async def _enumerate_ptr(cidr: str, max_hosts: int = 256) -> list[dict]:
    """Reverse-lookup PTR records for all IPs in a CIDR range."""
    findings: list[dict] = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return findings

    hosts_found: list[dict] = []
    sem = asyncio.Semaphore(50)

    async def _lookup(ip_str: str) -> None:
        async with sem:
            loop = asyncio.get_running_loop()
            try:
                hostname = await loop.run_in_executor(
                    None, socket.gethostbyaddr, ip_str
                )
                hosts_found.append({"ip": ip_str, "hostname": hostname[0]})
            except Exception:
                pass

    ips = list(network.hosts())[:max_hosts]
    await asyncio.gather(*[_lookup(str(ip)) for ip in ips])

    if hosts_found:
        # Not a vulnerability per se — but valuable recon data
        findings.append(_finding(
            cidr, "ptr_records_discovered", "info",
            f"PTR Records Discovered ({len(hosts_found)} hosts in {cidr})",
            f"Reverse DNS lookup revealed {len(hosts_found)} active hostnames in {cidr}. "
            f"Internal naming conventions may reveal infrastructure architecture.",
            confidence=0.95,
            evidence={
                "total": len(hosts_found),
                "hosts": hosts_found[:30],
            },
        ))
    return findings


# ── SOA Analysis ───────────────────────────────────────────────────────────────

def _analyze_soa(domain: str) -> list[dict]:
    """Extract and analyze SOA record for admin email and zone staleness."""
    findings: list[dict] = []
    soa_records = _resolve(domain, "SOA")
    if not soa_records:
        return findings

    soa_str = soa_records[0]
    # SOA format: <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>
    parts = soa_str.split()
    if len(parts) >= 2:
        admin_email = parts[1].rstrip(".").replace(".", "@", 1)
        findings.append(_finding(
            domain, "soa_admin_email", "info",
            f"DNS Zone Admin Email: {admin_email}",
            f"SOA record reveals zone admin email: {admin_email}. "
            f"Useful for social engineering and targeting.",
            confidence=0.95,
            evidence={"soa": soa_str, "admin": admin_email},
        ))

    # Check for NSEC/NSEC3 (DNSSEC zone walking)
    nsec_records = _resolve(domain, "NSEC")
    if nsec_records:
        findings.append(_finding(
            domain, "dnssec_zone_walking", "medium",
            "DNSSEC Zone Walking via NSEC Records",
            "Domain uses NSEC (not NSEC3). An attacker can walk the entire "
            "zone and enumerate all DNS names without brute-forcing.",
            confidence=0.88,
            evidence={"nsec_sample": nsec_records[:3]},
        ))

    return findings


# ── MX / Mail Infrastructure ───────────────────────────────────────────────────

def _analyze_mx(domain: str) -> list[dict]:
    """Check MX records for dangling / misconfigured mail infrastructure."""
    findings: list[dict] = []
    mx_records = _resolve(domain, "MX")
    if not mx_records:
        return findings

    for mx in mx_records:
        # MX typically: "10 mail.example.com."
        parts = mx.split()
        mx_host = parts[-1].rstrip(".") if parts else ""
        if not mx_host:
            continue

        # Try to resolve MX host
        a_records = _resolve(mx_host, "A")
        if not a_records:
            findings.append(_finding(
                domain, "mx_dangling", "high",
                f"Dangling MX Record — {mx_host} Does Not Resolve",
                f"MX record points to '{mx_host}' which has no A/AAAA record. "
                f"If an attacker registers '{mx_host}', they receive all email for {domain}.",
                confidence=0.92,
                evidence={"mx": mx, "unresolvable_host": mx_host},
            ))

    return findings


# ── Main entry point ───────────────────────────────────────────────────────────

async def dns_recon(domain: str, enumerate_subdomains: bool = False,
                    cidr_for_ptr: Optional[str] = None) -> dict:
    """
    Comprehensive DNS reconnaissance for a domain.

    Args:
        domain:               Target domain (e.g. "example.com").
        enumerate_subdomains: If True, check a subset of discovered subdomains
                              for takeover (complementary to deep_recon).
        cidr_for_ptr:         Optional CIDR for PTR record enumeration.
    Returns:
        Standard findings dict with 'findings', 'vulnerabilities', 'dns_data' keys.
    """
    if not HAS_DNSPYTHON:
        logger.warning("dnspython not installed — DNS recon degraded")

    all_findings: list[dict] = []
    dns_data: dict[str, Any] = {"domain": domain, "records": {}}

    # ── Gather basic records ─────────────────────────────────────────────────
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        records = _resolve(domain, rtype)
        if records:
            dns_data["records"][rtype] = records

    # ── Zone transfer ────────────────────────────────────────────────────────
    zt_findings = await _scan_zone_transfer(domain)
    all_findings.extend(zt_findings)

    # ── DNSSEC ───────────────────────────────────────────────────────────────
    loop = asyncio.get_running_loop()
    dnssec = await loop.run_in_executor(None, _check_dnssec, domain)
    dns_data["dnssec"] = dnssec
    if not dnssec.get("enabled"):
        all_findings.append(_finding(
            domain, "dnssec_not_enabled", "medium",
            "DNSSEC Not Configured",
            f"Domain {domain} has no DNSSEC signature records. "
            f"DNS responses can be forged (cache poisoning, Kaminsky attack).",
            confidence=0.95,
        ))

    # ── SOA analysis ─────────────────────────────────────────────────────────
    soa_findings = await loop.run_in_executor(None, _analyze_soa, domain)
    all_findings.extend(soa_findings)

    # ── MX analysis ──────────────────────────────────────────────────────────
    mx_findings = await loop.run_in_executor(None, _analyze_mx, domain)
    all_findings.extend(mx_findings)

    # ── Email security (SPF / DMARC / DKIM) ──────────────────────────────────
    email_findings = await _scan_email_security(domain)
    all_findings.extend(email_findings)

    # ── Wildcard detection ────────────────────────────────────────────────────
    has_wildcard = await loop.run_in_executor(None, _detect_wildcard, domain)
    dns_data["wildcard"] = has_wildcard
    if has_wildcard:
        all_findings.append(_finding(
            domain, "dns_wildcard", "low",
            "DNS Wildcard Configured",
            f"Wildcard DNS (* .{domain}) resolves arbitrary subdomains. "
            f"Makes subdomain enumeration unreliable and may allow domain fronting.",
            confidence=0.98,
        ))

    # ── Subdomain takeover check ──────────────────────────────────────────────
    if enumerate_subdomains:
        # Check any discovered subdomains from zone transfer
        subdomains: list[str] = []
        if zt_findings:
            # Extract subdomains from zone transfer evidence
            for f in zt_findings:
                records = f.get("evidence", {}).get("sample_records", [])
                for rec in records:
                    if " CNAME " in rec:
                        sub = rec.split()[0].rstrip(".")
                        if sub and sub != domain:
                            subdomains.append(sub)

        takeover_tasks = [_check_subdomain_takeover(sub) for sub in subdomains[:50]]
        takeover_results = await asyncio.gather(*takeover_tasks, return_exceptions=True)
        for r in takeover_results:
            if isinstance(r, dict):
                all_findings.append(r)

    # ── PTR enumeration ───────────────────────────────────────────────────────
    if cidr_for_ptr:
        ptr_findings = await _enumerate_ptr(cidr_for_ptr)
        all_findings.extend(ptr_findings)

    # ── Check for DNS-based information disclosure ────────────────────────────
    # Version query (CHAOS class)
    try:
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4.0
            ns_records = dns_data["records"].get("NS", [])
            if ns_records:
                ns_ip = socket.gethostbyname(ns_records[0].rstrip("."))
                resp = dns.query.udp(
                    dns.message.make_query("version.bind", dns.rdatatype.TXT,
                                           dns.rdataclass.CHAOS),   # type: ignore[attr-defined]
                    ns_ip, timeout=4,
                )
                for rrset in resp.answer:
                    version = str(rrset[0]).strip('"')
                    if version and version != "\\#":
                        all_findings.append(_finding(
                            domain, "dns_version_disclosure", "low",
                            f"DNS Server Version Disclosed: {version}",
                            f"BIND/DNS server responded to version.bind CHAOS query with: {version}. "
                            f"Disable with: version 'none'; in named.conf.",
                            confidence=0.97,
                            evidence={"version": version},
                        ))
    except Exception:
        pass

    all_findings = _dedup(all_findings)
    crit = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    logger.info(f"DNS recon {domain} → {len(all_findings)} issues ({crit}C {high}H)")

    return {
        "domain": domain,
        "dns_data": dns_data,
        "findings": all_findings,
        "vulnerabilities": all_findings,
        "total": len(all_findings),
    }


async def dns_recon_targets(domains: list[str]) -> dict:
    """Run DNS recon against multiple domains concurrently."""
    sem = asyncio.Semaphore(5)
    all_findings: list[dict] = []

    async def _one(domain: str) -> None:
        async with sem:
            r = await dns_recon(domain)
            all_findings.extend(r.get("findings", []))

    await asyncio.gather(*[_one(d) for d in domains], return_exceptions=True)
    return {
        "total": len(all_findings),
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }

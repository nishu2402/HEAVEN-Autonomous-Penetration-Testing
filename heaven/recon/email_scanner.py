"""
HEAVEN — Email Security Scanner
SPF, DKIM, DMARC analysis, MX enumeration, SMTP relay testing, spoofing risk.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.email")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class EmailFinding:
    target: str
    vuln_type: str
    severity: str
    title: str
    description: str
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target, "vuln_type": self.vuln_type,
            "severity": self.severity, "title": self.title,
            "description": self.description, "confidence": self.confidence,
            "evidence": self.evidence, "remediation": self.remediation,
        }


class EmailSecurityScanner:
    """Comprehensive email security scanner."""

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
        self._findings: list[EmailFinding] = []

    async def scan_domain(self, domain: str) -> list[EmailFinding]:
        """Run full email security scan for a domain."""
        logger.info(f"📧 Email Security Scan: {domain}")
        self._findings = []

        await self.check_mx(domain)
        await self.check_spf(domain)
        await self.check_dkim(domain)
        await self.check_dmarc(domain)
        await self.check_dnssec(domain)
        await self.check_mta_sts(domain)
        await self.check_tls_rpt(domain)
        await self.check_smtp_relay(domain)

        logger.info(f"Email scan complete for {domain}: {len(self._findings)} findings")
        return self._findings

    async def check_mx(self, domain: str) -> None:
        """Enumerate MX records."""
        if not HAS_DNS:
            logger.warning("dnspython not installed — DNS lookups unavailable")
            return
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    "priority": rdata.preference,
                    "server": str(rdata.exchange).rstrip("."),
                })
            if mx_records:
                self._findings.append(EmailFinding(
                    target=domain, vuln_type="mx_enumeration",
                    severity="info",
                    title=f"MX Records: {len(mx_records)} mail servers",
                    description=f"Mail servers: {', '.join(m['server'] for m in mx_records[:5])}",
                    confidence=1.0,
                    evidence={"mx_records": mx_records},
                ))
        except Exception as e:
            logger.debug(f"MX lookup failed for {domain}: {e}")

    async def check_spf(self, domain: str) -> None:
        """Analyze SPF record for weaknesses."""
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            spf_record = None
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break

            if not spf_record:
                self._findings.append(EmailFinding(
                    target=domain, vuln_type="spf_missing",
                    severity="high",
                    title=f"SPF Missing: {domain}",
                    description="No SPF record found. Anyone can send email as this domain.",
                    confidence=0.95,
                    remediation="Add SPF record: v=spf1 include:<provider> -all",
                ))
                return

            issues = []
            if "+all" in spf_record:
                issues.append("SPF uses '+all' (allows any sender)")
                severity = "critical"
            elif "~all" in spf_record:
                issues.append("SPF uses '~all' (softfail) instead of '-all' (hardfail)")
                severity = "medium"
            elif "?all" in spf_record:
                issues.append("SPF uses '?all' (neutral) — provides no protection")
                severity = "high"
            elif "-all" in spf_record:
                severity = "info"
            else:
                issues.append("SPF record has no 'all' mechanism")
                severity = "medium"

            # Check for too many DNS lookups (max 10)
            lookup_count = sum(1 for mech in ["include:", "a:", "mx:", "ptr:", "redirect="]
                               if mech in spf_record)
            if lookup_count > 8:
                issues.append(f"SPF has {lookup_count} DNS lookups (max 10 allowed)")

            self._findings.append(EmailFinding(
                target=domain, vuln_type="spf_analysis",
                severity=severity,
                title=f"SPF {'Issues' if issues else 'Configured'}: {domain}",
                description="; ".join(issues) if issues else "SPF properly configured with -all",
                confidence=0.95,
                evidence={"spf_record": spf_record, "issues": issues},
                remediation="Use '-all' mechanism. Minimize DNS lookups. Use include for providers." if issues else "",
            ))
        except dns.resolver.NXDOMAIN:
            self._findings.append(EmailFinding(
                target=domain, vuln_type="spf_missing", severity="high",
                title=f"SPF Missing: {domain} (NXDOMAIN)", description="Domain does not exist.",
                confidence=0.95,
            ))
        except Exception as e:
            logger.debug(f"SPF check failed: {e}")

    async def check_dkim(self, domain: str) -> None:
        """Check common DKIM selectors."""
        if not HAS_DNS:
            return
        common_selectors = [
            "default", "google", "selector1", "selector2", "k1", "k2",
            "mail", "dkim", "s1", "s2", "sig1", "smtp", "mx",
            "mandrill", "amazonses", "cm", "protonmail", "zoho",
        ]
        found_selectors = []
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        key_length = "unknown"
                        found_selectors.append({
                            "selector": selector, "key_length": key_length,
                        })
                        if "p=" in txt:
                            key_data = txt.split("p=")[1].split(";")[0].strip()
                            key_bits = len(key_data) * 6  # Approximate
                            key_length = f"~{key_bits} bits"
                            found_selectors[-1]["key_length"] = key_length
                            # Weak-key check only when an actual key is present.
                            # key_data == "" means a revoked selector, not a weak key.
                            if key_data and key_bits < 1024:
                                self._findings.append(EmailFinding(
                                    target=domain, vuln_type="dkim_weak_key",
                                    severity="high",
                                    title=f"DKIM Weak Key: {selector} ({key_length})",
                                    description=f"DKIM key for selector '{selector}' is too short.",
                                    confidence=0.80,
                                    remediation="Use 2048-bit RSA keys minimum for DKIM.",
                                ))
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue

        if not found_selectors:
            self._findings.append(EmailFinding(
                target=domain, vuln_type="dkim_missing",
                severity="medium",
                title=f"DKIM: No selectors found for {domain}",
                description="No DKIM records found for common selectors.",
                confidence=0.60,
                remediation="Configure DKIM with your email provider.",
            ))
        else:
            self._findings.append(EmailFinding(
                target=domain, vuln_type="dkim_found",
                severity="info",
                title=f"DKIM: {len(found_selectors)} selectors found",
                description=f"Active selectors: {', '.join(s['selector'] for s in found_selectors)}",
                confidence=0.95,
                evidence={"selectors": found_selectors},
            ))

    async def check_dmarc(self, domain: str) -> None:
        """Analyze DMARC policy."""
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = None
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                self._findings.append(EmailFinding(
                    target=domain, vuln_type="dmarc_missing",
                    severity="high",
                    title=f"DMARC Missing: {domain}",
                    description="No DMARC record. Email spoofing is possible.",
                    confidence=0.95,
                    remediation="Add DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
                ))
                return

            # Parse policy
            policy = "none"
            if "p=reject" in dmarc_record:
                policy = "reject"
            elif "p=quarantine" in dmarc_record:
                policy = "quarantine"
            elif "p=none" in dmarc_record:
                policy = "none"

            severity = "info" if policy == "reject" else ("medium" if policy == "quarantine" else "high")

            issues = []
            if policy == "none":
                issues.append("DMARC policy is 'none' — no enforcement")
            if "pct=" in dmarc_record:
                pct_match = re.search(r"pct=(\d+)", dmarc_record)
                if pct_match and int(pct_match.group(1)) < 100:
                    issues.append(f"DMARC only applied to {pct_match.group(1)}% of messages")
            if "rua=" not in dmarc_record:
                issues.append("No aggregate report URI (rua) configured")

            self._findings.append(EmailFinding(
                target=domain, vuln_type="dmarc_analysis",
                severity=severity,
                title=f"DMARC Policy: {policy} — {domain}",
                description="; ".join(issues) if issues else f"DMARC properly configured with p={policy}",
                confidence=0.95,
                evidence={"dmarc_record": dmarc_record, "policy": policy, "issues": issues},
                remediation="Set p=reject for full protection." if policy != "reject" else "",
            ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._findings.append(EmailFinding(
                target=domain, vuln_type="dmarc_missing", severity="high",
                title=f"DMARC Missing: {domain}",
                description="No DMARC record found.", confidence=0.95,
                remediation="Add DMARC record with p=reject.",
            ))
        except Exception as e:
            logger.debug(f"DMARC check failed: {e}")

    async def check_dnssec(self, domain: str) -> None:
        """Check whether the zone is DNSSEC-signed (DNSKEY present)."""
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(domain, "DNSKEY")
            if answers:
                self._findings.append(EmailFinding(
                    target=domain, vuln_type="dnssec_enabled", severity="info",
                    title=f"DNSSEC enabled: {domain}",
                    description=f"Zone is DNSSEC-signed ({len(answers)} DNSKEY record(s)).",
                    confidence=0.95, evidence={"dnskey_count": len(answers)},
                ))
                return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"DNSSEC check failed for {domain}: {e}")
            return
        self._findings.append(EmailFinding(
            target=domain, vuln_type="dnssec_missing", severity="low",
            title=f"DNSSEC not enabled: {domain}",
            description="No DNSKEY records — the zone is not DNSSEC-signed, so DNS "
                        "responses (incl. MX) can be spoofed via cache poisoning.",
            confidence=0.85,
            remediation="Sign the zone with DNSSEC and publish a DS record at the registrar.",
        ))

    async def check_mta_sts(self, domain: str) -> None:
        """Check for an MTA-STS policy record (_mta-sts TXT, v=STSv1)."""
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
            for rdata in answers:
                if "v=STSv1" in str(rdata):
                    self._findings.append(EmailFinding(
                        target=domain, vuln_type="mta_sts_enabled", severity="info",
                        title=f"MTA-STS configured: {domain}",
                        description="MTA-STS policy record present — enforces TLS for "
                                    "inbound mail.",
                        confidence=0.9, evidence={"record": str(rdata).strip('"')},
                    ))
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"MTA-STS check failed for {domain}: {e}")
            return
        self._findings.append(EmailFinding(
            target=domain, vuln_type="mta_sts_missing", severity="low",
            title=f"MTA-STS not configured: {domain}",
            description="No MTA-STS policy — sending servers cannot enforce TLS and may "
                        "be downgraded to cleartext by an on-path attacker.",
            confidence=0.8,
            remediation="Publish an MTA-STS policy (_mta-sts TXT + https policy file).",
        ))

    async def check_tls_rpt(self, domain: str) -> None:
        """Check for a TLS-RPT record (_smtp._tls TXT, v=TLSRPTv1)."""
        if not HAS_DNS:
            return
        try:
            answers = dns.resolver.resolve(f"_smtp._tls.{domain}", "TXT")
            for rdata in answers:
                if "v=TLSRPTv1" in str(rdata):
                    self._findings.append(EmailFinding(
                        target=domain, vuln_type="tls_rpt_enabled", severity="info",
                        title=f"TLS-RPT configured: {domain}",
                        description="SMTP TLS reporting is configured.",
                        confidence=0.9, evidence={"record": str(rdata).strip('"')},
                    ))
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"TLS-RPT check failed for {domain}: {e}")

    async def check_smtp_relay(self, domain: str) -> None:
        """Check STARTTLS support and probe for an open relay.

        The open-relay probe is NON-INTRUSIVE: it issues MAIL FROM / RCPT TO for
        two external domains and inspects the RCPT response code, then always
        sends RSET — it never sends DATA, so no mail is ever relayed.
        """
        mx_findings = [f for f in self._findings if f.vuln_type == "mx_enumeration"]
        if not mx_findings:
            return

        mx_servers = mx_findings[0].evidence.get("mx_records", [])
        for mx in mx_servers[:3]:
            server = mx["server"]
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server, 25), timeout=self._timeout
                )
                await asyncio.wait_for(reader.readline(), timeout=5)
                writer.write(b"EHLO heaven-scanner.example\r\n")
                await writer.drain()
                ehlo_resp = await asyncio.wait_for(reader.read(2048), timeout=5)
                ehlo_text = ehlo_resp.decode(errors="ignore")

                if "STARTTLS" not in ehlo_text.upper():
                    self._findings.append(EmailFinding(
                        target=server, vuln_type="smtp_no_starttls",
                        severity="medium",
                        title=f"SMTP: No STARTTLS on {server}",
                        description="Mail server does not advertise STARTTLS — inbound "
                                    "mail can be delivered in cleartext.",
                        confidence=0.85,
                        remediation="Enable STARTTLS on the mail server.",
                    ))

                # ── Non-intrusive open-relay probe (RSET before DATA) ──
                async def _cmd(line: bytes) -> str:
                    writer.write(line)  # type: ignore[union-attr]
                    await writer.drain()  # type: ignore[union-attr]
                    data = await asyncio.wait_for(reader.read(512), timeout=5)
                    return data.decode(errors="ignore")

                mail_resp = await _cmd(b"MAIL FROM:<probe@heaven-scanner.example>\r\n")
                if mail_resp.startswith("250"):
                    rcpt_resp = await _cmd(b"RCPT TO:<relay-test@example.net>\r\n")
                    if rcpt_resp.startswith("250"):
                        self._findings.append(EmailFinding(
                            target=server, vuln_type="smtp_open_relay",
                            severity="critical",
                            title=f"SMTP open relay on {server}",
                            description="Server accepted MAIL FROM and RCPT TO for two "
                                        "external domains (no DATA was sent). An open "
                                        "relay can be abused to send spoofed mail/spam.",
                            confidence=0.85,
                            evidence={"mail_from": mail_resp.strip()[:120],
                                      "rcpt_to": rcpt_resp.strip()[:120]},
                            remediation="Restrict relaying to authenticated senders / "
                                        "trusted networks only.",
                        ))
                    await _cmd(b"RSET\r\n")  # abandon the transaction — never DATA

                writer.write(b"QUIT\r\n")
                await writer.drain()
            except (asyncio.TimeoutError, OSError):
                pass
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:  # noqa: BLE001
                        logger.debug("suppressed non-fatal exception", exc_info=True)

    def summary(self) -> dict:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "total_findings": len(self._findings),
            "severity": sev,
            "findings": [f.to_dict() for f in self._findings],
        }


async def scan_email_domains(domains: Optional[list[str]] = None, **kwargs) -> dict:
    """Entry point from orchestrator."""
    target_domains = domains or kwargs.get("email_domains", [])
    if not target_domains:
        return {"skipped": True}
    scanner = EmailSecurityScanner()
    all_findings = []
    for domain in target_domains:
        findings = await scanner.scan_domain(domain)
        all_findings.extend(findings)
    return {"total": len(all_findings), "findings": [f.to_dict() for f in all_findings]}

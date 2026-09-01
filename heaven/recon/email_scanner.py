"""
HEAVEN — Email Security Scanner
SPF, DKIM, DMARC analysis, MX enumeration, SMTP relay testing, spoofing risk.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
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
        # SMTP is always port 25 in production; kept configurable so the
        # relay / user-enumeration path can be exercised against a local server.
        self._smtp_port = 25

    async def scan_domain(self, domain: str) -> list[EmailFinding]:
        """Run full email security scan for a domain."""
        logger.info(f"📧 Email Security Scan: {domain}")
        self._findings = []

        await self.check_mx(domain)
        await self.check_spf(domain)
        await self.check_dkim(domain)
        await self.check_dmarc(domain)
        await self.check_bimi(domain)
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

    @staticmethod
    def _dkim_key_bits(key_b64: str) -> tuple[Optional[int], str]:
        """Decode a DKIM public key (base64 DER SubjectPublicKeyInfo) and return
        ``(key_size_bits, algorithm)``. This reads the *real* modulus size rather
        than estimating from the base64 length. Returns ``(None, "")`` when the
        key cannot be parsed (malformed / unsupported)."""
        key_b64 = (key_b64 or "").strip()
        if not key_b64:
            return None, ""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
            from cryptography.hazmat.primitives.serialization import (
                load_der_public_key,
            )
            raw = base64.b64decode(key_b64 + "=" * (-len(key_b64) % 4))
            pub = load_der_public_key(raw)
            if isinstance(pub, rsa.RSAPublicKey):
                return pub.key_size, "rsa"
            if isinstance(pub, ed25519.Ed25519PublicKey):
                return 256, "ed25519"
            return getattr(pub, "key_size", None), pub.__class__.__name__.lower()
        except Exception:
            logger.debug("DKIM key decode failed", exc_info=True)
            return None, ""

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
                            bits, algo = self._dkim_key_bits(key_data)
                            if bits:
                                key_length = f"{bits}-bit {algo}".strip()
                            elif key_data:
                                key_length = "unparseable"
                            else:
                                # Empty p= is a revoked selector, not a weak key.
                                key_length = "revoked"
                            found_selectors[-1]["key_length"] = key_length
                            found_selectors[-1]["key_bits"] = bits
                            # Genuinely weak: RSA below 1024 bits is broken.
                            if algo == "rsa" and bits and bits < 1024:
                                self._findings.append(EmailFinding(
                                    target=domain, vuln_type="dkim_weak_key",
                                    severity="high",
                                    title=f"DKIM Weak Key: {selector} ({key_length})",
                                    description=f"DKIM key for selector '{selector}' is "
                                                f"{bits}-bit RSA, which is cryptographically "
                                                f"weak and can be factored.",
                                    confidence=0.90,
                                    evidence={"selector": selector, "key_bits": bits},
                                    remediation="Rotate to a 2048-bit RSA key for DKIM.",
                                ))
                            # 1024-bit RSA is deprecated (below the 2048 recommendation).
                            elif algo == "rsa" and bits == 1024:
                                self._findings.append(EmailFinding(
                                    target=domain, vuln_type="dkim_weak_key",
                                    severity="low",
                                    title=f"DKIM Legacy Key: {selector} (1024-bit rsa)",
                                    description=f"DKIM selector '{selector}' uses a 1024-bit "
                                                f"RSA key, below the current 2048-bit "
                                                f"recommendation.",
                                    confidence=0.85,
                                    evidence={"selector": selector, "key_bits": bits},
                                    remediation="Rotate to a 2048-bit RSA key for DKIM.",
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

            # Alignment modes (relaxed 'r' is the RFC default and not a finding
            # by itself; recorded in evidence for the assessor).
            adkim_m = re.search(r"adkim=([rs])", dmarc_record)
            aspf_m = re.search(r"aspf=([rs])", dmarc_record)
            adkim = adkim_m.group(1) if adkim_m else "r"
            aspf = aspf_m.group(1) if aspf_m else "r"

            # Subdomain policy (sp=). If the domain enforces but sp= is weaker,
            # sub-domains remain spoofable even though the apex is protected.
            sp_m = re.search(r"sp=(none|quarantine|reject)", dmarc_record)
            sub_policy = sp_m.group(1) if sp_m else None
            _rank = {"none": 0, "quarantine": 1, "reject": 2}
            if (sub_policy and policy in ("quarantine", "reject")
                    and _rank.get(sub_policy, 0) < _rank.get(policy, 0)):
                self._findings.append(EmailFinding(
                    target=domain, vuln_type="dmarc_subdomain_policy_weak",
                    severity="medium",
                    title=f"DMARC subdomain policy weaker than domain: sp={sub_policy}",
                    description=(f"The DMARC record enforces p={policy} for {domain} but "
                                 f"sets sp={sub_policy} for subdomains, so mail can still "
                                 f"be spoofed from any subdomain of {domain}."),
                    confidence=0.90,
                    evidence={"policy": policy, "subdomain_policy": sub_policy,
                              "dmarc_record": dmarc_record},
                    remediation="Set sp= to at least the same enforcement as p= "
                                "(quarantine or reject).",
                ))

            self._findings.append(EmailFinding(
                target=domain, vuln_type="dmarc_analysis",
                severity=severity,
                title=f"DMARC Policy {policy} for {domain}",
                description="; ".join(issues) if issues else f"DMARC properly configured with p={policy}",
                confidence=0.95,
                evidence={"dmarc_record": dmarc_record, "policy": policy,
                          "issues": issues, "adkim": adkim, "aspf": aspf,
                          "subdomain_policy": sub_policy},
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

    async def check_bimi(self, domain: str) -> None:
        """Check for a BIMI record (default._bimi TXT, v=BIMI1).

        BIMI only delivers value once DMARC is enforced, so a *missing* record is
        only reported when this domain already publishes an enforcing DMARC policy
        (quarantine/reject). Otherwise it is not yet applicable and stays silent
        (no noise)."""
        if not HAS_DNS:
            return
        dmarc = next((f for f in self._findings
                      if f.vuln_type == "dmarc_analysis"), None)
        policy = dmarc.evidence.get("policy") if dmarc else None
        try:
            answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT")
            for rdata in answers:
                if "v=BIMI1" in str(rdata):
                    self._findings.append(EmailFinding(
                        target=domain, vuln_type="bimi_configured", severity="info",
                        title=f"BIMI configured: {domain}",
                        description="A BIMI record is published, enabling verified "
                                    "brand logos in supporting mail clients.",
                        confidence=0.9,
                        evidence={"record": str(rdata).strip('"')[:200]},
                    ))
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"BIMI check failed for {domain}: {e}")
            return
        if policy in ("reject", "quarantine"):
            self._findings.append(EmailFinding(
                target=domain, vuln_type="bimi_missing", severity="low",
                title=f"BIMI not configured: {domain}",
                description="DMARC is enforced but no BIMI record is published, so "
                            "recipients receive no verified brand logo (a missed "
                            "anti-impersonation and brand-trust signal).",
                confidence=0.75,
                remediation="Publish a BIMI record (default._bimi TXT) referencing an "
                            "SVG logo, ideally backed by a VMC certificate.",
            ))

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
            target=domain, vuln_type="dnssec_missing", severity="medium",
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
        """Probe each MX for STARTTLS support, VRFY user-enum and an open relay.

        The open-relay probe is NON-INTRUSIVE: it issues MAIL FROM / RCPT TO for
        two external domains and inspects the RCPT response code, then always
        sends RSET — it never sends DATA, so no mail is ever relayed.
        """
        mx_findings = [f for f in self._findings if f.vuln_type == "mx_enumeration"]
        if not mx_findings:
            return

        mx_servers = mx_findings[0].evidence.get("mx_records", [])
        for mx in mx_servers[:3]:
            await self._probe_smtp_server(mx["server"], self._smtp_port)

    async def scan_smtp_server(self, host: str, port: int = 25) -> list[EmailFinding]:
        """Probe a raw SMTP endpoint (host:port) DIRECTLY, without an MX lookup.

        This is the entry point used when a network scan finds an open SMTP port
        on a bare IP / host that has no associated mail domain, and by the
        open-relay lab. It runs exactly the same non-intrusive checks as the
        MX-driven path (STARTTLS advertisement, VRFY user-enum differential, and
        the RSET-before-DATA open-relay probe)."""
        self._findings = []
        await self._probe_smtp_server(host, port)
        return self._findings

    async def _probe_smtp_server(self, server: str, port: int) -> None:
        """Connect to one SMTP server and run the STARTTLS / VRFY-enum / open-relay
        checks, appending any findings. Non-intrusive: RSET is always sent before
        DATA, so no mail is ever relayed."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port),
                timeout=self._timeout
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

            # ── Non-intrusive SMTP user-enumeration (VRFY differential) ──
            # Only reported when a plausibly-valid mailbox and a random one
            # produce DIFFERENT response classes (2xx vs 5xx): that proves the
            # server discloses which accounts exist. No mail is ever sent.
            try:
                valid_resp = await _cmd(b"VRFY postmaster\r\n")
                junk_resp = await _cmd(
                    f"VRFY heaven{secrets.token_hex(5)}\r\n".encode())
                if (valid_resp[:3] in ("250", "251")
                        and junk_resp[:3] in ("550", "551", "553")):
                    self._findings.append(EmailFinding(
                        target=server, vuln_type="smtp_user_enumeration",
                        severity="low",
                        title=f"SMTP user enumeration via VRFY on {server}",
                        description="The mail server answers VRFY differently for "
                                    "existing vs non-existing mailboxes, so valid "
                                    "usernames can be enumerated for phishing or "
                                    "password-spray targeting.",
                        confidence=0.85,
                        evidence={"valid_vrfy": valid_resp.strip()[:120],
                                  "invalid_vrfy": junk_resp.strip()[:120]},
                        remediation="Disable VRFY/EXPN or make them return a uniform "
                                    "response for all addresses.",
                    ))
            except (asyncio.TimeoutError, OSError):
                pass

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


async def scan_smtp_endpoint(host: str, port: int = 25) -> dict:
    """Entry point for a raw SMTP endpoint discovered by the network scanner
    (a bare IP / host with an open SMTP port and no mail domain to resolve).

    Runs the non-intrusive relay / STARTTLS / VRFY probes directly against
    ``host:port`` — no MX lookup required — so an open relay on an internal box
    is caught even when it publishes no MX record."""
    scanner = EmailSecurityScanner()
    findings = await scanner.scan_smtp_server(host, port)
    return {"total": len(findings), "findings": [f.to_dict() for f in findings]}

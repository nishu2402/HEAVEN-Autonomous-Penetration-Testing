# HEAVEN ↔ Cyber Essentials Plus (NCSC)

Mapping of HEAVEN's detectors against the UK NCSC [Cyber Essentials
**Plus**](https://www.ncsc.gov.uk/cyberessentials/overview) assessment — the
hands-on audit that *independently verifies* the same five controls a Cyber
Essentials self-assessment claims (see `cyber_essentials`). It assesses the same
current [*Requirements for IT Infrastructure* v3.3](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf)
("Danzell" question set, effective April 2026).

CE Plus adds technical assurance the assessor performs directly, following the
NCSC *Illustrative Test Specification*: an external vulnerability assessment of
the internet-facing footprint, an authenticated (credentialed) patch and
configuration audit of a device sample, a malware-protection functionality test,
and account-separation / MFA checks. HEAVEN automates every part of that test
specification that is a network or credentialed scan, each named to a real
detector. The residual endpoint functionality tests (running an EICAR file,
exercising email/web filtering on a workstation) and internal IdP checks have no
scan footprint and are listed per area as **out-of-band (analyst-attested)** —
never fabricated.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| CE Plus test area | HEAVEN evidence |
|---|---|
| External vulnerability assessment | full external scan suite |
| Authenticated patch & configuration audit | credentialed CVE/EOL/config audit |
| Malware protection functionality test | email-spoofing surface; endpoint tests analyst-attested |
| Account separation & MFA | lockout/default-cred/transport; IdP checks analyst-attested |
| Assessment sampling, evidence & reporting | scope + evidence + report generators |

## Detailed mapping

### External Vulnerability Assessment
The assessor scans every internet-facing IP in scope for missing patches and
insecure configuration — HEAVEN's default external run *is* this test.

| Test | Description | HEAVEN coverage |
|---|---|---|
| CEP-EXT-1 | Enumerate the internet-facing attack surface | `heaven.recon.network_scanner` (full-port external sweep) |
| CEP-EXT-2 | Flag services that should not be exposed | `heaven.recon.network_exposure` (Telnet/SNMP/IPMI/DB) |
| CEP-EXT-3 | Detect missing security updates on exposed services | `heaven.vulnscan.cve_mapper` (known-CVE versions) |
| CEP-EXT-4 | Detect unsupported / end-of-life software | `heaven.vulnscan.eol_scanner` |
| CEP-EXT-5 | Verify transport encryption on exposed services | `heaven.vulnscan.ssl_scanner` |
| CEP-EXT-6 | Detect exposed sensitive files / default content | `heaven.vulnscan.exposure_scanner`, `heaven.vulnscan.dir_fuzzer` |
| CEP-EXT-7 | Web-application vulnerability checks | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.advanced_attacks` |

### Authenticated Patch & Configuration Audit
CE Plus samples in-scope devices and audits, *with credentials*, that high/
critical patches are applied and default configuration is removed.

| Test | Description | HEAVEN coverage |
|---|---|---|
| CEP-AUTH-1 | Credentialed check for missing high/critical patches | `heaven.vulnscan.cve_mapper` (authenticated network testing) |
| CEP-AUTH-2 | Confirm all software is in vendor support | `heaven.vulnscan.eol_scanner` |
| CEP-AUTH-3 | Third-party / dependency components patched | `heaven.vulnscan.sca_scanner` |
| CEP-AUTH-4 | Default accounts and passwords removed | `heaven.vulnscan.auth_scanner` |
| CEP-AUTH-5 | Unnecessary services disabled on the sample | `heaven.recon.network_exposure` |

### Malware Protection Functionality Test
The externally measurable email-spoofing surface is automated; the endpoint/
mailbox functional tests are performed by the assessor.

| Test | Description | HEAVEN coverage |
|---|---|---|
| CEP-MW-3 | Inbound email spoofing surface is hardened | `heaven.recon.dns_recon` (SPF/DMARC/DKIM/MTA-STS) |

**Out-of-band (analyst-attested):** CEP-MW-1 (anti-malware blocks a benign EICAR
file), CEP-MW-2 (malicious email attachment rejected) and CEP-MW-4 (malicious
browser download blocked) are endpoint/mailbox functional tests a remote scanner
cannot perform without fabricating a result.

### Account Separation & Multi-Factor Authentication
| Test | Description | HEAVEN coverage |
|---|---|---|
| CEP-AC-1 | No default/shared credentials on exposed logins | `heaven.vulnscan.auth_scanner` |
| CEP-AC-2 | Credentials only accepted over encrypted channels | `heaven.vulnscan.ssl_scanner` |
| CEP-AC-3 | Brute-force / lockout resistance on exposed logins | `heaven.vulnscan.auth_scanner` (lockout probe — no-lockout is confirmed only on observed unlimited attempts) |

**Out-of-band (analyst-attested):** CEP-AC-4 (admin accounts separated from
standard users) and CEP-AC-5 (MFA enforced on cloud/admin) are internal IdP /
authenticated-review controls.

### Assessment Sampling, Evidence & Reporting
| Test | Description | HEAVEN coverage |
|---|---|---|
| CEP-REP-1 | Reproducible, evidenced findings for the assessor | `heaven.devsecops.evidence` (replayable proof) |
| CEP-REP-2 | Structured pass/fail report against the controls | `heaven.devsecops.compliance_report` |
| CEP-REP-3 | Define the device/IP sample and scope | `heaven scope` (the engagement scope DB *is* the defined sample) |

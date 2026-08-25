# HEAVEN ↔ Cyber Essentials (NCSC)

Mapping of HEAVEN's detectors against the UK NCSC [Cyber
Essentials](https://www.ncsc.gov.uk/cyberessentials/overview) scheme's five
technical control themes, aligned with the current [*Cyber Essentials
Requirements for IT Infrastructure* v3.3](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf)
, the "Danzell" question set, effective April 2026.

Cyber Essentials is a **self-assessed** certification: an organisation attests
that the five controls are in place. HEAVEN cannot issue that attestation, but it
provides *external, evidence-based verification* for every control with an
observable network footprint, what is exposed at the boundary, whether default
credentials remain, whether services run supported and patched software, and
whether transport is encrypted. Each such control below is automated by a real,
named detector. The residual controls that are purely endpoint-, IdP- or
policy-based (anti-malware on laptops, application allow-listing, automatic-update
configuration, MFA/least-privilege on internal accounts) have **no external
footprint**; they are listed per theme as **out-of-band (analyst-attested)** and
are not scored, an authenticated Cyber Essentials **Plus** audit (see
`cyber_essentials_plus`) covers them. HEAVEN never fabricates evidence.

A control row is marked **✓ exercised** on the live Methodology page only when
the HEAVEN detector it names actually produced a finding in the active
engagement.

## Coverage summary

| Control theme | HEAVEN evidence |
|---|---|
| 1. Firewalls & Internet Gateways | external attack-surface enumeration |
| 2. Secure Configuration | headers/TLS/default-file & default-credential checks |
| 3. Security Update Management | CVE / end-of-life / dependency detection |
| 4. User Access Control | default-credential & authentication checks (external) |
| 5. Malware Protection | email-spoofing surface; endpoint controls analyst-attested |

## Detailed mapping

### 1. Firewalls & Internet Gateways
HEAVEN enumerates exactly what the boundary actually exposes, the ground-truth
firewall rules cannot be read remotely, but their *effect* is measurable.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-FW-1 | Minimise internet-exposed services / block unrequired inbound | `heaven.recon.network_scanner` (full-port external surface) |
| CE-FW-2 | No unnecessary management services on the boundary | `heaven.recon.network_exposure` (Telnet, SNMP, IPMI, exposed DB/RDP) |
| CE-FW-3 | Change default admin password on boundary/router/AP devices | `heaven.vulnscan.auth_scanner`, `heaven.recon.wireless_posture` |
| CE-FW-4 | Administrative interfaces not published to the internet | `heaven.vulnscan.dir_fuzzer` (admin panels), `heaven.recon.web_crawler` |

**Out-of-band (analyst-attested):** CE-FW-5 (documented business case for each
open port) is a firewall-ruleset paperwork check, HEAVEN supplies the
authoritative open-port inventory the operator maps business justifications onto,
but does not assert the justification itself.

### 2. Secure Configuration
| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-SC-1 | Remove or disable unnecessary services and accounts | `heaven.recon.network_exposure`, `heaven.vulnscan.auth_scanner` |
| CE-SC-2 | Change default passwords before deployment | `heaven.vulnscan.auth_scanner` (default-credential probes) |
| CE-SC-3 | Remove default/backup/sample files and directory listing | `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.exposure_scanner` |
| CE-SC-4 | Apply security headers and disable verbose errors | `heaven.recon.web_crawler`, `heaven.vulnscan.misconfig_scanner` (headers, error leakage) |
| CE-SC-5 | Enforce secure transport configuration (TLS) | `heaven.vulnscan.ssl_scanner` |

**Out-of-band (analyst-attested):** CE-SC-6 (disable auto-run / lock down endpoint
config) is a host-level control with no network-observable footprint.

### 3. Security Update Management
The core of Cyber Essentials, HEAVEN detects software that is missing security
patches or is out of vendor support.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-UP-1 | All software licensed and in vendor support | `heaven.vulnscan.eol_scanner` (end-of-life / unsupported software) |
| CE-UP-2 | Security updates applied within the required window | `heaven.vulnscan.cve_mapper` (known-CVE service versions) |
| CE-UP-3 | Remove unsupported software / components | `heaven.vulnscan.eol_scanner` |
| CE-UP-4 | Third-party dependencies kept patched | `heaven.vulnscan.sca_scanner` (vulnerable dependencies, OSV-backed) |

**Out-of-band (analyst-attested):** CE-UP-5 (automatic updates enabled) is an
endpoint-configuration setting, not externally observable.

### 4. User Access Control
| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-AC-1 | No default or shared credentials on exposed services | `heaven.vulnscan.auth_scanner` |
| CE-AC-2 | Credentials protected in transit | `heaven.vulnscan.ssl_scanner` (credentials over encrypted channel) |
| CE-AC-3 | Account lockout / brute-force resistance on exposed logins | `heaven.vulnscan.auth_scanner` (lockout probe) |

**Out-of-band (analyst-attested):** CE-AC-4 (unique accounts / least privilege /
MFA on admin & cloud) and CE-AC-5 (remove accounts no longer required) are
internal IdP / authenticated-review controls with no external footprint.

### 5. Malware Protection
Cyber Essentials permits anti-malware, application allow-listing, or sandboxing.
The endpoint controls a remote scanner cannot observe are attested by the CE
**Plus** audit; the email-spoofing surface that *is* externally measurable is
automated.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-MW-3 | Email and web content filtering hardened | `heaven.recon.dns_recon` (SPF/DMARC/DKIM/MTA-STS, inbound email spoofing surface) |

**Out-of-band (analyst-attested):** CE-MW-1 (anti-malware installed on all
devices) and CE-MW-2 (application allow-listing) are endpoint controls verified
by the CE Plus functional test, a remote external scanner cannot see them
without fabricating evidence.

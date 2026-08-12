# HEAVEN ↔ Cyber Essentials (NCSC)

Mapping of HEAVEN's detectors against the UK NCSC [Cyber
Essentials](https://www.ncsc.gov.uk/cyberessentials/overview) scheme's five
technical control themes, aligned with the current [*Cyber Essentials
Requirements for IT Infrastructure* v3.3](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf)
— the "Danzell" question set, effective April 2026.

Cyber Essentials is a **self-assessed** certification: an organisation attests
that the five controls are in place. HEAVEN cannot issue that attestation, but
it can provide *external, evidence-based verification* for the controls that
have an observable network footprint — chiefly what is exposed at the internet
boundary, whether default credentials remain, whether services run supported
and patched software, and whether transport is encrypted. Controls that are
purely endpoint- or policy-based (anti-malware on laptops, application
allow-listing, MFA configuration) are honestly marked `(manual)` — a remote
scanner cannot see them without faking evidence.

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
| 5. Malware Protection | mostly manual — endpoint control, not network-observable |

## Detailed mapping

### 1. Firewalls & Internet Gateways
HEAVEN enumerates exactly what the boundary actually exposes — the ground-truth
firewall rules cannot be read remotely, but their *effect* is measurable.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-FW-1 | Minimise internet-exposed services / block unrequired inbound | `heaven.recon.network_scanner` (full-port external surface) |
| CE-FW-2 | No unnecessary management services on the boundary | `heaven.recon.network_exposure` (Telnet, SNMP, IPMI, exposed DB/RDP) |
| CE-FW-3 | Change default admin password on boundary/router/AP devices | `heaven.vulnscan.auth_scanner`, `heaven.recon.wireless_posture` |
| CE-FW-4 | Administrative interfaces not published to the internet | `heaven.vulnscan.dir_fuzzer` (admin panels), `heaven.recon.web_crawler` |
| CE-FW-5 | Documented business case for each open port | (manual — operator confirms against the firewall ruleset) |

### 2. Secure Configuration
| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-SC-1 | Remove or disable unnecessary services and accounts | `heaven.recon.network_exposure`, `heaven.vulnscan.auth_scanner` |
| CE-SC-2 | Change default passwords before deployment | `heaven.vulnscan.auth_scanner` (default-credential probes) |
| CE-SC-3 | Remove default/backup/sample files and directory listing | `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.exposure_scanner` |
| CE-SC-4 | Apply security headers and disable verbose errors | `heaven.recon.web_crawler` (headers, error leakage) |
| CE-SC-5 | Enforce secure transport configuration (TLS) | `heaven.vulnscan.ssl_scanner` |
| CE-SC-6 | Disable auto-run / lock down endpoint config | (manual — host-level, not network-observable) |

### 3. Security Update Management
The core of Cyber Essentials — HEAVEN detects software that is missing security
patches or is out of vendor support.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-UP-1 | All software licensed and in vendor support | `heaven.vulnscan.eol_scanner` (end-of-life / unsupported software) |
| CE-UP-2 | Security updates applied within the required window | `heaven.vulnscan.cve_mapper` (known-CVE service versions) |
| CE-UP-3 | Remove unsupported software / components | `heaven.vulnscan.eol_scanner` |
| CE-UP-4 | Third-party dependencies kept patched | `heaven.devsecops.sca_scanner` (vulnerable dependencies) |
| CE-UP-5 | Automatic updates enabled where available | (manual — endpoint configuration) |

### 4. User Access Control
| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-AC-1 | No default or shared credentials on exposed services | `heaven.vulnscan.auth_scanner` |
| CE-AC-2 | Credentials protected in transit | `heaven.vulnscan.ssl_scanner` (credentials over encrypted channel) |
| CE-AC-3 | Account lockout / brute-force resistance on exposed logins | `heaven.vulnscan.auth_scanner` (lockout probe) |
| CE-AC-4 | Unique accounts, least privilege, MFA on admin/cloud | (manual — internal/IdP configuration) |
| CE-AC-5 | Remove or disable accounts no longer required | (manual — authenticated review) |

### 5. Malware Protection
Cyber Essentials permits anti-malware, application allow-listing, or sandboxing.
These are endpoint controls a remote external scanner cannot observe without
fabricating evidence, so they are honestly out of scope here — an authenticated
Cyber Essentials **Plus** audit covers them (see `cyber_essentials_plus`).

| Control | Description | HEAVEN coverage |
|---|---|---|
| CE-MW-1 | Anti-malware installed and updated on all devices | (manual — endpoint control) |
| CE-MW-2 | Application allow-listing where used | (manual — endpoint control) |
| CE-MW-3 | Email and web content filtering hardened | `heaven.recon.dns_recon` (SPF/DMARC/DKIM/MTA-STS — inbound email spoofing surface) |

# HEAVEN ↔ PCI DSS v4.0.1

Mapping of HEAVEN's detectors against the [PCI DSS
v4.0.1](https://www.pcisecuritystandards.org/) (Payment Card Industry Data
Security Standard) twelve requirements.

PCI DSS combines technical controls with process, policy and physical controls.
HEAVEN directly supports the *technical testing* requirements — most importantly
**Requirement 11** (regular vulnerability scanning and penetration testing),
plus network security controls (Req 1), secure configuration (Req 2), encryption
in transit (Req 4), secure systems and software (Req 6) and authentication
(Req 8). Requirements about stored-data protection, physical access, logging
policy and governance are attested through the assessor's process and are marked
`(organizational)` / `(physical)` here.

> HEAVEN is not an ASV (Approved Scanning Vendor) and does not produce an ASV
> attestation; it provides the internal technical evidence that supports a PCI
> assessment. A control row is **✓ exercised** only when the detector it names
> produced a finding in the active engagement.

## Coverage summary

| Requirement | HEAVEN evidence |
|---|---|
| 1 Network security controls | external surface & exposed-service enumeration |
| 2 Secure configurations | default-credential / config / service checks |
| 4 Encryption in transit | TLS strength assessment |
| 6 Secure systems & software | CVE / EOL / dependency / SAST / web-app checks |
| 8 Identify & authenticate access | authentication & default-credential checks |
| 11 Test security regularly | extensive — the core scanning & pentest suite |
| 3, 5, 7, 9, 10, 12 | organizational / physical / endpoint — see rows |

## Detailed mapping

### Requirement 1 — Install and maintain network security controls
| Control | Description | HEAVEN coverage |
|---|---|---|
| 1.2 | Restrict inbound/outbound traffic to what is necessary | `heaven.recon.network_scanner` (external reachable surface) |
| 1.3 | No direct exposure of untrusted networks to the CDE | `heaven.recon.network_exposure` (services that should not be exposed) |
| 1.4 | Controls between trusted and untrusted networks | `heaven.recon.network_scanner` (segmentation reachability, partial) |

### Requirement 2 — Apply secure configurations to all system components
| Control | Description | HEAVEN coverage |
|---|---|---|
| 2.2 | System components configured securely | `heaven.recon.web_crawler`, `heaven.vulnscan.dir_fuzzer` |
| 2.2.2 | Vendor default accounts removed or secured | `heaven.vulnscan.auth_scanner` (default credentials) |
| 2.2.4 | Only necessary services/protocols enabled | `heaven.recon.network_exposure` |

### Requirement 3 — Protect stored account data
Stored cardholder-data protection (encryption at rest, truncation, key
management) is evidenced through the assessor's data-flow and key-management
review, not an external scan.

| Control | Description | HEAVEN coverage |
|---|---|---|
| 3.x | Protect stored account data at rest | (organizational — data-at-rest / key management) |

### Requirement 4 — Protect cardholder data with strong cryptography during transmission
| Control | Description | HEAVEN coverage |
|---|---|---|
| 4.2.1 | Strong cryptography and security protocols in transit | `heaven.vulnscan.ssl_scanner` |

### Requirement 5 — Protect all systems and networks from malicious software
| Control | Description | HEAVEN coverage |
|---|---|---|
| 5.x | Anti-malware deployed, current, and monitored | (manual — endpoint control) |

### Requirement 6 — Develop and maintain secure systems and software
| Control | Description | HEAVEN coverage |
|---|---|---|
| 6.2 | Bespoke software developed securely | `heaven.vulnscan.sast_runner` |
| 6.2.4 | Protect against common web-application attacks | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.advanced_attacks` |
| 6.3.2 | Inventory of bespoke and third-party software | `heaven.devsecops.sca_scanner` |
| 6.3.3 | Security patches / updates installed | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner` |

### Requirement 7 — Restrict access to system components by business need to know
| Control | Description | HEAVEN coverage |
|---|---|---|
| 7.x | Least-privilege access enforced | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` (partial — authorization flaws) |

### Requirement 8 — Identify users and authenticate access
| Control | Description | HEAVEN coverage |
|---|---|---|
| 8.3 | Strong authentication for users and administrators | `heaven.vulnscan.auth_scanner` |
| 8.3.6 | No default / guessable credentials | `heaven.vulnscan.auth_scanner` |
| 8.4 | Multi-factor authentication for access to the CDE | (manual — IdP / MFA configuration) |

### Requirement 9 — Restrict physical access to cardholder data
| Control | Description | HEAVEN coverage |
|---|---|---|
| 9.x | Physical access controls | (physical — site control) |

### Requirement 10 — Log and monitor all access
| Control | Description | HEAVEN coverage |
|---|---|---|
| 10.x | Audit logs and monitoring in place | `heaven.devsecops.alerting` (webhook/SIEM feed, partial) |

### Requirement 11 — Test security of systems and networks regularly
HEAVEN's primary alignment — this requirement *is* recurring vulnerability
scanning and penetration testing.

| Control | Description | HEAVEN coverage |
|---|---|---|
| 11.3.1 | Internal vulnerability scans | `heaven.recon.network_scanner`, `heaven.vulnscan.cve_mapper` |
| 11.3.2 | External vulnerability scans | `heaven.recon.network_scanner`, `heaven.vulnscan.ssl_scanner`, `heaven.vulnscan.exposure_scanner` |
| 11.4 | External and internal penetration testing | `heaven.orchestrator` (full scan suite) |
| 11.4.3 | Application-layer penetration testing | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.api_scanner` |

### Requirement 12 — Support information security with organizational policies
| Control | Description | HEAVEN coverage |
|---|---|---|
| 12.x | Security policy, risk assessment, awareness | (organizational — policy & governance) |

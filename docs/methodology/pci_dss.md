# HEAVEN ↔ PCI DSS v4.0.1

Mapping of HEAVEN's detectors against the [PCI DSS
v4.0.1](https://www.pcisecuritystandards.org/) (Payment Card Industry Data
Security Standard) twelve requirements.

PCI DSS combines technical controls with process, policy and physical controls.
HEAVEN directly supports the *technical testing* requirements — most importantly
**Requirement 11** (regular vulnerability scanning and penetration testing), plus
network security controls (Req 1), secure configuration (Req 2), encryption in
transit (Req 4), secure systems and software (Req 6), least-privilege (Req 7) and
authentication (Req 8) — each named to a real detector. Requirements about
stored-data protection, physical access, anti-malware, audit-logging and
governance have no external-scan footprint and are listed as **out-of-band
(analyst-attested)**.

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
| 7 Least privilege | authorization-flaw testing (IDOR / broken access control) |
| 8 Identify & authenticate access | authentication & default-credential checks |
| 11 Test security regularly | extensive — the core scanning & pentest suite |
| 3, 5, 9, 10, 12 | data-at-rest / physical / endpoint / logging / governance — analyst-attested |

## Detailed mapping

### Requirement 1 — Install and maintain network security controls
| Control | Description | HEAVEN coverage |
|---|---|---|
| 1.2 | Restrict inbound/outbound traffic to what is necessary | `heaven.recon.network_scanner` (external reachable surface) |
| 1.3 | No direct exposure of untrusted networks to the CDE | `heaven.recon.network_exposure` (services that should not be exposed) |
| 1.4 | Controls between trusted and untrusted networks | `heaven.recon.network_scanner` (host-to-host reachability from the scan vantage point evidences the segmentation boundary) |

### Requirement 2 — Apply secure configurations to all system components
| Control | Description | HEAVEN coverage |
|---|---|---|
| 2.2 | System components configured securely | `heaven.recon.web_crawler`, `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.misconfig_scanner` |
| 2.2.2 | Vendor default accounts removed or secured | `heaven.vulnscan.auth_scanner` (default credentials) |
| 2.2.4 | Only necessary services/protocols enabled | `heaven.recon.network_exposure` |

### Requirement 3 — Protect stored account data
**Out-of-band (analyst-attested):** stored cardholder-data protection (encryption
at rest, truncation, key management) is evidenced through the assessor's data-flow
and key-management review, not an external scan.

### Requirement 4 — Protect cardholder data with strong cryptography during transmission
| Control | Description | HEAVEN coverage |
|---|---|---|
| 4.2.1 | Strong cryptography and security protocols in transit | `heaven.vulnscan.ssl_scanner` |

### Requirement 5 — Protect all systems and networks from malicious software
**Out-of-band (analyst-attested):** anti-malware deployment, currency and
monitoring is an endpoint control with no external footprint.

### Requirement 6 — Develop and maintain secure systems and software
| Control | Description | HEAVEN coverage |
|---|---|---|
| 6.2 | Bespoke software developed securely | `heaven.vulnscan.sast_runner` |
| 6.2.4 | Protect against common web-application attacks | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.advanced_attacks` |
| 6.3.2 | Inventory of bespoke and third-party software | `heaven.vulnscan.sca_scanner` |
| 6.3.3 | Security patches / updates installed | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner` |

### Requirement 7 — Restrict access to system components by business need to know
| Control | Description | HEAVEN coverage |
|---|---|---|
| 7.x | Least-privilege access enforced | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` (authorization-flaw testing — vertical/horizontal privilege violations) |

### Requirement 8 — Identify users and authenticate access
| Control | Description | HEAVEN coverage |
|---|---|---|
| 8.3 | Strong authentication for users and administrators | `heaven.vulnscan.auth_scanner` |
| 8.3.6 | No default / guessable credentials | `heaven.vulnscan.auth_scanner` |

**Out-of-band (analyst-attested):** 8.4 (multi-factor authentication for CDE
access) is an IdP / MFA-configuration control.

### Requirement 9 — Restrict physical access to cardholder data
**Out-of-band (analyst-attested):** physical access controls are site controls
outside the reach of a remote scanner.

### Requirement 10 — Log and monitor all access
**Out-of-band (analyst-attested):** whether the CDE logs and retains access
records is a target-side operational control an external scan cannot verify —
HEAVEN feeds its own findings to a SIEM (`heaven.devsecops.alerting`) but does not
assert the target's logging is in place.

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
**Out-of-band (analyst-attested):** security policy, risk assessment and
awareness are governance controls attested through the assessor's process.

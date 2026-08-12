# HEAVEN ↔ CIS Critical Security Controls v8.1

Mapping of HEAVEN's detectors against the [CIS Critical Security Controls
v8.1](https://www.cisecurity.org/controls) — 18 prioritised controls (each with
underlying Safeguards).

The CIS Controls span the whole security programme, from technical hardening to
governance and incident response. HEAVEN provides external and credentialed
technical evidence for the controls it can measure — most directly **CIS 7
Continuous Vulnerability Management**, **CIS 4 Secure Configuration**, **CIS 12
Network Infrastructure Management**, **CIS 16 Application Software Security** and
**CIS 18 Penetration Testing**. Programme controls (awareness training, incident
response, data recovery) are `(organizational)`.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Control | HEAVEN evidence |
|---|---|
| CIS 1–2 Asset & Software Inventory | external discovery & version detection (partial) |
| CIS 4 Secure Configuration | config / TLS / default-credential checks |
| CIS 6 Access Control Management | authorization & authentication flaws |
| CIS 7 Continuous Vulnerability Management | extensive — CVE / EOL / dependency |
| CIS 9 Email & Browser Protections | SPF/DMARC/DKIM/MTA-STS checks |
| CIS 12 Network Infrastructure | exposed-service & wireless-mgmt checks |
| CIS 16 Application Software Security | SAST / web / API vulnerability testing |
| CIS 18 Penetration Testing | extensive — the full scan suite |
| CIS 3,5,8,10,11,13,14,15,17 | partial / organizational — see rows |

## Detailed mapping

### Identify & Inventory (CIS 1–3)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-1 | Inventory and control of enterprise assets | `heaven.recon.network_scanner` (external host/service discovery, partial) |
| CSC-2 | Inventory and control of software assets | `heaven.vulnscan.eol_scanner`, `heaven.devsecops.sca_scanner` (partial) |
| CSC-3 | Data protection | `heaven.vulnscan.exposure_scanner` (exposed data/secrets, partial) |

### Secure Configuration & Access (CIS 4–6)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-4 | Secure configuration of enterprise assets and software | `heaven.recon.web_crawler`, `heaven.vulnscan.ssl_scanner`, `heaven.recon.network_exposure`, `heaven.vulnscan.auth_scanner` |
| CSC-5 | Account management | `heaven.vulnscan.auth_scanner` (default accounts, partial) |
| CSC-6 | Access control management | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` |

### Continuous Vulnerability Management (CIS 7)
HEAVEN's centre of gravity — continuous detection of known-vulnerable, unpatched
and end-of-life software.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-7.1 | Establish and maintain a vulnerability management process | `heaven.recon.network_scanner`, `heaven.vulnscan.cve_mapper` |
| CSC-7.5 | Perform automated vulnerability scans | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.ssl_scanner`, `heaven.vulnscan.api_scanner` |
| CSC-7.7 | Remediate detected vulnerabilities (unsupported software) | `heaven.vulnscan.eol_scanner`, `heaven.devsecops.sca_scanner` |

### Logging, Email & Malware (CIS 8–10)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-8 | Audit log management | `heaven.devsecops.alerting` (webhook/SIEM feed, partial) |
| CSC-9 | Email and web browser protections | `heaven.recon.dns_recon` (SPF/DMARC/DKIM/MTA-STS) |
| CSC-10 | Malware defenses | (manual — endpoint control) |

### Recovery & Network Infrastructure (CIS 11–12)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-11 | Data recovery | (organizational — backup / recovery process) |
| CSC-12 | Network infrastructure management | `heaven.recon.network_scanner`, `heaven.recon.network_exposure`, `heaven.recon.wireless_posture`, `heaven.vulnscan.ssl_scanner` |

### Monitoring, Awareness & Service Providers (CIS 13–15)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-13 | Network monitoring and defense | `heaven.recon.adaptive_intel` (WAF/IDS fingerprint, partial) |
| CSC-14 | Security awareness and skills training | (organizational — training) |
| CSC-15 | Service provider management | `heaven.recon.cloud_enum`, `heaven.recon.cloud_iam` (cloud posture, partial) |

### Application Security, Incident Response & Pentest (CIS 16–18)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-16 | Application software security | `heaven.vulnscan.sast_runner`, `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.api_scanner`, `heaven.devsecops.sca_scanner` |
| CSC-17 | Incident response management | (organizational — IR process) |
| CSC-18 | Penetration testing | `heaven.orchestrator` (full external & application scan suite) |

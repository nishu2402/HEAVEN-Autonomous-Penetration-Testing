# HEAVEN ↔ CIS Critical Security Controls v8.1

Mapping of HEAVEN's detectors against the [CIS Critical Security Controls
v8.1](https://www.cisecurity.org/controls), 18 prioritised controls (each with
underlying Safeguards).

The CIS Controls span the whole security programme, from technical hardening to
governance and incident response. HEAVEN provides external and credentialed
technical evidence for every control it can measure, asset & software inventory,
secure configuration, continuous vulnerability management, email/browser
protections, network-infrastructure management, monitoring/defense fingerprinting,
application-software security and penetration testing, each named to a real
detector. Programme controls (audit-log retention, data recovery, awareness
training, incident response) have no scan footprint and are listed as
**out-of-band (analyst-attested)**.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Control | HEAVEN evidence |
|---|---|
| CIS 1-3 Asset, Software & Data | external discovery, version detection, exposed-data checks |
| CIS 4-6 Secure Config & Access | config / TLS / default-credential / authorization checks |
| CIS 7 Continuous Vulnerability Management | extensive, CVE / EOL / dependency |
| CIS 9 Email & Browser Protections | SPF/DMARC/DKIM/MTA-STS checks |
| CIS 12-13 Network Infra & Monitoring | exposed-service, wireless-mgmt, defense fingerprint |
| CIS 15 Service Providers | cloud enumeration & IAM posture |
| CIS 16 Application Software Security | SAST / web / API vulnerability testing |
| CIS 18 Penetration Testing | extensive, the full scan suite |
| CIS 8,10,11,14,17 | logging / endpoint / recovery / training / IR, analyst-attested |

## Detailed mapping

### Identify & Inventory (CIS 1-3)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-1 | Inventory and control of enterprise assets | `heaven.recon.network_scanner`, `heaven.devsecops.inventory` (host/service discovery + inventory table) |
| CSC-2 | Inventory and control of software assets | `heaven.vulnscan.eol_scanner`, `heaven.vulnscan.sca_scanner`, `heaven.devsecops.sbom` (CycloneDX SBOM) |
| CSC-3 | Data protection | `heaven.vulnscan.exposure_scanner` (exposed data / secrets) |

### Secure Configuration & Access (CIS 4-6)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-4 | Secure configuration of enterprise assets and software | `heaven.recon.web_crawler`, `heaven.vulnscan.ssl_scanner`, `heaven.recon.network_exposure`, `heaven.vulnscan.auth_scanner` |
| CSC-5 | Account management | `heaven.vulnscan.auth_scanner` (default/weak accounts on exposed services) |
| CSC-6 | Access control management | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` |

### Continuous Vulnerability Management (CIS 7)
HEAVEN's centre of gravity, continuous detection of known-vulnerable, unpatched
and end-of-life software.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-7.1 | Establish and maintain a vulnerability management process | `heaven.recon.network_scanner`, `heaven.vulnscan.cve_mapper` |
| CSC-7.5 | Perform automated vulnerability scans | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.ssl_scanner`, `heaven.vulnscan.api_scanner` |
| CSC-7.7 | Remediate detected vulnerabilities (unsupported software) | `heaven.vulnscan.eol_scanner`, `heaven.vulnscan.sca_scanner` |

### Logging, Email & Malware (CIS 8-10)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-9 | Email and web browser protections | `heaven.recon.dns_recon` (SPF/DMARC/DKIM/MTA-STS) |

**Out-of-band (analyst-attested):** CSC-8 (audit-log management: whether the
target collects and retains logs is a target-side operational control an external
scan cannot verify) and CSC-10 (malware defenses, endpoint control).

### Recovery & Network Infrastructure (CIS 11-12)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-12 | Network infrastructure management | `heaven.recon.network_scanner`, `heaven.recon.network_exposure`, `heaven.recon.wireless_posture`, `heaven.vulnscan.ssl_scanner` |

**Out-of-band (analyst-attested):** CSC-11 (data recovery) is a backup/recovery
process control.

### Monitoring, Awareness & Service Providers (CIS 13-15)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-13 | Network monitoring and defense | `heaven.recon.adaptive_intel` (WAF/IDS fingerprint), `heaven.recon.firewall_detector` (perimeter firewall/IDS classification) |
| CSC-15 | Service provider management | `heaven.recon.cloud_enum`, `heaven.recon.cloud_iam` (cloud posture / IAM) |

**Out-of-band (analyst-attested):** CSC-14 (security awareness and skills
training) is an HR/training control.

### Application Security, Incident Response & Pentest (CIS 16-18)
| Control | Description | HEAVEN coverage |
|---|---|---|
| CSC-16 | Application software security | `heaven.vulnscan.sast_runner`, `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.api_scanner`, `heaven.vulnscan.sca_scanner` |
| CSC-18 | Penetration testing | `heaven.orchestrator` (full external & application scan suite) |

**Out-of-band (analyst-attested):** CSC-17 (incident response management) is an
IR-process control.

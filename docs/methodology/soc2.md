# HEAVEN ↔ SOC 2 (Trust Services Criteria)

Mapping of HEAVEN's detectors against the AICPA [SOC 2 Trust Services Criteria
(TSC)](https://www.aicpa-cima.com/) — the **2017 criteria (with revised points
of focus, 2022)**, specifically the Common Criteria (CC1–CC9) that underpin the
*Security* category.

SOC 2 is an **attestation** performed by an independent CPA over a period of
time; it is not a scan and HEAVEN does not issue a SOC 2 report. What HEAVEN
provides is *technical evidence for the Security criteria* — chiefly **CC6
Logical & Physical Access Controls**, **CC7 System Operations** and the
risk/monitoring points of CC3–CC4 and CC8 — each named to a real detector, that
an organisation and its auditor can use as supporting control evidence.
Governance, control-design and risk-programme criteria are attested through
records and are listed as **out-of-band (analyst-attested)**.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Common Criteria | HEAVEN evidence |
|---|---|
| CC1–CC2 Control Environment & Communication | governance — analyst-attested |
| CC3–CC4 Risk Assessment & Monitoring | vulnerability identification + continuous re-scan |
| CC5 Control Activities | governance — analyst-attested |
| CC6 Logical & Physical Access Controls | extensive — access, boundary, transport crypto |
| CC7 System Operations | extensive — vulnerability detection & monitoring |
| CC8 Change Management | secure-development evidence (SAST + SCA) |
| CC9 Risk Mitigation | governance — analyst-attested |

## Detailed mapping

### CC1–CC2 Control Environment & Communication
**Out-of-band (analyst-attested):** CC1 (control environment, integrity,
oversight) and CC2 (communication and information) are governance criteria
attested through records, not scannable properties.

### CC3–CC5 Risk Assessment, Monitoring & Control Activities
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC3.2 | Identify and assess risks (vulnerabilities as risk inputs) | `heaven.vulnscan.cve_mapper`, `heaven.orchestrator` (full suite + scoring) |
| CC4.1 | Monitor the effectiveness of controls over time | `heaven.utils.watcher` (recurring re-scan), `heaven.devsecops.retest_report` (remediation verification across scans) |

**Out-of-band (analyst-attested):** CC5 (control activities support the
objectives) is a control-design criterion.

### CC6 Logical & Physical Access Controls
The strongest SOC 2 alignment for a technical scanner.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CC6.1 | Logical access security (authentication) | `heaven.vulnscan.auth_scanner` |
| CC6.1b | Authorization / least privilege enforced | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` |
| CC6.6 | Boundary protection against external threats | `heaven.recon.network_scanner`, `heaven.recon.network_exposure` |
| CC6.7 | Data transmitted is protected (encryption in transit) | `heaven.vulnscan.ssl_scanner` |

**Out-of-band (analyst-attested):** CC6.8 (prevent or detect unauthorized/
malicious software) is an endpoint control.

### CC7 System Operations
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC7.1 | Detect configuration changes and vulnerabilities | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner`, `heaven.recon.network_scanner` |
| CC7.2 | Monitor for anomalies and security events | `heaven.recon.adaptive_intel` (defense fingerprint), `heaven.recon.firewall_detector` (perimeter classification) |
| CC7.3 | Evaluate security events and respond | `heaven.vulnscan.safe_validator` + `heaven.vulnscan.fp_suppress` (evaluate) → `heaven.devsecops.alerting` (structured SIEM/webhook delivery) |

**Out-of-band (analyst-attested):** CC7.4 (respond to identified security
incidents) is an IR-process criterion.

### CC8–CC9 Change Management & Risk Mitigation
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC8.1 | Changes are developed and tested securely | `heaven.vulnscan.sast_runner`, `heaven.vulnscan.sca_scanner` |

**Out-of-band (analyst-attested):** CC9.1 (risk mitigation and vendor/business-
partner risk) is a risk-programme criterion.

# HEAVEN ↔ SOC 2 (Trust Services Criteria)

Mapping of HEAVEN's detectors against the AICPA [SOC 2 Trust Services Criteria
(TSC)](https://www.aicpa-cima.com/) — the **2017 criteria (with revised points
of focus, 2022)**, specifically the Common Criteria (CC1–CC9) that underpin the
*Security* category, plus notes on the additional categories.

SOC 2 is an **attestation** performed by an independent CPA over a period of
time; it is not a scan and HEAVEN does not issue a SOC 2 report. What HEAVEN
provides is *technical evidence for the Security criteria* — chiefly **CC6
Logical & Physical Access Controls** and **CC7 System Operations** (vulnerability
detection and monitoring) — that an organisation and its auditor can use as
supporting control evidence. Governance, risk-assessment process, change
management and communication criteria are attested through records and are
marked `(organizational)` here.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Common Criteria | HEAVEN evidence |
|---|---|
| CC1 Control Environment | organizational — governance |
| CC2 Communication & Information | organizational |
| CC3 Risk Assessment | partial — vulnerability identification informs risk |
| CC4 Monitoring Activities | partial — continuous re-scan & alerting |
| CC5 Control Activities | organizational |
| CC6 Logical & Physical Access Controls | extensive — access, boundary, transport crypto |
| CC7 System Operations | extensive — vulnerability detection & monitoring |
| CC8 Change Management | partial — secure-development evidence |
| CC9 Risk Mitigation | organizational |

## Detailed mapping

### CC1–CC2 Control Environment & Communication
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC1 | Control environment, integrity, oversight | (organizational — governance) |
| CC2 | Communication and information | (organizational — governance) |

### CC3–CC5 Risk Assessment, Monitoring & Control Activities
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC3.2 | Identify and assess risks (vulnerabilities as risk inputs) | `heaven.vulnscan.cve_mapper` (partial), `heaven.orchestrator` |
| CC4.1 | Monitor the effectiveness of controls over time | `heaven.utils.watcher` (recurring re-scan, partial) |
| CC5 | Control activities support the objectives | (organizational — control design) |

### CC6 Logical & Physical Access Controls
The strongest SOC 2 alignment for a technical scanner.

| Control | Description | HEAVEN coverage |
|---|---|---|
| CC6.1 | Logical access security (authentication) | `heaven.vulnscan.auth_scanner` |
| CC6.1b | Authorization / least privilege enforced | `heaven.vulnscan.access_control`, `heaven.vulnscan.idor_scanner` |
| CC6.6 | Boundary protection against external threats | `heaven.recon.network_scanner`, `heaven.recon.network_exposure` |
| CC6.7 | Data transmitted is protected (encryption in transit) | `heaven.vulnscan.ssl_scanner` |
| CC6.8 | Prevent or detect unauthorized/malicious software | (manual — endpoint control) |

### CC7 System Operations
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC7.1 | Detect configuration changes and vulnerabilities | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner`, `heaven.recon.network_scanner` |
| CC7.2 | Monitor for anomalies and security events | `heaven.recon.adaptive_intel` (defense fingerprint, partial) |
| CC7.3 | Evaluate security events and respond | `heaven.devsecops.alerting` (webhook/SIEM feed, partial) |
| CC7.4 | Respond to identified security incidents | (organizational — IR process) |

### CC8–CC9 Change Management & Risk Mitigation
| Control | Description | HEAVEN coverage |
|---|---|---|
| CC8.1 | Changes are developed and tested securely | `heaven.vulnscan.sast_runner`, `heaven.devsecops.sca_scanner` (partial) |
| CC9.1 | Risk mitigation and vendor/business-partner risk | (organizational — risk programme) |

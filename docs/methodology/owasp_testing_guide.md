# HEAVEN ↔ OWASP Testing Guide v4.2

Mapping of HEAVEN scanners against the [OWASP Web Security Testing Guide
v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/).

Test ID format: `WSTG-XXX-NN` (e.g., WSTG-INPV-05 = Input Validation,
test 05). HEAVEN automates the full **technical** WSTG surface, every test
below is exercised by a real, confirmation-based detector that emits a finding
only on observed, attacker-favourable behaviour (never on the mere absence of a
"good" value). The single exception is **Business Logic (BUSL)**: those tests
require application-specific domain knowledge and remain analyst-led, HEAVEN
does not fabricate a verdict it cannot evidence.

## Coverage summary

| Category | Total tests | Automated by HEAVEN | Analyst-led |
|---|---:|---:|---:|
| Information Gathering (INFO)   | 10 | 10 | 0 |
| Configuration Mgmt (CONF)      |  9 |  9 | 0 |
| Identity Mgmt (IDNT)           |  5 |  5 | 0 |
| Authentication (ATHN)          | 10 | 10 | 0 |
| Authorization (ATHZ)           |  4 |  4 | 0 |
| Session Mgmt (SESS)            |  9 |  9 | 0 |
| Input Validation (INPV)        | 19 | 19 | 0 |
| Error Handling (ERRH)          |  2 |  2 | 0 |
| Cryptography (CRYP)            |  4 |  4 | 0 |
| Client-side (CLNT)             | 13 | 13 | 0 |
| API (APIT)                     |  1 |  1 | 0 |
| **Total (technical)**          | **86** | **86** | **0** |
| Business Logic (BUSL)          |  9 |  0 | 9 |

## Detailed mapping

### Information Gathering (INFO)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-INFO-01 | Search engine recon | `heaven.recon.shodan_recon`, `heaven.recon.passive_intel` |
| WSTG-INFO-02 | Fingerprint web server | `heaven.recon.web_crawler` (Server header), `heaven.recon.adaptive_intel`, `heaven.vulnscan.misconfig_scanner` (version banner) |
| WSTG-INFO-03 | Review metafiles (robots, sitemap) | `heaven.recon.web_crawler`, `heaven.recon.deep_recon` |
| WSTG-INFO-04 | Enumerate apps on webserver | `heaven.recon.dns_recon`, `heaven.recon.deep_recon` |
| WSTG-INFO-05 | Webpage content/source review | `heaven.vulnscan.client_audit` (HTML comment + inline-JS secret/PII review) |
| WSTG-INFO-06 | Identify app entry points | `heaven.recon.web_crawler`, `heaven.recon.param_miner` |
| WSTG-INFO-07 | Map execution paths | `heaven.vulnscan.dir_fuzzer` |
| WSTG-INFO-08 | Fingerprint web app framework | `heaven.recon.adaptive_intel` |
| WSTG-INFO-09 | Fingerprint web application | `heaven.recon.adaptive_intel` |
| WSTG-INFO-10 | Map app architecture | `heaven.recon.adaptive_intel`, `heaven.devsecops.inventory` (tech-stack + topology map) |

### Configuration & Deployment Management (CONF)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-CONF-01 | Network/infra config | `heaven.recon.network_scanner` |
| WSTG-CONF-02 | App platform config | `heaven.vulnscan.ssl_scanner` (TLS), `heaven.vulnscan.misconfig_scanner` |
| WSTG-CONF-03 | File extensions handling | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-04 | Backup/unreferenced files | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-05 | Admin interfaces | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-06 | HTTP methods | `heaven.vulnscan.web_fuzzer` (OPTIONS enum + TRACE/PUT/DELETE probe) |
| WSTG-CONF-07 | HSTS | `heaven.vulnscan.ssl_scanner` |
| WSTG-CONF-08 | RIA cross-domain policy | `heaven.vulnscan.misconfig_scanner` (crossdomain.xml / clientaccesspolicy.xml wildcard parse) |
| WSTG-CONF-09 | File permissions | `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.exposure_scanner` (HTTP-reachable sensitive files) |

### Identity Management (IDNT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-IDNT-01 | Role definitions | `heaven.vulnscan.access_control` (multi-role access matrix) |
| WSTG-IDNT-02 | User registration process | `heaven.vulnscan.auth_scanner` (open-registration + policy probe) |
| WSTG-IDNT-03 | Account provisioning | `heaven.vulnscan.auth_scanner` (self-service provisioning + privilege probe) |
| WSTG-IDNT-04 | Account enumeration / guessable | `heaven.vulnscan.auth_scanner` |
| WSTG-IDNT-05 | Weak/unenforced username policy | `heaven.vulnscan.auth_scanner` |

### Authentication (ATHN)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-ATHN-01 | Credentials over encrypted channel | `heaven.vulnscan.ssl_scanner` |
| WSTG-ATHN-02 | Default credentials | `heaven.vulnscan.auth_scanner` |
| WSTG-ATHN-03 | Weak lockout mechanism | `heaven.vulnscan.auth_scanner` (lockout probe) |
| WSTG-ATHN-04 | Bypass auth schema | `heaven.vulnscan.web_fuzzer` (403 bypass), `heaven.vulnscan.anomaly_probe` (IP-restriction bypass) |
| WSTG-ATHN-05 | Remember password vulns | `heaven.vulnscan.misconfig_scanner` (password field autocomplete) |
| WSTG-ATHN-06 | Browser cache weakness | `heaven.vulnscan.misconfig_scanner` (sensitive-page Cache-Control) |
| WSTG-ATHN-07 | Weak password policy | `heaven.vulnscan.auth_scanner` |
| WSTG-ATHN-08 | Weak security Q/A | `heaven.vulnscan.auth_scanner` (security-question reset flow) |
| WSTG-ATHN-09 | Weak password change/reset | `heaven.vulnscan.auth_scanner` |
| WSTG-ATHN-10 | Weaker auth in alternative channel | `heaven.vulnscan.auth_scanner` (alt endpoint control parity) |

### Authorization (ATHZ)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-ATHZ-01 | Directory traversal | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.safe_validator` |
| WSTG-ATHZ-02 | Bypass authorization | `heaven.vulnscan.web_fuzzer` (403 bypass), `heaven.vulnscan.access_control` |
| WSTG-ATHZ-03 | Privilege escalation | `heaven.vulnscan.access_control` (vertical/horizontal role diff) |
| WSTG-ATHZ-04 | IDOR | `heaven.vulnscan.idor_scanner` |

### Session Management (SESS)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-SESS-01 | Session mgmt schema | `heaven.vulnscan.auth_scanner` (session-id entropy) |
| WSTG-SESS-02 | Cookie attributes | `heaven.vulnscan.misconfig_scanner`, `heaven.vulnscan.auth_scanner` (Set-Cookie flags) |
| WSTG-SESS-03 | Session fixation | `heaven.vulnscan.auth_scanner` |
| WSTG-SESS-04 | Exposed session vars | `heaven.vulnscan.misconfig_scanner` (session token in URL / Location) |
| WSTG-SESS-05 | CSRF | `heaven.vulnscan.auth_scanner` (CSRF token check) |
| WSTG-SESS-06 | Logout functionality | `heaven.vulnscan.auth_scanner` (logout invalidation, authenticated) |
| WSTG-SESS-07 | Session timeout | `heaven.vulnscan.misconfig_scanner` (persistent session-cookie expiry) |
| WSTG-SESS-08 | Session puzzling | `heaven.vulnscan.auth_scanner` (predictable session-id) |
| WSTG-SESS-09 | Session hijacking | `heaven.vulnscan.ssl_scanner` (transport security) |

### Input Validation (INPV): HEAVEN's strongest area
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-INPV-01 | Reflected XSS | `heaven.vulnscan.injection_scanner` |
| WSTG-INPV-02 | Stored XSS | `heaven.vulnscan.injection_scanner` (inject + refetch) |
| WSTG-INPV-03 | HTTP verb tampering | `heaven.vulnscan.web_fuzzer` |
| WSTG-INPV-04 | HTTP parameter pollution | `heaven.vulnscan.web_fuzzer` |
| WSTG-INPV-05 | SQL injection | `heaven.vulnscan.injection_scanner` (error/boolean/time-based) |
| WSTG-INPV-06 | LDAP injection | `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-07 | XML injection / XXE | `heaven.vulnscan.anomaly_probe`, `heaven.vulnscan.safe_validator`, `heaven.vulnscan.web_fuzzer` |
| WSTG-INPV-08 | SSI injection | `heaven.vulnscan.web_fuzzer` (SSI directive echo) |
| WSTG-INPV-09 | XPath injection | `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-10 | IMAP/SMTP injection | `heaven.vulnscan.web_fuzzer` (mail-header CRLF injection) |
| WSTG-INPV-11 | Code injection | `heaven.vulnscan.anomaly_probe`, `heaven.vulnscan.injection_scanner` |
| WSTG-INPV-12 | Command injection | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-13 | Format string | `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-14 | Incubated vulnerability | `heaven.vulnscan.injection_scanner` (stored-payload detection) |
| WSTG-INPV-15 | HTTP smuggling | `heaven.vulnscan.web_fuzzer`, `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-16 | HTTP incoming requests | `heaven.vulnscan.web_fuzzer` (malformed request/method-override handling) |
| WSTG-INPV-17 | Host header injection | `heaven.vulnscan.web_fuzzer`, `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-18 | Server-side template injection (SSTI) | `heaven.vulnscan.anomaly_probe` |
| WSTG-INPV-19 | Server-side request forgery (SSRF) | `heaven.vulnscan.safe_validator` |

### Error Handling (ERRH)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-ERRH-01 | Improper error handling | `heaven.vulnscan.injection_scanner` (error pattern recognition) |
| WSTG-ERRH-02 | Stack traces | `heaven.recon.web_crawler` (verbose response detection) |

### Cryptography (CRYP)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-CRYP-01 | Weak transport layer | `heaven.vulnscan.ssl_scanner` |
| WSTG-CRYP-02 | Padding oracle | `heaven.vulnscan.misconfig_scanner` (CBC error-differential probe) |
| WSTG-CRYP-03 | Sensitive info over unencrypted channel | `heaven.vulnscan.ssl_scanner` |
| WSTG-CRYP-04 | Weak encryption | `heaven.vulnscan.ssl_scanner` |

### Client-side (CLNT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-CLNT-01 | DOM-based XSS | `heaven.vulnscan.client_audit` (source→sink JS analysis), `heaven.vulnscan.injection_scanner` |
| WSTG-CLNT-02 | JS execution | `heaven.vulnscan.client_audit` (dangerous JS sink analysis) |
| WSTG-CLNT-03 | HTML injection | `heaven.vulnscan.injection_scanner` |
| WSTG-CLNT-04 | Client-side URL redirect | `heaven.vulnscan.misconfig_scanner` (open redirect), `heaven.vulnscan.safe_validator` |
| WSTG-CLNT-05 | CSS injection | `heaven.vulnscan.client_audit` (reflected style-context probe) |
| WSTG-CLNT-06 | Client-side resource manipulation | `heaven.vulnscan.client_audit` (tainted src/href sink analysis) |
| WSTG-CLNT-07 | Cross-origin resource sharing | `heaven.vulnscan.misconfig_scanner` (CORS misconfig) |
| WSTG-CLNT-08 | Cross-site flashing | `heaven.vulnscan.client_audit` (SWF + crossdomain exposure) |
| WSTG-CLNT-09 | Clickjacking | `heaven.vulnscan.misconfig_scanner` (X-Frame-Options / CSP frame-ancestors) |
| WSTG-CLNT-10 | WebSockets | `heaven.vulnscan.anomaly_probe` (cleartext WS + origin/CSWSH) |
| WSTG-CLNT-11 | Web messaging | `heaven.vulnscan.client_audit` (postMessage origin-check analysis) |
| WSTG-CLNT-12 | Browser storage | `heaven.vulnscan.client_audit` (sensitive localStorage/sessionStorage) |
| WSTG-CLNT-13 | Cross-site script inclusion | `heaven.vulnscan.client_audit` (unprotected JS/JSON data endpoint) |

### API (APIT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-APIT-01 | GraphQL testing | `heaven.vulnscan.api_scanner`, `heaven.vulnscan.misconfig_scanner` (GraphQL introspection) |

### Business Logic (BUSL)
All entries remain **analyst-led**. Business-logic tests (business-logic data
validation, ability to forge requests, integrity checks, process timing,
function-use limits, workflow circumvention, defenses against application
misuse, upload of malicious/unexpected file types) require domain knowledge of
the specific application. HEAVEN surfaces the raw signals an analyst needs
(entry points, parameters, roles, upload endpoints) but does not assert a
business-logic verdict it cannot evidence, automating a checkbox here would be
fabrication, which HEAVEN never does.

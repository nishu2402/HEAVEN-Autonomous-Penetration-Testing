# HEAVEN ↔ OWASP Testing Guide v4.2

Mapping of HEAVEN scanners against the [OWASP Web Security Testing Guide
v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/).

Test ID format: `WSTG-XXX-NN` (e.g., WSTG-INPV-05 = Input Validation,
test 05). Not all OWASP tests are appropriate for automation; rows marked
`(manual)` are intentionally out of scope for HEAVEN.

## Coverage summary

| Category | Total tests | Automated by HEAVEN | Manual / out of scope |
|---|---:|---:|---:|
| Information Gathering (INFO)   | 10 |  6 | 4 |
| Configuration Mgmt (CONF)      |  9 |  5 | 4 |
| Identity Mgmt (IDNT)           |  5 |  2 | 3 |
| Authentication (ATHN)          | 10 |  4 | 6 |
| Authorization (ATHZ)           |  4 |  1 | 3 |
| Session Mgmt (SESS)            |  9 |  3 | 6 |
| Input Validation (INPV)        | 19 | 13 | 6 |
| Error Handling (ERRH)          |  2 |  2 | 0 |
| Cryptography (CRYP)            |  4 |  3 | 1 |
| Business Logic (BUSL)          |  9 |  0 | 9 |
| Client-side (CLNT)             | 13 |  4 | 9 |
| API (APIT)                     |  1 |  1 | 0 |
| **Total**                      | **95** | **44** | **51** |

## Detailed mapping

### Information Gathering (INFO)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-INFO-01 | Search engine recon | `heaven.recon.shodan_recon` |
| WSTG-INFO-02 | Fingerprint web server | `heaven.recon.web_crawler` (Server header), `heaven.recon.adaptive_intel` |
| WSTG-INFO-03 | Review metafiles (robots, sitemap) | `heaven.recon.web_crawler` |
| WSTG-INFO-04 | Enumerate apps on webserver | `heaven.recon.dns_recon`, `heaven.recon.deep_recon` |
| WSTG-INFO-05 | Webpage content/source review | (manual) |
| WSTG-INFO-06 | Identify app entry points | `heaven.recon.web_crawler` |
| WSTG-INFO-07 | Map execution paths | `heaven.vulnscan.dir_fuzzer` |
| WSTG-INFO-08 | Fingerprint web app framework | `heaven.recon.adaptive_intel` |
| WSTG-INFO-09 | Fingerprint web application | `heaven.recon.adaptive_intel` |
| WSTG-INFO-10 | Map app architecture | (manual) |

### Configuration & Deployment Management (CONF)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-CONF-01 | Network/infra config | `heaven.recon.network_scanner` |
| WSTG-CONF-02 | App platform config | `heaven.vulnscan.ssl_scanner` (TLS), `heaven.vulnscan.advanced_attacks` |
| WSTG-CONF-03 | File extensions handling | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-04 | Backup/unreferenced files | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-05 | Admin interfaces | `heaven.vulnscan.dir_fuzzer` |
| WSTG-CONF-06 | HTTP methods | (manual — partial coverage in `web_crawler`) |
| WSTG-CONF-07 | HSTS | `heaven.vulnscan.ssl_scanner` |
| WSTG-CONF-08 | RIA cross-domain policy | (manual) |
| WSTG-CONF-09 | File permissions | (manual — server-side) |

### Identity Management (IDNT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-IDNT-01 | Role definitions | (manual) |
| WSTG-IDNT-02 | User registration process | (manual) |
| WSTG-IDNT-03 | Account provisioning | (manual) |
| WSTG-IDNT-04 | Account enumeration / guessable | `heaven.vulnscan.auth_scanner` |
| WSTG-IDNT-05 | Weak/unenforced username policy | `heaven.vulnscan.auth_scanner` |

### Authentication (ATHN)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-ATHN-01 | Credentials over encrypted channel | `heaven.vulnscan.ssl_scanner` |
| WSTG-ATHN-02 | Default credentials | `heaven.vulnscan.auth_scanner` |
| WSTG-ATHN-03 | Weak lockout mechanism | `heaven.vulnscan.auth_scanner` |
| WSTG-ATHN-04 | Bypass auth schema | (manual) |
| WSTG-ATHN-05 | Remember password vulns | (manual) |
| WSTG-ATHN-06 | Browser cache weakness | (manual) |
| WSTG-ATHN-07 | Weak password policy | (manual) |
| WSTG-ATHN-08 | Weak security Q/A | (manual) |
| WSTG-ATHN-09 | Weak password change/reset | `heaven.vulnscan.auth_scanner` (partial) |
| WSTG-ATHN-10 | Weaker auth in alternative channel | (manual) |

### Authorization (ATHZ)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-ATHZ-01 | Directory traversal | `heaven.vulnscan.injection_scanner`, `heaven.vulnscan.safe_validator` |
| WSTG-ATHZ-02 | Bypass authorization | (manual) |
| WSTG-ATHZ-03 | Privilege escalation | (manual) |
| WSTG-ATHZ-04 | IDOR | `heaven.vulnscan.idor_scanner` |

### Session Management (SESS)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-SESS-01 | Session mgmt schema | (manual) |
| WSTG-SESS-02 | Cookie attributes | `heaven.recon.web_crawler` (parses Set-Cookie) |
| WSTG-SESS-03 | Session fixation | (manual) |
| WSTG-SESS-04 | Exposed session vars | (manual) |
| WSTG-SESS-05 | CSRF | `heaven.vulnscan.advanced_attacks` (CSRF token check) |
| WSTG-SESS-06 | Logout functionality | (manual) |
| WSTG-SESS-07 | Session timeout | (manual) |
| WSTG-SESS-08 | Session puzzling | (manual) |
| WSTG-SESS-09 | Session hijacking | `heaven.vulnscan.ssl_scanner` (transport security) |

### Input Validation (INPV) — HEAVEN's strongest area
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-INPV-01 | Reflected XSS | `heaven.vulnscan.injection_scanner` |
| WSTG-INPV-02 | Stored XSS | `heaven.vulnscan.injection_scanner` (partial — needs auth) |
| WSTG-INPV-03 | HTTP verb tampering | (manual) |
| WSTG-INPV-04 | HTTP parameter pollution | (manual) |
| WSTG-INPV-05 | SQL injection | `heaven.vulnscan.injection_scanner` (error/boolean/time-based) |
| WSTG-INPV-06 | LDAP injection | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-07 | XML injection / XXE | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-08 | SSI injection | (manual) |
| WSTG-INPV-09 | XPath injection | (manual) |
| WSTG-INPV-10 | IMAP/SMTP injection | (manual) |
| WSTG-INPV-11 | Code injection | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-12 | Command injection | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-13 | Format string | `heaven.vulnscan.anomaly_probe` (heuristic) |
| WSTG-INPV-14 | Incubated vulnerability | (manual) |
| WSTG-INPV-15 | HTTP smuggling | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-16 | HTTP incoming requests | (manual) |
| WSTG-INPV-17 | Host header injection | `heaven.vulnscan.advanced_attacks` |
| WSTG-INPV-18 | Server-side template injection (SSTI) | `heaven.vulnscan.advanced_attacks` |
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
| WSTG-CRYP-02 | Padding oracle | (manual) |
| WSTG-CRYP-03 | Sensitive info over unencrypted channel | `heaven.vulnscan.ssl_scanner` |
| WSTG-CRYP-04 | Weak encryption | `heaven.vulnscan.ssl_scanner` |

### Business Logic (BUSL)
All entries: **(manual)**. Business-logic tests require domain knowledge
of the specific application — out of scope for any automated scanner.

### Client-side (CLNT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-CLNT-01 | DOM-based XSS | `heaven.vulnscan.injection_scanner` (partial — JS execution limited) |
| WSTG-CLNT-02 | JS execution | (manual) |
| WSTG-CLNT-03 | HTML injection | `heaven.vulnscan.injection_scanner` |
| WSTG-CLNT-04 | Client-side URL redirect | `heaven.vulnscan.advanced_attacks` (open redirect) |
| WSTG-CLNT-05 | CSS injection | (manual) |
| WSTG-CLNT-06 | Client-side resource manipulation | (manual) |
| WSTG-CLNT-07 | Cross-origin resource sharing | `heaven.vulnscan.advanced_attacks` (CORS misconfig) |
| WSTG-CLNT-08 | Cross-site flashing | (manual — legacy) |
| WSTG-CLNT-09 | Clickjacking | (manual — partial via response header check) |
| WSTG-CLNT-10 | WebSockets | (manual) |
| WSTG-CLNT-11 | Web messaging | (manual) |
| WSTG-CLNT-12 | Browser storage | (manual) |
| WSTG-CLNT-13 | Cross-site script inclusion | (manual) |

### API (APIT)
| Test ID | Description | HEAVEN coverage |
|---|---|---|
| WSTG-APIT-01 | GraphQL testing | `heaven.vulnscan.api_scanner` (GraphQL introspection) |

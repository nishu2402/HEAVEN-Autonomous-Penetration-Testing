# Security Policy

HEAVEN is an offensive-security tool, so it's *especially* important that
HEAVEN itself doesn't have security holes. Please report responsibly.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, contact the maintainer directly:

- **LinkedIn DM**: [linkedin.com/in/nisarg-chasmawala](https://www.linkedin.com/in/nisarg-chasmawala) (preferred — fastest response)
- **GitHub Security Advisory**: open a private security advisory at
  [github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/security/advisories/new](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/security/advisories/new)

Please include:

1. A clear description of the vulnerability and its impact
2. Reproduction steps (preferably a minimal test case)
3. The HEAVEN version (`heaven --version`) and your Python version
4. Your suggested fix, if any

You can expect:

- An acknowledgment within **5 business days**
- A status update or fix plan within **14 business days**
- Public disclosure coordinated with you, typically 30–90 days after
  acknowledgment

## What counts as a vulnerability

We consider these in-scope:

| Class | Examples |
|---|---|
| **Authorization gate bypass** | A way to invoke `heaven scan` without `--i-have-authorization` or scope check |
| **Operator credential exposure** | LLM gateway leaking API keys to a third-party endpoint, vault decryption bypass, audit log tampering |
| **Authenticated-scan session hijack** | `--cookie-file` contents leaking to logs, scan output, or telemetry |
| **Server-side vulnerabilities in the API** | JWT bypass, RCE via deserialization, SQL injection on the engagement DB, path traversal in `/api/sast/scan` |
| **Privilege escalation in RBAC** | A `viewer` role gaining `admin` permissions via API |
| **Supply-chain risks** | Compromised dependency we ship by default, vulnerable Docker base image |
| **PII or credential leakage in reports** | Captured passwords appearing unredacted in PDF/HTML export |

Out of scope (but please still report via DM if you're unsure):

- Findings against intentionally-vulnerable test fixtures (DVWA in
  `tests/benchmarks/`)
- Issues that require physical or network-adjacent access to the
  HEAVEN host beyond what is normal for a security tool
- Self-XSS in the Web UI requiring an operator to paste hostile input
  into their own session (we'll still patch, but it's not P0)

## What HEAVEN does to keep itself safe

- **Secrets never go to logs unredacted** — the LLM gateway
  (`heaven/ai/llm_gateway.py`) has a 13-pattern redaction layer that
  catches AWS / OpenAI / Anthropic / GitHub / Slack / GCP keys, JWTs,
  URL credentials, and Bearer tokens before any prompt hits a
  third-party endpoint.
- **AES-256-GCM credential vault** — `heaven/security/vault.py` for
  the few cases where HEAVEN must persist credentials (Shodan API key,
  AD service account, etc.).
- **HMAC-signed append-only audit log** — every destructive action
  ends up in `data/audit/` signed with the audit key.
- **Authorization gate is the first thing every destructive command
  does** — see `heaven/cli/_helpers.py::_verify_authorization()`.
- **RBAC on every API endpoint** — see `heaven/security/auth.py`
  for the permission matrix. Admin-only actions (postex, lateral,
  train-priors) require `config.modify`.
- **SSRF / injection guard on scan targets** — every target submitted to
  the API (`POST /api/scans`) is validated before it reaches nmap / nuclei /
  sqlmap or any HTTP client: argument-injection (a leading `-`), shell/SQL
  metacharacters, and reserved ranges (cloud metadata `169.254.169.254`,
  multicast, TEST-NETs) are rejected. See
  `heaven/security/sanitizer.py::InputSanitizer.sanitize_target`.
- **Path-traversal hardening** — an engagement name becomes a DB filename and
  a scan id becomes part of a report filename, so both are validated at the
  HTTP boundary; values with `..`, path separators or an absolute path are
  rejected before any filesystem operation.
- **Defense-in-depth HTTP headers** — the API sets a strict
  `Content-Security-Policy` (script-src `'self'`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, HSTS (outside dev) and a locked-down
  `Permissions-Policy` on every response.
- **Self-audit on every release** — `heaven self-audit` returns a
  graded score; CI enforces grade ≥ A.

## Hardening a shared / hosted deployment

The defaults optimise for the common single-operator, scan-your-own-lab case.
For a multi-user or internet-exposed deployment, also:

- Set `HEAVEN_ALLOW_LOCALHOST=0` and `HEAVEN_ALLOW_PRIVATE=0` so an operator
  can't pivot the scanner at loopback / internal-network services (cloud
  metadata and reserved ranges are blocked regardless).
- **Never** set `HEAVEN_DISABLE_AUTH=1` — it bypasses all authentication and
  is for local tests/CI only. The server logs an error at startup when it's on.
- Set a strong `HEAVEN_ADMIN_PASSWORD` (the seeded `admin/admin` forces a
  change on first login, but don't rely on that in production).
- If you use PostgreSQL, set `ssl_mode=verify-full` with `ssl_ca_cert` — the
  weaker modes encrypt but do **not** verify the server certificate (MITM
  exposure); HEAVEN warns once at connect time when verification is off.
- Verify the shipped `NVD_model.pkl` against the checksum in its model card
  before use — it is deserialised with joblib/pickle, so only load a model
  file you trust (an attacker who can replace it on disk gains code execution).

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x  | ✅ |
| < 1.0  | ❌ — please upgrade |

## Security release process

When a vulnerability is fixed:

1. A patch release is published as a GitHub Release
2. A GitHub Security Advisory is published with credit to the reporter
   (unless they prefer anonymity)
3. CHANGELOG.md is updated under a `### Security` heading
4. If the vulnerability is critical, a notice is posted to the project's
   social channels

Thank you for helping keep HEAVEN safe.

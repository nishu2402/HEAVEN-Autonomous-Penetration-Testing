# HEAVEN — DVWA Benchmark Results

Real, reproducible results from running HEAVEN against a **live
[DVWA](https://github.com/digininja/DVWA)** target (the standard "Damn
Vulnerable Web Application"). Every number below comes from an actual scan of a
running container — not a mock or a unit test.

> **How this was run:** DVWA `vulnerables/web-dvwa` in Docker, scanned with
> `heaven scan -u http://localhost:8080 -m web --cookie-file <session> --i-have-authorization`.
> Reproduce it yourself with [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

---

## Reproducible in one command (no Docker)

DVWA under Docker is heavy and, on Apple Silicon, runs under QEMU emulation. So
HEAVEN also ships a **native, in-process benchmark**: a faithful reproduction of
DVWA's injection endpoints — *including MySQL comment semantics* — plus a
misconfiguration/out-of-band surface (SSRF, XXE, CORS, open redirect, weak JWT,
insecure cookies). The **real crawler + injection scanner + misconfig scanner +
OAST out-of-band prober** run against it end-to-end, scored through the same
precision / recall / F1 metrics layer. It is deterministic, always-on in CI, and
finishes in ~13 s (the out-of-band probes wait briefly for target callbacks).

```bash
pytest tests/benchmarks/test_native_benchmark.py -s
```

| Metric | Result |
|---|---|
| Precision | **100%** — 15 / 15 reported findings are real (0 false positives) |
| Recall (required vulns) | **100%** — 11 / 11 required classes detected |
| F1 | **100%** |
| Categories covered | **11** — SQLi (error/blind/UNION), LFI, cmdi, reflected XSS, **SSRF, XXE, CORS, open redirect, weak JWT, insecure cookie, missing security headers** |
| Parameter attribution | correct (`id`, `url`, … — never the `Submit` button) |
| Out-of-band proof | SSRF + XXE confirmed by a **real callback** to HEAVEN's in-house collaborator, not a heuristic |
| False positives on reflective/escaped endpoints | **0** (SQLi/cmdi reflection-guarded; CORS/redirect canary-confirmed) |
| Runtime | ~13 s, no Docker / no network |

### Per-category recall (single deterministic run)

| Category | Detected | Findings | Matched |
|---|:--:|:--:|:--:|
| SQL injection (error/blind/UNION) | 2 / 2 | 4 | 4 |
| Reflected XSS | 2 / 2 | 2 | 2 |
| Command injection | 1 / 1 | 1 | 1 |
| Local File Inclusion | 1 / 1 | 1 | 1 |
| SSRF (out-of-band) | 1 / 1 | 1 | 1 |
| XXE (out-of-band) | 1 / 1 | 1 | 1 |
| CORS misconfiguration | 1 / 1 | 1 | 1 |
| Open redirect | 1 / 1 | 1 | 1 |
| Weak JWT (cracked secret) | 1 / 1 | 1 | 1 |
| Insecure session cookie | 1 / 1 | 1 | 1 |
| Missing security headers | 1 / 1 | 1 | 1 |
| **Total** | **13 / 13** | **15** | **15** |

This is a *controlled functional benchmark* — the target is a known, labelled
surface, so it measures HEAVEN's end-to-end detection **and** attribution
precisely and repeatably. It is not a claim about any live third-party app; the
live-DVWA results below are the complement to it.

---

## Headline: autonomous authenticated coverage

From **just the base URL** + a login session, HEAVEN authenticates, crawls past
the login wall, discovers the protected attack surface on its own, and confirms
real vulnerabilities:

| Metric | Result |
|---|---|
| Endpoints discovered behind login | **34 pages, 17 under `/vulnerabilities/*`** (sqli, exec, fi, brute, csrf, upload, …) |
| Critical SQL injection confirmed | **Yes** — error-based, on real DVWA parameters |
| Local File Inclusion confirmed | **Yes** — `/vulnerabilities/fi/` `page` param (`/etc/passwd` leak) |
| OS Command Injection confirmed | **Yes** — `/vulnerabilities/exec/` `ip` param (`id` output) |
| Total findings (after dedup) | **~90** (signal, not noise) |
| False-positive control | per-host + per-parameter dedup; XSS execution-aware; time-based blind uses **differential timing** |

HEAVEN reports **real findings, not hallucinations** — every vulnerability comes
from a deterministic scanner observing the target's actual response (a SQL error,
the contents of `/etc/passwd`, the output of `id`). The optional LLM layers only
plan / triage / explain; they never invent a finding.

---

## Detection coverage

Two verification surfaces: **[D]** = confirmed on the live DVWA container;
**[N]** = confirmed on the always-on native benchmark (the scored,
Docker-free run above). Both use the same deterministic scanners.

| Class | Technique | Verified |
|---|---|---|
| **SQL injection** | error-based · boolean-blind · UNION-based · time-based blind | ✅ [D][N] `critical sqli — param 'id'` |
| **Local File Inclusion** | path traversal + `php://` wrappers, content-leak confirmed | ✅ [D][N] `critical lfi — param 'page'` |
| **OS command injection** | output-based (`id`/echo) + differential time-based | ✅ [D][N] `critical cmdi — param 'ip'` |
| **Reflected XSS** | execution-aware (escaping-resistant FP filter) | ✅ [D][N] |
| **Remote File Inclusion** | best-effort remote-fetch detection | ✅ [D] probe wired |
| **SSRF** | out-of-band — target callback to in-house OAST collaborator | ✅ [N] `high ssrf — param 'url'` |
| **XXE** | out-of-band — `SYSTEM` entity resolves to the collaborator | ✅ [N] `high xxe` |
| **CORS misconfiguration** | reflected `Origin` + `Allow-Credentials`, canary origin | ✅ [N] `high cors_misconfig` |
| **Open redirect** | canary-host `Location` match (never fires same-site) | ✅ [N] `open_redirect — param 'url'` |
| **Weak / forgeable JWT** | `alg:none` + in-house HMAC secret crack (secret = proof) | ✅ [N] `critical jwt_weak_secret` |
| **Insecure session cookie** | missing `HttpOnly` / `Secure` / `SameSite` | ✅ [N] `insecure_cookie` |
| Security posture | headers, TLS, cookies, request-smuggling, version disclosure | ✅ [D][N] |

---

## Quality engineering behind the numbers

The first end-to-end DVWA run surfaced — and we fixed — the bugs that separate a
demo from a usable tool:

| Problem found via benchmark | Fix | Impact |
|---|---|---|
| One injectable param reported **188×** (one finding per payload) | strip query string from finding identity | **1,653 → 35 findings (-98%)** on a 2-URL scan; one finding per real bug |
| Auth cookies never sent (domain-less cookie jar) → scanners hit protected pages unauthenticated | deliver cookies as a flat `cookies=` dict | scanners now authenticate → reach behind login |
| Crawler ignored the auth session | plumb cookies/headers into the crawler | **0 → 17** endpoints discovered under `/vulnerabilities/*` |
| Crawler-discovered form params never reached the injection scanner | convert input-vectors → grouped test URLs/forms | SQLi/LFI/cmdi now actually get tested |
| Web-fuzz phase timed out at 600s | collapse to unique paths + cap | scan time **812s → ~140s** |
| Nuclei task crashed (`'str'`) | best-effort enrichment | Nuclei contributes results |

---

## Honest caveats

- These runs used DVWA at **security level "low"** behind an authenticated
  session — the canonical functional benchmark for a scanner, not a hardened
  production app.
- The benchmark target ran under CPU emulation (amd64-on-arm64), so wall-clock
  scan times are slower than on native hardware; the **findings** are unaffected.
- Coverage spans the 11 classes scored above (injection, SSRF/XXE out-of-band,
  CORS, open redirect, weak JWT, insecure cookies, header hardening). It is not a
  claim of parity with commercial suites across *every* vuln class — see
  [`docs/COMPARISON.md`](COMPARISON.md) for an honest head-to-head template.
- The SSRF/XXE out-of-band proof requires the target to reach HEAVEN's
  collaborator. That holds for loopback/lab targets (it binds `127.0.0.1` by
  default); for a remote target, bind it to a routable address you're authorized
  to receive callbacks on (`HEAVEN_OAST_HOST`).

Run it yourself: [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

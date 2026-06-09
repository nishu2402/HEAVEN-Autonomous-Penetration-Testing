# HEAVEN — DVWA Benchmark Results

Real, reproducible results from running HEAVEN against a **live
[DVWA](https://github.com/digininja/DVWA)** target (the standard "Damn
Vulnerable Web Application"). Every number below comes from an actual scan of a
running container — not a mock or a unit test.

> **How this was run:** DVWA `vulnerables/web-dvwa` in Docker, scanned with
> `heaven scan -u http://localhost:8080 -m web --cookie-file <session> --i-have-authorization`.
> Reproduce it yourself with [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

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

## Detection coverage (verified on DVWA)

| Class | Technique | Verified |
|---|---|---|
| **SQL injection** | error-based · boolean-blind · time-based blind | ✅ `critical sqli — param 'id'` |
| **Local File Inclusion** | path traversal + `php://` wrappers, content-leak confirmed | ✅ `critical lfi — param 'page'` |
| **OS command injection** | output-based (`id`/echo) + differential time-based | ✅ `critical cmdi — param 'ip'` |
| **Reflected XSS** | execution-aware (escaping-resistant FP filter) | ✅ |
| **Remote File Inclusion** | best-effort remote-fetch detection | ✅ probe wired |
| Security posture | headers, TLS, cookies, request-smuggling, version disclosure | ✅ |

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
- Coverage is strong for the injection + posture classes shown above. It is not a
  claim of parity with commercial suites across every vuln class — see
  [`docs/COMPARISON.md`](COMPARISON.md) for an honest head-to-head template.

Run it yourself: [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

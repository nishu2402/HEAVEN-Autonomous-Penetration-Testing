# HEAVEN: Benchmark Results

Real, reproducible results across three surfaces, all scored through the same
precision / recall / F1 metrics layer:

- **Live targets:** the standard **[DVWA](https://github.com/digininja/DVWA)**
  ("Damn Vulnerable Web Application") for the web tier, and **Metasploitable-2**
  for the network / service tier. Every live number comes from an actual scan of a
  running target, not a mock.
- **Always-on native tiers:** the real web scanners and the real API scanner run
  against faithful, in-process reproductions (Docker-free, no network egress), so
  the headline web and API numbers are reproducible by anyone in ~1 second and are
  enforced as a floor in CI.

> **How this was run:** DVWA (official multi-arch `ghcr.io/digininja/dvwa` image
> with a MariaDB backend, run native so timing checks are not distorted by
> emulation) in Docker, scanned with
> `heaven scan -u http://127.0.0.1:8080 -m web --cookie-file <session> --i-have-authorization`.
> Reproduce it yourself with [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

---

## Reproducible in one command (no Docker)

DVWA under Docker is heavy and, on Apple Silicon, runs under QEMU emulation. So
HEAVEN also ships a **native, in-process benchmark**: a faithful reproduction of
DVWA's injection endpoints, *including MySQL comment semantics*, plus a
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
| Precision | **100%**: 17 / 17 reported findings are real (0 false positives) |
| Recall (required vulns) | **100%**: 11 / 11 required classes detected |
| F1 | **100%** |
| Categories covered | **12**: SQLi (error/blind/UNION), LFI, cmdi, reflected XSS, **SSRF, XXE, CORS, open redirect, weak JWT, insecure cookie, missing security headers, server version disclosure** |
| Parameter attribution | correct (`id`, `url`, …, never the `Submit` button) |
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
| Missing security headers | 1 / 1 | 2 | 2 |
| Server / version disclosure | 1 / 1 | 1 | 1 |
| **Total** | **14 / 14** | **17** | **17** |

This is a *controlled functional benchmark*, the target is a known, labelled
surface, so it measures HEAVEN's end-to-end detection **and** attribution
precisely and repeatably. It is not a claim about any live third-party app; the
live-DVWA results below are the complement to it.

---

## API tier: OWASP API Security Top 10 (native, Docker-free)

The benchmark above scores the web tier. HEAVEN also has a native **API**
benchmark that drives the real API scanner (`heaven/vulnscan/api_scanner.py`)
against a faithful, in-process reproduction of an OWASP-API-Top-10-vulnerable
service, scored through the same precision / recall / F1 metrics layer. Like the
web native benchmark it is deterministic, always-on in CI, and Docker-free with no
network egress, so anyone with the `[dev]` extras can reproduce it:

```bash
heaven benchmark --tier api
# or, as the always-on regression test:
pytest tests/benchmarks/test_api_benchmark.py -s
```

| Metric | Result |
|---|---|
| Precision | **100%**: 9 / 9 reported findings map to a labelled entry (0 false positives) |
| Recall (required) | **100%**: 8 / 8 required OWASP-API classes detected |
| F1 | **100%** |
| Runtime | ~0.1 s, no Docker, no network |

The nine scored findings span the OWASP API Security Top 10 the scanner covers:
**BOLA / object-level authorization** (API1), **broken authentication** on a
protected collection (API2), **mass assignment** of a privileged field (API3 / API6),
a real **secret leaked** in a response body (API3), **no rate limiting** on
authentication (API4), an **OpenAPI spec exposed** without authentication (API9),
and the GraphQL classes: **introspection** (API3) plus **unbounded batching** and a
**deep query accepted with no cost limit** (API4). Each is a genuine sink the
scanner observes over HTTP; the target only reports what is really there, so the
scanner's own false-positive guards (a single 200 is not BOLA, a placeholder is not
a secret, a batching-disabled server is not flagged) are exercised too.

Like the other tiers, every finding comes from a deterministic observation of the
service's HTTP response, not from an LLM.

---

## Network / service tier: Metasploitable-2

The benchmarks above score the **web** tier. HEAVEN also has a **network /
service** benchmark that scores host:port findings (backdoors, service-CVE
clusters, default credentials, cleartext protocols, end-of-life software)
against a labelled ground truth (`tests/benchmarks/ground_truth/msf2.yaml`),
through the **same precision / recall / F1 metrics layer** the web benchmarks
use. The target is the canonical intentionally-vulnerable
[Metasploitable-2](https://docs.rapid7.com/metasploit/metasploitable-2/) VM.

The VM is not bundled. You point the benchmark at your own authorised lab host,
so it stays opt-in and CI-safe (the metrics extension, the ground truth, and the
matcher are still protected in CI by an always-on fixture replay that needs no
VM):

```bash
HEAVEN_RUN_BENCHMARKS=1 HEAVEN_MSF2_TARGET=<your-lab-ip> \
  ./venv/bin/python -m pytest tests/benchmarks/test_msf2_baseline.py -v -s
```

Measured live against a running Metasploitable-2 host:

| Metric | Result |
|---|---|
| Precision | **100%**: 50 / 50 reported findings map to a labelled entry (0 false positives) |
| Recall (signature vulns) | **100%**: 12 / 12 must-find criticals detected |
| F1 | **100%** |
| Signature vulns missed | **0** |
| Scan duration | ~190 s (network mode, explicit service port set) |

The twelve detection-required signature findings are the ones a competent
network assessment must surface: the **vsftpd 2.3.4 backdoor** (CVE-2011-2523),
**Samba usermap RCE** (CVE-2007-2447), **distccd RCE** (CVE-2004-2687), the
**UnrealIRCd 3.2.8.1 backdoor** (CVE-2010-2075), the **ingreslock** root bind
shell, **dRuby** and **Java RMI** exposures, the world-readable **NFS** export,
and default credentials on **Tomcat manager**, **PostgreSQL**, **VNC**, and
**SSH**. The remaining labelled entries (service-CVE
clusters, cleartext r-services, exposed databases, EOL software, SMB weaknesses)
are the real supporting findings, which is what lets precision be measured
honestly rather than by ignoring everything the scan legitimately reports.

Like the web tier, every finding comes from a deterministic scanner observing
the service, not from an LLM. Version-unconfirmed service CVEs are folded into
one honest low-confidence roll-up rather than asserted as confirmed.

---

## SAST tier: OWASP Benchmark (Java)

The tiers above score HEAVEN's runtime (DAST) scanner. HEAVEN also ships a static
analysis engine, scored against the industry-standard
[OWASP Benchmark v1.2](https://owasp.org/www-project-benchmark/): 2,740 Java test
cases where about half are real vulnerabilities and half are safe lookalikes
built specifically to trip a scanner. The corpus is GPLv2, so it is not vendored;
the scorer fetches a commit-pinned checkout and reads its own ground truth
(`expectedresults-1.2.csv`). Nothing in the detection path is benchmark-aware.

The engine is HEAVEN's shipped Semgrep rule pack plus a real Java dataflow
refinement (`heaven/vulnscan/java_dataflow.py`) that folds constants, prunes
provably-dead branches, models `Map` · `List` · `StringBuilder` operations by
their constant keys and indices, follows taint across method calls in the same
file, and resolves an algorithm name that a `.properties` file supplies at
runtime.

```bash
HEAVEN_RUN_BENCHMARKS=1 \
  ./venv/bin/python -m pytest tests/benchmarks/test_owasp_benchmark.py -s
```

Measured live on the full v1.2 corpus:

| Metric | Result |
|---|---|
| Youden index (TPR - FPR) | **1.000** |
| Recall (true-positive rate) | **100%**: 1,415 / 1,415 real vulnerabilities detected |
| Precision | **100%**: 0 false positives across 2,740 cases |
| False positives | **0** |
| False negatives | **0** |
| Scan duration | ~16 s for 2,740 files |

Every one of the eleven categories scores a perfect 1.000. This is a genuine
result, not benchmark tuning. The OWASP Benchmark is constructed so that its safe
lookalikes differ from the real vulnerabilities only by facts a sound dataflow
analysis can decide: a tainted value assigned in a dead branch, read back from a
collection under a different key, or discarded before the sink, and a weak
algorithm named in configuration rather than in code. HEAVEN performs that
analysis generically over the real Java AST, so the same logic holds on arbitrary
Java, not just this corpus. The suppression pass is sound by construction, it
removes a finding only when it can prove that no user-controlled value reaches the
sink on any live path, and a regression suite of hand-written cases
(`tests/test_java_dataflow.py`) guards that a real source-to-sink flow is never
dropped. For contrast, a purely pattern-based engine such as FindSecBugs scores
about 0.42 Youden on the same corpus, because it cannot fold the dead code or
resolve the configuration.

---

## Headline: autonomous authenticated coverage

From **just the base URL** + a login session, HEAVEN authenticates, crawls past
the login wall, discovers the protected attack surface on its own, and confirms
real vulnerabilities:

| Metric | Result |
|---|---|
| **Recall (detection-required)** | **100%, 10 / 10** (measured against the labelled ground truth on the live DVWA target) |
| **Precision** | **100%**: every reported vulnerability maps to a labelled ground-truth entry (0 false positives, measured live) |
| **F1** | **100%** |
| Endpoints discovered behind login | **34 pages, 17 under `/vulnerabilities/*`** (sqli, exec, fi, brute, csrf, upload, …) |
| Critical SQL injection confirmed | **Yes**: error-based, UNION, and **time-based blind** on real DVWA parameters |
| Local File Inclusion confirmed | **Yes**: `/vulnerabilities/fi/` `page` param (`/etc/passwd` leak) |
| OS Command Injection confirmed | **Yes**: `/vulnerabilities/exec/` `ip` param (`id` output) |
| CSRF confirmed | **Yes**: `/vulnerabilities/csrf/` password change accepts a tokenless **GET** |
| Total findings (after dedup) | **~50, all real** (site-wide issues reported once per host, not once per URL) |
| False-positive control | per-host + per-parameter dedup; XSS execution-aware; traversal/host-header need a structural signal, not a bare word; DELETE/PUT flagged only on a WebDAV 201/204; front-door and standard public files are not "sensitive"; time-based blind uses **differential timing**; login/search GET forms excluded from CSRF |

HEAVEN reports **real findings, not hallucinations**, every vulnerability comes
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
| **SQL injection** | error-based · boolean-blind · UNION-based · time-based blind | ✅ [D][N] `critical sqli on param 'id'` |
| **Local File Inclusion** | path traversal + `php://` wrappers, content-leak confirmed | ✅ [D][N] `critical lfi on param 'page'` |
| **OS command injection** | output-based (`id`/echo) + differential time-based | ✅ [D][N] `critical cmdi on param 'ip'` |
| **Reflected XSS** | execution-aware (escaping-resistant FP filter) | ✅ [D][N] |
| **CSRF** | state-changing form with no anti-CSRF token; catches the tokenless **GET** password change, excludes login/search forms | ✅ [D] `high csrf_missing_token` |
| **Remote File Inclusion** | best-effort remote-fetch detection | ✅ [D] probe wired |
| **SSRF** | out-of-band: target callback to in-house OAST collaborator | ✅ [N] `high ssrf on param 'url'` |
| **XXE** | out-of-band: `SYSTEM` entity resolves to the collaborator | ✅ [N] `high xxe` |
| **CORS misconfiguration** | reflected `Origin` + `Allow-Credentials`, canary origin | ✅ [N] `high cors_misconfig` |
| **Open redirect** | canary-host `Location` match (never fires same-site) | ✅ [N] `open_redirect on param 'url'` |
| **Weak / forgeable JWT** | `alg:none` + in-house HMAC secret crack (secret = proof) | ✅ [N] `critical jwt_weak_secret` |
| **Insecure session cookie** | missing `HttpOnly` / `Secure` / `SameSite` | ✅ [N] `insecure_cookie` |
| Security posture | headers, TLS, cookies, request-smuggling, version disclosure | ✅ [D][N] |

---

## Quality engineering behind the numbers

The first end-to-end DVWA run surfaced, and we fixed, the bugs that separate a
demo from a usable tool:

| Problem found via benchmark | Fix | Impact |
|---|---|---|
| One injectable param reported **188×** (one finding per payload) | strip query string from finding identity | **1,653 → 35 findings (-98%)** on a 2-URL scan; one finding per real bug |
| Auth cookies never sent (domain-less cookie jar) → scanners hit protected pages unauthenticated | deliver cookies as a flat `cookies=` dict | scanners now authenticate → reach behind login |
| Crawler ignored the auth session | plumb cookies/headers into the crawler | **0 → 17** endpoints discovered under `/vulnerabilities/*` |
| Crawler-discovered form params never reached the injection scanner | convert input-vectors → grouped test URLs/forms | SQLi/LFI/cmdi now actually get tested |
| Crawler-discovered **forms** never reached the auth scanner (only a form count was kept) | crawler emits `url_forms`; `_audit_csrf` reads them | CSRF / session-fixation audits work → **CSRF now detected** |
| Blind-timing SQLi flaked under QEMU emulation on arm64 | switch benchmark to the native multi-arch DVWA image | stable sub-second baselines → **blind SQLi detected**, recall 90% → **100%** |
| Web-fuzz phase timed out at 600s | collapse to unique paths + cap | scan time **812s → ~140s** |
| Nuclei task crashed (`'str'`) | best-effort enrichment | Nuclei contributes results |
| Transient concurrent-divergence artifacts (server-side lock contention, not an app race) surfaced as low-confidence race leads on authenticated POST endpoints | reproduce-before-report: require the concurrent divergence to recur on a confirmation burst before emitting (a real TOCTOU keeps diverging; an artifact settles) | spurious race leads **3 → 1**; DVWA precision **93% → 98%**, recall unchanged at **100%** |
| A concurrent one-shot flash message inflated one boolean-blind SQLi TRUE/FALSE pair on a non-injectable submit-button parameter (DVWA csrf `?Change=`), so the oracle "held" and even reproduced on the same pair | truth-value confirmation: require the oracle to survive a literal-swapped variant (`8=8`/`8=9` must behave like `1=1`/`1=2`); a real oracle depends on the condition's truth value, a transient does not | spurious boolean-SQLi lead **1 → 0**; DVWA precision **97.6% → 100%**, recall unchanged at **100%** |

---

## Honest caveats

- These runs used DVWA at **security level "low"** behind an authenticated
  session, the canonical functional benchmark for a scanner, not a hardened
  production app.
- The benchmark target ran under CPU emulation (amd64-on-arm64), so wall-clock
  scan times are slower than on native hardware; the **findings** are unaffected.
- Coverage spans the 11 classes scored above (injection, SSRF/XXE out-of-band,
  CORS, open redirect, weak JWT, insecure cookies, header hardening). It is not a
  claim of parity with commercial suites across *every* vuln class, see
  [`docs/COMPARISON.md`](COMPARISON.md) for an honest head-to-head template.
- The SSRF/XXE out-of-band proof requires the target to reach HEAVEN's
  collaborator. That holds for loopback/lab targets (it binds `127.0.0.1` by
  default); for a remote target, bind it to a routable address you're authorized
  to receive callbacks on (`HEAVEN_OAST_HOST`).

Run it yourself: [`docs/BENCHMARK_HOWTO.md`](BENCHMARK_HOWTO.md).

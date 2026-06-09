# Changelog

All notable changes to HEAVEN are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.3.0] — 2026-06-09

### Added — wider injection coverage: LFI / RFI / OS command injection

- The injection scanner is no longer SQLi+XSS only. It now tests every GET param
  and POST field for, additionally:
  - **Local File Inclusion / path traversal** — `/etc/passwd`, `..//` bypasses,
    null-byte, `php://filter` wrappers; **content-leak confirmed** (CWE-98).
  - **OS command injection** — output-based (`;id` / `$(id)` / `` `id` `` →
    detects `uid=…`) and **time-based blind with differential timing** (doubling
    the injected `sleep` must double the delay — defeats server jitter, so no
    false positives on naturally-slow endpoints) (CWE-78).
  - **Remote File Inclusion** — best-effort detection of remote-fetch attempts
    (CWE-98).
  Verified live against DVWA (`critical lfi — param 'page'`,
  `critical cmdi — param 'ip'`) and covered by deterministic unit tests
  (`tests/test_injection_probes.py`). See
  [docs/BENCHMARK_RESULTS.md](docs/BENCHMARK_RESULTS.md).

### Added — published DVWA benchmark results

- `docs/BENCHMARK_RESULTS.md` documents the real, reproducible results of running
  HEAVEN against live DVWA (autonomous authenticated discovery of 17
  `/vulnerabilities/*` endpoints; confirmed critical SQLi/LFI/cmdi; the
  report-quality + auth fixes that made it work), linked from the README summary.

### Fixed — authenticated scanning now actually works end-to-end (commercial-grade coverage)

Running the live DVWA benchmark surfaced four real bugs that, together, meant an
authenticated web scan reached nothing behind the login wall. All fixed and
verified against live DVWA:

- **Auth cookies were never sent by the scanners.** `aiohttp_session_kwargs()`
  built a cookie *jar* via `CookieJar.update_cookies({k: v})` with no
  response_url, leaving every cookie domain-less — aiohttp then silently dropped
  them. So the injection/fuzzer/API scanners hit protected pages
  **unauthenticated** and found nothing. Now cookies are passed as the flat
  `cookies=` dict (the approach the crawler already used). *This was the single
  biggest blocker to authenticated coverage.* Verified: the scanner now reaches
  DVWA's SQLi page authenticated (HTTP 200) and reports
  `critical sqli (error-based) — param 'id'`.
- **Crawler ignored the auth session.** The orchestrator never passed
  `auth_config` to `crawl_targets`, so the crawl stopped at `/login.php`. Now the
  active session's cookies/headers are plumbed in — verified the crawler
  self-discovers **17 endpoints under `/vulnerabilities/*`** (sqli/exec/fi/…)
  from just the base URL.
- **Crawler input-vectors never reached the injection scanner.** `_injection_scan`
  read `forms`/`url_forms` keys the crawler doesn't emit. Now it converts the
  crawler's `input_vectors` into testable targets, grouping a form's params into
  one URL (DVWA's SQLi needs `id` *and* `Submit` present, so single-param URLs
  never triggered it).
- **Nuclei task crashed with `'str'`.** Its URL-enrichment loop wasn't guarded
  against malformed task results. Made it best-effort so Nuclei always runs.
- **Web fuzzer timed out at 600s.** It fuzzed every payload-varying URL; the
  host/path-level checks are now collapsed to unique paths and capped
  (`max_urls=40`), so the phase is bounded (scan time 812s → ~140–170s).

Regression tests added (`test_scan_wiring.py`, plus the per-payload dedup test).

### Fixed — findings multiplied per payload (major report-quality bug, found via live DVWA benchmark)

- Running the real DVWA benchmark exposed that one injectable parameter probed
  with N payloads produced **N findings** — a single SQLi on `?id=` became
  **188 "findings"** (and a live scan ballooned to 1,653 rows from 2 URLs).
  Root cause: `_finding_hash` keyed path-level findings on the full target URL
  **including the query string**, so each payload (`?id=1`, `?id=1' OR 1=1`, …)
  hashed to a distinct identity. Now the query string + fragment are stripped
  from the identity, so all payloads on the same (endpoint, parameter, vuln_type)
  collapse to one finding. **Replaying the real scan's findings: 1,653 → 35
  (-98%).** Since the finding `id` is this hash (PRIMARY KEY), the collapse takes
  effect at persist time too. Regression test added; genuinely-different
  parameters still stay separate.
- The DVWA benchmark harness itself queried a non-existent `evidence` column
  (the schema column is `evidence_json`) — it would have failed for anyone with
  Docker. Fixed the query (`evidence_json AS evidence`).

### Added — onboarding / UX polish

- The "X not set — random value generated" config notice is now DEBUG-level, so
  normal commands are quiet for unconfigured users (the actionable nudge still
  lives in `heaven serve` startup + `heaven doctor`'s next-step).
- Web Scans page shows **live elapsed time** for running scans (updates every
  second) alongside the existing progress bar.
- **First-run guide on the Dashboard** — a dismissible checklist
  (scope → scan → findings → report) that auto-checks each step from real
  engagement state and hides once the core flow is complete.

### Added — live autonomous progress over WebSocket

- The autonomous loop now streams each iteration the instant it completes over
  `WS /api/autonomous/jobs/{id}/stream` (snapshot → iteration… → done), with
  per-subscriber fan-out. `run_autonomous` gained an `on_iteration` hook and
  `IterationReport.to_dict()`. The web UI renders a live table and falls back to
  polling if the socket drops. Verified end-to-end over a real socket.

### Added — test + CI coverage

- New `tests/test_report_auth_api.py`: report export (empty-engagement 404,
  unknown-format handling) and the password-change flow (wrong-current 401,
  weak/common new-password 422, success persists to `.env`).
- CI now builds the web UI (`ui-build` job: `npm ci` + `npm run build`, uploads
  `dist`) and the Docker job depends on it.

### Added — `heaven doctor` is now a guide, not just a diagnostic

- `heaven doctor` ends with a contextual **Next step** block that walks the
  happy path based on current state (no admin password → `heaven init`; no
  engagement → `heaven engage init` + `scope add`; no findings → `heaven scan`;
  has findings → `heaven report` / `heaven serve`). A new operator is never left
  wondering "now what?".

### Security — patched vulnerable dependency

- Bumped `aiohttp` to **>=3.14.0** (was >=3.9.0). `pip-audit` flagged
  `aiohttp 3.13.x` for CVE-2026-34993 (`CookieJar.load()` RCE on untrusted input)
  and CVE-2026-47265 (cookies leaked across a cross-origin redirect) — both
  relevant to HEAVEN's authenticated-scan cookie handling + redirect following.
  `pip-audit` is now clean (0 known vulnerabilities).

### Fixed — site-wide findings multiplied per URL (report-quality bug)

- Host/domain-level issues (missing security headers, `server_version_disclosure`,
  HTTP request smuggling, `xml_accepted`, weak TLS, SPF/DMARC/DNSSEC) were being
  reported **once per discovered URL** instead of once per host. Root cause: the
  scanners emit vuln_type strings (`no_x_content_type`, `http_smuggling_te_obfuscation`,
  …) that didn't match the spellings in `HOST_LEVEL_VULN_TYPES`, so they fell
  through to per-URL dedup. Found via a real end-to-end scan that produced **2,384
  findings** against a one-page target. `is_host_level()` now also matches a set of
  host-level substring signals, so every spelling collapses to one finding per
  host while per-endpoint bugs (xss/sqli/idor/csrf…) stay distinct. Regression
  test added.

### Fixed — `heaven update` CVE-feed refresh was a stub

- `heaven update` bailed with "NVDPipeline.download_recent not implemented yet".
  Implemented `NVDPipeline.download_recent(days=7)` — fetches CVEs published in
  the window via the NVD 2.0 API and appends new records (de-duped by CVE id) to
  `nvd_data/nvd_dataset.jsonl`. The command now actually refreshes the CVE feed.

### Changed — Gemini SDK migration (`google-generativeai` → `google-genai`)

- Google deprecated the `google-generativeai` package (it prints a end-of-life
  warning and stops receiving updates) in favour of the new `google-genai` SDK.
  The LLM gateway now uses the current client-based SDK
  (`from google import genai` → `genai.Client(...).models.generate_content(...)`,
  with a real `system_instruction` instead of prompt-prepending) and **falls back
  to the legacy SDK** if only that one is installed. Updated the `[gemini]` /
  `[llm]` / `[all]` extras, `requirements.txt`, the `heaven init` pip hint, and
  the README to `google-genai`. New `tests/test_llm_gateway.py` covers provider
  selection, the SDK choice, secret redaction, and structured parsing.

### Fixed — bytes/str handling in SSH post-exploitation

- `asyncssh`'s `conn.run().stdout/stderr` can be `bytes` or `str` depending on
  the connection encoding. `linpeas_runner.py` and `lateral.py` assumed `str`,
  so on a `bytes` result the linpeas output would be parsed with a `b'...'`
  wrapper and the SSH-key-reuse check (`"uid=" in out`) would raise `TypeError`.
  Added a defensive `_as_text()` coercion at each boundary. (Surfaced by mypy once
  the `[lateral]` extra was installed.)

### Fixed — security hardening

- **Credential vault is written `0600`.** `vault.enc` (the AES-256-GCM credential
  store) was created with the default umask (often `0644` → world-readable). It's
  now chmod'd to owner-only `0600` on every save. Flagged by `heaven self-audit`,
  which now scores **100/100 (grade A, 0 findings)**.
- **`cryptography` and `pyjwt` are core deps now** (see packaging note below).
  Without them the vault silently fell back to *plaintext* and auth used opaque
  (non-JWT) tokens — both degrade-gracefully paths, but not what a security tool
  should ship by default.

### Changed — packaging: base install vs. feature extras

- **`pip install` now matches the documented experience.** Three deps that power
  the default out-of-the-box flow were missing from `pyproject.toml`'s base
  install: `aiosqlite` (the default offline SQLite store — it was wrongly buried
  in the `dev` extra), `pyjwt` (JWT sessions) and `cryptography` (vault). Moved
  them to core `dependencies`.
- **Optional features are now installable as pip extras** instead of only via
  `requirements.txt`: `[recon]`, `[reports]`, `[lateral]`, `[mitre]`, `[deploy]`,
  `[scheduling]`, and an umbrella `[all]` (mirrors the existing `[gemini]` /
  `[anthropic]` / `[openai]` / `[llm]` pattern). Each feature still degrades
  gracefully when its extra isn't installed. README documents the matrix.

### Changed — `.env` is now authoritative

- The CLI auto-loads `.env` with `override=True`, so it wins over stale shell
  exports. Editing `.env` (or the Web-UI password change that writes back to it)
  now always takes effect on the next run — no "I changed it but a leftover
  `export` shadowed it" gotcha. `heaven init`'s next-steps no longer tell you to
  `source`/`export` the file (that step is obsolete).

### Fixed — CLI ↔ API ↔ Web UI wiring (the ".env never reached the server" class of bugs)

- **`.env` was only loaded when you passed `--config-file`.** Plain
  `heaven serve` / `heaven autonomous` (and every other command) never read
  `.env`, so the password, LLM keys, NVD/Shodan keys and SIEM/ticketing config
  written by `heaven init` were silently invisible to the running stack. The CLI
  now **auto-loads `.env` from the working directory at startup** (an explicit
  `--config-file` still overrides). This single fix resolved four reported
  symptoms at once:
  - **Web-UI admin password set via `heaven init` didn't take effect** — the
    server fell back to `admin/admin` + forced change because it never saw
    `HEAVEN_ADMIN_PASSWORD`. Now the configured password works on first login.
  - **`heaven autonomous` "did nothing smart"** — the LLM key was never loaded,
    so the planner always used the dumb rule-based fallback. With the key now
    loaded, the LLM planner engages.
- **Admin identity is now configurable.** New `HEAVEN_ADMIN_USERNAME` env var
  (defaults to `admin`); `heaven init` prompts for it and `.env.example`
  documents it. The header badge previously *looked* static ("admin · admin")
  because both the username and role were `admin`; it now renders the real
  username plus a distinct role pill, and the username follows your config.
- **Web-UI password changes now persist to `.env`.** The AuthManager is
  in-memory, so a password set in the browser used to vanish on restart
  (reverting to the old value or to admin/admin). `POST /api/auth/change-password`
  now writes `HEAVEN_ADMIN_PASSWORD` back to `.env` (surgical, comment-preserving
  edit via the new `heaven/utils/env_file.py`, file mode tightened to 0600) and
  updates the running process, so the change sticks across restarts — `.env` is
  the single source of truth. The forced first-login change now sticks too.

### Fixed — autonomous loop loses its run when you navigate away

- **`POST /api/autonomous/run` ran the whole loop synchronously**, blocking the
  HTTP request for minutes; the React page kept run state in component-local
  state, so switching pages discarded the in-flight run and the result. The
  endpoint now launches the loop as a **background job** and returns a `job_id`
  immediately; added `GET /api/autonomous/jobs` and
  `GET /api/autonomous/jobs/{id}`. The Autonomous page polls the job and
  persists the active `job_id` in `sessionStorage`, so a run **survives
  navigating away and back — and a full page refresh**. Verified live: POST
  returned in 0.47 s, the job completed in the background, and returning to the
  page re-rendered the summary.

### Added — Reports page in the Reporting nav group

- The multi-format report export already existed but was buried as a dropdown on
  the Findings page, so the **Reporting** section (Tickets / Benchmark /
  Methodology) had no obvious way to "get a report". Added a first-class
  **Reports** page (`/reports`) that shows a live severity snapshot of the active
  engagement and one-click download in all 8 formats (PDF / HTML / Markdown /
  CSV / JSON / SARIF / Burp / Proxy-JSONL), with an actionable empty state when
  there are no findings yet.

### Fixed — API-key configuration consistency

- The README's Quick Start told users to set **`GOOGLE_API_KEY`** for Gemini,
  but the code reads **`GEMINI_API_KEY`** — so the documented key was silently
  ignored. Corrected, and added a dedicated **API Keys & Configuration** section
  (every key, where to get it, three ways to set it, and a free-Gemini
  walkthrough).
- **`heaven init` wrote `HEAVEN_SHODAN_API_KEY` / `HEAVEN_NVD_API_KEY`**, but the
  code reads `SHODAN_API_KEY` / `NVD_API_KEY` — so wizard-set recon keys didn't
  take effect. The wizard now writes the canonical names; `config.py` also
  accepts `NVD_API_KEY` (keeping `HEAVEN_NVD_API_KEY` as a legacy alias).
- **Wrong SDK hint** — a missing Gemini SDK suggested `pip install gemini`
  (doesn't exist). It now suggests the correct `pip install google-generativeai`.

### Added — easy LLM setup

- pip extras for the AI layers: `pip install -e ".[gemini]"` / `".[anthropic]"` /
  `".[openai]"`, or `".[llm]"` for all three. `.env.example` and `heaven init`
  now document each key, where to obtain it, and which SDK to install; `heaven
  init` prints the get-a-key URLs and the exact `pip install` line.

### Fixed — web UI crash on login (critical)

- `App.jsx` referenced `needsPasswordChange()` and `<ForcedPasswordChange>`
  without importing either (the imports had been dropped). With no ESLint to
  catch it and Vite not flagging undefined refs, the authenticated app threw a
  `ReferenceError` and **white-screened for every logged-in user**. Added the
  missing imports; verified end-to-end in a browser (login → forced-change →
  dashboard, zero console errors).

### Added — web UI resilience & usability

- **Error boundary** around the routed content — a render error now shows a
  recoverable "something went wrong" card (Reload / Back to dashboard) instead
  of a blank screen. Keyed by route, so navigating away clears it.
- **404 route** — unknown URLs render a proper "page not found" instead of an
  empty content area.
- **Session survives refresh** — the auth token is persisted in sessionStorage
  (clears on tab close), so F5 / reopening a tab no longer forces re-login.
  Tradeoff documented in `api.js`; httpOnly cookie remains the max-hardening
  option.
- **Graceful session expiry** — a 401 clears auth, raises a "Session expired"
  toast, and ProtectedRoute redirects to /login (no more raw error card).
- **Actionable empty states** — the "no engagement" screens on Dashboard,
  Findings, Kill Chain and Engagement now offer an in-app **Launch a scan →**
  button (the Scans page has a full launcher) instead of telling the operator
  to go run CLI commands / restart the server.
- **Global "scan running" indicator** in the header — polls so it stays visible
  after you navigate away from the Scans page; click to return.
- **Findings filters** — debounced auto-apply + Enter-to-apply, and a loading
  skeleton on first fetch.
- **Accessibility** — visible keyboard focus rings, keyboard-operable sortable
  table headers with `aria-sort`, `aria-expanded` on sidebar groups, and
  `aria-hidden` on decorative icons; honors `prefers-reduced-motion`.
- **Consistency pass across all pages** — skeleton loaders on every
  fetch/run (Coverage, Knowledge, Tickets, Methodology, Benchmark, Diff, SAST,
  Autonomous, Post-Ex, Lateral, AI Plans) and actionable empty states
  (Knowledge / Diff → "Launch a scan", Benchmark / Watch → clear guidance).
- **No more `alert()` dialogs** — the Replay (Scans) and Train-priors (Coverage)
  flows now use the in-app toast system instead of blocking browser alerts.

### Added — CLI usability pass

- **Colourised, grouped help via rich-click.** `heaven --help` now renders the
  38 commands in six labelled panels (Scanning & Monitoring · Engagements &
  Findings · Reporting & Tickets · AI & Threat Intel · Models · Platform &
  Setup) instead of one flat alphabetical dump. `heaven scan --help` groups its
  options into Targets / Scan profile / Authorization & scope / Exploitation
  chaining / Output panels and shows a worked Examples block. Falls back to
  plain Click (same commands) when `rich-click` isn't installed.
- **`heaven use <engagement>`** — git-branch-style sticky engagement context
  stored per working directory (`./.heaven/`), so you stop retyping
  `--engagement` on every command. Resolution precedence: explicit flag >
  `HEAVEN_ENGAGEMENT` env > `heaven use` > default. `heaven use` shows the
  current selection + available engagements; `heaven use --clear` resets it.
  The no-arg dashboard now displays the active engagement.
- **"Did you mean?" suggestions** on a mistyped command
  (`heaven scna` → suggests `scan`).

### Changed — CLI command clarity

- **`heaven sys-status` → `heaven doctor`.** The deployment health check now
  uses the familiar `doctor` idiom and is discoverable in the grouped help.
  `sys-status` is kept as a hidden, backward-compatible alias.
- **`heaven schedule` deprecated** in favour of `heaven watch` (which adds
  change-detection and alert-on-change). It is now hidden and prints a
  deprecation notice, but still runs for backward compatibility.

### Added — report downloads, vuln knowledge base, forced-change auth

- **Downloadable reports (webapp + API).** New `GET /api/report/export?format=…`
  streams a report in 8 working text/standard formats — HTML (compliance-mapped),
  Markdown, CSV, JSON, SARIF, Burp XML, proxy-JSONL — plus PDF when `reportlab`
  is installed (a declared dependency; returns a clear 503 if absent). A
  "Download report" menu is wired into the Findings page (`ReportMenu`). The API
  reuses the exact reporters behind `heaven export` / `heaven report`, so CLI and
  webapp output match.
- **Vulnerability Knowledge Base** (`heaven/devsecops/vuln_kb.py`) — 16 curated
  classes with real description / impact / remediation / references / MITRE / CWE /
  OWASP. The evidence packager and the finding-detail API enrich every finding
  from it, so the UI and reports never show blank fields. Fixes the empty
  `DOCKER_SOCKET_EXPOSED` detail view (now shows CVSS 9.8, MITRE T1610, CWE-284,
  remediation, and references). Also surfaced real stored fields the detail page
  previously dropped (CVSS from risk_score, seen-count, last-seen date).
- **Finding-detail page** now renders an "About this vulnerability" section,
  impact, CWE/OWASP/MITRE chips, and a references list.
- **admin/admin default + forced change.** Fresh installs seed admin/admin so the
  console works out-of-the-box, but the account is flagged `must_change_password`:
  the webapp shows a blocking change-password screen on first login and refuses
  to proceed until a strong password is set (≥8 chars, common-password blocklist).
  `HEAVEN_ADMIN_PASSWORD` still overrides with no forced change. New
  `POST /api/auth/change-password`; `self-audit` still flags unchanged defaults.

### Changed — web UI redesign (premium "hybrid" theme)

- **Complete React UI overhaul** — replaced the green-on-black CRT/matrix
  aesthetic with a modern, professional dark theme: deep-slate surfaces,
  aurora-gradient backdrop, glassmorphism, a violet→blue primary accent
  with emerald kept as the live/signature colour, **Inter** for UI text +
  **JetBrains Mono** for data/code, layered elevation, and framer-motion.
- **Rebuilt design system** (`heaven-ui/src/index.css`) around the same
  class vocabulary, so all 19 pages re-theme consistently. Flagship
  surfaces hand-built: split-hero **LoginPage**, **Dashboard** (gradient
  stat cards + real severity-distribution chart), **Sidebar**/**Header**;
  3D topology reskinned to the new palette.
- **Verified live** — server-rendered screenshots of Login, Dashboard,
  Findings and Scans against a seeded engagement confirm real data flow.
- **Code-splitting** — the heavy three.js 3D topology (~900 KB) is now
  lazy-loaded behind a dynamic import, and every authenticated page is its
  own chunk (`React.lazy` + `Suspense`). First-load JS dropped from a single
  ~1.1 MB bundle to ~313 KB (login + shell); the 3D engine only downloads
  when the Dashboard opens. Removed dead `recharts`/`mermaid` manual chunks.

### Fixed — functional reliability (no fake/stub behaviour)

- **Exploit-DB product search** — added `search_product(service, version)`
  to `vulnscan/exploitdb_client.py` (searchsploit + CSV-mirror free-text
  search). The recon agent's `_tool_correlate_exploit` now returns **real**
  PoC matches instead of an empty placeholder; honest empty result when no
  source is available.
- **Honeypot orchestrator phase** — `recon/honeypot_detector.check_honeypots`
  no longer returns hardcoded zeros; it runs the real `analyze_host` over
  the network scan's discovered hosts and reports genuine counts (wired via
  an orchestrator closure that reads the network task result).
- **Honeypot detection calibration** — a known honeypot-software banner
  (cowrie/kippo/…) now flags on its own; the weighted composite capped
  banner signal at ~0.28 (below the 0.5 threshold), so definitive matches
  went undetected. Added a score floor on signature match.
- **8 new regression tests** (`tests/test_honeypot_and_exploitdb.py`).
  Suite now **313 passed, 1 skipped**.

### Fixed — CI / packaging

- **`pyproject.toml` dependencies block** had drifted under `[project.urls]`,
  so setuptools parsed it as `project.urls.dependencies` and every
  `pip install -e .` aborted — breaking the test, mypy, self-audit and
  docker CI jobs. Moved it back under `[project]`.
- **Wheel data files** — added `[tool.setuptools.package-data]` so SAST
  rulesets (`vulnscan/sast_rules/*.yml`) and `db/schema.sql` ship in the
  wheel; tightened `packages.find` to exclude `heaven-ui`.
- **Dockerfile** — aligned the py-builder workdir with the runtime path
  (`/build` → `/app`) so the editable-install finder resolves after COPY
  (image built fine but crashed on startup before). Added **`.dockerignore`**
  (keeps host venv / node_modules / `data/` / secrets out of the context)
  and a **CI smoke-test** that runs the built image (`heaven --version`).
- **GitHub Actions** — bumped all Node-20 actions to current majors
  (checkout@v5, setup-python@v6, upload/download-artifact@v5, buildx@v4,
  build-push@v7, …), clearing the deprecation warnings.

### Verified

- **NVD model** (`NVD_model.pkl`) confirmed a genuinely trained 13-feature
  ExtraTreesRegressor (R²=0.9925) — discriminates critical→10.0 / low→2.35,
  top features = Integrity/Confidentiality/Availability impact. Not a stub.
- **CLI ↔ webapp parity** — every operational CLI command maps to a UI
  surface; all 35 `api.js` helpers map to real server routes.

### Added — publication-readiness sprint

- **PyPI release workflow** (`.github/workflows/release.yml`) — on `v*`
  tags, builds sdist+wheel, verifies install, publishes via PyPI OIDC
  trusted publishing, and cuts a GitHub Release with CHANGELOG body.
- **Docker GHCR build+push workflow** (`.github/workflows/docker.yml`) —
  multi-arch (amd64 + arm64) image at `ghcr.io/nishu2402/heaven` on
  branch push, semver tags on `v*` tags.
- **`heaven init`** — interactive first-time-setup wizard. Generates
  strong passwords, prompts for optional LLM / SIEM / ticketing keys,
  writes a versioned `.env`. Idempotent.
- **`heaven update`** — refreshes Nuclei templates, NVD CVE delta, and
  ExploitDB CSV mirror in one command. Useful for cron / pre-engagement.
- **`heaven scan --watch-tail`** — headless mode that disables the Rich
  live HUD and streams flat one-line-per-event output. For CI / ssh /
  `tee scan.log` workflows where the live HUD scrambles the recording.
- **Asset-criticality risk multiplier** — `heaven scope add --criticality
  {low,medium,high,crown_jewel}` adjusts every finding's `risk_score` by
  the configured multiplier (0.7 / 1.0 / 1.3 / 1.5). 11 new tests.
- **Helm chart** (`deploy/helm/heaven/`) — standard chart with
  Deployment + Service + Secret + ConfigMap + PVC + Ingress (opt-in)
  + ServiceAccount + NOTES.txt. Multi-arch image-ready.
- **`docs/QUICKSTART.md`** — 5-minute walkthrough for evaluators.
- **`docs/COMPARISON.md`** — feature parity matrix vs Burp / ZAP /
  sqlmap / Nessus / Acunetix + empirical-numbers template.
- **`docs/DEMO.md`** — asciinema/video recording script (substitute
  for an actual recorded demo this session).
- **`docs/BENCHMARK_HOWTO.md`** — step-by-step to produce real DVWA
  precision/recall numbers (substitute for the actual benchmark run).
- **Live CI badges** in README — replaces the manually-maintained
  `Tests-294_Passing` badge with the actual GitHub Actions status,
  benchmark workflow status, and PyPI version badges.
- **`pyproject.toml` metadata polish** — full PyPI classifier set,
  project URLs, marketing description, additional keywords. Renamed
  the published package from `heaven` (squatted) to `heaven-pentest`.

### Added — publication push

- **Continuous monitoring** (`heaven watch`) — interval+jitter loop with
  auto-diff against the previous scan. Fires alerts ONLY on `new` or
  `regressed` findings (configurable `--heartbeat` to alert every run).
  Optional `--auto-tickets` to create Jira / Linear issues on regressions.
- **Differential scanning** (`heaven diff <base> <current>`) — bucketed
  output (new / resolved / regressed / unchanged) with CI-friendly exit
  codes. API: `GET /api/scans/{id}/diff?baseline=...`.
- **SAST** (`heaven sast`) — Semgrep wrapper with a curated 18-rule pack
  for Python / JavaScript / Go covering OWASP Top 10. Findings land in
  the engagement DB alongside DAST findings.
- **Ticketing** (`heaven tickets`) — Jira (REST v3) + Linear (GraphQL)
  with auto-priority mapping, label normalisation, and bulk push.
- **Iterative autonomous loop** (`heaven autonomous`) — LLM-driven
  observe → plan → act loop bounded by `--max-iterations` and
  `--time-budget`. Falls back to a deterministic rule-based playbook
  when no LLM API key is set.
- **Coverage grader** (`heaven coverage`) — rule-based OWASP coverage %
  + scope hit rate + optional LLM gap analysis.
- **Lateral movement** (`heaven lateral`) — SSH key reuse + SMB PsExec
  + pass-the-hash with a hop graph output.
- **Knowledge graph** (`heaven knowledge`) — SQLite-backed cross-engagement
  memory of (target_profile, technique, outcome) tuples with Beta-smoothed
  per-technique success priors.
- **Exploit-DB lookup** (`heaven exploitdb <cve>`) — local `searchsploit`
  (preferred) + ExploitDB CSV mirror.
- **AI namespace** — Layers A–E: provider-agnostic LLM gateway
  (Anthropic / OpenAI / Gemini), recon agent, attack-chain planner,
  FP review, autonomous loop.
- **Authenticated scanning** — `--cookie-file PATH` (Netscape format)
  and `--auth url=/login,user=X,pass=Y[,csrf_field=token]` on
  `heaven scan`.
- **Exploit proof** — `heaven/vulnscan/exploit_proof.py` ties sqlmap,
  RCE canary file dropping, and an SSRF callback verifier into a single
  `prove_finding()` entry point. Auto-triggered with `--auto-prove` on
  `heaven scan`.
- **Post-exploitation** — `heaven/postex/` with `linpeas_runner`,
  `bloodhound_collector`, `cred_validator`. Admin-gated.
- **Benchmark suite** — `tests/benchmarks/` against DVWA with adapters
  for Burp / ZAP / sqlmap, scanner-agnostic metrics, markdown + CSV
  reporters, GitHub Actions weekly workflow.
- **Methodology mapping docs** — `docs/methodology/` with explicit
  mappings to OWASP Testing Guide v4, NIST SP 800-115, and PTES.
- **NVD model card** — `data/models/NVD_model.MODEL_CARD.md` following
  Google's Model Cards format.
- **Reproducibility** — `--seed` flag on `heaven scan` + `heaven replay
  <scan-id>` for deterministic re-execution.
- **SIEM forwarders** — `SplunkHECAlerter` + `ElasticAlerter` in
  `devsecops/alerting.py`.
- **Web UI pages** — Watch, ScanDiff, SAST, Autonomous, AIPlans,
  Coverage, Postex, Lateral, Knowledge, Tickets, Benchmark, Methodology.

### Changed

- **CLI split** — `heaven/main.py` decomposed from a 1380-line monolith
  into a thin shim plus `heaven/cli/` subpackage (one module per command
  group). The `heaven = heaven.main:cli` pyproject entry point is unchanged.
- **`zeroday_engine.py` → `anomaly_probe.py`** — renamed to match what
  the code actually does (behavioural fuzzing heuristics, not real
  zero-day discovery).
- **`ai_brain.py` priors** moved from hardcoded module constants into
  `data/models/priors_bootstrap.json`. `heaven/ml/train_priors.py` +
  `heaven train-priors` produce `priors_learned.json` from engagement
  history, which is preferred at runtime when present.

### Fixed

- Several mypy strict-mode issues across the new modules.
- Ruff E731 (lambda-assignment) + F401 (unused imports) across the
  AI layer.

---

## [1.0.0] — pre-publication baseline

Initial public release of HEAVEN — autonomous penetration testing
framework. See README.md for the feature matrix.

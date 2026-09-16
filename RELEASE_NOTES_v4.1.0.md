<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/v4.1.0/docs/assets/heaven-poster.svg"/>
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/v4.1.0/docs/assets/heaven-poster-light.svg"/>
  <img src="https://raw.githubusercontent.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/v4.1.0/docs/assets/heaven-release-banner.png" width="100%" alt="HEAVEN: Autonomous Penetration-Testing Framework v4.1.0 · Recon -> ML Risk Scoring -> Verified Exploitation -> Reporting"/>
</picture>
</p>

<div align="center">

  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-FF36AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
    <img src="https://img.shields.io/badge/API-FastAPI_99_Routes-7400B8?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
    <img src="https://img.shields.io/github/actions/workflow/status/nishu2402/HEAVEN-Autonomous-Penetration-Testing/ci.yml?style=for-the-badge&logo=pytest&logoColor=black&label=Tests" alt="Tests"/>
    <img src="https://img.shields.io/badge/LLM-Anthropic_%7C_OpenAI_%7C_Gemini-FF6E00?style=for-the-badge&logo=openai&logoColor=white" alt="LLM"/>
    <img src="https://img.shields.io/badge/License-MIT-00D2FF?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License"/>
  </p>

  <p>
    <img src="https://img.shields.io/github/v/release/nishu2402/HEAVEN-Autonomous-Penetration-Testing?style=flat-square&logo=github&logoColor=white&label=Release&color=FF36AB" alt="Release"/>
    <img src="https://img.shields.io/badge/Modules-219-7400B8?style=flat-square&logo=python&logoColor=white" alt="Modules"/>
    <img src="https://img.shields.io/badge/CLI_Commands-62-B8FF00?style=flat-square&logo=gnubash&logoColor=black" alt="CLI"/>
    <img src="https://img.shields.io/badge/UI_Pages-25-00D2FF?style=flat-square&logo=react&logoColor=black" alt="UI"/>
    <img src="https://img.shields.io/badge/CVSS_Predictor-R²%3D0.91-FF6E00?style=flat-square&logo=databricks&logoColor=white" alt="CVSS"/>
  </p>

</div>

---

## What's new in HEAVEN v4.1.0

### Added

- **Combined Risk now builds end-to-end attack paths, not just pairs.** The
  correlation engine chains its individual combinations into ordered walks where
  each step hands the attacker a capability the next step consumes (code execution,
  reusable credentials, internal network reach, a hijacked account, administrative
  control), ending in a concrete business impact (full host, database, or domain
  compromise, data exposure, account takeover). A link is only drawn where one step
  genuinely produces what the next requires, and a cross-host hop only where the
  attacker actually gained a way to move (reused credentials or internal reach), so
  nothing is fabricated. The Combined Risk page renders each path as a visual graph
  of severity-coloured step nodes joined by labelled hops and a final impact node,
  with the plain-language narrative beneath it; the CLI and the HTML report render
  the same paths.
- **"Break the chain" tells you the single fixes with the most leverage.** Because a
  combined risk needs all of its parts, fixing any one constituent breaks it. The
  engine now ranks every constituent finding by how many combined risks (and attack
  paths) it breaks, names the highest-leverage fix, and computes the smallest set of
  fixes that severs every attack path to your crown jewels. Surfaced in the page, the
  `heaven correlate` output, and the report. New coverage in
  `tests/test_correlation.py` (attack-path chaining, host-role and impact labelling,
  the no-false-chain guard, subpath suppression, and remediation leverage).
- **The PDF report now carries the same Combined Risk and attack-path analysis as
  the HTML report and the web UI.** The formal client deliverable stopped at the
  per-finding summary, so the correlation work reached the web report and the live
  UI but never the PDF a client is handed. A new "Combined Risk & Attack Paths"
  section is built from the same `CorrelationEngine().summary()` the other surfaces
  use, computed at report-build time: it leads with the highest-leverage single
  fixes and the smallest set that severs every path to the crown jewels, then lists
  each combined risk with its elevated severity and constituents, then the attack
  paths with their business impact. It adds no new detection, so it introduces no
  new false positives: it re-expresses combinations already built from confirmed
  findings, and the section (with its number) is omitted entirely when a scan
  produced no correlations, exactly as the HTML report does. Covered by
  `tests/test_report_and_triage_fixes.py`.
- **Shellshock detection now covers any HTTP service and proves execution in-band.**
  The check was tied to a fixed list of web ports and relied on a reverse callback,
  so a CGI on an unlisted port was missed and a proof needed outbound egress. It now
  applies wherever a service looks like HTTP (unlisted ports included) and tries an
  in-band proof first: it injects an arithmetic-expansion marker ahead of the
  command, so a server that merely echoes the header back shows the literal
  `$((a*b))` while genuine execution shows the computed product. Matching the product
  proves code execution with no callback, and the reverse-callback path stays as a
  fallback for a CGI whose output never appears in the response. New coverage in
  `tests/test_exploit_engine.py`.
- **An optional overall time budget lets a long scan finish cleanly instead of being
  cut off mid-run.** Set `HEAVEN_SCAN_DEADLINE` (seconds) and the scan watches its
  own wall-clock: once the budget is spent it stops launching new phases and caps
  every phase still in flight to the time that remains, so the run finalises with the
  findings it already has and persists them. It is off by default (a budget of 0
  means unlimited), so an ordinary scan is never shortened. The one place it is
  enabled is the weekly `Benchmark — HEAVEN vs. DVWA` job, where a slow shared runner
  could overrun the harness timeout and be killed with nothing written to disk: a
  900s internal budget, kept 300s below the hard subprocess backstop, now returns a
  real persisted result instead of an empty database. New coverage in
  `tests/test_phase_deadline_and_timeout_scale.py`.

### Fixed

- **Three web-fuzzer false positives that a live DVWA scan surfaced are suppressed
  at the emitter.** An authenticated benchmark scan produced five findings that were
  not real, each traced to a specific over-broad check. The "403 bypass via path
  manipulation" test appended path tricks to a forbidden URL and flagged any 200 in
  response, but two of its suffixes (`/../`, `/.%2e/`) normalize to the parent
  directory, so on `/server-status`, `/docs` and `/config` the "bypass" simply
  fetched the site's home page (a different resource) and reported access that never
  happened. Those parent-escaping suffixes are removed, and a candidate bypass whose
  body matches the origin root is now rejected. The hidden-parameter probe reported
  `redirect` as a "discovered" parameter on a page where it was already part of the
  request, so the discovery step now skips names already present in the query. The
  parameter-pollution check fired whenever duplicating a parameter changed the
  response at all, which is ordinary last-value behaviour for any working parameter;
  it now requires a genuine desync, where the duplicate smuggles a value into the
  response that a single occurrence does not. No detection changed: each suppressed
  finding was confirmed false against live DVWA, the genuine cases still fire (with
  new positive-control coverage), and the `Benchmark — HEAVEN vs. DVWA` precision is
  now a true 100% with recall already at 100%. New
  `tests/test_web_fuzzer_fp_hardening.py`.
- **A web scan no longer spends minutes fuzzing static documents or re-probing one
  host for request smuggling.** The heaviest active web tasks (advanced exploitation
  and the anomaly probe) fire a per-URL battery of payloads, several of them
  time-based, so on a target that ships many parameter-less static files (DVWA's
  official image alone serves 14 localized `README.*.md` files, plus a PDF manual,
  `robots.txt` and `security.txt`) they spent seconds each on URLs that cannot carry
  an injection. They now skip any parameter-less static document or asset, as do the
  web fuzzer and the misconfiguration / out-of-band scan. The CL.TE request-smuggling
  probe, whose desync is a property of the origin rather than any one path and which
  stalls to its own timeout on a normal server, now runs once per origin instead of
  once per discovered URL, and advanced exploitation gained the same monotonic
  wall-budget the anomaly probe already carried. Recall is unchanged (every
  detection-required vector is a parameterised endpoint, still fuzzed): on live DVWA
  the authenticated scan drops from over 15 minutes back to a few, so the weekly
  `Benchmark — HEAVEN vs. DVWA` run no longer trips its per-scan timeout. New
  `heaven/vulnscan/url_surface.py` and `tests/test_url_surface_and_advanced_scope.py`.
- **Combined Risk now follows the engagement you are viewing.** Switching the
  active engagement left the Combined Risk page (and the `/api/correlations`,
  `/api/kill-chain`, `/api/attack-tree`, `/api/risk-scores` and
  `/api/vulnerabilities` endpoints behind it) showing the same combinations, even
  after a refresh. Those endpoints read whichever `report_*.json` was newest on
  disk across every engagement, so with more than one engagement they all resolved
  to a single global report regardless of which one was selected. They now read the
  active engagement's stored findings, exactly as the dashboard and the
  `heaven correlate` CLI already did: a specific scan id still loads that scan's
  report, an engagement with no findings shows nothing rather than another
  engagement's data, and only a fresh install with no active engagement falls back
  to the latest report. The Combined Risk and Kill Chain pages also refresh
  immediately when the engagement changes instead of waiting for a full reload.
  Covered by `tests/test_correlations_engagement_scope.py`.
- **A network range scanned by CIDR no longer invents a bogus email domain.**
  Domain-level DNS and email-posture checks (SPF, DMARC, DKIM, DNSSEC) resolve a
  target to its registered domain first, and only skipped plain IP literals, not
  CIDR notation. A target like `192.168.2.0/24` is not an IP address, so it fell
  through to the eTLD+1 fallback and became the fake domain `2.0` (`10.0.0.0/8`
  became `0.0`), against which those lookups then fired guaranteed
  false-positive "record missing" findings. Those phantom findings surfaced in
  Combined Risk as a nonsense host. The shared registered-domain helper now
  rejects CIDR ranges and bare network addresses the same way it already rejected
  IP literals, localhost and single-label hosts, so an internal-network
  engagement contributes no email-posture findings unless a real domain is also
  in scope. Covered by `tests/test_orchestrator_domain.py`.
- **A `.co.uk` (or other multi-part ccTLD) domain no longer reports email posture
  against the wrong name.** The registered-domain helper took the last two labels,
  so `example.co.uk` collapsed to the bare public suffix `co.uk`. SPF, DMARC, DKIM
  and DNSSEC were then checked against `co.uk`, a suffix nobody can send mail as,
  producing guaranteed "record missing" findings and a spurious "Practical Email
  Spoofing" combined risk, while the real domain was never checked. The same
  collapse also let a redirect from the target to a different organisation on the
  same suffix (say `attacker.co.uk`) count as on-site. The helper now recognises
  common multi-part suffixes and resolves `a.b.example.co.uk` to `example.co.uk`,
  returning nothing for a bare suffix. The eTLD+1 logic, previously duplicated in
  two files that had already drifted, now lives in one module
  (`heaven/utils/domains.py`) that both the orchestrator and the auth scanner
  import, so they cannot diverge again. Covered by `tests/test_orchestrator_domain.py`.
- **A missing security header is reported once, not two or three times.** Two
  scanners legitimately probe response headers: one emits a single bundle naming
  every header it found absent, the other emits a granular finding per header. On a
  host where both ran, the same missing header (Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options) surfaced under two or three different
  finding names, which the identity-based dedup could not merge because different
  finding types are distinct identities by design. A conservative consolidation pass
  now drops the redundant bundle, and the duplicate clickjacking finding, for a host
  only when the granular per-header equivalents are present for that same host, so a
  scan mode that runs a single scanner never loses coverage. HSTS is reported
  separately and is untouched. Clickjacking severity is reconciled to medium across
  both scanners, matching its CWE-1021 CVSS score, and the granular X-Frame-Options
  check no longer fires when a CSP frame-ancestors directive already blocks framing.
  Covered by `tests/test_security_header_consolidation.py`.
- **The web crawler no longer re-scans one page once per in-page anchor.** A URL
  fragment (the `#section` part) is client-side only and never reaches the server,
  so `page.php#a` and `page.php#b` are the same resource. The crawler used to
  dedupe on the full URL including the fragment, so a page that links to many of
  its own anchors (phpinfo's roughly forty `#module_*` table-of-contents links are
  the classic case) was crawled, and then fully re-scanned by every downstream web
  audit, once per fragment. It now strips the fragment before deduping, which on a
  DVWA target cut the crawl from 99 endpoints to 51 real ones (phpinfo fetched once
  instead of about forty times), cutting scan time and removing duplicate findings
  keyed on the fragmented URL. Covered by `tests/test_crawler_url_normalization.py`.
- **A scan can no longer hang indefinitely at a fixed percentage.** Each pipeline
  phase now runs under a hard deadline (its slowest task's own scope/stealth-scaled
  timeout, plus generous headroom). A task whose cancellation stalls, for example an
  HTTP request whose TLS teardown never completes against an unresponsive target, is
  force-finalised as failed, its dependents are released, and the scan moves on with
  the partial results it already has, instead of freezing the whole run. Previously a
  per-task timeout could be silently defeated by that stall and there was no
  higher-level watchdog to recover.
- **Web and vulnerability task timeouts now fit the scope.** The fixed per-task caps
  were sized for a single fast host, so a slow or rate-limiting real-world target, a
  full-range or UDP sweep, or a quieter stealth profile tripped them mid-scan and
  discarded the task's partial work. Those timeouts now scale with the stealth level
  and scan breadth (a quieter or wider scan gets proportionally longer), while the
  network task keeps its own separate scaling. New
  `tests/test_phase_deadline_and_timeout_scale.py`.
- **Combined Risk "Method Not Allowed" on Correlate is fixed, and no API call can
  be swallowed by the web UI again.** The built UI is served from a catch-all mount
  at the site root, which matched every path for every method. So any `/api/` request
  that no route answered, a call to a server started before that route existed, or a
  stray trailing slash, was handled by the static file server and came back as a bare
  "Method Not Allowed" instead of a real API response. That is what the Correlate
  button hit. An API fallback now sits ahead of the static mount: real routes still
  win, a trailing slash is redirected to the canonical path with its method and body
  intact, an unsupported method returns a proper 405 with an `Allow` header, and an
  unknown endpoint returns a clear JSON 404 rather than the app's HTML shell. Added
  live routing regression tests in `tests/test_correlation.py`.
- **Combined Risk now surfaces the chains it was hiding.** Across a large sample of
  real scans, most showed zero combined risks even when genuine attack chains were
  present. The cause was the engine only reporting a combination when its rating came
  out strictly higher than its strongest constituent, so the most dangerous chains,
  built from findings that are already high or critical on their own (SQL injection
  plus an exposed admin panel, default credentials plus an exposed service, a leaked
  key plus a reachable service), were discarded precisely because there was no number
  left above critical. A combination is now reported whenever distinct real findings
  fill it, and its severity is the higher of the rule's rating and the strongest part,
  so it is never rated below one of its parts and never above what the rule warrants; a
  chain whose parts are already critical stays critical but is shown, with its concrete
  exploitation path. Nothing is invented: every slot is still filled by a distinct real
  finding.
- **Combined Risk no longer double-counts or self-pairs findings.** A scan report
  carries the same finding set under both its `vulnerabilities` and `findings` fields,
  and the correlation endpoint concatenated them, so every finding was counted twice
  and a finding could be "combined" with a duplicate of itself (for example one SSH
  default-credential finding paired with its own copy). The endpoint now merges and
  dedupes by identity, and the engine also dedupes defensively, so the input count is
  honest and a chain is only ever built from genuinely distinct findings.
- **Combined Risk correlation rules corrected against the real finding vocabulary.**
  Informational observations (a healthy SPF or DMARC record, a benign note) are no
  longer eligible to form a chain. The cleartext-transport rule, whose keywords matched
  no finding any detector actually emits, was retargeted to the real sslstrip-style
  chain (a downgradable or cleartext channel plus a session cookie or credential not
  bound to TLS). A weak-JWT signing finding is no longer mistaken for a redirectable
  OAuth flow, and default or guessable credentials are no longer treated as a leaked
  secret. A new rule reports a practically spoofable email domain when it has neither an
  enforceable SPF nor DMARC. Extended `tests/test_correlation.py` (duplicate and
  info-severity exclusion, the severity floor, the retargeted and corrected rules, the
  new email rule, and a guard that every rule can still match real findings).
- **An SPF record that ends in `?all` (neutral) is no longer treated as safe.** The
  email-posture check handled `-all` (hardfail) and `~all` (softfail) but silently
  passed a neutral `?all` record, a common hosting default. Neutral tells a receiver
  to treat every sender as unspecified, which is no enforcement at all, so with a
  missing or non-enforcing DMARC policy the domain stays spoofable. It is now
  reported as a medium finding that recommends `-all`. Covered by
  `tests/test_dns_enumeration.py`.
- **A distribution-packaged service no longer inherits CVEs its distro already
  backport-fixed.** Distributions patch a flaw inside the same upstream version
  string, so matching an upstream version range against a distro-packaged banner
  (Ubuntu, Debian, RHEL and the like) produces near-certain false positives. The
  archetype is regreSSHion (CVE-2024-6387): its 8.5p1 to 9.7p1 range covers the
  OpenSSH shipped by current Ubuntu and Debian, which was fixed by backport within
  days. Records known to be distro-backport-fixed are now dropped for
  distro-packaged banners, the OpenSSH ceiling that read `<=9.6` is corrected to a
  strict `<9.6` so the fixed release stops matching, and an exposed
  `Docker Registry 2.0` is matched to its own product first so its `2.0` API version
  can no longer collide with Docker Engine CVE ceilings (CVE-2022-0492). New
  `tests/test_cve_version_fp.py`.
- **Combined Risk cards show OWASP categories in the current Top 10:2025 edition.**
  The amplification rules still carry OWASP 2021 ids internally, but the rest of the
  report, the per-finding tags and the UI moved to Top 10:2025, so a combined-risk
  card could show a stale `A07:2021` next to 2025 findings in the same deliverable.
  The tag is now crosswalked to the 2025 taxonomy at the single point every combined
  risk is built, and a label with no recognisable web-OWASP id (an OT/ICS tag, or
  none) is left unchanged. Covered by `tests/test_correlation.py`.

### Install

HEAVEN is distributed here, not on PyPI. Install the attached wheel:

```bash
pip install heaven_pentest-4.1.0-py3-none-any.whl
```

…or from source: one command sets up everything.

```bash
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
./scripts/install.sh          # macOS / Linux  (Windows: scripts\install.ps1)
```

### Pre-trained NVD CVSS model

The ML CVSS model (R²≈0.99) ships as a release asset, not in the wheel. Fetch it once (SHA-256 verified):

```bash
heaven download-model --tag v4.1.0
```

HEAVEN runs without it (CVSS falls back to each finding's base score).

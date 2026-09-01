# Changelog

All notable changes to HEAVEN are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Java SAST rules + OWASP Benchmark scoring (devsecops/ci now GREEN).** HEAVEN's
  static-analysis engine gains a real Java rule pack
  (`heaven/vulnscan/sast_rules/java_security.yml`) covering 11 CWE classes:
  taint-tracked command / SQL / LDAP / XPath injection, path traversal, XSS and
  trust-boundary violations (with generic collection/StringBuilder propagators and
  ESAPI/parameterization sanitizers), plus pattern rules for weak randomness, weak
  hashes, weak ciphers and insecure cookies. A new scorer
  (`tests/benchmarks/owasp_benchmark.py`) runs the shipped engine against the
  standard OWASP Benchmark v1.2 (2740 real Java test cases) and computes the
  Benchmark's Youden index (TPR minus FPR) per category and pooled. Live headline:
  pooled Youden about 0.51, recall about 0.96, precision about 0.70, with
  weak-randomness, weak-crypto and insecure-cookie at a perfect 1.00. The corpus is
  GPLv2 so it is fetched (a pinned shallow clone, or `HEAVEN_OWASP_BENCHMARK_DIR`)
  rather than vendored into this MIT tree; ground truth is read from the checkout.
  A gated live test (`tests/benchmarks/test_owasp_benchmark.py`) enforces an honest
  floor, and a Docker-free hermetic test proves the rules separate a genuine vuln
  from a safe look-alike. This takes the `devsecops` and `ci` scan modes to a GREEN
  lab-matrix status (green modes 11 to 13).

- **AWS IAM privilege-escalation path detection.** The authenticated cloud IAM
  audit now flags the scoped escalation primitives a non-admin identity can abuse
  to reach administrator (the Rhino Security / Pacu taxonomy: CreatePolicyVersion,
  AttachUserPolicy, PutUserPolicy, CreateAccessKey, PassRole+RunInstances,
  PassRole+Lambda, UpdateAssumeRolePolicy and more), not only a wildcard `*`/`*`
  grant. Evaluation is deny-wins over the identity's effective actions and is
  read-only. Proven live against a real IAM (LocalStack) via the new
  `--endpoint` / `HEAVEN_AWS_ENDPOINT` override on `heaven cloud iam`.

- **Spec-driven API testing (`heaven scan --api-spec`).** Ingests an OpenAPI /
  Swagger (v2 + v3), Postman collection, or GraphQL introspection document and
  tests every operation it declares, expanding path templates to concrete
  same-origin URLs the crawler could never reach. Includes an authorization-matrix
  planner and analyser (role x operation) that flags broken function-level
  authorization (BFLA) and missing authentication from the observed status codes.

- **YARA-backed malware/webshell signature engine.** A curated ruleset of real
  webshell, backdoor and obfuscated-loader indicators (named shells, eval-from-
  superglobal, China Chopper, JSP/ASPX shells, packed loaders) runs during the
  malware scan's webshell sweep. It uses yara-python when installed and an
  always-on builtin matcher otherwise, so detection is never gated on the native
  library, and every match names which engine produced it.

- **Shellshock (CVE-2014-6271) proven live as the eighth exploit.** A new in-repo
  lab compiles unpatched bash 4.3 from source behind a busybox CGI; HEAVEN's
  exploit engine proves a genuine reverse-callback RCE (root output) against it,
  taking the exploit corpus to 8 of 8 live and the `exploit` scan mode to a GREEN
  lab status. A new `HEAVEN_CALLBACK_HOST` override lets the callback target a
  NAT/redirector/host-gateway address, and the callback listener now reads the
  full command output instead of only the first packet.

- **Live OT breadth (Siemens S7comm).** A Conpot ICS-honeypot lab proves the
  `probe_s7comm` ISO-COTP handshake and Modbus live on their standard ICS ports,
  extending the OT proof beyond Modbus alone.

- **Live Kubernetes lab (real k3s) for CONTAINER mode.** A new in-repo lab boots
  a genuine k3s control plane (real kube-apiserver / etcd / scheduler) started
  with anonymous auth enabled and cluster-admin bound to `system:anonymous` (both
  real, common misconfigurations). HEAVEN's `check_api_server` reads the live
  apiserver on :6443 with no credentials, proving the `k8s_anon_auth` and
  `k8s_secrets_exposed` detectors against a real cluster rather than a unit-test
  double, and taking CONTAINER mode to a second GREEN lab beyond the Docker-API /
  registry one.

- **Reproducible open-relay mail lab (real Postfix) for EMAIL mode.** A new
  in-repo lab boots a genuine Postfix MTA misconfigured as an open relay (a single
  over-broad `mynetworks = 0.0.0.0/0`, so `permit_mynetworks` matches every client
  before any reject, exactly how real open relays happen). HEAVEN's non-intrusive
  SMTP probe detects `smtp_open_relay` live on the raw endpoint (it sends RSET
  before DATA, so no mail is ever relayed) plus `smtp_no_starttls` on the same
  cleartext box, taking EMAIL mode to a GREEN lab status. To make this reachable
  outside the lab, the email scanner gained a direct `scan_smtp_server` /
  `scan_smtp_endpoint` entry point (no MX lookup required) and the orchestrator now
  injects the relay/posture probe whenever a scan finds an open SMTP port on a bare
  host, so an open relay on an internal box is caught even with no MX record.

- **Reproducible Active Directory lab (Samba AD DC) for AD mode.** A new in-repo
  lab provisions a real Samba Active Directory Domain Controller from scratch and
  proves two AD probes live against it: credential-free Kerberos account
  enumeration (`kerberos_user_enumeration`) and MS-RPRN/MS-DFSNM coercion-surface
  detection (`ntlm_coercion`, bind only). It also live-guards the AS-REP-roasting
  false-positive fix (protected accounts are not reported roastable against
  Samba's KDC). This replaces the previous manual, non-reproducible AD validation
  and takes AD mode to a GREEN lab status.

- **Active Directory Certificate Services (AD CS) abuse detection.** The AD scan
  now enumerates the Certificate Authorities and published certificate templates
  over the same read-only LDAP session and classifies them against the ESC abuse
  categories: ESC1 (enrollee-supplies-subject with a client-auth EKU), ESC2
  (Any-Purpose / SubCA), ESC3 (enrolment agent), ESC4 (a low-privileged principal
  can rewrite the template), and ESC8 (an NTLM-accepting web-enrolment endpoint,
  the relay-to-domain-takeover path). Enrolment rights are read from the template
  security descriptor; when the descriptor cannot be parsed the finding is reported
  as a lower-confidence "potential" rather than overclaimed. Read-only throughout:
  it never requests or forges a certificate.

- **Kerberos pre-authentication probe (credential-free).** A new probe validates
  usernames against a Domain Controller with no credentials (the AS-REQ-without-
  pre-auth technique, which cannot lock accounts out) and catches AS-REP-roastable
  accounts, capturing the crackable `$krb5asrep$` hash. This complements the
  existing LDAP-based AS-REP check for a DC reachable only on 88/tcp.

- **NTLM authentication-coercion surface detection.** HEAVEN already flags the two
  ends of a relay chain (SMB signing not required, and AD CS web enrolment); it now
  detects the middle, binding to the MS-RPRN (PrinterBug), MS-EFSR (PetitPotam) and
  MS-DFSNM (DFSCoerce) RPC interfaces to confirm they are reachable. It binds only
  and never issues the coercion call, so no authentication is ever coerced.

- **SAML single sign-on testing.** Alongside the existing OAuth 2.0 checks, the
  authentication scan now discovers SAML/federation metadata and audits its signing
  posture (a service provider that advertises `WantAssertionsSigned="false"` or
  unsigned AuthnRequests), plus a conservative RelayState open-redirect check that
  fires only on a real off-site reflection.

- **Internet-facing edge / VPN appliance KEV fingerprint.** A new pass fingerprints
  Citrix NetScaler/Gateway, Ivanti Connect Secure, FortiOS SSL-VPN, Palo Alto
  GlobalProtect, Microsoft Exchange/OWA and F5 BIG-IP from their distinctive
  cookies, server strings and login paths, and surfaces the actively-exploited
  (CISA KEV) CVEs for each family so a perimeter scan flags the exposure and the
  exact patches to verify. It is framed as an exposure to verify unless a concrete
  vulnerable version is observed, and only ever GETs the login surface.

- **Dual-version CVSS: every finding now carries both CVSS v4.0 and v3.1.** HEAVEN
  scores each finding with CVSS v4.0, the current standard, and shows its CVSS v3.1
  score and vector alongside it (the calibrated score that still drives the severity
  band). Published CVE scores come straight from NVD / OSV, preferring the v4.0
  vector when the advisory carries one; a finding with no published score is scored
  by the ML base-score predictor and then expressed in both versions. The HTML and
  PDF reports show all four CVSS cells (v4.0 base + vector, v3.1 base + vector), the
  finding-detail and findings-list views agree with the reports, and the SARIF
  export carries the v4.0 score as `cvss-v4` / `cvss-v4-severity` next to the
  GitHub-native v3.1 `security-severity`.

- **Live AI model discovery.** The model picker no longer relies only on a built-in
  catalog. For a configured provider it now queries that provider's own model list
  at pick time and merges the live result with the curated defaults, so a
  newly-released model (for example a freshly-published Gemini or a just-pulled
  Ollama tag) shows up without waiting for a HEAVEN release. The merge is additive
  and de-duplicated, and it degrades cleanly to the built-in catalog when a provider
  is unreachable or unconfigured, so a model is always selectable.

- **Hybrid CVSS risk model with a description-based fallback trained on 337k real
  CVEs.** The ML risk scorer is now two models working together. When a finding
  carries real CVSS metrics, the 13-feature ExtraTrees vector model scores it (as
  before). When a finding has no published score (a heuristic web or network
  finding), HEAVEN now uses a new text model — a TF-IDF vectoriser over the
  finding's own description plus vulnerability-type flags, fed to a Ridge regressor —
  trained on the NVD_Cybersecurity dataset. It reads what the finding actually says
  instead of collapsing the class onto a hand-picked constant, so two SQL-injection
  findings with different impact wording get different scores, grounded in how
  hundreds of thousands of real CVEs of that shape scored. It is trained and measured
  on the population HEAVEN actually routes to it — the 315,648 CVEs with a real
  (non-zero) CVSS score, of which the 177,763 that carry a vuln-type flag are the true
  deployment population. On that deployment population honest 5-fold cross-validation
  is R²=0.63 and MAE=0.79, and it lands the right severity band 99% of the time within
  one level. (The ~22k score-0 informational CVEs the model never sees in practice are
  dropped from training rather than left in to inflate R² with trivial zeros; the leaky
  CVSS sub-scores that would push R² to a meaningless 0.999 are also excluded.) The
  model, its metrics and its per-type grounding are documented in
  `data/models/NVD_model.MODEL_CARD.md`; it is trained by
  `heaven train-model --csv <NVD_Cybersecurity_Dataset.csv>` and lives in
  `heaven/ml/desc_model.py`. It degrades cleanly: with the model absent, the hybrid
  uses the vector model for every finding, exactly as before, so nothing regresses
  offline or without the dataset.

- **Severity-band accuracy is now reported for the description model, on the
  population it actually runs on.** R² is a harsh lens for a CVSS predictor — the same
  vuln class genuinely spans a wide score range in the NVD data, so no honest feature
  available at scan time can pin the exact number. What matters is landing the finding
  in the right severity band, and on the deployment population (flagged findings) the
  model does: **70.4% exact band, 98.9% within one band** (5-fold, out-of-fold).
  `heaven train-model`, the model meta and `get_metrics()` now surface both the
  real-finding metrics (`cv_r2` / `cv_mae` / `cv_band_exact` / `cv_band_within1`) and
  the deployment metrics (`deploy_r2` / `deploy_mae` / `deploy_band_exact` /
  `deploy_band_within1`). An exhaustive architecture search (word+char n-grams,
  gradient boosting on a TruncatedSVD of the TF-IDF, MAE-loss linear models, and a
  direct severity-band classifier) confirmed nothing honestly beats this linear text
  model on the deployment population. The score a client actually sees is still
  computed exactly from each finding's CVSS vector (the reference formula, R²=1.0) and
  reconciled to it; the text model is only a ranking hint for scoreless findings,
  pinned to the authoritative severity, so it can never move a report's badge.

### Changed

- **CVSS model retrained under the current scikit-learn, with honest reproducible
  metrics.** The vector model was re-pickled under scikit-learn 1.9.0, which clears
  the 1.8.0 to 1.9.0 version-skew warning (and the risk of silently invalid results
  it warns about) and shrinks the artifact from about 48 MB to about 6 MB with no
  loss of accuracy. Its advertised accuracy is now the figure `heaven train-model`
  actually reproduces from the in-repo dataset, 5-fold cross-validated R-squared 0.91,
  rather than the R-squared 0.9925 earlier docs quoted from a larger, non-reproducible
  dump. The trainer now records cross-validated metrics and the scikit-learn version
  in `metrics.json`, and the README, posters, comparison table and model card all
  state the reproducible number. Because the model binary changed, `download-model`'s
  pinned SHA-256 and size were updated to the retrained artifact; re-upload
  `data/models/NVD_model.pkl` and `cvss_text_model.joblib` to the GitHub Release so a
  fresh `download-model` matches what `train-model` produces.

- **Confidence is shown as a percentage.** Every place a finding's confidence
  surfaces now reads as `0-100%` instead of a raw `0.90`: the Findings, Finding
  detail, Kill-chain and Diff pages, the `heaven findings` / `heaven diff` CLI
  output, and the alert, evidence, Burp and diff Markdown exports. The stored value
  stays `0-1` in the database and in every machine-readable format (JSON, SARIF), so
  this is a display change only; the findings-list "min confidence" filter accepts a
  `0-100` value and converts it before it hits the API.

- **AI false-positive triage now reviews borderline findings concurrently.** The
  optional LLM second-opinion pass used to walk borderline findings one at a time,
  one blocking model round-trip each, so on a service-rich host the triage phase
  spent roughly 112 seconds waiting on the network. It now fans the reviews out with
  bounded concurrency (tunable with `HEAVEN_FP_REVIEW_CONCURRENCY`, default 5),
  collapsing that phase to a few seconds while staying gentle on the provider. The
  borderline-band gate still short-circuits out-of-band findings before any network
  call, a single failed review can no longer sink the batch, and the gateway's
  rate-limit breaker still arms on the first 429 and falls back to the deterministic
  path. A live end-to-end scan dropped from about 240 seconds to 116.

### Fixed

- **Kerberos pre-auth probe no longer reports a false AS-REP roasting finding for
  every account.** impacket's `sendReceive` does not raise on
  `KDC_ERR_PREAUTH_REQUIRED`; it returns the raw KRB-ERROR bytes (that error is the
  expected first step of a normal TGT exchange). The probe read "no exception" as
  "a roastable AS-REP came back", so every pre-auth-required account was flagged
  AS-REP roastable (high). Confirmed live against a real KDC. The probe now decodes
  the reply and only reports roasting for a genuine AS-REP, mirroring impacket
  `GetNPUsers`. The captured hash also now covers AES128/AES256 (etype 17/18) in the
  hashcat layout, not only RC4, so a genuinely roastable AES-only account yields a
  usable hash instead of an empty one.

- **Local-model structured output (Ollama / LM Studio / vLLM) recovers from a
  malformed reply instead of losing the verdict.** When a small local model wraps or
  malforms its JSON past what the brace-extractor can recover, the gateway now
  re-issues the request once with an explicit "return only the JSON object" nudge
  before giving up, rather than treating the parse failure as a hard error. This
  restores the FP-review verdict (and every other structured local call) on models
  that do not reliably emit clean JSON on the first try.

- **A generic Denial-of-Service finding is now scored with an availability vector.**
  A bare `denial_of_service` / `dos` / `ddos` finding resolved to a generic high-severity
  vector implying full confidentiality and integrity loss with **no** availability
  impact (`C:H/I:H/A:N`) — the opposite of what a DoS is — and `denial_of_service`
  carried no CWE. It now has its own knowledge-base entry: an availability-impact
  vector (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, base 7.5), CWE-400 and MITRE T1499,
  with `dos`/`ddos`/`resource_exhaustion` aliased to it. Specific DoS classes
  (`graphql_dos`, `snmp_amplification`) keep their own narrower vectors.

- **CVSS base score and vector no longer come up blank on any finding.** Twenty-three
  knowledge-base vulnerability classes, mostly web, client-side, session and mail
  issues, had no vector in either the v3.1 or the v4.0 table, so on a web-heavy
  engagement it could look like "every finding is blank." Faithful v3.1 and v4.0
  vectors were authored for all of them (both tables are now key-aligned with the
  knowledge base, scores computed with the reference `cvss` library and verified in
  range), and finding enrichment now always falls back to a severity-band generic
  vector, so no finding is ever left without a score. Generic band vectors that had
  drifted (a generic "high" that scored up into the Critical band) were re-authored
  to score inside their own band, and the HTML / PDF / compliance reports and the
  findings-list endpoint now enrich findings the same way the detail view does, so
  the list, the detail page and the report never disagree.

- **`heaven scan` no longer double-counts persisted findings.** The command summed
  two summary keys that both point at the same deduplicated list, so it reported
  twice the real number (for example "Persisted 126 findings" for 63 real ones; the
  database itself was always correct because the upsert is idempotent). It now
  reports the true count.

- **The NVD vulnerability-mapping task no longer pollutes the finding stream.** That
  task publishes a broad, CPE-keyed CVE catalog for threat intelligence, but it did
  so under a key the finding collector treats as findings, so hundreds of
  identity-less catalog entries flashed through the live scan view as zero-confidence
  blanks, inflated the running findings counter mid-scan, and were then all discarded
  by de-duplication (they have no stable identity). The catalog is now kept separate
  from the finding stream, and its CISA KEV and EPSS threat-intel is cross-referenced
  onto the real findings by CVE id after de-duplication (filling gaps only), so the
  intelligence is preserved without ever appearing as a phantom finding.

- **The AI false-positive review no longer stalls or fails hard when the model
  provider is overloaded.** A provider that answers with an overload or deadline error
  (for example Gemini's `504 DEADLINE_EXCEEDED`, or a `503 UNAVAILABLE`) used to be
  retried the full budget, three attempts each waiting out the request timeout, and
  still fail; on a bulk pass every borderline finding repeated that against the same
  busy provider. Such errors are now their own class: a genuine one-off blip clears on
  a single quick retry, an interactive "second opinion" fails fast instead of waiting
  minutes, and a provider that stays overloaded arms a short, self-clearing cooldown so
  the rest of the pass falls back to the deterministic path immediately rather than
  hammering the provider. The window is much shorter than the quota breaker's (overload
  clears in seconds) and is tunable with `HEAVEN_LLM_OVERLOAD_COOLDOWN`. A busy provider
  never causes a real finding to be dropped: an unavailable verdict simply leaves the
  finding untouched.

## [3.1.0]: 2026-08-27

### Added

- **Read-only active checks for four high-value network services.** The Network
  Service Exposure scan now confirms, without exploiting anything, four
  misconfigurations a banner-only pass cannot see. NFS shares exported to the
  world are read off the wire with an ONC-RPC MOUNT dump (the equivalent of
  `showmount -e`), and a follow-up read-only NFSv3 ACCESS query reports whether an
  anonymous client is actually granted write access, so the finding states
  read-write or read-only instead of guessing from the export list (nothing is
  created, written or deleted). Apache Tomcat Manager default credentials are
  checked against a 401 baseline so only a credential that truly authenticated is
  reported, and nothing is deployed. PostgreSQL default and weak superuser
  credentials are checked by connecting and closing with no query. VNC servers are
  flagged when they require no authentication or accept a default password. Every
  probe reports only what a live response proved, tears the session down at once,
  and is gated off in the stealth and paranoid profiles.

- **DeepSeek is now a first-class LLM provider.** Set `HEAVEN_LLM_PROVIDER=deepseek`
  and `DEEPSEEK_API_KEY` to route the AI layers (autonomous mode, attack plans, LLM
  false-positive review, chat, remediation) through DeepSeek's OpenAI-compatible
  Chat Completions API. It rides HEAVEN's built-in HTTP client, so there is no
  extra SDK to install; the default model is `deepseek-chat` (`deepseek-reasoner`
  is also offered in the model picker), the base URL defaults to
  `https://api.deepseek.com` and is overridable with `DEEPSEEK_BASE_URL`. The key
  is sent only as an `Authorization` header and never logged; auto-detection,
  the Settings provider dropdown, the model picker, `heaven init`, the deterministic
  no-key fallback, and the rate-limit circuit breaker all recognize it. The LLM
  stays advisory: HEAVEN's deterministic scanners remain the source of truth.

- **True one-command install.** `scripts/install.sh` and `scripts/install.ps1` now
  self-bootstrap: run them straight from a pipe with no prior clone
  (`curl -fsSL <raw>/scripts/install.sh | bash` on macOS/Linux,
  `irm <raw>/scripts/install.ps1 | iex` on Windows) and the installer clones the
  repo (into `./HEAVEN-Autonomous-Penetration-Testing`, override with `HEAVEN_DIR`)
  and re-execs itself from inside it. Run from an existing checkout it is a no-op,
  so the documented `git clone` + `./scripts/install.sh` flow is unchanged. From
  there the installer still does the whole job unattended: virtualenv, every
  runtime dependency, the external scanner tools, the web UI, and a ready-to-use
  `.env`.

- **Methodology coverage now links to the findings that exercised each test.**
  The Methodology page's live overlay already flagged which standard tests an
  engagement exercised; now every exercised row is **clickable** and expands to
  show the concrete findings that lit it, severity, title, target, each a link
  straight to the finding detail (an "expand all" toggle reveals them across a
  whole standard at once). The overlay carries the real finding identities end to
  end (`heaven/methodology.py` attaches `findings` refs per row; the API + CLI
  projections now pass `id/title/severity/target`), so the page, the CLI and the
  downloads never disagree. **Every aligned finding is shown**, the row count is
  the number of *distinct* findings (it no longer double-counts a finding that
  names several detectors), so the page never advertises a phantom "+N more". Each
  standard's live matrix can also be **downloaded** as a standalone, printable
  coverage report, now including **PDF** alongside HTML / Markdown / JSON, via
  `GET /api/methodology/export`.

- **Compliance reports mapped to your findings, now 10 frameworks: HIPAA, UK GDPR,
  EU GDPR, PCI DSS v4.0.1, ISO/IEC 27001:2022, SOC 2, NIST CSF 2.0, Cyber
  Essentials, Cyber Essentials Plus, CIS Controls v8.1.** A new
  `heaven.devsecops.compliance_frameworks` registry maps every finding onto a
  framework's controls by matching its **CWE, OWASP-2025 category and vuln_type**
  (grounded, never fabricated), and the professional report gains a **control-
  coverage matrix** for a chosen framework (present / not-observed per control,
  with the mapped findings linked). It is explicitly a *coverage view, not an
  attestation of compliance*. Available in the **HTML, PDF and Markdown**
  deliverables via the `framework` export param, downloadable per framework from
  the **Compliance-mapped report** card on the Reports page. Governance / physical
  / policy controls a remote scan can't evidence are listed and honestly show
  "Not observed".

- **New Compliance page, a live, per-control coverage view (the control analogue
  of the Methodology page).** A dedicated **Compliance** section (under Reporting)
  shows each framework's controls with the ACTIVE engagement's findings mapped onto
  them, control-by-control, with click-through to each finding and an "expand all"
  toggle, and downloads the live matrix as **HTML / PDF / Markdown / JSON** per
  framework. Backed by `GET /api/compliance/coverage` and `GET
  /api/compliance/export`; `GET /api/compliance/frameworks` lists all ten.

- **Provider-aware AI model picker (Settings).** The LLM model was a free-text box
  you had to type a model id into, so "I can't select the model." It's now a real
  chooser: a dropdown of the chosen provider's known models (Claude Opus 5 /
  Sonnet 5 / Haiku 4.5, GPT-4o / mini / o3-mini, Gemini Flash/Pro latest, and your
  actually-pulled Ollama models), a "provider default" option and a "Custom…"
  escape hatch for any id. With no provider chosen it lists **all** providers'
  models grouped, so a model is always selectable. Backed by a new
  `GET /api/ai/models` catalog (shared with the gateway via
  `llm_gateway.known_models`); it writes the same `HEAVEN_LLM_MODEL` setting, so
  the CLI and `.env` stay in sync.

- **Update HEAVEN from the web app.** A new **Updates** settings group adds an
  opt-in **auto-check** toggle (`HEAVEN_UPDATE_AUTO_CHECK`); when on, the web app
  checks the git remote on load and shows an **"update available" banner**
  (vX → vY, commits behind) at the top of every page. An admin can apply the
  update in one click, **Update now** in the banner or the Settings → Updates
  panel, with a live progress log. It reuses the exact, tested `heaven update`
  core: fast-forward only, **never overwrites uncommitted work**, honest about a
  non-git install, and it never restarts the server (the new code is active after
  the next `heaven serve`). New endpoints: `GET /api/update/status`,
  `POST /api/update/apply` (admin), `GET /api/update/apply/status`. Because
  applying from the browser means running new code on the server, it is gated by a
  deploy-time kill switch **`HEAVEN_DISABLE_WEB_UPDATE=1`** (for shared / hosted
  deployments), detection still works, but applying must then be done from the
  shell. The switch is read from the environment (not web-editable) and enforced
  server-side, not just hidden in the UI. Documented in `.env.example` +
  `SECURITY.md`.

- **Egress routing, send scanning traffic through TOR / VPN / WireGuard while
  the dashboard stays local.** A new `heaven.net.egress` module routes HEAVEN's
  *outbound scanning* traffic through an operator-configured anonymity path,
  legitimate OPSEC for an **authorized** engagement, while the FastAPI dashboard
  and API stay bound to localhost. Two mechanisms, no new dependencies:
  - **WireGuard tunnel mode** (`HEAVEN_EGRESS_MODE=wireguard`), network-layer,
    the complete path: it carries *every* tool transparently (raw nmap SYN/UDP/OS
    scans, the nuclei binary, and every in-process aiohttp/httpx check) with no
    per-tool config. HEAVEN raises/drops the interface via `wg-quick` using the
    same passwordless-`sudo -n` policy nmap uses; the WireGuard config is
    referenced by path so its private key never enters HEAVEN's settings.
  - **Proxy mode** (`http` / `socks5` / `tor`), application-layer: nuclei
    (`-proxy`) and ffuf (`-x`) get native proxy flags; nmap is auto-switched to a
    proxychains-wrapped TCP connect scan (`-sT`, since raw scans can't traverse a
    proxy); HTTP proxies also propagate to httpx/`requests`/subprocess tools via
    the exported `*_PROXY` env. The in-process aiohttp scanners route through a
    shared `client_session()` wrapper, **HTTP proxies via `trust_env`, and
    SOCKS5/Tor through a built-in SOCKS5 connector** that speaks the RFC 1928
    CONNECT handshake on a raw socket, so aiohttp tunnels through SOCKS/Tor with
    **no new dependency** and DNS resolves at the proxy (no local leak). Verified
    end-to-end against a loopback SOCKS5 proxy. (No-auth SOCKS only in-process; an
    authenticated proxy or raw SYN/UDP scans need WireGuard.)
  - **Kill-switch (on by default) + leak check.** Before any packet leaves, a
    scan confirms the armed egress is actually carrying traffic (the apparent
    public IP differs from the direct baseline) and **aborts cleanly** otherwise
, a dropped tunnel or dead proxy can never leak the real IP. Cases a proxy
    genuinely can't cover *fail closed* rather than bypass: the nmap port scan +
    host discovery are skipped when proxychains is unavailable, and in-process
    HTTP is skipped only if the SOCKS connector itself can't be built. A SOCKS
    URL is never exported to `*_PROXY` (that would crash env-trusting httpx with a
    missing-backend `ImportError`); enrichment traffic (NVD/OSV/threat-intel/LLM)
    stays direct under a proxy by design and rides the tunnel under WireGuard.
  - Surfaced everywhere the rest of HEAVEN's config is: a new **Egress /
    anonymity** group on the web **Settings** page with live **Confirm egress**
    (leak check) and **Tunnel up/down** actions; a `heaven egress`
    CLI (`status` / `confirm` / `up` / `down` / `set`); and
    `GET /api/egress`, `POST /api/egress/confirm`, `POST /api/egress/tunnel`.
    Config persists to the shared `.env`, so a value set in the browser, the CLI
    or `heaven config` is live everywhere. Default (`off`) is a transparent
    no-op, existing scans behave exactly as before.

- **Resume an interrupted scan from the dashboard.** A scan the app was closed on
  (or that a killed process abandoned) is now reconciled to an **interrupted**
  state at server startup, the perpetual, ticking "running" scan with no work
  behind it is gone, and can be continued from its last checkpoints with a new
  **▸ Resume** button in Scan Activity (`POST /api/scans/{id}/resume`, mirroring
  the CLI `heaven resume`). The web resume replays the stored, deterministic scan
  config through the same checkpoint machinery, skipping tasks that already
  completed. "Cancel" now actually cancels the running task (it previously only
  relabelled it), and cancelling or removing an unfinished scan **preserves its
  checkpoints** so it stays resumable instead of being destroyed.

- **Assets, device identity: MAC address, auto device type, manual override.**
  The host inventory now shows a host's **MAC address** on a local scan: the ARP
  address from the nmap discovery sweep (previously parsed for liveness then
  discarded) is threaded through to the host, and for any on-segment host still
  missing one, HEAVEN reads the OS's own ARP/neighbour table (`ip neigh` / `arp`,
  no new dependency), a real layer-2 fact our scan traffic populated. A host's
  **device type** is now inferred from the services it exposes (RDP/SMB → Windows
  host, 9100/515 → printer, RTSP → IP camera, Modbus/S7 → OT/ICS, MQTT → IoT, …)
  when no nmap `-O` class or MAC-vendor category is available, and each value is
  labelled by how it was learned. Where the scan can't observe a name or type, an
  operator can **set them manually** (inline "✎ Edit" on each Assets card,
  `PATCH /api/assets/label`); operator-set values rank above any inference and
  flow through to the report. No hostname is ever fabricated.

- **Content Discovery report section.** Directory/file brute-forcing hits
  (200 / 3xx / 401 / 403 …) are now consolidated into a dedicated **Content
  Discovery** table in the HTML and PDF reports, Path · Status · Severity · URL, 
  so every interesting directory is listed together instead of scattered through
  the detailed findings, and a 3xx hit records where it redirects.

### Fixed

- **The GraphQL denial-of-service checks no longer fire on a server that already
  enforces its limits.** The query-complexity check reported "No Query
  Depth/Complexity Limit" on any HTTP 200, and the batching check reported
  "Unlimited Query Batching" on any list of more than 50 entries. A properly
  hardened GraphQL server answers 200 with an errors array that rejects the deep
  query ("depth 8 exceeds maximum of 5") or rejects the batch, so both were live
  false positives against a depth-limited, batching-disabled endpoint. A finding
  now requires the query to have been accepted: complexity suppresses when the
  response carries a depth/complexity/cost rejection error (and is downgraded to a
  medium verify-me signal, since a 200 to an introspection depth query is not by
  itself proof of a missing limit), and batching counts only entries the server
  actually processed, not error entries. Verified against a local vulnerable API
  (both still fire) and a depth-limited one (both now silent);
  `tests/test_api_graphql_fp.py`.
- **Cloud bucket hunting no longer derives candidate names from an IP address.**
  Scanning an IP target directly (for example the Metasploitable host at
  192.168.0.162) turned the octets into guesses like `192-assets` and `0-backup`.
  A bare IP has no registrable domain label, so any hit could only be an unrelated
  third party's bucket mis-attributed to the target as a critical exposure, the
  same false-positive class the reserved-name guard already blocks. IPv4 and IPv6
  literals now produce no candidates. Live `heaven cloud storage http://192.168.0.162/`
  went from 60 mis-targeted probes to zero; `tests/test_cloud_scanner.py`.
- **The finding detail no longer contradicts itself.** The "Proof of Issue" panel
  rendered the ML predictor's raw scoring fields (predicted CVSS, priority score,
  risk band) straight from the finding evidence, so a banner-inferred finding could
  show "risk band: high" beside a reconciled Medium severity, along with a second,
  different priority number. Those model intermediates are now kept out of the
  observed-evidence block, since the header already shows the reconciled,
  authoritative scores, and the internal risk band is pinned to the reconciled
  severity on read, so no surface can disagree with the severity badge.
- **Terrapin (CVE-2023-48795) is no longer reported on OpenSSH releases that
  cannot be attacked.** The check flagged every OpenSSH below 9.6, but the attack
  only works against a connection negotiating ChaCha20-Poly1305 or an
  Encrypt-then-MAC mode, which OpenSSH gained in 6.5 and 6.2. Releases before 6.2
  (for example the 4.7p1 on a classic Metasploitable host) support neither and
  were a live false positive; the affected range now starts at 6.2.
- **A service exposed on more than one port is reported once, not once per port.**
  A version-matched CVE is a property of the running daemon, so the same finding on
  Samba's 139 and 445 (or a web server on 80 and 443) now collapses into a single
  entry that lists the extra ports, keeping the more precise version fingerprint.
  Two genuinely different builds (different precise versions) still stay distinct.
- **File-upload findings carry a full taxonomy, and two OWASP labels were corrected.**
  Unrestricted file upload now resolves to CWE-434 with the A06:2025 Insecure Design
  category and a matching CVSS vector instead of a blank OWASP cell. A legacy-Flash
  finding that carried the retired "Vulnerable and Outdated Components" label (which
  silently normalised to the wrong 2025 category) is now tagged A03:2025 Software
  Supply Chain Failures, and a padding-oracle label was corrected to the canonical
  spelling. A regression guard now pins every knowledge-base OWASP label to its
  canonical 2025 form.
- **Remote File Inclusion is no longer reported when the server refused the fetch.**
  The RFI probe supplies an unroutable URL and looks for PHP echoing an
  `include(http://<host>/...)` warning that names it. On a hardened host with
  `allow_url_include` disabled (the PHP default), the interpreter still echoes that
  warning but adds "URL file-access is disabled in the server configuration" and
  never fetches, so a target that cannot be remotely included was flagged high-risk
  RFI. The check now recognises that refusal (the disabled-wrapper notice, or "no
  suitable wrapper could be found") and stays silent, while a genuinely includable
  host, which fails on the network rather than on configuration, still fires.
  Confirmed against a live DVWA/PHP 5.2 target, where the false positive was found.
- **A slow target no longer wipes out every injection finding.** The XSS/SQLi
  sweep ran unbounded until the orchestrator's hard per-task timeout cancelled it,
  which discarded every finding gathered so far and reported zero injection on an
  app full of it, then skipped the dependent IDOR scan as "failed". This surfaced
  on a heavily loaded emulated target where the sweep could not finish in time. The
  scanner now honours a soft wall-clock deadline (90% of the task timeout): when it
  is reached, the sweep returns the findings it already proved instead of losing
  them, and the IDOR scan still runs. It also scans URLs that carry an injectable
  surface (a query string or a POST form) before bare, param-less pages, so a
  truncated sweep spends its budget where a finding can actually surface. Confirmed
  live against DVWA: a 20-second budget over the full 31-URL surface returned nine
  real findings (command injection, SQLi, reflected and stored XSS, LFI) instead of
  nothing.


- **CI is green again: mypy, the unit-test matrix, and the Docker image build.**
  Three real `mypy` errors were fixed (a dynamic `TraceConfig` marker in
  `heaven/net/throttle.py`, and a variable-type clash in the AI-layer endpoint in
  `heaven/api/server.py`). A flaky unit test (`test_update_apply_runs_and_reports`,
  failing only on the loaded 3.11 runner) traced to a real bug: the web "Update
  now" background task was launched with `asyncio.create_task(...)` **without
  keeping a reference**, so under GC pressure it could be collected mid-flight and
  cancelled, leaving the apply reporting `done` but not `ok`. The apply task (and
  the replay-scan task, which had the same latent bug) now hold a strong reference
  until completion, matching the pattern the scan/autonomous/watch tasks already
  use. With the test job passing, the Docker image build (which `needs` it) no
  longer skips.

- **IP addresses are shown for website / webapp targets, in the report and the
  Assets view.** When the target was a hostname the inventory only ever showed the
  domain; the resolved **IP address** is now recorded and displayed alongside it
  (an `IP:` line in the HTML / Markdown / PDF report inventory, and an IP chip on
  the Assets page). `inventory.normalize_assets` keeps the hostname label distinct
  from the address, captures a scan-supplied IP, and best-effort-resolves the A
  record when none was supplied (cached, hard-timeout, and skippable on air-gapped
  hosts with `HEAVEN_NO_DNS_RESOLVE=1`). The **sample data** (`heaven demo` /
  "Load sample data") now ships a small host/service inventory too, so the Assets
  page and the report's Host & Service Inventory populate out of the box, with the
  web-app host shown as its hostname *and* the IP it resolved to, so the feature is
  visible in the demo without running a live scan.

- **Complete proof on every finding detail.** The "Observed" block for a
  non-HTTP finding (DNS / TLS / exposed-service / host-level) previously rendered
  only a raw captured-output string, so the real evidence HEAVEN captured (the
  banner, port, service, records, policy values) was missing from the UI and many
  such findings showed *no* concrete proof at all. The **Proof of issue** card now
  renders the full observed-evidence set as a readable key/value table (matching,
  and going beyond, the written report), and both the HTTP and non-HTTP proof
  cards explain what the evidence is and how to reproduce it.

- **"LLM false-positive review" no longer claims the AI is unavailable when it is
  configured.** A manual, operator-requested second-opinion review returned
  *"LLM review is unavailable, add a provider key"* whenever the finding's
  confidence sat **outside the automatic 0.40-0.70 review band**, even with a
  provider fully configured. The band gates only the cost-bounded *bulk* pass; a
  manual review of one finding now **forces** past it (`FPReviewer.review(...,
  force=True)`), and the endpoint returns an **honest reason**: the "add a
  provider key" message appears only when no provider is actually configured.

- **Out-of-scope subdomains are no longer actively scanned.** A single host/URL
  target (`https://example.com`, or a bare `example.com`) authorised its *entire*
  subdomain tree for the closed-loop feedback engine, so a one-host engagement
  silently expanded into active port/web scans of every discovered subdomain, 
  many resolving to third-party infrastructure (a mail provider, a CDN, a SaaS)
  the operator never authorised. `ScopeGuard` now grants subdomain-wide scope
  **only** for a deliberate domain target (the `domains` bucket, or an explicit
  `*.example.com` / `.example.com`); URL/host seeds authorise exactly that host.
  Certificate-Transparency (crt.sh) and cert-SAN discovered names are also
  liveness-verified before being surfaced, so long-dead ghosts no longer inflate
  the discovered-subdomain count.
- **Subdomain *discovery* now follows the same scope rule as scanning.** Previously
  even a single-host target still ran full subdomain enumeration (CT-log + DNS
  brute-force) against the whole registered domain, discovering, counting and
  logging *hundreds* of adjacent subdomains it would never scan (e.g. a
  `https://example.com` scan logging "Subdomain enumeration: 147 found"), while
  the DNS-inventory panel showed a different, smaller resolving-only list, two
  inconsistent numbers for one engagement. Subdomain enumeration (the deep-recon
  CT/brute path **and** the DNS-inventory subdomain brute-force) now runs only
  when the operator authorised subdomain-wide scope, via the new
  `ScopeGuard.allows_subdomains()`. An exact-host engagement therefore discovers
  no adjacent subdomains in *either* path (DNS records for the target are still
  enumerated); a domain/wildcard target enumerates as before. The CLI
  `heaven dns <domain>` is unaffected, it still brute-forces on demand.
- **Catch-all / soft-404 servers no longer produce phantom `SENSITIVE_FILE`
  findings.** On a site whose framework redirects (or 200-serves) every unknown
  path to its homepage, `/phpmyadmin/`, `/adminer.php`, `/backup.zip`, … were
  reported as exposed and even "confirmed". Two fixes: the directory fuzzer's
  soft-404 calibration is now redirect-aware and consistent with how it probes
  (it recognises "unknown path → homepage" catch-alls and drops them), and the
  Active-Confirmation endpoint check calibrates against a random sibling path,
  rejects a probe that redirects to the homepage, and requires a real content
  signature for named tools (phpMyAdmin/Adminer/phpinfo), so a homepage served
  at `/phpmyadmin/` is never confirmed as phpMyAdmin.
- **Directory-discovery severity is now status-aware.** A `401`/`403` on a
  sensitive path (e.g. a blocked `.env` / `.git/config`) was rated *critical
  "Exposed …"* when a 403 means the file is **protected**, not exposed. Such hits
  are now honest low/`info` discovery ("Access-controlled resource (403), …");
  the critical/high "exposed" ratings apply only when the resource is actually
  served (2xx).
- **Vulnerable dependency in the screenshot tooling (extract-zip / CVE-2026-56876)
  removed.** `scripts/screenshots` pulled `extract-zip@2.0.1` transitively through
  `puppeteer-core@^24` → `@puppeteer/browsers@2.x`; that release is affected by
  CVE-2026-56876 (symlink path traversal, HIGH) with **no fixed version published**.
  Bumped `puppeteer-core` to `^25` (and pinned `@puppeteer/browsers >=3.0.2` via
  `overrides`), the 3.x line dropped the `extract-zip` dependency entirely, so it
  is gone from the tree. `npm audit` on the regenerated lockfile now reports **0
  vulnerabilities**; the tool launches Chrome via `executablePath`, so the upgrade
  is behaviour-neutral.
- **False-positive findings are excluded from the report.** A finding triaged as
  `false_positive` still appeared in every downloaded report (HTML / PDF / Markdown
  / JSON …) because the export read *all* findings. It is now dropped from the
  deliverable across the web export endpoint and the `heaven report` / `heaven
  export` CLI paths (the latter still honours an explicit `--status false_positive`
  for auditing them).
- **PDF export no longer fails with the misleading "reportlab installed?" and one
  bad finding can't sink the whole report.** When the PDF build raised for *any*
  reason it silently fell back to writing an empty `.pdf`, and the API surfaced the
  generic "PDF generation failed (reportlab installed?)" even though reportlab was
  present. The web export now runs the generator in **strict** mode and returns the
  *real* error, and each finding renders defensively, a single malformed finding
  degrades to a minimal safe block instead of aborting the export.
- **Report polish, layout, truncation and per-finding proof.** Fixed several
  presentation defects seen in the rendered PDF: the Findings-summary "CVSS" column
  header wrapped to "CVS/S" (widened), the detail label "Contextual CVSS
  (temporal+environmental)" broke mid-word (shortened to "Contextual CVSS"; the
  definition stays in the glossary), candidate-CVE scores showed
  binary-float noise like `9.2000000000001` (now formatted to one decimal), and the
  remediation-roadmap action was cut mid-word, "Rotate any s…" (now trimmed at a
  word boundary). **Every finding now carries a proof/evidence block**: explicit
  artefacts (payload / request / response / curl / proof) when present, otherwise a
  synthesised, honest one, an *Observed* summary, the detection rationale, and a
  read-only reproduce command, so no finding is left without a "how this was
  determined". HTML and PDF share one resolver, so they stay identical.
- **Operator notes save without a status change.** The triage note only persisted
  as a side effect of a status change, so a note typed while leaving the status
  unchanged (or re-clicking the current status, which is disabled) was silently
  lost. Added an explicit **Save note** action (`PUT /api/engagement/findings/{id}/
  notes` + `EngagementStore.set_finding_notes`) with saved / unsaved-changes
  feedback; a status change still saves the note too.
- **Findings filters persist across navigation.** The Findings page filter
  selection (severity / status / target / min-confidence, plus sort and group-by-
  host) reset to defaults every time the operator opened a finding and came back,
  because it was ephemeral component state. It is now backed by a small
  `usePersistentState` (sessionStorage) hook, so the chosen view survives in-tab
  navigation and reloads.
- **End-of-life operating systems (e.g. Windows 10) are now flagged.** The EOL
  scanner already knew Windows 10 (past its 2025-10-14 end of support), but the
  detected OS string routinely collapsed to a generic "Windows" that no EOL rule
  could match: an OS-level CPE was mapped version-less and the precise, root-free
  `smb-os-discovery` OS line (e.g. *Windows 10 Pro 19041*) was mined only for the
  computer name. HEAVEN now preserves the release from a Windows OS CPE
  (`windows_10` → "Windows 10", `windows_server_2008` → "Windows Server 2008", …)
  and reads the SMB-advertised OS string, so an end-of-life OS raises an
  `unsupported_software` finding (CWE-1104) that flows into the report, kill chain
  and methodology. Added conservative EOL rules for old macOS (10.x); a
  version-less "Windows" is still never flagged (that would be a guess).

- **Operator-set device names/types now show in the CLI inventory and report,
  not only the web report.** A manual label (Assets "✎ Edit" → `host_labels`) was
  overlaid at the web asset choke point but the CLI path (`heaven assets`,
  `heaven report`) read raw scan assets without it, so the same engagement showed
  the operator name/type on the web but not in a CLI-generated report. The CLI
  collector now applies the same `merge_host_labels` overlay at its single
  read point, so a manually-set name/type is reflected everywhere the inventory
  is rendered.

- **The hero poster stat figures can no longer silently drift.** The marketing
  poster SVGs (`docs/assets/heaven-poster*.svg`) still advertised a stale "1856
  tests · 55 CLI commands · 77 API routes" long after the code had grown, because
  `scripts/sync_test_count.py` only rewrote the README and left the posters to be
  hand-maintained. The sync tool now rewrites the three mechanically-derived
  counts in both posters too, in the stat block (anchored by each `<text>`
  node's design position) and in the accessibility `aria-label`, and CI's
  `--check` now fails on a stale poster, so the figures stay honest. The two
  hand-set poster figures (UI pages, scan modes) have no collector and are left
  untouched.

- **Exposed-database findings no longer double-report, and their severity is
  now honest.** A directly-reachable database service was flagged by two
  detectors under two reversed spellings, `network_exposure` emitted
  `database_exposed` (rich evidence, public-host-scoped) while the orchestrator's
  per-port `_db_check` emitted the reversed `exposed_database` with an empty
  evidence blob, so a single exposed MySQL/Postgres surfaced **twice** and never
  deduped. The orchestrator now emits the canonical `database_exposed` slug with
  evidence, so the two collapse to one finding (the richer copy wins) while an
  internal-host DB exposure, where `network_exposure` stays silent, is still an
  evidence-backed finding. Severity is now context-aware: an **auth-gated** engine
  (MySQL/Postgres/MSSQL/Oracle) reachable from a public address stays **High**,
  while a **no-auth-by-default** engine (Redis, MongoDB, Elasticsearch, Memcached,
  CouchDB, Cassandra) exposed to the public Internet is **Critical**, and the
  label survives `reconcile_severity` because the finding pins a matching
  `typical_cvss` (a bare "critical" with no score was previously realigned back
  down to the class's High band). No inflation: an authenticated database is not
  forced to Critical just because it is reachable.
- **The Anomaly Probe can no longer dominate a scan when the target throttles
  us.** On a heavy full scan a defensive target starts silently dropping our
  connections; the Anomaly Probe (the highest-request-volume web task) would then
  stall every request to its connect timeout and burn its **entire 600 s budget
  for zero extra findings**, accounting for more than half the wall-clock of a
  full scan. It now uses a short per-request connect timeout, a monotonic
  wall-budget that stops the sweep early once the target is plainly not
  answering, and a consecutive-stall breaker, with the hard task ceiling lowered
  from 600 s to 300 s. A healthy target is unaffected (it answers fast and the
  budget is never reached); a throttling one no longer holds the whole scan
  hostage.

### Added

- **Candidate-CVE awareness table on version-undetermined services.** When a
  service advertises a product but *no version* (e.g. Bluehost's `Server: Apache`,
  which strips the version), HEAVEN deliberately does **not** assert every product
  CVE as a confirmed Critical, an unverifiable version-specific RCE has no place
  in a client report. It collapses them to one honest **low** `potential
  vulnerable service` finding. That finding is now genuinely *useful*: it carries
  a **candidate-CVE table** naming every CVE known for the product with its
  published CVSS, severity, the **affected-version range each one requires**, CWE,
  whether a public exploit exists, and an NVD reference, plus a one-line,
  product-specific *"how to confirm the running version"* hint. You get full
  awareness of what the service *might* be vulnerable to (and exactly which
  version each CVE needs) without any of them being mislabelled as present. The
  table renders in the web Finding Detail page, the HTML and PDF reports, and the
  Markdown/CLI export; the finding stays low and never inflates the Critical/High
  count. (`cve_mapper._candidate_details` / `_version_confirm_hint`;
  `evidence.EvidencePackage._candidate_cve_markdown`;
  `tests/test_candidate_cve_awareness.py`.)

---

## [3.0.0]: 2026-08-17

### Added

- **OWASP Testing Guide (WSTG v4.2) coverage is now fully automated, every
  technical test runs a real detector.** The `§ Methodology Coverage` OWASP page
  previously marked ~half of the 86 technical WSTG tests as *manual/partial*.
  Root cause: two scanners that run on every web scan (`web_fuzzer`,
  `misconfig_scanner`) emitted real, confirmation-based findings but were never
  wired into the methodology map, and the mapping doc credited several tests to
  the wrong module. That is fixed, and the remaining genuine gaps were filled
  with new, evidence-only probes:
    - **New `heaven/vulnscan/client_audit.py`**, static analysis of a page's own
      HTML + inline/linked JS: source/comment secret review (WSTG-INFO-05),
      DOM-XSS source→sink (CLNT-01/02), insecure `postMessage` (CLNT-11),
      sensitive `localStorage`/`sessionStorage` (CLNT-12), XSSI (CLNT-13), CSS
      injection (CLNT-05), client-side resource manipulation (CLNT-06), legacy
      Flash (CLNT-08). Wired into the web scan phase.
    - **`misconfig_scanner`** gains dedicated clickjacking (CLNT-09), RIA
      cross-domain policy (CONF-08), password-field autocomplete (ATHN-05),
      sensitive-page cache-control (ATHN-06), session-token-in-URL (SESS-04) and
      a conservative CBC padding-oracle probe (CRYP-02).
    - **`web_fuzzer`** gains SSI injection (INPV-08) and mail-header/CRLF
      injection (INPV-10); **`auth_scanner`** gains open-registration/provisioning
      (IDNT-02/03), security-question reset (ATHN-08) and alternate-auth-channel
      (ATHN-10) surrogates; **`injection_scanner`** gains a stored-XSS
      inject-and-refetch probe (INPV-02/14).
  All new finding types carry full OWASP-2025 / CWE / CVSS taxonomy. The page now
  reports **86/86 technical tests automated**; only **Business Logic** remains
  analyst-led (it requires application-specific domain knowledge, HEAVEN never
  fabricates a verdict it cannot evidence). Verified live against a
  Metasploitable 2 target (84/86 rows exercised with real findings; the two
  unlit rows genuinely have no footprint on that host).
- **Every remaining Methodology Coverage framework is now fully automated too, 
  honestly.** The nine non-WSTG standards (NIST SP 800-115, PTES, Cyber
  Essentials + Plus, ISO/IEC 27001:2022, PCI DSS v4.0.1, CIS Controls v8.1, NIST
  CSF 2.0, SOC 2) previously showed large *partial/manual* counts. The cause was
  the same family of mapping bugs as WSTG: a real emitter left unmapped
  (`heaven/recon/firewall_detector.py`'s `perimeter_defense` lit no row, now
  wired), a literal-pipe table-parsing bug (NIST §6.3), real tool features not
  named in their cell (NIST §6.5/§6.6/§8.3, PTES target-selection/RoE/pillaging),
  over-modest "partial" qualifiers on detectors that do the whole external job,
  and a wrong module path (`devsecops.sca_scanner` → `vulnscan.sca_scanner`).
  Every **technically-assessable** control is now genuine **AUTO**, named to a
  real, pre-existing detector (`network_exposure`, `cve_mapper`, `eol_scanner`,
  `sca_scanner`, `sbom`, `inventory`, `access_control`, `firewall_detector`,
  `watcher`, `alerting`, `retest_report`, …). Controls no remote/credentialed
  scan can evidence (governance, physical, endpoint anti-malware, target-side
  audit-logging, social engineering, on-wire sniffing, MFA/IdP config) are
  consolidated per theme into an honest **out-of-band (analyst-attested)** prose
  note, 0 counted rows, exactly like WSTG's Business Logic, never fabricated as a
  scan result. All ten standards now report **0 partial / 0 manual**. Verified
  live against Metasploitable 2 + DVWA (`192.168.0.162`).
- **Firewall / IDS-IPS aware scanning, still get findings through a filtering
  perimeter.** The network scanner now tells a stateful firewall (which *drops*
  probes → nmap `filtered`) apart from a normal host (which *refuses* them → TCP
  `closed`/RST) and, for a host whose ports are being silently filtered, runs a
  bounded, **authorized** evasion re-probe of the high-value ports, packet
  fragmentation, padding, a trusted source port (53) and decoys via nmap, plus an
  independent pure-Python connect-scan second opinion, that routinely recovers
  services the naive scan could not see (the classic "the box is clearly
  vulnerable but the scan found nothing" case on hardened / internal targets). A
  new read-only classifier (`heaven/recon/firewall_detector.py`) labels the
  perimeter posture (**firewall / IDS-IPS / tarpit**, plus a **WAF** fingerprinter
  for web targets, Cloudflare, Akamai, Imperva, AWS WAF, F5 ASM, ModSecurity, …)
  and surfaces an informational **"Perimeter Defense Detected"** finding that
  explains *why* results may be thin and exactly how to still get them (evasion,
  scan from an in-scope segment, tester-IP allowlist). It is deliberately
  conservative, a normal, closed-heavy host (e.g. Metasploitable) is classified
  "none" and adds no note. Opt into always-on evasion with `heaven scan --evade`
  or the web launcher's **Firewall / IDS evasion** toggle (`ScanRequest.evade`);
  even off, the adaptive re-probe still fires on a detected filtering perimeter.
- **Methodology Coverage expanded to seven compliance frameworks, live, not
  static.** The `§ Methodology Coverage` page (and `heaven methodology coverage`
  + `/api/methodology`) now map HEAVEN's detectors against **Cyber Essentials**,
  **Cyber Essentials Plus**, **ISO/IEC 27001:2022 (Annex A)**, **PCI DSS
  v4.0.1**, **CIS Controls v8.1**, **NIST CSF 2.0** and **SOC 2 (Trust Services
  Criteria)**, alongside the existing OWASP WSTG / NIST 800-115 / PTES
  methodologies (ten standards in total). Every framework is driven by the same
  live machinery: a control lights up **✓ exercised** only when the HEAVEN
  detector it names actually produced a finding in the active engagement, and
  governance / physical / endpoint controls a remote scanner cannot evidence are
  honestly marked `(organizational)` / `(physical)` / `(manual)`, coverage is
  never fabricated. To make the compliance rows genuinely light up, the
  finding-→detector map (`heaven/methodology.py`) gained the real `vuln_type`s
  the scanners emit for vulnerability/patch management (CVE, end-of-life,
  dependencies), network-boundary exposure (Telnet/SNMP/IPMI/cleartext),
  container/cloud misconfiguration, broken access control and SAST. The CLI
  `--standard` filter is now dynamic (any doc stem or a short alias like `iso`,
  `pci`, `ce-plus`), so future frameworks are selectable without code changes.
  Each framework is pinned to its current published version, Cyber Essentials
  **v3.3** ("Danzell" question set, 2026), ISO/IEC 27001:2022 **Amendment
  1:2024**, PCI DSS **v4.0.1**, CIS **v8.1**, NIST CSF **2.0**, SOC 2 **TSC 2017
  (revised points of focus, 2022)**. `scripts/sync_test_count.py` now also keeps
  the README's **CLI-command count** in sync, introspected straight from the
  Click root group (exactly what `heaven --help` lists), alongside the existing
  test / module / API-route counts, so none can silently drift.
- **Editable engagement details, set Client & Statement of work from the web.**
  The **Engagement Details** card used to show *Client* and *Statement of work*
  as read-only ", ". Both are now editable inline: click **✎ Edit**, type, and
  **Save** (Enter to save, Esc to cancel). Values are trimmed and length-capped,
  written straight to the engagement DB, and flow through to the report cover
  page. Backed by a new `PATCH /api/engagement` (partial update, send either or
  both fields; the untouched one is preserved) and `EngagementStore.update_
  engagement_details`. Works even on a switched-to-but-never-scanned engagement
  (the row is created under the canonical name).
- **The Benchmark page's Refresh button now actually re-runs the benchmark.** It
  previously only re-read the last cached report, so clicking it appeared to do
  nothing. It's now **↻ Re-run benchmark**: it regenerates the native,
  Docker-free benchmark on the server (the same run `heaven benchmark` performs),
  shows a **⏳ Running…** state while it works, and loads the fresh
  precision/recall/F1, no shelling into the server required. New endpoint
  `POST /api/benchmark/run` (needs the benchmark extras server-side; returns a
  clear 503 and keeps the cached report otherwise).
- **Watch Mode is now a full web feature, launch, watch live, and stop from the
  browser.** The **Watch** page used to be read-only ("run it from the CLI").
  It's now a real launcher: pick targets + an engagement + interval + iteration
  count + scan mode, tick authorization, and **Start watch loop**. Each iteration
  streams in live over a WebSocket, a per-run table shows 🆕 new / ⚠ regressed /
  ✅ resolved counts, whether an alert fired, and *what* changed (the top
  new/regressed findings), with a running "N with changes" tally and a **Stop**
  button. The run survives navigating away and a full refresh (resumes from
  sessionStorage + the server-side job), exactly like the Autonomous loop.
  Web-launched watches are **bounded** (1-500 iterations, 15 s, 24 h interval) so
  a browser click can't spawn an unkillable loop; `heaven watch` remains the tool
  for a truly endless monitor. New endpoints: `POST /api/watch/start`,
  `GET /api/watch/jobs[/{id}]`, `POST /api/watch/jobs/{id}/stop`,
  `WS /api/watch/jobs/{id}/stream`, and `GET /api/watch/channels` (which drives
  the alert-channel tiles honestly, a channel now shows "active" only when its
  env vars are actually set). The per-iteration diff is persisted into each
  scan's summary, so what changed is visible after the fact, not just in the
  terminal.
- **Device identity in the Host & Service Inventory, MAC address, device name
  and device type.** Every host in the **Assets** view (and the CLI `heaven
  assets` / scan summary and every report format) now shows, where the scan
  observed them: its **MAC address** (+ OUI vendor) from nmap's ARP reply, its
  **device / computer name** (NetBIOS/SMB name, else reverse-DNS PTR), and its
  **device type** (nmap `-O` classification, else a conservative MAC-vendor
  category). Each value is reported exactly as nmap observed it and carries an
  honest source label, a device type tagged *(per MAC vendor)* is a maker hint,
  not a fingerprint, and stays blank when unobserved. A MAC is an L2/ARP fact,
  so it appears only for a host on the **same local segment** scanned with
  sufficient privileges (routed/remote hosts have none); nothing is fabricated.
- **Local LLM support (Ollama + any OpenAI-compatible server), no API key, no
  rate limits, private.** HEAVEN's whole AI layer (FP triage, remediation,
  attack-chain planning, coverage grading, vuln hypotheses) plus the new chatbot
  now run against a model on your own machine. Two new gateway providers, 
  `ollama` (keyless, `http://localhost:11434`) and `local` (LM Studio / llama.cpp
  / vLLM / LocalAI via `HEAVEN_LLM_BASE_URL`), speak the OpenAI-compatible schema
  over `httpx`, so **no new Python dependency** is added. One command wires it up:
  `heaven ai setup` detects/installs Ollama, pulls the default **qwen2.5:7b**
  (override with `HEAVEN_LLM_MODEL`; `llama3.1:8b`/`qwen2.5:14b` also great), saves
  `.env`, and live-tests it. Also `heaven ai models` / `ai pull` / `ai test` /
  `ai status`, and shown in `heaven doctor` + System Health.
- **Point-and-click local-AI setup in the web app (no terminal).** The web
  **Settings → AI / LLM → Local AI** card is now a full wizard: it detects whether
  Ollama is installed/running (live status + Refresh), shows a copy-paste install
  one-liner for your OS if it's missing, **pulls a model with a live progress bar**
  (streamed over `WS /api/ai/local/pull` from Ollama's native pull API), and points
  HEAVEN at it in **one click** with a live "Local AI is live" test, no `.env`
  editing, no restart. An "Other endpoint" tab connects any OpenAI-compatible
  server by base URL + model. Backed by new `POST /api/ai/local/configure` and
  `WS /api/ai/local/pull` endpoints.
- **AI security assistant (chatbot), CLI + Web, engagement-grounded, streaming.**
  A conversational analyst over the LLM gateway that can be fed a compact summary
  of your **active engagement** (top findings, hosts, last scan) so it answers
  about *your* results, cites specific findings, and never fabricates. `heaven
  chat` (streaming terminal REPL, `--once`/`--engagement`/`--no-context`); a
  dedicated **Assistant** page and a **floating chat widget** on every page in the
  web UI; `POST /api/chat` + a streaming `WS /api/chat/stream`. Replies stream
  token-by-token and stay local (private) when using Ollama.
- **Hybrid AI fallback.** `HEAVEN_LLM_FALLBACK_PROVIDER`, if the primary provider
  is unavailable or returns nothing, HEAVEN transparently retries once on the
  fallback (e.g. local primary + a cloud key as a safety net, or vice-versa). A
  dead local endpoint fails *fast* (distinct "unreachable" error, no retry burn)
  so a scan never stalls waiting on a model that isn't running. Opt-in, default
  behavior is unchanged. `scripts/install.sh` / `install.ps1` gained an opt-in
  `HEAVEN_WITH_OLLAMA=1` step (otherwise they just point at `heaven ai setup`).
- **Full 65,535-port scanning by default from the web/API path, plus a Port scope
  control.** A web/API scan used to default to ports **1-1024** while the CLI and a
  plain `nmap -p-` scan all 65,535, so a scan launched from the UI genuinely
  missed everything above 1024 (services on high ports, alt-HTTP, some databases),
  which read as "HEAVEN only scans a few ports vs nmap". The default is now a full
  `1-65535` sweep (parity with `heaven scan`), and the launcher gained a **Port
  scope** selector, *Full* (default), *Fast* (common 1-1024) or a *Custom*
  nmap-style range, so speed is an explicit, honest choice. High-value web / DB /
  mail / cPanel ports are still always folded in regardless of scope.
- **Pure-Python TCP connect-scan fallback when nmap isn't installed.** Previously a
  host with no nmap on `PATH` returned **zero** ports (the scan silently found
  nothing). The scanner now falls back to a real, concurrent TCP connect scan that
  genuinely covers every requested port, real handshakes only, service names from
  the well-known port map, live banner grabs, so a full-range sweep still works
  without nmap (the honest trade-off is no `-sV` version depth or `-O` OS
  fingerprint; install nmap for those). Nothing is ever fabricated.
- **Fewer blank Service / CPE cells in the Host & Service Inventory, filled from
  real observed data, never guessed.** Three gaps left cells empty that a
  side-by-side nmap fills: (1) a well-known port nmap couldn't name by banner was
  shown unlabelled even though HEAVEN's port table knows it, a known port now
  falls back to its conventional label (e.g. `2077 → cpanel-webdav`), while a port
  with *no* standard assignment (e.g. `26`) honestly stays blank; (2) the CPE
  column was empty for every port because HEAVEN had no CPE fallback when nmap
  omits the `<cpe>` element (common for newer versions like nginx 1.29.8), a CPE
  is now derived from the product+version nmap *did* report, for well-established
  NVD vendors only (an unknown product yields no CPE, no guessed vendor); (3)
  passive OSINT (Shodan InternetDB) now carries its real observed CPE onto passive
  ports and backfills a blank product/version/CPE on an actively-found port,
  without ever overwriting richer active data. Versions on TLS/non-bannering ports
  that returned no data stay blank, inventing them would be fabrication.

- **Active verification promotes Potential findings to Confirmed via safe,
  read-only probes.** A version banner does not prove exploitability (vendors
  backport fixes without bumping it). For a curated set of well-known CVEs, Apache
  path-traversal (CVE-2021-41773 / 42013), Shellshock (CVE-2014-6271 / 6278), a
  new `heaven/vulnscan/active_verifier.py` runs a non-destructive behavioural probe
  (read a world-readable file via the traversal; echo a unique canary through the
  CGI). A probe that fires promotes the finding **Potential → Confirmed**
  (`validated=True` + `evidence.active_verification`); a negative or absent probe
  leaves it untouched, never fabricated, never deleted. Authorization-gated and
  opt-in: `heaven scan --verify` (implied by `--autonomous`) runs it in-pipeline,
  and `heaven verify --i-have-authorization` re-verifies a stored engagement's
  Potential findings and persists the proof.
- **Remediation retest report, Fixed / Still-open / Reintroduced / New.**
  `heaven retest <baseline> <current>` compares a baseline scan to a later re-scan
  of the same engagement and renders a client-facing HTML deliverable
  (`heaven/devsecops/retest_report.py`) with a remediation-rate headline (measured
  only against the findings that existed at the baseline), plus API endpoints
  (`GET /api/scans/{id}/retest` and `…/retest.html`) and a Remediation Retest card
  on the web Scans page. A previously-fixed finding that returns is flagged urgent.
- **SARIF 2.1.0 + JUnit XML export for CI pipelines.** A dedicated
  `heaven/devsecops/ci_export.py` emits SARIF with correct `artifactLocation` URIs
  (the target), `partialFingerprints` (so GitHub/GitLab track a finding across
  runs), a numeric `security-severity`, CWE/OWASP rule tags and the confirmation
  status; and JUnit XML where findings at/above `--fail-on` become failing tests so
  a build can gate. Wired through `heaven export --format sarif|junit`, the
  `/api/report/export` endpoint and the web Reports page.
- **Committed benchmark scorecard.** `heaven benchmark --scorecard PATH` writes the
  headline precision/recall/F1 as a machine-readable JSON artifact
  (`docs/benchmark_scorecard.json`) so the README, CI and web can cite one
  canonical, honestly-captioned number.
- **Confirmation status, Confirmed vs Potential, on every finding, end to
  end.** A professional test separates what was *proven present* (a header seen
  in a live response, an open cleartext port, a payload that executed, an
  anonymous login that succeeded, an authoritative dependency-manifest match)
  from what is only *inferred* from an unauthenticated service version banner
  (the backport caveat). One compute-on-read resolver
  (`heaven.utils.cvss.confirmation_status`) drives it everywhere: the HTML/PDF
  reports gain a **Confirmation** column and a confirmed/potential split, the web
  Findings table + Finding detail + Dashboard show a Confirmed/Potential badge,
  the `/api/*` finding payloads and the dashboard/summary stats carry the label,
  and `heaven findings` tags each row `CONFIRMED`/`POTENTIAL`. Potential findings
  are never suppressed, they stay in full, clearly labelled.

### Changed

- **`heaven update` now genuinely self-updates HEAVEN, not just its detection
  feeds.** Previously `heaven update` only refreshed Nuclei templates + the NVD
  delta + the ExploitDB mirror and, by its own docstring, *did not* touch HEAVEN's
  own code, so when a newer version was published, `heaven update` brought in
  nothing new about HEAVEN itself. It now, first, brings the install up to the
  latest released code and then refreshes the detection data:
    - The standard install is an **editable git checkout** (`git clone` +
      `scripts/install.sh` → `pip install -e .`), so a fast-forward `git pull`
      makes the new Python live on the very next `heaven` command. HEAVEN re-runs
      `pip install -e .` **only when dependencies changed** and rebuilds the web UI
      **only when the frontend changed** (its built `heaven-ui/dist/` is gitignored,
      so a plain pull would otherwise leave the UI stale). It reports the real
      `vX → vY` bump.
    - **It never destroys uncommitted work:** a dirty working tree is *refused*
      (with the exact files listed) unless you pass `--force`, which stashes →
      fast-forwards → pops non-destructively. It only ever *fast-forwards*, never a
      merge, rebase, or `reset --hard`, and never claims success on a failed pull.
    - **Honest about non-git installs:** a release tarball / Docker image /
      non-editable pip install can't be updated in place, so HEAVEN says so and
      points you at the right step instead of pretending it worked.
    - New flags: `--check` (dry-run: "is a newer version available?"),
      `--code-only`, `--data-only` (the pre-2.1 behavior), `--force`, `--skip-ui`.
      The existing `--skip-nuclei` / `--skip-nvd` / `--skip-exploitdb` / `--output`
      still apply to the detection-data step. Covered by `tests/test_self_update.py`
      and live-verified end-to-end against a real git fast-forward (v2.0.0 → current).
- **Network-recon deadline now scales with port breadth.** A full-range sweep of a
  single host earns materially more time (~13 min vs the old ~4 min single-host
  floor) so a `-p- -sV -sC` scan finishes instead of being truncated mid-scan back
  to "a few ports". Still capped at 30 min and bounded per-host by nmap's
  `--host-timeout`.
- **Host & Service Inventory (web) sorts ascending and is searchable.** The Assets
  page now lists hosts in ascending order (IPv4 numerically, `.2` before `.10`, 
  hostnames after) and adds a **search box** that filters by IP, hostname, service,
  version or port number, so a specific target is one keystroke away.

- **Active Confirmation now works for *every* finding, one honest verdict, not a
  blunt "Proved: no".** The finding-detail "Active Confirmation" panel used to run
  an injection-only exploit prover, so any non-injection finding (missing headers,
  exposed files, weak TLS, an exposed database/port, a directory listing, …)
  silently came back "Proved: no" with no explanation, indistinguishable from a
  real failed proof. A new unified dispatcher (`heaven/vulnscan/confirm.py`) routes
  each finding to the safest applicable **live** proof and returns a structured,
  honest verdict:
  - **Injection** (SQLi/command-injection/SSRF/XSS) → the exploitation canary.
  - **Known CVEs** (Apache path-traversal, Shellshock) → the safe read-only probe.
  - **HTTP-observable misconfig** (missing security headers, directory listing, an
    exposed file, permissive CORS, an open redirect, an exposed management
    endpoint) → a single read-only GET that re-checks the exact condition live.
  - **TLS/SSL** → a fresh handshake via the SSL scanner; confirmed only if the same
    issue reappears.
  - **Exposed network service/port** → a plain TCP connect proving reachability.

  The verdict is one of **Confirmed** (a live probe proved it now), **Already
  confirmed** (the detection itself is the proof, e.g. an SCA/DNS/config
  observation), **Could not confirm** (a probe ran but couldn't reproduce it, 
  patched or unreachable), or **No automated proof** (a class with no safe
  auto-proof, the panel now shows the concrete manual next step instead of a
  misleading "no"). Every probe is read-only, bounded, and authorization-gated;
  nothing is ever fabricated. A fresh proof promotes the finding to Confirmed and
  persists the evidence.
- **Accurate, time-linear scan-progress bar with a live "time left" estimate.**
  The Scan Activity bar previously advanced by *task count*, so it raced through
  the many cheap recon tasks (1→50% fast) then crawled through the few heavy scan
  tasks (50→100% slow). Progress is now **weighted by each task's expected cost**
  (a clamp of its timeout) and a running task earns its *actual* elapsed seconds,
  so the bar tracks real work and moves at a steady pace. Each running scan also
  shows an honest estimated time-remaining (`~2m left`), extrapolated from observed
  progress and suppressed until there is enough signal to estimate. Exposed as
  `eta_s` on the scans API and rendered under the percentage.
- **Passive internet-scan enrichment, HEAVEN no longer misses a port/service/CVE
  that is already publicly visible.** During recon, every *public* target is now
  cross-referenced against Shodan's free, key-less **InternetDB**
  (`https://internetdb.shodan.io/{ip}`) and the results are merged into the one
  host-inventory blob every downstream stage reads (inventory, exposed-database,
  end-of-life audit, CVE mapping). This directly fixes the class of miss where an
  authenticated Shodan record shows 80/443 + MySQL/PostgreSQL but a single flaky
  active scan came back without them. A port the public record lists but the
  active scan didn't return is **re-probed read-only to confirm it**, then
  labelled honestly, a confirmed re-probe becomes `open` (`passive+active`),
  while one that can't be reached from the scan origin is kept but clearly marked
  *"passive (public OSINT, unconfirmed)"* in the inventory's new **Source**
  column. CVE IDs the public record ties to the host are surfaced as **Potential**
  findings (never inflating the confirmed-only Overall Risk), and CPEs carry a
  real product+version into the EOL/CVE stages. On by default for internet-routable
  targets only (private/loopback are a no-op); disable with
  `HEAVEN_NO_PASSIVE_INTEL=1`. Fully graceful offline. New module
  `heaven/recon/passive_intel.py`.
- **Dynamic end-of-life detection via the live endoflife.date feed.** The EOL
  audit now consults the key-less endoflife.date API for any product the curated
  static table doesn't cover, so an unsupported component that isn't in HEAVEN's
  hand-maintained list is still flagged, firing only on a real, published EOL
  date (never a guess). The static table remains the offline fallback.
- **A high-value always-probe port set is folded into every network scan** (web,
  database, mail/LDAP, cPanel/WHM), so a flaky, rate-limited or narrowed run can
  never silently drop the common ports. Union-only: it adds coverage, never
  removes a requested port, and is a no-op for a full-range scan.

- **Installers now prefer a well-tested Python interpreter, and `heaven doctor`
  flags an unvetted one.** HEAVEN's native security dependencies
  (`asyncssh`↔Nettle, `cryptography`, `numpy`/`scikit-learn`) are only ABI-stable
  on released Python lines; a brand-new major (e.g. 3.14 in its first months) can
  crash those C extensions natively, the same root cause as the UMAC segfault
  below. `scripts/install.sh` and `scripts/install.ps1` now pick the newest
  known-good interpreter they can find (Python 3.13 → 3.12 → 3.11) before falling
  back to whatever `python3`/`py` resolves to, and warn (without failing) when the
  chosen interpreter is newer than the tested range (3.11-3.13), telling the
  operator to use 3.12/3.13 if they hit a native crash. `heaven doctor` gained a
  matching runtime check: it reports `python_supported` and, on an untested
  interpreter, surfaces a header warning and a top "rebuild your venv on Python
  3.12 or 3.13" next-step. The supported range is now documented in the README.

- **Overall Risk is now rated from confirmed findings only.** A hardened target
  whose only "Critical" is an unauthenticated, version-based CVE match no longer
  shows an inflated **Critical** headline, the rating reflects the worst
  *confirmed* finding, while the potential critical still appears in the findings
  list (as `Critical · Potential`) and the executive summary calls out how many
  potential findings need verification. Applies consistently to the reports, the
  dashboard headline and the engagement summary.
- **Web-tier EOL + CVE detection from HTTP response headers (the "outdated PHP"
  gap).** An end-of-life PHP disclosed only in `X-Powered-By: PHP/5.2.4` or a
  `Server:` header was never flagged, because the EOL scanner and CVE mapper read
  only nmap-derived `open_ports[].product/version`. A new
  `heaven/recon/web_tech.py` extracts versioned components from response headers
  (PHP, Apache, nginx, OpenSSL, IIS, Tomcat …, only when a real version is
  present, never guessed) and runs them through the **existing** `eol_scanner`
  (CWE-1104 `unsupported_software`) and `cve_mapper`, so a header-disclosed EOL or
  CVE-bearing component now surfaces exactly like an nmap-detected one, findings
  carry an honest `detection_source: http_response_header` provenance (kept
  distinct from the CVE mapper's own match `source`). Wired into the web scan
  phase; web components are attached to the Host & Service Inventory
  (`PHP 5.2.4 (web, X-Powered-By header)`). Verified live against Metasploitable 2
  (`192.168.0.162`): Apache 2.2.8 + OpenSSL 0.9.8 + PHP 5.2.4 → 3 EOL findings +
  the mapped PHP/OpenSSL CVEs.
- **Dynamic, faithful reproduction per finding, curl + raw HTTP request, or a
  class-appropriate command.** The "Reproduce / Paste as request" block used to
  emit a bogus `curl -i http://host:3306` for DNS/DB/TLS/host findings that made
  no HTTP request, and never rendered the raw request its label promised. Now
  `evidence.package_finding` decides per finding: a real HTTP finding gets a
  **faithful curl** (method, param + proof-payload folded into the exact
  URL/body) **and** a **raw HTTP/1.1 request** for Burp Repeater's *Paste as
  request*, both built from the same transaction; a non-HTTP finding gets a
  read-only, class-appropriate command (`openssl s_client`, `dig`, `nmap`,
  `redis-cli`, `smbclient`, `mysql`, …) or an honest "observed via …; no
  single-command reproduction" note, **never** a fabricated curl. Surfaced
  through the evidence API (`is_http`, `raw_http_request`, `repro_command`,
  `repro_note`), the Finding-detail Reproduce card (each block with its own Copy
  button) and `heaven findings replay`.

- **Cyber Kill Chain, real phase coverage.** Many `vuln_type` slugs the scanners
  actually emit (`cmdi`, `missing_authentication`, `database_exposed`,
  `docker_api_exposed`, `kubelet_exposed`, `perimeter_defense`,
  `unsupported_software`, `telnet`, `smtp_open_relay`, k8s/ICS/IPMI exposures …)
  were absent from `VULN_KILLCHAIN_MAP`, so those findings fell through to the
  default *Reconnaissance* bucket and the **Weaponization / Installation /
  Command-&-Control** phases stayed structurally dark. The map was grounded by
  grepping every emitter and extended so each real slug resolves to the phase(s)
  its exposure enables (reporting-only, the module never executes a phase; a
  *good* control like "SPF present" is deliberately never mapped as an attacker
  enabler). A realistic finding set now lights all seven phases.

### Fixed

- **POST-form command injection is now exercised by the default test gate, the
  Docker-free benchmark modelled DVWA's exec page as a GET form, so a regression
  in POST command-injection handling could have shipped green.** Real
  command-injection sinks (DVWA's `/vulnerabilities/exec/` and most ping-style
  forms) POST their input; a live authenticated DVWA scan confirms HEAVEN detects
  it (the crawler extracts the `ip` POST vector, `build_injection_targets` builds
  the POST form, and `_test_cmdi_param(post=True)` confirms via the reflection-safe
  `uid=` signal). But the native benchmark's exec endpoint was a **GET** form, so
  the perfect-score recall floor never actually covered the POST path. Fixed:
  `tests/benchmarks/native/vuln_app.py` now models exec as a faithful `method="post"`
  form (reads `$_REQUEST`-style `request.values`) and the ground truth
  (`native.yaml`) marks it POST, the default-gate benchmark now genuinely
  exercises POST command injection end-to-end and still scores 100% precision /
  recall / F1. Added `tests/test_injection_post_cmdi.py` (flask-free) pinning the
  POST-cmdi path, the wiring (`build_injection_targets` extracts the POST `ip`
  vector), the confirmation (uid= over POST → `cmdi`/CWE-78), and a benign-POST
  negative control (no false positive). No detection-logic change was needed: the
  capability was already correct; this closes the *coverage* gap so it stays that
  way. (Note: against an emulated amd64-on-arm64 DVWA saturated by concurrent scan
  phases, the exec probe, which triggers a slow server-side `ping -c 4`, can time
  out and be missed intermittently; that is a target-saturation artifact of the
  emulated fixture, not a detection or pipeline defect, the cmdi finding survives
  dedup/suppression identically to SQLi.)
- **CVE version-matching no longer flags ancient software with modern-branch CVEs
  (major false-positive class, found live vs Metasploitable 2).** An
  upper-bound-only curated spec (`<8.3.8`, `<=2.4.39`) matched *any* version below
  the ceiling, so PHP **5.2.4** collected PHP 7/8 CVEs (incl. CVE-2024-4577 "PHP
  CGI RCE on **Windows**") and Apache **2.2.8** collected Apache 2.4-only CVEs
  (mod_http2 / mod_lua / mod_proxy). Fixes: (a) `specs_match_version` now treats a
  record's multiple `<=`/`<` ceilings as *per-branch* fix levels, a version only
  matches within its own `major.minor` (or `major`, for PostgreSQL-style 2-part
  ceilings) branch, so 5.2.4 / 5.0.51 are excluded from 7/8 / 5.7/8.0 branch CVEs
  while in-branch and two-sided windows are unchanged; (b) the Apache inline
  records carry honest lower bounds (`>=2.4.0`) and the two CVEs that genuinely
  span 2.2 (mod_mime CVE-2017-7679, Optionsbleed CVE-2017-9798) use explicit 2.2 +
  2.4 branch ranges (so 2.2.8 gets those *real* CVEs, not the fake 2.4 ones);
  (c) OpenSSH records gained real lower bounds, CVE-2021-41617 `>=6.2` and
  CVE-2023-38408 `>=5.4` (its ssh-agent PKCS#11 code path did not exist before
  5.4), so an OpenSSH 4.7p1 keeps only its genuine CVEs. `tests/test_cve_version_fp.py`.
- **Live CVE feed no longer asserts misattributed CVEs on version-less services.**
  A version-less service ("vnc", "telnet") pulled specific CVEs by product-NAME
  keyword, RealVNC-on-Windows onto a Linux VNC, GNU-inetutils telnetd onto netkit
  telnetd. The feed path now emits an individual finding only for a
  *version-confirmed* range match and collapses the unconfirmed keyword remainder
  into a single honest low `potential_vulnerable_service` finding (mirroring the
  inline version-less collapse) instead of N speculative Criticals.
- **SSL/TLS audit no longer floods plain-HTTP port 80 until the phase times out.**
  The audit derived a target from every crawled URL, defaulting an `http://` URL
  to `host:80` and never de-duplicating, so a crawl of a plain-HTTP host queued
  dozens of identical `:80` TLS probes that exhausted the 300s budget and produced
  nothing. It now audits only `https://` URLs (a cleartext URL has no TLS to
  audit) plus real TLS ports found by the network scan, and `scan_ssl_targets`
  de-duplicates defensively. `tests/test_ssl_target_selection.py`.
- **Cyber Kill Chain now lights Command & Control / Installation for backdoors.**
  A vsftpd 2.3.4 / UnrealIRCd command-execution backdoor or a root bindshell
  classifies as a generic `vulnerable_service` (Weaponization + Exploitation), so
  the C2 phase stayed dark on a host defined by its backdoors. Explicit
  backdoor / bindshell / web-shell / root-shell language now also lights
  Installation + Command & Control (evidence-gated, ordinary findings are never
  promoted). `tests/test_killchain_phase_coverage.py`.

- **Network scan no longer hangs and then reports 0 findings on a slow /
  heavily-filtered host (e.g. Metasploitable in a VM).** A full-range
  `-sV -sC -p 1-65535` nmap sweep cannot finish on a slow, emulated, or firewalled
  host, most ports are *filtered* (silently dropped), so nmap spends its whole
  budget waiting on them and never reaches the dozen that are open. It then either
  (a) ran until the orchestrator's deep-scan `time_budget` fired and **cancelled
  the whole `scan_host` coroutine mid-nmap, discarding the host result** (the "scan
  sits for minutes then finds nothing" symptom), or (b) hit its own
  `--host-timeout` and emitted a *clean, well-formed* XML reporting **0 ports**
  (`timedout="true"`, `rc 0`) that HEAVEN accepted as "nothing open". Under `-Pn`
  the old connect-scan safety net was gated on the host having *answered* (a real
  probe reason or a refused/closed port), which a fully-filtered `-Pn` target never
  satisfies, so it never fired. Fixed on three fronts: (1) `_parse_nmap_xml` now
  detects `timedout="true"` and treats a cut-short scan as **incomplete**, not
  clean-empty; (2) `scan_host` runs a reworked **connect-scan recovery** whenever
  nmap finds no open ports *or* timed out, it probes the high-value service ports
  first (a live host answers in seconds; a dead one is ruled out just as fast, so a
  `/24` sweep isn't slowed), then completes the range, and **unions** its result
  with any ports a partial nmap did find (nmap's version-rich entries are kept); and
  (3) `scan_network` now caps nmap's per-host `--host-timeout` well below the deep-
  scan budget so a stuck sweep always yields in time for recovery to run and the
  host to be **kept**, not cancelled. Live result vs a real Metasploitable 2 VM at
  `192.168.0.162` (UTM/QEMU): **0 → 54 findings (9 critical)** including the
  vsftpd 2.3.4 backdoor (CVE-2011-2523), telnetd `-f root` auth bypass, Apache
  SSRF, and OpenSSH agent RCE.

- **Service / Version / CPE / CVE columns no longer come back blank after that
  recovery.** With the ports recovered, the *next* layer surfaced: the built-in
  connect scanner proves a port OPEN but does no `-sV`, so the recovered ports had
  no `product` / `version` / `cpe`, which left the inventory's Service / Version /
  CPE columns empty and starved CVE mapping (it keys off product/version/banner),
  so only the two or three ports that happen to emit a text banner (FTP/SSH/HTTP)
  got a CVE. A full-range `-sV` can't finish on such a host, but nmap has no trouble
  on a **short explicit port list**, so HEAVEN now runs a targeted `nmap -sV`
  (`_nmap_service_scan`) on the recovered open ports and merges the real
  service/version/CPE detail back onto them, exactly what a manual `nmap -sV`
  shows, in ~15 s. The **ordering is load-bearing**: the version scan runs on the
  *service band* (the low ports + curated high-value ports, where every CVE-bearing
  service lives) **before** the full-range completion sweep. That sweep floods the
  target with tens of thousands of short-lived connections, which leaves a fragile /
  emulated / rate-limited host, and the scanner's own local ephemeral-port pool, 
  unresponsive; a `-sV` that ran *after* it was starved and came back completely
  empty (found live vs the VM: 0/30 enriched). Enriching the service band first
  sidesteps that entirely. The ephemeral/high band (dynamic RPC / OS ports) is then
  swept and given its **own** targeted pass, but only after a short settle lets the
  flood drain, and with two things the primary sweep lacked: a forced **connect
  scan** (`-sT`, these ports answer a full handshake but not a bare SYN on a
  filtered / emulated host, so a privileged SYN scan reports them `filtered`) and
  the **rpcbind port (111) handed to nmap as context**, without which a dynamically
  assigned RPC port can't be resolved and stays `unknown`. Enrichment fires
  **only** on the degraded path (a sweep that timed out / crashed), never
  re-scanning a host that already completed `-sV`, and is budgeted so the whole
  per-host scan still finishes inside the deep-scan `time_budget`. Live vs the real
  Metasploitable 2 VM at `192.168.0.162` (UTM/QEMU): the service ports went from
  **product 0/30, version 0/30** to full identification, vsftpd 2.3.4, OpenSSH
  4.7p1, telnetd, Postfix, ISC BIND 9.4.2, Apache 2.2.8, Samba 3.0.20, ProFTPD
  1.3.1, MySQL 5.0.51a, distccd, PostgreSQL 8.3, UnrealIRCd, Tomcat, Ruby DRb, and
  the four dynamic RPC high ports (43967/52107/55016/57901), formerly blank, now
  resolve to **java-rmi / status / nlockmgr / mountd** (`service=30/30`), with CVE
  mapping covering the full service surface, not just FTP/SSH/HTTP. Every enriched
  port was already proven open by a real handshake, no service, version or CVE is
  invented.

- **SSH credential spray no longer fabricates a "Default Credentials" finding
  from the auditor's own key or a permissive server.** `CredentialSprayer.
  spray_ssh` reported a critical `SSH Default Credentials: <user>:<pass>` finding
  whenever `asyncssh.connect` succeeded, but asyncssh does not restrict itself
  to the sprayed password: by default it also offers the operator's SSH agent
  keys, their `~/.ssh/id_*` identity files, and a GSSAPI/Kerberos ticket, and it
  will authenticate against a server that permits SSH `none` auth. Any of those
  made the connection succeed while the *password* was never accepted, so a scan
  that happened to probe the auditor's own `localhost:22` could emit a fabricated
  "default password" critical. The spray now (1) forces **password-only
  authentication** (public-key/agent/GSSAPI all disabled), so a hit can only mean
  the sprayed password was accepted, and (2) runs an **accept-all baseline
  probe** first with a random invalid credential, if the service accepts *that*
  it enforces no authentication, and HEAVEN reports it **once, honestly** as
  "SSH service accepts unauthenticated access" (`missing_authentication`) instead
  of a bogus specific pair. Genuinely weak servers (`user:user` really works) are
  still detected, the true positive is preserved.

- **Network scan no longer returns 0 findings when nmap under-reports a live
  host.** A vulnerable, wide-open box (Metasploitable, an internal server) could
  come back with an empty inventory and **0 findings** even though its ports were
  open. Root cause: the pure-Python connect-scan safety net only deployed when
  nmap's XML was *unparseable* (a crash). When nmap instead returned a clean,
  well-formed document that wrongly reported **every port closed** on a host that
  was plainly answering, an aggressive-timing connect scan exhausting ephemeral
  ports, a half-applied privilege state, transient drops under `-T4`/`--min-rate`
, HEAVEN trusted it, so `scan_host` returned no open ports and every downstream
  stage (CVE mapping, service exposure, EOL audit) inherited an empty inventory.
  `scan_host` now **cross-checks with a real TCP connect scan whenever nmap
  reports zero open ports on a host that answered** (it refused ports, or a probe
  confirmed it). The check is free on the happy path (skipped the instant nmap
  finds a port), cheap exactly where it fires (a responsive host refuses ports
  instantly, so `connect()` never waits), and can only *add* genuinely-open ports
, a truly closed host still yields nothing, and a firewalled/all-filtered host
  is still handled by the existing evasion re-probe. Banners grabbed for the
  standard service ports keep the recovered ports' CVE findings intact.
- **Shell Tab-completion now completes options and flag values, and installs with
  one command.** Two problems are fixed. First, pressing Tab after an option
  (`heaven scan --<TAB>`) or a choice flag (`heaven scan --stealth <TAB>`)
  produced nothing: rich-click's `patch()` created a *second* `click.core.Option`
  class, so Click's own completion loop (`isinstance(param, Option)`) matched zero
  options, command/subcommand completion worked, but options and their values
  never did. rich-click is now skipped only while completion is running (help
  styling is irrelevant there), so Click keeps native class identity and every
  command, subcommand, option and `Choice()` value completes. Second, installing
  completion used to mean hand-editing your shell rc, the `fpath`/`compinit`
  ordering is easy to get wrong (oh-my-zsh runs `compinit` for you, so a
  `fpath` line added afterwards is ignored and Tab silently stays dead). New
  `heaven completion --install` writes the script to `~/.config/heaven/` and adds
  a small guarded, `compinit`-aware block to `~/.zshrc` / `~/.bashrc` (fish needs
  no rc edit), idempotent, backed up first, and reversible with
  `--uninstall`; preview with `--dry-run`. The installers now run this for you,
  so Tab works out of the box on a fresh install (opt out with
  `HEAVEN_SKIP_COMPLETION=1`; the matching completion block is removed on
  uninstall).
- **Windows / PowerShell Tab-completion.** Click ships no PowerShell completion
  backend, so `heaven` never completed in PowerShell. HEAVEN now provides a native
  argument-completer (`Register-ArgumentCompleter`, reusing Click's `zsh_complete`
  protocol under the hood) that `heaven completion --install` (auto-detected on
  Windows, or `--install powershell`) wires into your `$PROFILE`, idempotent,
  backed up, and removed on uninstall. `scripts/install.ps1` sets it up
  automatically.
- **`scripts/install.ps1` now downloads the Playwright Chromium bundle**, matching
  `install.sh`. Without it the headless DAST proof (DOM / stored-XSS execution,
  JS-rendered crawl) silently degraded on Windows even though the `playwright`
  wheel was installed. Skipped for a lean footprint (`-CoreOnly` /
  `HEAVEN_SKIP_BROWSER=1`).
- **The live finding count no longer balloons then collapses during a web scan.**
  The in-progress count could spike (e.g. 65 → 346) as noisy raw candidates
  surfaced and only settled back to the real number when the final dedup /
  FP-suppression ran at completion. The web scan's live flush now mirrors the
  finalizer exactly, it collects the same result keys (including each task's
  `suppressed_findings`), runs the same `dedup_findings`, and reconciles the store
  to the deduped survivors on every tick, so the running count tracks the
  authoritative set and *converges as verdicts land* instead of snapping down at
  the end.
- **A scan no longer freezes mid-run redundantly re-scanning the host it just
  scanned.** The closed-loop feedback engine treated the operator's own seed
  target as a "newly-discovered in-scope host", every finding carries the host
  as its `target`, and the network result lists it under `hosts`, and queued it
  for a full `DYNAMIC_FOLLOWUP` re-scan across ~10,000 ports. On a service-rich
  host this stalled the scan for ~90s at ~44% with no new findings (the "it
  scanned forever and looked like it found nothing" symptom). The
  `FeedbackEngine` now records the seed hosts (and any host it has already
  followed up) and never re-queues them; genuinely-new hosts (DNS subdomains,
  loot references, redirects to *other* hosts) are still followed up. Verified
  live against Metasploitable-2: same 67 findings, no seed re-scan, ~90s faster.
- **`heaven scan --engagement <name>` no longer silently produces zero
  findings.** A name with no existing DB hard-exited the whole scan (`Engagement
  DB not found … exit 2`); the CLI now **auto-creates** the engagement (parity
  with the web/API path). And when `--use-scope` (the default) filtered out
  *every* target because the engagement's scope didn't include it, the scan used
  to proceed against nothing and report zero, it now records the named targets
  into a fresh/empty scope automatically, and if a *populated* scope excludes all
  targets it stops with a clear fix (`heaven scope add …`, a different
  `--engagement`, or `--no-use-scope`) instead of a mystery empty run.
- **Finding-detail "CVSS base" is labelled for what the number actually is.** The
  base score row printed "(weakness class)" even when the number was a real
  published CVSS score; it now reads "(base score)" for the resolved objective
  base and "(typical for class)" only when falling back to the class default.
- **A dependency finding no longer shows a CVSS vector that contradicts its
  score.** A `VULNERABLE_DEPENDENCY` finding (nanoid 3.3.16 / CVE-2026-67213)
  rendered "CVSS base **5.9**" beside a `.../C:H/I:H/A:H` vector that computes to
  **9.8**, the generic *known-vulnerable-component* class vector, stamped
  because the advisory had been cached in its first hours (before GitHub/NVD
  added the real CVSS + CWE). Two root fixes: (1) `OSVClient` now **refreshes a
  cached advisory that carries no severity yet** on the next scan (offline-safe:
  it keeps the cached copy if the refresh fails), so a finding picks up the real
  score/CWE the moment upstream publishes them; (2) a KB-wide sweep reconciled
  every vuln class's **curated CVSS vector with its documented `typical_cvss`**, 
  28 classes had drifted (e.g. `vulnerable_component` 7.5-vs-9.8,
  `sensitive_file_exposure` 5.3-vs-7.5), so the detail view's *CVSS base* and
  *CVSS vector* rows disagreed on every fallback-scored finding. The vectors were
  corrected to match the documented score (severity bands and ML features
  unchanged), and a regression test now locks base ⇄ vector agreement so it can
  never drift again.
- **Dependency upgrades (SCA-clean end to end).** Upgraded the project's own
  vulnerable dependency **nanoid 3.3.16 → 3.3.18** (clears CVE-2026-67213, the
  finding above, `npm audit`: 0 vulnerabilities) and bumped the test-only
  **pypdf** floor to **>=6.15.0** (clears CVE-2026-71852 / CVE-2026-71870). A
  full OSV.dev audit of the Python environment and both npm lockfiles now reports
  zero known-vulnerable dependencies.
- **Duplicate findings on a domain scan, the same site-wide issue no longer
  reports two or three times for one host.** A domain assessment names the same
  host several ways: the DNS/email phase uses the bare domain (`example.com`)
  while the web phase probes both `http://example.com` and `https://example.com`.
  The finding-identity key kept the scheme and explicit port, so a single
  site-wide issue (missing security headers, weak TLS, SPF/DMARC), and a service
  CVE, hashed differently per representation and persisted as separate rows,
  surfacing as duplicates in the findings list, reports and host topology. The
  host key now canonicalises to the bare host (scheme dropped, default web ports
  80/443 normalised away, host lower-cased, trailing dot stripped), so all those
  forms collapse to **one finding per host**, while a genuinely distinct service
  port (`:8080`, `:8443`) is still kept separate and `www.`-vs-apex stay distinct.
  The CVE identity also unifies "port in the URL" and "port in the field" forms
  of the same finding. (Existing rows in an engagement DB de-duplicate on the
  next scan, when the new identity is written.)
- **README/hero-poster stat figures corrected and the API-route count is now
  CI-checked.** The "API routes" figure read **66** (distinct HTTP paths only,
  dropping the 6 WebSocket endpoints despite the "REST + WebSocket API" label);
  it now reads **77**, every registered `/api/*` route handler including
  WebSockets. The hero poster's visible stat strip was also stale (`1358` tests,
  `51` CLI commands, `64` routes) and now matches the real counts (1663 / 53 /
  77). `scripts/sync_test_count.py` gained a static, import-free route counter
  (parses `heaven/api/server.py`), so the README route figure is now kept in sync
  and CI-gated alongside the test and module counts and can't silently drift.
- **Benchmark report title now names HEAVEN's version, removing the "which v1.0?"
  confusion.** The header read `Benchmark: HEAVEN vs. heaven-native-vuln-app
  v1.0`. That `v1.0` is the *target app's* own version, but with HEAVEN's
  version absent it looked like HEAVEN was stuck at v1.0. The title now reads
  `Benchmark: HEAVEN v3.0.0 vs. heaven-native-vuln-app v1.0`, so it's clear the
  tool is on 2.1.0 and the labelled target reproduction is its own v1.0. (The
  scanner version is pulled from `heaven.__version__`, so it stays in sync on
  every release.)
- **Watch Mode now actually alerts when something changes that isn't
  critical/high, and `--heartbeat` finally pings.** The watch loop routed its
  change alerts through the scan-complete webhook path, which by design stays
  *silent* unless there are critical or high findings, so a run that turned up a
  new **medium** or **low** finding (or a regression of one) reported
  `alert=✓` but sent nothing, and the first-run heartbeat never fired at all.
  Watch alerts now go through a dedicated change-focused sender that always
  posts when a webhook is configured, with a message that says *what* changed
  (🆕 new / ⚠ regressed / ✅ resolved counts + severity), not a generic "critical
  vulnerabilities detected". SIEM events are now tagged `watch.change` /
  `watch.heartbeat` / `watch.start`.
- **Header engagement name no longer ellipsizes to nothing when the chip is
  crowded (~1000px, or any width once the running-scan / task badges appear).**
  The name was the only shrinkable item in the chip, so when the "ENGAGEMENT"
  label, client and finding/target counts filled the row it was squeezed to an
  empty `…`. Fixed two ways: (1) the name now keeps a `min-width` floor so it can
  never collapse to nothing, it ellipsizes past the floor instead; (2) the chip
  progressively sheds its least-important metadata (counts → client → label) as
  space runs out, keeping the name. That shedding is driven by a **container
  query** on the header's left region, not a viewport breakpoint, so it reacts to
  the *actual* room the chip has, including the running-scan / task badges on the
  right that eat into it, which a viewport media query can't see. Verified live in
  both themes from 1000px up to a wide viewport, and under a simulated badge
  squeeze where a viewport rule would have failed.
- **Light-theme polish, round 2, unreadable coloured text, odd black panels,
  invisible in-console text selection, and a 3D-map overlap.** Follow-up to the
  light-theme rebuild below, from reviewing the live app: (1) severity/accent hues
  (emerald, cyan, amber, sky, orange, violet) are vivid on the dark base but wash
  out as *text/dots/borders* on white (~1.5-2:1), so the light theme now deepens
  those tokens (`--crit/--high/--med/--low/--info/--brand/--cyan/--accent-2/
  --danger`) to WCAG-grade variants; pill *fills* are separate `rgba()` literals
  so pills keep their soft wash while their text darkens, and the sidebar/login
  wordmark gradient and the faint `--text-3` tier were deepened too; the Dashboard
  (which used hard-coded severity hex) now points its stat numbers and severity
  labels at those tokens. (2) The terminal / code / evidence / CLI blocks now use
  a **light** code surface in light mode instead of a lone black panel; this also
  fixes text **selected inside a console being invisible** (the default light
  selection now reads correctly on the light surface). (3) In the 3D topology map,
  the selected-host card no longer overlaps the severity legend, the legend hides
  while a host is selected and returns on deselect. Dark mode is unchanged.
- **Light theme was only half-built, the web UI looked broken in light mode,
  and the dashboard crowded on narrow laptops.** The light theme overrode only
  the surface/text/border tokens, but the whole UI was painted with ~30 hard-coded
  `rgba(255,255,255,…)` overlays (button/badge/pill fills, row hovers, the
  progress track, scrollbar, text selection) that vanished white-on-white in light
  mode, a global dark bottom-vignette (`body::after`) that smeared grey across
  every light page, several inline styles referencing **undefined** design tokens
  (`--surface-1`, `--bg-elev`, `--danger`, a bare `--text`) that fell back to
  hard-coded dark (the Settings *Save changes* bar rendered dark; the Autonomous
  executive-summary box had no background), a login card with no surface (its form
  was invisible on the light page), and a 3D topology map hard-wired to a dark
  grid + starfield. Fixes: one set of **theme-aware overlay tokens**
  (`--overlay-weak/-med/-strong`, `--hover`, `--track`, `--scrollbar-thumb`,
  `--selection-*`) that flip to slate-alpha in light and equal the old values in
  dark; the missing tokens are now defined in both themes; the light-mode vignette
  is removed; the terminal, code and evidence blocks get a light code surface in
  light mode (dark in dark mode); and the 3D map reads the active theme (light
  grid, no starfield, light tooltip).
  Dark mode is unchanged. Separately, the Dashboard now collapses its two-pane
  grid to a single column at ≤1100px (was 860px), so the four stat cards no longer
  clip their labels on a narrow laptop.
- **A whole scan could return 0 findings and an empty inventory on a live,
  service-rich host, and give different results at different stealth levels.**
  Root cause: HEAVEN always ran nmap with `-sC` (default NSE scripts), and on some
  nmap builds, notably nmap 7.9x on macOS/Apple-Silicon, the scripting engine
  **aborts** mid-scan (`Assertion failed: lua_status(L) == LUA_YIELD`, SIGABRT),
  emitting a truncated XML document with **zero ports**. nmap crashing took the
  entire scan down with it: no ports → empty Host & Service Inventory → no
  exposed-DB / EOL / CVE findings → "0 findings" on targets that a side-by-side
  nmap lit up (Metasploitable 2, `certifiedhacker.com`, …). Because the crash is
  timing-dependent on a remote host, it fired *intermittently*, so the same target
  produced different results run-to-run and across stealth levels. Fixes:
  - **nmap `-sC`/NSE crash is now survived.** A crashed/truncated nmap run is told
    apart from a clean "nothing open" result; on a crash the host is **retried
    without `-sC`** so the full port + service-version inventory is still captured
    (only the optional default-script output is lost). If nmap is unusable on every
    attempt, HEAVEN falls back to its pure-Python TCP connect scan, so a live host
    is never reported as 0 ports. Nothing is fabricated.
  - **Stealth levels are now consistent and finite.** The paranoid profile's packet
    floor (`--min-rate 10`) was so low a real port range could never finish inside
    the time budget, the host was cancelled and returned nothing, so a paranoid
    scan disagreed with a normal one. Floors were raised to values that stay
    progressively quieter (`-T1`/`-T2` still drive the real IDS evasion) while
    guaranteeing completion, every level now retries ≥ 2 (no single-retry port
    loss → stable results run-to-run), and the network-recon deadline scales up for
    the slower profiles so the same target converges on the same inventory at every
    stealth level. Verified end-to-end: a Metasploitable-class host went from 0 →
    a full set of findings, and all four stealth levels return an identical,
    reproducible port set.
- **A firewalled/hardened target could make an entire scan return almost nothing
  (empty Host & Service Inventory, only one port, far fewer findings).** The
  passive-OSINT enrichment's read-only re-probe was unbounded, against a host
  that silently drops probe traffic (e.g. a cPanel/WHM server behind CSF/LFD
  port-scan blocking) it could run for many minutes, tipping the network-recon
  task past its hard timeout. The orchestrator then cancelled that task, and
  because assets and network-derived findings are only collected from *completed*
  tasks, the inventory came back empty and the exposed-database / EOL / CVE stages
  had no hosts to work from. Enrichment is now bulletproof: every publicly-visible
  port is merged **first** (before any active traffic), the re-probe is an
  optional *upgrade* pass bounded twice (nmap `--host-timeout` + an asyncio
  backstop) with a global wall-clock deadline, and the whole pass is wrapped so it
  can never overrun the scan. The orchestrator also reserves more headroom below
  the task timeout. Net effect: even when a host blocks an active sweep, HEAVEN
  still recovers its real surface (ports, exposed databases, EOL software, CVEs)
  from the public record, honestly labelled, instead of losing the scan.
- **A rate-limited/out-of-quota AI key could drag a scan out for many minutes.** A
  scan fans a lot of LLM calls out sequentially (per-finding false-positive review,
  vuln hypotheses, coverage grading, remediation). When the operator's key was
  throttled, *every* call hit a `429`/`RESOURCE_EXHAUSTED`, and two things turned
  that into a multi-minute stall (observed as an ~8-minute DVWA scan that timed out
  in the AI phases): the provider SDKs' **own** internal retry loops re-sent each
  request honoring the response's multi-second `Retry-After` *before* HEAVEN ever
  saw the error, and even after HEAVEN fast-failed one `429` the next call
  round-tripped again. The AI retry/backoff is now bounded on both fronts:
  provider-SDK internal retries are disabled at client init (`max_retries=0` for
  Anthropic/OpenAI, `retry_options=attempts=1` for google-genai) so the gateway is
  the sole retry controller; and the first quota/`429` error arms a short cooldown
  during which the remaining LLM calls short-circuit straight to their non-LLM
  fallback (the built-in remediation knowledge base, heuristic FP review, etc.)
  instead of each making a doomed call. The cooldown is sized from the server's own
  `Retry-After` hint when present, else a bounded default, always clamped, and
  self-clears; `HEAVEN_LLM_RATELIMIT_COOLDOWN=0` disables the breaker. Genuinely
  transient errors (5xx/timeout) are still retried on the existing bounded backoff.
  A throttled key now degrades a scan to its (excellent) non-LLM output in seconds
  rather than minutes.

- **Report proofs no longer fabricate an HTTP request/response for findings that
  never made one.** The evidence renderer unconditionally emitted a
  `Request: GET <target>`, a `Response: HTTP 0 (0 bytes)` line, and a `curl`
  reproduction for *every* finding, including DNS/mail posture (SPF, DMARC,
  DNSSEC, MTA-STS), TLS, and exposed-service findings that issue no HTTP request
  at all. The result was a report where nearly every proof read as fake
  (`GET certifiedhacker.com` → `HTTP 0 (0 bytes)`, plus a `curl` that reproduces
  nothing). The renderer now emits the HTTP request/response/`curl` block only
  when the finding actually performed an HTTP transaction; DNS/mail/network
  findings instead show their real observed evidence (the actual SPF record, DNS
  answer, port/service). Relatedly, the security-header audit now carries the
  real response status and headers (Set-Cookie redacted), so a missing-header
  finding shows a genuine `HTTP 200` with the headers as proof instead of
  `HTTP 0`.

- **Several web detectors no longer emit false positives on ordinary sites.**
  (1) `race_condition` fired on mere HTTP status-*variance* across concurrent
  requests, so an admin panel that simply answered inconsistently (`/cpanel`
  returning a spread of 301/401/403) produced a bogus "Race Condition Detected".
  It now requires genuinely divergent *successful* responses to identical
  concurrent state-changing requests (never GET), reported as a low-confidence
  lead. (2) `http_smuggling_indicator` treated any non-`(400,501,505)` status
  differing from baseline as a signal, so a WAF's `406` tripped it, and it
  attached the unrelated **CVE-2019-16278** (a nostromo RCE) to the guess. It now
  ignores 4xx/5xx rejections (only a normal 2xx/3xx deviation counts) and carries
  no bogus CVE. (3) `dangerous_http_method` flagged PUT/DELETE on any status
  `< 405`, so a benign `404` fired; it now requires a real success (200/201/204/
  207). (4) An "endpoint accepts XML" surface note (`xml_accepted`) was aliased
  into the full **XXE (High, CWE-611)** class and fired on any `200` to an XML
  POST; it now has its own low-severity taxonomy and only fires when the response
  is genuinely XML/SOAP or shows an XML parser error. Confirmed
  `xxe_entity_expansion` stays High.

- **Coverage gaps closed vs a real external host.** Internet-reachable databases
  (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch,
  CouchDB, Memcached, Cassandra) are now flagged as an exposure
  (`database_exposed`, high), but only on a public/routable host, so
  internal-range (`/24`) scans aren't spammed. The end-of-life table gained
  **PostgreSQL** (branches before 13) and **ISC BIND** (before 9.18), and the
  network scanner now fingerprints the **cPanel / WHM / webmail control-plane
  ports** (2077/2078/2082/2083/2086/2087/2095/2096) and alt-SSH (2222), which are
  ubiquitous on shared-hosting targets.

- **Scans no longer crash the server with "Python quit unexpectedly" when an SSH
  target is in scope.** `asyncssh` ships an optional UMAC message-auth
  implementation that is an untyped `ctypes` binding to the native Nettle library
  (`asyncssh/crypto/umac.py`); on some platforms that binding is ABI-incompatible
  with the installed `libnettle` and **segfaults the instant an SSH MAC is
  computed** (reproduced on Apple Silicon + CPython 3.14 + Homebrew `nettle` 9:
  `nettle_umac64_digest` → SIGSEGV). Because HEAVEN runs scans in-process, that
  native crash took down the whole API server, every in-flight scan died and the
  UI showed "Load failed". It triggered on any ordinary engagement: connecting to
  an SSH service that offers `umac-64@openssh.com`/`umac-128@openssh.com` MACs
  (OpenSSH does, e.g. Metasploitable-2). New `heaven/utils/ssh_safe.py` strips
  those UMAC MACs from `asyncssh`'s negotiation before any connection (its
  documented no-Nettle fallback path), so SSH negotiates a standard HMAC-SHA2 MAC
  instead, verified against a live SSH handshake. Every SSH call site now routes
  through `ssh_safe.connect`, and `faulthandler` is enabled at server/CLI startup
  so any *future* native crash surfaces a Python traceback instead of a silent
  kill.

- **SARIF export now carries usable locations and lost its stray-file side
  effect.** The previous exporter read a non-existent `asset` key, so every
  `artifactLocation.uri` was `"unknown"`, and calling it without an output path
  silently wrote a `heaven-results.sarif` into the working directory. Both the
  `heaven export`/scan paths and the API now route through the new
  `ci_export.findings_to_sarif`, which uses the finding's real target and writes
  nothing unless asked; `aggregator.export_sarif` delegates to it for
  backward-compatibility.

- **Version-based CVE mapping no longer floods reports with unverified
  "potential" CVEs as confirmed Criticals.** When a service banner named a
  product but not its exact version (e.g. a hardened `Server: Apache` with the
  version stripped), the inline-CVE path emitted *every* CVE known for that
  product as a separate Critical/High **Open** finding, so a single Apache host
  reachable on ports 80 and 443 produced ~20 speculative findings, and a
  *patched* server that still advertised an old-looking banner would light up
  red. The version-undetermined path now collapses to **one** low-severity,
  low-confidence `potential_vulnerable_service` finding per product per host that
  names the candidate CVEs for manual verification instead of asserting them.
  Findings with a real, observed version are unaffected (each matched CVE keeps
  its genuine per-CVE score). On a live re-run of an external target whose
  Apache/Dovecot versions are hidden, this removed roughly 30 speculative
  Critical/High rows.
- **Bounded CVE version ranges are matched jointly (AND), not as a flat OR, kills
  "patched-but-flagged" false positives.** A record like OpenSSH regreSSHion's
  `['<=9.7p1', '>=8.5p1']` (affected 8.5p1-9.7p1) was matched if *any* single
  spec held, so a **patched OpenSSH 9.9** matched via `>=8.5p1` alone and was
  reported as vulnerable. A new shared `heaven/vulnscan/cve_mapper.py::
  specs_match_version` treats a `>=`/`<=` pair as a bounded window that must hold
  jointly, keeps branch-ceiling lists (`['<=16.1','<=15.5']`) and exact/dash/`all*`
  clauses as OR, and now backs both the inline DB and the live-feed
  `filter_by_version` confirmation. This corrects the same over-match on Log4Shell
  (patched 2.17), Struts, GitLab, Confluence, Redis, Samba and Node.js records, 
  a version above the fixed ceiling no longer matches.
- **Consolidated "potential" service findings deduplicate per host+product**, so
  a version-undetermined service reachable on several ports (Apache on 80 *and*
  443) is reported once rather than once per port. Confirmed per-CVE findings keep
  their existing per-(host, port, CVE) identity.
- **Server-version / security-header findings from a cross-site redirect are no
  longer attributed to the in-scope target.** The header audit follows redirects,
  so a target that redirected to a CDN / parking / SSO host fronted by a
  *different* server (e.g. `Server: nginx/1.29.8` when the real host runs Apache)
  produced a wrong-target "Server Version Disclosed" false positive. A new
  same-registered-site guard (`heaven/vulnscan/auth_scanner.py::_same_site`) drops
  every header-derived finding when the response was redirected off the target's
  registered domain; on-site hops (`http→https`, apex↔`www`) and IP targets are
  unaffected, and a genuine on-host banner still reports (now with the observed
  URL recorded in evidence).

- **Directory brute-force silently found nothing when ffuf 2.x was installed.**
  `dir_fuzzer` prefers the ffuf binary when present, but the invocation passed
  `-silent`, a flag removed in ffuf 2.x, so ffuf aborted with "flag provided
  but not defined", wrote no output, and the wrapper returned zero, while the
  working native async engine was skipped precisely *because* ffuf was present.
  Net effect on a live Metasploitable 2 target: 0 interesting directories where
  the native engine finds several. Fixed by dropping the unsupported flag and
  making `_run_ffuf` return `None` on any failure (missing binary, non-zero exit,
  unparseable output), distinct from `[]` ("ran, found nothing"), so `fuzz`
  falls back to the native engine per-target. A target ffuf handled is trusted
  and never re-scanned. Live-verified: `http://192.168.0.162/` now returns real
  200/301 hits (`index.php`, `phpinfo.php`, `phpMyAdmin`) across the
  200/300/403 bands the report expects.

### Security

- **Dependency floors patched to the nearest fixed stable (audit + SCA verify).**
  A `pip-audit` / OSV pass bumped floors in `pyproject.toml` for advisories in
  `aiohttp`, `scikit-learn`, `click`, `python-dotenv`, `pyjwt`, `cryptography`,
  `dnspython`, `scapy`, `jinja2`, `asyncssh`, `azure-identity` and the dev tools
  (`pytest`, `black`, `flask`), floors only, no new packages, nothing that breaks
  the pinned React 19 / Vite 8 / Node ≥22 UI stack. The reported
  `extract-zip 2.0.1` / **CVE-2026-56876** (symlink path-traversal) is **not** a
  HEAVEN dependency (absent from `heaven-ui/package.json`, `package-lock.json` and
  `node_modules`); instead HEAVEN's own SCA scanner is verified to flag it on a
  *target* lockfile, an `extract-zip@2.0.1` `package-lock.json` is parsed as an
  npm package and, against the OSV advisory, reported as `vulnerable_dependency`
  carrying CVE-2026-56876 and its fix.

## [2.1.0]: 2026-08-04

Accuracy and scope-correctness release. Builds on 2.0.0 with a false-positive
elimination pass on the injection scanner, a scope-safety fix so a URL target
never drags in unrelated services on a host's *other* ports, a completed DVWA
benchmark ground truth, and a genuine 100 % native functional benchmark.

### Changed

- **Native functional benchmark is now a genuine 100% / 100% / 100%
  (precision / recall / F1).** The one remaining unmatched finding, the werkzeug
  server-version header leak, is a real information disclosure, so it is now
  labelled in the ground truth; the benchmark floor is tightened from "precision
  ≥ 0.90" to an exact perfect score, making any future false positive *or* newly
  emitted real finding fail the benchmark until it is triaged.

### Fixed

- **Authenticated crawler no longer logs itself out, restores deep, behind-login
  detection.** The web crawler followed *every* same-origin link, including
  logout links (e.g. DVWA's `/logout.php`). Because that URL tears the session
  down server-side and every scanner shares the one authenticated session, once
  any request reached it the crawler, injection, fuzzing and auth scanners were
  all bounced to the login page and detection silently collapsed, and, since
  requests fire concurrently, *whether* the logout landed first was
  timing-dependent, so the collapse was intermittent and unreproducible. The
  crawler (both the aiohttp and Playwright paths) now skips session-destroying
  URLs, `logout` / `logoff` / `signout` / `signoff` / `deauth` / `disconnect` /
  `session/{destroy,end,kill}` and `?action=logout`-style query values, via a
  new, unit-tested `heaven/recon/web_crawler.py::_is_session_destroying` (matched
  per path-segment, so `/checkout`, `/login`, `/sessions` stay in scope).
  Measured against the DVWA benchmark, authenticated recall of the
  detection-required set went from **0% → ~80%** (SQLi ×2, reflected-XSS ×2,
  command-injection ×2, LFI ×2 detect deterministically). The DVWA benchmark now
  asserts a real recall floor (≥ 0.5) instead of only "a scan ran," so this
  regression cannot return unnoticed.
- **Injection scanner false-positive pass, three real detector FPs eliminated,
  live-verified against DVWA.**
  - *Time-based SQLi cross-parameter false positive.* Every parameter of a URL is
    probed concurrently, so a genuinely-injectable parameter's `SLEEP` request and
    a benign parameter's probe were in flight at once; against a serialising
    target (single-threaded PHP/MySQL) the benign request queued behind the real
    sleep and inherited its delay, and the interference *scaled* when the sleep
    doubled, defeating a naive check. Time-based detection now (a) runs every
    timed measurement under a global lock so no two injected sleeps ever overlap,
    and (b) confirms a hit only when doubling the sleep adds proportional delay
    (`_time_blind_confirmed`). Fixed a critical-looking `SLEEP` false positive on
    DVWA's non-injectable `Submit` button.
  - *RFI false positive on pages that merely mention a PHP directive.* The remote-
    file-inclusion check keyed on a bare `allow_url_include` / `allow_url_fopen`
    substring, so any documentation or phpinfo page that *names* the directive
    (DVWA's `instructions.php`) was flagged. RFI now requires the response to name
    our unroutable probe host, proof the app actually attempted the remote fetch.
  - *Command-injection false positive on log/aggregation pages.* The echo marker
    was a fixed constant, so a page that reflects previously-submitted payloads (a
    log viewer such as DVWA's `ids_log.php`) echoed the marker from *other* scan
    requests and false-positived as RCE. The marker is now unique per request and
    the reflected `echo <marker>` command text is stripped, so only genuine echo
    *output* counts.
- **Scope-safe port expansion, a URL target no longer pulls in unrelated
  services on the same host's *other* ports.** When the operator submits a bare
  IP / hostname / CIDR, HEAVEN discovers and web-scans whatever web app that host
  turns out to run (the internal-scan capability, unchanged). But a host reached
  *only* via an explicit `scheme://host:port` URL is now scanned at exactly that
  origin: its other open ports are outside the operator's declared scope, so
  authorising `https://app.example.com` never spills over into a different
  service on `app.example.com:8080` (potentially a separate app or team), and a
  scan of `http://localhost:8080/` no longer drags in an unrelated dev server
  co-located on `localhost:5000`. The web-URL bridge is gated on a new
  `heaven/orchestrator.py::_is_port_expansion_host` predicate (exact host, CIDR
  containment, or subdomain of a bare-host target); service-level checks
  (exposed-DB / SSH / RDP) on directly-scanned hosts are unaffected. This also
  removes the localhost cross-service noise that had depressed recall on shared
  developer boxes.
- **DVWA benchmark ground truth completed** so real, previously-unlabelled DVWA
  vulnerabilities (the `brute` username SQLi, the `fi` header-reflected XSS, the
  `xss_s` name-field stored XSS, and the `csp` script-injection sink) are credited
  as true positives instead of being scored as false positives. Focused
  crawl→scan precision rose from **59% → 94%** with recall holding at 80-90%.

## [2.0.0]: 2026-08-01

HEAVEN's first **major** release, consolidating everything built on top of the
1.0.0 foundation into a hardened 2.0 line. Highlights: the web risk taxonomy
moved to the **OWASP Top 10:2025** model platform-wide; scoring was overhauled
with **per-finding contextual CVSS** (Temporal + Environmental), **CVSS v4.0**
support, and severity ⇄ CVSS reconciliation so a label and its score can never
contradict; the web UI migrated to **React 19**, clearing the `react-router`
advisory at the source; and new capabilities landed, a standalone **DNS
enumeration** tool, authenticated **cloud IAM auditing** (AWS / GCP / Azure), a
network-reachable **wireless configuration review**, and **OT / IoT framework**
scoring, alongside a sustained false-positive-reduction effort and reproducibly
green CI. The complete, itemised history follows.

### Added

- **DNS enumeration tool (`heaven dns`), records + subdomains surfaced in the
  Assets view and reports, wired end-to-end.** A new enumeration engine
  (`heaven/recon/dns_recon.py::enumerate_dns`) resolves a domain's full DNS
  surface, A / AAAA / MX / NS / TXT / SOA / CNAME records, mail servers,
  nameservers, DNSSEC status, wildcard detection, and brute-forces a curated
  common-subdomain wordlist, reporting a subdomain **only** when it actually
  resolves (nothing fabricated; skipped entirely on wildcard domains where every
  label would resolve). A shared normalizer (`heaven/devsecops/dns_inventory.py`,
  the DNS counterpart of the host `inventory` module) is the single source every
  surface renders identically. Surfaced everywhere: the standalone CLI tool
  `heaven dns <domain>` (`--no-subdomains` / `--no-security` / `--engagement` /
  `--format table|json|markdown`), a new **🌐 DNS Enumeration** section on the web
  **Assets** page and in the `heaven assets` CLI output (both fed by `GET
  /api/assets`, which now returns `dns` + `dns_totals`), and a **DNS Enumeration**
  section (records table + resolved subdomains + DNSSEC/wildcard) in the HTML,
  PDF and Markdown reports with a matching table-of-contents entry. The
  orchestrator's DNS recon task now persists the enumeration into the scan
  summary (`dns_records`) so every full/network/web/email scan populates it
  automatically, and the whole scoring/rendering path is offline-safe (empty,
  never an exception, when nothing resolves). Regression-locked by
  `tests/test_dns_enumeration.py`.

- **Per-finding CONTEXTUAL CVSS, a genuinely dynamic 0.0-10.0 score for every
  finding, shown beside the standards base score.** A CVSS *base* score is, by
  the spec, a property of the weakness class, so two findings of the same class
  (two reflected-XSS, two missing-header issues) legitimately share it, which is
  why the report's CVSS column repeated within a severity band. HEAVEN now also
  computes each finding's CVSS **Temporal + Environmental** score
  (`heaven/utils/cvss.py::contextual_score`), the same instance-specific number
  Tenable/Qualys/Rapid7 surface, from the real per-finding signals the platform
  already collects: Exploit Code Maturity (EPSS probability / public-exploit /
  CISA-KEV), Report Confidence (the detector's own confidence), and the asset's
  Security Requirements (criticality) + Modified Attack Vector (internet-facing vs
  internal). It is standards-based, not fabricated: the number moves because the
  *evidence* moves, and a finding with no such signals degrades exactly to its
  base score (never a random jitter). The HTML **and** PDF reports now show a
  **CVSS** (base) column and a **Contextual** column side by side, the web
  Finding Detail shows both (`contextual_cvss_score` on `GET /api/.../evidence`),
  and the persisted risk/priority score falls back to the contextual score so
  prioritisation is per-finding too. Result: same-class findings that used to
  read one identical number now read e.g. 7.4 / 6.0 / 4.6. Regression-locked by
  `tests/test_per_finding_cvss.py`.

- **Animated README hero poster** (`docs/assets/heaven-poster.svg`). A single,
  self-contained SMIL-animated SVG, no third-party image services, carrying the
  Ascendant Aegis mark, the violet→cyan→emerald brand ramp, a live-recon radar
  with target-lock pings, the **Recon → ML Risk → Verified Exploit → Report**
  pipeline (with a travelling packet), and a verified in-sync stat strip (1327
  tests · 51 CLI · 64 API routes · 24 UI pages · 12 scan modes · CVSS ML R²=0.9925).
  Replaces the three external capsule-render / typing-SVG banners at the top of the
  README with one brand-exact, offline-safe hero.

- **Full-power runtime dependencies are now installed by default, so the proof
  and credentialed-audit paths light up out of the box.** The `playwright` wheel
  and `pywinrm` join the base install, and `scripts/install.sh` fetches the
  headless-Chromium bundle automatically (skippable with `HEAVEN_CORE_ONLY=1` or
  `HEAVEN_SKIP_BROWSER=1`). This turns on, with no extra steps: the **XSS
  execution proof** and **JS-rendered crawl** (Playwright), and **WinRM**
  credential-reuse validation (pywinrm) alongside the existing SMB/SSH. The
  authenticated multi-cloud IAM audit now declares its real SDKs in the right
  extras, `[cloud-azure]` gains `azure-identity` / `azure-mgmt-authorization` /
  `azure-mgmt-resource` and `[cloud-gcp]` gains `google-api-python-client` /
  `google-auth`, so `heaven cloud iam --provider azure|gcp` enables with a
  single `pip install -e ".[cloud-azure]"` (or `[cloud-gcp]`). Every one of these
  still degrades gracefully with an honest install hint when its dependency is
  absent.

- **`heaven doctor` and the web System-Health panel now report *runtime
  capabilities*, optional feature-enablers that aren't PATH binaries.** The
  first is the **Playwright browser bundle** that arms the headless-browser XSS
  execution proof and JS-rendered crawl: the wheel ships in the base install but
  the ~150 MB Chromium download is separate, so operators previously had no way
  to see whether that capability was actually *armed*. It now shows as a clear
  "armed / not armed" row (with the one-line `playwright install chromium` hint
  and a next-step when missing), reported honestly, only present when
  Playwright's own resolved Chromium executable exists on disk. The probe is
  safe from both the sync CLI and the async web endpoint.

- **Credential-reuse validation gained LDAP/LDAPS and Kerberos handlers**, so a
  discovered credential is now validated against directory services too, not
  just SSH/HTTP/SMB/WinRM. `ldap`/`ldaps` perform an authenticated simple bind
  (ldap3), and `kerberos` proves the password via an AS-REQ pre-authentication
  TGT request (impacket) without touching any application service. Both are
  never-overclaim: LDAP refuses an empty password (RFC 4513 unauthenticated
  bind), and Kerberos requires the realm (`DOMAIN\user` / `user@domain`) and
  treats `KDC_ERR_PREAUTH_FAILED` as a clean no-hit. The orchestrator's
  cred-reuse path auto-targets LDAP/LDAPS (389/636) on discovered hosts.

- **Web-exploitation depth (P0): proven XSS + two new confirmation-based
  detectors + a taxonomy gap-fill.** Reflected/DOM XSS is now *proven*, not just
  detected, a new `XSSExecutionProver` loads the injected request in headless
  Chromium (Playwright) and only confirms when the payload's JavaScript actually
  executes (a `dialog` carrying a unique per-run token); it is authorization-
  gated and degrades gracefully with an install hint when Playwright is absent.
  A new **XPath-injection** detector (error-based + boolean-differential) and a
  **WebSocket** detector (cleartext `ws://` plus Cross-Site WebSocket Hijacking,
  raised only when the app uses cookie auth *and* the handshake ignores a foreign
  `Origin`, so cookieless/origin-validated/third-party sockets stay silent) join
  the anomaly probe. Finally, ten anomaly categories that previously rendered
  with blank OWASP/MITRE/CVSS columns (NoSQL, LDAP, XPath, prototype-pollution,
  integer-overflow, format-string, buffer-overflow, resource-exhaustion,
  version-regression, IP-restriction-bypass) now carry curated
  CWE/OWASP-2025/MITRE/CVSS-vector taxonomy, and the orchestrator tags each
  anomaly finding with a real `vuln_type` so enrichment resolves it.

- **Dynamic closed-loop scanning (P1): the scan now reacts to its own
  discoveries.** A new feedback engine (`heaven/feedback.py`) watches every
  finding and task result as it lands and distils fresh, in-scope scan inputs
  from them, new hosts (from loot, redirects, findings), JS-bundle endpoints,
  credentials and tokens. In-scope new hosts get a self-contained follow-up scan
  (recon → web-derive → injection) injected into a new `DYNAMIC_FOLLOWUP` phase;
  JS-derived endpoints are fed straight into the injection/API scanners. Scope is
  never widened (a derived host is actioned only when it is already inside the
  operator's targets), and dedup + generation/host caps guarantee the loop
  terminates. JavaScript bundles are now mined for endpoints as a first-class
  pipeline step (`JS Bundle Endpoint Mining`), resolving each route to an
  absolute, same-origin URL and dropping third-party/noise matches.

- **Insecure-deserialization detector + confirmed cache poisoning (P2).** A new
  signature-verified detector flags unsafe-deserialization surface actually
  present in HTTP traffic, Java serialized objects (`0xACED` magic / content-
  type) and PHP serialized-object cookies, so a benign app stays silent. The
  existing unkeyed-header cache-poisoning check is upgraded from reflection-only
  to *confirmed*: a safe per-test cache-buster isolates a throwaway cache entry,
  and a finding is raised `high` only when a clean follow-up request is served
  the injected canary from cache (mere reflection is downgraded to a low
  indicator).

- **Authorized credentialed network testing, SMB + WinRM (P2).** The
  credential-reuse validator now sprays *discovered* credentials over SMB
  (impacket) and WinRM (pywinrm, optional) in addition to SSH/HTTP, and the
  autonomous post-ex chain builds per-service reuse targets from the open ports
  it actually found (SSH→22, SMB→445, WinRM→5985/5986). Authorization-gated;
  tests known credentials, never guesses.

- **Multi-cloud authenticated IAM/RBAC parity, GCP + Azure (P3).** The
  read-only authenticated IAM audit now covers all three major clouds via a
  single dispatcher (`audit_cloud_iam(provider=…)` / `heaven cloud iam
  --provider aws|gcp|azure`). **GCP** reads the project IAM policy and flags
  public bindings (`allUsers`/`allAuthenticatedUsers`) and primitive Owner/Editor
  grants; **Azure** reads subscription-scope RBAC and flags Owner / Contributor /
  User Access Administrator assignments and legacy classic administrators. Each
  degrades gracefully when its SDK or credentials are absent, and the secret is
  never read or logged.

- **Report Findings Summary now shows a genuine, per-finding CVSS score** instead
  of a value that tracked severity (e.g. every High reading 6.2). A single
  resolver prefers, most-authoritative-first: a real published base score
  (NVD/OSV/CVE), the KB's per-class score, the CVSS v3.1 base score computed from
  the class's curated vector, then, last, the severity-anchored ML prediction.
  A CVE finding now shows its true NVD score and two different vulnerability
  classes no longer collapse to the same number.
- **Multi-step remediations render one step per line** in the HTML and PDF
  reports (numbered steps and Verify/Reference markers each start a new line)
  rather than one run-on paragraph, both newline-separated and legacy inline
  `1. … 2. …` text are handled, and version numbers like `9.9` are never split.
- **Authenticated AWS IAM privilege audit** (`heaven/recon/cloud_iam.py`,
  `heaven cloud iam`, and a CLOUD-mode orchestrator task). When AWS credentials
  are supplied via the standard chain (env vars / `--profile` / instance role),
  it audits the identity you are authenticated as, **read-only** (STS
  `GetCallerIdentity` + IAM `List*`/`Get*`), and HEAVEN never reads or logs the
  secret (boto3 resolves it). Reports over-privileged principals (a policy that
  literally grants `*`/`*`), console users without MFA, stale/unrotated access
  keys, root access keys and a weak/absent password policy. Fires only on
  positive evidence, a least-privileged key yields no issue findings, and
  no-ops gracefully when no credentials are present.

- **OWASP API Security Top 10 (2023) coverage matrix + full framework-coverage
  parity across report, self-grade and web UI.** The API scanner already tagged
  findings with `owasp_api` (API1, API10) but the professional report never
  rendered an API matrix. Now the HTML **and** PDF report render an "OWASP API
  Security Top 10 (2023) Coverage" matrix (shown only when the engagement has
  API findings), and the **Coverage self-grade page** (`heaven coverage` /
  `/api/coverage` / the web UI) now scores **all four** frameworks, web OWASP
  2021, OWASP API 2023, OWASP IoT 2018 and IEC 62443, instead of web-OWASP
  only. API/IoT/OT findings are excluded from the web matrix everywhere so
  nothing is double-counted, and the self-grade can never disagree with the
  report. Fixed a latent bug where the grader built the API category list but
  never populated its finding counts (always 0).

- **New provable, read-only per-domain detectors.**
  - **API:** `API9 Improper Inventory Management`, body-confirmed exposure of
    OpenAPI/Swagger specs, Swagger UI / GraphQL Playground and Spring Boot
    Actuator management endpoints; `API2 Broken Authentication`, a
    conventionally-authenticated collection endpoint returning records/sensitive
    objects with no credentials (conservative, needs-verify). A benign SPA that
    returns 200-HTML on every path produces zero findings.
  - **Containers / Kubernetes:** kube-apiserver legacy insecure port (8080),
    exposed cAdvisor (4194), and open Docker registry v2 catalog (5000). Also
    **fixed a real bug**: the read-only kubelet port (10255) was probed over
    `https`, so that check never fired, it now uses `http` for 10255 and
    `https` for 10250.

- **Wireless configuration-review surrogate (`heaven scan --mode wireless`).**
  RF/monitor-mode Wi-Fi scanning needs local radio hardware a remote scanner
  cannot have and is never faked; instead a new `heaven/recon/wireless_posture.py`
  reviews the **network-reachable** management plane of wireless infrastructure, 
  vendor-fingerprinted AP / router / WLAN-controller web admin panels, over
  read-only GETs, flagging exposed (medium) or unauthenticated (high) interfaces.
  The `wireless` scan mode is wired end-to-end (config → orchestrator → CLI → API
  → web launcher) and the NIST 800-115 §4.4 mapping updated accordingly.

- **Cloud identity recon, credential-free Azure AD / Microsoft 365 tenant
  discovery (`heaven/recon/azure_tenant.py`, CLOUD mode).** The existing cloud
  checks cover storage exposure and metadata SSRF but not the *identity* plane.
  Using only Microsoft's own public, unauthenticated discovery endpoints
  (`getuserrealm.srf` + the tenant OpenID-Connect metadata), HEAVEN now confirms
  whether a target domain is backed by Entra ID, whether authentication is
  **managed** (cloud-only, external sign-in/spray surface) or **federated**
  (disclosing the on-prem/ADFS STS), and resolves the **tenant GUID** and region.
  Read-only GETs against Microsoft, no target credentials used or guessed;
  reported at **informational** severity (external attack-surface intelligence,
  not a flaw) and only when Microsoft positively confirms a tenant, so it can
  never false-positive on a non-Entra domain.

- **Cloud identity recon, ADFS / federation endpoint reachability** (extends
  `heaven/recon/azure_tenant.py`). When user-realm discovery reports a
  **federated** domain it also discloses the target's Security Token Service
  (`AuthURL`); HEAVEN now turns that into concrete posture with two further
  read-only GETs against the disclosed STS: (1) if the WS-Fed/SAML
  `FederationMetadata.xml` is reachable it raises an **informational**
  `federation_sts_exposed` finding that maps the internet-facing on-prem/ADFS
  identity component (STS host, endpoints, token-signing certificate) as a pivot
  target; (2) if the ADFS **IdP-initiated sign-on page**
  (`/adfs/ls/idpinitiatedsignon.aspx`) is served it raises a **medium**
  `adfs_idp_signon_enabled` finding, Microsoft recommends disabling it because
  it is an unauthenticated password-spray target and username-enumeration oracle.
  Both fire only from positive evidence (metadata actually parsed / the sign-on
  page actually served with ADFS markers), so a hardened or non-ADFS STS yields
  nothing.

- **Active Directory, anonymous LDAP _enumeration_ depth.** Previously the AD
  scanner detected an anonymous LDAP bind (RootDSE read) but never proved its
  impact. It now performs a bounded, read-only anonymous subtree search for
  enabled user accounts; if the Domain Controller returns real `sAMAccountName`
  values without credentials, it raises a **high**-severity
  `anonymous_ldap_enumeration` finding (pre-auth user list → password-spray /
  AS-REP-roast target material) with a sample of the exposed accounts as
  evidence. It fires only when concrete accounts come back, so a hardened DC that
  merely permits the RootDSE read is never flagged.

- **IoT and OT findings are now scored against their _own_ security frameworks,
  not the web OWASP Top 10.** A Modbus PLC reachable on the LAN is not "A01
  Broken Access Control", so device and industrial findings are mapped to the
  standards the industry actually uses (`heaven/devsecops/frameworks.py`):
  - **Consumer / building-automation IoT → OWASP IoT Top 10 (2018)** (I1, I10):
    default credentials → I1, exposed MQTT/RTSP/UPnP → I2 Insecure Network
    Services, device web panels → I3, cleartext CoAP → I7, default SNMP
    community → I9.
  - **Operational technology / ICS → IEC 62443-3-3 foundational requirements**
    (FR1, FR7) cross-referenced to **MITRE ATT&CK for ICS**: an unauthenticated
    Modbus/S7comm/DNP3/IEC-104/OPC-UA/EtherNet-IP/BACnet service → FR1
    Identification & Authentication Control (Modbus, being writable, carries
    T0855 Unauthorized Command Message); an open-but-unconfirmed ICS port →
    FR5 Restricted Data Flow.
  - The professional report (HTML **and** PDF) now renders **two new dynamic
    coverage matrices**, "OWASP IoT Top 10 (2018) Coverage" and "OT / ICS
    Security Coverage (IEC 62443)", shown only when the engagement actually
    produced device/industrial findings, and linked to the concrete findings
    that landed in each category. The per-finding detail (report + web UI) shows
    the correct framework row instead of a blank or wrong web-OWASP label.
  - IoT/OT findings are explicitly **excluded from the web OWASP Top 10 (2021)
    matrix** so a Modbus finding whose title contains "unauthenticated" can no
    longer be mis-bucketed into A01, the enrichment layer no longer forces a
    web category onto a finding that carries an IoT/OT tag.

- **Real-world report parity, new detectors closing the gaps against
  professional pen-test/health-check deliverables.** A gap analysis against two
  real Cyphere engagement reports (an internal IT security health check and a
  black-box WordPress web-app test) surfaced high-signal findings HEAVEN wasn't
  producing; every one is now a genuine, read-only, confirmation-based check:
  - **CMS/WordPress hardening scanner** (`vulnscan/cms_scanner.py`, WEB/API scan
    modes): flags an **admin panel exposed to the Internet** (`/wp-login.php`,
    `/wp-admin`), an enabled **XML-RPC** endpoint (HIGH when it advertises the
    SSRF/DoS-abused `pingback.ping`, confirmed by a read-only `system.listMethods`
, never an actual pingback), **WordPress version disclosure**, and **username
    enumeration** (`/wp-json/wp/v2/users`, `?author=`). Fingerprint-gated, so it
    no-ops on non-WordPress sites.
  - **Server software-version banner exposure** (misconfig scanner): flags
    `Server: nginx/1.22.1`, `X-Powered-By`, `X-AspNet-Version` etc., only when a
    concrete version is present (a bare product token isn't flagged).
  - **Deeper network-service probes** (`recon/network_exposure.py`, all read-only):
    an **IPMI RAKP password-hash disclosure** probe (RMCP+/RAKP-2 hash dump,
    CVE-2013-4786) that upgrades a bare IPMI exposure to a proven HIGH; **SNMP
    GETBULK amplification** measurement (reflected-DDoS source); an active
    **anonymous-FTP login** test; and an **RDP Network Level Authentication (NLA)
    not-required** negotiation probe. Each fires only on a proven, attacker-
    favourable response, disabled under the stealthiest profiles.
  - **Unsupported / end-of-life software detector** (`vulnscan/eol_scanner.py`,
    CWE-1104): turns the discovered product/version/OS inventory into
    unsupported-software findings (Windows 10 22H2, Silverlight, Apache httpd 2.2,
    PHP < 8.1, OpenSSL < 3.0, …), version-gated against published vendor EOL dates
    and carrying the EOL date as proof.
  - Full CWE/OWASP/MITRE/CVSS taxonomy added for all new finding classes, so they
    enrich cleanly into reports; wired mode-aware into the orchestrator (CLI +
    web/API scan paths inherit them automatically).

- **New "Ascendant Aegis" brand identity, one mark, synced everywhere.** HEAVEN
  now has a proper logo: a faceted violet→cyan→emerald hexagonal aegis (the app's
  own `#6D7CFF → #22D3EE → #34E5A3` ramp) enclosing an "H" whose crossbar rises to
  a glowing apex node, its six vertices reading as a targeting reticle. It is
  single-sourced (`heaven-ui/src/components/Logo.jsx` for the app, a canonical
  `heaven-ui/public/heaven-mark.svg` for everything else) and carried consistently
  across every surface: the web UI sidebar and login screen, the browser favicon,
  the CLI startup banner, reframed as a gradient box that renders a genuine
  top-to-bottom violet→cyan→emerald ramp, the `heaven` command-centre dashboard,
  the HTML and PDF report cover pages, and the README. Report covers also adopt
  the HEAVEN indigo accent (`#4f46e5`) so client deliverables match the identity.
  The old ⚡ emoji placeholder is gone; the screenshots in `docs/` were regenerated
  against the new look.
- **Authenticated scanning from the web UI.** The scan launcher now has an
  optional "Authenticated scan" panel, supply the target's session cookie or a
  form-login spec (and, optionally, a second lower-privilege identity) and the
  web-launched scan runs its authenticated crawl, IDOR checks and the multi-role
  Broken Access Control audit, exactly like the CLI's `--cookie-file`/`--auth`
  and `--low-priv-*` flags. Previously credentials could only be passed on the
  command line, so BAC's *proven* mode was unreachable from the browser. The
  `POST /api/scans` body gains `cookie` / `auth` / `low_priv_cookie` /
  `low_priv_auth`; sessions are activated before the pipeline runs and cleared
  after, so one scan's credentials never leak into the next.
- **Hidden-parameter mining (Arjun-style).** A new `param_miner` recon module
  discovers *unlinked* GET parameters (`?debug=`, `?redirect=`, `?file=`, …) that
  the crawler can't see by observing the target's own reaction, reflection and
  out-of-band length/status deltas, isolated with bucket binary-search. Every
  candidate is confirmed with a fresh canary **and** a control junk parameter, so
  a name that merely rides response jitter never survives. Discovered parameters
  are emitted as input vectors and fed to the injection/anomaly scanners, which
  find (and actively confirm) vulns behind inputs nothing linked to. WEB/API modes.
- **Multi-role Broken Access Control audit (OWASP A01).** A new `access_control`
  module replays privileged-session URLs as anonymous, and, when you supply a
  second `--low-priv-cookie-file` / `--low-priv-auth` session, as that lower role
, and raises a finding only on a *proven differential*: the app protects a
  resource (anonymous denied) yet a lower identity still retrieves the same
  content. Correctly-enforced resources and public pages raise nothing. High +
  proven for the differential, medium + "verify" for a privileged path served
  anonymously.
- **Blind out-of-band command injection + reachable collaborator.** The OOB
  prober now proves blind OS command injection (a `curl`/`wget`/`certutil` payload
  that calls the in-house collaborator back = zero-FP RCE proof), alongside the
  existing SSRF/XXE. The collaborator can now advertise a routable address for
  remote engagements via `HEAVEN_OAST_HOST` / `HEAVEN_OAST_BIND` /
  `HEAVEN_OAST_PORT` (`OASTListener.from_env()`) while still defaulting to
  loopback.
- **Exposed-file & secret discovery (content-verified).** A new
  `exposure_scanner` finds world-readable `.git`, `.env`, `.htpasswd`, `phpinfo()`,
  `.DS_Store`, published JavaScript source maps and backup/editor copies of
  server-side files. Each hit is confirmed against a strict artefact signature and
  screened against a soft-404 baseline, so a SPA that answers `200` for every path
  produces no false positives.
- **Mid-scan session renewal.** A form login is now remembered (`remember_login`)
  so a session that dies during a long authenticated scan can be transparently
  re-authenticated (`refresh_active_session`) instead of the scan silently going
  unauthenticated.
- **Autonomous run now produces an executive report.** Every autonomous run ends
  with a professional summary, a plain-English executive narrative, a full
  severity breakdown (critical→info), the distinct hosts engaged, the top findings
  (with live NVD CVE links), the actions taken, and prioritised recommendations, 
  rendered in both the CLI and the web UI. This makes the output read like a report
  even on a lean rule-based (no-LLM) run.
- **Engagement picker on every launcher.** The Autonomous, SAST and SCA sections
  now have the same "Save findings to engagement" dropdown as the scan launcher
  (existing engagements with finding counts + "＋ New engagement…"), so a run's
  findings always land where you explicitly chose instead of a mistyped, empty
  engagement. New reusable `EngagementPicker` component.
- **Report download engagement selector.** The Reports page now lets you pick
  *which* engagement to export when more than one exists (defaults to the active
  one), passing the engagement's DB-stem name to every export format.
- **Lateral movement, load discovered hosts.** A one-click button pre-fills the
  spray targets with each `host:port` the network scan discovered speaking
  SSH/SMB/RDP, so targets come from real findings instead of manual entry.
- **Cross-engagement knowledge graph now populates.** Every completed scan records
  its findings' outcomes (per target-profile technique success/failure) into the
  knowledge graph, previously nothing wrote to it, so it was permanently empty.

- **Rename an engagement, CLI, API and dashboard.** An engagement's name was
  welded to both its store key *and* its SQLite filename
  (`engagements/<name>.db`) with no way to change it, so an awkward name (e.g.
  `certified hacker`) was permanent. You can now rename in place:
  - New **`heaven engage rename <old> <new>`** CLI command.
  - New **`POST /api/engagements/{name}/rename`** route, backing a **rename (✎)**
    action in the dashboard's engagement manager (which now also shows for a
    single engagement, so you can rename the only one you have).
  - The rename moves the DB and its WAL/SHM sidecars, rewrites the in-DB name
    row, handles a case-only rename on case-insensitive filesystems (macOS:
    `certified hacker` → `Certified Hacker`), and repoints the active pointer if
    you rename the engagement you're currently viewing. It never clobbers a
    different existing engagement. Covered by `tests/test_engagement_rename.py`.

- **Host & Service Inventory, open ports, service versions and OS, surfaced
  everywhere.** The network scanner already ran a full-spectrum nmap scan
  (`-sV -sC -O`, all 65535 ports by default, plus UDP), but the ports, service
  versions and OS it captured only lived inside the raw scan summary and never
  reached the operator. They are now a first-class inventory shown identically
  across the whole tool:
  - New **Assets** page in the web UI (host → OS → open ports / service versions
    / CPE), fed by a reshaped `GET /api/assets` that returns a normalized,
    deduplicated inventory plus roll-up totals.
  - New **`heaven assets`** CLI command (table / JSON / markdown), and every
    `heaven scan` / `heaven resume` now prints the inventory at the end.
  - A **"Host & Service Inventory" section** added to the HTML, PDF and Markdown
    reports (and the `heaven report` / `heaven export` / API report exports),
    so a written report documents the attack surface, not just the findings.
  - Accuracy improvements in the scanner: the service version now recombines
    nmap's product + version + extrainfo (previously the product name was
    dropped), and OS detection records its **source and confidence**, an nmap
    `-O` stack fingerprint is labelled *(fingerprinted, N%)* while a TTL guess is
    labelled *(heuristic, unconfirmed)*. Nothing is fabricated: an
    undetermined OS is shown as such, and a guess is never presented as a fact.
  - **OS fingerprinting no longer silently needs root.** `nmap -O` (and SYN/UDP
    scans) require raw sockets and abort the whole scan if run unprivileged, so
    HEAVEN now auto-elevates via passwordless `sudo -n` when it's available
    (controllable with `HEAVEN_NMAP_SUDO=auto|always|never`; `-n` never prompts,
    so no credential is ever handled), and detects an elevated session on
    Windows. When it genuinely can't fingerprint, it no longer falls straight to
    a coarse TTL guess: it first infers the OS from nmap's own service-detection
    evidence (the `ostype` attribute and OS-level CPEs that `-sV` reports without
    root), a real, more specific signal, still labelled *unconfirmed*, and logs
    a one-line hint on how to unlock authoritative results (run as root, enable
    passwordless sudo, or `setcap cap_net_raw` on nmap).
  - A shared `heaven/devsecops/inventory.py` is the single source of truth for
    normalization/labelling reused by the CLI, API, UI and reports;
    `tests/test_service_inventory.py` locks in the parsing, the no-false-positive
    OS labelling and the cross-surface rendering.

- **Per-section scan results in the web UI.** SAST and SCA runs now have their
  own result lists on the SAST and SCA pages (a "SAST scan history" / "SCA audit
  history" panel, same expandable-row + inline-findings view as the Scans page),
  instead of being merged into the general Scan Activity list where the same run
  showed up twice. Backed by a new `kind` filter on `GET /api/scans`
  (`pentest`, the default, excludes code-analysis runs, plus `sast`, `sca`,
  `all`). Reusable `ScanList` component (`heaven-ui/src/components/ScanList.jsx`)
  drives all three sections.
- **More scan modes in the launcher.** The Launch Scan mode dropdown now exposes
  every mode with a real scanner phase: FULL, WEB, NETWORK, API, CLOUD,
  CONTAINER, IOT, **OT**, AD and EMAIL (was only web/network/full/ad/cloud). Added
  `OT` (operational technology) to the `ScanMode` enum; it runs the same
  IoT/SCADA/OT scanner phase.
- **Dashboard quick-launch panel.** The dashboard now has a "Launch a scan" grid
  with a tile for every scan surface (Full, Web, Network, API, Cloud, Container,
  IoT, OT, AD, Email) plus the analysis tools (SAST, SCA, CVE), each one click
  from the landing page. Scan-mode tiles deep-link into the launcher with the
  mode preselected (`/scans?mode=<mode>`); FULL is highlighted and appears once.
  Both the panel and the launcher `<select>` read from one shared source of truth
  (`heaven-ui/src/scanModes.js`), so they can never drift apart.

### Changed

- **README module count is now a real, reproducible figure (157) and CI-guarded.**
  The badge and metric table read 148 while the footer/structure line read 152, 
  and neither matched the project's own counting method. It is now derived
  mechanically as the number of substantive Python modules in the `heaven/`
  package (`find heaven -name '*.py' ! -name __init__.py`) and synced across all
  four README spots by `scripts/sync_test_count.py`, whose `--check` mode CI
  already runs, so a reviewer who clones and counts gets exactly the printed
  number, and it can never silently drift again.

- **Upgraded the web OWASP mapping to the OWASP Top 10:2025 across the whole
  platform.** The report coverage matrix (HTML + PDF), the Coverage self-grade
  (`heaven coverage` / `/api/coverage` / web UI), the vulnerability knowledge
  base, every scanner/demo tag, the SAST rule pack and the methodology page now
  speak the 2025 taxonomy. The 2025 edition is a re-ranking with two structural
  changes that are respected everywhere: **SSRF** (A10:2021) folds into **A01
  Broken Access Control**, and **Vulnerable & Outdated Components** (A06:2021)
  broadens into **A03 Software Supply Chain Failures**; the brand-new **A10
  Mishandling of Exceptional Conditions** now receives verbose-error / stack-
  trace findings. A single canon + a 2021→2025 crosswalk live in
  `frameworks.py` (`OWASP_2025`, `normalize_owasp`, `owasp_2025_id`), so any
  finding stored under a legacy 2021 tag is **upgraded on read**, old
  engagement data renders as 2025 without a migration.

- **A blank "active engagement" now resolves to your most-populated engagement,
  not `default`.** When no engagement is explicitly selected and no active
  pointer exists (e.g. the one you were viewing was deleted), the app, and the
  scan writer, now resolve to the on-disk engagement richest in real data
  instead of a blank `default` that silently absorbed scans. On startup the app
  also adopts that engagement as active, so it opens on your actual work.

- **The scan launcher now picks the destination engagement explicitly.** The
  free-text "engagement name" field is a dropdown of the engagements on disk
  (plus "＋ New engagement…"), defaulting to the one you're viewing and showing
  where findings will be saved, so a scan can't silently pile into a surprise
  or stale engagement.

- **Every scan mode now runs a real, focused pipeline, the mode selector is no
  longer cosmetic.** `build_full_scan` previously registered all ~35 tasks
  regardless of the chosen mode, so WEB, NETWORK, API, CLOUD, CONTAINER, IOT, OT,
  AD and EMAIL all executed the identical full scan (neither the CLI nor the web
  launcher wired the mode through). Each task is now tagged with the modes it
  belongs to; a focused mode registers only its dedicated modules plus the shared
  enrichment tail (validation, FP-suppression, ML scoring, MITRE mapping,
  reporting), and `FULL` still runs everything. The CLI (`heaven scan -m …`) and
  the web API (`POST /api/scans` `mode`) both pass the mode through to a
  per-scan-isolated builder (no shared-singleton mutation). New
  `tests/test_scan_modes.py` locks in the per-mode task sets.
- **OT is now a distinct mode from IOT.** OT/ICS runs ICS/SCADA protocol probes
  (Modbus, Siemens S7comm, EtherNet/IP, DNP3, IEC 60870-5-104, OPC-UA, BACnet);
  IOT covers consumer / building-automation devices (MQTT, SNMP, RTSP, CoAP,
  UPnP/SSDP, vendor web panels). Previously OT re-ran the IoT scanner.
- **CLOUD mode now does real work against any target.** Selecting CLOUD mode is
  itself the opt-in for the public-bucket exposure probe (previously gated behind
  the `--cloud-buckets` flag), so a CLOUD scan automatically guesses bucket names
  from the target host and proves public exposure from each provider's own
  response. The probe stays opt-in in every other mode.
- **Zero Bandit findings at every severity (previously clean only at medium+).**
  The 132 best-effort `except … : pass|continue` handlers that silently swallowed
  probe errors now log at `debug` with `exc_info`, a scanner that hides an
  unexpected probe error can silently miss a vulnerability, so the breadcrumb is a
  real observability win (and it costs nothing when debug logging is off). The
  irreducible intentional patterns carry a precise, documented per-line
  `# nosec <id>` instead of a blanket skip (default-credential and auth-bypass
  test payloads, MITRE ATT&CK ids / taxonomy strings, deterministic seedable repro
  RNG and non-crypto jitter, subprocess calls to vetted CLI tools, and XML
  output-escaping), so the checks stay live for any *new* real issue. Also
  modernized `asyncio.get_event_loop()` → `get_running_loop()` inside coroutines,
  replaced a mypy-narrowing `assert` with a positive `isinstance` guard, and
  tightened the CI Bandit gate from `-ll` to `-l` so low-severity regressions
  surface in code scanning.

- **Default scan mode is now FULL** (was WEB) in both the web launcher and the
  `heaven scan` CLI wizard, so the out-of-the-box scan runs every module.
- **Full power by default.** Folded the pure-Python runtime feature-packs
  (recon, reports, lateral movement, deploy, scheduling, AWS cloud, and the
  default Gemini AI SDK) into the base `dependencies`, so a plain `pip install`
  is fully powered with no extras to remember. The former `[recon]`/`[reports]`/…
  extras remain as backward-compatible aliases.
- **The one-command install now does everything in one pass and can't hang.**
  External-tool installation runs as part of `install.sh` / `install.ps1` (no
  separate step to remember). Every per-tool install is bounded by a timeout
  (`HEAVEN_TOOL_INSTALL_TIMEOUT`, default 900s) with a watchdog that kills a
  stalled command, runs package managers non-interactively
  (`DEBIAN_FRONTEND=noninteractive`, `HOMEBREW_NO_AUTO_UPDATE`, winget
  `--disable-interactivity`), and makes `sudo` fail fast when there's no
  interactive terminal instead of blocking forever on a password prompt.
  `install.sh` pre-authorizes `sudo` once up front so Linux tool installs never
  stall mid-run.
- **Web UI build now targets Node 22 (active LTS)** in CI and the Dockerfile.
  Vite 8 requires Node ≥20.19 / ≥22.12, and Node 20 has reached end-of-life.

### Fixed

- **Documentation accuracy pass, corrected stale counts, a stale demo banner,
  broken README deep-links, and two out-of-date runbooks.** A full sweep of
  `docs/` against the shipped code: the README Project-Summary table said **50**
  CLI commands while its own poster/footer (and the real CLI) say **51**, aligned
  to 51; `docs/QUICKSTART.md` claimed **19** web pages (actual **24**);
  `docs/DEMO.md`'s Scene 1 described the `heaven --version` output as a branded
  banner "listing 31 commands" (it prints only the version string), rewritten to
  use `heaven info`, which shows the real ASCENDANT AEGIS banner. Three README
  deep-links that no longer resolved (`#installation-detailed`,
  `#continuous-monitoring`, `#scanner-rating`) were repointed to live anchors, and
  `docs/BENCHMARK_HOWTO.md` §3 now points at `BENCHMARK_RESULTS.md` instead of a
  removed section. Two aspirational runbooks that misrepresented the shipped
  product were rewritten to match reality: `docs/runbooks/frontend_audit.md` (the
  UI ships with token auth + a 401 interceptor + CSP/security headers, it no
  longer reads as "the frontend has no auth yet") and `docs/runbooks/ml_training.md`
  (the CVSS model is a **real** NVD-trained ExtraTreesRegressor, R²=0.9925, via
  `heaven train-model`, not the "synthetic stub" the old doc described; it also
  referenced two files that don't exist). `docs/runbooks/ad_lab.md` no longer
  claims "HEAVEN doesn't do lateral movement" (it does, `heaven lateral` /
  `heaven postex`). No product code changed; the README test/module count-check
  still passes.

- **CI "Check README test count is in sync" no longer fails, and now can't drift
  again.** After the previous test-skip fix, `pytest` itself passed on both
  Python versions, but the 3.12-only docs-sync step (`scripts/sync_test_count.py
  --check`) still failed: the recent feature commits added tests (**1352 → 1358**)
  without re-running the sync script, so the decorative count printed in
  `README.md` (poster alt-text, Project Summary, Project Structure listing,
  footer) had gone stale. The counts are re-synced to the real values
  (tests = 1358, modules = 159). To stop this recurring, a **`.githooks/pre-commit`
  guard** (wired via `core.hooksPath`) now re-syncs and re-stages `README.md`
  automatically on every commit, so the printed count can never fall out of step
  with the suite, CI stays green by construction. Fresh clones enable it with
  `git config core.hooksPath .githooks`.

- **CI unit tests (Python 3.11 / 3.12) are green again.** The regression test that
  asserts the ML model spreads predicted CVSS across a genuine range
  (`test_ml_predicted_cvss_spreads_within_a_severity_band`) requires the trained
  NVD regressor (`data/models/NVD_model.pkl`), which is intentionally gitignored
  and fetched with `heaven download-model`, so it is absent on a fresh checkout
  and in CI, where `predict_cvss_score` returns a constant fallback by design. The
  test now **skips** when the model isn't loaded instead of failing, matching how
  the suite already treats other optional artifacts. The class-vector spread that
  the test guards is still asserted model-free by
  `test_ml_features_vary_by_class_not_flat_per_severity`, which runs everywhere.

- **Severity and CVSS can no longer contradict each other (no more "CVSS 8.1 /
  Low", or a "Critical" badge beside a 7.5 score).** A finding shows two views of
  its risk side by side, the qualitative severity the detector assigned and the
  numeric CVSS resolved for its class, and the two could drift apart. A single
  shared reconciler (`heaven/utils/cvss.py::reconcile_severity`, applied at the
  `vuln_kb.enrich_finding` chokepoint every report/export/API path flows through)
  now keeps them in the same band, honestly and without ever inventing a number:
  a **weak, unconfirmed detection** ("possible … indicator", low confidence) has
  its inherited *confirmed-class* base capped down to its own low severity, so a
  heuristic smuggling indicator reads **Low / 3.9**, not Low / 8.1; a **published
  CVE score** is authoritative and drives the label up or down (a real Critical is
  never buried behind a hand-set Low, an over-rated Critical is corrected to its
  real High); and a confirmed non-CVE posture finding is aligned to its curated
  class band. To make this correct on **older persisted findings**, a CVE finding
  that lost its numeric score would otherwise fall back to a generic class number, 
  `enrich_finding` now backfills the **real published CVSS** for any CVE in the
  bundled inline DB (`cve_mapper.published_cvss_for`, offline), so a stale Critical
  is never demoted to its class fallback and its severity matches the true per-CVE
  score. Regression-locked in `tests/test_per_finding_cvss.py`.

- **Report tables no longer overflow the page horizontally.** Wide tables (the
  Findings Summary with long target URLs, the coverage matrices) pushed the whole
  page sideways in the HTML report and its in-app viewer. Every table is now
  wrapped in a horizontally-scrollable box (`.tablewrap`) and long cell content is
  allowed to break, so a wide table scrolls inside its own frame and the page body
  never scrolls sideways, across HTML, PDF (already wrapping via reportlab
  `Paragraph` cells) and Markdown.

- **DNSSEC "not configured" no longer reported twice.** The DNS-recon task emitted
  `dnssec_not_enabled` (medium) while the email-posture check emitted
  `dnssec_missing` (low) for the same domain, same issue, different `vuln_type`,
  so the content-hash dedup never collapsed them. Both now emit `dnssec_missing`
  at a consistent **medium** severity (matching the class's CVSS base), so a full
  scan records one DNSSEC finding, not two.

- **DNS enumeration now actually appears after a normal scan, not only after the
  standalone `heaven dns` command.** Scanning a hostname (`heaven scan --target
  example.com`, or the web launcher) produced an empty DNS section everywhere.
  Root cause: the DNS-reconnaissance task gathered domains only from the `domains`
  and `urls` target buckets, but a plain hostname target is placed in the `ips`
  bucket ("IPs, hostnames, or CIDRs") by both the CLI and the API, so the task
  ran with no domains and enumerated nothing. A new shared `_scan_domains()`
  resolver now also mines registered domains (eTLD+1) from the `ips` bucket (IP
  literals, `localhost` and single-label hosts are dropped), so every scan of a
  real domain populates the Assets **DNS Enumeration** section and the report's
  DNS section. As a bonus, email-posture checks (SPF/DMARC/DKIM/DNSSEC) now also
  run against hostname targets. Two further gaps in the same feature were closed:
  `heaven dns --engagement <name>` now **auto-creates** the engagement instead of
  erroring when it doesn't exist yet, and the CLI `heaven report` (HTML) and
  `heaven export --format markdown` now include the DNS Enumeration section (they
  passed host inventory but not DNS records; the web report-download already did).
- **A CVE finding now shows its own real CVSS, not a flat 7.5 for every service
  vulnerability.** In a live report, every OpenSSH / Apache / Dovecot CVE in the
  Findings Summary rendered the same **7.5** regardless of the actual CVE, and the
  score disagreed with the severity ("Critical … 7.5", "Low … 8.1"). Root cause:
  the findings table has no CVSS column and `upsert_finding` never preserved the
  real per-CVE base score, so after the DB round-trip the report resolver fell
  back to the `vulnerable_component` class "typical" constant (7.5) for all of
  them, and the ML feature extractor had the same blind spot (it read
  `cvss_base` but the CVE score was carried under `cvss`), collapsing the priority
  score too. Fixed end-to-end and in sync: `cve_mapper` now emits the canonical
  `cvss_base` on every inline / live-feed / NVD CVE **and derives the severity
  band from that objective score** (a curated "critical/8.1" like regreSSHion is
  corrected to its true **High/8.1**, matching NVD); `upsert_finding` persists the
  real `cvss_base` + vector through the DB round-trip; the ML extractor and the
  risk fallback both read the real score; and the web finding-detail shows the
  same objective score the report does. A live re-run of the certifiedhacker
  engagement now renders **9.8 / 8.8 / 8.2 / 8.1 / 7.5 / 5.9** across the CVE
  findings with every severity band consistent with its score. Regression-locked
  by `tests/test_per_finding_cvss.py`.
- **CVSS is now a genuine per-finding score, not a flat per-severity constant.**
  Every finding in a severity band used to show the same number (all highs 8.0,
  all mediums 5.5, …) because the ML feature extractor collapsed any finding
  without its own CVSS vector into one of four per-severity constant feature
  vectors, and the qualitative-label fallback returned a fixed number per band.
  Findings now resolve their **class's curated CVSS vector** (48 curated vectors →
  32 distinct base scores) and score it with the standard formula, so two
  different weakness classes get genuinely different scores (SQLi 9.8, XSS 6.1,
  missing-header 5.2…) while the same class stays stable, that's correct CVSS
  semantics, not fabricated uniqueness. One authoritative resolver
  (`heaven/utils/cvss.py::objective_base_score`, precedence: published CVE/NVD/OSV
  score → KB class typical → class-vector base score → the finding's own vector)
  is now shared by the report, the store/UI and the ML feature extractor, so a
  finding's CVSS reads the same everywhere.
- **CVSS v4.0 advisories are now scored (fixes the flat `react-router` row).**
  The in-house calculator only understood CVSS v3.1, so any advisory carrying a
  **v4.0** vector (increasingly common on 2025+ GHSA records) was unscoreable and
  fell back to the flat severity-label constant, e.g. the real react-router
  advisory GHSA-qwww-vcr4-c8h2 showed `8` instead of its true base score. CVSS:4.0
  vectors are now routed to the reference-grade `cvss` library (added as a base
  dependency), so that finding correctly reads **7.1** and its v4.0 vector is
  preserved; v3.x scoring is unchanged. Degrades gracefully to the label fallback
  if the library is somehow absent.
- **Cleared the `react-router` advisory at the source by migrating the web UI to
  React 19.** The SCA self-scan flagged `react-router@7.18.1` for
  GHSA-qwww-vcr4-c8h2 (RSC-mode CSRF, CWE-352, affected range `[7.12.0, 8.3.0)`), 
  a real, correctly-matched advisory. The 7.x line has no backported fix and the
  fixed release lives only on the consolidated **`react-router` 8.3.0** package
  (there is no `react-router-dom@8`), which requires **React ≥ 19.2.7**. The whole
  frontend was therefore upgraded: **React 18 → 19** (react + react-dom 19.2.8),
  **`react-router-dom` → `react-router` 8.3.0** with imports rewritten across 22
  files, **@react-three/fiber 8 → 9** and **@react-three/drei 9 → 10** (React 19
  reconciler), types bumped to 19, and the unused `recharts` dependency dropped.
  HEAVEN's own SCA scan of `heaven-ui` now reports **0 vulnerabilities**, and
  **all 24 UI routes** (plus the finding-detail and not-found routes and a
  client-side router transition) were live-verified end-to-end, sign-in, the R3F
  3D topology and framer-motion animations included, with **zero console errors**
  on every page. This supersedes the interim CVSS-scoring fix above: the finding is
  now **removed**, not merely rescored.
- **Pinned the Node ≥ 22.22 build floor everywhere it's declared.** react-router 8
  requires `node >=22.22.0`, so the requirement is now enforced consistently
  instead of relying on "latest 22.x" resolving above the floor by chance: a
  `heaven-ui/package.json` `engines` field, a new `heaven-ui/.nvmrc` (`22.22`),
  both CI `setup-node` jobs pinned to `22.22`, the Dockerfile `node:22-slim` base
  documented as the ≥22.22 floor, and the Unix/Windows install scripts warn early
  when the local Node is older (message and gate updated from the stale "18+/20+").

- **Green CI, reproducibly.** Two jobs had begun failing on `main` from
  environment drift rather than any code defect:
  - *Lint (ruff).* CI installs ruff unpinned (`pip install ruff`), so when ruff
    **0.16** shipped, its broadened *implicit* default rule set flagged 1800+
    style items (import order, f-strings, annotation styles) on unchanged,
    previously-clean code. The lint rule set is now declared **explicitly** in
    `[tool.ruff.lint]` (`select = ["E4","E7","E9","F"]`, ruff's long-standing
    default, exactly what the codebase was linted against), so any ruff version
    enforces the same rules and a future release can't silently break the build.
  - *Unit tests (3.11 / 3.12).* Three `test_p3_cloud_iam_parity.py` cases
    imported the deliberately opt-in cloud SDKs (`googleapiclient`,
    `azure.identity`), present on dev machines but not in CI's lean
    `pip install -e ".[dev]"`, so they raised `ModuleNotFoundError`. They now
    `pytest.importorskip(...)` those SDKs: they **skip cleanly** where the
    `[cloud-gcp]` / `[cloud-azure]` extras aren't installed and still **run
    fully** wherever they are. Collected test count is unchanged (1319).

- **The authenticated Azure IAM audit never claims authentication it doesn't
  have.** `DefaultAzureCredential` and the management client both construct
  lazily, so a bad or absent credential only failed on first use, meaning the
  audit could emit an "Authenticated to Azure" finding when it actually had no
  token (a false positive if `AZURE_SUBSCRIPTION_ID` was set with invalid creds).
  The audit now forces a real token acquisition up front and degrades to an
  honest `authenticated=False` (`"no valid Azure credentials"`) otherwise. A
  latent Playwright cookie type-mismatch in the JS-rendered crawler, surfaced
  once the real Playwright stubs were installed, was also corrected.

- **Test suite runs clean, zero warnings on Python 3.14.** The suite emitted
  249 warnings, all transitional `Deprecation`/`PendingDeprecation` notices about
  APIs slated for removal in Python 3.16 / future library releases. The ones
  rooted in HEAVEN's own code are fixed at source: `configure_event_loop()` now
  scopes uvloop's `install()` / event-loop-policy deprecations to the single call
  that knowingly uses them; the rich-click presentation layer prefers the modern
  `TEXT_MARKUP` / options-table config attributes and only touches the legacy
  `USE_RICH_MARKUP` / `SHOW_METAVARS_COLUMN` / `APPEND_METAVARS_HELP` toggles on
  older rich-click; and the SSL scanner uses timezone-correct UTC instead of the
  deprecated `datetime.utcnow()`. The remainder originate in third-party
  dependencies we cannot edit (asyncssh, aiohttp, anyio still call the
  soon-removed `asyncio.iscoroutinefunction`; Starlette's test-only `TestClient`
  imports `httpx`) and are narrowly filtered by exact message in
  `pyproject.toml`, HEAVEN never calls those deprecated APIs directly.
- **Dashboard network topology reads cleanly instead of a jittery tangle.** The
  3D host map placed nodes with `Math.random()` height and wired random
  criss-cross edges, so even a dozen hosts looked like a cluttered mess that
  re-shuffled on every render. Nodes now use a deterministic phyllotaxis
  (sunflower) spread, evenly spaced, never overlapping, stable across renders, 
  linked by sparse nearest-neighbour edges, and shrink slightly as the count
  grows. Wide sweeps are capped to the top 24 hosts **ranked by severity** with a
  "top N of M · +K more" indicator, so a `/24` scan no longer floods the view.
- **Scan reports and the audit trail now honour the configured data directory.**
  The report writer hard-coded a current-directory-relative `data/` for
  `report_<id>.json`/`.sarif`, while the API's report-download endpoint reads them
  from `get_config().data_dir`. When `HEAVEN_DATA_DIR` was set, or the API server
  ran from a different working directory than the CLI scan, the writer and reader
  diverged and report download returned 404. Likewise the tamper-evident audit
  logger always wrote to a CWD-relative `data/audit/`, ignoring `HEAVEN_DATA_DIR`.
  All three now resolve the same configured data dir (default `data/`, unchanged),
  so reports download regardless of where the scan ran and the audit trail follows
  a relocated data directory. The test suite is also isolated to a temp data dir
  so running the tests no longer appends test entries into a real audit log.
- **Real findings *still* showed blank CWE / OWASP / MITRE / CVSS-vector.** The
  earlier fix only stopped attack-plan artifacts; genuine findings whose
  `vuln_type` was simply not in the knowledge base (e.g. the OPTIONS-methods
  finding `dangerous_methods_allowed`, plus ~40 more from the auth/web-fuzzer/
  DNS/e-mail detectors) still rendered every taxonomy cell as `—`. Root cause was
  a coverage gap between the detector spellings and the KB keys. Fixed at two
  levels: (1) curated aliases + new KB entries so every class a detector actually
  emits (CSRF, session fixation, host-header injection, HTTP parameter pollution,
  web-cache poisoning/deception, SMTP open relay, MTA-STS, weak password policy /
  no lockout, DNS zone transfer, the network-device and Active-Directory classes
  below) resolves to real CWE/OWASP/MITRE + a CVSS v3.1 vector; and (2) a
  **dynamic keyword fallback** so *any* uncurated finding still derives standard
  taxonomy from its type/title, and, failing that, at least a severity-based
  CVSS vector, so a real finding is never blank again. Positive/informational
  posture (e.g. "DNSSEC enabled") is intentionally left without a weakness CWE
  rather than mislabelled. Applied on read, so existing stored findings are fixed
  with no re-scan.
- **Scanning a network device (router / switch / firewall) produced "No findings
  recorded".** Network recon discovered the device's open ports but nothing turned
  its exposures into findings, the service-injection layer only handled SSH/SMB/
  RDP/DB and web ports. A new **network service exposure analyzer**
  (`recon/network_exposure.py`, wired as a mode-gated orchestrator task) now emits
  real findings for cleartext / legacy management protocols (Telnet, FTP,
  r-services, TFTP, Finger), SNMP exposure, with an active, strictly **read-only**
  default-community probe (`public`/`private`) that proves the weakness from a live
  `sysDescr.0` reply, and high-risk appliance planes (Cisco Smart Install,
  IPMI/BMC). A hardened host (only SSH + HTTPS) still yields zero findings, and the
  service-name matching is exact-token (never substring) so an unrelated service
  can't trip a false positive.
- **The Active Directory scan was shallow and usually skipped entirely.**
  `scan_active_directory` bailed out whenever a domain name wasn't supplied, so
  the SMB-triggered AD scan (which passes only the DC's IP) always skipped, and the
  AD mode did almost nothing. It now runs a real **pre-auth assessment from a DC IP
  alone**: it reads the DC's RootDSE anonymously to auto-derive the domain / forest
  / DC hostname / functional level (and flags anonymous LDAP), and runs an SMB layer
  that detects **SMB signing not required** (the genuine NTLM-relay signal, replacing
  a bogus LDAP heuristic), **legacy SMBv1 / MS17-010 exposure**, and **null-session
  share enumeration**. Authenticated runs additionally check the **machine-account
  quota** (RBCD/noPac prerequisite). AD findings now also carry full CWE/OWASP/CVSS
  taxonomy.
- **Most findings showed blank CWE / OWASP / MITRE / CVSS-vector and a 0.00
  confidence.** The AI attack-chain planner converts its *hypothetical* steps for
  the kill-chain analyzer with `vuln_type` set to a bare MITRE technique id
  (`T1190`, `T1059.001`). Those steps leaked into the collected findings and
  persisted as pseudo-findings, and because their `vuln_type` matches no
  knowledge-base entry, the detail view rendered every taxonomy field empty and
  confidence as 0.00. They are plans, not observations: they are now recognised
  as artifacts (`engagement.is_attack_plan_artifact`) and excluded from the
  findings list, the report/coverage/kill-chain views, and every headline count
  (dashboard chip, stats, per-scan counts), no re-scan needed to clear the ones
  older scans already stored. Genuine findings enrich correctly (e.g. a missing
  CSP now shows CWE-693 · A05:2021 · T1185 · a full CVSS v3.1 vector).
- **Host & Service Inventory looked empty even after a productive scan.** The
  inventory defaulted to the *newest* scan that produced any host row, including
  a dead/mistyped-host scan that recorded a host with **zero** open ports, so an
  earlier scan with real services was hidden. The default (CLI, API and web) now
  prefers the newest scan that actually found open ports, and the scan picker
  annotates each scan with its port count so you can see at a glance which one has
  data.
- **Findings from an IP-range scan can now be grouped per host.** The Findings
  page groups results under each host/IP ("_5 findings across 2 hosts_") with a
  per-host severity breakdown, so a `/24` scan reads as "for this IP, these
  findings; for that IP, those." A **Group by host** toggle appears whenever a
  scan spanned more than one machine.
- **Scanning a whole subnet (`192.168.1.0/24`) came back empty even with live,
  vulnerable hosts on it.** A CIDR expands to hundreds of addresses, and the
  network scanner had three compounding problems that made a range scan return
  nothing:
  - **Hosts were scanned one-at-a-time.** The 254 addresses of a /24 ran
    strictly sequentially, ignoring the configured concurrency, so the scan
    crawled and blew past its deadline. They are now deep-scanned **concurrently**
    (bounded by the stealth profile), so a range finishes in a fraction of the
    time.
  - **Every dead address was full-scanned.** Under `-Pn` (needed so firewalled
    hosts aren't skipped) nmap faithfully port-scanned all ~250 dead addresses of
    a typical /24, burning the entire budget on empty air. HEAVEN now runs a
    fast **host-discovery sweep** first (nmap `-sn`, with a pure-Python
    TCP-connect fallback) and only deep-scans the hosts that actually answered. A
    single host or a small explicit list still skips discovery and is scanned
    directly with `-Pn` (the operator named it, so it's trusted).
  - **A too-tight deadline discarded everything.** The Network Recon task used a
    fixed 300 s timeout regardless of range size; when it elapsed, the task was
    hard-cancelled and returned **no data**, so every downstream scanner saw an
    empty result. The deadline now **scales with the size of the range** (capped
    at 30 min) and the scanner honours a time budget that returns whatever
    finished so far, partial results beat none. Live-proven: a `/27` CIDR whose
    only live host ran a weak web app went from *nothing* to 15 attributed
    findings (a critical CVE-2021-41773 on the host:port, reflected input,
    missing security headers), discovery correctly reporting "1/30 up".
- **Subnet scope now covers the hosts inside it.** Under an engagement,
  `is_in_scope()` matched targets by *exact string* only, so adding
  `192.168.1.0/24` to scope didn't authorize `192.168.1.55` (or the /24 scanned
  as individual IPs), and those targets were silently dropped. Scope is now
  **CIDR-aware**: a target contained by an in-scope range passes (including a
  URL whose host falls in the range). It only ever authorizes a target *inside*
  an authorized range, a range broader than what was scoped still fails, so
  scanning can never exceed authorization.
- **Internal / IP-only targets came back empty even when riddled with holes.**
  Two engine gaps meant scanning a bare IP (the normal case for an internal
  network) could report *nothing*, and both are fixed:
  - **nmap now runs with `-Pn`** (assume the authorized host is online). Windows
    boxes, firewalled hosts and hardened Linux routinely drop nmap's discovery
    ping, so without `-Pn` nmap declared them "down" and scanned **zero** ports, 
    the exact "I know it's vulnerable but the scan found nothing" symptom.
    Liveness is now inferred from a real probe reason or an actually-responding
    port, so `-Pn` doesn't fake a dead address as alive.
  - **Open web ports on a bare-IP target now flow into the web scanners.** The
    crawler, injection (XSS/SQLi), auth, fuzzer, misconfig and exposure checks
    only ran against URLs; a bare IP had none, so a discovered HTTP(S) service
    was port-listed but never web-tested. After recon, HEAVEN now derives a URL
    from each open web port (`http(s)://host:port`), crawls it, and feeds it to
    the full web pipeline, deduped against URLs you already supplied, and only
    in modes whose pipeline includes web scanners (FULL/WEB/API). Live-proven:
    scanning a bare IP that hosts a weak web app went from a bare port list to
    28 findings (confirmed reflected XSS, missing security headers, a
    known-vulnerable Apache).
  - **Scan-privilege transparency.** When nmap runs without raw sockets it can't
    do SYN/UDP/OS scans (open ports are still found via TCP connect). HEAVEN now
    says so plainly in the scan summary and prints the **exact, platform-correct**
    one-time command to unlock full detection, macOS gets `sudo`/passwordless-sudo
    guidance instead of the Linux-only `setcap` (which doesn't exist on macOS). A
    new `scan_capability()` is the single source, also exposed on the network-scan
    result (`scan_privilege`).
- **CVE findings showed a blank Target in the CLI table and kill chain.** A
  version-matched CVE carried `host`/`port` but no `target`, so a CRITICAL row
  rendered with an empty target column (the persisted record was fine). Every
  CVE finding is now attributed to its concrete `host:port`.
- **Test suite polluted the operator's live engagement.** The `/api/sca`
  smoke-test did not isolate its data directory, so every full-suite run
  persisted a `SCA: test_…` junk scan into the real active engagement DB under
  `./data/engagements/`. It now `chdir`s to a tmp path like its sibling tests;
  the full suite no longer touches real operator data (verified by byte-level
  before/after comparison).
- **Malformed `Authorization: Bearer` header returned 500 instead of 401.** A
  bearer header with no token (`"Bearer"` / `"Bearer "`) hit an unguarded list
  index and raised a server error; it now returns a clean 401. Found while
  live-verifying the dashboard fixes.
- **Every CVE finding showed the same generic remediation.** Every
  known-vulnerable-component finding (inline DB / live feed / NVD) is typed
  `vulnerable_service` and resolved to one KB entry, so OpenSSH regreSSHion, an
  Apache path-traversal RCE and an Apache SSRF all displayed the identical
  three-line "upgrade / SBOM / virtual-patch" advice. Remediation for these
  findings is now generated per-CVE: it names the actual product and version,
  cites the specific CVE (with its NVD link), flags a public exploit when one
  exists, and picks an interim control that fits the weakness class (SSRF →
  block egress + metadata endpoints; path traversal → `../` WAF rule;
  deserialization → firewall the listener; memory-safety → reduce exposure).
  The product/version/CWE now survive the DB round-trip, so the dashboard
  "Fix this first", the finding detail and every report show the tailored text.
- **Dashboard "Fix this first" cards overflowed with no way to scroll.** A
  finding title set to `white-space:nowrap` inside a grid item (whose default
  `min-width:auto` refuses to shrink below its content) forced each card wider
  than the pane, pushing the risk score and remediation off-screen. The cards
  now shrink to the pane and ellipsis/clamp their own contents.
- **Reports engagement selector was hidden with a single engagement.** The
  "Engagement to export" picker only appeared when more than one engagement
  existed, so with one engagement it looked missing. It's now always shown, so
  the export scope is explicit.
- **Host & Service Inventory merged two scans' ports together.** Running two
  separate scans blended every discovered host/port into one table. The inventory
  is now scoped to a single scan, the most recent by default, with a scan
  picker in the Assets page (and `heaven assets --scan-id` / `--all` on the CLI)
  so two scans stay independent. The lateral-movement page opts into the
  engagement-wide union (`?all=1`) since it wants every pivot host.
- **Scan launcher targets couldn't be edited after entry.** Once a target became
  a chip you had to delete and retype it to fix a typo. Click a chip's text (or
  Backspace on the empty field) to pull it back into the input and edit it.
- **Copying a target chip smuggled junk on paste.** Copying a chip picked up its
  "URL/IP" kind-label and the "×" remove glyph; pasting it back created garbage
  tokens. The label and × are now excluded from text selection, and paste strips
  the × glyph plus zero-width/BOM/non-breaking-space characters.
- **README stats and model names were stale and inconsistent.** The badges and
  tables cited conflicting figures (967 vs 981 tests, 47 CLI commands, 59 vs 60
  API routes, 21 vs 22 UI pages) and retired model defaults (`claude-sonnet-4-6`,
  `gemini-1.5-pro`). All are now synced to the actual project, **1028 tests · 145
  modules · 50 CLI commands · 64 API routes · 24 UI pages**, with current model
  defaults (`claude-sonnet-5` / `gemini-flash-latest`), and the previously
  undocumented **Assets** (Host & Service Inventory) page was added to the Web UI
  page table.
- **Web UI leaked internal implementation details in user-facing text.** Several
  descriptions read like developer notes: the Knowledge Graph exposed an on-disk
  path (`~/.heaven/knowledge.db`) and an internal record schema; the AI
  Attack-Chain Planner showed an internal architecture label ("Layer D") and a
  raw internal API response (`{"skipped": "LLM gateway unavailable"}`); two
  finding-detail buttons carried internal issue-tracker tags ("(Gap 4)",
  "(Gap 6)"). All were rewritten as professional, product-facing copy with no
  filesystem paths, internal identifiers, or raw response shapes, and the
  "unavailable" states now guide the user to add a provider key in Settings.
- **Host & Service Inventory was empty after scanning a URL target, in every
  mode.** Network reconnaissance only received bare IP targets, so a URL/hostname
  target (e.g. `https://app.example.com`) never reached nmap and the inventory
  came back empty, even on a FULL scan. Recon now scans the host parsed from
  every URL target too, and runs for WEB/API (not only NETWORK), so any
  host-based mode populates the inventory.
- **Focused scans showed the FULL badge.** A running scan carried no top-level
  mode and the UI read `config.scan_type` (always its "full" default) instead of
  the operator-selected `mode`, so a network scan displayed as FULL. The
  in-memory scan now carries an authoritative `mode`, and the badge prefers it.
- **AI Attack-Chain Planner returned nothing without an LLM key.** It was purely
  LLM-driven and returned `{"skipped": …}` when no key was set. It now always
  builds grounded chains deterministically from the real findings
  (vuln-class → MITRE technique → kill-chain stage, per-host + cross-host lateral
  chains), and the LLM only layers creative variants on top when a key is present.
- **OWASP Top 10 (2021) coverage wasn't linked to findings.** The report re-derived
  categories from an incomplete keyword map that missed most vuln types (headers,
  TLS, CSRF, credentials, …), so their findings vanished from the matrix. It now
  maps each finding to its enriched OWASP category first (keyword fallback second),
  renders the full 10-category matrix, and lists the actual findings under each.
- **Cyber Kill Chain dumped every finding into Reconnaissance.** Phase mapping only
  matched a few exact vuln_type keys, so real scanner types (`sql_injection`,
  `missing_security_headers`, `ssl_weak_cipher`, …) fell through to the default.
  Aliases + substring matching now distribute findings across the real phases.
- **CVE was a static string in findings and reports.** Findings' CVE(s) now link
  straight to the live NVD record (`nvd.nist.gov/vuln/detail/…`) in both the
  finding-detail view and the exported HTML/PDF report.
- **Scan diff surfaced an opaque 500 and offered running scans.** Diffing two scans
  from different engagements now returns an actionable 400, and the diff pickers
  list only completed scans.
- **Autonomous run gave thin output and stopped after one iteration without an
  LLM.** The rule-based fallback recon'd only the *first* seed then bailed unless
  it happened to find a high-confidence SQLi. It's now a thorough deterministic
  playbook that recons *every* seed, follows newly-discovered web surfaces, runs
  an exploitation-proof pass on exploitable findings, attempts read-only
  credential reuse, and only stops when the playbook is genuinely exhausted, 
  never repeating an action. Paired with the new executive report, a no-LLM run
  now does real work and reads professionally.
- **`heaven install-tools` couldn't auto-install Docker on macOS.** The catalog had
  no Homebrew formula for `docker`, so on macOS it was reported "manual" instead
  of installed. Added `brew install docker` (the CLI client HEAVEN shells out to),
  so all seven external tools now auto-install from the standard package manager.

- **Scan findings were inaccurate, CVEs were wrong/blank, and the stored results
  disagreed with the report.** Every CVE discovered on one host collapsed into a
  *single* finding, the finding identity (`_finding_hash`) keyed only on
  `(target, vuln_type, endpoint, param)`, which is identical for every
  `vulnerable_service` CVE on a host, so all but one CVE silently vanished and
  the surviving `cve_id` (and its severity) was non-deterministic, differing
  between the engagement store and the report JSON. The identity is now
  **CVE- and port-aware**: distinct CVEs on a host are distinct findings, the
  same CVE still dedups across re-scans, and host-level / injection findings
  still collapse as before. The web scan runner also **reconciles** the store to
  the final authoritative finding set (`prune_scan_findings`) after the live
  progress flush, so the engagement view, scan list and downloaded report always
  agree.
- **False "Apache" CVEs on ordinary HTTP servers.** The live CVE feed searched
  NVD/CIRCL for the bare protocol label `http`, which its CPE map resolves to
  Apache, so any HTTP server (a plain Python `http.server`, a Uvicorn app)
  collected ~25 confident-looking Apache CVEs. A generic protocol label
  (`http`, `https`, `ssl`, …) now never drives a live search, only a concrete,
  identified product does, and the mapper passes the resolved product, not the
  raw service word, to the feed.
- **Open ports / services were missing from the Assets view after a web-launched
  scan.** The web scan runner persisted a summary that dropped the host/service
  assets (the CLI kept them), so the inventory fell back to a single global
  "latest report" that could belong to a different engagement. Web scans now
  persist their assets into the scan summary, and the report-JSON fallback is
  scoped to the engagement's own scans.
- **Launching one scan started two.** A double-submit (double-click,
  Enter-then-click, a retry) sent two `POST /api/scans` and each spawned its own
  scan. An idempotency guard now returns the in-flight scan for an identical
  request (same targets + mode + engagement), and the launcher hardens against a
  rapid re-submit.
- **Unactionable junk findings.** A finding carrying a CVE but naming no
  host/target (seen live: a stray `CVE-2020-29396` with an empty target and
  `vuln_type: unknown`) is now dropped instead of persisting as a bogus
  high-severity row.
- **The header/sidebar clock lagged real time by up to a second.** The 1000 ms
  interval drifted off the wall-clock second; both clocks now re-arm just after
  each whole second.
- **The scan progress bar jumped in big steps (2 → 12 → 35 → 89) and sat frozen
  in between.** Progress only moved when a whole task finished, and the UI
  sampled it every 8 s. Now an in-flight task earns genuine, time-based partial
  credit, the orchestrator emits progress on task *start* and on a periodic
  heartbeat (so a long single task like an nmap sweep keeps advancing), the
  running scan is polled every 2 s, and the bar eases smoothly toward the real
  server value. It stays monotonic and never shows a premature 100, honest
  motion, not a fabricated animation.
- **The CVE column read as "blank/broken" on finding detail.** Configuration,
  policy and hygiene findings (DMARC/SPF, missing headers, weak TLS, …) have no
  CVE, so the bare ", " looked like a bug. The CVE cell now says *", (not a
  CVE-class finding)"* for those classes and *", (no CVE resolved)"* for a
  service finding with no match, while real CVE-tracked findings show their CVE.
- **The CVE Lookup form overflowed its card.** The Limit box spilled past the
  card edge and the "Look up CVEs" button sat awkwardly. The form's grid columns
  now shrink correctly (`minmax(0, …)`), the fields stack on narrow screens, and
  the button is spaced properly.

- **Web UI is responsive again, the dashboard no longer overflows or overlaps
  on small screens.** The dashboard's two-pane grid was locked to a fixed
  `1fr 360px` at one viewport height, and the 3D topology `<canvas>` kept its
  desktop pixel width; because grid/flex children default to `min-width: auto`,
  that width propagated up and inflated the whole page far past a phone's
  viewport, so the stat cards were clipped ("CRITIC…", "TARGE…"), the engagement
  chip was crushed, and the right rail overlapped everything. The layout now
  uses `minmax(0, 1fr)` tracks (and `min-width: 0` on the content column) so it
  can shrink to fit; on phones the two panes stack, the stat grid drops to two
  columns, the map gets a fixed height, and the header keeps the engagement name
  (ellipsized) while dropping the counts/SIEM/role chips it has no room for.
  Wide data tables (CVE, findings, assets, scans) now scroll horizontally inside
  their card instead of being clipped.
- **Help tooltips (the "?" icons) are no longer clipped.** The explanation bubble
  was an absolutely-positioned child, so any card with `overflow: hidden` (every
  stat tile) cut it off or bled it across neighbouring tiles. It now renders
  through a portal to `<body>` with fixed positioning, so it always appears in
  full, above everything, on every page, and it opens on tap too, for touch
  devices with no hover.
- **"Generate AI remediation" no longer echoes back the same text.** With no LLM
  key configured the remediation engine returns the knowledge-base text, which
  the finding page then showed a second time under an "AI-tailored" heading, an
  identical duplicate. The page now shows the AI block only when the result is
  genuinely AI-generated *and* differs from the KB text; otherwise it shows a
  single, clear note that no LLM key is configured, with a link to Settings.
- **CVE Lookup explains an empty result instead of just going blank.** A lookup
  that returns nothing (usually NVD rate-limiting an unkeyed request, only ~5
  lookups per 30 s without an `NVD_API_KEY`, or an offline host, or a
  product/vendor that doesn't match NVD's CPE dictionary) now spells out those
  causes and links to Settings to add an NVD key, rather than showing a bare
  "no results" line that reads as broken.
- **Grammar: single-item counts.** The header and dashboard now read "1 target"
  / "1 finding" instead of "1 targets" / "1 findings".
- **Stealth level now genuinely changes scan behaviour at every setting, it was
  partly cosmetic.** The web launcher / CLI expose four levels (paranoid /
  stealth / normal / aggressive), but several scanners accepted `stealth_level`
  and then discarded it. The web crawler and the adaptive-intel profiler built a
  *bare* `EvasionProfile(stealth_level=…)` whose timing fields stay `0`, so the
  inter-request delay was a **no-op for every level** and the crawler's
  concurrency was hardcoded (100) instead of scaling with the profile; the web
  fuzzer collapsed all four levels into a stealthy/loud binary with a fixed
  `Semaphore(5)`; and the IDOR scanner varied concurrency but never applied a
  delay. Root cause was a footgun, `EvasionProfile(stealth_level=X)` only sets
  the label; the real timing/concurrency lives in `STEALTH_PROFILES` via
  `get_profile()`. Added `evasion_engine.profile_for()` /
  `resolve_stealth_level()` (case-insensitive, unknown→NORMAL, returns a *copy*
  so the long-lived API server can't corrupt the shared template) and routed the
  crawler, adaptive-intel, network scanner, web fuzzer and IDOR scanner through
  it. All four levels now differ in concurrency **and** inter-request delay (and
  aggressive correctly stops rotating the User-Agent). The network scanner also
  resolves its profile up front so an optional honeypot/CTF import failure can no
  longer silently drop it to a no-evasion profile. New
  `tests/test_stealth_levels.py` proves each level's behaviour and locks in the
  footgun fix.
- **`heaven replay` now actually works, and web-launched scans are reproducible.**
  Two real gaps: (1) the web-scan background runner recorded a scan with **no
  config at all**, so `heaven replay` / the replay endpoint had nothing to
  reconstruct and the operator's stealth choice was lost the moment the scan
  finished; (2) both replay paths read the stored config off `list_all_scans()`,
  which returns only id/name/status/timestamps, **no `config_json`, no `mode`**, 
  so every replay silently fell back to an empty config ("no replayable targets").
  Web scans now persist a full, replayable config (targets incl. the resolved
  stealth level, `mode`, and the active seed), both replay paths read via
  `list_scans()` (`SELECT *`, which carries `config_json` + `mode`), and CLI
  `replay` now passes the stored `scan_mode` so it reproduces the original
  *focused* mode instead of a blanket FULL run (stealth rides inside `targets`).
  Added `server._resolve_stealth_name()` (int 1-4 / name → profile name, unknown →
  normal) and `tests/test_replay_stealth_persistence.py`.
- **IoT/OT scans no longer fabricate findings from an open port.** The IoT
  scanner asserted BACnet and UPnP findings from a mere open port (no protocol
  probe), did TCP-only discovery so UDP services (SNMP/BACnet/CoAP/UPnP) were
  never actually reached, claimed default credentials without testing them, and
  matched vendors by naive substring (`"GE"` in "imaGE"). It now sends real,
  **read-only** protocol handshakes over the correct transport (UDP for
  SNMP/CoAP/BACnet-Who-Is/SSDP-M-SEARCH; TCP for the ICS protocols), reports a
  finding only on a protocol-correct response, **actively verifies** a default
  credential before claiming it (else a low-confidence "verify" note), and
  matches vendor tokens on whole words only. Open ICS ports that don't confirm
  become an honest `info` "verify" finding, never a fabricated critical.
- **Container scan no longer reports the scanner's own host for a remote target.**
  The local `/var/run/docker.sock`, privileged-container and RBAC checks inspect
  the machine HEAVEN runs on, so scanning any remote target from a workstation
  with Docker installed emitted a bogus critical "Docker Socket Exposed"
  attributed to the remote. Those local-host checks now run only when the target
  is this host; remote targets get only the genuinely target-scoped probes
  (Docker API 2375/2376, K8s API, etcd, kubelet).
- **Email posture deepened.** Added DNSSEC (DNSKEY), MTA-STS and TLS-RPT checks
  and a **non-intrusive** open-relay probe (MAIL FROM / RCPT TO for external
  domains, then `RSET`, never `DATA`, so no mail is relayed).
- **IoT vendor-panel default-credential false positive.** The panel check
  attempted HTTP Basic auth and treated any `200` as "accepts default
  credentials", so an **open, no-auth** panel was reported as a CRITICAL
  default-credential finding. It now only attempts (and claims) a default login
  when the panel actually issued a `401` Basic challenge and the credential
  clears it (`401`→`200` without a renewed challenge); open panels and
  form-login panels stay a fingerprint-only `info` finding. (Also replaced the
  deprecated `aiohttp.BasicAuth` with an explicit `Authorization` header.)
- **API-mode false positives (deep detector audit).** Three FP paths in the API
  scanner were closed: (1) the "API key leaked" check reported *any* `token=…` /
  `secret=…` string in a response as a **critical** leak, but a login/CSRF/session
  token in a response is normal, not a leak; the blanket `token` pattern is
  removed, unambiguous provider keys (AWS/OpenAI/GitHub/Slack/Google/Stripe) stay
  critical, and a generic `api_key`/`client_secret` value is reported only when it
  passes a placeholder/entropy guard, as `medium` + "verify". (2) "No rate
  limiting" fired even when the probed endpoint returned all `404`s (i.e. didn't
  exist); it now requires the endpoint to actually process the requests. (3) "Mass
  assignment" fired when the response merely *contained the field name* (a normal
  profile object has a `role`/`active` field); it now reads the object first and
  requires the injected privileged **value** to round-trip *and* differ from the
  pre-existing value.
- **WEB-mode injection false positives.** (1) Header-injection XSS was flagged on
  the bare reflected canary, an HTML-escaped header reflection is inert, so it now
  requires an *executable* reflection (matching the parameter-XSS gate). (2) POST
  time-based SQLi was asserted from a single slow response, so a naturally slow
  POST endpoint became a **critical** finding; it now uses the same
  baseline-plus-reproduce guard the GET path already had.
- **HTTP request-smuggling false positive (live sandbox E2E).** The web fuzzer
  baselined the smuggling probes with a **GET** but sent the ambiguous CL.TE /
  TE.TE requests as **POST**, so any server that answers POST differently from
  GET, a `404`/`405` on a GET-only route, i.e. almost every server, tripped the
  "smuggling indicator" on every path. The baseline is now a well-formed **POST**
  to the same URL, isolating the ambiguous framing as the only variable.
- **HSTS "max-age too short (0s)" on plain-HTTP ports.** The `no_hsts` branch was
  correctly gated on TLS actually working, but the `hsts_short_maxage` branch was
  not, so scanning any non-TLS port fired "HSTS max-age Too Short (0s)" from the
  default `max_age=0`. HSTS is a TLS-only control; the whole check now runs only
  when a TLS version negotiated.
- **Version-based CVE findings persisted as `vuln_type: "unknown"`.** The inline
  CVE-DB and NVD paths in the CVE mapper built findings without a `vuln_type`, so
  every version-matched CVE (e.g. an Apache banner → Optionsbleed) landed
  uncategorised, no KB taxonomy, blank type in reports. They now carry
  `vulnerable_service` (aliased to the `vulnerable_component` KB entry) like the
  live-feed path.
- **CLOUD bucket mis-attribution.** Bucket-name guessing derived candidates from
  RFC 2606 / 6761 reserved or non-distinctive registrable labels (`example`,
  `test`, `localhost`, …), so a scan of `example.com` matched the unrelated public
  `example-images` bucket and reported it as the target's **critical** exposed
  asset. Those reserved base names are now skipped, a coincidental generic-name
  match is no longer claimed as the target's bucket.

- **SAST/SCA findings now show up after a scan.** Running a SAST or SCA scan with
  an engagement name persisted the findings into that engagement's store but left
  the app pointed at whatever engagement was active before, so the Findings page
  and dashboard (which read the *active* engagement) showed nothing. These scans
  now activate the engagement they persist into, exactly like a pentest scan, so
  the run is immediately visible in triage. The header chip and dashboard refresh
  on completion.
- **Dashboard topology follows the selected engagement.** Switching the viewing
  engagement now updates the "hosts mapped" topology and stats immediately (the
  dashboard listens for the engagement-changed event, not just its poll). An
  engagement with no findings no longer falls back to some *other* engagement's
  latest report file, an empty engagement shows an empty topology instead of
  leaking another engagement's hosts.
- **Code-analysis findings no longer pollute the topology.** SAST/SCA findings
  (whose "target" is a source file or package, not a network host) are excluded
  from the 3D host map, so they no longer spawn phantom nodes like `src`. They
  still count toward severity totals and appear on the Findings page.
- **Tool-install watchdog now actually kills a stuck install (CI red on Linux).**
  `_run_install` launched the package manager via a shell and, on timeout, killed
  only the shell. On Linux (`/bin/sh` = dash) the forked child kept the stdout
  pipe open, so the streaming read loop blocked for the *full* command duration
  and the timeout never took effect (`test_run_install_times_out_instead_of_hanging`
  waited the whole 30 s and failed the 3.11/3.12 unit-test jobs). The child now
  runs in its own process group and the watchdog kills the **whole group**, so a
  hung install is terminated at the configured timeout on every platform.
- **`heaven engage list` type error (mypy CI).** The dedupe map was annotated
  `dict[str, object]`, so passing a value to `EngagementStore(Path | str)` was a
  type error. It holds `Path` values, annotated correctly now; mypy is clean.
- **`scripts/uninstall.ps1` reported success as failure on Windows.** The
  uninstaller runs only PowerShell cmdlets (no native command), so in a fresh
  session `$LASTEXITCODE` stayed `$null`; a caller's `if ($LASTEXITCODE -ne 0)`
  read `$null -ne 0` as *true* and treated a clean uninstall as a failure (the
  native-Windows E2E job went red even though every step printed success). Both
  `install.ps1` and `uninstall.ps1` now `exit 0` explicitly on the success path
  (fatal errors already abort via `Die`/non-zero), so their exit codes are
  deterministic.

- **`heaven install-tools`**, one command installs the external scanner
  binaries HEAVEN shells out to (nmap, nuclei, sqlmap, ffuf, searchsploit,
  semgrep, docker) using the host package manager (brew / apt / dnf / pacman /
  **winget / choco / scoop**) or pip / go, so the scanner runs at full power.
  Idempotent, with `--dry-run` and per-tool selection. Driven by a single shared
  catalog (`heaven/utils/tool_installer.py`) that also powers `heaven doctor` and
  the web System-Health panel, so the tool list and install recipes never drift.
  Runs automatically as part of install (opt out with `HEAVEN_SKIP_TOOLS=1`).
- **Windows one-command install/uninstall**: `scripts/install.ps1` and
  `scripts/uninstall.ps1` mirror the macOS/Linux shell scripts (Python venv,
  full dependencies, external tools via winget/choco/scoop/pip/go, web UI build,
  generated `.env`), so HEAVEN now installs unattended on **macOS, Linux, and
  Windows** from a single command.
- **Delete engagements from the dashboard**: the "Viewing engagement" selector
  is now a full manager: every engagement is a clickable row (switch by clicking)
  with a per-row trash button that permanently removes it (its scans, findings and
  scope). Deleting the engagement you're viewing repoints the active pointer to
  the best surviving engagement (most findings, real engagements preferred over
  the `demo` sample) or falls back to the empty-state quick-start; a one-click
  **Remove N empty engagements** clears stray empties in a batch. Previously there
  was no way to remove an engagement, so deleting *scans* left the empty
  engagement DB behind and it lingered in the switcher forever. Backed by a new
  `DELETE /api/engagements/{name}` endpoint and matching CLI `heaven engage list`
  / `heaven engage delete` for CLI ↔ API ↔ UI parity; the delete removes the
  SQLite DB *and* its WAL/SHM sidecars so the name can't be resurrected.

- **A phantom "default, empty" engagement appeared on its own and couldn't be
  removed.** Merely loading the dashboard opened the fallback `default`
  engagement for a *read*, and the store constructor eagerly created its SQLite
  file, so `data/engagements/default.db` was materialised on every page load and
  reappeared in the switcher no matter how many times it was deleted (and
  deleting *scans* never removed the engagement). `EngagementStore` now has a
  read-only mode (`create=False`) that serves a not-yet-scanned engagement from
  an ephemeral in-memory schema instead of writing a file; every dashboard read
  (summary, dashboard, findings, top-findings, scans, report/coverage/methodology
  exports) uses it via a new `_read_store()` helper. The engagement switcher no
  longer invents a phantom `default` row, and on startup an empty auto-created
  `default.db` (no scans, findings or scope) is pruned, a real `default`
  engagement you actually scanned into is left untouched.
- **The dashboard looked like it "started scanning" the moment you opened it.**
  The live terminal read a `heaven_active_scan` browser-storage key that older
  builds set but never cleared, so a stale value made it show "CONNECTING" and
  open a log socket on a fresh open even though nothing was running. The terminal
  now derives its target from the actually-running scan (via the scans list) and
  clears the stale key, so it sits **IDLE** unless a scan is genuinely in
  progress. (Confirmed there is no auto-scan anywhere: nothing on server startup
  or page load launches a scan.)
- **Header engagement chip went stale after switching engagements.** The
  top-of-page "Engagement · N findings · M targets" indicator only re-fetched on a
  route change, so switching or deleting an engagement on the Dashboard left it
  showing the previous engagement (or a spurious "No active engagement" warning)
  until you navigated. It now refreshes immediately on a `heaven:engagement-changed`
  event fired by the switch/delete actions, with an 8s poll as a fallback, so the
  header, the selector and the dashboard stats can never disagree about which
  engagement is active.
- **CI unit-tests failing on `ModuleNotFoundError: No module named 'pypdf'`.**
  `pypdf` is a test-only dependency (the PDF-report regression test reads the
  generated PDF back to verify it; nothing at runtime imports it) but lived in
  `requirements.txt`, which the CI test job doesn't install. Moved it to the
  `[dev]` extra and guarded the test with `importorskip`, so the suite runs green
  in CI and skips cleanly without dev extras.
- **Installer appearing to hang / getting stuck** during the external-tool step, 
  see the install hardening under *Changed* above.
- **Windows installer could abort mid-run under two edge cases** (found by
  executing `install.ps1`/`uninstall.ps1` end-to-end, not just linting them):
  (1) `$env:Path.Split(';')` had no null-guard, so in any context where the
  process `Path` is unset it would throw and stop the install right after adding
  the PATH entry, now guarded like the adjacent user-PATH handling; (2) the web
  UI build ran under `ErrorActionPreference='Stop'`, so a broken/missing Node or
  npm could throw and abort the whole installer (losing `.env` creation and the
  smoke test), the UI build is now wrapped in try/catch and is genuinely
  non-fatal, matching the script's stated "the CLI works fine without the UI"
  contract. Both `.ps1` scripts now pass PSScriptAnalyzer with zero findings and
  run install→uninstall to a clean exit. A new **`windows-install-e2e` CI job
  executes the full installer and uninstaller on real `windows-latest`** every
  push (native venv + pip install, `cmd /c npm` UI build, `.env`, smoke test,
  then uninstall with a data-preservation assertion), so the Windows path is now
  gated by actual Windows execution, not just static analysis.

### Security

- **Closed an XXE in the SCA Maven parser** (CWE-611). `pom.xml` files come from
  the *scanned* project, which may be hostile, parsing them with stdlib
  `xml.etree.ElementTree` allowed external-entity / external-DTD attacks that
  could read local files off the analyst's host or drive SSRF. The Maven and
  nmap XML parsers now use `defusedxml`, and a regression test proves a
  malicious `pom.xml` cannot exfiltrate a local file. `defusedxml` is now a
  declared dependency.
- **Randomised the linPEAS post-ex staging path** (CWE-377). The privilege-
  escalation runner dropped `linpeas.sh` at a fixed `/tmp/linpeas.sh` on the
  target, then `chmod +x` and executed it, a TOCTOU/symlink opening on a
  multi-user target's world-writable `/tmp`. It now uses an unpredictable
  `/tmp/.heaven-<random>.sh` per run.
- **Clean bandit (SAST) baseline, findings _and_ log.** Reviewed and resolved
  every `-ll` bandit finding: the two real issues above are fixed; the remaining
  flagged lines (the scheme-validated + checksum-verified model download, the
  readiness-probe host comparison, and the authorised OOB-callback listener bind)
  are genuine intentional/false-positive cases. Broadly-intentional test classes
  for a network-pentest tool (`B104` all-interfaces bind, `B108` remote-target
  `/tmp` staging path) are documented in `[tool.bandit] skips`; `B310`/urlopen
  stays on a scoped, prose-free `# nosec B310` so any *new* urlopen must be
  reviewed. Result: `bandit -r heaven/ -ll -c pyproject.toml` now emits **zero
  findings and zero parser warnings** (previously ~70 cosmetic "Test in comment"
  / "no failed test" lines cluttered the CI SAST log).
- **Cleared all 19 web-UI dependency advisories** reported by `heaven sca`
  (OSV.dev). Removed the **unused `mermaid`** dependency, it was never imported,
  and dropping it eliminated 13 advisories on its own (4 mermaid CVEs plus the
  transitive `dompurify` set and a high-severity `uuid` issue) and removed 113
  packages. Bumped `vite` 5→8, `@vitejs/plugin-react` 4→6 and `react-router-dom`
  6→7 to clear the remainder. `heaven sca` and `npm audit` now report **zero**
  vulnerable dependencies.
- **Hardened evasion/fuzzer randomness to a CSPRNG** (CWE-330). All timing
  jitter, User-Agent rotation, scan-order shuffling and canary generation in
  `recon/evasion_engine.py` and `vulnscan/web_fuzzer.py` now draw from
  `secrets.SystemRandom` instead of the default PRNG, unpredictable to IDS/WAF
  fingerprinting, and clearing HEAVEN's own `weak-random-for-crypto` SAST rule.

## [1.0.0]: 2026-07-08

### Added

- **In-house OAST collaborator (`heaven/vulnscan/oast.py`), provable SSRF & XXE.**
  A pure-standard-library out-of-band listener binds locally and records target
  callbacks tagged with a per-probe token. SSRF and XXE are now *proven* (the
  target actually connects back) rather than guessed, with **no external
  dependency**, no Burp Collaborator, no interactsh, no third-party DNS. Bind a
  routable address via `HEAVEN_OAST_HOST` for remote engagements.
- **Dedicated misconfiguration & session-security scanner
  (`heaven/vulnscan/misconfig_scanner.py`).** Deterministic, confirmation-based
  checks wired into the main VULN_SCAN phase: CORS reflected-origin **with
  credentials**, insecure session cookies (HttpOnly/Secure/SameSite), missing
  security headers (host-scoped), canary-confirmed open redirect, and JWT
  weaknesses, `alg:none` acceptance plus HMAC **weak-secret cracking** (the
  recovered secret is the proof). A new `oob_scanner.py` drives SSRF/XXE through
  the collaborator. All classes are proven against the native vulnerable app.
- **Expanded in-house remediation knowledge base (`heaven/devsecops/vuln_kb.py`).**
  Added entries for XXE, CORS, insecure cookies, JWT (weak-secret + alg:none),
  command injection, file inclusion, path traversal, SSTI, CRLF, request
  smuggling and subdomain takeover, plus an alias map so every emitted
  `vuln_type` spelling resolves. `AIRemediationEngine`'s LLM-free fallback now
  returns a full, class-accurate write-up from the KB instead of a generic
  one-liner, **remediation is excellent with or without an API key**.
- **`heaven download-model`**, fetch the pre-trained 48 MB NVD CVSS model
  (R²≈0.99) from the GitHub Release, **SHA-256 verified**, instead of training
  it. The model isn't bundled in the wheel or committed to git, so `pip install`
  and `git clone` users previously fell back to heuristic CVSS; now one command
  enables the ML scores. The loader search path gained a user-cache location
  (`~/.cache/heaven/models/`) and a `HEAVEN_MODEL_PATH` override so the fetched
  model is found even in read-only site-packages installs. Fully tested offline
  (verify pass/fail, atomic install, idempotent re-run).
- **`heaven config test-llm`**, CLI parity with the web-UI Settings LLM check.
  A cheap check by default (provider/key/SDK present, no billed call) and a
  `--live` flag that sends one minimal completion through the *same gateway the
  AI layers use*, so you can confirm a key works end-to-end before a scan relies
  on it. Fully covered by tests.
- **Native benchmark now scores HEAVEN's full web surface, not just injection.**
  `tests/benchmarks/test_native_benchmark.py` drives the crawler + injection +
  misconfig + OAST out-of-band scanners against the labelled native target and
  scores **11 categories**, SQLi (error/blind/UNION), reflected XSS, command
  injection, LFI, **SSRF, XXE, CORS, open redirect, weak JWT, insecure cookie,
  missing security headers**, at **100% precision / 100% recall / 100% F1**
  (13/13 ground-truth entries, 15 findings, 0 false positives). The v1.0
  detectors are now proven by the always-on CI benchmark, and the numbers in
  `docs/BENCHMARK_RESULTS.md` / `docs/COMPARISON.md` reflect the expanded surface.

- **UNION-based SQL injection detection**: the fourth classic SQLi technique
  (alongside error-based, boolean-blind and time-based). It sweeps the unknown
  column count, exfiltrates a unique marker via `UNION SELECT` in both string and
  numeric contexts, and confirms a hit only when the marker surfaces as rendered
  query OUTPUT, the reflected payload is stripped first, so an app that merely
  echoes the input can't trigger a false positive
  (`heaven/vulnscan/injection_scanner.py`, verified by the native benchmark).
- **Native, Docker-free web-injection benchmark (scored).** A tiny in-process
  Flask target (`tests/benchmarks/native/vuln_app.py`) faithfully reproduces
  DVWA's SQLi/LFI/cmdi/XSS endpoints, *including MySQL comment semantics*, so
  the real crawler and injection scanner are exercised end-to-end in ~1 s with no
  QEMU or Docker. Two always-on tests consume it: `test_native_sqli_recall.py`
  asserts HEAVEN detects error-based **and** blind SQLi, LFI, command injection
  and reflected XSS, each attributed to the correct parameter (`id`, not the
  `Submit` button) and with no SQLi/cmdi false positives on reflective/escaped
  endpoints; `test_native_benchmark.py` scores the same run through the existing
  precision/recall/F1 metrics layer against a labelled ground truth
  (`ground_truth/native.yaml`) and enforces floors (currently 100% precision,
  100% required recall, 100% F1). The crawler-vector → scan-target conversion was
  extracted from the orchestrator into a pure, unit-tested
  `build_injection_targets()` (single source of truth).

- **CycloneDX SBOM export.** `heaven sbom` and `GET /api/sbom` generate a
  CycloneDX 1.5 SBOM whose components are the services HEAVEN discovered
  (product/version/CPE per open port) and whose `vulnerabilities` section
  folds in CVE-bearing findings. A "SBOM (CycloneDX)" download was added to the
  web Reports page. The generator now consumes the real scanner asset shape
  (`{host, open_ports:[…]}`), previously it expected a shape the scanner never
  produced, so it always emitted an empty SBOM (`heaven/devsecops/sbom.py`).
- **AI-assisted remediation.** `heaven remediate <finding-id>` and
  `POST /api/findings/{id}/remediation` generate remediation guidance via the
  configured LLM provider, falling back to the knowledge-base remediation when
  no key is set (`ai_generated` flags which path produced the text). A
  "Generate AI remediation" button was added to the finding detail page
  (`heaven/devsecops/ai_remediation.py`).

- **Rebuilt the HTML report into a client-ready deliverable.** It now opens with
  a cover page (classification, engagement, overall-risk badge), then a
  confidentiality notice, document control + revision history, table of contents,
  executive summary (narrative + severity distribution bar + KPI tiles + key
  findings), scope & methodology (in-scope targets + standards: OWASP/PTES/NIST/
  MITRE/CVSS), a risk-rating methodology table with remediation SLAs, a findings
  summary table, detailed findings (per-finding metadata, description, impact,
  evidence/PoC, remediation, references), OWASP Top 10 coverage, a prioritised
  remediation roadmap, and an appendix (tooling, glossary, disclaimer).
- **Print-ready.** Light, A4-friendly layout with `@page`/print CSS, page breaks
  between sections, and a built-in **Print / Save as PDF** button, so the HTML
  doubles as a polished PDF with one click (`heaven/devsecops/compliance_report.py`).
- **One-click download + in-browser preview** on the web Reports page: a primary
  "Download report (HTML)", a "Preview in browser" (opens the deliverable in a new
  tab), and a direct "Download PDF". Other formats (Markdown/CSV/JSON/SARIF/Burp/
  Proxy-JSONL) remain as secondary data exports.

- **Sample data in one step.** New `heaven demo` (CLI) and a **Load sample data**
  button on the dashboard seed a realistic example engagement (12 findings,
  critical→info, with evidence) into the same store the dashboard reads, so a
  fresh install shows a full Dashboard / Findings / Kill-chain / Reports
  instantly instead of an empty screen. Idempotent and fully offline
  (`heaven/demo.py`; `POST /api/demo/seed`).
- **System Health page (web UI)**: the browser equivalent of `heaven doctor`.
  Shows external tools (nmap/nuclei/sqlmap/ffuf/searchsploit/semgrep/docker)
  with install hints, which API keys/integrations are configured, Python-module
  health, and recommended next steps, so "is it broken or just missing a tool?"
  is answerable at a glance (`GET /api/system/health`; `doctor` now also probes
  ffuf + searchsploit).
- **Friendlier CLI.** Uncaught errors now render a one-line, actionable message
  (with a "re-run with `--debug`" hint) instead of a raw traceback. A new global
  `--quiet`/`-q` flag silences informational logs so output pipes cleanly, pair
  it with a command's `--format json` (e.g. `heaven --quiet findings --format
  json | jq …`) for scripting/CI.
- **Docs**: `docs/FAQ.md` (troubleshooting), `pipx install heaven-pentest` and
  `docker run` one-liners, and a "See it in 60 seconds" quickstart in the README.
- **One-click demo scan**: a "Run demo scan" button (Scans page) and
  `POST /api/demo/scan` animate the full loop (recon → crawl → injection →
  reporting) with live progress, then land the sample findings, so a new user
  experiences a real-feeling scan without a target or authorization.
- **Global `--json`**, a root flag that emits machine-readable JSON from the
  data commands (`findings`, `doctor`, `config list`, `demo`); implies `--quiet`
  so stdout is clean for `jq`/CI.
- **In-app help tooltips**: a reusable `HelpTip` (?) explains CVSS / EPSS /
  severity / confidence / risk score / kill-chain phases inline on the Dashboard
  and Kill Chain pages.
- **Light theme + mobile nav**: a header toggle switches light/dark (persisted
  to `localStorage`, applied before first paint), and the sidebar collapses to an
  off-canvas hamburger menu on narrow screens.
- **`heaven quickstart`**, one command takes a fresh clone to a populated
  dashboard: ensures `.env` (generating a strong admin password if missing),
  loads sample data, and prints the next step (`--serve` launches the UI too).
- **"Fix this first"**: a Dashboard card + `GET /api/engagement/top-findings`
  rank findings by risk score and show a one-line remediation for each, so the
  highest-impact next action is obvious; click through to the detail.
- **Guided scan launcher**: the Scans launcher now validates targets live
  (URL / IP / CIDR / host) with a valid/invalid count, disables Launch until
  there's a valid target, shows the engagement's current scope size, and adds
  inline help on Stealth + the authorization gate.
- **Executive summary** on the "Fix this first" card ("N critical · M high
  across K targets · top risk …").
- **Animated demo**: `docs/assets/demo.svg`, a lightweight terminal cast
  (`quickstart` → `serve` → dashboard) embedded at the top of the README's
  "See it in 60 seconds".

- A short, skippable **in-app tour** (`heaven-ui/src/components/Tour.jsx`) orients
  a first-time operator across Dashboard → Scans → Findings/Reports → Settings →
  System Health, ending with a one-click **Load sample data**. Auto-opens once
  per browser and is re-launchable anytime from the command palette
  ("Take the tour"). Token-styled, so it renders in light and dark.

- **Entering API keys no longer means hand-editing `.env`.** A new
  **Settings** page in the web UI (`/settings`) lists every configurable key, 
  LLM (Gemini / Anthropic / OpenAI), NVD, Shodan, Slack/Teams webhook, Splunk &
  Elastic SIEM, Jira & Linear, grouped, each with a one-line description, a
  *"how to get it"* link, and a masked indicator of whether it's already set.
  Paste a value, click **Save**, and it's applied to the running server
  immediately *and* persisted, survives a restart, and the CLI picks it up too.
- **One catalog backs everything** (`heaven/settings_catalog.py`): the web
  Settings page, the new **`heaven config`** command (`list` / `get` / `set` /
  `unset`), and the `heaven init` wizard all read & write the **same `.env`**
  plus `os.environ`, so a key set on any surface is live everywhere. No more
  "I set it in the CLI but the web app didn't see it".
- New endpoints `GET/POST /api/settings` (+ `POST /api/settings/test-llm` for a
  no-cost "is my LLM key working?" check), gated by `config.modify`. Secrets are
  **never** returned in full, only a short masked preview. New
  `heaven/utils/env_file.unset_env_var()` cleanly removes a key.
- Tests: `tests/test_settings.py` (14 cases) covers masking, persistence,
  unset, unknown-key rejection, and the API surface.

- The injection scanner is no longer SQLi+XSS only. It now tests every GET param
  and POST field for, additionally:
  - **Local File Inclusion / path traversal**: `/etc/passwd`, `..//` bypasses,
    null-byte, `php://filter` wrappers; **content-leak confirmed** (CWE-98).
  - **OS command injection**: output-based (`;id` / `$(id)` / `` `id` `` →
    detects `uid=…`) and **time-based blind with differential timing** (doubling
    the injected `sleep` must double the delay, defeats server jitter, so no
    false positives on naturally-slow endpoints) (CWE-78).
  - **Remote File Inclusion**: best-effort detection of remote-fetch attempts
    (CWE-98).
  Verified live against DVWA (`critical lfi — param 'page'`,
  `critical cmdi — param 'ip'`) and covered by deterministic unit tests
  (`tests/test_injection_probes.py`). See
  [docs/BENCHMARK_RESULTS.md](docs/BENCHMARK_RESULTS.md).

- `docs/BENCHMARK_RESULTS.md` documents the real, reproducible results of running
  HEAVEN against live DVWA (autonomous authenticated discovery of 17
  `/vulnerabilities/*` endpoints; confirmed critical SQLi/LFI/cmdi; the
  report-quality + auth fixes that made it work), linked from the README summary.

- The "X not set, random value generated" config notice is now DEBUG-level, so
  normal commands are quiet for unconfigured users (the actionable nudge still
  lives in `heaven serve` startup + `heaven doctor`'s next-step).
- Web Scans page shows **live elapsed time** for running scans (updates every
  second) alongside the existing progress bar.
- **First-run guide on the Dashboard**: a dismissible checklist
  (scope → scan → findings → report) that auto-checks each step from real
  engagement state and hides once the core flow is complete.

- The autonomous loop now streams each iteration the instant it completes over
  `WS /api/autonomous/jobs/{id}/stream` (snapshot → iteration… → done), with
  per-subscriber fan-out. `run_autonomous` gained an `on_iteration` hook and
  `IterationReport.to_dict()`. The web UI renders a live table and falls back to
  polling if the socket drops. Verified end-to-end over a real socket.

- New `tests/test_report_auth_api.py`: report export (empty-engagement 404,
  unknown-format handling) and the password-change flow (wrong-current 401,
  weak/common new-password 422, success persists to `.env`).
- CI now builds the web UI (`ui-build` job: `npm ci` + `npm run build`, uploads
  `dist`) and the Docker job depends on it.

- `heaven doctor` ends with a contextual **Next step** block that walks the
  happy path based on current state (no admin password → `heaven init`; no
  engagement → `heaven engage init` + `scope add`; no findings → `heaven scan`;
  has findings → `heaven report` / `heaven serve`). A new operator is never left
  wondering "now what?".

- The multi-format report export already existed but was buried as a dropdown on
  the Findings page, so the **Reporting** section (Tickets / Benchmark /
  Methodology) had no obvious way to "get a report". Added a first-class
  **Reports** page (`/reports`) that shows a live severity snapshot of the active
  engagement and one-click download in all 8 formats (PDF / HTML / Markdown /
  CSV / JSON / SARIF / Burp / Proxy-JSONL), with an actionable empty state when
  there are no findings yet.

- pip extras for the AI layers: `pip install -e ".[gemini]"` / `".[anthropic]"` /
  `".[openai]"`, or `".[llm]"` for all three. `.env.example` and `heaven init`
  now document each key, where to obtain it, and which SDK to install; `heaven
  init` prints the get-a-key URLs and the exact `pip install` line.

- **Error boundary** around the routed content: a render error now shows a
  recoverable "something went wrong" card (Reload / Back to dashboard) instead
  of a blank screen. Keyed by route, so navigating away clears it.
- **404 route**: unknown URLs render a proper "page not found" instead of an
  empty content area.
- **Session survives refresh**: the auth token is persisted in sessionStorage
  (clears on tab close), so F5 / reopening a tab no longer forces re-login.
  Tradeoff documented in `api.js`; httpOnly cookie remains the max-hardening
  option.
- **Graceful session expiry**: a 401 clears auth, raises a "Session expired"
  toast, and ProtectedRoute redirects to /login (no more raw error card).
- **Actionable empty states**: the "no engagement" screens on Dashboard,
  Findings, Kill Chain and Engagement now offer an in-app **Launch a scan →**
  button (the Scans page has a full launcher) instead of telling the operator
  to go run CLI commands / restart the server.
- **Global "scan running" indicator** in the header: polls so it stays visible
  after you navigate away from the Scans page; click to return.
- **Findings filters**: debounced auto-apply + Enter-to-apply, and a loading
  skeleton on first fetch.
- **Accessibility**: visible keyboard focus rings, keyboard-operable sortable
  table headers with `aria-sort`, `aria-expanded` on sidebar groups, and
  `aria-hidden` on decorative icons; honors `prefers-reduced-motion`.
- **Consistency pass across all pages**: skeleton loaders on every
  fetch/run (Coverage, Knowledge, Tickets, Methodology, Benchmark, Diff, SAST,
  Autonomous, Post-Ex, Lateral, AI Plans) and actionable empty states
  (Knowledge / Diff → "Launch a scan", Benchmark / Watch → clear guidance).
- **No more `alert()` dialogs**, the Replay (Scans) and Train-priors (Coverage)
  flows now use the in-app toast system instead of blocking browser alerts.

- **Colourised, grouped help via rich-click.** `heaven --help` now renders the
  38 commands in six labelled panels (Scanning & Monitoring · Engagements &
  Findings · Reporting & Tickets · AI & Threat Intel · Models · Platform &
  Setup) instead of one flat alphabetical dump. `heaven scan --help` groups its
  options into Targets / Scan profile / Authorization & scope / Exploitation
  chaining / Output panels and shows a worked Examples block. Falls back to
  plain Click (same commands) when `rich-click` isn't installed.
- **`heaven use <engagement>`**, git-branch-style sticky engagement context
  stored per working directory (`./.heaven/`), so you stop retyping
  `--engagement` on every command. Resolution precedence: explicit flag >
  `HEAVEN_ENGAGEMENT` env > `heaven use` > default. `heaven use` shows the
  current selection + available engagements; `heaven use --clear` resets it.
  The no-arg dashboard now displays the active engagement.
- **"Did you mean?" suggestions** on a mistyped command
  (`heaven scna` → suggests `scan`).

- **Downloadable reports (webapp + API).** New `GET /api/report/export?format=…`
  streams a report in 8 working text/standard formats, HTML (compliance-mapped),
  Markdown, CSV, JSON, SARIF, Burp XML, proxy-JSONL, plus PDF when `reportlab`
  is installed (a declared dependency; returns a clear 503 if absent). A
  "Download report" menu is wired into the Findings page (`ReportMenu`). The API
  reuses the exact reporters behind `heaven export` / `heaven report`, so CLI and
  webapp output match.
- **Vulnerability Knowledge Base** (`heaven/devsecops/vuln_kb.py`), 16 curated
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

- **PyPI release workflow** (`.github/workflows/release.yml`), on `v*`
  tags, builds sdist+wheel, verifies install, publishes via PyPI OIDC
  trusted publishing, and cuts a GitHub Release with CHANGELOG body.
- **Docker GHCR build+push workflow** (`.github/workflows/docker.yml`), 
  multi-arch (amd64 + arm64) image at `ghcr.io/nishu2402/heaven` on
  branch push, semver tags on `v*` tags.
- **`heaven init`**, interactive first-time-setup wizard. Generates
  strong passwords, prompts for optional LLM / SIEM / ticketing keys,
  writes a versioned `.env`. Idempotent.
- **`heaven update`**, refreshes Nuclei templates, NVD CVE delta, and
  ExploitDB CSV mirror in one command. Useful for cron / pre-engagement.
- **`heaven scan --watch-tail`**, headless mode that disables the Rich
  live HUD and streams flat one-line-per-event output. For CI / ssh /
  `tee scan.log` workflows where the live HUD scrambles the recording.
- **Asset-criticality risk multiplier**: `heaven scope add --criticality
  {low,medium,high,crown_jewel}` adjusts every finding's `risk_score` by
  the configured multiplier (0.7 / 1.0 / 1.3 / 1.5). 11 new tests.
- **Helm chart** (`deploy/helm/heaven/`), standard chart with
  Deployment + Service + Secret + ConfigMap + PVC + Ingress (opt-in)
  + ServiceAccount + NOTES.txt. Multi-arch image-ready.
- **`docs/QUICKSTART.md`**, 5-minute walkthrough for evaluators.
- **`docs/COMPARISON.md`**, feature parity matrix vs Burp / ZAP /
  sqlmap / Nessus / Acunetix + empirical-numbers template.
- **`docs/DEMO.md`**, asciinema/video recording script (substitute
  for an actual recorded demo this session).
- **`docs/BENCHMARK_HOWTO.md`**, step-by-step to produce real DVWA
  precision/recall numbers (substitute for the actual benchmark run).
- **Live CI badges** in README: replaces the manually-maintained
  `Tests-294_Passing` badge with the actual GitHub Actions status,
  benchmark workflow status, and PyPI version badges.
- **`pyproject.toml` metadata polish**, full PyPI classifier set,
  project URLs, marketing description, additional keywords. Renamed
  the published package from `heaven` (squatted) to `heaven-pentest`.

- **Continuous monitoring** (`heaven watch`), interval+jitter loop with
  auto-diff against the previous scan. Fires alerts ONLY on `new` or
  `regressed` findings (configurable `--heartbeat` to alert every run).
  Optional `--auto-tickets` to create Jira / Linear issues on regressions.
- **Differential scanning** (`heaven diff <base> <current>`), bucketed
  output (new / resolved / regressed / unchanged) with CI-friendly exit
  codes. API: `GET /api/scans/{id}/diff?baseline=...`.
- **SAST** (`heaven sast`), Semgrep wrapper with a curated 18-rule pack
  for Python / JavaScript / Go covering OWASP Top 10. Findings land in
  the engagement DB alongside DAST findings.
- **Ticketing** (`heaven tickets`), Jira (REST v3) + Linear (GraphQL)
  with auto-priority mapping, label normalisation, and bulk push.
- **Iterative autonomous loop** (`heaven autonomous`), LLM-driven
  observe → plan → act loop bounded by `--max-iterations` and
  `--time-budget`. Falls back to a deterministic rule-based playbook
  when no LLM API key is set.
- **Coverage grader** (`heaven coverage`), rule-based OWASP coverage %
  + scope hit rate + optional LLM gap analysis.
- **Lateral movement** (`heaven lateral`), SSH key reuse + SMB PsExec
  + pass-the-hash with a hop graph output.
- **Knowledge graph** (`heaven knowledge`), SQLite-backed cross-engagement
  memory of (target_profile, technique, outcome) tuples with Beta-smoothed
  per-technique success priors.
- **Exploit-DB lookup** (`heaven exploitdb <cve>`), local `searchsploit`
  (preferred) + ExploitDB CSV mirror.
- **AI namespace**: Layers A, E: provider-agnostic LLM gateway
  (Anthropic / OpenAI / Gemini), recon agent, attack-chain planner,
  FP review, autonomous loop.
- **Authenticated scanning**: `--cookie-file PATH` (Netscape format)
  and `--auth url=/login,user=X,pass=Y[,csrf_field=token]` on
  `heaven scan`.
- **Exploit proof**: `heaven/vulnscan/exploit_proof.py` ties sqlmap,
  RCE canary file dropping, and an SSRF callback verifier into a single
  `prove_finding()` entry point. Auto-triggered with `--auto-prove` on
  `heaven scan`.
- **Post-exploitation**: `heaven/postex/` with `linpeas_runner`,
  `bloodhound_collector`, `cred_validator`. Admin-gated.
- **Benchmark suite**: `tests/benchmarks/` against DVWA with adapters
  for Burp / ZAP / sqlmap, scanner-agnostic metrics, markdown + CSV
  reporters, GitHub Actions weekly workflow.
- **Methodology mapping docs**: `docs/methodology/` with explicit
  mappings to OWASP Testing Guide v4, NIST SP 800-115, and PTES.
- **NVD model card**: `data/models/NVD_model.MODEL_CARD.md` following
  Google's Model Cards format.
- **Reproducibility**: `--seed` flag on `heaven scan` + `heaven replay
  <scan-id>` for deterministic re-execution.
- **SIEM forwarders**: `SplunkHECAlerter` + `ElasticAlerter` in
  `devsecops/alerting.py`.
- **Web UI pages**: Watch, ScanDiff, SAST, Autonomous, AIPlans,
  Coverage, Postex, Lateral, Knowledge, Tickets, Benchmark, Methodology.

### Changed

- **Hostile-target resilience.** Every core-path orchestrator HTTP session now
  carries a per-request timeout ceiling, and the open-redirect check probes its
  candidate parameters concurrently (was sequential, it multiplied a slow
  target's latency ~20×). A new `tests/test_resilience.py` drives the live web
  detectors against slow / 500 / connection-drop / redirect-loop servers and
  asserts they finish fast, never crash, and emit no false findings.

- **Leaner dependency footprint for publication.** Removed eight declared
  packages that nothing in the codebase imports: `python-nmap` (HEAVEN shells
  out to the `nmap` *binary*), `python-whois`, `shodan` (Shodan recon uses
  plain HTTP), `mitreattack-python` / `stix2` / `taxii2-client` (ATT&CK mapping
  ships a bundled dataset + HTTP TAXII), `matplotlib`, and `lxml` (the crawler
  parses with the stdlib `html.parser`). Also moved the two heaviest guarded
  deps out of the base install into extras, `scapy` → `[recon]`, `boto3` →
  the new `[cloud-aws]`, so `pip install heaven-pentest` is much lighter and
  the AWS/scapy features still degrade gracefully. No feature was removed; the
  `[mitre]` extra is gone because it required no pip packages. All tests still
  pass, base dependency count trimmed to 28.
- **DVWA benchmark now scans authenticated by default.** The fixture logs into
  DVWA (CSRF token + `security=low` cookie) and hands the scan a `--cookie-file`
  so it exercises the real `/vulnerabilities/*` attack surface instead of only
  the public login page; the per-scan timeout default was raised to 900 s (the
  authenticated crawl does far more work). Closes the auto-login TODO in
  `tests/benchmarks/conftest.py`.

- The PDF is now a full client deliverable matching the HTML report
  section-for-section: cover page, confidentiality notice, document control +
  revision history, a **real table of contents with page numbers**, executive
  summary (narrative + severity KPIs + distribution bar + key findings), scope &
  methodology, risk-rating methodology with SLAs, findings summary, detailed
  findings (metadata, description, impact, evidence/PoC, remediation, references),
  OWASP Top 10 coverage, remediation roadmap, and appendix, with a
  "CONFIDENTIAL … Page X of Y" footer on every page.
- The PDF and HTML reports now **share** the severity palette, OWASP mapping and
  knowledge-base enrichment, so a finding looks identical in both, and all text is
  escaped (long unbroken payloads wrap instead of overflowing the page).
- **Dependency reduced:** dropped WeasyPrint (which needs Pango/Cairo system
  libraries) from the `reports` extra and `requirements.txt`. PDF export now needs
  only `reportlab`; the HTML report needs nothing extra.

- **`install.sh` now creates `.env` for you** with a generated admin password on
  first run (`heaven init --non-interactive`), so the web UI / API work out of
  the box, no manual `export HEAVEN_ADMIN_PASSWORD`. It points you at the
  Settings page / `heaven config` for API keys.
- **Lean core by default, resilient extras.** It installs the lightweight core
  first (guaranteed) then attempts each optional feature pack
  (`recon` / `reports` / `mitre` / `scheduling` / `lateral` / `deploy`)
  *independently*, so one heavy dependency that needs system libraries can't
  abort the whole install. `HEAVEN_CORE_ONLY=1` skips extras entirely; LLM SDKs
  stay opt-in.

- Google deprecated the `google-generativeai` package (it prints a end-of-life
  warning and stops receiving updates) in favour of the new `google-genai` SDK.
  The LLM gateway now uses the current client-based SDK
  (`from google import genai` → `genai.Client(...).models.generate_content(...)`,
  with a real `system_instruction` instead of prompt-prepending) and **falls back
  to the legacy SDK** if only that one is installed. Updated the `[gemini]` /
  `[llm]` / `[all]` extras, `requirements.txt`, the `heaven init` pip hint, and
  the README to `google-genai`. New `tests/test_llm_gateway.py` covers provider
  selection, the SDK choice, secret redaction, and structured parsing.

- **`pip install` now matches the documented experience.** Three deps that power
  the default out-of-the-box flow were missing from `pyproject.toml`'s base
  install: `aiosqlite` (the default offline SQLite store, it was wrongly buried
  in the `dev` extra), `pyjwt` (JWT sessions) and `cryptography` (vault). Moved
  them to core `dependencies`.
- **Optional features are now installable as pip extras** instead of only via
  `requirements.txt`: `[recon]`, `[reports]`, `[lateral]`, `[mitre]`, `[deploy]`,
  `[scheduling]`, and an umbrella `[all]` (mirrors the existing `[gemini]` /
  `[anthropic]` / `[openai]` / `[llm]` pattern). Each feature still degrades
  gracefully when its extra isn't installed. README documents the matrix.

- The CLI auto-loads `.env` with `override=True`, so it wins over stale shell
  exports. Editing `.env` (or the Web-UI password change that writes back to it)
  now always takes effect on the next run, no "I changed it but a leftover
  `export` shadowed it" gotcha. `heaven init`'s next-steps no longer tell you to
  `source`/`export` the file (that step is obsolete).

- **`heaven sys-status` → `heaven doctor`.** The deployment health check now
  uses the familiar `doctor` idiom and is discoverable in the grouped help.
  `sys-status` is kept as a hidden, backward-compatible alias.
- **`heaven schedule` deprecated** in favour of `heaven watch` (which adds
  change-detection and alert-on-change). It is now hidden and prints a
  deprecation notice, but still runs for backward compatibility.

- **Complete React UI overhaul**: replaced the green-on-black CRT/matrix
  aesthetic with a modern, professional dark theme: deep-slate surfaces,
  aurora-gradient backdrop, glassmorphism, a violet→blue primary accent
  with emerald kept as the live/signature colour, **Inter** for UI text +
  **JetBrains Mono** for data/code, layered elevation, and framer-motion.
- **Rebuilt design system** (`heaven-ui/src/index.css`) around the same
  class vocabulary, so all 19 pages re-theme consistently. Flagship
  surfaces hand-built: split-hero **LoginPage**, **Dashboard** (gradient
  stat cards + real severity-distribution chart), **Sidebar**/**Header**;
  3D topology reskinned to the new palette.
- **Verified live**: server-rendered screenshots of Login, Dashboard,
  Findings and Scans against a seeded engagement confirm real data flow.
- **Code-splitting**: the heavy three.js 3D topology (~900 KB) is now
  lazy-loaded behind a dynamic import, and every authenticated page is its
  own chunk (`React.lazy` + `Suspense`). First-load JS dropped from a single
  ~1.1 MB bundle to ~313 KB (login + shell); the 3D engine only downloads
  when the Dashboard opens. Removed dead `recharts`/`mermaid` manual chunks.

- **CLI split**: `heaven/main.py` decomposed from a 1380-line monolith
  into a thin shim plus `heaven/cli/` subpackage (one module per command
  group). The `heaven = heaven.main:cli` pyproject entry point is unchanged.
- **`zeroday_engine.py` → `anomaly_probe.py`**, renamed to match what
  the code actually does (behavioural fuzzing heuristics, not real
  zero-day discovery).
- **`ai_brain.py` priors** moved from hardcoded module constants into
  `data/models/priors_bootstrap.json`. `heaven/ml/train_priors.py` +
  `heaven train-priors` produce `priors_learned.json` from engagement
  history, which is preferred at runtime when present.

### Removed

- Deleted two orphaned modules with no callers: `recon/wireless_recon.py`
  (PCAP wireless parsing, needed operator-supplied captures, never wired into
  the scan flow) and `vulnscan/msf_client.py` (Metasploit RPC, required an
  external `msfrpcd` and an uninstalled optional dependency).
- Removed the corresponding README claims that had no backing code: "wireless"
  reconnaissance and the Metasploit integration row (which referenced a
  `--enable-exploitation` flag that did not exist).
- Refreshed the drifted project statistics (tests, modules, CLI-command count).

### Fixed

- **ML risk scores never reached the web dashboard (always showed 0).** The ML
  scoring phase annotates findings with `predicted_cvss_score` / `priority_score`,
  but `EngagementStore.upsert_finding` persisted `finding.get("risk_score")`, a
  key nothing sets, so the DB `risk_score` column was `0.0` for every finding.
  The CLI/JSON report (in-memory) showed the real CVSS, but the web Command
  Centre (which reads the DB) reported `avg_risk: 0.0` and per-finding risk of 0.
  Persistence now falls back through the ML fields (`_risk_value`) and preserves
  the full ML detail (CVSS/priority/EPSS/KEV/band) in `evidence_json`. Verified
  live: the dashboard now shows the true risk. Regression tests in
  `tests/test_finding_precision.py`.
- **`confidence_bucket` was blank for every finding except FP-reviewed ones.**
  Only the FP-review path set the bucket, so the web UI / reports showed an empty
  confidence tier for most findings. `upsert_finding` now derives it from the
  confidence score (`_confidence_bucket`, same tiers as
  `fp_suppress._bucket_for`, floored at `tentative`) when the finding doesn't
  carry one. Verified live: 0 blank buckets after a full scan.
- **README test-count badge no longer goes stale.** The primary Tests badge is
  now a **live GitHub Actions status badge**, and the decorative counts are kept
  honest by `scripts/sync_test_count.py` (run it to sync; `--check` fails CI when
  stale, wired into `.github/workflows/ci.yml`).
- **Scanner precision, three false-positive classes found by a full live run.**
  (1) The Nuclei parser ingested wordlist/parameter-list helper templates as
  real findings, `top-xss-params` surfaced as a HIGH "Top 38 Parameters -
  Cross-Site Scripting" with empty `vuln_type`; these are now skipped and every
  Nuclei finding carries a concrete `vuln_type`. (2) A stray Python docstring
  (`http.cookies.Morsel.js_output()…`) leaked in as a finding with no type,
  evidence, or confidence; `dedup_findings` now drops such reportless noise via
  a conservative `_is_junk_finding` guard (no real finding is ever dropped, 
  it requires *all* of empty-type, no-evidence, no-confidence). (3) Both
  request-smuggling detectors false-positived on ordinary servers, the CL.TE
  timing probe flagged any slow/hung origin as **critical**, and the web-fuzzer
  checks keyed off the *response* `Content-Length` (present on nearly every
  200). The CL.TE detector now requires a baseline timing differential and
  reports a `medium` "possible, verify manually" indicator instead of a
  confirmed critical; the web-fuzzer checks require a behavioural deviation from
  a well-formed baseline and are downgraded to `low`. Verified on a live full
  scan: the three noise classes drop to zero while every real finding
  (cmdi/lfi/error+UNION+boolean SQLi/XSS) is retained. Regression tests:
  `tests/test_finding_precision.py`, `tests/test_nuclei_parse.py`.
- **Nuclei parser could abort a scan on malformed output.** The `-jsonl`
  parser assumed every stdout line was a JSON object with a dict `info` block;
  a bare non-object line (string/array/number) or a `null` `info` raised an
  `AttributeError` that escaped the `except json.JSONDecodeError` and killed the
  scan. Parsing is now shape-guarded, decodes with `errors="replace"` (invalid
  UTF-8 in matched banners no longer crashes), and was extracted into a testable
  `_parse_nuclei_output` with regression tests (`heaven/vulnscan/nuclei_scanner.py`,
  `tests/test_nuclei_parse.py`).
- **Version strings synced to `1.0.0`** across the project, the ML risk model's
  internal version (`2.0.0`), the uninstaller banner (`1.3.0`), and the installer
  comment, plus the README header counts (tests/modules/CLI commands).
- **Boolean-blind SQLi false positives on reflective endpoints.** The probe used
  a length-only comparison against the baseline and never compared the TRUE/FALSE
  responses to each other, so pages that merely echo input (search/reflection),
  name the missing file (LFI warnings), or return a constant error (login forms)
  were mis-flagged as `sqli`. Verified live against DVWA (authenticated,
  `security=low`): false `sqli` on `/vulnerabilities/{xss_r,fi,brute}/`. The
  decision is now a reflection-resistant, page-size-independent oracle check
  (`_boolean_sqli_confirmed`): the reflected payload is stripped (HTML-entity
  decoded first, so `htmlspecialchars`-escaped echoes like `&#039;` are still
  matched) and a genuine TRUE-vs-FALSE content divergence is required while TRUE
  tracks the baseline. It runs in ~0.4 ms even on large/repetitive pages (a naive
  char diff was super-linear). Live-validated: the clear reflection FPs are gone,
  the real SQLi is still detected, and a genuine boolean oracle (row vs no-row)
  is correctly confirmed. 13 regression tests
  (`heaven/vulnscan/injection_scanner.py`, `tests/test_injection_boolean_sqli.py`).
- **SQLi payloads used a bare `--` comment that MySQL/MariaDB ignore, silently
  killing blind-SQLi recall.** MySQL only treats `--` as a comment when it is
  followed by whitespace (`-- `) or you use `#`; a bare `--` left the injected
  quote dangling, so both the true and false boolean probes errored identically
  and no oracle formed, the exact reason authenticated recall against DVWA
  (which runs MySQL) collapsed. All error/boolean/time payload terminators are
  now MySQL-safe (`-- ` / `#`), which also comment correctly on Postgres, MSSQL
  and SQLite. Proven with a Docker-free negative control: blind-SQLi on the
  vulnerable `id` param is detected with the fix and undetected with a bare `--`
  (`heaven/vulnscan/injection_scanner.py`).
- **Command-injection false positives on reflective endpoints.** The output-based
  cmdi probe flagged any page whose body contained the echo marker
  (`; echo h3av3n7x7`), but a page that merely *reflects* the payload text
  contains the marker without ever executing a shell. Surfaced by the new scored
  benchmark: cmdi false positives on the XSS/LFI/echo endpoints. The probe now
  strips the reflected payload (HTML-entity-decoded, covering escaped echoes)
  before matching, so the marker/`uid=` only counts as genuine command OUTPUT
, the same reflection-resistant principle as the boolean-SQLi fix
  (`heaven/vulnscan/injection_scanner.py`).

- **Report no longer breaks on scan-controlled content.** All finding fields
  (titles, targets, payloads, evidence) are HTML-escaped, so a payload like
  `<script>…</script>` renders as text instead of injecting markup into the
  deliverable.
- **PDF export was mis-wired and could download an empty file.** The API gated
  PDF export on `reportlab` but the generator actually used WeasyPrint, so with
  reportlab-but-not-WeasyPrint installed the API served a 0-byte `.pdf`. The PDF
  generator was rebuilt on **reportlab** (pure Python, no system libraries), so
  the API check and the generator now agree (`heaven/devsecops/pdf_report.py`).

- **NVD lookups returned nothing.** The client queried NVD's `cpeName`
  parameter, which requires an *exact* CPE 2.3 name with a concrete version and
  answers **HTTP 404** for the wildcard-version CPEs HEAVEN generates from banner
  fingerprints, so CVE enrichment silently found zero results. Switched to
  `virtualMatchString`, which accepts partial/wildcard CPEs and applies NVD's own
  version-range matching (e.g. OpenSSH wildcard: 0 → 50 CVEs; Apache 2.4.49: real
  hits). Results are now sorted KEV-first, then by CVSS (`heaven/vulnscan/nvd_client.py`).
- **nmap CPEs were rejected.** nmap emits CPE 2.2 (`cpe:/a:…`); NVD only
  understands 2.3. Added `_normalize_cpe()` to convert 2.2 → 2.3 before querying.
- **An invalid API key looked like "no vulns."** NVD returns 404 (not 401/403)
  for a rejected `apiKey`, so a typo'd key silently produced empty scans. The
  client now warns once when a 404 occurs with a key set, and a new
  **connectivity test** distinguishes *key valid* / *key rejected* / *no key
  (slow tier)*: **Settings → Recon enrichment → Test NVD connection** (web),
  `heaven config test-nvd` (CLI, supports `--json`), and `POST
  /api/settings/test-nvd` (API).

- **`heaven update` never refreshed ExploitDB.** It looked up a
  `refresh_csv_mirror` that didn't exist and fell back to the lazy cache loader,
  which returns early when the file is already present, so on any existing
  install the ExploitDB refresh was a silent no-op. Added a real
  `refresh_csv_mirror()` that force-re-downloads the GitLab CSV mirror (~47k
  exploit rows) and reports the new row count (`heaven/vulnscan/exploitdb_client.py`).
- **MITRE ATT&CK TAXII pointed at a retired server.** `cti-taxii.mitre.org` was
  shut down by MITRE in 2022 (every fetch timed out, then fell back to an empty
  dataset). Updated to the current `attack-taxii.mitre.org` TAXII 2.1 service
  (`/api/v21`) and the current Enterprise ATT&CK collection id
  (`heaven/mitre/taxii_client.py`, `MITREConfig.taxii_url` default).
- Verified-correct (no change needed): EPSS, CISA KEV, Shodan, the LLM gateway
  (Anthropic/OpenAI/Gemini), Jira v3 + Linear ticketing, and Slack / Splunk HEC /
  Elastic alerting all use correct endpoints, auth, and payload formats.

- **Light theme: the sidebar was unreadable.** `.sidebar` and `.nav-item.active`
  were hardcoded dark (dark gradient + white active text) while nav labels use
  theme tokens that turn dark in light mode, i.e. dark-on-dark. Added light-mode
  overrides so the sidebar surface and active item flip correctly.
- **`--help` / `--version` printed a spurious error and exited non-zero.** The
  new friendly-error wrapper swallowed `click.exceptions.Exit` (raised by
  `--help`, `--version` and any `ctx.exit(0)`), tacking on a "✗ Exit: 0" notice
  and exiting 1. It now passes those through untouched. Regression test added.
- **Demo `risk_score` was on a 0-10 scale** while real findings use 0-100
  (`risk_model` caps at 100). Demo findings now use the same 0-100 scale so the
  dashboard / "Fix this first" numbers read consistently for sample and real data.

Running the live DVWA benchmark surfaced four real bugs that, together, meant an
authenticated web scan reached nothing behind the login wall. All fixed and
verified against live DVWA:

- **Auth cookies were never sent by the scanners.** `aiohttp_session_kwargs()`
  built a cookie *jar* via `CookieJar.update_cookies({k: v})` with no
  response_url, leaving every cookie domain-less, aiohttp then silently dropped
  them. So the injection/fuzzer/API scanners hit protected pages
  **unauthenticated** and found nothing. Now cookies are passed as the flat
  `cookies=` dict (the approach the crawler already used). *This was the single
  biggest blocker to authenticated coverage.* Verified: the scanner now reaches
  DVWA's SQLi page authenticated (HTTP 200) and reports
  `critical sqli (error-based) — param 'id'`.
- **Crawler ignored the auth session.** The orchestrator never passed
  `auth_config` to `crawl_targets`, so the crawl stopped at `/login.php`. Now the
  active session's cookies/headers are plumbed in, verified the crawler
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
  (`max_urls=40`), so the phase is bounded (scan time 812s → ~140-170s).

Regression tests added (`test_scan_wiring.py`, plus the per-payload dedup test).

- Running the real DVWA benchmark exposed that one injectable parameter probed
  with N payloads produced **N findings**, a single SQLi on `?id=` became
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
  (the schema column is `evidence_json`), it would have failed for anyone with
  Docker. Fixed the query (`evidence_json AS evidence`).

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

- `heaven update` bailed with "NVDPipeline.download_recent not implemented yet".
  Implemented `NVDPipeline.download_recent(days=7)`, fetches CVEs published in
  the window via the NVD 2.0 API and appends new records (de-duped by CVE id) to
  `nvd_data/nvd_dataset.jsonl`. The command now actually refreshes the CVE feed.

- `asyncssh`'s `conn.run().stdout/stderr` can be `bytes` or `str` depending on
  the connection encoding. `linpeas_runner.py` and `lateral.py` assumed `str`,
  so on a `bytes` result the linpeas output would be parsed with a `b'...'`
  wrapper and the SSH-key-reuse check (`"uid=" in out`) would raise `TypeError`.
  Added a defensive `_as_text()` coercion at each boundary. (Surfaced by mypy once
  the `[lateral]` extra was installed.)

- **Credential vault is written `0600`.** `vault.enc` (the AES-256-GCM credential
  store) was created with the default umask (often `0644` → world-readable). It's
  now chmod'd to owner-only `0600` on every save. Flagged by `heaven self-audit`,
  which now scores **100/100 (grade A, 0 findings)**.
- **`cryptography` and `pyjwt` are core deps now** (see packaging note below).
  Without them the vault silently fell back to *plaintext* and auth used opaque
  (non-JWT) tokens, both degrade-gracefully paths, but not what a security tool
  should ship by default.

- **`.env` was only loaded when you passed `--config-file`.** Plain
  `heaven serve` / `heaven autonomous` (and every other command) never read
  `.env`, so the password, LLM keys, NVD/Shodan keys and SIEM/ticketing config
  written by `heaven init` were silently invisible to the running stack. The CLI
  now **auto-loads `.env` from the working directory at startup** (an explicit
  `--config-file` still overrides). This single fix resolved four reported
  symptoms at once:
  - **Web-UI admin password set via `heaven init` didn't take effect**, the
    server fell back to `admin/admin` + forced change because it never saw
    `HEAVEN_ADMIN_PASSWORD`. Now the configured password works on first login.
  - **`heaven autonomous` "did nothing smart"**, the LLM key was never loaded,
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
  updates the running process, so the change sticks across restarts, `.env` is
  the single source of truth. The forced first-login change now sticks too.

- **`POST /api/autonomous/run` ran the whole loop synchronously**, blocking the
  HTTP request for minutes; the React page kept run state in component-local
  state, so switching pages discarded the in-flight run and the result. The
  endpoint now launches the loop as a **background job** and returns a `job_id`
  immediately; added `GET /api/autonomous/jobs` and
  `GET /api/autonomous/jobs/{id}`. The Autonomous page polls the job and
  persists the active `job_id` in `sessionStorage`, so a run **survives
  navigating away and back, and a full page refresh**. Verified live: POST
  returned in 0.47 s, the job completed in the background, and returning to the
  page re-rendered the summary.

- The README's Quick Start told users to set **`GOOGLE_API_KEY`** for Gemini,
  but the code reads **`GEMINI_API_KEY`**, so the documented key was silently
  ignored. Corrected, and added a dedicated **API Keys & Configuration** section
  (every key, where to get it, three ways to set it, and a free-Gemini
  walkthrough).
- **`heaven init` wrote `HEAVEN_SHODAN_API_KEY` / `HEAVEN_NVD_API_KEY`**, but the
  code reads `SHODAN_API_KEY` / `NVD_API_KEY`, so wizard-set recon keys didn't
  take effect. The wizard now writes the canonical names; `config.py` also
  accepts `NVD_API_KEY` (keeping `HEAVEN_NVD_API_KEY` as a legacy alias).
- **Wrong SDK hint**: a missing Gemini SDK suggested `pip install gemini`
  (doesn't exist). It now suggests the correct `pip install google-generativeai`.

- `App.jsx` referenced `needsPasswordChange()` and `<ForcedPasswordChange>`
  without importing either (the imports had been dropped). With no ESLint to
  catch it and Vite not flagging undefined refs, the authenticated app threw a
  `ReferenceError` and **white-screened for every logged-in user**. Added the
  missing imports; verified end-to-end in a browser (login → forced-change →
  dashboard, zero console errors).

- **Exploit-DB product search**: added `search_product(service, version)`
  to `vulnscan/exploitdb_client.py` (searchsploit + CSV-mirror free-text
  search). The recon agent's `_tool_correlate_exploit` now returns **real**
  PoC matches instead of an empty placeholder; honest empty result when no
  source is available.
- **Honeypot orchestrator phase**: `recon/honeypot_detector.check_honeypots`
  no longer returns hardcoded zeros; it runs the real `analyze_host` over
  the network scan's discovered hosts and reports genuine counts (wired via
  an orchestrator closure that reads the network task result).
- **Honeypot detection calibration**: a known honeypot-software banner
  (cowrie/kippo/…) now flags on its own; the weighted composite capped
  banner signal at ~0.28 (below the 0.5 threshold), so definitive matches
  went undetected. Added a score floor on signature match.
- **8 new regression tests** (`tests/test_honeypot_and_exploitdb.py`).
  Suite now **313 passed, 1 skipped**.

- **`pyproject.toml` dependencies block** had drifted under `[project.urls]`,
  so setuptools parsed it as `project.urls.dependencies` and every
  `pip install -e .` aborted, breaking the test, mypy, self-audit and
  docker CI jobs. Moved it back under `[project]`.
- **Wheel data files**: added `[tool.setuptools.package-data]` so SAST
  rulesets (`vulnscan/sast_rules/*.yml`) and `db/schema.sql` ship in the
  wheel; tightened `packages.find` to exclude `heaven-ui`.
- **Dockerfile**: aligned the py-builder workdir with the runtime path
  (`/build` → `/app`) so the editable-install finder resolves after COPY
  (image built fine but crashed on startup before). Added **`.dockerignore`**
  (keeps host venv / node_modules / `data/` / secrets out of the context)
  and a **CI smoke-test** that runs the built image (`heaven --version`).
- **GitHub Actions**: bumped all Node-20 actions to current majors
  (checkout@v5, setup-python@v6, upload/download-artifact@v5, buildx@v4,
  build-push@v7, …), clearing the deprecation warnings.

- Several mypy strict-mode issues across the new modules.
- Ruff E731 (lambda-assignment) + F401 (unused imports) across the
  AI layer.

Initial public release of HEAVEN, autonomous penetration-testing
framework. See README.md for the full feature matrix.

### Security

- **Column allowlist on the raw-SQL repositories.** `EngagementRepository`,
  `WebPathRepository`, `NotificationRepository` and `ReportRepository` build
  `INSERT`/`UPDATE` statements by interpolating column *names* from
  `kwargs.keys()` (values were always bound parameters). Added a per-table
  `_COLUMNS` allowlist enforced by `_reject_unknown_columns()` so a dict key can
  never smuggle SQL, even if raw request data were ever forwarded into
  `create`/`update`, defense-in-depth, not a known-exploitable path
  (`heaven/db/repository.py`).
- **Patched 5 dependency advisories flagged by `pip-audit`.** Bumped
  `cryptography` floor to `>=48.0.1` (48.0.0 had GHSA-537c-gmf6-5ccf; kept below
  49 for pyopenssl compatibility) and added a `msgpack>=1.2.1` transitive floor
  (GHSA-6v7p-g79w-8964, pulled in via `cachecontrol`). `starlette` and
  `pydantic-settings` were already pinned to their fixed floors; the local env
  had simply drifted. `pip-audit` now reports no known vulnerabilities
  (`requirements.txt`).

- Bumped `aiohttp` to **>=3.14.0** (was >=3.9.0). `pip-audit` flagged
  `aiohttp 3.13.x` for CVE-2026-34993 (`CookieJar.load()` RCE on untrusted input)
  and CVE-2026-47265 (cookies leaked across a cross-origin redirect), both
  relevant to HEAVEN's authenticated-scan cookie handling + redirect following.
  `pip-audit` is now clean (0 known vulnerabilities).

### Verified

- **NVD model** (`NVD_model.pkl`) confirmed a genuinely trained 13-feature
  ExtraTreesRegressor (R²=0.9925), discriminates critical→10.0 / low→2.35,
  top features = Integrity/Confidentiality/Availability impact. Not a stub.
- **CLI ↔ webapp parity**: every operational CLI command maps to a UI
  surface; all 35 `api.js` helpers map to real server routes.

# Changelog

All notable changes to HEAVEN are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **IoT and OT findings are now scored against their _own_ security frameworks,
  not the web OWASP Top 10.** A Modbus PLC reachable on the LAN is not "A01
  Broken Access Control", so device and industrial findings are mapped to the
  standards the industry actually uses (`heaven/devsecops/frameworks.py`):
  - **Consumer / building-automation IoT → OWASP IoT Top 10 (2018)** (I1–I10):
    default credentials → I1, exposed MQTT/RTSP/UPnP → I2 Insecure Network
    Services, device web panels → I3, cleartext CoAP → I7, default SNMP
    community → I9.
  - **Operational technology / ICS → IEC 62443-3-3 foundational requirements**
    (FR1–FR7) cross-referenced to **MITRE ATT&CK for ICS**: an unauthenticated
    Modbus/S7comm/DNP3/IEC-104/OPC-UA/EtherNet-IP/BACnet service → FR1
    Identification & Authentication Control (Modbus, being writable, carries
    T0855 Unauthorized Command Message); an open-but-unconfirmed ICS port →
    FR5 Restricted Data Flow.
  - The professional report (HTML **and** PDF) now renders **two new dynamic
    coverage matrices** — "OWASP IoT Top 10 (2018) Coverage" and "OT / ICS
    Security Coverage (IEC 62443)" — shown only when the engagement actually
    produced device/industrial findings, and linked to the concrete findings
    that landed in each category. The per-finding detail (report + web UI) shows
    the correct framework row instead of a blank or wrong web-OWASP label.
  - IoT/OT findings are explicitly **excluded from the web OWASP Top 10 (2021)
    matrix** so a Modbus finding whose title contains "unauthenticated" can no
    longer be mis-bucketed into A01 — the enrichment layer no longer forces a
    web category onto a finding that carries an IoT/OT tag.

- **Real-world report parity — new detectors closing the gaps against
  professional pen-test/health-check deliverables.** A gap analysis against two
  real Cyphere engagement reports (an internal IT security health check and a
  black-box WordPress web-app test) surfaced high-signal findings HEAVEN wasn't
  producing; every one is now a genuine, read-only, confirmation-based check:
  - **CMS/WordPress hardening scanner** (`vulnscan/cms_scanner.py`, WEB/API scan
    modes): flags an **admin panel exposed to the Internet** (`/wp-login.php`,
    `/wp-admin`), an enabled **XML-RPC** endpoint (HIGH when it advertises the
    SSRF/DoS-abused `pingback.ping`, confirmed by a read-only `system.listMethods`
    — never an actual pingback), **WordPress version disclosure**, and **username
    enumeration** (`/wp-json/wp/v2/users`, `?author=`). Fingerprint-gated, so it
    no-ops on non-WordPress sites.
  - **Server software-version banner exposure** (misconfig scanner): flags
    `Server: nginx/1.22.1`, `X-Powered-By`, `X-AspNet-Version` etc. — only when a
    concrete version is present (a bare product token isn't flagged).
  - **Deeper network-service probes** (`recon/network_exposure.py`, all read-only):
    an **IPMI RAKP password-hash disclosure** probe (RMCP+/RAKP-2 hash dump,
    CVE-2013-4786) that upgrades a bare IPMI exposure to a proven HIGH; **SNMP
    GETBULK amplification** measurement (reflected-DDoS source); an active
    **anonymous-FTP login** test; and an **RDP Network Level Authentication (NLA)
    not-required** negotiation probe. Each fires only on a proven, attacker-
    favourable response — disabled under the stealthiest profiles.
  - **Unsupported / end-of-life software detector** (`vulnscan/eol_scanner.py`,
    CWE-1104): turns the discovered product/version/OS inventory into
    unsupported-software findings (Windows 10 22H2, Silverlight, Apache httpd 2.2,
    PHP < 8.1, OpenSSL < 3.0, …), version-gated against published vendor EOL dates
    and carrying the EOL date as proof.
  - Full CWE/OWASP/MITRE/CVSS taxonomy added for all new finding classes, so they
    enrich cleanly into reports; wired mode-aware into the orchestrator (CLI +
    web/API scan paths inherit them automatically).

- **New "Ascendant Aegis" brand identity — one mark, synced everywhere.** HEAVEN
  now has a proper logo: a faceted violet→cyan→emerald hexagonal aegis (the app's
  own `#6D7CFF → #22D3EE → #34E5A3` ramp) enclosing an "H" whose crossbar rises to
  a glowing apex node, its six vertices reading as a targeting reticle. It is
  single-sourced (`heaven-ui/src/components/Logo.jsx` for the app, a canonical
  `heaven-ui/public/heaven-mark.svg` for everything else) and carried consistently
  across every surface: the web UI sidebar and login screen, the browser favicon,
  the CLI startup banner — reframed as a gradient box that renders a genuine
  top-to-bottom violet→cyan→emerald ramp — the `heaven` command-centre dashboard,
  the HTML and PDF report cover pages, and the README. Report covers also adopt
  the HEAVEN indigo accent (`#4f46e5`) so client deliverables match the identity.
  The old ⚡ emoji placeholder is gone; the screenshots in `docs/` were regenerated
  against the new look.
- **Authenticated scanning from the web UI.** The scan launcher now has an
  optional "Authenticated scan" panel — supply the target's session cookie or a
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
  the crawler can't see by observing the target's own reaction — reflection and
  out-of-band length/status deltas, isolated with bucket binary-search. Every
  candidate is confirmed with a fresh canary **and** a control junk parameter, so
  a name that merely rides response jitter never survives. Discovered parameters
  are emitted as input vectors and fed to the injection/anomaly scanners, which
  find (and actively confirm) vulns behind inputs nothing linked to. WEB/API modes.
- **Multi-role Broken Access Control audit (OWASP A01).** A new `access_control`
  module replays privileged-session URLs as anonymous — and, when you supply a
  second `--low-priv-cookie-file` / `--low-priv-auth` session, as that lower role
  — and raises a finding only on a *proven differential*: the app protects a
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
  with a professional summary — a plain-English executive narrative, a full
  severity breakdown (critical→info), the distinct hosts engaged, the top findings
  (with live NVD CVE links), the actions taken, and prioritised recommendations —
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
- **Lateral movement — load discovered hosts.** A one-click button pre-fills the
  spray targets with each `host:port` the network scan discovered speaking
  SSH/SMB/RDP, so targets come from real findings instead of manual entry.
- **Cross-engagement knowledge graph now populates.** Every completed scan records
  its findings' outcomes (per target-profile technique success/failure) into the
  knowledge graph — previously nothing wrote to it, so it was permanently empty.

### Fixed

- **Test suite runs clean — zero warnings on Python 3.14.** The suite emitted
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
  `pyproject.toml` — HEAVEN never calls those deprecated APIs directly.
- **Dashboard network topology reads cleanly instead of a jittery tangle.** The
  3D host map placed nodes with `Math.random()` height and wired random
  criss-cross edges, so even a dozen hosts looked like a cluttered mess that
  re-shuffled on every render. Nodes now use a deterministic phyllotaxis
  (sunflower) spread — evenly spaced, never overlapping, stable across renders —
  linked by sparse nearest-neighbour edges, and shrink slightly as the count
  grows. Wide sweeps are capped to the top 24 hosts **ranked by severity** with a
  "top N of M · +K more" indicator, so a `/24` scan no longer floods the view.
- **Scan reports and the audit trail now honour the configured data directory.**
  The report writer hard-coded a current-directory-relative `data/` for
  `report_<id>.json`/`.sarif`, while the API's report-download endpoint reads them
  from `get_config().data_dir`. When `HEAVEN_DATA_DIR` was set — or the API server
  ran from a different working directory than the CLI scan — the writer and reader
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
  taxonomy from its type/title — and, failing that, at least a severity-based
  CVSS vector — so a real finding is never blank again. Positive/informational
  posture (e.g. "DNSSEC enabled") is intentionally left without a weakness CWE
  rather than mislabelled. Applied on read, so existing stored findings are fixed
  with no re-scan.
- **Scanning a network device (router / switch / firewall) produced "No findings
  recorded".** Network recon discovered the device's open ports but nothing turned
  its exposures into findings — the service-injection layer only handled SSH/SMB/
  RDP/DB and web ports. A new **network service exposure analyzer**
  (`recon/network_exposure.py`, wired as a mode-gated orchestrator task) now emits
  real findings for cleartext / legacy management protocols (Telnet, FTP,
  r-services, TFTP, Finger), SNMP exposure — with an active, strictly **read-only**
  default-community probe (`public`/`private`) that proves the weakness from a live
  `sysDescr.0` reply — and high-risk appliance planes (Cisco Smart Install,
  IPMI/BMC). A hardened host (only SSH + HTTPS) still yields zero findings, and the
  service-name matching is exact-token (never substring) so an unrelated service
  can't trip a false positive.
- **The Active Directory scan was shallow and usually skipped entirely.**
  `scan_active_directory` bailed out whenever a domain name wasn't supplied — so
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
  persisted as pseudo-findings — and because their `vuln_type` matches no
  knowledge-base entry, the detail view rendered every taxonomy field empty and
  confidence as 0.00. They are plans, not observations: they are now recognised
  as artifacts (`engagement.is_attack_plan_artifact`) and excluded from the
  findings list, the report/coverage/kill-chain views, and every headline count
  (dashboard chip, stats, per-scan counts) — no re-scan needed to clear the ones
  older scans already stored. Genuine findings enrich correctly (e.g. a missing
  CSP now shows CWE-693 · A05:2021 · T1185 · a full CVSS v3.1 vector).
- **Host & Service Inventory looked empty even after a productive scan.** The
  inventory defaulted to the *newest* scan that produced any host row — including
  a dead/mistyped-host scan that recorded a host with **zero** open ports — so an
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
    a typical /24 — burning the entire budget on empty air. HEAVEN now runs a
    fast **host-discovery sweep** first (nmap `-sn`, with a pure-Python
    TCP-connect fallback) and only deep-scans the hosts that actually answered. A
    single host or a small explicit list still skips discovery and is scanned
    directly with `-Pn` (the operator named it, so it's trusted).
  - **A too-tight deadline discarded everything.** The Network Recon task used a
    fixed 300 s timeout regardless of range size; when it elapsed, the task was
    hard-cancelled and returned **no data**, so every downstream scanner saw an
    empty result. The deadline now **scales with the size of the range** (capped
    at 30 min) and the scanner honours a time budget that returns whatever
    finished so far — partial results beat none. Live-proven: a `/27` CIDR whose
    only live host ran a weak web app went from *nothing* to 15 attributed
    findings (a critical CVE-2021-41773 on the host:port, reflected input,
    missing security headers), discovery correctly reporting "1/30 up".
- **Subnet scope now covers the hosts inside it.** Under an engagement,
  `is_in_scope()` matched targets by *exact string* only, so adding
  `192.168.1.0/24` to scope didn't authorize `192.168.1.55` (or the /24 scanned
  as individual IPs), and those targets were silently dropped. Scope is now
  **CIDR-aware**: a target contained by an in-scope range passes (including a
  URL whose host falls in the range). It only ever authorizes a target *inside*
  an authorized range — a range broader than what was scoped still fails, so
  scanning can never exceed authorization.
- **Internal / IP-only targets came back empty even when riddled with holes.**
  Two engine gaps meant scanning a bare IP (the normal case for an internal
  network) could report *nothing*, and both are fixed:
  - **nmap now runs with `-Pn`** (assume the authorized host is online). Windows
    boxes, firewalled hosts and hardened Linux routinely drop nmap's discovery
    ping, so without `-Pn` nmap declared them "down" and scanned **zero** ports —
    the exact "I know it's vulnerable but the scan found nothing" symptom.
    Liveness is now inferred from a real probe reason or an actually-responding
    port, so `-Pn` doesn't fake a dead address as alive.
  - **Open web ports on a bare-IP target now flow into the web scanners.** The
    crawler, injection (XSS/SQLi), auth, fuzzer, misconfig and exposure checks
    only ran against URLs; a bare IP had none, so a discovered HTTP(S) service
    was port-listed but never web-tested. After recon, HEAVEN now derives a URL
    from each open web port (`http(s)://host:port`), crawls it, and feeds it to
    the full web pipeline — deduped against URLs you already supplied, and only
    in modes whose pipeline includes web scanners (FULL/WEB/API). Live-proven:
    scanning a bare IP that hosts a weak web app went from a bare port list to
    28 findings (confirmed reflected XSS, missing security headers, a
    known-vulnerable Apache).
  - **Scan-privilege transparency.** When nmap runs without raw sockets it can't
    do SYN/UDP/OS scans (open ports are still found via TCP connect). HEAVEN now
    says so plainly in the scan summary and prints the **exact, platform-correct**
    one-time command to unlock full detection — macOS gets `sudo`/passwordless-sudo
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
  is now scoped to a single scan — the most recent by default — with a scan
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
  `gemini-1.5-pro`). All are now synced to the actual project — **1028 tests · 145
  modules · 50 CLI commands · 64 API routes · 24 UI pages**, with current model
  defaults (`claude-sonnet-5` / `gemini-flash-latest`) — and the previously
  undocumented **Assets** (Host & Service Inventory) page was added to the Web UI
  page table.
- **Web UI leaked internal implementation details in user-facing text.** Several
  descriptions read like developer notes: the Knowledge Graph exposed an on-disk
  path (`~/.heaven/knowledge.db`) and an internal record schema; the AI
  Attack-Chain Planner showed an internal architecture label ("Layer D") and a
  raw internal API response (`{"skipped": "LLM gateway unavailable"}`); two
  finding-detail buttons carried internal issue-tracker tags ("(Gap 4)",
  "(Gap 6)"). All were rewritten as professional, product-facing copy with no
  filesystem paths, internal identifiers, or raw response shapes — and the
  "unavailable" states now guide the user to add a provider key in Settings.
- **Host & Service Inventory was empty after scanning a URL target, in every
  mode.** Network reconnaissance only received bare IP targets, so a URL/hostname
  target (e.g. `https://app.example.com`) never reached nmap and the inventory
  came back empty — even on a FULL scan. Recon now scans the host parsed from
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
  credential reuse, and only stops when the playbook is genuinely exhausted —
  never repeating an action. Paired with the new executive report, a no-LLM run
  now does real work and reads professionally.
- **`heaven install-tools` couldn't auto-install Docker on macOS.** The catalog had
  no Homebrew formula for `docker`, so on macOS it was reported "manual" instead
  of installed. Added `brew install docker` (the CLI client HEAVEN shells out to),
  so all seven external tools now auto-install from the standard package manager.

- **Scan findings were inaccurate, CVEs were wrong/blank, and the stored results
  disagreed with the report.** Every CVE discovered on one host collapsed into a
  *single* finding — the finding identity (`_finding_hash`) keyed only on
  `(target, vuln_type, endpoint, param)`, which is identical for every
  `vulnerable_service` CVE on a host — so all but one CVE silently vanished and
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
  Apache — so any HTTP server (a plain Python `http.server`, a Uvicorn app)
  collected ~25 confident-looking Apache CVEs. A generic protocol label
  (`http`, `https`, `ssl`, …) now never drives a live search — only a concrete,
  identified product does — and the mapper passes the resolved product, not the
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
  server value. It stays monotonic and never shows a premature 100 — honest
  motion, not a fabricated animation.
- **The CVE column read as "blank/broken" on finding detail.** Configuration,
  policy and hygiene findings (DMARC/SPF, missing headers, weak TLS, …) have no
  CVE, so the bare "—" looked like a bug. The CVE cell now says *"— (not a
  CVE-class finding)"* for those classes and *"— (no CVE resolved)"* for a
  service finding with no match, while real CVE-tracked findings show their CVE.
- **The CVE Lookup form overflowed its card.** The Limit box spilled past the
  card edge and the "Look up CVEs" button sat awkwardly. The form's grid columns
  now shrink correctly (`minmax(0, …)`), the fields stack on narrow screens, and
  the button is spaced properly.

### Changed

- **A blank "active engagement" now resolves to your most-populated engagement,
  not `default`.** When no engagement is explicitly selected and no active
  pointer exists (e.g. the one you were viewing was deleted), the app — and the
  scan writer — now resolve to the on-disk engagement richest in real data
  instead of a blank `default` that silently absorbed scans. On startup the app
  also adopts that engagement as active, so it opens on your actual work.

- **The scan launcher now picks the destination engagement explicitly.** The
  free-text "engagement name" field is a dropdown of the engagements on disk
  (plus "＋ New engagement…"), defaulting to the one you're viewing and showing
  where findings will be saved — so a scan can't silently pile into a surprise
  or stale engagement.

### Added

- **Rename an engagement — CLI, API and dashboard.** An engagement's name was
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

- **Host & Service Inventory — open ports, service versions and OS, surfaced
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
    dropped), and OS detection records its **source and confidence** — an nmap
    `-O` stack fingerprint is labelled *(fingerprinted, N%)* while a TTL guess is
    labelled *(heuristic — unconfirmed)*. Nothing is fabricated: an
    undetermined OS is shown as such, and a guess is never presented as a fact.
  - **OS fingerprinting no longer silently needs root.** `nmap -O` (and SYN/UDP
    scans) require raw sockets and abort the whole scan if run unprivileged, so
    HEAVEN now auto-elevates via passwordless `sudo -n` when it's available
    (controllable with `HEAVEN_NMAP_SUDO=auto|always|never`; `-n` never prompts,
    so no credential is ever handled), and detects an elevated session on
    Windows. When it genuinely can't fingerprint, it no longer falls straight to
    a coarse TTL guess: it first infers the OS from nmap's own service-detection
    evidence (the `ostype` attribute and OS-level CPEs that `-sV` reports without
    root) — a real, more specific signal — still labelled *unconfirmed*, and logs
    a one-line hint on how to unlock authoritative results (run as root, enable
    passwordless sudo, or `setcap cap_net_raw` on nmap).
  - A shared `heaven/devsecops/inventory.py` is the single source of truth for
    normalization/labelling reused by the CLI, API, UI and reports;
    `tests/test_service_inventory.py` locks in the parsing, the no-false-positive
    OS labelling and the cross-surface rendering.

### Changed

- **Every scan mode now runs a real, focused pipeline — the mode selector is no
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
  probe errors now log at `debug` with `exc_info` — a scanner that hides an
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

### Fixed

- **Web UI is responsive again — the dashboard no longer overflows or overlaps
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
  full, above everything, on every page — and it opens on tap too, for touch
  devices with no hover.
- **"Generate AI remediation" no longer echoes back the same text.** With no LLM
  key configured the remediation engine returns the knowledge-base text, which
  the finding page then showed a second time under an "AI-tailored" heading — an
  identical duplicate. The page now shows the AI block only when the result is
  genuinely AI-generated *and* differs from the KB text; otherwise it shows a
  single, clear note that no LLM key is configured, with a link to Settings.
- **CVE Lookup explains an empty result instead of just going blank.** A lookup
  that returns nothing (usually NVD rate-limiting an unkeyed request — only ~5
  lookups per 30 s without an `NVD_API_KEY` — or an offline host, or a
  product/vendor that doesn't match NVD's CPE dictionary) now spells out those
  causes and links to Settings to add an NVD key, rather than showing a bare
  "no results" line that reads as broken.
- **Grammar: single-item counts.** The header and dashboard now read "1 target"
  / "1 finding" instead of "1 targets" / "1 findings".
- **Stealth level now genuinely changes scan behaviour at every setting — it was
  partly cosmetic.** The web launcher / CLI expose four levels (paranoid /
  stealth / normal / aggressive), but several scanners accepted `stealth_level`
  and then discarded it. The web crawler and the adaptive-intel profiler built a
  *bare* `EvasionProfile(stealth_level=…)` whose timing fields stay `0`, so the
  inter-request delay was a **no-op for every level** and the crawler's
  concurrency was hardcoded (100) instead of scaling with the profile; the web
  fuzzer collapsed all four levels into a stealthy/loud binary with a fixed
  `Semaphore(5)`; and the IDOR scanner varied concurrency but never applied a
  delay. Root cause was a footgun — `EvasionProfile(stealth_level=X)` only sets
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
  which returns only id/name/status/timestamps — **no `config_json`, no `mode`** —
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
  domains, then `RSET` — never `DATA`, so no mail is relayed).
- **IoT vendor-panel default-credential false positive.** The panel check
  attempted HTTP Basic auth and treated any `200` as "accepts default
  credentials" — so an **open, no-auth** panel was reported as a CRITICAL
  default-credential finding. It now only attempts (and claims) a default login
  when the panel actually issued a `401` Basic challenge and the credential
  clears it (`401`→`200` without a renewed challenge); open panels and
  form-login panels stay a fingerprint-only `info` finding. (Also replaced the
  deprecated `aiohttp.BasicAuth` with an explicit `Authorization` header.)
- **API-mode false positives (deep detector audit).** Three FP paths in the API
  scanner were closed: (1) the "API key leaked" check reported *any* `token=…` /
  `secret=…` string in a response as a **critical** leak — but a login/CSRF/session
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
  the bare reflected canary — an HTML-escaped header reflection is inert, so it now
  requires an *executable* reflection (matching the parameter-XSS gate). (2) POST
  time-based SQLi was asserted from a single slow response, so a naturally slow
  POST endpoint became a **critical** finding; it now uses the same
  baseline-plus-reproduce guard the GET path already had.
- **HTTP request-smuggling false positive (live sandbox E2E).** The web fuzzer
  baselined the smuggling probes with a **GET** but sent the ambiguous CL.TE /
  TE.TE requests as **POST**, so any server that answers POST differently from
  GET — a `404`/`405` on a GET-only route, i.e. almost every server — tripped the
  "smuggling indicator" on every path. The baseline is now a well-formed **POST**
  to the same URL, isolating the ambiguous framing as the only variable.
- **HSTS "max-age too short (0s)" on plain-HTTP ports.** The `no_hsts` branch was
  correctly gated on TLS actually working, but the `hsts_short_maxage` branch was
  not — so scanning any non-TLS port fired "HSTS max-age Too Short (0s)" from the
  default `max_age=0`. HSTS is a TLS-only control; the whole check now runs only
  when a TLS version negotiated.
- **Version-based CVE findings persisted as `vuln_type: "unknown"`.** The inline
  CVE-DB and NVD paths in the CVE mapper built findings without a `vuln_type`, so
  every version-matched CVE (e.g. an Apache banner → Optionsbleed) landed
  uncategorised — no KB taxonomy, blank type in reports. They now carry
  `vulnerable_service` (aliased to the `vulnerable_component` KB entry) like the
  live-feed path.
- **CLOUD bucket mis-attribution.** Bucket-name guessing derived candidates from
  RFC 2606 / 6761 reserved or non-distinctive registrable labels (`example`,
  `test`, `localhost`, …), so a scan of `example.com` matched the unrelated public
  `example-images` bucket and reported it as the target's **critical** exposed
  asset. Those reserved base names are now skipped — a coincidental generic-name
  match is no longer claimed as the target's bucket.

### Security

- **Closed an XXE in the SCA Maven parser** (CWE-611). `pom.xml` files come from
  the *scanned* project, which may be hostile — parsing them with stdlib
  `xml.etree.ElementTree` allowed external-entity / external-DTD attacks that
  could read local files off the analyst's host or drive SSRF. The Maven and
  nmap XML parsers now use `defusedxml`, and a regression test proves a
  malicious `pom.xml` cannot exfiltrate a local file. `defusedxml` is now a
  declared dependency.
- **Randomised the linPEAS post-ex staging path** (CWE-377). The privilege-
  escalation runner dropped `linpeas.sh` at a fixed `/tmp/linpeas.sh` on the
  target, then `chmod +x` and executed it — a TOCTOU/symlink opening on a
  multi-user target's world-writable `/tmp`. It now uses an unpredictable
  `/tmp/.heaven-<random>.sh` per run.
- **Clean bandit (SAST) baseline — findings _and_ log.** Reviewed and resolved
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
  (OSV.dev). Removed the **unused `mermaid`** dependency — it was never imported,
  and dropping it eliminated 13 advisories on its own (4 mermaid CVEs plus the
  transitive `dompurify` set and a high-severity `uuid` issue) and removed 113
  packages. Bumped `vite` 5→8, `@vitejs/plugin-react` 4→6 and `react-router-dom`
  6→7 to clear the remainder. `heaven sca` and `npm audit` now report **zero**
  vulnerable dependencies.
- **Hardened evasion/fuzzer randomness to a CSPRNG** (CWE-330). All timing
  jitter, User-Agent rotation, scan-order shuffling and canary generation in
  `recon/evasion_engine.py` and `vulnscan/web_fuzzer.py` now draw from
  `secrets.SystemRandom` instead of the default PRNG — unpredictable to IDS/WAF
  fingerprinting, and clearing HEAVEN's own `weak-random-for-crypto` SAST rule.

### Added

- **Per-section scan results in the web UI.** SAST and SCA runs now have their
  own result lists on the SAST and SCA pages (a "SAST scan history" / "SCA audit
  history" panel, same expandable-row + inline-findings view as the Scans page),
  instead of being merged into the general Scan Activity list where the same run
  showed up twice. Backed by a new `kind` filter on `GET /api/scans`
  (`pentest` — the default, excludes code-analysis runs — plus `sast`, `sca`,
  `all`). Reusable `ScanList` component (`heaven-ui/src/components/ScanList.jsx`)
  drives all three sections.
- **More scan modes in the launcher.** The Launch Scan mode dropdown now exposes
  every mode with a real scanner phase: FULL, WEB, NETWORK, API, CLOUD,
  CONTAINER, IOT, **OT**, AD and EMAIL (was only web/network/full/ad/cloud). Added
  `OT` (operational technology) to the `ScanMode` enum; it runs the same
  IoT/SCADA/OT scanner phase.
- **Dashboard quick-launch panel.** The dashboard now has a "Launch a scan" grid
  with a tile for every scan surface (Full, Web, Network, API, Cloud, Container,
  IoT, OT, AD, Email) plus the analysis tools (SAST, SCA, CVE) — each one click
  from the landing page. Scan-mode tiles deep-link into the launcher with the
  mode preselected (`/scans?mode=<mode>`); FULL is highlighted and appears once.
  Both the panel and the launcher `<select>` read from one shared source of truth
  (`heaven-ui/src/scanModes.js`), so they can never drift apart.

### Fixed

- **SAST/SCA findings now show up after a scan.** Running a SAST or SCA scan with
  an engagement name persisted the findings into that engagement's store but left
  the app pointed at whatever engagement was active before — so the Findings page
  and dashboard (which read the *active* engagement) showed nothing. These scans
  now activate the engagement they persist into, exactly like a pentest scan, so
  the run is immediately visible in triage. The header chip and dashboard refresh
  on completion.
- **Dashboard topology follows the selected engagement.** Switching the viewing
  engagement now updates the "hosts mapped" topology and stats immediately (the
  dashboard listens for the engagement-changed event, not just its poll). An
  engagement with no findings no longer falls back to some *other* engagement's
  latest report file — an empty engagement shows an empty topology instead of
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
  type error. It holds `Path` values — annotated correctly now; mypy is clean.
- **`scripts/uninstall.ps1` reported success as failure on Windows.** The
  uninstaller runs only PowerShell cmdlets (no native command), so in a fresh
  session `$LASTEXITCODE` stayed `$null`; a caller's `if ($LASTEXITCODE -ne 0)`
  read `$null -ne 0` as *true* and treated a clean uninstall as a failure (the
  native-Windows E2E job went red even though every step printed success). Both
  `install.ps1` and `uninstall.ps1` now `exit 0` explicitly on the success path
  (fatal errors already abort via `Die`/non-zero), so their exit codes are
  deterministic.

- **`heaven install-tools`** — one command installs the external scanner
  binaries HEAVEN shells out to (nmap, nuclei, sqlmap, ffuf, searchsploit,
  semgrep, docker) using the host package manager (brew / apt / dnf / pacman /
  **winget / choco / scoop**) or pip / go, so the scanner runs at full power.
  Idempotent, with `--dry-run` and per-tool selection. Driven by a single shared
  catalog (`heaven/utils/tool_installer.py`) that also powers `heaven doctor` and
  the web System-Health panel, so the tool list and install recipes never drift.
  Runs automatically as part of install (opt out with `HEAVEN_SKIP_TOOLS=1`).
- **Windows one-command install/uninstall** — `scripts/install.ps1` and
  `scripts/uninstall.ps1` mirror the macOS/Linux shell scripts (Python venv,
  full dependencies, external tools via winget/choco/scoop/pip/go, web UI build,
  generated `.env`), so HEAVEN now installs unattended on **macOS, Linux, and
  Windows** from a single command.
- **Delete engagements from the dashboard** — the "Viewing engagement" selector
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

### Changed

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

- **A phantom "default — empty" engagement appeared on its own and couldn't be
  removed.** Merely loading the dashboard opened the fallback `default`
  engagement for a *read*, and the store constructor eagerly created its SQLite
  file — so `data/engagements/default.db` was materialised on every page load and
  reappeared in the switcher no matter how many times it was deleted (and
  deleting *scans* never removed the engagement). `EngagementStore` now has a
  read-only mode (`create=False`) that serves a not-yet-scanned engagement from
  an ephemeral in-memory schema instead of writing a file; every dashboard read
  (summary, dashboard, findings, top-findings, scans, report/coverage/methodology
  exports) uses it via a new `_read_store()` helper. The engagement switcher no
  longer invents a phantom `default` row, and on startup an empty auto-created
  `default.db` (no scans, findings or scope) is pruned — a real `default`
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
- **Installer appearing to hang / getting stuck** during the external-tool step —
  see the install hardening under *Changed* above.
- **Windows installer could abort mid-run under two edge cases** (found by
  executing `install.ps1`/`uninstall.ps1` end-to-end, not just linting them):
  (1) `$env:Path.Split(';')` had no null-guard, so in any context where the
  process `Path` is unset it would throw and stop the install right after adding
  the PATH entry — now guarded like the adjacent user-PATH handling; (2) the web
  UI build ran under `ErrorActionPreference='Stop'`, so a broken/missing Node or
  npm could throw and abort the whole installer (losing `.env` creation and the
  smoke test) — the UI build is now wrapped in try/catch and is genuinely
  non-fatal, matching the script's stated "the CLI works fine without the UI"
  contract. Both `.ps1` scripts now pass PSScriptAnalyzer with zero findings and
  run install→uninstall to a clean exit. A new **`windows-install-e2e` CI job
  executes the full installer and uninstaller on real `windows-latest`** every
  push (native venv + pip install, `cmd /c npm` UI build, `.env`, smoke test,
  then uninstall with a data-preservation assertion) — so the Windows path is now
  gated by actual Windows execution, not just static analysis.

## [1.0.0] — 2026-07-08

### Added

- **In-house OAST collaborator (`heaven/vulnscan/oast.py`) — provable SSRF & XXE.**
  A pure-standard-library out-of-band listener binds locally and records target
  callbacks tagged with a per-probe token. SSRF and XXE are now *proven* (the
  target actually connects back) rather than guessed, with **no external
  dependency** — no Burp Collaborator, no interactsh, no third-party DNS. Bind a
  routable address via `HEAVEN_OAST_HOST` for remote engagements.
- **Dedicated misconfiguration & session-security scanner
  (`heaven/vulnscan/misconfig_scanner.py`).** Deterministic, confirmation-based
  checks wired into the main VULN_SCAN phase: CORS reflected-origin **with
  credentials**, insecure session cookies (HttpOnly/Secure/SameSite), missing
  security headers (host-scoped), canary-confirmed open redirect, and JWT
  weaknesses — `alg:none` acceptance plus HMAC **weak-secret cracking** (the
  recovered secret is the proof). A new `oob_scanner.py` drives SSRF/XXE through
  the collaborator. All classes are proven against the native vulnerable app.
- **Expanded in-house remediation knowledge base (`heaven/devsecops/vuln_kb.py`).**
  Added entries for XXE, CORS, insecure cookies, JWT (weak-secret + alg:none),
  command injection, file inclusion, path traversal, SSTI, CRLF, request
  smuggling and subdomain takeover, plus an alias map so every emitted
  `vuln_type` spelling resolves. `AIRemediationEngine`'s LLM-free fallback now
  returns a full, class-accurate write-up from the KB instead of a generic
  one-liner — **remediation is excellent with or without an API key**.
- **`heaven download-model`** — fetch the pre-trained 48 MB NVD CVSS model
  (R²≈0.99) from the GitHub Release, **SHA-256 verified**, instead of training
  it. The model isn't bundled in the wheel or committed to git, so `pip install`
  and `git clone` users previously fell back to heuristic CVSS; now one command
  enables the ML scores. The loader search path gained a user-cache location
  (`~/.cache/heaven/models/`) and a `HEAVEN_MODEL_PATH` override so the fetched
  model is found even in read-only site-packages installs. Fully tested offline
  (verify pass/fail, atomic install, idempotent re-run).
- **`heaven config test-llm`** — CLI parity with the web-UI Settings LLM check.
  A cheap check by default (provider/key/SDK present, no billed call) and a
  `--live` flag that sends one minimal completion through the *same gateway the
  AI layers use*, so you can confirm a key works end-to-end before a scan relies
  on it. Fully covered by tests.
- **Native benchmark now scores HEAVEN's full web surface, not just injection.**
  `tests/benchmarks/test_native_benchmark.py` drives the crawler + injection +
  misconfig + OAST out-of-band scanners against the labelled native target and
  scores **11 categories** — SQLi (error/blind/UNION), reflected XSS, command
  injection, LFI, **SSRF, XXE, CORS, open redirect, weak JWT, insecure cookie,
  missing security headers** — at **100% precision / 100% recall / 100% F1**
  (13/13 ground-truth entries, 15 findings, 0 false positives). The v1.0
  detectors are now proven by the always-on CI benchmark, and the numbers in
  `docs/BENCHMARK_RESULTS.md` / `docs/COMPARISON.md` reflect the expanded surface.

### Changed

- **Hostile-target resilience.** Every core-path orchestrator HTTP session now
  carries a per-request timeout ceiling, and the open-redirect check probes its
  candidate parameters concurrently (was sequential — it multiplied a slow
  target's latency ~20×). A new `tests/test_resilience.py` drives the live web
  detectors against slow / 500 / connection-drop / redirect-loop servers and
  asserts they finish fast, never crash, and emit no false findings.

### Fixed

- **ML risk scores never reached the web dashboard (always showed 0).** The ML
  scoring phase annotates findings with `predicted_cvss_score` / `priority_score`,
  but `EngagementStore.upsert_finding` persisted `finding.get("risk_score")` — a
  key nothing sets — so the DB `risk_score` column was `0.0` for every finding.
  The CLI/JSON report (in-memory) showed the real CVSS, but the web Command
  Centre (which reads the DB) reported `avg_risk: 0.0` and per-finding risk of 0.
  Persistence now falls back through the ML fields (`_risk_value`) and preserves
  the full ML detail (CVSS/priority/EPSS/KEV/band) in `evidence_json`. Verified
  live: the dashboard now shows the true risk. Regression tests in
  `tests/test_finding_precision.py`.
- **`confidence_bucket` was blank for every finding except FP-reviewed ones.**
  Only the FP-review path set the bucket, so the web UI / reports showed an empty
  confidence tier for most findings. `upsert_finding` now derives it from the
  confidence score (`_confidence_bucket` — same tiers as
  `fp_suppress._bucket_for`, floored at `tentative`) when the finding doesn't
  carry one. Verified live: 0 blank buckets after a full scan.
- **README test-count badge no longer goes stale.** The primary Tests badge is
  now a **live GitHub Actions status badge**, and the decorative counts are kept
  honest by `scripts/sync_test_count.py` (run it to sync; `--check` fails CI when
  stale — wired into `.github/workflows/ci.yml`).
- **Scanner precision — three false-positive classes found by a full live run.**
  (1) The Nuclei parser ingested wordlist/parameter-list helper templates as
  real findings — `top-xss-params` surfaced as a HIGH "Top 38 Parameters -
  Cross-Site Scripting" with empty `vuln_type`; these are now skipped and every
  Nuclei finding carries a concrete `vuln_type`. (2) A stray Python docstring
  (`http.cookies.Morsel.js_output()…`) leaked in as a finding with no type,
  evidence, or confidence; `dedup_findings` now drops such reportless noise via
  a conservative `_is_junk_finding` guard (no real finding is ever dropped —
  it requires *all* of empty-type, no-evidence, no-confidence). (3) Both
  request-smuggling detectors false-positived on ordinary servers — the CL.TE
  timing probe flagged any slow/hung origin as **critical**, and the web-fuzzer
  checks keyed off the *response* `Content-Length` (present on nearly every
  200). The CL.TE detector now requires a baseline timing differential and
  reports a `medium` "possible — verify manually" indicator instead of a
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
- **Version strings synced to `1.0.0`** across the project — the ML risk model's
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
  and no oracle formed — the exact reason authenticated recall against DVWA
  (which runs MySQL) collapsed. All error/boolean/time payload terminators are
  now MySQL-safe (`-- ` / `#`), which also comment correctly on Postgres, MSSQL
  and SQLite. Proven with a Docker-free negative control: blind-SQLi on the
  vulnerable `id` param is detected with the fix and undetected with a bare `--`
  (`heaven/vulnscan/injection_scanner.py`).
- **Command-injection false positives on reflective endpoints.** The output-based
  cmdi probe flagged any page whose body contained the echo marker
  (`; echo h3av3n7x7`) — but a page that merely *reflects* the payload text
  contains the marker without ever executing a shell. Surfaced by the new scored
  benchmark: cmdi false positives on the XSS/LFI/echo endpoints. The probe now
  strips the reflected payload (HTML-entity-decoded, covering escaped echoes)
  before matching, so the marker/`uid=` only counts as genuine command OUTPUT
  — the same reflection-resistant principle as the boolean-SQLi fix
  (`heaven/vulnscan/injection_scanner.py`).

### Added

- **UNION-based SQL injection detection** — the fourth classic SQLi technique
  (alongside error-based, boolean-blind and time-based). It sweeps the unknown
  column count, exfiltrates a unique marker via `UNION SELECT` in both string and
  numeric contexts, and confirms a hit only when the marker surfaces as rendered
  query OUTPUT — the reflected payload is stripped first, so an app that merely
  echoes the input can't trigger a false positive
  (`heaven/vulnscan/injection_scanner.py`, verified by the native benchmark).
- **Native, Docker-free web-injection benchmark (scored).** A tiny in-process
  Flask target (`tests/benchmarks/native/vuln_app.py`) faithfully reproduces
  DVWA's SQLi/LFI/cmdi/XSS endpoints — *including MySQL comment semantics* — so
  the real crawler and injection scanner are exercised end-to-end in ~1 s with no
  QEMU or Docker. Two always-on tests consume it: `test_native_sqli_recall.py`
  asserts HEAVEN detects error-based **and** blind SQLi, LFI, command injection
  and reflected XSS — each attributed to the correct parameter (`id`, not the
  `Submit` button) and with no SQLi/cmdi false positives on reflective/escaped
  endpoints; `test_native_benchmark.py` scores the same run through the existing
  precision/recall/F1 metrics layer against a labelled ground truth
  (`ground_truth/native.yaml`) and enforces floors (currently 100% precision,
  100% required recall, 100% F1). The crawler-vector → scan-target conversion was
  extracted from the orchestrator into a pure, unit-tested
  `build_injection_targets()` (single source of truth).

### Changed

- **Leaner dependency footprint for publication.** Removed eight declared
  packages that nothing in the codebase imports: `python-nmap` (HEAVEN shells
  out to the `nmap` *binary*), `python-whois`, `shodan` (Shodan recon uses
  plain HTTP), `mitreattack-python` / `stix2` / `taxii2-client` (ATT&CK mapping
  ships a bundled dataset + HTTP TAXII), `matplotlib`, and `lxml` (the crawler
  parses with the stdlib `html.parser`). Also moved the two heaviest guarded
  deps out of the base install into extras — `scapy` → `[recon]`, `boto3` →
  the new `[cloud-aws]` — so `pip install heaven-pentest` is much lighter and
  the AWS/scapy features still degrade gracefully. No feature was removed; the
  `[mitre]` extra is gone because it required no pip packages. All tests still
  pass, base dependency count trimmed to 28.
- **DVWA benchmark now scans authenticated by default.** The fixture logs into
  DVWA (CSRF token + `security=low` cookie) and hands the scan a `--cookie-file`
  so it exercises the real `/vulnerabilities/*` attack surface instead of only
  the public login page; the per-scan timeout default was raised to 900 s (the
  authenticated crawl does far more work). Closes the auto-login TODO in
  `tests/benchmarks/conftest.py`.

### Security

- **Column allowlist on the raw-SQL repositories.** `EngagementRepository`,
  `WebPathRepository`, `NotificationRepository` and `ReportRepository` build
  `INSERT`/`UPDATE` statements by interpolating column *names* from
  `kwargs.keys()` (values were always bound parameters). Added a per-table
  `_COLUMNS` allowlist enforced by `_reject_unknown_columns()` so a dict key can
  never smuggle SQL, even if raw request data were ever forwarded into
  `create`/`update` — defense-in-depth, not a known-exploitable path
  (`heaven/db/repository.py`).
- **Patched 5 dependency advisories flagged by `pip-audit`.** Bumped
  `cryptography` floor to `>=48.0.1` (48.0.0 had GHSA-537c-gmf6-5ccf; kept below
  49 for pyopenssl compatibility) and added a `msgpack>=1.2.1` transitive floor
  (GHSA-6v7p-g79w-8964, pulled in via `cachecontrol`). `starlette` and
  `pydantic-settings` were already pinned to their fixed floors; the local env
  had simply drifted. `pip-audit` now reports no known vulnerabilities
  (`requirements.txt`).

### Added — SBOM + AI remediation (wired from previously-dead code)

- **CycloneDX SBOM export.** `heaven sbom` and `GET /api/sbom` generate a
  CycloneDX 1.5 SBOM whose components are the services HEAVEN discovered
  (product/version/CPE per open port) and whose `vulnerabilities` section
  folds in CVE-bearing findings. A "SBOM (CycloneDX)" download was added to the
  web Reports page. The generator now consumes the real scanner asset shape
  (`{host, open_ports:[…]}`) — previously it expected a shape the scanner never
  produced, so it always emitted an empty SBOM (`heaven/devsecops/sbom.py`).
- **AI-assisted remediation.** `heaven remediate <finding-id>` and
  `POST /api/findings/{id}/remediation` generate remediation guidance via the
  configured LLM provider, falling back to the knowledge-base remediation when
  no key is set (`ai_generated` flags which path produced the text). A
  "Generate AI remediation" button was added to the finding detail page
  (`heaven/devsecops/ai_remediation.py`).

### Removed — dead code + documentation overclaims

- Deleted two orphaned modules with no callers: `recon/wireless_recon.py`
  (PCAP wireless parsing — needed operator-supplied captures, never wired into
  the scan flow) and `vulnscan/msf_client.py` (Metasploit RPC — required an
  external `msfrpcd` and an uninstalled optional dependency).
- Removed the corresponding README claims that had no backing code: "wireless"
  reconnaissance and the Metasploit integration row (which referenced a
  `--enable-exploitation` flag that did not exist).
- Refreshed the drifted project statistics (tests, modules, CLI-command count).

### Added — professional penetration-test report

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
  between sections, and a built-in **Print / Save as PDF** button — so the HTML
  doubles as a polished PDF with one click (`heaven/devsecops/compliance_report.py`).
- **One-click download + in-browser preview** on the web Reports page: a primary
  "Download report (HTML)", a "Preview in browser" (opens the deliverable in a new
  tab), and a direct "Download PDF". Other formats (Markdown/CSV/JSON/SARIF/Burp/
  Proxy-JSONL) remain as secondary data exports.

### Fixed
- **Report no longer breaks on scan-controlled content.** All finding fields
  (titles, targets, payloads, evidence) are HTML-escaped, so a payload like
  `<script>…</script>` renders as text instead of injecting markup into the
  deliverable.
- **PDF export was mis-wired and could download an empty file.** The API gated
  PDF export on `reportlab` but the generator actually used WeasyPrint, so with
  reportlab-but-not-WeasyPrint installed the API served a 0-byte `.pdf`. The PDF
  generator was rebuilt on **reportlab** (pure Python — no system libraries), so
  the API check and the generator now agree (`heaven/devsecops/pdf_report.py`).

### Changed — professional PDF report (reportlab)
- The PDF is now a full client deliverable matching the HTML report
  section-for-section: cover page, confidentiality notice, document control +
  revision history, a **real table of contents with page numbers**, executive
  summary (narrative + severity KPIs + distribution bar + key findings), scope &
  methodology, risk-rating methodology with SLAs, findings summary, detailed
  findings (metadata, description, impact, evidence/PoC, remediation, references),
  OWASP Top 10 coverage, remediation roadmap, and appendix — with a
  "CONFIDENTIAL … Page X of Y" footer on every page.
- The PDF and HTML reports now **share** the severity palette, OWASP mapping and
  knowledge-base enrichment, so a finding looks identical in both, and all text is
  escaped (long unbroken payloads wrap instead of overflowing the page).
- **Dependency reduced:** dropped WeasyPrint (which needs Pango/Cairo system
  libraries) from the `reports` extra and `requirements.txt`. PDF export now needs
  only `reportlab`; the HTML report needs nothing extra.

### Fixed — NVD CVE enrichment now returns real results

- **NVD lookups returned nothing.** The client queried NVD's `cpeName`
  parameter, which requires an *exact* CPE 2.3 name with a concrete version and
  answers **HTTP 404** for the wildcard-version CPEs HEAVEN generates from banner
  fingerprints — so CVE enrichment silently found zero results. Switched to
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

### Fixed — other external-integration bugs (same class as the NVD one)

- **`heaven update` never refreshed ExploitDB.** It looked up a
  `refresh_csv_mirror` that didn't exist and fell back to the lazy cache loader,
  which returns early when the file is already present — so on any existing
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

## [1.0.0] — 2026-06-09

### Added — onboarding & user-friendliness pass

- **Sample data in one step.** New `heaven demo` (CLI) and a **Load sample data**
  button on the dashboard seed a realistic example engagement (12 findings,
  critical→info, with evidence) into the same store the dashboard reads — so a
  fresh install shows a full Dashboard / Findings / Kill-chain / Reports
  instantly instead of an empty screen. Idempotent and fully offline
  (`heaven/demo.py`; `POST /api/demo/seed`).
- **System Health page (web UI)** — the browser equivalent of `heaven doctor`.
  Shows external tools (nmap/nuclei/sqlmap/ffuf/searchsploit/semgrep/docker)
  with install hints, which API keys/integrations are configured, Python-module
  health, and recommended next steps — so "is it broken or just missing a tool?"
  is answerable at a glance (`GET /api/system/health`; `doctor` now also probes
  ffuf + searchsploit).
- **Friendlier CLI.** Uncaught errors now render a one-line, actionable message
  (with a "re-run with `--debug`" hint) instead of a raw traceback. A new global
  `--quiet`/`-q` flag silences informational logs so output pipes cleanly — pair
  it with a command's `--format json` (e.g. `heaven --quiet findings --format
  json | jq …`) for scripting/CI.
- **Docs** — `docs/FAQ.md` (troubleshooting), `pipx install heaven-pentest` and
  `docker run` one-liners, and a "See it in 60 seconds" quickstart in the README.
- **One-click demo scan** — a "Run demo scan" button (Scans page) and
  `POST /api/demo/scan` animate the full loop (recon → crawl → injection →
  reporting) with live progress, then land the sample findings — so a new user
  experiences a real-feeling scan without a target or authorization.
- **Global `--json`** — a root flag that emits machine-readable JSON from the
  data commands (`findings`, `doctor`, `config list`, `demo`); implies `--quiet`
  so stdout is clean for `jq`/CI.
- **In-app help tooltips** — a reusable `HelpTip` (?) explains CVSS / EPSS /
  severity / confidence / risk score / kill-chain phases inline on the Dashboard
  and Kill Chain pages.
- **Light theme + mobile nav** — a header toggle switches light/dark (persisted
  to `localStorage`, applied before first paint), and the sidebar collapses to an
  off-canvas hamburger menu on narrow screens.
- **`heaven quickstart`** — one command takes a fresh clone to a populated
  dashboard: ensures `.env` (generating a strong admin password if missing),
  loads sample data, and prints the next step (`--serve` launches the UI too).
- **"Fix this first"** — a Dashboard card + `GET /api/engagement/top-findings`
  rank findings by risk score and show a one-line remediation for each, so the
  highest-impact next action is obvious; click through to the detail.
- **Guided scan launcher** — the Scans launcher now validates targets live
  (URL / IP / CIDR / host) with a valid/invalid count, disables Launch until
  there's a valid target, shows the engagement's current scope size, and adds
  inline help on Stealth + the authorization gate.
- **Executive summary** on the "Fix this first" card ("N critical · M high
  across K targets · top risk …").
- **Animated demo** — `docs/assets/demo.svg`, a lightweight terminal cast
  (`quickstart` → `serve` → dashboard) embedded at the top of the README's
  "See it in 60 seconds".

### Added — guided product tour

- A short, skippable **in-app tour** (`heaven-ui/src/components/Tour.jsx`) orients
  a first-time operator across Dashboard → Scans → Findings/Reports → Settings →
  System Health, ending with a one-click **Load sample data**. Auto-opens once
  per browser and is re-launchable anytime from the command palette
  ("Take the tour"). Token-styled, so it renders in light and dark.

### Fixed

- **Light theme: the sidebar was unreadable.** `.sidebar` and `.nav-item.active`
  were hardcoded dark (dark gradient + white active text) while nav labels use
  theme tokens that turn dark in light mode — i.e. dark-on-dark. Added light-mode
  overrides so the sidebar surface and active item flip correctly.
- **`--help` / `--version` printed a spurious error and exited non-zero.** The
  new friendly-error wrapper swallowed `click.exceptions.Exit` (raised by
  `--help`, `--version` and any `ctx.exit(0)`), tacking on a "✗ Exit: 0" notice
  and exiting 1. It now passes those through untouched. Regression test added.
- **Demo `risk_score` was on a 0–10 scale** while real findings use 0–100
  (`risk_model` caps at 100). Demo findings now use the same 0–100 scale so the
  dashboard / "Fix this first" numbers read consistently for sample and real data.

### Added — in-app API-key management (web UI + CLI, one source of truth)

- **Entering API keys no longer means hand-editing `.env`.** A new
  **Settings** page in the web UI (`/settings`) lists every configurable key —
  LLM (Gemini / Anthropic / OpenAI), NVD, Shodan, Slack/Teams webhook, Splunk &
  Elastic SIEM, Jira & Linear — grouped, each with a one-line description, a
  *“how to get it”* link, and a masked indicator of whether it's already set.
  Paste a value, click **Save**, and it's applied to the running server
  immediately *and* persisted — survives a restart, and the CLI picks it up too.
- **One catalog backs everything** (`heaven/settings_catalog.py`): the web
  Settings page, the new **`heaven config`** command (`list` / `get` / `set` /
  `unset`), and the `heaven init` wizard all read & write the **same `.env`**
  plus `os.environ`, so a key set on any surface is live everywhere. No more
  "I set it in the CLI but the web app didn't see it".
- New endpoints `GET/POST /api/settings` (+ `POST /api/settings/test-llm` for a
  no-cost "is my LLM key working?" check), gated by `config.modify`. Secrets are
  **never** returned in full — only a short masked preview. New
  `heaven/utils/env_file.unset_env_var()` cleanly removes a key.
- Tests: `tests/test_settings.py` (14 cases) covers masking, persistence,
  unset, unknown-key rejection, and the API surface.

### Changed — friendlier, leaner install (`install.sh`)

- **`install.sh` now creates `.env` for you** with a generated admin password on
  first run (`heaven init --non-interactive`), so the web UI / API work out of
  the box — no manual `export HEAVEN_ADMIN_PASSWORD`. It points you at the
  Settings page / `heaven config` for API keys.
- **Lean core by default, resilient extras.** It installs the lightweight core
  first (guaranteed) then attempts each optional feature pack
  (`recon` / `reports` / `mitre` / `scheduling` / `lateral` / `deploy`)
  *independently*, so one heavy dependency that needs system libraries can't
  abort the whole install. `HEAVEN_CORE_ONLY=1` skips extras entirely; LLM SDKs
  stay opt-in.

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

Initial public release of HEAVEN — autonomous penetration-testing
framework. See README.md for the full feature matrix.

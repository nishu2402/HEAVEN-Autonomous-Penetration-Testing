"""HEAVEN — the lab matrix: an honest ledger of what proves what.

The rule this file enforces is simple and load-bearing: *a scan mode only earns
its "10/10" when it is green against a real, reproducible vulnerable lab for its
domain, and its label promises exactly what it delivers — no more.* Rather than
leave that as a claim in a README, this module encodes it as data and a test
(``tests/test_lab_matrix.py``) checks it, so the moment a mode or an exploit
starts claiming a capability nothing proves, CI goes red.

Nothing here is aspirational. Each entry states the *actual* current status:

* ``GREEN``          — a reproducible lab (an in-repo compose file / native app,
                       or a documented external VM the benchmark drives) exercises
                       this mode's detectors end to end and scores recall live.
* ``PARTIAL``        — real detectors, unit-tested, and a lab covers *part* of the
                       surface; the rest is honestly still ``NEEDS_LAB``.
* ``NEEDS_LAB``      — the detectors exist and are unit-tested, but no reproducible
                       domain lab is wired yet, so live recall is unproven.
* ``NEEDS_HARDWARE`` — the mode's *full* promise needs hardware a network-reachable
                       scanner cannot have (an 802.11 radio in monitor mode). The
                       module is deliberately scoped to the reachable subset and
                       its label says so.
* ``NEEDS_AGENT``    — the active part needs an on-host / on-segment agent; the
                       network-reachable susceptibility check is the honest scope.

The ``NEEDS_HARDWARE`` / ``NEEDS_AGENT`` statuses are not failures — they are the
honest gate the rule demands. What the test forbids is a mode of that kind
quietly claiming ``GREEN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from heaven.config import ScanMode

# ── status vocabulary ───────────────────────────────────────────────────────
GREEN = "green"
PARTIAL = "partial"
NEEDS_LAB = "needs-lab"
NEEDS_HARDWARE = "needs-hardware"
NEEDS_AGENT = "needs-agent"

_STATUSES = {GREEN, PARTIAL, NEEDS_LAB, NEEDS_HARDWARE, NEEDS_AGENT}
# Statuses that assert a mode is *proven* against a live lab. A mode honestly
# gated behind missing hardware / an agent must never carry one of these.
_PROVEN = {GREEN, PARTIAL}

# ── lab kinds ───────────────────────────────────────────────────────────────
COMPOSE = "compose"    # an in-repo docker-compose stack (path is checked to exist)
NATIVE = "native"      # an in-repo native app the benchmark serves (path checked)
EXTERNAL = "external"  # a documented external VM the operator supplies + we score
NONE = "none"          # no lab artifact (only valid for NEEDS_* statuses)

_REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Lab:
    """One proving ground for a scan mode."""
    name: str
    kind: str
    status: str
    proves: str            # what a green run of this lab demonstrates
    note: str = ""         # honest caveat / what is still unproven
    artifact: str = ""     # repo-relative path (COMPOSE/NATIVE) — checked to exist
    target: str = ""       # how the lab is reached (URL / env var / host)

    def artifact_path(self) -> Path | None:
        return (_REPO_ROOT / self.artifact) if self.artifact else None


# ── the matrix ──────────────────────────────────────────────────────────────
# Real in-repo lab artifacts, cited once so the entries below stay consistent.
_DVWA = "tests/benchmarks/docker-compose.yml"
_NATIVE_WEB = "tests/benchmarks/native/vuln_app.py"
_NATIVE_API = "tests/benchmarks/native/api_app.py"
_MSF2_GT = "tests/benchmarks/ground_truth/msf2.yaml"
# Reproducible domain-lab compose stacks (real vulnerable services; each proved
# live by tests/benchmarks/test_domain_labs.py under HEAVEN_RUN_BENCHMARKS=1).
_LAB_CLOUD = "tests/benchmarks/labs/cloud-compose.yml"
_LAB_CONTAINER = "tests/benchmarks/labs/container-compose.yml"
_LAB_IOT = "tests/benchmarks/labs/iot-compose.yml"
_LAB_OT = "tests/benchmarks/labs/ot-compose.yml"
_LAB_DOS = "tests/benchmarks/labs/dos-compose.yml"
_LAB_SHELLSHOCK = "tests/benchmarks/labs/shellshock-compose.yml"
_LAB_LOCALSTACK = "tests/benchmarks/labs/localstack-compose.yml"
_LAB_CONPOT = "tests/benchmarks/labs/conpot-compose.yml"
_LAB_K3S = "tests/benchmarks/labs/k3s-compose.yml"
_LAB_SAMBA_DC = "tests/benchmarks/labs/samba-dc-compose.yml"
_LAB_POSTFIX = "tests/benchmarks/labs/postfix-relay-compose.yml"
_LAB_JUICESHOP = "tests/benchmarks/labs/juiceshop-compose.yml"
_LAB_VAMPI = "tests/benchmarks/labs/vampi-compose.yml"
_LAB_WEBSHELL = "tests/benchmarks/labs/webshell-compose.yml"
_LAB_CLOUD_SSRF = "tests/benchmarks/labs/cloud-ssrf-compose.yml"
_LAB_WIRELESS = "tests/benchmarks/labs/wireless-compose.yml"
_LAB_SMTP_VRFY = "tests/benchmarks/labs/smtp-vrfy-compose.yml"

LAB_MATRIX: dict[ScanMode, list[Lab]] = {
    ScanMode.FULL: [
        Lab("DVWA + Metasploitable-2 (aggregate)", EXTERNAL, GREEN,
            "FULL runs every phase; web recall is scored live against DVWA and "
            "service/network recall against Metasploitable-2.",
            note="Aggregate of the web + network labs below; cloud/AD/IoT/OT "
                 "phases within FULL inherit their own NEEDS_LAB status.",
            artifact=_DVWA),
    ],
    ScanMode.WEB: [
        Lab("DVWA (official ghcr.io/digininja/dvwa)", COMPOSE, GREEN,
            "OWASP web-app recall/precision (SQLi, cmdi->RCE, XSS, LFI, CSRF, "
            "auth, upload) scored live.",
            artifact=_DVWA, target="http://127.0.0.1:8080"),
        Lab("HEAVEN native vulnerable web app", NATIVE, GREEN,
            "Hermetic SQLi/recall regression that runs in CI without Docker.",
            artifact=_NATIVE_WEB),
        Lab("OWASP Juice Shop DOM-XSS (headless-browser execution proof)",
            COMPOSE, GREEN,
            "A real modern Angular SPA whose search route renders the `q` "
            "parameter into an innerHTML sink via bypassSecurityTrustHtml. "
            "HEAVEN's shipped XSS execution prover (exploit_proof.prove_finding, "
            "the orchestrator's exploit-proof entry) loads the injected route in "
            "headless Chromium and proves the DOM XSS by observing a dialog that "
            "carries a unique per-run token — real client-side JavaScript "
            "execution, which a mere reflection cannot fake. This complements the "
            "DVWA lab: DVWA proves server-reflected/stored XSS, Juice Shop proves "
            "a client-side DOM sink an HTTP-only scanner cannot see.",
            note="Needs the Playwright Chromium bundle (playwright install "
                 "chromium); without it the prover degrades honestly to a "
                 "detected candidate and the lab test skips. The SPA's "
                 "toolbar-hidden search box is supplied as the known injection "
                 "point — the JS crawler maps the app's routes but does not "
                 "auto-reveal that input — so the lab machine-checks the proof "
                 "(JavaScript actually running), not unassisted input discovery. "
                 "The gated live test is test_juiceshop_lab_proves_dom_xss in "
                 "tests/benchmarks/test_domain_labs.py.",
            artifact=_LAB_JUICESHOP, target="http://127.0.0.1:3000"),
    ],
    ScanMode.API: [
        Lab("HEAVEN native API app (OWASP API Top 10)", NATIVE, GREEN,
            "REST/GraphQL BOLA, BFLA, mass-assignment, injection recall scored "
            "live in CI, no external service.",
            artifact=_NATIVE_API),
        Lab("VAmPI (real third-party OWASP API Top 10)", COMPOSE, GREEN,
            "Spec-driven discovery proves the API scan against an external app: "
            "HEAVEN reads VAmPI's published OpenAPI contract, then confirms live "
            "the /users/v1/_debug password leak (excessive_data_exposure, "
            "API3:2023), the unauthenticated /users/v1 collection (broken_auth, "
            "API2), and the public spec (API9).",
            note="Complements the native fixture with a target HEAVEN did not "
                 "author. The test calls VAmPI's own /createdb seed route, then "
                 "scans read-only; the container binds to loopback.",
            artifact=_LAB_VAMPI, target="127.0.0.1:5001"),
    ],
    ScanMode.NETWORK: [
        Lab("Metasploitable-2", EXTERNAL, GREEN,
            "Host/service recall: backdoors, RCE service CVEs, default creds, "
            "cleartext protocols, EOL software, scored against a real MSF2 VM.",
            note="VM not bundled; operator supplies an authorised target via "
                 "HEAVEN_MSF2_TARGET. Ground truth is in-repo.",
            artifact=_MSF2_GT, target="HEAVEN_MSF2_TARGET"),
    ],
    ScanMode.EXPLOIT: [
        # In-repo reproducible lab: Shellshock proves a real reverse-callback RCE
        # end to end against unpatched bash 4.3 built from source (no external VM).
        Lab("Shellshock (CVE-2014-6271) from-source lab", COMPOSE, GREEN,
            "Real remote command execution proven live: HEAVEN's exploit_shellshock "
            "injects the `() { :; };` header payload with a benign reverse-callback "
            "command and the vulnerable bash CGI connects back with root output "
            "(uid=0) — the eighth of eight corpus exploits, now live.",
            note="The container reaches HEAVEN's callback listener on the host via "
                 "host.docker.internal (the HEAVEN_CALLBACK_HOST override, the same "
                 "knob a real NAT/redirector engagement uses).",
            artifact=_LAB_SHELLSHOCK, target="http://127.0.0.1:8092"),
        Lab("Metasploitable-2 (service RCEs)", EXTERNAL, PARTIAL,
            "7 of the 8 corpus exploits (ingreslock, vsftpd 2.3.4, UnrealIRCd, "
            "distcc, Samba usermap, SSH/Telnet weak creds) prove live against "
            "MSF2 with a benign proof command; the eighth (Shellshock) is proven "
            "by the in-repo from-source lab above.",
            note="VM not bundled; operator supplies an authorised target via "
                 "HEAVEN_MSF2_TARGET. Ground truth is in-repo.",
            artifact=_MSF2_GT, target="HEAVEN_MSF2_TARGET"),
    ],
    ScanMode.AD: [
        Lab("Samba Active Directory DC (from-scratch provision)", COMPOSE, GREEN,
            "A real Samba AD Domain Controller (realm HEAVEN.LOCAL) speaking "
            "genuine Kerberos/LDAP/SMB is provisioned from scratch, and two AD "
            "probes are proven live against it: kerberos_preauth_probe "
            "enumerates seeded accounts credential-free (KDC_ERR_PREAUTH_REQUIRED "
            "vs C_PRINCIPAL_UNKNOWN) -> kerberos_user_enumeration, and "
            "coercion_surface_probe binds (only) the MS-RPRN spoolss pipe over an "
            "authenticated SMB session -> ntlm_coercion.",
            note="The lab also live-guards the AS-REP-roasting false-positive fix "
                 "(protected accounts must NOT be reported roastable against "
                 "Samba's KDC). ADCS ESC1-8 template classification is thoroughly "
                 "unit-tested (tests/test_adcs_scanner.py: ESC1-4 + ESC8 with the "
                 "real template-attribute + security-descriptor shapes, plus "
                 "negative controls for manager-approval / RA-signature / "
                 "disabled / server-auth-only). A *live* ESC proof is honestly "
                 "environment-gated, not merely unfinished: AD CS is a "
                 "Windows-only role (MS-ICPR certificate enrolment), which Samba "
                 "does not implement and no Linux/Docker CA provides, so proving "
                 "it end to end needs a Windows Enterprise CA + Certipy — the "
                 "same class of honest gate as Wireless RF.",
            artifact=_LAB_SAMBA_DC,
            target="127.0.0.1:88 (Kerberos) + :445 (SMB) + :389 (LDAP)"),
    ],
    ScanMode.EMAIL: [
        Lab("Postfix open-relay lab (deliberate misconfig)", COMPOSE, GREEN,
            "A genuine Postfix MTA misconfigured as an open relay (mynetworks = "
            "0.0.0.0/0, so permit_mynetworks matches every client before any "
            "reject) accepts MAIL FROM + RCPT TO for two unrelated external "
            "domains with no authentication. HEAVEN's non-intrusive probe detects "
            "smtp_open_relay live on the raw endpoint (RSET before DATA — no mail "
            "is ever relayed), plus smtp_no_starttls on the same cleartext box.",
            note="VRFY user-enum is not demonstrable on Postfix (it answers VRFY "
                 "with 252 / cannot-verify, disclosing nothing, so the "
                 "differential probe correctly stays silent — a true negative). "
                 "That surface is proved live by the VRFY lab below; DNS-based "
                 "posture by the entry after it.",
            artifact=_LAB_POSTFIX, target="127.0.0.1:2525 (SMTP)"),
        Lab("VRFY user-enumeration lab (real aiosmtpd MTA)", COMPOSE, GREEN,
            "The SMTP user-enumeration differential is proved live against a real "
            "SMTP server (aiosmtpd, a real independent stack) with VRFY left "
            "enabled: it answers 250 for a user that exists in its real "
            "local-user set and 550 for one that does not — the classic "
            "sendmail-style account-enumeration misconfiguration. HEAVEN's "
            "non-intrusive probe (VRFY postmaster vs VRFY <random>) detects "
            "smtp_user_enumeration live.",
            note="The 250/550 differential is driven purely by real user "
                 "existence; the server never inspects whether the probe is "
                 "HEAVEN's. Complements the Postfix lab, which correctly proves "
                 "the opposite (252 -> true negative). Gated live test: "
                 "test_smtp_vrfy_lab_detects_user_enumeration.",
            artifact=_LAB_SMTP_VRFY, target="127.0.0.1:2526 (SMTP)"),
        Lab("Live public mail domains (DNS-only)", EXTERNAL, PARTIAL,
            "SPF/DKIM/DMARC/DNSSEC/MTA-STS/TLS-RPT/BIMI posture validated live, "
            "DNS-only, against real domains; DKIM key strength is a real DER "
            "decode.",
            note="DNS posture needs real public domains, so it stays EXTERNAL; "
                 "the open-relay lab above now covers the SMTP surface "
                 "reproducibly.",
            artifact="", target="engagement mail domains"),
    ],
    ScanMode.CLOUD: [
        Lab("MinIO public-bucket lab (S3-compatible)", COMPOSE, GREEN,
            "A world-readable, listable object-storage bucket is detected live: "
            "MinIO serves the real S3 API, an anonymous listing returns a real "
            "<ListBucketResult>, and the scanner reports a critical "
            "exposed_storage_bucket via its S3-endpoint override.",
            note="Proves the public-bucket detector end to end against a real "
                 "S3-compatible store (MinIO/Ceph/LocalStack pattern). The "
                 "metadata-SSRF path is now proved live by the lab below.",
            artifact=_LAB_CLOUD,
            target="http://127.0.0.1:9000 (HEAVEN_S3_ENDPOINT)"),
        Lab("Instance-metadata SSRF lab (link-local IMDS)", COMPOSE, GREEN,
            "HEAVEN's cloud metadata-SSRF detection is proved live: a "
            "deliberately SSRF-vulnerable web app (/fetch?url=) sits on a Docker "
            "network whose subnet is the link-local metadata range, with a fake "
            "EC2 IMDS pinned to the canonical 169.254.169.254. validate_ssrf "
            "injects the AWS metadata endpoints, the app fetches them "
            "server-side, and the instance-metadata response CONFIRMS the SSRF "
            "(probe_url 169.254.169.254/latest/meta-data/). The IMDS returns only "
            "an inert AKIA...EXAMPLE placeholder.",
            note="This lab drove out and now guards a real bug: the 12 "
                 "localhost-obfuscation SSRF variants filled the entire probe "
                 "budget, so the cloud-metadata endpoints were never actually "
                 "sent (a silent false negative on credential-exfil SSRF). The "
                 "high-signal metadata/scheme probes now run first. Gated live "
                 "test: test_cloud_ssrf_lab_reaches_instance_metadata; offline "
                 "regression: tests/test_ssrf_metadata_probe.py.",
            artifact=_LAB_CLOUD_SSRF, target="http://127.0.0.1:8095/fetch"),
        Lab("LocalStack IAM privilege-escalation lab", COMPOSE, GREEN,
            "The authenticated IAM audit is proven live against a real "
            "AWS-compatible IAM (LocalStack): a non-admin user whose scoped "
            "policy permits a privilege-escalation primitive "
            "(iam:CreatePolicyVersion) is flagged with a "
            "cloud_iam_privilege_escalation finding via the audit's "
            "--endpoint / HEAVEN_AWS_ENDPOINT override.",
            note="Validates the privesc detector (19 AWS escalation primitives, "
                 "deny-wins evaluation) end to end. A seeded multi-account "
                 "PassRole-chain lab is future work.",
            artifact=_LAB_LOCALSTACK, target="http://127.0.0.1:4566"),
    ],
    ScanMode.CONTAINER: [
        Lab("Docker-in-Docker API + open registry lab", COMPOSE, GREEN,
            "An unauthenticated remote Docker API (an isolated nested dockerd on "
            ":2375, no TLS) and an anonymous Docker Registry v2 (:5000) are "
            "detected live: GET /version -> docker_api_exposed (critical) and "
            "GET /v2/_catalog -> registry_exposed (high).",
            note="The exposed daemon is the dind container's OWN nested daemon, "
                 "isolated from the host. The Kubernetes API / secrets path is "
                 "proved live by the k3s lab below; the kubelet / etcd / cAdvisor "
                 "detectors share the same code path and are unit-tested.",
            artifact=_LAB_CONTAINER, target="http://127.0.0.1:2375 + :5000"),
        Lab("Kubernetes cluster (real k3s) with anonymous API", COMPOSE, GREEN,
            "A genuine k3s control plane (real kube-apiserver / etcd / scheduler) "
            "is started with anonymous auth enabled and cluster-admin bound to "
            "system:anonymous (both real, common misconfigurations). HEAVEN's "
            "KubernetesScanner.check_api_server reads the live apiserver on :6443 "
            "with no credentials -> k8s_anon_auth (critical) and "
            "k8s_secrets_exposed (critical).",
            note="Proves the Kubernetes anonymous-access + secrets-exposure "
                 "detectors against a real apiserver, not a unit-test double, and "
                 "now also the RBAC over-privilege analysis: the admin kubeconfig "
                 "is pulled from the k3s container and analyze_rbac flags the "
                 "cluster-admin-to-system:anonymous binding as critical live "
                 "(while never tripping on the legitimate system:masters group). "
                 "That drove a real detector fix — the old analyzer only counted "
                 "ServiceAccount admins above a threshold, so an anonymous/"
                 "all-users cluster-admin binding was missed entirely "
                 "(tests/test_k8s_rbac_assessment.py locks the FP-safe rule). "
                 "Pinned to a multi-arch k3s release so it runs natively on Apple "
                 "Silicon.",
            artifact=_LAB_K3S, target="https://127.0.0.1:6443"),
    ],
    ScanMode.IOT: [
        Lab("Mosquitto (anon MQTT) + Modbus + MediaMTX RTSP lab", COMPOSE, GREEN,
            "Real IoT services detected live via protocol-correct handshakes: an "
            "anonymous MQTT broker (CONNACK code 0 -> critical), an "
            "unauthenticated Modbus/TCP endpoint (Read-Device-Identification -> "
            "critical), and a real MediaMTX RTSP server (DESCRIBE -> RTSP/1.0, "
            "the exposed IP-camera/streaming surface). Scored vs OWASP IoT Top "
            "10 / IEC 62443.",
            note="MQTT + Modbus + RTSP are proven live (three real TCP "
                 "services). The remaining probes (SNMP/CoAP/BACnet/SSDP) are "
                 "UDP and share the same read-only harness; they stay "
                 "unit-tested because Docker Desktop for Mac's userspace UDP NAT "
                 "drops the reflected datagram (the same platform limit the DoS "
                 "amplification vector documents), so a published-port UDP "
                 "handshake cannot complete on that host. Broader device breadth "
                 "is future work.",
            artifact=_LAB_IOT,
            target="127.0.0.1:1883 (MQTT) + :502 (Modbus) + :554 (RTSP)"),
    ],
    ScanMode.OT: [
        Lab("Unauthenticated Modbus/TCP + OPC-UA ICS lab", COMPOSE, GREEN,
            "Two real, unauthenticated ICS services detected live via "
            "protocol-correct handshakes: a pymodbus Modbus/TCP server on port "
            "502 (Read-Device-Identification -> critical 'Modbus TCP ICS service "
            "reachable') and a real asyncua OPC-UA server on port 4840 (the "
            "OPC-UA Connection Protocol HEL -> ACK handshake -> 'OPC-UA ICS "
            "service reachable'). Mapped to IEC 62443 / MITRE ATT&CK for ICS.",
            note="Modbus (the most widely deployed ICS protocol) and OPC-UA (the "
                 "modern ICS interoperability standard) are proved live here; "
                 "Siemens S7comm is proved live by the Conpot lab below — three "
                 "real OT protocols in total. DNP3 + IEC-104 share the same "
                 "read-only handshake harness and stay unit-tested (no clean "
                 "pure-Python outstation to run reproducibly; a real simulator is "
                 "future breadth), and EtherNet/IP is UDP, which Docker Desktop "
                 "for Mac's UDP NAT does not forward on this host.",
            artifact=_LAB_OT, target="127.0.0.1:502 (Modbus) + :4840 (OPC-UA)"),
        Lab("Conpot ICS honeypot (S7comm + Modbus)", COMPOSE, GREEN,
            "A real Conpot ICS/SCADA honeypot answers genuine Siemens S7comm "
            "(ISO-COTP connection confirm) and Modbus/TCP on their standard ports; "
            "HEAVEN's OT scanner detects both live -> 'Siemens S7comm' (high) and "
            "'Modbus TCP' (critical), validating the probe_s7comm handshake "
            "against a service that actually speaks the protocol.",
            note="Broadens the OT proof beyond Modbus to a second real ICS "
                 "protocol (S7comm). DNP3/IEC-104/OPC-UA remain unit-tested; a "
                 "wider ICS-protocol lab is future breadth.",
            artifact=_LAB_CONPOT, target="127.0.0.1:102 (S7comm) + :502 (Modbus)"),
    ],
    ScanMode.DEVSECOPS: [
        Lab("OWASP Benchmark v1.2 (Java SAST corpus)", EXTERNAL, GREEN,
            "HEAVEN's own Semgrep-based Java rules (11 CWE classes: cmdi, sqli, "
            "path traversal, LDAP/XPath injection, XSS, trust-boundary, weak "
            "randomness, weak hash, weak crypto, insecure cookie) score the "
            "standard OWASP Benchmark v1.2 (2740 real Java test cases) live via "
            "the shipped SAST engine: pooled Youden index (TPR-FPR) ~0.52, "
            "recall ~0.97, precision ~0.70, with weak-randomness, weak-crypto "
            "and insecure-cookie at a perfect 1.00 and every injection class "
            "detecting all of its real vulnerabilities. Every finding is matched "
            "against the corpus's own expectedresults ground truth by CWE.",
            note="The corpus is GPLv2, so it is fetched (a pinned shallow clone, "
                 "or HEAVEN_OWASP_BENCHMARK_DIR) rather than vendored into this "
                 "MIT tree, and its ground truth is read from the checkout. The "
                 "residual gap is structural, not a rules deficiency: the false "
                 "positives are the Benchmark's deliberately adversarial 'safe' "
                 "cases (a tainted value discarded behind an always-true "
                 "arithmetic ternary, a switch on a constant char, or a "
                 "key-insensitive collection overwrite / reflection hop) that a "
                 "rule engine cannot constant-fold, and the config-driven hash "
                 "cases (weak algorithm named in a .properties file, read at "
                 "runtime) are honest false negatives. Closing either would mean "
                 "matching the Benchmark's own synthetic constructs, which we do "
                 "not do. The "
                 "scorer + gated live test are tests/benchmarks/"
                 "owasp_benchmark.py and test_owasp_benchmark.py.",
            target="pinned BenchmarkJava clone / HEAVEN_OWASP_BENCHMARK_DIR"),
        Lab("Multi-ecosystem vulnerable-dependency corpus + OSV.dev (SCA, live)",
            EXTERNAL, GREEN,
            "Dependency SCA is now corpus-scored, live: the in-repo corpus "
            "tests/benchmarks/labs/sca-corpus/ pins seven real known-vulnerable "
            "PyPI + npm releases, and HEAVEN's scan_path audits them against "
            "OSV.dev. Recall over a curated set of permanent CVE advisories is "
            "100% (11/11), and a precision control passes — the patched half of "
            "the corpus (the versions that FIXED each CVE) reports none of those "
            "CVEs, proving HEAVEN honours OSV's fixed ranges and never flags a "
            "resolved dependency.",
            note="The corpus is inert manifest text (nothing is installed) and "
                 "the ground truth (ground_truth/sca.yaml) was live-confirmed "
                 "against OSV before being pinned. The scorer + gated live test "
                 "are tests/benchmarks/sca_benchmark.py and test_sca_benchmark.py "
                 "(HEAVEN_RUN_BENCHMARKS=1; skips offline).",
            artifact="tests/benchmarks/labs/sca-corpus",
            target="sca-corpus + OSV.dev"),
    ],
    ScanMode.CI: [
        Lab("OWASP Benchmark v1.2 (Java SAST corpus)", EXTERNAL, GREEN,
            "The same SAST engine and Java rules scored against the OWASP "
            "Benchmark under DEVSECOPS, exercised through the CI export path "
            "(SARIF / JUnit). Pooled Youden ~0.52, recall ~0.97 live.",
            note="See DEVSECOPS for the full scorecard and caveats, including "
                 "the live SCA vulnerable-dependency corpus (recall 11/11 vs "
                 "OSV.dev) that the CI export path carries alongside SAST.",
            target="pinned BenchmarkJava clone / HEAVEN_OWASP_BENCHMARK_DIR"),
    ],
    # ── hardware/agent-gated modes: the reachable subset can be proven live,
    #    but each MUST keep an explicit NEEDS_HARDWARE / NEEDS_AGENT entry naming
    #    the part that genuinely needs a radio / on-segment agent (the gate is
    #    never hidden — see validate() rule 3). RF / active capture is never
    #    simulated. ────────────────────────────────────────────────────────────
    ScanMode.WIRELESS: [
        Lab("Exposed WLAN admin panel (posture review)", COMPOSE, GREEN,
            "The network-reachable half of WIRELESS is proven live: a real nginx "
            "server hosts an unauthenticated MikroTik RouterOS 'webfig' "
            "management page (an inert decoy carrying the genuine vendor "
            "fingerprint), and scan_wireless_posture fetches it, fingerprints the "
            "vendor, and reports 'Unauthenticated wireless management interface: "
            "MikroTik RouterOS' (high). This is exactly what the mode's label — "
            "'Wireless Posture Review' — promises.",
            note="Vendor-fingerprinted, read-only. The gated live test is "
                 "test_wireless_lab_detects_exposed_panel in "
                 "tests/benchmarks/test_domain_labs.py.",
            artifact=_LAB_WIRELESS, target="http://127.0.0.1:8080/"),
        Lab("RF / 802.11 monitor-mode capture", EXTERNAL, NEEDS_HARDWARE,
            "The RF half: 802.11 sniffing, WPA-handshake capture/cracking and "
            "SSID enumeration.",
            note="These need a local monitor-mode radio a network-reachable "
                 "scanner cannot have, so this half stays honestly gated and is "
                 "never simulated. The mode is labelled 'Wireless Posture "
                 "Review', not 'Wireless RF', precisely so the label matches "
                 "capability.",
            target="local 802.11 radio"),
    ],
    ScanMode.DOS: [
        Lab("Slow-HTTP + memcached-amplification susceptibility lab", COMPOSE,
            PARTIAL,
            "Slow-HTTP (Slowloris) susceptibility is proved live: a "
            "single-threaded server with no header-read timeout holds one "
            "incomplete request header open ~8s -> slow_http_dos (CWE-400). "
            "One benign probe per vector; deliberately never floods.",
            note="The lab also runs memcached with UDP enabled "
                 "(CVE-2018-1000115); its amplification is detected live on a "
                 "native-Linux Docker host, but Docker Desktop for Mac's "
                 "userspace UDP NAT drops the reflected datagram, so the "
                 "amplification vector is asserted best-effort. The label "
                 "promises susceptibility assessment, not a flood.",
            artifact=_LAB_DOS, target="127.0.0.1:8091 (HTTP) + :11211/udp"),
    ],
    ScanMode.SNIFF: [
        Lab("Name-poisoning / MITM susceptibility (on-segment)", EXTERNAL,
            NEEDS_AGENT,
            "Enumerates LLMNR/NBT-NS/mDNS/WPAD/mitm6 susceptibility and "
            "cleartext-credential exposure with one benign name query per "
            "protocol.",
            note="Actively capturing hashes / poisoning responses needs an "
                 "on-segment agent (Responder-class) on the target L2 segment; "
                 "the network-reachable susceptibility check is the honest scope "
                 "and the label says 'susceptibility'. A reproducible live lab is "
                 "additionally blocked on this host because LLMNR/NBT-NS/mDNS are "
                 "UDP multicast/broadcast, which Docker Desktop for Mac's "
                 "userspace UDP NAT does not forward (the same platform limit the "
                 "DoS amplification and IoT/OT UDP probes document) — so it stays "
                 "honestly NEEDS_AGENT and is never simulated.",
            target="local segment"),
    ],
    ScanMode.MALWARE: [
        Lab("Webshell sweep (seeded webroot lab)", COMPOSE, GREEN,
            "The read-only webshell sweep is proven live against a real HTTP "
            "server: an nginx webroot is seeded with INERT webshell-signature "
            "decoys (no PHP interpreter — nothing executes) and HEAVEN's "
            "scan_malware_targets GETs the known shell paths and flags every one "
            "via BOTH detection paths — the named-shell response signatures "
            "(c99/r57/b374k/WSO/IndoXploit/Alfa) and the generic YARA path "
            "(PHP_Webshell_Eval_Superglobal on a banner-less China-Chopper "
            "one-liner), the latter previously unit-tested only.",
            note="Read-only threat detection, not endpoint AV: the decoys carry "
                 "the fingerprint but have zero offensive capability (the EICAR "
                 "approach). The gated live test is "
                 "test_webshell_lab_detects_dropped_shells in "
                 "tests/benchmarks/test_domain_labs.py.",
            artifact=_LAB_WEBSHELL, target="http://127.0.0.1:8093"),
        Lab("Metasploitable-2 backdoor listeners", EXTERNAL, PARTIAL,
            "Known-backdoor listener ports/banners detect live against MSF2 "
            "(ingreslock 1524, the vsftpd 2.3.4 :6200 shell, etc.) and "
            "trojaned-service banners are matched on the raw banner grab.",
            note="Read-only threat detection, not endpoint AV. VM not bundled; "
                 "operator supplies an authorised target via HEAVEN_MSF2_TARGET.",
            artifact=_MSF2_GT, target="HEAVEN_MSF2_TARGET"),
    ],
}

# ── per-exploit ledger: every corpus exploit names the lab that proves it ────
# The exploit_id keys are validated against the live registry by the test, so a
# new exploit with no lab, or a stale entry naming a removed exploit, fails CI.
EXPLOIT_LABS: dict[str, str] = {
    "ingreslock_backdoor": "Metasploitable-2 (:1524 root bind shell)",
    "vsftpd_234_backdoor": "Metasploitable-2 (vsftpd 2.3.4, CVE-2011-2523)",
    "unrealircd_backdoor": "Metasploitable-2 (UnrealIRCd, CVE-2010-2075)",
    "ssh_weak_credentials": "Metasploitable-2 (msfadmin/msfadmin on :22)",
    "telnet_weak_credentials": "Metasploitable-2 (msfadmin on :23)",
    "distccd_exec": "Metasploitable-2 (distccd, CVE-2004-2687)",
    "samba_usermap_script": "Metasploitable-2 (Samba usermap, CVE-2007-2447)",
    # Live: proven end to end against an in-repo from-source lab (unpatched bash
    # 4.3 behind a busybox CGI) — a real reverse-callback RCE returning root.
    "shellshock_cgi": "In-repo from-source lab (unpatched bash 4.3 CGI, "
                      "tests/benchmarks/labs/shellshock-compose.yml)",
}


# ── accessors + validation ──────────────────────────────────────────────────
def mode_labs(mode: ScanMode) -> list[Lab]:
    return LAB_MATRIX.get(mode, [])


def mode_status(mode: ScanMode) -> str:
    """The strongest status any lab gives this mode (GREEN beats PARTIAL ...)."""
    order = [GREEN, PARTIAL, NEEDS_LAB, NEEDS_AGENT, NEEDS_HARDWARE]
    labs = mode_labs(mode)
    if not labs:
        return NEEDS_LAB
    return min((lab.status for lab in labs),
               key=lambda s: order.index(s) if s in order else len(order))


@dataclass
class MatrixIssue:
    where: str
    problem: str


def validate() -> list[MatrixIssue]:
    """Return every honesty/consistency violation in the matrix (empty == ok).

    This is the machine-checkable form of the rule. The test asserts it is
    empty; calling it directly (``heaven labs --check``) gives an operator the
    same guarantee.
    """
    issues: list[MatrixIssue] = []

    # 1. Every scan mode is documented.
    for mode in ScanMode:
        if mode not in LAB_MATRIX or not LAB_MATRIX[mode]:
            issues.append(MatrixIssue(mode.value, "no lab entry for this mode"))

    # 2. Each lab is internally consistent + honest.
    for mode, labs in LAB_MATRIX.items():
        for lab in labs:
            if lab.status not in _STATUSES:
                issues.append(MatrixIssue(
                    f"{mode.value}/{lab.name}",
                    f"unknown status {lab.status!r}"))
            # A proven status must be backed by a real artifact OR an external
            # lab with a stated target — never a bare NONE kind.
            if lab.status in _PROVEN and lab.kind == NONE:
                issues.append(MatrixIssue(
                    f"{mode.value}/{lab.name}",
                    "claims a proven status but has no lab artifact"))
            # In-repo artifacts (compose/native) must actually exist on disk, so
            # a GREEN claim can never point at a lab that was moved or deleted.
            if lab.kind in (COMPOSE, NATIVE):
                p = lab.artifact_path()
                if not lab.artifact or p is None or not p.exists():
                    issues.append(MatrixIssue(
                        f"{mode.value}/{lab.name}",
                        f"artifact missing on disk: {lab.artifact!r}"))
            # A NEEDS_* status must carry a note explaining the gap.
            if lab.status not in _PROVEN and not lab.note:
                issues.append(MatrixIssue(
                    f"{mode.value}/{lab.name}",
                    "gated status without an explanatory note"))

    # 3. The hardware/agent-gated modes may prove their network-reachable subset
    #    live, but the gate must NEVER be hidden: each MUST retain at least one
    #    NEEDS_HARDWARE / NEEDS_AGENT entry naming the part that genuinely needs a
    #    radio / on-segment agent. This is the honest core of the rule — the
    #    RF / active-capture result is never simulated to manufacture a green.
    _GATE_STATUS = {ScanMode.WIRELESS: NEEDS_HARDWARE, ScanMode.SNIFF: NEEDS_AGENT}
    for mode, required_gate in _GATE_STATUS.items():
        labs = mode_labs(mode)
        if not any(lab.status == required_gate for lab in labs):
            issues.append(MatrixIssue(
                mode.value,
                f"hardware/agent-gated mode must keep an explicit "
                f"{required_gate!r} entry for the part it cannot reach "
                f"(the gate must never be hidden behind a proven subset)"))

    # 4. Exploit ledger lines up with the live corpus exactly.
    try:
        from heaven.vulnscan.exploit_engine import list_exploits
        corpus = {e["exploit_id"] for e in list_exploits()}
    except Exception as e:  # pragma: no cover - import guard
        issues.append(MatrixIssue("EXPLOIT_LABS", f"cannot load corpus: {e}"))
        corpus = set()
    for eid in corpus:
        if eid not in EXPLOIT_LABS:
            issues.append(MatrixIssue(
                "EXPLOIT_LABS", f"corpus exploit {eid!r} has no proving lab"))
    for eid in EXPLOIT_LABS:
        if corpus and eid not in corpus:
            issues.append(MatrixIssue(
                "EXPLOIT_LABS", f"ledger names unknown exploit {eid!r}"))

    return issues


def matrix_rows() -> list[dict]:
    """Flat, serialisable view for the CLI / UI / reports."""
    rows: list[dict] = []
    for mode in ScanMode:
        for lab in mode_labs(mode):
            rows.append({
                "mode": mode.value,
                "lab": lab.name,
                "kind": lab.kind,
                "status": lab.status,
                "proves": lab.proves,
                "note": lab.note,
                "artifact": lab.artifact,
                "target": lab.target,
            })
    return rows


# Summary counts for a quick health read.
def status_summary() -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _STATUSES}
    for mode in ScanMode:
        counts[mode_status(mode)] = counts.get(mode_status(mode), 0) + 1
    return counts


__all__ = [
    "Lab", "LAB_MATRIX", "EXPLOIT_LABS", "MatrixIssue",
    "GREEN", "PARTIAL", "NEEDS_LAB", "NEEDS_HARDWARE", "NEEDS_AGENT",
    "COMPOSE", "NATIVE", "EXTERNAL", "NONE",
    "mode_labs", "mode_status", "validate", "matrix_rows", "status_summary",
]

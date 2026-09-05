"""Live domain-lab benchmarks: prove cloud / container / IoT / OT / DoS recall.

Each test brings up a small ``docker compose`` stack of GENUINELY-vulnerable
services (real MinIO, real Docker-in-Docker + registry, real Mosquitto + a real
pymodbus server, a real slow-HTTP-susceptible server + memcached) and runs the
actual HEAVEN scanner for that domain against it, asserting the expected finding
fires. Nothing is mocked and no result is simulated — this is the machine-checked
form of the honesty rule: a mode is only GREEN in ``heaven/labs.py`` because a
run like this detects the real thing live.

Gated by ``HEAVEN_RUN_BENCHMARKS=1`` + Docker (see conftest ``collect_ignore``);
the default ``pytest`` run never pulls an image or starts a container.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.benchmarks.labs.harness import (
    LabStack,
    http_body,
    http_status,
    skip_reason,
    wait_until,
)


def _skip_if_unavailable() -> None:
    reason = skip_reason()
    if reason:
        pytest.skip(reason)


# ── container: exposed Docker API + open registry ────────────────────────────
def test_container_lab_detects_docker_api_and_registry():
    _skip_if_unavailable()
    from heaven.recon.container_scanner import scan_containers

    with LabStack("container-compose.yml"):
        ready = wait_until(
            lambda: http_status("http://127.0.0.1:2375/version") == 200
            and http_status("http://127.0.0.1:5000/v2/_catalog") == 200,
            timeout_s=120.0)
        assert ready, "container lab (dind API + registry) never became reachable"

        res = asyncio.run(scan_containers(["127.0.0.1"]))
        types = {f["vuln_type"] for f in res["findings"]}
        assert "docker_api_exposed" in types, f"no docker_api_exposed in {types}"
        assert "registry_exposed" in types, f"no registry_exposed in {types}"


# ── cloud: public, listable S3-compatible bucket ─────────────────────────────
def test_cloud_lab_detects_public_bucket():
    _skip_if_unavailable()
    from heaven.vulnscan.cloud_scanner import CloudStorageScanner

    with LabStack("cloud-compose.yml"):
        # The bucket is ready once anonymous listing returns the S3 XML root.
        ready = wait_until(
            lambda: "<ListBucketResult" in http_body(
                "http://127.0.0.1:9000/heaven-public/"),
            timeout_s=120.0)
        assert ready, "cloud lab (MinIO public bucket) never became listable"

        scanner = CloudStorageScanner(endpoint_url="http://127.0.0.1:9000")
        res = asyncio.run(scanner.scan(
            "127.0.0.1:9000", extra_names=["heaven-public"], limit=60))
        findings = res.to_findings()
        opens = [f for f in findings
                 if f["vuln_type"] == "exposed_storage_bucket"]
        assert opens, f"no exposed_storage_bucket detected; got {[f['vuln_type'] for f in findings]}"
        assert any(f["evidence"]["bucket"] == "heaven-public" for f in opens)


# ── iot: anonymous MQTT + unauthenticated Modbus ─────────────────────────────
def test_iot_lab_detects_mqtt_and_modbus():
    _skip_if_unavailable()
    from heaven.recon.iot_scanner import (
        probe_modbus, probe_mqtt, probe_rtsp, scan_iot_targets)

    with LabStack("iot-compose.yml", build=True):
        # Ready only when the protocol handshakes actually succeed (not merely
        # when the TCP port accepts) — the pymodbus server needs a moment after
        # the port opens before it answers a Read-Device-Identification request.
        ready = wait_until(
            lambda: asyncio.run(probe_mqtt("127.0.0.1", 1883, 4.0)) is not None
            and asyncio.run(probe_modbus("127.0.0.1", 502, 4.0)) is not None
            and asyncio.run(probe_rtsp("127.0.0.1", 554, 4.0)) is not None,
            timeout_s=120.0)
        assert ready, "iot lab (mqtt + modbus + rtsp) handshakes never confirmed"

        res = asyncio.run(scan_iot_targets(["127.0.0.1"]))
        fs = res["findings"]
        assert any(f["protocol"] == "MQTT" and f["severity"] == "critical"
                   for f in fs), "no critical anonymous-MQTT finding"
        assert any(f["protocol"] == "Modbus TCP" and f["severity"] == "critical"
                   for f in fs), "no critical unauthenticated-Modbus finding"
        # RTSP: a real MediaMTX server answers DESCRIBE with RTSP/1.0, so the
        # camera/streaming surface is confirmed live (broadens IoT beyond
        # MQTT+Modbus). Any RTSP finding proves the probe fired against a real
        # RTSP service.
        assert any(f["protocol"] == "RTSP" for f in fs), (
            f"no RTSP finding; got {[f['protocol'] for f in fs]}")


# ── ot: Modbus reachable as an ICS service ───────────────────────────────────
def test_ot_lab_detects_modbus_and_opcua_ics():
    _skip_if_unavailable()
    from heaven.recon.iot_scanner import probe_modbus, probe_opcua, scan_ot_targets

    with LabStack("ot-compose.yml", build=True):
        ready = wait_until(
            lambda: asyncio.run(probe_modbus("127.0.0.1", 502, 4.0)) is not None
            and asyncio.run(probe_opcua("127.0.0.1", 4840, 5.0)) is not None,
            timeout_s=120.0)
        assert ready, "ot lab (modbus + opc-ua) handshakes never confirmed"

        res = asyncio.run(scan_ot_targets(["127.0.0.1"]))
        fs = res["findings"]
        assert any(f["protocol"] == "Modbus TCP" and f["severity"] == "critical"
                   for f in fs), "no critical Modbus-ICS finding"
        # OPC-UA: a real asyncua server completes the HEL->ACK handshake, so the
        # modern-ICS interoperability surface is confirmed live (a third real OT
        # protocol alongside Modbus + S7comm).
        assert any(f["protocol"] == "OPC-UA" and f["severity"] != "info"
                   for f in fs), (
            f"no confirmed OPC-UA ICS finding; got "
            f"{[(f['protocol'], f['severity']) for f in fs]}")


# ── dos: slow-HTTP (Slowloris) susceptibility, + best-effort amplification ────
def test_dos_lab_detects_slow_http():
    _skip_if_unavailable()
    from heaven.vulnscan.dos_probe import scan_dos_targets

    with LabStack("dos-compose.yml"):
        ready = wait_until(
            lambda: http_status("http://127.0.0.1:8091/") == 200,
            timeout_s=90.0)
        assert ready, "dos lab (slow-http server) never became reachable"

        res = asyncio.run(scan_dos_targets(
            targets=["127.0.0.1"], urls=["http://127.0.0.1:8091"]))
        types = {f["vuln_type"] for f in res["findings"]}
        # slow-HTTP susceptibility is proven on every platform.
        assert "slow_http_dos" in types, f"no slow_http_dos in {types}"
        # UDP amplification (memcached) also fires on a native-Linux Docker host;
        # Docker Desktop for Mac's userspace UDP NAT drops the reflected datagram,
        # so it is asserted best-effort rather than required.
        if "dos_amplification" in types:
            amp = [f for f in res["findings"]
                   if f["vuln_type"] == "dos_amplification"]
            assert all(f["evidence"]["amplification_factor"] > 1.0 for f in amp)


# ── exploit: Shellshock (CVE-2014-6271) real RCE via reverse callback ─────────
def test_shellshock_lab_proves_rce():
    """Compile-from-source unpatched bash 4.3 behind a busybox CGI, then prove a
    genuine reverse-callback RCE end to end — the eighth (last) live exploit in
    HEAVEN's corpus. The container reaches HEAVEN's callback listener on the host
    via host.docker.internal (set through the HEAVEN_CALLBACK_HOST override, the
    same knob a real NAT/redirector engagement uses)."""
    _skip_if_unavailable()
    import os
    from heaven.vulnscan.exploit_engine import exploit_shellshock

    with LabStack("shellshock-compose.yml", build=True):
        # First bring-up compiles bash from the GNU tarball, so allow headroom;
        # the compose up --build already blocked on the build, this just waits
        # for httpd to answer.
        ready = wait_until(
            lambda: http_status("http://127.0.0.1:8092/cgi-bin/test") == 200,
            timeout_s=300.0)
        assert ready, "shellshock lab CGI never became reachable"

        prev = os.environ.get("HEAVEN_CALLBACK_HOST")
        os.environ["HEAVEN_CALLBACK_HOST"] = "host.docker.internal"
        try:
            out = asyncio.run(exploit_shellshock("127.0.0.1", 8092, "id"))
        finally:
            if prev is None:
                os.environ.pop("HEAVEN_CALLBACK_HOST", None)
            else:
                os.environ["HEAVEN_CALLBACK_HOST"] = prev

        assert out.proved, f"shellshock RCE not proved: {out.error}"
        # The callback carried the real command output — root on the target.
        assert "uid=" in (out.proof_output or ""), out.proof_output
        assert out.cve == "CVE-2014-6271"
        assert out.severity == "critical"


# ── cloud: IAM privilege-escalation detected live against LocalStack ──────────
def test_localstack_lab_detects_iam_privesc():
    """Seed a non-admin IAM user whose scoped policy still permits a privilege-
    escalation primitive (iam:CreatePolicyVersion) on a real AWS-compatible IAM
    (LocalStack), then prove HEAVEN's authenticated audit detects the escalation
    path live — the detector validated against a real IAM, not a fake client."""
    _skip_if_unavailable()
    import os

    import boto3

    from heaven.recon.cloud_iam import audit_aws_iam

    ep = "http://127.0.0.1:4566"
    with LabStack("localstack-compose.yml"):
        ready = wait_until(
            lambda: '"iam": "available"' in (
                http_body(ep + "/_localstack/health") or ""),
            timeout_s=180.0)
        assert ready, "localstack IAM never became available"

        admin = boto3.client(
            "iam", endpoint_url=ep, region_name="us-east-1",
            aws_access_key_id="test", aws_secret_access_key="test")
        admin.create_user(UserName="devops")
        doc = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
               '"Action":["iam:CreatePolicyVersion","iam:ListPolicies"],'
               '"Resource":"*"}]}')
        arn = admin.create_policy(
            PolicyName="DevOpsScoped", PolicyDocument=doc)["Policy"]["Arn"]
        admin.attach_user_policy(UserName="devops", PolicyArn=arn)
        key = admin.create_access_key(UserName="devops")["AccessKey"]

        prev = {k: os.environ.get(k) for k in (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION")}
        os.environ.update(AWS_ACCESS_KEY_ID=key["AccessKeyId"],
                          AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"],
                          AWS_DEFAULT_REGION="us-east-1")
        try:
            res = audit_aws_iam(endpoint_url=ep)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        assert res["authenticated"], res.get("skipped_reason")
        techniques = {f.get("privesc_technique") for f in res["findings"]
                      if f["vuln_type"] == "cloud_iam_privilege_escalation"}
        assert "CreatePolicyVersion" in techniques, res["findings"]


# ── ot/iot: Siemens S7comm (+ Modbus) live against a Conpot ICS honeypot ──────
def test_conpot_lab_detects_s7comm_and_modbus():
    """Broaden the OT/IoT proof beyond Modbus + MQTT: a real Conpot ICS honeypot
    answers genuine S7comm (ISO-COTP) and Modbus, and HEAVEN's OT scanner detects
    both live — validating the probe_s7comm handshake against a service that
    actually speaks the protocol, not a unit-test double."""
    _skip_if_unavailable()
    from heaven.recon.iot_scanner import probe_modbus, probe_s7comm, scan_ot_targets

    def _protocols_warm() -> bool:
        # Conpot runs under qemu emulation here, so it warms slowly; poll the
        # actual protocol handshakes (COTP confirm for S7, a Modbus reply) rather
        # than a bare TCP accept.
        try:
            s7 = asyncio.run(probe_s7comm("127.0.0.1", 102, timeout=6.0))
            mb = asyncio.run(probe_modbus("127.0.0.1", 502, timeout=6.0))
        except Exception:
            return False
        return bool(s7 and s7.get("cotp_confirmed")) and bool(mb)

    with LabStack("conpot-compose.yml"):
        ready = wait_until(_protocols_warm, timeout_s=180.0, interval_s=4.0)
        assert ready, "conpot S7comm/Modbus never answered their protocol handshake"

        res = asyncio.run(scan_ot_targets(["127.0.0.1"]))
        protocols = {f["protocol"] for f in res["findings"]}
        assert "Siemens S7comm" in protocols, res["findings"]
        assert "Modbus TCP" in protocols, res["findings"]


# ── container: anonymous Kubernetes API detected live against a real k3s ──────
def _anon_k8s_api_open() -> bool:
    """True once an anonymous GET /api/v1/namespaces on the k3s apiserver returns
    200 — i.e. the control plane is up AND the anonymous cluster-admin manifest
    has been auto-applied."""
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
                "https://127.0.0.1:6443/api/v1/namespaces",
                timeout=4.0, context=ctx) as r:
            return r.status == 200
    except Exception:
        return False


def test_k3s_lab_detects_anonymous_k8s_api():
    """Broaden CONTAINER mode beyond the Docker-API/registry lab to a real
    Kubernetes control plane: a genuine k3s cluster is started with anonymous
    auth enabled and cluster-admin bound to system:anonymous (both real, common
    misconfigurations). HEAVEN's KubernetesScanner.check_api_server then reads
    the live kube-apiserver on :6443 with NO credentials — proving the k8s
    anonymous-access + secrets-exposure detectors against a real apiserver, not
    a unit-test double."""
    _skip_if_unavailable()
    from heaven.recon.container_scanner import KubernetesScanner

    with LabStack("k3s-compose.yml"):
        # k3s must boot the whole control plane and apply its auto-deploy
        # manifest; readiness = an anonymous namespace listing actually returns
        # 200, which only happens once both are done.
        ready = wait_until(_anon_k8s_api_open, timeout_s=240.0, interval_s=4.0)
        assert ready, "k3s anonymous API access never became reachable"

        findings = asyncio.run(
            KubernetesScanner.check_api_server("127.0.0.1", 6443))
        types = {f.vuln_type for f in findings}
        assert "k8s_anon_auth" in types, f"no k8s_anon_auth in {types}"
        # cluster-admin for system:anonymous also exposes every cluster Secret.
        assert "k8s_secrets_exposed" in types, f"no k8s_secrets_exposed in {types}"

        # RBAC over-privilege analysis, live: pull the admin kubeconfig out of the
        # k3s container and run analyze_rbac against the real apiserver. The lab's
        # binding grants cluster-admin to system:anonymous + system:unauthenticated
        # (a User + a Group), so the corrected detector must flag it CRITICAL while
        # never tripping on the legitimate system:masters binding k3s ships with.
        import subprocess
        import tempfile
        raw = subprocess.run(
            ["docker", "exec", "heaven-lab-k3s",
             "cat", "/etc/rancher/k3s/k3s.yaml"],
            capture_output=True, text=True, timeout=30)
        assert raw.returncode == 0 and "clusters:" in raw.stdout, raw.stderr
        with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False) as kc:
            kc.write(raw.stdout)
            kubeconfig = kc.name
        try:
            rbac = asyncio.run(KubernetesScanner.analyze_rbac(kubeconfig))
        finally:
            import os
            os.unlink(kubeconfig)
        crit = [f for f in rbac if f.vuln_type == "k8s_rbac_overprivileged"
                and f.severity == "critical"]
        assert crit, f"analyze_rbac missed the anonymous cluster-admin: {rbac}"
        assert "anonymous" in crit[0].description or "authenticated" in crit[0].description


# ── email: open SMTP relay detected live against a real Postfix MTA ───────────
def _smtp_banner_ok(host: str, port: int) -> bool:
    """True once the SMTP server answers with a 220 greeting — Postfix's smtpd is
    spawned on demand, so this confirms it actually starts and answers."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=4.0) as s:
            s.settimeout(4.0)
            return s.recv(64).startswith(b"220")
    except Exception:
        return False


def test_postfix_lab_detects_open_relay():
    """Prove the EMAIL-mode SMTP probe against a real Postfix MTA that is
    deliberately configured as an open relay (mynetworks = 0.0.0.0/0, so
    permit_mynetworks matches every client before any reject). HEAVEN connects to
    the raw endpoint with NO MX lookup and detects smtp_open_relay live: the
    server accepts MAIL FROM + RCPT TO for two unrelated external domains. The
    probe is non-intrusive — it sends RSET before DATA, so no mail is relayed."""
    _skip_if_unavailable()
    from heaven.recon.email_scanner import scan_smtp_endpoint

    with LabStack("postfix-relay-compose.yml", build=True):
        ready = wait_until(
            lambda: _smtp_banner_ok("127.0.0.1", 2525),
            timeout_s=120.0)
        assert ready, "postfix relay lab never answered a 220 SMTP greeting"

        res = asyncio.run(scan_smtp_endpoint("127.0.0.1", 2525))
        types = {f["vuln_type"] for f in res["findings"]}
        assert "smtp_open_relay" in types, f"no smtp_open_relay in {types}"
        relay = next(f for f in res["findings"]
                     if f["vuln_type"] == "smtp_open_relay")
        assert relay["severity"] == "critical", relay
        # The external->external RCPT was accepted (2xx), which is the relay.
        assert relay["evidence"]["rcpt_to"].startswith("2"), relay["evidence"]
        # STARTTLS is off on this box, so cleartext is also reported.
        assert "smtp_no_starttls" in types, f"no smtp_no_starttls in {types}"
        # Postfix answers VRFY with 252 (cannot verify), which discloses nothing,
        # so the user-enumeration differential must correctly stay silent.
        assert "smtp_user_enumeration" not in types, res["findings"]


# ── email: VRFY user-enumeration live against a real VRFY-enabled MTA ─────────
def test_smtp_vrfy_lab_detects_user_enumeration():
    """Complete the EMAIL surface: the Postfix lab proves open-relay + no-STARTTLS
    but answers VRFY with 252 (a true negative). This lab runs a real aiosmtpd
    server with VRFY enabled against a genuine local-user set — 250 for a user
    that exists, 550 for one that doesn't — the classic sendmail-style account
    enumeration. HEAVEN's non-intrusive VRFY differential (postmaster vs a random
    name) detects smtp_user_enumeration live. The server's behaviour is driven by
    real user existence, never by inspecting HEAVEN's probe."""
    _skip_if_unavailable()
    from heaven.recon.email_scanner import scan_smtp_endpoint

    with LabStack("smtp-vrfy-compose.yml", build=True):
        ready = wait_until(lambda: _smtp_banner_ok("127.0.0.1", 2526),
                           timeout_s=90.0)
        assert ready, "smtp-vrfy lab never answered a 220 greeting"

        res = asyncio.run(scan_smtp_endpoint("127.0.0.1", 2526))
        enum = [f for f in res.get("findings", [])
                if f["vuln_type"] == "smtp_user_enumeration"]
        assert enum, f"VRFY user-enum not detected; got " \
                     f"{[f['vuln_type'] for f in res.get('findings', [])]}"
        ev = enum[0]["evidence"]
        assert ev["valid_vrfy"].startswith("250"), ev
        assert ev["invalid_vrfy"][:3] in ("550", "551", "553"), ev


# ── ad: Kerberos enumeration + NTLM coercion live against a Samba AD DC ───────
def test_samba_dc_lab_detects_kerberos_enum_and_coercion():
    """Prove the AD-mode probes against a real Samba Active Directory DC (realm
    HEAVEN.LOCAL) that speaks genuine Kerberos, LDAP and SMB/RPC:

    * kerberos_preauth_probe enumerates seeded accounts credential-free (the KDC
      returns distinct errors for existing vs absent users) and must NOT emit
      asrep_roasting — Samba's KDC does not honour DONT_REQUIRE_PREAUTH, so this
      live-guards the AS-REP-roasting false-positive fix that was found against a
      real DC.
    * coercion_surface_probe binds (only) to the MS-RPRN spoolss pipe over an
      authenticated SMB session, proving the coercion interface is reachable
      without ever issuing the coercion call.
    """
    _skip_if_unavailable()
    from heaven.recon.coercion_probe import coercion_surface_probe
    from heaven.recon.kerberos_probe import kerberos_preauth_probe

    seeded = ["alice", "bob", "svc_sql", "administrator"]

    def _kdc_answering() -> bool:
        # Ready once the KDC gives a conclusive Kerberos answer (a non-empty
        # enumeration finding means it distinguished existing from absent users).
        try:
            return bool(asyncio.run(kerberos_preauth_probe(
                "HEAVEN.LOCAL", "127.0.0.1", extra_users=["administrator"])))
        except Exception:
            return False

    with LabStack("samba-dc-compose.yml", build=True):
        ready = wait_until(_kdc_answering, timeout_s=240.0, interval_s=4.0)
        assert ready, "samba-dc KDC never answered a Kerberos AS-REQ"

        kfind = asyncio.run(kerberos_preauth_probe(
            "HEAVEN.LOCAL", "127.0.0.1",
            extra_users=[*seeded, "nonexistent_zzz999_absent"]))
        ktypes = {f["vuln_type"] for f in kfind}
        assert "kerberos_user_enumeration" in ktypes, kfind
        # The AS-REP false-positive fix must hold live: protected accounts are
        # NOT reported roastable against Samba's KDC.
        assert "asrep_roasting" not in ktypes, kfind
        valid = next(f["evidence"]["valid_users"] for f in kfind
                     if f["vuln_type"] == "kerberos_user_enumeration")
        assert "alice" in valid and "administrator" in valid, valid
        assert "nonexistent_zzz999_absent" not in valid, valid

        cfind = asyncio.run(coercion_surface_probe(
            "127.0.0.1", "alice", "Alice#Pass1!", "HEAVEN.LOCAL"))
        assert any(f["vuln_type"] == "ntlm_coercion" for f in cfind), cfind
        methods = {m["method"] for f in cfind for m in f["evidence"]["methods"]}
        assert "SpoolSample" in methods, methods  # MS-RPRN (PrinterBug) reachable


# ── web: DOM-XSS proven live in a headless browser against OWASP Juice Shop ───
def test_juiceshop_lab_proves_dom_xss():
    """OWASP Juice Shop's search DOM XSS: the ``q`` parameter is rendered into an
    innerHTML sink through Angular's bypassSecurityTrustHtml, so the payload's
    JavaScript executes client-side — invisible to an HTTP-only scanner. HEAVEN's
    shipped XSS execution prover (reached through ``prove_finding``, the
    orchestrator's exploit-proof entry) loads the injected route in headless
    Chromium and proves the vuln by observing a dialog carrying a unique per-run
    token; a mere reflection cannot fire that dialog, so a patched build could not
    false-positive. This complements the DVWA web lab, which proves
    server-reflected/stored XSS: DVWA cannot exercise a client-side DOM sink,
    Juice Shop can.

    The SPA's toolbar-hidden search box is supplied as the known injection point
    (the crawler maps the app's routes but does not auto-reveal that input); the
    *proof* — real JavaScript execution in a browser — is what this lab
    machine-checks.
    """
    _skip_if_unavailable()
    from heaven.utils.runtime_capabilities import _chromium_status

    ok, detail = _chromium_status()
    if not ok:
        pytest.skip(f"headless Chromium not available: {detail}")

    from heaven.vulnscan.exploit_proof import prove_finding

    with LabStack("juiceshop-compose.yml"):
        # Juice Shop serves its Angular shell immediately; wait for the app HTML.
        ready = wait_until(
            lambda: http_status("http://127.0.0.1:3000/") == 200
            and "Juice Shop" in http_body("http://127.0.0.1:3000/"),
            timeout_s=180.0, interval_s=3.0)
        assert ready, "Juice Shop never became reachable"

        finding = {
            "vuln_type": "reflected_xss",
            "target": "http://127.0.0.1:3000/#/search",
            "evidence": {"parameter": "q", "method": "GET"},
            "confidence": 0.5,
        }
        out = asyncio.run(prove_finding(finding, authorized=True))

        # The proof is real JavaScript execution in the browser, not reflection.
        assert out.get("proved") is True, out.get("evidence")
        proofs = out["evidence"]["exploit_proof"]
        hit = next(p for p in proofs if p["proved"])
        assert hit["technique"] == "xss_dom_execution", hit
        assert "javascript_executed_in_browser" in hit["evidence"]["signals"], hit
        # A fired dialog carrying the run token is the irrefutable execution proof.
        assert hit["evidence"].get("token"), hit
        # Confidence is upgraded to proven ground truth.
        assert out["confidence"] >= 0.99, out["confidence"]


# ── api: VAmPI (real third-party OWASP API Top 10) ───────────────────────────
def test_vampi_lab_detects_api_flaws():
    """VAmPI is a deliberately-vulnerable third-party REST API that publishes its
    own OpenAPI 3.0.1 contract. HEAVEN's api_scanner discovers the spec, probes
    the endpoints it *declares* (not just conventional ``/api/*`` guesses), and
    confirms the real flaws live:

      * ``excessive_data_exposure`` — GET /users/v1/_debug serialises every
        user's ``password`` (API3:2023, CWE-359). High confidence: the response
        literally carries populated password values, not a heuristic.
      * ``api_broken_auth``        — GET /users/v1 returns the whole user
        collection unauthenticated (API2:2023).
      * ``api_docs_exposed``       — the OpenAPI spec is itself public (API9).

    This proves the API mode against an external app, complementing the always-on
    native API fixture (which HEAVEN authored). Nothing is mocked: the scanner
    reads VAmPI's real contract and confirms each finding against a live response.
    """
    _skip_if_unavailable()
    from heaven.vulnscan.api_scanner import scan_api_targets

    base = "http://127.0.0.1:5001"
    with LabStack("vampi-compose.yml"):
        ready = wait_until(
            lambda: http_status(f"{base}/") == 200
            and "VAmPI" in http_body(f"{base}/"),
            timeout_s=120.0, interval_s=3.0)
        assert ready, "VAmPI never became reachable"
        # VAmPI seeds its user/book tables on demand via its own /createdb route.
        assert http_status(f"{base}/createdb") == 200, "VAmPI /createdb seed failed"

        res = asyncio.run(scan_api_targets(urls=[base]))
        by_type = {f["vuln_type"]: f for f in res.get("findings", [])}

        # The signature VAmPI leak: /users/v1/_debug hands back passwords.
        assert "excessive_data_exposure" in by_type, (
            f"missed the /users/v1/_debug password leak; got {list(by_type)}")
        leak = by_type["excessive_data_exposure"]
        assert leak["evidence"]["leaked_field"] in ("password", "passwd", "pwd"), leak
        assert leak["evidence"]["records_with_credential"] >= 1, leak
        assert leak["endpoint"].endswith("/users/v1/_debug"), leak
        assert leak["owasp_api"].startswith("API3"), leak

        # Unauthenticated user collection + public contract, via spec discovery.
        assert "api_broken_auth" in by_type, (
            f"missed the unauthenticated /users/v1 collection; got {list(by_type)}")
        assert "api_docs_exposed" in by_type, (
            f"missed the public OpenAPI spec; got {list(by_type)}")


# ── wireless: exposed WLAN admin panel (the reachable subset, proven live) ────
def test_wireless_lab_detects_exposed_panel():
    """Prove the network-reachable half of WIRELESS mode (its honest scope, per
    the 'Wireless Posture Review' label). A real nginx server hosts an
    unauthenticated MikroTik RouterOS 'webfig' page (an inert decoy carrying the
    genuine vendor fingerprint); scan_wireless_posture fetches it, fingerprints
    the vendor and reports the exposed management interface live. RF/802.11
    capture stays honestly hardware-gated and is never simulated."""
    _skip_if_unavailable()
    from heaven.recon.wireless_posture import scan_wireless_posture

    with LabStack("wireless-compose.yml"):
        ready = wait_until(
            lambda: "routeros" in http_body("http://127.0.0.1:8080/").lower(),
            timeout_s=90.0)
        assert ready, "wireless lab (RouterOS panel) never became reachable"

        res = asyncio.run(scan_wireless_posture(["127.0.0.1"]))
        fs = res.get("findings", [])
        assert any("RouterOS" in f.get("title", "") for f in fs), (
            f"no MikroTik RouterOS panel fingerprinted; got "
            f"{[f.get('title') for f in fs]}")
        assert any(f["vuln_type"].startswith("wireless_mgmt") for f in fs), fs


# ── cloud: metadata-SSRF confirmed live against a real (inert) IMDS ───────────
def test_cloud_ssrf_lab_reaches_instance_metadata():
    """Prove HEAVEN's metadata-SSRF detection end to end: a deliberately
    SSRF-vulnerable web app (/fetch?url=) sits on a Docker network whose subnet
    is the link-local metadata range, with a fake EC2 IMDS pinned to the real
    169.254.169.254. HEAVEN's validate_ssrf injects the AWS metadata endpoints;
    the app fetches them server-side and returns instance-metadata indicators,
    so the SSRF is CONFIRMED against a real IMDS reachable at the canonical
    address — not a unit-test double. The IMDS hands back only an inert
    AKIA...EXAMPLE placeholder.

    This also guards the real ordering fix in validate_ssrf: the cloud-metadata
    probes used to be crowded out of the probe budget by localhost-obfuscation
    variants, so a metadata SSRF was never actually tested.
    """
    _skip_if_unavailable()
    import aiohttp

    from heaven.vulnscan.safe_validator import validate_ssrf

    base = "http://127.0.0.1:8095"
    with LabStack("cloud-ssrf-compose.yml"):
        ready = wait_until(
            lambda: "ami-id" in http_body(
                f"{base}/fetch?url=http://169.254.169.254/latest/meta-data/"),
            timeout_s=120.0, interval_s=3.0)
        assert ready, "cloud SSRF lab (app -> IMDS) never became reachable"

        async def _run():
            async with aiohttp.ClientSession() as s:
                return await validate_ssrf(s, f"{base}/fetch", "url")

        res = asyncio.run(_run())
        assert res.result == "confirmed", f"metadata SSRF not confirmed: {res.result}"
        assert "169.254.169.254" in res.evidence.get("probe_url", ""), res.evidence


# ── malware: webshell sweep detected live against a real HTTP server ──────────
def test_webshell_lab_detects_dropped_shells():
    """Elevate MALWARE mode from PARTIAL to proven: a real nginx server hosts a
    webroot of INERT webshell-signature decoys (no PHP interpreter, nothing
    executes — see labs/webshell-root/README.txt), and HEAVEN's read-only
    webshell sweep GETs the known shell paths and flags every one. This proves
    BOTH detection paths against a live server, not a unit-test double:

      * named-shell response signatures — c99 / r57 / b374k / WSO / IndoXploit /
        Alfa are each fingerprinted from the served banner;
      * the generic YARA path — ``shell.php`` carries only a China-Chopper
        ``@eval($_POST[...])`` one-liner (no named banner), so it can be caught
        solely by ``PHP_Webshell_Eval_Superglobal``. That path had been
        unit-tested only; here it fires against a real HTTP response.
    """
    _skip_if_unavailable()
    from heaven.vulnscan.malware_scan import scan_malware_targets

    base = "http://127.0.0.1:8093"
    with LabStack("webshell-compose.yml"):
        ready = wait_until(
            lambda: http_status(f"{base}/c99.php") == 200
            and "c99shell" in http_body(f"{base}/c99.php"),
            timeout_s=90.0)
        assert ready, "webshell lab (nginx) never became reachable"

        res = asyncio.run(scan_malware_targets(urls=[base]))
        shells = [f for f in res["findings"]
                  if f["vuln_type"] == "webshell_detected"]
        paths = {f["target"].rsplit("/", 1)[-1] for f in shells}
        # Every seeded decoy must be detected (named-signature path).
        assert {"c99.php", "r57.php", "b374k.php", "wso.php",
                "indoxploit.php", "alfa.php"} <= paths, paths
        # The generic YARA path must catch the banner-less China-Chopper shell.
        generic = [f for f in shells if f["target"].endswith("/shell.php")]
        assert generic, f"generic YARA webshell path missed shell.php; got {paths}"
        assert generic[0]["evidence"]["signature"] == "PHP_Webshell_Eval_Superglobal"
        assert all(f["severity"] == "critical" for f in shells)

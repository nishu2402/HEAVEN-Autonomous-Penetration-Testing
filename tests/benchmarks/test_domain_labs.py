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
    from heaven.recon.iot_scanner import probe_modbus, probe_mqtt, scan_iot_targets

    with LabStack("iot-compose.yml", build=True):
        # Ready only when BOTH protocol handshakes actually succeed (not merely
        # when the TCP port accepts) — the pymodbus server needs a moment after
        # the port opens before it answers a Read-Device-Identification request.
        ready = wait_until(
            lambda: asyncio.run(probe_mqtt("127.0.0.1", 1883, 4.0)) is not None
            and asyncio.run(probe_modbus("127.0.0.1", 502, 4.0)) is not None,
            timeout_s=120.0)
        assert ready, "iot lab (mqtt + modbus) handshakes never confirmed"

        res = asyncio.run(scan_iot_targets(["127.0.0.1"]))
        fs = res["findings"]
        assert any(f["protocol"] == "MQTT" and f["severity"] == "critical"
                   for f in fs), "no critical anonymous-MQTT finding"
        assert any(f["protocol"] == "Modbus TCP" and f["severity"] == "critical"
                   for f in fs), "no critical unauthenticated-Modbus finding"


# ── ot: Modbus reachable as an ICS service ───────────────────────────────────
def test_ot_lab_detects_modbus_ics():
    _skip_if_unavailable()
    from heaven.recon.iot_scanner import probe_modbus, scan_ot_targets

    with LabStack("ot-compose.yml", build=True):
        ready = wait_until(
            lambda: asyncio.run(probe_modbus("127.0.0.1", 502, 4.0)) is not None,
            timeout_s=120.0)
        assert ready, "ot lab (modbus) handshake never confirmed"

        res = asyncio.run(scan_ot_targets(["127.0.0.1"]))
        fs = res["findings"]
        assert any(f["protocol"] == "Modbus TCP" and f["severity"] == "critical"
                   for f in fs), "no critical Modbus-ICS finding"


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

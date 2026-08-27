"""Network service exposure analyzer — turns a router/switch/host inventory into
findings (the fix for "scan a Cisco device → No findings recorded"), without
false positives on a hardened host. SNMP default-community probing is disabled
in these tests so nothing touches the network."""
from __future__ import annotations

import asyncio

from heaven.recon import network_exposure as nx
from heaven.devsecops.vuln_kb import enrich_finding


def _run(coro):
    return asyncio.run(coro)


def test_cisco_like_device_produces_findings():
    net = {"hosts": [{"ip": "192.168.1.1", "open_ports": [
        {"port": 23, "service": "telnet"},
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"},
        {"port": 161, "service": "snmp"},
        {"port": 4786, "service": "cisco-smi"},
        {"port": 22, "service": "ssh"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    types = {f["vuln_type"] for f in res["findings"]}
    assert "cleartext_service" in types          # telnet
    assert "snmp_exposed" in types               # snmp (probe off → exposed, not proven)
    assert "cisco_smart_install" in types        # SMI
    # every finding carries taxonomy after enrichment
    for f in res["findings"]:
        e = enrich_finding(f)
        assert e.get("cwe") and e.get("cvss_vector")


def test_hardened_host_has_no_false_positives():
    # Only SSH + HTTPS — no cleartext, no SNMP, no SMI.
    net = {"hosts": [{"ip": "10.0.0.5", "open_ports": [
        {"port": 22, "service": "ssh"},
        {"port": 443, "service": "https"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert res["findings"] == []


def test_ambiguous_service_name_does_not_trigger_cleartext():
    # A random service literally named "shell"/"login" on an unrelated port must
    # NOT be flagged (exact-token match only, never substring).
    net = {"hosts": [{"ip": "10.0.0.9", "open_ports": [
        {"port": 9999, "service": "someshell-thing"},
        {"port": 8443, "service": "https-alt"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert res["findings"] == []


def test_telnet_on_nonstandard_port_matched_by_service_name():
    net = {"hosts": [{"ip": "10.0.0.7", "open_ports": [
        {"port": 2323, "service": "telnet"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    assert any(f["vuln_type"] == "cleartext_service" for f in res["findings"])


def test_backdoor_bind_shell_flagged_critical():
    # Metasploitable's 1524 "root shell" bind shell: the banner/label advertises
    # an unauthenticated shell — an unambiguous critical backdoor.
    net = {"hosts": [{"ip": "192.168.0.162", "open_ports": [
        {"port": 1524, "service": "bindshell",
         "product": "Metasploitable root shell",
         "banner": "Metasploitable root shell"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False, active_probes=False))
    bd = [f for f in res["findings"] if f["vuln_type"] == "backdoor_shell"]
    assert bd and bd[0]["severity"] == "critical"
    assert enrich_finding(bd[0]).get("cwe")


def test_druby_and_java_rmi_exposed():
    net = {"hosts": [{"ip": "192.168.0.162", "open_ports": [
        {"port": 8787, "service": "drb", "product": "Ruby DRb RMI",
         "banner": "Ruby DRb RMI Ruby 1.8; path /usr/lib/ruby"},
        {"port": 1099, "service": "java-rmi", "product": "GNU Classpath grmiregistry",
         "banner": "GNU Classpath grmiregistry"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False, active_probes=False))
    titles = {f["title"] for f in res["findings"]
              if f["vuln_type"] == "dangerous_service_exposed"}
    assert any("dRuby" in t for t in titles)
    assert any("RMI" in t for t in titles)
    sev = {f["title"]: f["severity"] for f in res["findings"]}
    assert any(v == "critical" for k, v in sev.items() if "dRuby" in k)  # RCE by design


def test_benign_shell_named_service_is_not_a_backdoor():
    # rsh (service "shell") is cleartext, NOT a backdoor; a banner that merely
    # mentions a /bin/sh path must not be mistaken for a live root shell.
    net = {"hosts": [{"ip": "10.0.0.11", "open_ports": [
        {"port": 514, "service": "shell", "banner": "netkit-rsh rexecd"},
        {"port": 7000, "service": "custom",
         "banner": "MyApp helper; interpreter at /bin/sh available"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False, active_probes=False))
    assert not any(f["vuln_type"] == "backdoor_shell" for f in res["findings"])


def test_snmp_packet_is_well_formed_ber():
    pkt = nx._snmp_get_packet("public", 0x3039, nx.SYS_DESCR_OID)
    assert pkt[0] == 0x30            # outer SEQUENCE
    assert b"public" in pkt          # community string
    assert 0xA0 in pkt               # GetRequest-PDU tag
    # sysDescr OID bytes present in the varbind
    assert nx.SYS_DESCR_OID in pkt


def test_extract_sysdescr_requires_getresponse():
    # A packet without a GetResponse (0xA2) PDU is not a valid SNMP answer.
    assert nx._extract_sysdescr(b"\x30\x05not-snmp", nx.SYS_DESCR_OID) is None


# ── Active default-/weak-credential + NFS export probes ──────────────────────
# These are hermetic: the probe helpers that touch the network are monkeypatched
# so the tests never open a socket. They verify the wiring, severity, taxonomy,
# and — critically — the false-positive and stealth-gating discipline.

def _net(ip, *ports):
    return {"hosts": [{"ip": ip, "open_ports": [
        (p if isinstance(p, dict) else {"port": p[0], "service": p[1]})
        for p in ports]}]}


def _one(res, vuln_type):
    hits = [f for f in res["findings"] if f["vuln_type"] == vuln_type]
    assert len(hits) == 1, f"expected exactly one {vuln_type}, got {len(hits)}"
    return hits[0]


def _no_write_probe(monkeypatch):
    """Neutralise the live NFSv3 ACCESS probe so a test never opens a socket;
    the finding then falls back to its honest "undetermined" access mode."""
    async def _undet(host, dirpath, timeout=5.0):
        return None
    monkeypatch.setattr(nx, "_nfs_world_write_check", _undet)


def test_nfs_world_root_export_is_critical(monkeypatch):
    async def _fake(host, port=111, timeout=5.0):
        return [("/", ["*"])]
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    _no_write_probe(monkeypatch)
    net = _net("192.168.0.162", (111, "rpcbind"), (2049, "nfs"))
    res = _run(nx.analyze_network_exposure(net, active_snmp=True))
    f = _one(res, "nfs_export_exposed")
    assert f["severity"] == "critical"          # root filesystem exported world-wide
    assert f["typical_cvss"] == 9.1
    assert f["evidence"]["access_mode"] == "undetermined"
    assert "/" in f["evidence"]["world_exports"]
    assert enrich_finding(f).get("cwe") == "CWE-552"


def test_nfs_nonsensitive_world_export_is_high(monkeypatch):
    async def _fake(host, port=111, timeout=5.0):
        return [("/pub", ["*"])]
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    _no_write_probe(monkeypatch)
    res = _run(nx.analyze_network_exposure(
        _net("10.0.0.5", (2049, "nfs")), active_snmp=True))
    f = _one(res, "nfs_export_exposed")
    assert f["severity"] == "high"              # undetermined + non-sensitive
    assert f["typical_cvss"] == 7.5


def test_nfs_confirmed_world_write_is_critical(monkeypatch):
    # A read-only NFSv3 ACCESS probe that confirms anonymous WRITE promotes even a
    # non-sensitive path to critical and records the proof in the evidence.
    async def _fake(host, port=111, timeout=5.0):
        return [("/pub", ["*"])]
    async def _rw(host, dirpath, timeout=5.0):
        return "read-write"
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    monkeypatch.setattr(nx, "_nfs_world_write_check", _rw)
    res = _run(nx.analyze_network_exposure(
        _net("10.0.0.5", (2049, "nfs")), active_snmp=True))
    f = _one(res, "nfs_export_exposed")
    assert f["severity"] == "critical" and f["typical_cvss"] == 9.1
    assert f["evidence"]["access_mode"] == "read-write"
    assert f["evidence"]["writable_exports"] == "/pub"
    assert "write access" in f["description"]


def test_nfs_confirmed_readonly_is_downgraded(monkeypatch):
    # When ACCESS proves anonymous clients only get read (root_squash), a
    # non-sensitive share is medium, not high — accuracy over alarm.
    async def _fake(host, port=111, timeout=5.0):
        return [("/pub", ["*"])]
    async def _ro(host, dirpath, timeout=5.0):
        return "read-only"
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    monkeypatch.setattr(nx, "_nfs_world_write_check", _ro)
    res = _run(nx.analyze_network_exposure(
        _net("10.0.0.5", (2049, "nfs")), active_snmp=True))
    f = _one(res, "nfs_export_exposed")
    assert f["severity"] == "medium" and f["typical_cvss"] == 5.3
    assert f["evidence"]["access_mode"] == "read-only"


def test_nfs_readonly_sensitive_stays_high(monkeypatch):
    async def _fake(host, port=111, timeout=5.0):
        return [("/home", ["*"])]
    async def _ro(host, dirpath, timeout=5.0):
        return "read-only"
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    monkeypatch.setattr(nx, "_nfs_world_write_check", _ro)
    res = _run(nx.analyze_network_exposure(
        _net("10.0.0.5", (2049, "nfs")), active_snmp=True))
    f = _one(res, "nfs_export_exposed")
    assert f["severity"] == "high" and f["typical_cvss"] == 7.5


def test_nfs_host_restricted_export_is_not_flagged(monkeypatch):
    # An export shared only with specific hosts is normal, not a finding.
    async def _fake(host, port=111, timeout=5.0):
        return [("/srv/data", ["10.0.0.5", "10.0.0.6"])]
    monkeypatch.setattr(nx, "_nfs_exports", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("10.0.0.5", (2049, "nfs")), active_snmp=True))
    assert not any(f["vuln_type"] == "nfs_export_exposed" for f in res["findings"])


def test_tomcat_manager_default_creds_flagged(monkeypatch):
    async def _fake(host, port, timeout=6.0):
        return {"username": "tomcat", "password_used": "tomcat",
                "url": f"http://{host}:{port}/manager/html", "status": 200,
                "manager_ui_confirmed": True}
    monkeypatch.setattr(nx, "_tomcat_manager_default_creds", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("192.168.0.162", (8180, "http")), active_snmp=True))
    f = _one(res, "tomcat_manager_default_creds")
    assert f["severity"] == "critical" and f["typical_cvss"] == 9.8
    assert f["evidence"]["username"] == "tomcat"
    assert enrich_finding(f).get("cwe") == "CWE-1392"


def test_postgres_default_creds_flagged(monkeypatch):
    async def _fake(host, port=5432, timeout=6.0):
        return {"username": "postgres", "password_used": "postgres",
                "database": "template1", "server_version": "8.3.1"}
    monkeypatch.setattr(nx, "_postgres_default_creds", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("192.168.0.162", (5432, "postgresql")), active_snmp=True))
    f = _one(res, "weak_db_credentials")
    assert f["severity"] == "critical" and f["typical_cvss"] == 9.8
    assert "8.3.1" in f["evidence"]["server_version"]


def test_vnc_no_auth_flagged_critical(monkeypatch):
    async def _fake(host, port=5900, timeout=6.0):
        return {"auth": "none"}
    monkeypatch.setattr(nx, "_vnc_weak_auth", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("192.168.0.162", (5900, "vnc")), active_snmp=True))
    f = _one(res, "vnc_no_auth")
    assert f["severity"] == "critical"
    assert enrich_finding(f).get("cwe") == "CWE-306"


def test_vnc_weak_password_flagged_critical(monkeypatch):
    async def _fake(host, port=5900, timeout=6.0):
        return {"auth": "weak", "password_used": "password"}
    monkeypatch.setattr(nx, "_vnc_weak_auth", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("192.168.0.162", (5900, "vnc")), active_snmp=True))
    f = _one(res, "vnc_weak_credentials")
    assert f["severity"] == "critical"
    assert f["evidence"]["password"] == "password"


def test_vnc_strong_password_produces_no_finding(monkeypatch):
    # A reachable VNC that we could NOT authenticate to must never be reported.
    async def _fake(host, port=5900, timeout=6.0):
        return None
    monkeypatch.setattr(nx, "_vnc_weak_auth", _fake)
    res = _run(nx.analyze_network_exposure(
        _net("192.168.0.162", (5900, "vnc")), active_snmp=True))
    assert not any(f["vuln_type"] in ("vnc_no_auth", "vnc_weak_credentials")
                   for f in res["findings"])


def test_credential_probes_never_run_in_passive_mode(monkeypatch):
    # With active_probes off (stealthy profile), NONE of the credential/NFS
    # probes may be invoked — they must not touch the network at all.
    def _boom(*a, **k):
        raise AssertionError("active probe called in passive mode")
    for name in ("_nfs_exports", "_nfs_world_write_check",
                 "_tomcat_manager_default_creds",
                 "_postgres_default_creds", "_vnc_weak_auth"):
        monkeypatch.setattr(nx, name, _boom)
    net = _net("192.168.0.162", (111, "rpcbind"), (2049, "nfs"),
               (5432, "postgresql"), (5900, "vnc"), (8180, "http"))
    res = _run(nx.analyze_network_exposure(net, active_snmp=False))
    active = {"nfs_export_exposed", "tomcat_manager_default_creds",
              "weak_db_credentials", "vnc_no_auth", "vnc_weak_credentials"}
    assert not any(f["vuln_type"] in active for f in res["findings"])


def test_vnc_des_response_is_stable_and_warning_free():
    # Regression lock on the RFB VNC-auth DES (bit-reversed key, K1=K2=K3 triple
    # DES = single DES). Live-verified against a VNC server that accepted the
    # 'password' response; this pins the transform so it can't silently drift.
    import warnings
    chal = bytes(range(16))
    with warnings.catch_warnings():
        warnings.simplefilter("error")          # no CryptographyDeprecationWarning
        assert (nx._vnc_des_response("password", chal).hex()
                == "b866924125c8eebb9debc1db61c538e2")
        assert (nx._vnc_des_response("", chal).hex()
                == "491e890de9ace932838a49792f2213f3")


def test_rpc_record_has_full_authnull_cred_and_verf():
    # Guard the ONC-RPC framing bug that produced GARBAGE_ARGS: cred AND verf are
    # each an 8-byte AUTH_NULL, so a 0-arg call body is 24 (call header) + 16.
    rec = nx._rpc_record(100005, 1, 5)          # MOUNTPROC_EXPORT, no args
    body = rec[4:]                              # strip the record-marking header
    assert len(body) == 24 + 16


def test_auth_unix_credential_is_well_formed():
    # AUTH_UNIX cred (flavor 1) + AUTH_NULL verf. Body is 4-byte aligned so the
    # opaque length is exact; uid/gid 0 is what a `mount` sends by default.
    import struct
    cred = nx._auth_unix(uid=0, gid=0, machine=b"heaven")
    flavor, ln = struct.unpack(">II", cred[:8])
    assert flavor == 1                          # AUTH_UNIX / AUTH_SYS
    assert ln % 4 == 0 and 8 + ln <= len(cred)
    verf = cred[8 + ln:]
    assert verf == struct.pack(">II", 0, 0)     # AUTH_NULL verifier


def _access_reply(granted, with_attrs=True):
    """Build a record-marked, accepted NFSv3 ACCESS3resok reply carrying the
    given granted-rights bitmask (optionally preceded by a post_op_attr fattr3)."""
    import struct
    body = struct.pack(">III", 0x1234, 1, 0)                 # xid, REPLY, MSG_ACCEPTED
    body += struct.pack(">II", 0, 0)                         # AUTH_NULL verifier
    body += struct.pack(">I", 0)                             # accept_stat = SUCCESS
    body += struct.pack(">I", 0)                             # nfsstat3 = NFS3_OK
    if with_attrs:
        body += struct.pack(">I", 1) + b"\x00" * 84         # attrs_follow + fattr3
    else:
        body += struct.pack(">I", 0)                         # attrs_follow = false
    body += struct.pack(">I", granted)                       # ACCESS3resok.access
    return struct.pack(">I", 0x80000000 | len(body)) + body


def test_nfs_access_mode_parses_write_and_read(monkeypatch):
    # Feed a synthetic ACCESS reply through the real parser (record-marking +
    # fattr3 skip). MODIFY(0x04)|EXTEND(0x08) => read-write, else read-only.
    class _FakeReader:
        def __init__(self, data): self.buf = data
        async def readexactly(self, n):
            chunk, self.buf = self.buf[:n], self.buf[n:]
            return chunk

    class _FakeWriter:
        def write(self, *_): pass
        async def drain(self): pass
        def close(self): pass

    async def _open(host, port, timeout):
        return _FakeReader(_open.reply), _FakeWriter()
    monkeypatch.setattr(nx, "_open_reserved", _open)

    _open.reply = _access_reply(0x1f, with_attrs=True)      # RWXLD
    assert _run(nx._nfs_access_mode("h", 2049, b"fh", 2.0)) == "read-write"
    _open.reply = _access_reply(0x03, with_attrs=False)     # READ|LOOKUP only
    assert _run(nx._nfs_access_mode("h", 2049, b"fh", 2.0)) == "read-only"

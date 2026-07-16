"""
Tests for mode-aware scan dispatch + scanner accuracy (no fabricated findings).

Covers:
* build_full_scan registers a focused, distinct task set per ScanMode (FULL runs
  everything; specialised modes run their dedicated scanner + the shared tail).
* IoT/OT scanners never fabricate a finding from an open port — a protocol-
  correct response is required; garbage yields nothing.
* The vendor fingerprint matches whole words only (no "GE" in "imaGE").
* The container scanner never attributes the scanner's own docker.sock to a
  remote target.
"""

from __future__ import annotations

import asyncio
from unittest import mock

from heaven.config import ScanMode
from heaven.orchestrator import build_full_scan


def _task_names(mode: ScanMode) -> set[str]:
    orch = build_full_scan(
        {"ips": ["127.0.0.1"], "urls": ["http://127.0.0.1/"],
         "repositories": [], "cloud_providers": []},
        scan_mode=mode,
    )
    return {t.name for t in orch.tasks.values()}


# ── mode dispatch ─────────────────────────────────────────────────────────
def test_full_mode_registers_every_surface():
    names = _task_names(ScanMode.FULL)
    for n in ("Web Application Fuzzing", "Network Reconnaissance",
              "API Security Scan", "Cloud Asset Enumeration",
              "Container/K8s Scan", "IoT/SCADA Scan", "OT/ICS Scan",
              "Active Directory Scan", "Email Security Scan"):
        assert n in names, f"FULL mode is missing {n}"


def test_web_mode_is_focused():
    names = _task_names(ScanMode.WEB)
    assert "Web Application Fuzzing" in names
    assert "Injection Discovery (XSS/SQLi)" in names
    assert "Directory & File Fuzzing" in names
    # web mode must NOT drag in the specialised non-web scanners
    for n in ("Active Directory Scan", "IoT/SCADA Scan", "OT/ICS Scan",
              "Container/K8s Scan", "Email Security Scan", "Cloud Asset Enumeration"):
        assert n not in names, f"WEB mode should not include {n}"


def test_network_mode_is_focused():
    names = _task_names(ScanMode.NETWORK)
    assert "Network Reconnaissance" in names
    assert "SSL/TLS Audit" in names
    # no web-app fuzzing in a network scan
    assert "Web Application Fuzzing" not in names
    assert "Injection Discovery (XSS/SQLi)" not in names


def test_api_mode_runs_api_scanner_not_ad():
    names = _task_names(ScanMode.API)
    assert "API Security Scan" in names
    assert "Injection Discovery (XSS/SQLi)" in names
    assert "Active Directory Scan" not in names


def test_ot_mode_is_distinct_from_iot():
    ot = _task_names(ScanMode.OT)
    iot = _task_names(ScanMode.IOT)
    assert "OT/ICS Scan" in ot and "OT/ICS Scan" not in iot
    assert "IoT/SCADA Scan" in iot and "IoT/SCADA Scan" not in ot


def test_email_mode_is_minimal():
    names = _task_names(ScanMode.EMAIL)
    assert "Email Security Scan" in names
    assert "DNS Security Reconnaissance" in names
    assert "Network Reconnaissance" not in names
    assert "Web Application Fuzzing" not in names


def test_every_mode_keeps_the_scoring_and_report_tail():
    for mode in ScanMode:
        names = _task_names(mode)
        for tail in ("PoC Validation", "ML Risk Scoring",
                     "MITRE ATT&CK Mapping", "Report Generation"):
            assert tail in names, f"{mode.value} is missing tail task {tail}"


def test_focused_modes_are_smaller_than_full():
    full = len(_task_names(ScanMode.FULL))
    for mode in (ScanMode.EMAIL, ScanMode.CLOUD, ScanMode.CONTAINER,
                 ScanMode.AD, ScanMode.IOT, ScanMode.OT):
        assert len(_task_names(mode)) < full


# ── IoT / OT: no fabrication, protocol-correct probes ─────────────────────
def test_iot_closed_host_yields_no_findings():
    # A host with no IoT services must produce zero findings (never fabricated
    # from an open port). Short timeout keeps the closed-UDP-port waits fast.
    from heaven.recon.iot_scanner import IoTScanner
    findings = asyncio.run(IoTScanner(timeout=0.3).scan_host("127.0.0.1"))
    assert findings == []


def test_ot_closed_host_yields_no_findings():
    from heaven.recon.iot_scanner import OTScanner
    findings = asyncio.run(OTScanner(timeout=0.3).scan_host("127.0.0.1"))
    assert findings == []


def test_vendor_match_is_whole_word_only():
    from heaven.recon.iot_scanner import _match_vendor
    # innocuous page text must not match any vendor token
    assert _match_vendor("this page has an image and cloud storage widget") is None
    # real fingerprints match
    assert _match_vendor("Server: Hikvision-Webs") == "Hikvision"
    assert _match_vendor("Welcome to the MikroTik RouterOS panel") == "MikroTik"


# ── IoT vendor panel: default-credential login must be PROVEN, never assumed ──
def _fake_aiohttp_session(fingerprint: dict, login: dict | None = None):
    """Build a drop-in replacement for aiohttp.ClientSession whose .get() returns
    `fingerprint` for the unauthenticated probe and `login` for the Basic-auth
    retry (the request that carries an `auth=` kwarg)."""
    class _Resp:
        def __init__(self, spec): self._s = spec
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        @property
        def status(self): return self._s["status"]
        @property
        def headers(self): return self._s.get("headers", {})
        async def text(self, errors="ignore"): return self._s.get("text", "")

    class _Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def get(self, url, **kw):
            is_login = "auth" in kw or "Authorization" in kw.get("headers", {})
            if is_login and login is not None:
                return _Resp(login)
            return _Resp(fingerprint)
    return _Session


def test_iot_open_panel_is_not_reported_as_default_creds():
    """A vendor panel that answers 200 with NO auth challenge must be a
    fingerprint-only info finding — never a fabricated 'accepts default
    credentials' critical (the panel never required a credential at all)."""
    from heaven.recon import iot_scanner as m
    fake = _fake_aiohttp_session(
        {"status": 200, "headers": {"Server": "Hikvision-Webs"},
         "text": "<title>NVR</title>"})
    scanner = m.IoTScanner(timeout=0.3)
    with mock.patch("aiohttp.ClientSession", fake):
        asyncio.run(scanner._iot_web("10.0.0.5", 80))
    assert scanner._findings, "the vendor panel should still be fingerprinted"
    assert all(f.severity != "critical" for f in scanner._findings)
    assert all("default credential" not in f.title.lower() for f in scanner._findings)


def test_iot_basic_auth_default_cred_flip_is_confirmed_critical():
    """A 401 Basic challenge that flips to 200 with the default credential IS a
    genuinely confirmed critical."""
    from heaven.recon import iot_scanner as m
    fake = _fake_aiohttp_session(
        {"status": 401, "text": "",
         "headers": {"Server": "Hikvision-Webs",
                     "WWW-Authenticate": 'Basic realm="NVR"'}},
        login={"status": 200, "headers": {}, "text": "welcome"})
    scanner = m.IoTScanner(timeout=0.3)
    with mock.patch("aiohttp.ClientSession", fake):
        asyncio.run(scanner._iot_web("10.0.0.5", 80))
    assert any(f.severity == "critical" and "default credential" in f.title.lower()
               for f in scanner._findings)


def test_iot_basic_auth_wrong_cred_is_info_only():
    """A 401 that stays 401 under the default credential is not a critical."""
    from heaven.recon import iot_scanner as m
    fake = _fake_aiohttp_session(
        {"status": 401, "text": "",
         "headers": {"Server": "Hikvision-Webs",
                     "WWW-Authenticate": 'Basic realm="NVR"'}},
        login={"status": 401, "text": "",
               "headers": {"WWW-Authenticate": 'Basic realm="NVR"'}})
    scanner = m.IoTScanner(timeout=0.3)
    with mock.patch("aiohttp.ClientSession", fake):
        asyncio.run(scanner._iot_web("10.0.0.5", 80))
    assert scanner._findings
    assert all(f.severity != "critical" for f in scanner._findings)


def test_modbus_probe_requires_protocol_correct_response():
    from heaven.recon import iot_scanner as m
    # A valid Modbus response: tx-id 0x0001, proto 0x0000, function 0x2B
    valid = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xFF, 0x2B, 0x0E, 0x01])

    async def ok(*a, **k):
        return valid

    async def garbage(*a, **k):
        return b"HTTP/1.1 200 OK\r\n\r\nhello"

    with mock.patch.object(m, "_tcp_query", ok):
        assert asyncio.run(m.probe_modbus("1.2.3.4")) is not None
    with mock.patch.object(m, "_tcp_query", garbage):
        assert asyncio.run(m.probe_modbus("1.2.3.4")) is None


def test_opcua_and_iec104_probes_require_valid_reply():
    from heaven.recon import iot_scanner as m

    async def opcua_ack(*a, **k):
        return b"ACKF\x1c\x00\x00\x00"

    async def iec_con(*a, **k):
        return bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])

    async def none(*a, **k):
        return None

    with mock.patch.object(m, "_tcp_query", opcua_ack):
        assert asyncio.run(m.probe_opcua("1.2.3.4")) == {"acknowledged": True}
    with mock.patch.object(m, "_tcp_query", iec_con):
        assert asyncio.run(m.probe_iec104("1.2.3.4")) is not None
    with mock.patch.object(m, "_tcp_query", none):
        assert asyncio.run(m.probe_opcua("1.2.3.4")) is None


def test_ot_open_port_without_protocol_is_info_not_critical():
    """An open ICS port whose handshake did NOT confirm must be an honest
    low-confidence info finding — never a fabricated critical."""
    from heaven.recon import iot_scanner as m

    async def probe_none(*a, **k):
        return None

    scanner = m.OTScanner()
    asyncio.run(scanner._ics("1.2.3.4", 502, "Modbus TCP", probe_none, "critical"))
    assert len(scanner._findings) == 1
    f = scanner._findings[0]
    assert f.severity == "info"
    assert f.confidence <= 0.5
    assert "did not confirm" in f.description


def test_dnp3_crc_matches_spec_check_value():
    """CRC-16/DNP 'check' constant for b'123456789' is 0xEA82."""
    from heaven.recon import iot_scanner as m
    assert int.from_bytes(m._dnp3_crc(b"123456789"), "little") == 0xEA82


# ── container: local-host posture never attributed to a remote target ─────
def test_container_remote_target_never_reports_local_socket():
    from heaven.recon import container_scanner as c
    with mock.patch("os.path.exists", return_value=True):  # scanner host has a socket
        remote = asyncio.run(
            c.DockerScanner.check_docker_socket("10.20.30.40", is_local=False))
    assert not any(f.vuln_type == "docker_socket_exposed" for f in remote)


def test_container_local_target_reports_local_socket():
    from heaven.recon import container_scanner as c
    with mock.patch("os.path.exists", return_value=True):
        local = asyncio.run(
            c.DockerScanner.check_docker_socket("127.0.0.1", is_local=True))
    assert any(f.vuln_type == "docker_socket_exposed" for f in local)


def test_is_local_target_classification():
    from heaven.recon.container_scanner import _is_local_target
    assert _is_local_target("localhost")
    assert _is_local_target("127.0.0.1")
    assert _is_local_target("http://127.0.0.1:8080")
    assert not _is_local_target("10.20.30.40")
    assert not _is_local_target("scanme.example.com")


# ── CLOUD mode auto-enables the public-bucket exposure probe ───────────────
def _task_by_name(orch, name):
    return next(t for t in orch.tasks.values() if t.name == name)


def test_cloud_mode_auto_enables_bucket_exposure_probe():
    """Selecting CLOUD mode is itself the opt-in: the public-bucket probe runs
    without the --cloud-buckets flag. In FULL mode (no flag) it stays opt-in."""
    targets = {"ips": [], "urls": ["http://example.com/"],
               "repositories": [], "cloud_providers": []}

    # FULL mode, no --cloud-buckets → the probe is skipped (opt-in).
    orch_full = build_full_scan(targets, scan_mode=ScanMode.FULL)
    res_full = asyncio.run(
        _task_by_name(orch_full, "Public Cloud Bucket Exposure").coro_factory())
    assert res_full.get("skipped") is True

    # CLOUD mode → the probe runs automatically (mock out the network scanner).
    orch_cloud = build_full_scan(targets, scan_mode=ScanMode.CLOUD)

    class _FakeResult:
        def to_findings(self):
            return []

    class _FakeScanner:
        async def scan(self, seed):
            return _FakeResult()

    with mock.patch("heaven.vulnscan.cloud_scanner.CloudStorageScanner", _FakeScanner):
        res_cloud = asyncio.run(
            _task_by_name(orch_cloud, "Public Cloud Bucket Exposure").coro_factory())
    assert not res_cloud.get("skipped")
    assert "findings" in res_cloud

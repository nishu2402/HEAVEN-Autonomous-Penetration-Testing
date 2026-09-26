"""Deep TLS posture findings: HSTS directive audit + TLS 1.2 SHA-1 signature
algorithms.

These are configuration-hygiene findings a senior pentester always reports (the
sslyze / testssl / SSL Labs class) that HEAVEN previously captured-but-dropped
(HSTS directives) or did not test at all (legacy signature_algorithms). Each test
stubs the network probes so the only variable is the posture under test, keeping
the checks deterministic and false-positive-free.
"""

from __future__ import annotations

import struct

import heaven.vulnscan.ssl_scanner as ssl_scanner


class _FakeSock:
    def close(self):
        pass


def _stub_probes(monkeypatch, *, hsts, sigalg=""):
    """Stub every network probe. `hsts` is the 4-tuple _check_hsts returns;
    `sigalg` is what _check_legacy_sigalgs should return."""
    m = ssl_scanner
    monkeypatch.setattr(m.socket, "create_connection", lambda *a, **k: _FakeSock())
    import ssl as _ssl
    monkeypatch.setattr(m, "_check_protocol",
                        lambda h, p, lo, hi: hi == _ssl.TLSVersion.TLSv1_2)
    monkeypatch.setattr(m, "_probe_sslv3", lambda h, p, **k: False)
    monkeypatch.setattr(m, "_get_certificate", lambda h, p, **k: None)
    monkeypatch.setattr(m, "_check_heartbleed", lambda h, p, **k: False)
    monkeypatch.setattr(m, "_check_hsts", lambda h, p=443, **k: hsts)
    monkeypatch.setattr(m, "_get_ciphers",
                        lambda h, p, **k: (["ECDHE-RSA-AES256-GCM-SHA384"], []))
    monkeypatch.setattr(m, "_check_legacy_sigalgs", lambda h, p, **k: sigalg)


# ── HSTS directive audit ─────────────────────────────────────────────────────

def test_hsts_missing_include_subdomains(monkeypatch):
    # HSTS present, long max-age, preload set, but includeSubDomains absent.
    _stub_probes(monkeypatch, hsts=(True, 63072000, False, True))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "hsts_no_include_subdomains" in types
    assert "no_hsts" not in types
    assert "hsts_no_preload" not in types


def test_hsts_missing_preload(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, False))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "hsts_no_preload" in types
    assert "hsts_no_include_subdomains" not in types


def test_hsts_fully_configured_no_findings(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert not (types & {"no_hsts", "hsts_short_maxage",
                         "hsts_no_include_subdomains", "hsts_no_preload"})


def test_hsts_absent_still_one_finding(monkeypatch):
    # No HSTS at all → single no_hsts finding, not the per-directive ones.
    _stub_probes(monkeypatch, hsts=(False, 0, False, False))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "no_hsts" in types
    assert not (types & {"hsts_no_include_subdomains", "hsts_no_preload"})


# ── TLS 1.2 legacy signature algorithms ──────────────────────────────────────

def test_sha1_sigalg_ecdsa_finding(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True), sigalg="ecdsa_sha1")
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert res.legacy_sigalg == "ecdsa_sha1"
    hits = [f for f in res.findings if f["vuln_type"] == "tls_sha1_signature_algorithm"]
    assert len(hits) == 1
    assert "ecdsa_sha1" in hits[0]["title"]
    assert hits[0]["severity"] == "low"


def test_sha1_sigalg_rsa_finding(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True), sigalg="rsa_pkcs1_sha1")
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    hits = [f for f in res.findings if f["vuln_type"] == "tls_sha1_signature_algorithm"]
    assert len(hits) == 1
    assert "rsa_pkcs1_sha1" in hits[0]["title"]


def test_no_sha1_sigalg_when_server_refuses(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True), sigalg="")
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert res.legacy_sigalg == ""
    assert not any(f["vuln_type"] == "tls_sha1_signature_algorithm" for f in res.findings)


# ── Probe byte-builder / parser unit checks (no network) ─────────────────────

def test_probe_bytes_are_valid_tls12_clienthello():
    raw = ssl_scanner._tls12_sigalg_probe_bytes("example.com")
    assert raw[0] == 0x16                       # handshake record
    assert raw[5] == 0x01                       # ClientHello
    assert raw[9:11] == b"\x03\x03"             # client_version TLS 1.2
    # The only signature schemes offered are the three SHA-1 codepoints.
    assert ssl_scanner._SIGALG_ECDSA_SHA1 in raw
    assert ssl_scanner._SIGALG_RSA_SHA1 in raw


def test_probe_skips_sni_for_ip_literal():
    assert ssl_scanner._looks_like_ip("192.168.0.1") is True
    assert ssl_scanner._looks_like_ip("example.com") is False
    raw = ssl_scanner._tls12_sigalg_probe_bytes("192.168.0.1")
    # SNI extension type 0x0000 must be absent for an IP literal.
    assert b"\x00\x00\x00" not in raw[43:60]    # rough: no server_name ext head


def test_parse_alert_is_negative(monkeypatch):
    # A TLS alert (0x15) must yield "" — the server correctly refused SHA-1.
    alert = b"\x15\x03\x03\x00\x02\x02\x28"     # fatal handshake_failure
    _install_fake_wire(monkeypatch, alert)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == ""


def test_full_flight_sha1_ecdsa_is_positive(monkeypatch):
    # ServerHello (ECDHE-ECDSA 0xC02B) + ServerKeyExchange signed with SHA-1+ECDSA
    # + ServerHelloDone → the server actually used SHA-1 → positive.
    flight = (_serverhello(suite=0xC02B)
              + _server_key_exchange(suite=0xC02B, hash_b=0x02, sig_b=0x03)
              + _server_hello_done())
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == "ecdsa_sha1"


def test_full_flight_sha256_signature_is_negative(monkeypatch):
    # The crucial false-positive guard: server sends a ServerHello but signs the
    # ServerKeyExchange with SHA-256 (hash byte 0x04) despite our SHA-1-only list.
    # That is correct behaviour and must NOT be flagged.
    flight = (_serverhello(suite=0xC030)
              + _server_key_exchange(suite=0xC030, hash_b=0x04, sig_b=0x01)
              + _server_hello_done())
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == ""


def test_full_flight_sha1_rsa_is_positive(monkeypatch):
    flight = (_serverhello(suite=0xC030)
              + _server_key_exchange(suite=0xC030, hash_b=0x02, sig_b=0x01)
              + _server_hello_done())
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == "rsa_pkcs1_sha1"


def test_full_flight_dhe_sha1_is_positive(monkeypatch):
    flight = (_serverhello(suite=0x009E)
              + _server_key_exchange(suite=0x009E, hash_b=0x02, sig_b=0x01)
              + _server_hello_done())
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == "rsa_pkcs1_sha1"


def test_serverhello_without_ske_is_negative(monkeypatch):
    # A ServerHello with no ServerKeyExchange proves nothing about SHA-1.
    flight = _serverhello(suite=0xC02B) + _server_hello_done()
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == ""


def test_full_flight_non_tls12_negotiation_is_negative(monkeypatch):
    flight = (_serverhello(suite=0xC02B, version=b"\x03\x01")
              + _server_key_exchange(suite=0xC02B, hash_b=0x02, sig_b=0x03)
              + _server_hello_done())
    _install_fake_wire(monkeypatch, flight)
    assert ssl_scanner._check_legacy_sigalgs("h", 443) == ""


# ── TLS record/handshake byte builders for the parser tests ──────────────────

def _record(payload: bytes, ctype: int = 0x16) -> bytes:
    return bytes([ctype]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def _hs_msg(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + struct.pack(">I", len(body))[1:] + body


def _serverhello(suite: int, version: bytes = b"\x03\x03") -> bytes:
    body = (version + b"\x11" * 32 + b"\x00"               # ver, random, sid_len=0
            + struct.pack(">H", suite) + b"\x00")           # cipher_suite, compression
    return _record(_hs_msg(0x02, body))


def _server_key_exchange(suite: int, hash_b: int, sig_b: int) -> bytes:
    if suite in ssl_scanner._DHE_SUITES_ALL:
        # dh_p, dh_g, dh_Ys each 2-byte-length-prefixed.
        params = (struct.pack(">H", 4) + b"\xaa" * 4
                  + struct.pack(">H", 1) + b"\x02"
                  + struct.pack(">H", 4) + b"\xbb" * 4)
    else:
        # ECDHE named_curve: curve_type(0x03) named_curve(secp256r1) pubkey.
        params = b"\x03\x00\x17\x04" + b"\xcc" * 4
    sig = b"\xde\xad\xbe\xef"
    body = params + bytes([hash_b, sig_b]) + struct.pack(">H", len(sig)) + sig
    return _record(_hs_msg(0x0c, body))


def _server_hello_done() -> bytes:
    return _record(_hs_msg(0x0e, b""))


class _WireSock:
    def __init__(self, resp):
        self._resp = resp
        self._sent = False

    def settimeout(self, *_):
        pass

    def sendall(self, *_):
        pass

    def recv(self, *_):
        # Deliver the whole flight once, then EOF, so the read loop terminates.
        if self._sent:
            return b""
        self._sent = True
        return self._resp

    def close(self):
        pass


def _install_fake_wire(monkeypatch, resp):
    monkeypatch.setattr(ssl_scanner.socket, "create_connection",
                        lambda *a, **k: _WireSock(resp))


# ── Certificate posture: weak key + MD5/SHA-1 signature ──────────────────────
# These are standard sslyze/testssl findings. `key_bits`/`key_type` used to be
# declared but never populated, and an MD5 signature was silently missed because
# the finding block only checked for "sha1".

def _cert(**kw):
    ci = ssl_scanner.CertInfo()
    for k, v in kw.items():
        setattr(ci, k, v)
    return ci


def test_md5_signed_certificate_flagged(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_get_certificate",
                        lambda h, p, **k: _cert(signature_algorithm="md5",
                                                key_type="RSA", key_bits=2048))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "md5_signature" in types
    assert "sha1_signature" not in types            # MD5 wins, not double-reported


def test_weak_rsa_key_flagged_critical(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_get_certificate",
                        lambda h, p, **k: _cert(signature_algorithm="sha256",
                                                key_type="RSA", key_bits=1024))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    weak = [f for f in res.findings if f["vuln_type"] == "weak_cert_key"]
    assert weak and weak[0]["severity"] == "critical"   # <=1024-bit → critical


def test_strong_cert_no_key_or_sig_finding(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_get_certificate",
                        lambda h, p, **k: _cert(signature_algorithm="sha256",
                                                key_type="RSA", key_bits=2048))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert not (types & {"weak_cert_key", "md5_signature", "sha1_signature"})


def test_strong_ec_p256_not_flagged(monkeypatch):
    # A 256-bit EC key is strong; it must NOT trip the < 2048 RSA threshold.
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_get_certificate",
                        lambda h, p, **k: _cert(signature_algorithm="sha256",
                                                key_type="EC (secp256r1)", key_bits=256))
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert not any(f["vuln_type"] == "weak_cert_key" for f in res.findings)


# ── Weak Diffie-Hellman parameters (measured off ServerKeyExchange) ──────────
# The old logjam heuristic (`"1024" in cipher_name`) was never true, so weak DH
# was silently missed. These craft a server flight and confirm the real prime
# size is read, and that the right finding fires by size band.

def _dhe_flight(prime_bits: int, suite: int = 0x0033) -> bytes:
    pb = ((1 << (prime_bits - 1)) | 1).to_bytes(prime_bits // 8, "big")
    sh_body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", suite) + b"\x00"
    # SKE: dh_p (len+prime), then minimal dh_g / dh_Ys / signature filler.
    ske_body = (struct.pack(">H", len(pb)) + pb
                + struct.pack(">H", 1) + b"\x02"
                + struct.pack(">H", 1) + b"\x01"
                + b"\x08\x04" + struct.pack(">H", 2) + b"\x00\x00")
    sh = b"\x02" + struct.pack(">I", len(sh_body))[1:] + sh_body
    ske = b"\x0c" + struct.pack(">I", len(ske_body))[1:] + ske_body
    done = b"\x0e\x00\x00\x00"
    hs = sh + ske + done
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def test_check_dh_params_reads_prime_bits(monkeypatch):
    _install_fake_wire(monkeypatch, _dhe_flight(1024))
    assert ssl_scanner._check_dh_params("host.example", 443) == 1024


def test_check_dh_params_reads_2048(monkeypatch):
    _install_fake_wire(monkeypatch, _dhe_flight(2048))
    assert ssl_scanner._check_dh_params("host.example", 443) == 2048


def test_check_dh_params_ignores_non_dhe(monkeypatch):
    # Negotiated suite is ECDHE (0xC030) → no classic DH prime to measure → 0.
    _install_fake_wire(monkeypatch, _dhe_flight(1024, suite=0xC030))
    assert ssl_scanner._check_dh_params("host.example", 443) == 0


def test_logjam_finding_on_1024bit_dh(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_check_dh_params", lambda h, p, **k: 1024)
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "logjam" in types and "weak_dh_params" not in types


def test_weak_dh_finding_on_1536bit_dh(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_check_dh_params", lambda h, p, **k: 1536)
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    weak = [f for f in res.findings if f["vuln_type"] == "weak_dh_params"]
    assert weak and weak[0]["severity"] == "medium"
    assert "logjam" not in {f["vuln_type"] for f in res.findings}


def test_strong_2048bit_dh_no_finding(monkeypatch):
    _stub_probes(monkeypatch, hsts=(True, 63072000, True, True))
    monkeypatch.setattr(ssl_scanner, "_check_dh_params", lambda h, p, **k: 2048)
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert not ({"logjam", "weak_dh_params"} & {f["vuln_type"] for f in res.findings})

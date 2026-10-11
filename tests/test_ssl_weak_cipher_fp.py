"""Regression: two report-facing false positives in the SSL/TLS scanner.

1. The weak-cipher classifier flagged SEED and Camellia-128 as "weak" and told
   the reader they "enable downgrade and decryption attacks". Both are
   128-bit-secure block ciphers with no practical break (OpenSSL rates
   Camellia-128 at HIGH strength), so this was a HIGH-severity false positive.
   Genuinely broken suites (RC4/DES/3DES/NULL/EXPORT/anon/IDEA) must still match.

2. The "TLS 1.0 Only" finding fired whenever TLS 1.2/1.3 were absent, WITHOUT
   checking TLS 1.1. A server speaking TLS 1.0 and 1.1 (but not 1.2/1.3) was
   therefore told "Server only supports TLS 1.0" (false) and, in the same report,
   got the contradictory "TLS 1.1 Deprecated" finding. The fix requires TLS 1.1
   to also be absent before claiming "only TLS 1.0".

See heaven/vulnscan/ssl_scanner.py (_is_weak_cipher, the tls10_only branch).
"""
from __future__ import annotations

import ssl as _ssl

import heaven.vulnscan.ssl_scanner as ssl_scanner


# ── 1. Weak-cipher classifier ────────────────────────────────────────────────

def test_camellia128_not_classified_weak():
    assert ssl_scanner._is_weak_cipher("ECDHE-RSA-CAMELLIA128-SHA256") is False
    assert ssl_scanner._is_weak_cipher("CAMELLIA128-SHA") is False


def test_seed_not_classified_weak():
    assert ssl_scanner._is_weak_cipher("DHE-RSA-SEED-SHA") is False
    assert ssl_scanner._is_weak_cipher("SEED-SHA") is False


def test_strong_aead_not_classified_weak():
    for c in ("ECDHE-RSA-AES256-GCM-SHA384",
              "ECDHE-ECDSA-AES128-GCM-SHA256",
              "ECDHE-RSA-CHACHA20-POLY1305",
              "CAMELLIA256-SHA256"):
        assert ssl_scanner._is_weak_cipher(c) is False, c


def test_genuinely_weak_suites_still_classified_weak():
    for c in ("RC4-MD5", "DES-CBC-SHA", "ECDHE-RSA-DES-CBC3-SHA",
              "NULL-SHA", "EXP-RC4-MD5", "ADH-AES256-SHA",
              "DHE-RSA-IDEA-CBC-SHA"):
        assert ssl_scanner._is_weak_cipher(c) is True, c


# ── 2. "TLS 1.0 Only" must not fire when TLS 1.1 is also supported ────────────

class _FakeSock:
    def close(self):
        pass


def _stub_for_protocols(monkeypatch, *, enabled: set[str]):
    """Stub every probe except the protocol check, which reports the given set."""
    m = ssl_scanner
    monkeypatch.setattr(m.socket, "create_connection", lambda *a, **k: _FakeSock())
    V = _ssl.TLSVersion
    name_for = {
        V.TLSv1_3: "tls13", V.TLSv1_2: "tls12",
        V.TLSv1_1: "tls11", V.TLSv1: "tls10",
    }
    monkeypatch.setattr(m, "_check_protocol",
                        lambda h, p, lo, hi: name_for.get(hi) in enabled)
    monkeypatch.setattr(m, "_probe_sslv3", lambda h, p, **k: False)
    monkeypatch.setattr(m, "_get_certificate", lambda h, p, **k: None)
    monkeypatch.setattr(m, "_check_heartbleed", lambda h, p, **k: False)
    # HSTS fully configured and FS present so only protocol findings are in play.
    monkeypatch.setattr(m, "_check_hsts", lambda h, p=443, **k: (True, 63072000, True, True))
    monkeypatch.setattr(m, "_get_ciphers",
                        lambda h, p, **k: (["ECDHE-RSA-AES256-GCM-SHA384"], []))
    monkeypatch.setattr(m, "_check_legacy_sigalgs", lambda h, p, **k: "")
    monkeypatch.setattr(m, "_check_dh_params", lambda h, p, **k: 0)


def test_tls10_only_fires_when_truly_only_tls10(monkeypatch):
    _stub_for_protocols(monkeypatch, enabled={"tls10"})
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "tls10_only" in types
    assert "tls11_deprecated" not in types


def test_no_false_tls10_only_when_tls11_also_present(monkeypatch):
    # TLS 1.0 + 1.1, no 1.2/1.3: the "only TLS 1.0" claim is false and must not
    # fire; tls11_deprecated covers this server instead (no contradiction).
    _stub_for_protocols(monkeypatch, enabled={"tls10", "tls11"})
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "tls10_only" not in types
    assert "tls11_deprecated" in types


def test_no_tls10_only_on_modern_server(monkeypatch):
    _stub_for_protocols(monkeypatch, enabled={"tls12", "tls13"})
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "tls10_only" not in types
    assert "tls11_deprecated" not in types

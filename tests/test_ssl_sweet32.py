"""SWEET32 (CVE-2016-2183) named finding in the SSL/TLS scanner.

Drives `_run_ssl_scan` with the network probes stubbed so the only variable is
the accepted cipher list, then asserts a named SWEET32 finding appears exactly
when a 64-bit block cipher (3DES/IDEA) is offered — and never otherwise.
"""

from __future__ import annotations

import heaven.vulnscan.ssl_scanner as ssl_scanner


class _FakeSock:
    def close(self):
        pass


def _stub_probes(monkeypatch, ciphers):
    m = ssl_scanner
    monkeypatch.setattr(m.socket, "create_connection",
                        lambda *a, **k: _FakeSock())
    monkeypatch.setattr(m, "_check_protocol",
                        lambda h, p, lo, hi: hi == __import__("ssl").TLSVersion.TLSv1_2)
    monkeypatch.setattr(m, "_probe_sslv3", lambda h, p, **k: False)
    monkeypatch.setattr(m, "_get_certificate", lambda h, p, **k: None)
    monkeypatch.setattr(m, "_check_heartbleed", lambda h, p, **k: False)
    monkeypatch.setattr(m, "_check_hsts",
                        lambda h, p=443, **k: (True, 63072000, True, True))
    weak = [c for c in ciphers if any(t in c.upper() for t in ("3DES", "DES", "RC4", "IDEA"))]
    monkeypatch.setattr(m, "_get_ciphers", lambda h, p, **k: (ciphers, weak))


def test_sweet32_finding_when_3des_offered(monkeypatch):
    _stub_probes(monkeypatch, ["ECDHE-RSA-DES-CBC3-SHA", "AES256-GCM-SHA384"])
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert res.sweet32 is True
    s32 = [f for f in res.findings if f["vuln_type"] == "sweet32"]
    assert len(s32) == 1
    assert s32[0]["cve_id"] == "CVE-2016-2183"
    assert "SWEET32" in s32[0]["title"]


def test_no_sweet32_when_only_aead(monkeypatch):
    _stub_probes(monkeypatch,
                 ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-CHACHA20-POLY1305"])
    res = ssl_scanner._run_ssl_scan("host.example", 443)
    assert res.sweet32 is False
    assert not any(f["vuln_type"] == "sweet32" for f in res.findings)

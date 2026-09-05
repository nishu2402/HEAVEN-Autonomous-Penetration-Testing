"""Regression tests for the SECOND-tier scan-mode FP/accuracy audit
(devsecops / SAST / SCA, AD, email, container/k8s, wireless/IoT, forensics).

Each test pins a specific defect found by running the real pipeline against a
live lab so it cannot silently come back. Live-lab reproduction is documented in
the audit report; these are the fast, deterministic guards.
"""

from __future__ import annotations

import base64
import datetime
import tempfile
from pathlib import Path

import dns.resolver
import pytest
import yaml

from heaven.forensics.certificate import analyze_certificate
from heaven.forensics.dispatch import detect_kind
from heaven.recon.container_scanner import _is_dangerous_mount
from heaven.recon.email_scanner import EmailSecurityScanner
from heaven.recon.git_secrets import scan_file
from heaven.vulnscan.osv_client import _extract_fixed_version, _version_key


# ── SCA: OSV fixed-version extraction ────────────────────────────────────────


def _rec(*ranges):
    return {"affected": [{"package": {"name": "pkg"}, "ranges": list(ranges)}]}


def test_osv_fixed_version_skips_git_commit_sha():
    # A GIT range's `fixed` event is a commit hash, never a version — it must not
    # surface as the "fixed version" (that produced "Upgrade to 644124e… or later").
    rec = _rec(
        {"type": "GIT", "events": [{"introduced": "0"},
                                   {"fixed": "644124ecd0b6e417c527191f866daa05a5a2056d"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.17"}]},
    )
    assert _extract_fixed_version(rec, "PyPI", "pkg", "1.24.1") == "1.26.17"


def test_osv_fixed_version_git_only_returns_empty():
    rec = _rec({"type": "GIT", "events": [{"fixed": "a" * 40}]})
    assert _extract_fixed_version(rec, "PyPI", "pkg", "1.0.0") == ""


def test_osv_fixed_version_picks_nearest_above_installed():
    # Two patched branches (1.26.17 and 2.0.7): a 1.24.1 install should be told to
    # go to the nearest same-branch fix, not jumped to a new major.
    rec = _rec(
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.17"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.7"}]},
    )
    assert _extract_fixed_version(rec, "PyPI", "pkg", "1.24.1") == "1.26.17"
    assert _extract_fixed_version(rec, "PyPI", "pkg", "2.0.1") == "2.0.7"


def test_version_key_orders_numerically():
    assert _version_key("1.26.17") > _version_key("1.9.0")
    assert _version_key("2.0.0") > _version_key("1.26.17")


# ── SAST: curated semgrep rule pack additions ────────────────────────────────
_RULES_DIR = Path(__file__).resolve().parent.parent / "heaven" / "vulnscan" / "sast_rules"


def _rule_ids(filename: str) -> set[str]:
    doc = yaml.safe_load((_RULES_DIR / filename).read_text())
    return {r["id"] for r in doc.get("rules", [])}


def test_sast_php_rules_present_and_valid():
    ids = _rule_ids("php_security.yml")
    for rid in ("heaven.php.command-injection", "heaven.php.file-inclusion",
                "heaven.php.unsafe-deserialization", "heaven.php.sqli",
                "heaven.php.xss-echo", "heaven.php.eval-injection"):
        assert rid in ids
    # every rule targets php and carries a CWE
    doc = yaml.safe_load((_RULES_DIR / "php_security.yml").read_text())
    for r in doc["rules"]:
        assert r["languages"] == ["php"]
        assert str(r["metadata"]["cwe"]).startswith("CWE-")


def test_sast_python_gains_concat_sqli_and_tls_verify():
    ids = _rule_ids("python_injection.yml")
    assert "heaven.python.tls-verification-disabled" in ids
    doc = yaml.safe_load((_RULES_DIR / "python_injection.yml").read_text())
    sqli = next(r for r in doc["rules"] if r["id"] == "heaven.python.sqli-string-format")
    flat = yaml.dump(sqli)
    assert '"..." + $X' in flat and '$X + "..."' in flat  # concatenation forms added


def test_sast_java_gains_unsafe_deserialization():
    assert "heaven.java.unsafe-deserialization" in _rule_ids("java_security.yml")


# ── git-secrets: UUID must not be a "Heroku key" ─────────────────────────────


def _scan_text(text: str):
    p = Path(tempfile.mktemp(suffix=".py"))
    p.write_text(text)
    try:
        return scan_file(p, p.parent)
    finally:
        p.unlink()


def test_git_secrets_bare_uuid_not_flagged():
    findings = _scan_text('REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"\n')
    assert findings == [], "a bare UUID is a public identifier, not a secret"


def test_git_secrets_real_heroku_key_still_flagged():
    findings = _scan_text('HEROKU_API_KEY = "12345678-1234-1234-1234-123456789abc"\n')
    assert any(f.secret_type == "generic_secret" for f in findings)


def test_git_secrets_aws_and_private_key_still_flagged():
    aws = _scan_text('AWS_KEY = "AKIA1234567890ABCDEF"\n')
    assert any(f.secret_type == "aws_key" for f in aws)
    pk = _scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n")
    assert any(f.secret_type == "private_key" for f in pk)


# ── forensics: X.509 certificate analyzer ────────────────────────────────────


def _make_cert(key_bits: int, sig_hash, days_valid: int, *, start_offset_days: int = 0) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + datetime.timedelta(days=start_offset_days))
               .not_valid_after(now + datetime.timedelta(days=start_offset_days + days_valid)))
    cert = builder.sign(key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def _write(data: bytes, suffix: str) -> str:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_bytes(data)
    return str(p)


def test_forensics_detects_der_certificate():
    from cryptography.hazmat.primitives import hashes
    der = _make_cert(2048, hashes.SHA256(), 365)
    path = _write(der, ".der")
    try:
        assert detect_kind(path) == "certificate"
    finally:
        Path(path).unlink()


# A real 1024-bit, SHA-1-signed, self-signed DER certificate (openssl-generated).
# cryptography refuses to *create* SHA-1 signatures, but parses an existing one —
# exactly the field case where a weak signature must be flagged.
_SHA1_1024_CERT_B64 = (
    "MIICBDCCAW2gAwIBAgIUDvLFcViSHC3QtWtJRyY8ntkJxcAwDQYJKoZIhvcNAQEFBQAwFDESMBAG"
    "A1UEAwwJc2hhMS50ZXN0MB4XDTI2MDkwNDIxNDgzMFoXDTI2MTAwNDIxNDgzMFowFDESMBAGA1UE"
    "AwwJc2hhMS50ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBK06UP1J5Tz85wT5MQV06"
    "Qi0Cx3GZphBS193V1dNSN4zWIrdVT+Qc/k/9qWYvltEOGGOe9co+9+ZmlyoHRJHJ+MKBZFXvBBZF"
    "efWGCbbu8GWqto2jZ4w4ddKEcrVgBLxPsjWruHj42NpLEqYb1XacpPLeXRlIYn/kpJe+QT1AFQID"
    "AQABo1MwUTAdBgNVHQ4EFgQU6cmBO+HJasodQW6bCYunGyrFhLYwHwYDVR0jBBgwFoAU6cmBO+HJ"
    "asodQW6bCYunGyrFhLYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQB2CzMW7Akd"
    "IEN3ukFpSk1GOtdPokFll4K04p/X4eSvwhim/Q13jDLx21u40eBfUegfByp0xAeXkT/tHSt6cKeg"
    "hiwCziStr15bHdsa6FMlEgHmFMwiLwF8DDTbyoKkcNaRINkMrICANaboJ38w9UxuLtTJm+KaL7jx"
    "ACrDoSthVg=="
)


def test_forensics_weak_sha1_and_key_are_flagged():
    der = base64.b64decode(_SHA1_1024_CERT_B64)
    res = analyze_certificate(_write(der, ".der"))
    vts = {f["vuln_type"] for f in res["findings"]}
    assert "weak_certificate_key" in vts          # RSA 1024-bit
    assert "weak_certificate_signature" in vts     # SHA-1 signature
    assert "self_signed_certificate" in vts


def test_forensics_expired_cert_flags_expiry():
    from cryptography.hazmat.primitives import hashes
    # SHA-256 (createable), but validity ended 399 days ago.
    der = _make_cert(2048, hashes.SHA256(), 1, start_offset_days=-400)
    res = analyze_certificate(_write(der, ".der"))
    vts = {f["vuln_type"] for f in res["findings"]}
    assert "certificate_expired" in vts
    assert "weak_certificate_key" not in vts       # 2048-bit is fine
    assert "weak_certificate_signature" not in vts  # SHA-256 is fine


def test_forensics_strong_cert_only_self_signed():
    from cryptography.hazmat.primitives import hashes
    der = _make_cert(2048, hashes.SHA256(), 365)
    res = analyze_certificate(_write(der, ".der"))
    vts = {f["vuln_type"] for f in res["findings"]}
    assert vts == {"self_signed_certificate"}, f"unexpected findings on a strong cert: {vts}"


def test_forensics_private_key_is_flagged():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    res = analyze_certificate(_write(pem, ".key"))
    assert any(f["vuln_type"] == "exposed_private_key" for f in res["findings"])


def test_forensics_non_cert_der_degrades_gracefully():
    # ASN.1 SEQUENCE header but not a cert/key — must not crash or error.
    res = analyze_certificate(_write(b"\x30\x82\x00\x05hello", ".bin"))
    assert "error" not in res
    assert res["findings"] == []


# ── container: dangerous-mount classification ────────────────────────────────


def test_container_named_volume_is_not_dangerous():
    # Docker-managed named/anonymous volumes live under /var/lib/docker/volumes but
    # are Type=="volume" — not a host bind, so not a dangerous mount.
    assert _is_dangerous_mount(
        {"Type": "volume", "Source": "/var/lib/docker/volumes/data/_data"}) is False
    assert _is_dangerous_mount({"Type": "tmpfs", "Source": ""}) is False


def test_container_sensitive_bind_is_dangerous():
    assert _is_dangerous_mount({"Type": "bind", "Source": "/etc"}) is True
    assert _is_dangerous_mount({"Type": "bind", "Source": "/"}) is True
    assert _is_dangerous_mount({"Type": "bind", "Source": "/var/run/docker.sock"}) is True


def test_container_app_bind_is_not_dangerous():
    # A bind of application data is not a host-tamper vector.
    assert _is_dangerous_mount({"Type": "bind", "Source": "/srv/app"}) is False
    assert _is_dangerous_mount({"Type": "bind", "Source": "/data/uploads"}) is False


# ── email: severity honesty for near-universal hardening notes ───────────────


class _TXT:
    def __init__(self, text: str):
        self._t = text

    def __str__(self) -> str:
        return self._t


def _install_dns(monkeypatch, records: dict):
    def _resolve(qname, rdtype, *a, **k):
        val = records.get((str(qname).rstrip("."), rdtype))
        if val is None:
            raise dns.resolver.NoAnswer
        if isinstance(val, Exception):
            raise val
        return val
    monkeypatch.setattr(dns.resolver, "resolve", _resolve)


@pytest.mark.asyncio
async def test_email_spf_softfall_is_low_not_medium(monkeypatch):
    _install_dns(monkeypatch, {
        ("example.com", "TXT"): [_TXT("v=spf1 include:_spf.example.com ~all")],
    })
    s = EmailSecurityScanner()
    await s.check_spf("example.com")
    spf = [f for f in s._findings if f.vuln_type == "spf_analysis"]
    assert spf and spf[0].severity == "low", "~all softfail is a low hardening note"


@pytest.mark.asyncio
async def test_email_dkim_no_selector_is_low_and_inconclusive(monkeypatch):
    # Every DKIM selector lookup fails (NoAnswer) -> inconclusive, not a medium miss.
    _install_dns(monkeypatch, {})
    s = EmailSecurityScanner()
    await s.check_dkim("example.com")
    dkim = [f for f in s._findings if f.vuln_type == "dkim_missing"]
    assert dkim and dkim[0].severity == "low"
    assert "inconclusive" in dkim[0].description.lower()


@pytest.mark.asyncio
async def test_email_dnssec_missing_is_low(monkeypatch):
    _install_dns(monkeypatch, {})  # DNSKEY lookup -> NoAnswer
    s = EmailSecurityScanner()
    await s.check_dnssec("example.com")
    dns_f = [f for f in s._findings if f.vuln_type == "dnssec_missing"]
    assert dns_f and dns_f[0].severity == "low"

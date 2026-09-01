"""Tests for the Kerberos pre-auth probe (heaven.recon.kerberos_probe).

The AS-REQ builder is exercised for real; the KDC round-trip is replaced by a
monkeypatched ``_probe_one`` so response-classification and finding-shaping are
verified without a live Domain Controller.
"""
from __future__ import annotations

import asyncio
import base64

import pytest

from heaven.recon import kerberos_probe as k


pytestmark = pytest.mark.skipif(not k.HAS_KRB, reason="impacket/pyasn1 unavailable")


# ── genuine KDC responses captured live from a Samba AD DC (HEAVEN.LOCAL) ─────
# These are REAL bytes off the wire, used so _probe_one's classifier is tested
# against actual KDC output rather than a mock of it. The AS-REP's bulky ticket
# cipher was zeroed to keep the fixture compact; the outer enc-part (all the
# probe reads) is untouched — a 60-byte aes256 (etype 18) enc-part.
_REAL_ASREP_AES_B64 = (
    "a4IBFTCCARGgAwIBBaEDAgELojMwMTAvoQMCAROiKAQmMCQwIqADAgESoRMbEUhFQVZFTi5M"
    "T0NBTGFsaWNlogYEBAAAEACjDhsMSEVBVkVOLkxPQ0FMpBIwEKADAgEBoQkwBxsFYWxpY2Wl"
    "XmFcMFqgAwIBBaEOGwxIRUFWRU4uTE9DQUyiITAfoAMCAQGhGDAWGwZrcmJ0Z3QbDEhFQVZF"
    "Ti5MT0NBTKMgMB6gAwIBEqEDAgEBohIEEAAAAAAAAAAAAAAAAAAAAACmTDBKoAMCARKhAwIB"
    "AqI+BDwAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
    "MTIzNDU2Nzg5Ojs="
)
# The KRB-ERROR (code 25, KDC_ERR_PREAUTH_REQUIRED) a real KDC returns for an
# AS-REQ without pre-auth. impacket's sendReceive() does NOT raise on this — it
# returns these raw bytes — which is exactly the case the classifier must not
# mistake for a roastable AS-REP.
_REAL_KRBERR_25_B64 = (
    "foIBLTCCASmgAwIBBaEDAgEepBEYDzIwMjYwODMxMjAyMzQzWqUFAgMB84+mAwIBGacOGwxI"
    "RUFWRU4uTE9DQUyoEjAQoAMCAQGhCTAHGwVhbGljZakOGwxIRUFWRU4uTE9DQUyqITAfoAMC"
    "AQGhGDAWGwZrcmJ0Z3QbDEhFQVZFTi5MT0NBTKsrGylOZWVkIHRvIHVzZSBQQS1FTkMtVElN"
    "RVNUQU1QL1BBLVBLLUFTLVJFUax6BHgwdjAJoQMCARCiAgQAMAmhAwIBD6ICBAAwCqEEAgIA"
    "k6ICBAAwCaEDAgECogIEADAKoQQCAgCIogIEADAKoQQCAgKPogIEADAvoQMCAROiKAQmMCQw"
    "IqADAgESoRMbEUhFQVZFTi5MT0NBTGFsaWNlogYEBAAAEAA="
)


def test_asreq_builds_without_preauth():
    data = k._build_asreq_no_preauth("administrator", "CORP.LOCAL")
    assert isinstance(data, (bytes, bytearray)) and len(data) > 32


def test_probe_classifies_states(monkeypatch):
    # Map each candidate to a canned KDC outcome.
    canned = {
        "administrator": {"state": "exists"},
        "svc_roast": {"state": "roastable",
                      "hash": "$krb5asrep$23$svc_roast@CORP.LOCAL:aa$bb"},
        "ghost": {"state": "absent"},
        "locked": {"state": "revoked"},
    }
    monkeypatch.setattr(
        k, "_probe_one",
        lambda user, domain, kdc: canned.get(user, {"state": "absent"}))

    findings = asyncio.run(k.kerberos_preauth_probe(
        "corp.local", "10.0.0.10",
        extra_users=["administrator", "svc_roast", "ghost", "locked"]))

    vtypes = [f["vuln_type"] for f in findings]
    assert "kerberos_user_enumeration" in vtypes
    assert "asrep_roasting" in vtypes

    enum = next(f for f in findings if f["vuln_type"] == "kerberos_user_enumeration")
    valid = set(enum["evidence"]["valid_users"])
    assert {"administrator", "svc_roast", "locked"} <= valid
    assert "ghost" not in valid

    roast = next(f for f in findings if f["vuln_type"] == "asrep_roasting")
    assert roast["severity"] == "high"
    assert roast["evidence"]["username"] == "svc_roast"
    assert roast["evidence"]["krb5asrep_hash"].startswith("$krb5asrep$23$")


def test_no_conclusive_response_yields_nothing(monkeypatch):
    # Every probe errors (KDC filtered/unreachable) → invent no enumeration finding.
    monkeypatch.setattr(k, "_probe_one",
                        lambda user, domain, kdc: {"state": "error"})
    findings = asyncio.run(k.kerberos_preauth_probe(
        "corp.local", "10.0.0.10", extra_users=["administrator"]))
    assert findings == []


def test_missing_domain_returns_empty():
    assert asyncio.run(k.kerberos_preauth_probe("", "10.0.0.10")) == []


def test_candidate_list_is_bounded(monkeypatch):
    seen: list[str] = []

    def _spy(user, domain, kdc):
        seen.append(user)
        return {"state": "absent"}

    monkeypatch.setattr(k, "_probe_one", _spy)
    asyncio.run(k.kerberos_preauth_probe(
        "corp.local", "10.0.0.10",
        extra_users=[f"u{i}" for i in range(500)], max_users=10))
    assert len(seen) == 10


# ── _probe_one classifier against genuine KDC bytes ──────────────────────────
# Regression for a false positive confirmed live: impacket's sendReceive() does
# NOT raise for KDC_ERR_PREAUTH_REQUIRED — it returns the raw KRB-ERROR bytes.
# The old code read "no exception" as "roastable", so EVERY pre-auth-required
# account was mis-reported as AS-REP roastable. _probe_one must decode the reply
# and only call it roastable when it is a real AS-REP.
def test_probe_one_preauth_required_is_not_roastable(monkeypatch):
    kerr = base64.b64decode("".join(_REAL_KRBERR_25_B64))
    monkeypatch.setattr(k, "sendReceive", lambda msg, dom, kdc: kerr)
    res = k._probe_one("alice", "HEAVEN.LOCAL", "127.0.0.1")
    assert res["state"] == "exists"          # protected account, NOT roastable
    assert "hash" not in res


def test_probe_one_real_asrep_is_roastable(monkeypatch):
    asrep = base64.b64decode("".join(_REAL_ASREP_AES_B64))
    monkeypatch.setattr(k, "sendReceive", lambda msg, dom, kdc: asrep)
    res = k._probe_one("alice", "HEAVEN.LOCAL", "127.0.0.1")
    assert res["state"] == "roastable"
    assert res["hash"].startswith("$krb5asrep$18$")  # aes256 hashcat layout


def test_probe_one_kerberos_errors_classify(monkeypatch):
    def _raise(code):
        def _sr(msg, dom, kdc):
            raise k.KerberosError(error=code)
        return _sr

    monkeypatch.setattr(k, "sendReceive", _raise(k._ERR_PRINCIPAL_UNKNOWN))
    assert k._probe_one("ghost", "HEAVEN.LOCAL", "127.0.0.1")["state"] == "absent"
    monkeypatch.setattr(k, "sendReceive", _raise(k._ERR_CLIENT_REVOKED))
    assert k._probe_one("locked", "HEAVEN.LOCAL", "127.0.0.1")["state"] == "revoked"


def test_format_asrep_hash_rc4_and_aes():
    from impacket.krb5.asn1 import AS_REP
    from pyasn1.codec.der import decoder, encoder
    aes_bytes = base64.b64decode("".join(_REAL_ASREP_AES_B64))
    # AES (etype 18): "$krb5asrep$18$user$REALM$<12B checksum>$<data>"
    h_aes = k._format_asrep_hash(aes_bytes, "alice", "HEAVEN.LOCAL")
    assert h_aes.startswith("$krb5asrep$18$alice$HEAVEN.LOCAL$")
    # Derive an RC4 (etype 23) variant from the same real structure and confirm
    # the classic crackable layout "$krb5asrep$23$user@REALM:<16B>$<rest>".
    rep = decoder.decode(aes_bytes, asn1Spec=AS_REP())[0]
    rep["enc-part"]["etype"] = 23
    rep["enc-part"]["cipher"] = bytes(range(48))
    h_rc4 = k._format_asrep_hash(encoder.encode(rep), "alice", "HEAVEN.LOCAL")
    assert h_rc4.startswith("$krb5asrep$23$alice@HEAVEN.LOCAL:")
    assert h_rc4.count("$") == 4  # $krb5asrep$23$<...>:<hex>$<hex>

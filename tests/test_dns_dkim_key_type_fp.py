"""Regression: the DKIM weak-key finding (HIGH) must not fire on Ed25519 keys.

``_scan_email_security`` sizes a DKIM public key by base64 length and flags it as
"DKIM Key Too Short ... factorizable ... upgrade to 2048 bits" when it computes
under 1024 bits. That heuristic is only valid for RSA keys. A k=ed25519 key
(RFC 8463) is 256 bits by design and is an elliptic curve, not an RSA modulus —
it is not factorizable and sizing it against the RSA threshold reported a modern,
correct key as weak (a HIGH-severity false positive). The fix reads the k= tag
and applies the length heuristic only to RSA (the default when k= is absent).

See heaven/recon/dns_recon.py (_scan_email_security).
"""
from __future__ import annotations

import asyncio

import heaven.recon.dns_recon as dr

# A real-shaped Ed25519 DKIM record: 32 raw key bytes -> 44 base64 chars.
_ED25519 = '"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="'
# A genuinely weak ~512-bit RSA key (k=rsa, short modulus) must still be caught.
_RSA_512 = '"v=DKIM1; k=rsa; p=' + ("A" * 128) + '"'
# A healthy ~2048-bit RSA key with the k= tag omitted (RSA is the default).
_RSA_2048 = '"v=DKIM1; p=' + ("A" * 392) + '"'


def _resolver_for(dkim_record: str):
    """A _resolve stand-in: strong SPF+DMARC (no noise) and one DKIM selector."""
    def _resolve(name, rtype, nameservers=None, timeout=5.0):
        if rtype == "TXT" and name == "example.com":
            return ["v=spf1 -all"]
        if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; pct=100"]
        if name == "default._domainkey.example.com":
            return [dkim_record]
        return []
    return _resolve


def _weak_findings(dkim_record: str, monkeypatch) -> list[dict]:
    monkeypatch.setattr(dr, "_resolve", _resolver_for(dkim_record))
    findings = asyncio.run(dr._scan_email_security("example.com"))
    return [f for f in findings if f["vuln_type"] == "dkim_weak_key"]


def test_ed25519_key_not_flagged_as_weak(monkeypatch):
    assert _weak_findings(_ED25519, monkeypatch) == []


def test_weak_rsa_key_still_flagged(monkeypatch):
    weak = _weak_findings(_RSA_512, monkeypatch)
    assert len(weak) == 1
    assert weak[0]["severity"] == "high"


def test_healthy_rsa_key_without_k_tag_not_flagged(monkeypatch):
    # k= absent must default to RSA so a healthy 2048-bit key is judged on length.
    assert _weak_findings(_RSA_2048, monkeypatch) == []

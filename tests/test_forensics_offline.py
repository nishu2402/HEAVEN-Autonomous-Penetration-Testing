"""Tests for offline pcap + crypto analyzers (no live target)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from heaven.forensics.crypto import (
    _decode_variants,
    _md4,
    _ntlm,
    analyze_crypto,
    crack_hash,
    identify_hash,
)


# ── crypto: MD4/NTLM correctness (known vectors) ────────────────────────────
def test_md4_empty_vector():
    assert _md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_ntlm_known_vector():
    assert _ntlm("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_identify_hash():
    assert "MD5" in identify_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert "SHA256" in identify_hash("a" * 64)
    assert identify_hash("$6$abc$def")[0].startswith("sha512crypt")
    assert identify_hash("$2b$10$abc")[0] == "bcrypt"


def test_crack_raw_hashes():
    assert crack_hash(hashlib.md5(b"password").hexdigest(),  # noqa: S324
                      ["nope", "password"])["plaintext"] == "password"
    assert crack_hash(hashlib.sha256(b"secret").hexdigest(),
                      ["secret"])["plaintext"] == "secret"
    assert crack_hash(_ntlm("msfadmin"), ["msfadmin"])["plaintext"] == "msfadmin"


def test_crack_returns_none_when_absent():
    assert crack_hash(hashlib.md5(b"unguessable-xyz").hexdigest(),  # noqa: S324
                      ["a", "b", "c"]) is None


def test_analyze_hash_file(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text(
        f"alice:{hashlib.md5(b'password').hexdigest()}\n"      # noqa: S324
        f"bob:{hashlib.sha1(b'admin').hexdigest()}\n")          # noqa: S324
    r = analyze_crypto(str(f))
    assert r["report"]["cracked"] == 2
    vts = {x["vuln_type"] for x in r["findings"]}
    assert "weak_password_cracked" in vts


def test_decode_base64():
    variants = _decode_variants(base64.b64encode(b"admin:secret").decode())
    assert any(v["scheme"] == "base64" and v["decoded"] == "admin:secret"
               for v in variants)


# ── pcap: synthetic capture ─────────────────────────────────────────────────
def _write_test_pcap(path):
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import Raw, wrpcap
    from scapy.layers.inet import IP, TCP, UDP
    pkts = [
        IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=44000, dport=21, flags="PA")
        / Raw(load=b"USER msfadmin\r\n"),
        IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=44000, dport=21, flags="PA")
        / Raw(load=b"PASS msfadmin\r\n"),
        IP(src="10.0.0.5", dst="10.0.0.80") / TCP(sport=44002, dport=80, flags="PA")
        / Raw(load=(b"GET / HTTP/1.1\r\nAuthorization: Basic "
                    + base64.b64encode(b"admin:secret") + b"\r\n\r\n")),
    ]
    for i in range(700):
        pkts.append(IP(src=f"10.0.0.{i % 254 + 1}", dst="10.0.0.99")
                    / TCP(sport=1000 + i, dport=80, flags="S"))
    pkts.append(IP(src="8.8.8.8", dst="10.0.0.9") / UDP(sport=53, dport=33333)
                / Raw(load=b"A" * 900))
    wrpcap(str(path), pkts)


def test_analyze_pcap(tmp_path):
    pytest.importorskip("scapy")
    from heaven.forensics.pcap import analyze_pcap
    pcap = tmp_path / "t.pcap"
    _write_test_pcap(pcap)
    r = analyze_pcap(str(pcap))
    creds = r["report"]["cleartext_credentials"]
    assert any(c["type"] == "ftp_cleartext" for c in creds)
    assert any(c["type"] == "http_basic" and c["detail"] == "admin:secret" for c in creds)
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "cleartext_credentials" in vts
    assert "syn_flood" in vts
    assert "amplification_traffic" in vts

"""Credential-free SSH transport crypto audit (heaven/vulnscan/ssh_audit.py).

Covers the KEXINIT name-list parser, the weak-algorithm classification (the
ssh-dss / ssh-rsa-SHA1 case behind the reported missed finding), and an
end-to-end run over a fake socket that serves a real banner + KEXINIT packet.
"""
from __future__ import annotations

import asyncio
import struct

import heaven.vulnscan.ssh_audit as sa


def _nl(items):
    s = ",".join(items).encode()
    return struct.pack(">I", len(s)) + s


def _kexinit_payload(kex, host_keys, enc, mac):
    p = bytes([sa._SSH_MSG_KEXINIT]) + b"\x00" * 16
    p += _nl(kex) + _nl(host_keys)
    p += _nl(enc) + _nl(enc)          # enc c2s / s2c
    p += _nl(mac) + _nl(mac)          # mac c2s / s2c
    p += _nl(["none"]) + _nl(["none"])          # compression
    p += _nl([]) + _nl([])                       # languages
    p += b"\x00" + b"\x00\x00\x00\x00"          # first_kex_follows + reserved
    return p


def _ssh_packet(payload: bytes) -> bytes:
    """Frame a payload as a plaintext SSH binary packet (RFC 4253 §6)."""
    pad = 8 - ((4 + 1 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    pkt_len = 1 + len(payload) + pad
    return struct.pack(">I", pkt_len) + bytes([pad]) + payload + b"\x00" * pad


# ── parser ────────────────────────────────────────────────────────────────────

def test_parse_kexinit_roundtrip():
    payload = _kexinit_payload(
        ["curve25519-sha256"], ["ssh-ed25519", "ssh-rsa"],
        ["aes256-gcm@openssh.com"], ["hmac-sha2-256"])
    algos = sa.parse_kexinit(payload)
    assert algos["kex"] == ["curve25519-sha256"]
    assert algos["host_keys"] == ["ssh-ed25519", "ssh-rsa"]
    assert algos["enc_c2s"] == ["aes256-gcm@openssh.com"]


def test_parse_kexinit_rejects_non_kexinit():
    import pytest
    with pytest.raises(ValueError):
        sa.parse_kexinit(bytes([21]) + b"\x00" * 20)


def test_read_namelist_truncation_raises():
    import pytest
    with pytest.raises(ValueError):
        sa._read_namelist(b"\x00\x00\x00\x10ab", 0)   # claims 16 bytes, has 2


# ── classification ─────────────────────────────────────────────────────────────

def test_weak_host_keys_flagged():
    algos = sa.parse_kexinit(_kexinit_payload(
        ["curve25519-sha256"], ["rsa-sha2-512", "ssh-rsa", "ssh-dss"],
        ["aes256-gcm@openssh.com"], ["hmac-sha2-256"]))
    findings = sa.audit_algorithms("h", 22, algos)
    hk = [f for f in findings if f["vuln_type"] == "ssh_weak_host_key_algo"]
    assert len(hk) == 1
    assert hk[0]["severity"] == "high"             # ssh-dss drives it to high
    assert "ssh-dss" in hk[0]["title"] and "ssh-rsa" in hk[0]["title"]


def test_clean_algorithm_set_no_findings():
    algos = sa.parse_kexinit(_kexinit_payload(
        ["curve25519-sha256", "ecdh-sha2-nistp256"],
        ["ssh-ed25519", "rsa-sha2-512"],
        ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"]))
    assert sa.audit_algorithms("h", 22, algos) == []


def test_weak_kex_cipher_mac_grouped():
    algos = sa.parse_kexinit(_kexinit_payload(
        ["curve25519-sha256", "diffie-hellman-group1-sha1"],
        ["ssh-ed25519"],
        ["aes256-gcm@openssh.com", "3des-cbc", "arcfour", "aes128-cbc"],
        ["hmac-sha2-256", "hmac-md5", "umac-64@openssh.com"]))
    findings = {f["vuln_type"]: f for f in sa.audit_algorithms("h", 22, algos)}
    assert findings["ssh_weak_kex"]["severity"] == "high"      # group1-sha1
    assert findings["ssh_weak_cipher"]["severity"] == "medium"  # 3des/arcfour
    assert "aes128-cbc" in findings["ssh_weak_cipher"]["title"]  # CBC fallback rule
    assert findings["ssh_weak_mac"]["severity"] == "medium"     # hmac-md5


def test_classify_kex_sha1_fallback():
    assert sa._classify_kex("diffie-hellman-group16-sha1")[0] == "low"
    assert sa._classify_kex("curve25519-sha256") is None


def test_classify_cipher_cbc_fallback():
    assert sa._classify_cipher("aes192-cbc")[0] == "low"
    assert sa._classify_cipher("aes256-gcm@openssh.com") is None


# ── end-to-end over a fake socket ──────────────────────────────────────────────

class _BufferSock:
    def __init__(self, data: bytes):
        self._buf = data

    def settimeout(self, *_):
        pass

    def sendall(self, *_):
        pass

    def recv(self, n=4096):
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def close(self):
        pass


def test_run_ssh_audit_end_to_end(monkeypatch):
    payload = _kexinit_payload(
        ["curve25519-sha256"], ["ssh-rsa", "ssh-dss"],
        ["aes256-ctr", "3des-cbc"], ["hmac-sha2-256"])
    wire = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu\r\n" + _ssh_packet(payload)
    monkeypatch.setattr(sa.socket, "create_connection",
                        lambda *a, **k: _BufferSock(wire))
    res = sa._run_ssh_audit("h", 22)
    assert res.reachable and res.error is None
    assert res.software.startswith("OpenSSH_7.2p2")
    assert "ssh-dss" in res.host_keys
    vtypes = {f["vuln_type"] for f in res.findings}
    assert "ssh_weak_host_key_algo" in vtypes
    assert "ssh_weak_cipher" in vtypes


def test_aws_transfer_superseded_policy_flagged():
    algos = sa.parse_kexinit(_kexinit_payload(
        ["diffie-hellman-group14-sha1", "ecdh-sha2-nistp256"],
        ["rsa-sha2-512", "ssh-rsa"],
        ["aes256-ctr", "aes128-cbc"],
        ["hmac-sha2-256", "hmac-sha1"]))
    fs = sa.aws_transfer_findings("s-abc.server.transfer.eu-west-1.amazonaws.com",
                                  22, "SSH-2.0-AWS_SFTP_1.1", algos)
    assert len(fs) == 1
    assert fs[0]["vuln_type"] == "aws_transfer_superseded_policy"
    assert "ssh-rsa" in fs[0]["description"]


def test_aws_transfer_current_policy_not_flagged():
    # AWS Transfer endpoint offering only modern algorithms → no finding.
    algos = sa.parse_kexinit(_kexinit_payload(
        ["ecdh-sha2-nistp384", "curve25519-sha256"],
        ["rsa-sha2-512", "ecdsa-sha2-nistp384"],
        ["aes256-gcm@openssh.com", "aes256-ctr"],
        ["hmac-sha2-256", "hmac-sha2-512"]))
    assert sa.aws_transfer_findings(
        "s-abc.server.transfer.eu-west-1.amazonaws.com", 22,
        "SSH-2.0-AWS_SFTP_1.1", algos) == []


def test_non_aws_host_never_gets_transfer_finding():
    algos = sa.parse_kexinit(_kexinit_payload(
        ["diffie-hellman-group14-sha1"], ["ssh-rsa"],
        ["aes128-cbc"], ["hmac-sha1"]))
    assert sa.aws_transfer_findings("normal.example.com", 22,
                                    "SSH-2.0-OpenSSH_8.0", algos) == []


def test_scan_ssh_async_wrapper(monkeypatch):
    payload = _kexinit_payload(
        ["curve25519-sha256"], ["ssh-ed25519"],
        ["aes256-gcm@openssh.com"], ["hmac-sha2-256"])
    wire = b"SSH-2.0-OpenSSH_9.6\r\n" + _ssh_packet(payload)
    monkeypatch.setattr(sa.socket, "create_connection",
                        lambda *a, **k: _BufferSock(wire))
    out = asyncio.run(sa.scan_ssh("h", 22))
    assert out["software"] == "OpenSSH_9.6"
    assert out["findings"] == []      # clean modern set
    assert out["host_keys"] == ["ssh-ed25519"]

"""Tests for the deepened offline-artifact analyzers: protocol-aware pcap
analysis, the smart multi-scheme decoder, and the report renderer."""

from __future__ import annotations

import base64
import gzip
import io
import json
import struct

import pytest

from heaven.forensics.crypto import identify_hash
from heaven.forensics.decoder import smart_decode


# ── smart decoder ─────────────────────────────────────────────────────────────
def test_decode_base64_credentials_finding():
    r = smart_decode("YWRtaW46c2VjcmV0")           # base64("admin:secret")
    assert r["best"]["scheme"] == "base64"
    assert any("admin:secret" in d["decoded"] for d in r["decodings"])
    assert any(f["vuln_type"] == "decoded_credentials" for f in r["findings"])


def test_decode_nested_layers_chain():
    inner = base64.b64encode(b"nested secret here").decode()
    r = smart_decode(base64.b64encode(inner.encode()).decode())
    chains = [d.get("chain") for d in r["decodings"] if d.get("chain")]
    assert chains and len(chains[0]) >= 2


def test_decode_gzip_inside_base64_one_shot():
    payload = base64.b64encode(gzip.compress(b"super secret compressed")).decode()
    r = smart_decode(payload)
    assert r["best"]["decoded"] == "super secret compressed"
    assert "gzip" in r["best"]["scheme"]


def test_decode_hex_and_morse_and_binary():
    assert smart_decode("48656c6c6f")["best"]["decoded"] == "Hello"
    assert smart_decode(".... . .-.. .-.. ---")["best"]["decoded"] == "HELLO"
    assert smart_decode("0100100001101001")["best"]["decoded"] == "Hi"


def test_decode_jwt_alg_none_finding():
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    pl = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).rstrip(b"=").decode()
    r = smart_decode(f"{hdr}.{pl}.")
    assert r.get("jwt") and r["jwt"]["alg"] == "none"
    assert any(f["vuln_type"] == "jwt_alg_none" for f in r["findings"])


def test_decode_decompression_bomb_is_rejected():
    bomb = gzip.compress(b"\x00" * (40 * 1024 * 1024))
    r = smart_decode(base64.b64encode(bomb).decode())
    # The oversized inflate must be refused — no gzip-expanded decoding surfaces.
    assert not any("gzip" in d["scheme"] for d in r["decodings"])
    assert json.dumps(r)                            # still JSON-serialisable


def test_decode_result_is_json_safe():
    for s in ["YWRtaW46c2VjcmV0", "deadbeef", "Uryyb", "%41%42%43"]:
        json.dumps(smart_decode(s))


# ── hash identification ───────────────────────────────────────────────────────
@pytest.mark.parametrize("h,expect", [
    ("$argon2id$v=19$m=65536$abc", "Argon2id"),
    ("$krb5tgs$23$*u*$abcd", "Kerberos 5 TGS-REP (kerberoast)"),
    ("{SSHA}abcdefgh", "LDAP salted-SHA1"),
    ("pbkdf2_sha256$260000$s$h", "Django PBKDF2-SHA256"),
])
def test_identify_hash_expanded(h, expect):
    assert identify_hash(h)[0] == expect


def test_identify_hash_backcompat():
    assert "MD5" in identify_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert "SHA256" in identify_hash("a" * 64)
    assert identify_hash("$2b$10$abc")[0] == "bcrypt"


# ── deep pcap ─────────────────────────────────────────────────────────────────
def _ntlm_type2(challenge=b"\x11\x22\x33\x44\x55\x66\x77\x88"):
    sig = b"NTLMSSP\x00" + struct.pack("<I", 2)
    return sig + struct.pack("<HHI", 0, 0, 48) + struct.pack("<I", 0x00088205) \
        + challenge + b"\x00" * 8


def _ntlm_type3(user="alice", domain="CORP"):
    nt = b"\xaa" * 16 + b"\x01\x01\x00\x00" + b"\x00" * 40
    u = user.encode("utf-16-le")
    d = domain.encode("utf-16-le")
    ws = "WS01".encode("utf-16-le")
    lm = b"\x00" * 24
    sig = b"NTLMSSP\x00" + struct.pack("<I", 3)
    off = 64
    parts = []

    def field(data):
        nonlocal off
        f = struct.pack("<HHI", len(data), len(data), off)
        off += len(data)
        parts.append(data)
        return f
    header = sig + field(lm) + field(nt) + field(d) + field(u) + field(ws) \
        + struct.pack("<HHI", 0, 0, off) + struct.pack("<I", 0x00088205)
    return header.ljust(64, b"\x00") + b"".join(parts)


def _write_deep_pcap(path):
    from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR

    def stream(src, dst, sport, dport, payload):
        return [Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=payload)]
    pkts = []
    pkts += stream("10.0.0.5", "10.0.0.9", 45001, 21, b"USER admin\r\n")
    pkts += stream("10.0.0.5", "10.0.0.9", 45001, 21, b"PASS S3cr3tFtp!\r\n")
    # SNMP public
    snmp = bytes.fromhex("302902010104067075626c6963a01c0201000201000201003011300f06082b060102010101000500")
    pkts.append(Ether() / IP(src="10.0.0.8", dst="10.0.0.40") / UDP(sport=5, dport=161) / Raw(load=snmp))
    # ARP conflict
    pkts.append(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:01", pdst="10.0.0.5"))
    pkts.append(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="de:ad:be:ef:00:99", pdst="10.0.0.5"))
    # DNS query
    pkts.append(Ether() / IP(src="10.0.0.6", dst="10.0.0.53") / UDP(sport=5, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="example.com")))
    # NTLM type2 then type3 (same flow)
    pkts += stream("10.0.0.9", "10.0.0.50", 45011, 445, b"\xffSMB" + _ntlm_type2())
    pkts += stream("10.0.0.9", "10.0.0.50", 45011, 445, b"\xffSMB" + _ntlm_type3())
    wrpcap(str(path), pkts)


def test_deep_pcap_findings(tmp_path):
    pytest.importorskip("scapy")
    from heaven.forensics.pcap import analyze_pcap
    p = tmp_path / "deep.pcap"
    _write_deep_pcap(p)
    r = analyze_pcap(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "cleartext_credentials" in vts
    assert "snmp_default_community" in vts
    assert "arp_spoofing" in vts
    assert "ntlm_hash_captured" in vts
    # rich report is always present
    assert r["report"]["ntlm_hashes"] and r["report"]["ntlm_hashes"][0]["format"] == "NetNTLMv2"
    assert r["report"]["snmp_communities"][0]["community"] == "public"
    assert "protocol_breakdown" in r["report"]


def test_pcap_ntlm_hash_is_hashcat_format(tmp_path):
    pytest.importorskip("scapy")
    from heaven.forensics.pcap import analyze_pcap
    p = tmp_path / "ntlm.pcap"
    _write_deep_pcap(p)
    h = analyze_pcap(str(p))["report"]["ntlm_hashes"][0]
    assert h["hash"].startswith("alice::CORP:")
    assert h["hashcat_mode"] == 5600


# ── report renderer ───────────────────────────────────────────────────────────
def test_report_render_markdown_and_html():
    from heaven.forensics.report import render_report
    result = {
        "kind": "pcap", "filename": "capture.pcap",
        "summary": "10 packets · 1 finding(s)",
        "findings": [{"vuln_type": "cleartext_credentials", "severity": "high",
                      "title": "Creds on the wire", "description": "FTP creds seen.",
                      "cwe": "CWE-319", "confidence": 0.9,
                      "evidence": {"credentials": [{"user": "a"}]}}],
        "report": {"packets": 10, "protocol_breakdown": {"TCP": 8, "UDP": 2},
                   "cleartext_credentials": [{"protocol": "FTP", "detail": "USER a"}]},
    }
    md, mt_md, ext_md = render_report(result, "md")
    assert "# HEAVEN Offline Artifact Analysis" in md and "Creds on the wire" in md
    assert ext_md == "md"
    html_s, mt_html, ext_html = render_report(result, "html")
    assert html_s.startswith("<!doctype html>") and "Creds on the wire" in html_s
    assert "<script" not in html_s.lower()          # user values are escaped
    js, _, ext_js = render_report(result, "json")
    assert json.loads(js)["kind"] == "pcap" and ext_js == "json"


def test_report_html_escapes_injection():
    from heaven.forensics.report import render_html
    result = {"kind": "binary", "findings": [
        {"severity": "info", "title": "<script>alert(1)</script>", "description": "x"}],
        "report": {}}
    out = render_html(result)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_report_render_pdf_is_valid_and_covers_sections():
    pytest.importorskip("reportlab")
    pytest.importorskip("pypdf")
    from pypdf import PdfReader

    from heaven.forensics.report import render_pdf
    result = {
        "kind": "pcap", "filename": "capture.pcapng",
        "summary": "42 packets · 2 finding(s)",
        "findings": [
            {"vuln_type": "cleartext_credentials", "severity": "high",
             "title": "FTP credentials on the wire", "description": "USER/PASS seen.",
             "cwe": "CWE-319", "confidence": 0.9,
             "evidence": {"credentials": [{"user": "admin"}]}},
            {"vuln_type": "weak_tls_version", "severity": "medium",
             "title": "Legacy TLS 1.0 negotiated", "description": "Downgrade risk."},
        ],
        "report": {"packets": 42, "protocol_breakdown": {"TCP": 40, "UDP": 2},
                   "dns_queries": [{"query": "tunnel.evil.example", "type": "TXT"}]},
    }
    pdf = render_pdf(result)
    assert pdf[:5] == b"%PDF-"
    text = "\n".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(pdf)).pages)
    assert "Offline Artifact Analysis" in text
    assert "FTP credentials on the wire" in text
    assert "Protocol breakdown" in text


def test_report_render_pdf_no_findings():
    pytest.importorskip("reportlab")
    from heaven.forensics.report import render_pdf
    pdf = render_pdf({"kind": "binary", "filename": "a.out", "findings": [], "report": {}})
    assert pdf[:5] == b"%PDF-"


def test_report_render_pdf_escapes_injection():
    pytest.importorskip("reportlab")
    pytest.importorskip("pypdf")
    from pypdf import PdfReader

    from heaven.forensics.report import render_pdf
    # A finding whose title contains reportlab markup must not break the build or
    # inject markup — it renders as literal text.
    result = {"kind": "binary", "findings": [
        {"severity": "info", "title": "<font color='red'>x</font> & <b>y</b>",
         "description": "<para>z</para>"}], "report": {}}
    pdf = render_pdf(result)
    assert pdf[:5] == b"%PDF-"
    text = "\n".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(pdf)).pages)
    assert "<font" in text and "<b>y</b>" in text          # shown literally, not parsed

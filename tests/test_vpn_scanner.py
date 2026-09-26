"""OpenVPN control-channel exposure probe (heaven/vulnscan/vpn_scanner.py).

Verifies the packet builder, the opcode parser for both UDP and TCP framing, and
that a finding is emitted ONLY when the server actually returns a hard-reset
(proving the control channel is unauthenticated) — never on silence or noise.
"""
from __future__ import annotations

import asyncio
import struct

import heaven.vulnscan.vpn_scanner as vpn


def test_hard_reset_packet_shape():
    pkt = vpn.build_hard_reset_client_v2()
    assert len(pkt) == 14
    assert pkt[0] == 0x38               # opcode 7 << 3, key_id 0
    assert pkt[0] >> 3 == vpn._P_CONTROL_HARD_RESET_CLIENT_V2


def test_response_opcode_udp_and_tcp():
    # UDP: opcode is high 5 bits of byte 0. Server hard-reset V2 = opcode 8.
    udp_reply = bytes([8 << 3]) + b"\x00" * 8
    assert vpn.response_opcode(udp_reply, "udp") == 8
    # TCP: 2-byte length prefix, then the opcode byte.
    tcp_reply = struct.pack(">H", 9) + bytes([8 << 3]) + b"\x00" * 8
    assert vpn.response_opcode(tcp_reply, "tcp") == 8
    assert vpn.response_opcode(b"", "udp") is None
    assert vpn.response_opcode(b"\x00", "tcp") is None   # too short for TCP framing


def test_finding_when_server_hard_reset(monkeypatch):
    monkeypatch.setattr(vpn, "_openvpn_exchange",
                        lambda h, p, pr, timeout=5.0: bytes([8 << 3]) + b"\x11" * 8)
    res = vpn._run_openvpn_scan("vpn.example", 1194, "udp")
    assert res["openvpn_detected"] is True
    assert res["response_opcode"] == 8
    f = res["findings"]
    assert len(f) == 1
    assert f[0]["vuln_type"] == "openvpn_unauthenticated_control"
    assert f[0]["severity"] == "medium"


def test_no_finding_on_silence(monkeypatch):
    # tls-auth/tls-crypt server drops our packet → no reply → no detection.
    monkeypatch.setattr(vpn, "_openvpn_exchange",
                        lambda h, p, pr, timeout=5.0: None)
    res = vpn._run_openvpn_scan("vpn.example", 1194, "udp")
    assert res["openvpn_detected"] is False
    assert res["findings"] == []


def test_no_finding_on_non_openvpn_reply(monkeypatch):
    # Some unrelated UDP service answering: opcode 0 is not an OpenVPN opcode.
    monkeypatch.setattr(vpn, "_openvpn_exchange",
                        lambda h, p, pr, timeout=5.0: b"\x00\x01\x02\x03")
    res = vpn._run_openvpn_scan("vpn.example", 1194, "udp")
    assert res["openvpn_detected"] is False
    assert res["findings"] == []


def test_ack_only_reply_detected_but_no_reset_finding(monkeypatch):
    # P_ACK_V1 (opcode 5) confirms OpenVPN but is not a hard-reset → detected,
    # no unauthenticated-control finding (conservative: only resets prove it).
    monkeypatch.setattr(vpn, "_openvpn_exchange",
                        lambda h, p, pr, timeout=5.0: bytes([5 << 3]) + b"\x00" * 8)
    res = vpn._run_openvpn_scan("vpn.example", 1194, "udp")
    assert res["openvpn_detected"] is True
    assert res["findings"] == []


def test_scan_openvpn_both_protocols(monkeypatch):
    calls = []

    def _fake(h, p, pr, timeout=5.0):
        calls.append(pr)
        return bytes([8 << 3]) + b"\x00" * 8 if pr == "udp" else None

    monkeypatch.setattr(vpn, "_openvpn_exchange", _fake)
    out = asyncio.run(vpn.scan_openvpn("vpn.example", 1194, proto="both"))
    assert set(calls) == {"udp", "tcp"}
    assert len(out["findings"]) == 1        # only the UDP reset produced a finding


def test_udp_probe_bytes_match_builder():
    # The UDP sweep's inline 1194 probe must equal the canonical builder output,
    # or the sweep would send a malformed packet OpenVPN ignores.
    from heaven.recon.udp_scanner import UDP_SERVICE_PROBES
    assert UDP_SERVICE_PROBES[1194] == vpn.build_hard_reset_client_v2()

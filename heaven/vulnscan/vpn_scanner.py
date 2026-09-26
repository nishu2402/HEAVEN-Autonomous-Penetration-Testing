"""
HEAVEN — OpenVPN control-channel exposure probe.

Detects an OpenVPN server whose control channel answers *unauthenticated* control
packets, i.e. that is not protected by ``tls-auth`` / ``tls-crypt``. This is the
exact class behind the missed finding *"SSL VPN answers unauthenticated OpenVPN
control packets"* — HEAVEN previously labelled UDP/1194 "openvpn" but sent it only
a generic empty probe, which OpenVPN never answers, so the service was never even
detected.

How it works (read-only, no authentication, no exploitation):

OpenVPN's reliability layer opens with a ``P_CONTROL_HARD_RESET_CLIENT_V2`` packet
(opcode 7). A server WITHOUT ``tls-auth`` / ``tls-crypt`` replies with a
``P_CONTROL_HARD_RESET_SERVER_V2`` (opcode 8). A server WITH ``tls-auth`` /
``tls-crypt`` cannot verify our (absent) HMAC and silently drops the packet — so a
reply is positive proof that the control channel is unauthenticated. The reply
opcode is the evidence, so the finding is deterministic and false-positive-free.

Reference: OpenVPN protocol, `ssl_pkt.h` P_* opcodes; the hardening guidance to
always enable tls-auth/tls-crypt to hide the control channel from unauthenticated
peers (mitigating pre-auth DoS and TLS-stack attack surface).
"""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vpn_scanner")

# OpenVPN opcodes occupy the high 5 bits of the first byte; the low 3 bits are the
# key_id. opcode = first_byte >> 3.
_P_CONTROL_HARD_RESET_CLIENT_V2 = 7
_SERVER_RESET_OPCODES = {2, 8}          # HARD_RESET_SERVER_V1 (2) / _V2 (8)
_OPENVPN_OPCODES = {2, 4, 5, 8, 9}      # any of these confirms an OpenVPN speaker

# A fixed 8-byte client session id — its value is irrelevant to a reset, only its
# presence and the packet shape matter.
_SESSION_ID = b"\x48\x45\x41\x56\x45\x4e\x01\x02"


def build_hard_reset_client_v2(key_id: int = 0) -> bytes:
    """A P_CONTROL_HARD_RESET_CLIENT_V2 packet with no tls-auth HMAC.

    Layout: opcode/key_id(1) + session_id(8) + ack_array_len(1)=0 +
    message_packet_id(4)=0.
    """
    opcode = (_P_CONTROL_HARD_RESET_CLIENT_V2 << 3) | (key_id & 0x07)   # 0x38
    return bytes([opcode]) + _SESSION_ID + b"\x00" + b"\x00\x00\x00\x00"


def response_opcode(data: bytes, proto: str) -> Optional[int]:
    """Extract the OpenVPN opcode from a server reply, or None if not parseable.

    For TCP the datagram is framed by a 2-byte big-endian length prefix.
    """
    if not data:
        return None
    if proto == "tcp":
        if len(data) < 3:
            return None
        return data[2] >> 3
    return data[0] >> 3


def _openvpn_exchange(host: str, port: int, proto: str,
                      timeout: float = 5.0) -> Optional[bytes]:
    """Send one hard-reset and return the raw reply bytes (or None)."""
    packet = build_hard_reset_client_v2()
    try:
        if proto == "tcp":
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(struct.pack(">H", len(packet)) + packet)
                return s.recv(2048)
        else:  # udp
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(timeout)
                s.sendto(packet, (host, port))
                data, _ = s.recvfrom(2048)
                return data
            finally:
                s.close()
    except (socket.timeout, TimeoutError):
        return None
    except OSError as e:
        logger.debug("openvpn %s probe to %s:%s failed: %s", proto, host, port, e)
        return None


def _finding(host: str, port: int, proto: str, opcode: int) -> dict:
    return {
        "target": f"{host}:{port}/{proto}",
        "vuln_type": "openvpn_unauthenticated_control",
        "title": "OpenVPN Control Channel Answers Unauthenticated Packets "
                 "(no tls-auth/tls-crypt)",
        "severity": "medium",
        "description": (
            f"The OpenVPN server on {host}:{port}/{proto} replied to an "
            "unauthenticated P_CONTROL_HARD_RESET_CLIENT_V2 with a server hard-reset "
            f"(opcode {opcode}). This proves the control channel is not wrapped by "
            "tls-auth or tls-crypt: any unauthenticated peer can reach the server's "
            "TLS stack directly. That expands the pre-authentication attack surface "
            "(control-channel DoS, resource exhaustion, and exposure of the TLS "
            "implementation to remote attackers) and lets anyone fingerprint the "
            "VPN. Enable tls-crypt (preferred) or tls-auth so the server silently "
            "drops packets lacking a valid HMAC."),
        "confidence": 0.97,
        "cve_id": "",
        "source": "vpn_scanner",
    }


def _run_openvpn_scan(host: str, port: int = 1194,
                      proto: str = "udp") -> dict:
    """Probe one host/port/proto for an unauthenticated OpenVPN control channel."""
    reply = _openvpn_exchange(host, port, proto)
    op = response_opcode(reply, proto)
    findings: list[dict] = []
    detected = op in _OPENVPN_OPCODES if op is not None else False
    if op in _SERVER_RESET_OPCODES:
        findings.append(_finding(host, port, proto, op))
    return {
        "target": f"{host}:{port}/{proto}",
        "openvpn_detected": detected,
        "response_opcode": op,
        "findings": findings,
    }


async def scan_openvpn(host: str, port: int = 1194,
                       proto: str = "udp") -> dict:
    """Async entry point. proto = "udp" | "tcp" | "both"."""
    loop = asyncio.get_running_loop()
    protos = ("udp", "tcp") if proto == "both" else (proto,)
    findings: list[dict] = []
    detected = False
    opcode: Optional[int] = None
    for pr in protos:
        res = await loop.run_in_executor(None, _run_openvpn_scan, host, port, pr)
        findings.extend(res.get("findings", []))
        detected = detected or res.get("openvpn_detected", False)
        if res.get("response_opcode") is not None:
            opcode = res["response_opcode"]
    if findings:
        logger.info("OpenVPN unauthenticated control channel: %s:%s", host, port)
    return {
        "target": f"{host}:{port}",
        "openvpn_detected": detected,
        "response_opcode": opcode,
        "findings": findings,
    }

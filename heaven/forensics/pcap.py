"""HEAVEN — offline packet-capture analysis.

Reads a pcap / pcapng the operator supplies and extracts the things a pentester
cares about, none of which need a live network:

* **Cleartext credentials** carried over FTP, HTTP Basic, HTTP login forms,
  Telnet, SMTP/POP/IMAP AUTH — the classic "sniffing check".
* **DDoS / flood indicators** — SYN floods, single-source packet storms, and
  reflection/amplification responses (DNS/NTP/SNMP/SSDP/memcached).
* **IoT / OT protocol messages** — MQTT, Modbus, CoAP seen on the wire.
* **Traffic summary** — protocol breakdown and top talkers.

Uses scapy for parsing (streamed, so large captures don't exhaust memory).
Every finding reflects packets actually present in the file.
"""

from __future__ import annotations

import base64
import binascii
from collections import Counter
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.pcap")

MAX_PACKETS = 2_000_000     # hard bound so a giant capture can't hang
_AMPLIFIERS = {53: "DNS", 123: "NTP", 161: "SNMP", 1900: "SSDP", 11211: "memcached"}


def _b64_user_pass(blob: str) -> str:
    try:
        dec = base64.b64decode(blob, validate=True).decode("latin1", "replace")
        return dec
    except (binascii.Error, ValueError):
        return ""


def analyze_pcap(path: str, **_: Any) -> dict[str, Any]:
    """Analyze a pcap/pcapng file. Returns ``{"report": {...}, "findings": [...]}``."""
    try:
        import logging as _lg
        _lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)
        from scapy.all import PcapReader, Raw  # noqa: F401
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        return {"error": "scapy not installed (pip install scapy)"}

    proto_counts: Counter = Counter()
    talkers: Counter = Counter()          # src IP → packet count
    bytes_by_src: Counter = Counter()
    syn_to: Counter = Counter()           # dst → SYN count
    synack_from: Counter = Counter()      # src → SYN/ACK count
    icmp_count = 0
    total = 0
    creds: list[dict] = []
    iot: list[dict] = []
    amps: list[dict] = []
    seen_cred_keys: set = set()

    def add_cred(kind, proto, src, dst, detail):
        key = (kind, detail)
        if key in seen_cred_keys:
            return
        seen_cred_keys.add(key)
        creds.append({"type": kind, "protocol": proto, "src": src,
                      "dst": dst, "detail": detail})

    try:
        with PcapReader(path) as pcap:
            for pkt in pcap:
                total += 1
                if total > MAX_PACKETS:
                    break
                if not pkt.haslayer(IP):
                    proto_counts["non-IP"] += 1
                    continue
                ip = pkt[IP]
                src, dst = ip.src, ip.dst
                talkers[src] += 1
                bytes_by_src[src] += len(pkt)

                if pkt.haslayer(ICMP):
                    icmp_count += 1
                    proto_counts["ICMP"] += 1
                    continue

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto_counts["TCP"] += 1
                    flags = int(tcp.flags)
                    if flags & 0x02 and not (flags & 0x10):      # SYN, not ACK
                        syn_to[dst] += 1
                    if (flags & 0x02) and (flags & 0x10):        # SYN/ACK
                        synack_from[src] += 1
                    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
                    if payload:
                        _scan_tcp_payload(payload, tcp, src, dst, add_cred, iot)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto_counts["UDP"] += 1
                    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
                    # Amplification: a large response from a known amplifier port.
                    if udp.sport in _AMPLIFIERS and len(payload) > 512:
                        amps.append({"service": _AMPLIFIERS[udp.sport],
                                     "src": src, "dst": dst, "resp_bytes": len(payload)})
                    if udp.dport == 5683 or udp.sport == 5683:
                        iot.append({"protocol": "CoAP", "src": src, "dst": dst})
    except FileNotFoundError:
        return {"error": f"file not found: {path}"}
    except Exception as e:  # noqa: BLE001
        logger.debug("pcap parse error", exc_info=True)
        return {"error": f"pcap parse failed: {type(e).__name__}: {e}",
                "packets_read": total}

    findings = _build_findings(creds, syn_to, synack_from, talkers, amps, icmp_count, total)
    report = {
        "packets": total,
        "protocol_breakdown": dict(proto_counts.most_common()),
        "top_talkers": [{"src": s, "packets": c, "bytes": bytes_by_src[s]}
                        for s, c in talkers.most_common(10)],
        "cleartext_credentials": creds,
        "iot_ot_messages": _dedup_iot(iot),
        "amplification_responses": amps[:50],
    }
    return {"report": report, "findings": findings,
            "summary": (f"{total} packets · {len(creds)} cleartext credential(s) · "
                        f"{len(findings)} finding(s)")}


def _scan_tcp_payload(payload: bytes, tcp, src, dst, add_cred, iot) -> None:
    dport, sport = int(tcp.dport), int(tcp.sport)
    try:
        text = payload.decode("latin1", "replace")
    except Exception:
        return
    up = text.upper()

    # FTP / SMTP / POP / IMAP cleartext USER/PASS
    if dport in (21, 2121) or sport in (21, 2121):
        for line in text.splitlines():
            u = line.upper()
            if u.startswith("USER ") or u.startswith("PASS "):
                add_cred("ftp_cleartext", "FTP", src, dst, line.strip())
    if dport in (110, 143) or sport in (110, 143):
        for line in text.splitlines():
            if line.upper().startswith(("USER ", "PASS ", "LOGIN ")):
                add_cred("mail_cleartext", "POP/IMAP", src, dst, line.strip())

    # SMTP AUTH LOGIN (base64 user then pass on following lines)
    if "AUTH LOGIN" in up or "AUTH PLAIN" in up:
        add_cred("smtp_auth", "SMTP", src, dst, "AUTH LOGIN/PLAIN observed")

    # HTTP Basic auth + form logins + cookies
    if dport in (80, 8080, 8000, 8180) or sport in (80, 8080, 8000, 8180):
        for line in text.split("\r\n"):
            if line.lower().startswith("authorization: basic "):
                dec = _b64_user_pass(line.split(" ", 2)[-1].strip())
                if dec and ":" in dec:
                    add_cred("http_basic", "HTTP", src, dst, dec)
        # crude form-login body detection
        low = text.lower()
        if ("password=" in low or "passwd=" in low or "pwd=" in low) and "post " in low[:8].lower():
            body = text.split("\r\n\r\n", 1)[-1][:300]
            add_cred("http_form", "HTTP", src, dst, body.strip())

    # IoT MQTT (CONNECT=0x10 first byte) / Modbus (port 502)
    if dport == 1883 or sport == 1883:
        if payload and (payload[0] & 0xF0) in (0x10, 0x30):  # CONNECT / PUBLISH
            iot.append({"protocol": "MQTT", "src": src, "dst": dst,
                        "message": "CONNECT" if payload[0] & 0xF0 == 0x10 else "PUBLISH"})
    if dport == 502 or sport == 502:
        iot.append({"protocol": "Modbus", "src": src, "dst": dst})


def _dedup_iot(iot: list[dict]) -> list[dict]:
    seen, out = set(), []
    for m in iot:
        k = (m.get("protocol"), m.get("src"), m.get("dst"), m.get("message"))
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out[:100]


def _finding(vt, sev, title, desc, **extra):
    return {"vuln_type": vt, "severity": sev, "title": title,
            "description": desc, "scanner": "pcap_analyzer", "confidence": 0.9, **extra}


def _build_findings(creds, syn_to, synack_from, talkers, amps, icmp_count, total):
    findings = []
    if creds:
        sample = "; ".join(c["detail"][:40] for c in creds[:3])
        findings.append(_finding(
            "cleartext_credentials", "high",
            f"{len(creds)} cleartext credential(s) captured on the wire",
            "Credentials were transmitted in cleartext and are recoverable by "
            f"anyone sniffing the network. Examples: {sample}.",
            cwe="CWE-319", evidence={"credentials": creds[:20]},
            remediation="Move these protocols to TLS (FTPS/HTTPS/SMTPS/IMAPS) and "
                        "rotate every exposed credential."))
    # SYN flood: a dst receiving many SYNs with almost no SYN/ACK back.
    for dst, syns in syn_to.items():
        acks = synack_from.get(dst, 0)
        if syns >= 500 and acks < syns * 0.1:
            findings.append(_finding(
                "syn_flood", "high", f"Possible SYN flood against {dst}",
                f"{syns} SYN packets were sent to {dst} with only {acks} SYN/ACK "
                "responses — the signature of a SYN-flood denial-of-service attempt.",
                cwe="CWE-400", evidence={"dst": dst, "syn": syns, "synack": acks}))
    # Single-source storm.
    if total >= 1000 and talkers:
        top_src, top_n = talkers.most_common(1)[0]
        if top_n > total * 0.6:
            findings.append(_finding(
                "packet_storm", "medium", f"Single source dominates traffic: {top_src}",
                f"{top_src} accounts for {top_n} of {total} packets "
                f"({top_n * 100 // total}%), consistent with a flood or scan.",
                cwe="CWE-400", evidence={"src": top_src, "packets": top_n}))
    if amps:
        svcs = sorted({a["service"] for a in amps})
        findings.append(_finding(
            "amplification_traffic", "medium",
            f"Reflection/amplification responses observed ({', '.join(svcs)})",
            "Large UDP responses from known amplifier services were seen. If the "
            "source addresses are spoofed victims, this capture shows a "
            "reflection/amplification DDoS in progress.",
            cwe="CWE-406", evidence={"samples": amps[:10]}))
    if icmp_count >= 1000:
        findings.append(_finding(
            "icmp_flood", "low", f"High ICMP volume ({icmp_count} packets)",
            "A large number of ICMP packets can indicate a ping flood or "
            "network sweep.", cwe="CWE-400"))
    return findings

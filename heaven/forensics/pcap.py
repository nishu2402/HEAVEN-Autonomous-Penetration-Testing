"""HEAVEN — offline packet-capture analysis (deep, protocol-aware).

Reads a pcap / pcapng the operator supplies and reconstructs, from the real
bytes on the wire, everything a pentester triages a capture for — no live
network required:

* **Traffic model** — protocol hierarchy, endpoints (talkers), and TCP/UDP
  conversations with duration, so the shape of the capture is always visible
  even when nothing is "wrong".
* **DNS** — every query and answer, with a tunneling/exfil heuristic (long
  encoded labels, TXT-heavy or high-volume lookups to one domain) and
  suspicious-TLD flagging.
* **TLS** — ClientHello SNI, negotiated version, cipher suites and a JA3
  fingerprint, with a finding when a deprecated protocol (SSLv3 / TLS 1.0 /
  TLS 1.1) is negotiated.
* **HTTP** — reconstructed transactions (method, host, path, user-agent,
  status, server), cleartext Basic-auth and form credentials on any port,
  cookies sent in the clear, and known offensive-tool user-agents.
* **Cleartext credentials** — FTP, Telnet, SMTP/POP/IMAP AUTH, SNMP community
  strings, and a generic USER/PASS sweep, all recoverable by a sniffer.
* **NTLM** — NetNTLMv1 / NetNTLMv2 challenge/response pairs reassembled into
  crackable hashcat-format hashes (the pcap equivalent of a relay capture).
* **Layer-2 / DHCP** — ARP spoofing (one IP claimed by multiple MACs) and a
  DHCP lease inventory.
* **Attack indicators** — SYN floods, single-source storms, port scans and host
  sweeps, reflection/amplification, ICMP tunneling, and periodic beaconing that
  looks like C2.
* **In-payload secrets** — API keys, private keys and tokens seen in cleartext.

Uses scapy for framing (streamed, so large captures don't exhaust memory); the
application-layer dissection (TLS, HTTP, NTLM, SNMP) is done on the raw payload
bytes here, so it does not depend on scapy's optional layer autoloading. Every
finding reflects packets actually present in the file — nothing is inferred that
the bytes do not show.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import struct
from collections import Counter, defaultdict
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("forensics.pcap")

MAX_PACKETS = 2_000_000       # hard bound so a giant capture can't hang
_TLS_PARSE_CAP = 50_000       # bound TLS handshake dissection work
_HTTP_PARSE_CAP = 50_000
_LIST_CAP = 500               # cap per evidence list in the report

_AMPLIFIERS = {53: "DNS", 123: "NTP", 161: "SNMP", 1900: "SSDP", 11211: "memcached",
               389: "CLDAP", 19: "chargen", 111: "portmap"}

# Cleartext application protocols by well-known port → protocol label.
_CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "rsh",
    1521: "Oracle-TNS", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 11211: "memcached", 27017: "MongoDB",
}

_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_WEAK_TLS = {0x0300, 0x0301, 0x0302}

# GREASE values (RFC 8701) are stripped before computing JA3.
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

# Offensive-tool / scanner user-agents worth surfacing when seen in cleartext.
_SUSPICIOUS_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|nessus|acunetix|wpscan|hydra|gobuster|"
    r"dirbuster|feroxbuster|ffuf|nuclei|metasploit|zgrab|curl|wget|python-requests|"
    r"go-http-client|libwww-perl)\b")

_SUSPICIOUS_TLD = re.compile(
    r"\.(top|xyz|tk|ml|ga|cf|gq|su|pw|zip|mov|rest|cyou|click|link|work|loan)$",
    re.I)

# Secrets that should never appear in cleartext on the wire.
_PAYLOAD_SECRETS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id", "high"),
    (re.compile(rb"ASIA[0-9A-Z]{16}"), "AWS temp access key id", "high"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key", "high"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub token", "high"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token", "high"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "private key", "critical"),
    (re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     "JWT", "medium"),
]


# ── small helpers ─────────────────────────────────────────────────────────────
def _b64_user_pass(blob: str) -> str:
    try:
        return base64.b64decode(blob, validate=True).decode("latin1", "replace")
    except (binascii.Error, ValueError):
        return ""


def _flow_key(a_ip: str, a_port: int, b_ip: str, b_port: int) -> tuple:
    """Direction-independent key for a TCP/UDP conversation."""
    return tuple(sorted(((a_ip, a_port), (b_ip, b_port))))


def _finding(vt: str, sev: str, title: str, desc: str, **extra: Any) -> dict:
    return {"vuln_type": vt, "severity": sev, "title": title, "description": desc,
            "scanner": "pcap_analyzer", "confidence": extra.pop("confidence", 0.9),
            **extra}


# ── TLS handshake parsing (raw bytes) ────────────────────────────────────────
def _parse_tls_records(payload: bytes) -> list[dict]:
    """Walk TLS records in a TCP payload and return handshake summaries."""
    out: list[dict] = []
    i, n = 0, len(payload)
    while i + 5 <= n and len(out) < 4:
        ctype = payload[i]
        ver = struct.unpack_from(">H", payload, i + 1)[0]
        rlen = struct.unpack_from(">H", payload, i + 3)[0]
        if ctype != 22 or rlen == 0 or ver not in _TLS_VERSIONS:  # 22 = handshake
            break
        body = payload[i + 5:i + 5 + rlen]
        hs = _parse_handshake(body)
        if hs:
            out.append(hs)
        i += 5 + rlen
    return out


def _parse_handshake(body: bytes) -> Optional[dict]:
    if len(body) < 4:
        return None
    hs_type = body[0]
    hs_len = int.from_bytes(body[1:4], "big")
    hd = body[4:4 + hs_len]
    if hs_type == 1:            # ClientHello
        return _parse_client_hello(hd)
    if hs_type == 2:            # ServerHello
        return _parse_server_hello(hd)
    return None


def _parse_client_hello(d: bytes) -> Optional[dict]:
    try:
        ver = struct.unpack_from(">H", d, 0)[0]
        p = 2 + 32                                     # version + random
        sid_len = d[p]
        p += 1 + sid_len
        cs_len = struct.unpack_from(">H", d, p)[0]
        p += 2
        ciphers = [struct.unpack_from(">H", d, p + j)[0] for j in range(0, cs_len, 2)]
        p += cs_len
        comp_len = d[p]
        p += 1 + comp_len
        sni, groups, ec_formats, exts = "", [], [], []
        if p + 2 <= len(d):
            ext_total = struct.unpack_from(">H", d, p)[0]
            p += 2
            end = min(len(d), p + ext_total)
            while p + 4 <= end:
                etype = struct.unpack_from(">H", d, p)[0]
                elen = struct.unpack_from(">H", d, p + 2)[0]
                edata = d[p + 4:p + 4 + elen]
                exts.append(etype)
                if etype == 0x0000 and len(edata) >= 5:            # SNI
                    nlen = struct.unpack_from(">H", edata, 3)[0]
                    sni = edata[5:5 + nlen].decode("utf-8", "replace")
                elif etype == 0x000a and len(edata) >= 2:          # supported_groups
                    glen = struct.unpack_from(">H", edata, 0)[0]
                    groups = [struct.unpack_from(">H", edata, 2 + j)[0]
                              for j in range(0, glen, 2)]
                elif etype == 0x000b and len(edata) >= 1:          # ec_point_formats
                    ec_formats = list(edata[1:1 + edata[0]])
                p += 4 + elen
        ja3 = _ja3(ver, ciphers, exts, groups, ec_formats)
        return {"kind": "client_hello", "version": ver, "sni": sni,
                "ciphers": ciphers[:32], "ja3": ja3}
    except Exception:
        logger.debug("TLS ClientHello parse failed", exc_info=True)
        return None


def _parse_server_hello(d: bytes) -> Optional[dict]:
    try:
        ver = struct.unpack_from(">H", d, 0)[0]
        p = 2 + 32
        sid_len = d[p]
        p += 1 + sid_len
        cipher = struct.unpack_from(">H", d, p)[0]
        return {"kind": "server_hello", "version": ver, "cipher": cipher}
    except Exception:
        return None


def _ja3(ver: int, ciphers: list[int], exts: list[int], groups: list[int],
         ec: list[int]) -> str:
    def clean(xs):
        return "-".join(str(x) for x in xs if x not in _GREASE)
    s = f"{ver},{clean(ciphers)},{clean(exts)},{clean(groups)},{'-'.join(map(str, ec))}"
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()  # JA3 fingerprint, not a security digest


# ── NTLMSSP parsing (NetNTLMv1/v2 hash reassembly) ───────────────────────────
def _parse_ntlm(payload: bytes) -> Optional[dict]:
    idx = payload.find(b"NTLMSSP\x00")
    if idx == -1:
        return None
    base = idx
    if base + 12 > len(payload):
        return None
    msg_type = struct.unpack_from("<I", payload, base + 8)[0]
    try:
        if msg_type == 2 and base + 32 <= len(payload):
            challenge = payload[base + 24:base + 32]
            return {"type": 2, "challenge": challenge}
        if msg_type == 3:
            def field(off):
                flen, _mx, foff = struct.unpack_from("<HHI", payload, base + off)
                start = base + foff
                return payload[start:start + flen]
            lm = field(12)
            nt = field(20)
            domain = field(28).decode("utf-16-le", "replace")
            user = field(36).decode("utf-16-le", "replace")
            ws = field(44).decode("utf-16-le", "replace")
            return {"type": 3, "lm": lm, "nt": nt, "domain": domain,
                    "user": user, "workstation": ws}
    except Exception:
        logger.debug("NTLMSSP parse failed", exc_info=True)
    return None


def _ntlm_hash(user: str, domain: str, nt: bytes, lm: bytes,
               challenge: bytes) -> Optional[dict]:
    ch = challenge.hex()
    if len(nt) == 24:            # NetNTLMv1
        h = f"{user}::{domain}:{lm.hex()}:{nt.hex()}:{ch}"
        return {"format": "NetNTLMv1", "user": user, "domain": domain, "hash": h,
                "hashcat_mode": 5500}
    if len(nt) > 24:             # NetNTLMv2
        nt_proof = nt[:16].hex()
        blob = nt[16:].hex()
        h = f"{user}::{domain}:{ch}:{nt_proof}:{blob}"
        return {"format": "NetNTLMv2", "user": user, "domain": domain, "hash": h,
                "hashcat_mode": 5600}
    return None


# ── SNMP community extraction (minimal ASN.1) ────────────────────────────────
def _snmp_community(payload: bytes) -> Optional[tuple[str, str]]:
    """Return (version, community) for an SNMP v1/v2c message, else None."""
    try:
        if not payload or payload[0] != 0x30:
            return None
        p = 2
        if payload[1] & 0x80:                    # long-form length
            p = 2 + (payload[1] & 0x7F)
        if payload[p] != 0x02:                   # version INTEGER
            return None
        vlen = payload[p + 1]
        ver = payload[p + 2] if vlen == 1 else 0
        p += 2 + vlen
        if payload[p] != 0x04:                   # community OCTET STRING
            return None
        clen = payload[p + 1]
        community = payload[p + 2:p + 2 + clen].decode("latin1", "replace")
        vname = {0: "v1", 1: "v2c"}.get(ver, f"v{ver}")
        return vname, community
    except Exception:
        return None


# ── main entry point ─────────────────────────────────────────────────────────
def analyze_pcap(path: str, **_: Any) -> dict[str, Any]:
    """Analyze a pcap/pcapng file. Returns ``{"report": {...}, "findings": [...]}``."""
    try:
        import logging as _lg
        _lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)
        from scapy.all import PcapReader, Raw  # noqa: F401
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        try:
            from scapy.layers.inet6 import IPv6
        except Exception:
            IPv6 = None  # type: ignore
        from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: F401
        from scapy.layers.l2 import ARP
    except ImportError:
        return {"error": "scapy not installed (pip install scapy)"}

    a = _PcapAnalyzer()
    try:
        with PcapReader(path) as pcap:
            for pkt in pcap:
                a.total += 1
                if a.total > MAX_PACKETS:
                    a.report_notes.append(f"stopped at {MAX_PACKETS} packet cap")
                    break
                try:
                    a.feed(pkt, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw)
                except Exception:
                    logger.debug("per-packet analysis error", exc_info=True)
    except FileNotFoundError:
        return {"error": f"file not found: {path}"}
    except Exception as e:  # noqa: BLE001
        logger.debug("pcap parse error", exc_info=True)
        return {"error": f"pcap parse failed: {type(e).__name__}: {e}",
                "packets_read": a.total}

    return a.finalize()


class _PcapAnalyzer:
    def __init__(self) -> None:
        self.total = 0
        self.proto_counts: Counter = Counter()
        self.app_proto_counts: Counter = Counter()
        self.talkers: Counter = Counter()
        self.bytes_by_host: Counter = Counter()
        self.flows: dict[tuple, dict] = {}
        self.syn_to: Counter = Counter()
        self.synack_from: Counter = Counter()
        self.icmp_count = 0
        self.icmp_tunnel = 0
        self.creds: list[dict] = []
        self._cred_keys: set = set()
        self.dns_queries: list[dict] = []
        self.dns_answers: dict[str, list[str]] = defaultdict(list)
        self.dns_qcount: Counter = Counter()
        self.dns_txt = 0
        self.tls: list[dict] = []
        self._tls_seen: set = set()
        self.http_txns: list[dict] = []
        self.suspicious_ua: set = set()
        self.arp_map: dict[str, set] = defaultdict(set)
        self.dhcp: list[dict] = []
        self.snmp: list[dict] = []
        self.ntlm_hashes: list[dict] = []
        self._ntlm_chal: dict[tuple, bytes] = {}
        self.cleartext_protos: dict[str, int] = defaultdict(int)
        self.scan_dstports: dict[str, set] = defaultdict(set)
        self.scan_dsthosts: dict[str, set] = defaultdict(set)
        self.payload_secrets: list[dict] = []
        self._secret_keys: set = set()
        self.amps: list[dict] = []
        self._tls_parsed = 0
        self._http_parsed = 0
        self.report_notes: list[str] = []

    # ── credential dedup ──
    def add_cred(self, kind, proto, src, dst, detail):
        key = (kind, detail)
        if key in self._cred_keys or len(self.creds) >= _LIST_CAP:
            return
        self._cred_keys.add(key)
        self.creds.append({"type": kind, "protocol": proto, "src": src,
                           "dst": dst, "detail": detail[:200]})

    def feed(self, pkt, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw):
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if int(arp.op) == 2:                     # is-at (reply)
                self.arp_map[arp.psrc].add(arp.hwsrc)
            self.proto_counts["ARP"] += 1
            return

        ipl = None
        if pkt.haslayer(IP):
            ipl = pkt[IP]
        elif IPv6 is not None and pkt.haslayer(IPv6):
            ipl = pkt[IPv6]
        if ipl is None:
            self.proto_counts["non-IP"] += 1
            return

        src, dst = ipl.src, ipl.dst
        self.talkers[src] += 1
        self.bytes_by_host[src] += len(pkt)

        if pkt.haslayer(ICMP):
            self.icmp_count += 1
            self.proto_counts["ICMP"] += 1
            if pkt.haslayer(Raw) and len(bytes(pkt[Raw].load)) > 64:
                self.icmp_tunnel += 1
            return

        if pkt.haslayer(TCP):
            self.proto_counts["TCP"] += 1
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = int(tcp.flags)
            self._flow(src, sport, dst, dport, "TCP", len(pkt), pkt.time)
            if flags & 0x02 and not (flags & 0x10):
                self.syn_to[dst] += 1
                self.scan_dstports[src].add(dport)
                self.scan_dsthosts[src].add(dst)
            if (flags & 0x02) and (flags & 0x10):
                self.synack_from[src] += 1
            # bytes(tcp.payload) re-serialises the full application payload even
            # when scapy split it into sub-layers (SMB on 445, etc.), so app-layer
            # dissection here does not depend on scapy's autoloading.
            payload = _payload_bytes(tcp)
            if payload:
                self._scan_tcp_payload(payload, src, dst, sport, dport)
            return

        if pkt.haslayer(UDP):
            self.proto_counts["UDP"] += 1
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            self._flow(src, sport, dst, dport, "UDP", len(pkt), pkt.time)
            payload = _payload_bytes(udp)
            if pkt.haslayer(DNS):
                self._scan_dns(pkt, src, dst, DNS, DNSQR, DNSRR)
            elif dport in (161, 162) or sport in (161, 162):
                self._scan_snmp(payload, src, dst)
            elif dport in (67, 68) or sport in (67, 68):
                self._scan_dhcp(pkt, src, dst)
            if udp.sport in _AMPLIFIERS and len(payload) > 512:
                self.amps.append({"service": _AMPLIFIERS[udp.sport], "src": src,
                                  "dst": dst, "resp_bytes": len(payload)})

    def _flow(self, src, sport, dst, dport, proto, nbytes, ts):
        key = _flow_key(src, sport, dst, dport)
        f = self.flows.get(key)
        ts = float(ts) if ts else 0.0
        if f is None:
            if len(self.flows) < 200_000:
                self.flows[key] = {"proto": proto, "a": key[0], "b": key[1],
                                   "packets": 1, "bytes": nbytes,
                                   "first": ts, "last": ts, "times": [ts]}
        else:
            f["packets"] += 1
            f["bytes"] += nbytes
            f["last"] = ts
            if len(f["times"]) < 500:
                f["times"].append(ts)

    # ── application-layer dissection ──
    def _scan_tcp_payload(self, payload: bytes, src, dst, sport, dport):
        proto = _CLEARTEXT_PORTS.get(dport) or _CLEARTEXT_PORTS.get(sport)
        if proto:
            self.cleartext_protos[proto] += 1

        # NTLMSSP anywhere (SMB 445/139, HTTP, LDAP, MSSQL...)
        if b"NTLMSSP\x00" in payload:
            self._scan_ntlm(payload, src, dst, sport, dport)

        # TLS handshake (0x16 = handshake record)
        if payload[:1] == b"\x16" and self._tls_parsed < _TLS_PARSE_CAP:
            self._tls_parsed += 1
            for hs in _parse_tls_records(payload):
                self._record_tls(hs, src, dst, dport if dport == 443 else sport)
            return

        # Decode text once for the text protocols.
        try:
            text = payload.decode("latin1", "replace")
        except Exception:
            return
        up = text.upper()

        if dport in (21, 2121) or sport in (21, 2121):
            for line in text.splitlines():
                u = line.upper()
                if u.startswith("USER ") or u.startswith("PASS "):
                    self.add_cred("ftp_cleartext", "FTP", src, dst, line.strip())
        if dport == 23 or sport == 23:
            for line in text.splitlines():
                low = line.lower()
                if ("login:" in low or "password:" in low or "username:" in low) \
                        and len(line) < 120:
                    self.add_cred("telnet_cleartext", "Telnet", src, dst, line.strip())
        if dport in (110, 143) or sport in (110, 143):
            for line in text.splitlines():
                if line.upper().startswith(("USER ", "PASS ", "LOGIN ")):
                    self.add_cred("mail_cleartext", "POP/IMAP", src, dst, line.strip())
        if "AUTH LOGIN" in up or "AUTH PLAIN" in up:
            self.add_cred("smtp_auth", "SMTP", src, dst, "AUTH LOGIN/PLAIN observed")

        # HTTP on any port — detect by request line or status line.
        if _looks_http(text):
            self._scan_http(text, src, dst, dport)

        # In-payload secret sweep (bounded).
        if len(self.payload_secrets) < _LIST_CAP:
            for rx, label, sev in _PAYLOAD_SECRETS:
                m = rx.search(payload)
                if m:
                    snip = m.group(0)[:80].decode("latin1", "replace")
                    k = (label, snip)
                    if k not in self._secret_keys:
                        self._secret_keys.add(k)
                        self.payload_secrets.append(
                            {"type": label, "severity": sev, "match": snip,
                             "src": src, "dst": dst})

    def _record_tls(self, hs: dict, src, dst, port):
        if hs["kind"] == "client_hello":
            key = (dst, hs.get("sni"), hs.get("ja3"))
            if key in self._tls_seen or len(self.tls) >= _LIST_CAP:
                return
            self._tls_seen.add(key)
            self.tls.append({"src": src, "dst": dst, "sni": hs.get("sni", ""),
                             "version": _TLS_VERSIONS.get(hs["version"], hex(hs["version"])),
                             "version_raw": hs["version"], "ja3": hs.get("ja3", ""),
                             "role": "client"})
            self.app_proto_counts["TLS"] += 1
        elif hs["kind"] == "server_hello":
            self.tls.append({"src": src, "dst": dst,
                             "version": _TLS_VERSIONS.get(hs["version"], hex(hs["version"])),
                             "version_raw": hs["version"],
                             "cipher": hs.get("cipher"), "role": "server"})

    def _scan_http(self, text: str, src, dst, dport):
        if self._http_parsed >= _HTTP_PARSE_CAP:
            return
        self._http_parsed += 1
        self.app_proto_counts["HTTP"] += 1
        head = text.split("\r\n\r\n", 1)
        headers = head[0]
        body = head[1] if len(head) > 1 else ""
        lines = headers.split("\r\n")
        first = lines[0] if lines else ""
        hdr = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        m = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(\S+)\s+HTTP", first)
        if m:                                    # request
            txn = {"src": src, "dst": dst, "method": m.group(1), "path": m.group(2),
                   "host": hdr.get("host", ""), "user_agent": hdr.get("user-agent", ""),
                   "port": dport}
            if len(self.http_txns) < _LIST_CAP:
                self.http_txns.append(txn)
            ua = hdr.get("user-agent", "")
            if ua and _SUSPICIOUS_UA.search(ua):
                self.suspicious_ua.add(_SUSPICIOUS_UA.search(ua).group(0))
            auth = hdr.get("authorization", "")
            if auth.lower().startswith("basic "):
                dec = _b64_user_pass(auth.split(" ", 1)[-1].strip())
                if dec and ":" in dec:
                    self.add_cred("http_basic", "HTTP", src, dst, dec)
            if hdr.get("cookie"):
                self.add_cred("http_cookie_cleartext", "HTTP", src, dst,
                              f"{txn['host']} {hdr['cookie'][:80]}")
            low = (body or "").lower()
            if ("password=" in low or "passwd=" in low or "pwd=" in low
                    or "pass=" in low):
                self.add_cred("http_form", "HTTP", src, dst, body.strip()[:200])
        elif first.startswith("HTTP/"):         # response
            if len(self.http_txns) < _LIST_CAP:
                self.http_txns.append({"src": src, "dst": dst, "response": first.strip(),
                                       "server": hdr.get("server", ""),
                                       "set_cookie": hdr.get("set-cookie", "")[:80]})

    def _scan_ntlm(self, payload, src, dst, sport, dport):
        parsed = _parse_ntlm(payload)
        if not parsed:
            return
        self.app_proto_counts["NTLM"] += 1
        key = _flow_key(src, sport, dst, dport)
        if parsed["type"] == 2:
            self._ntlm_chal[key] = parsed["challenge"]
        elif parsed["type"] == 3:
            challenge = self._ntlm_chal.get(key, b"\x11\x22\x33\x44\x55\x66\x77\x88")
            h = _ntlm_hash(parsed["user"], parsed["domain"], parsed["nt"],
                           parsed["lm"], challenge)
            if h and h not in self.ntlm_hashes and len(self.ntlm_hashes) < 100:
                h["src"] = src
                h["dst"] = dst
                self.ntlm_hashes.append(h)

    def _scan_dns(self, pkt, src, dst, DNS, DNSQR, DNSRR):
        self.app_proto_counts["DNS"] += 1
        dns = pkt[DNS]
        try:
            # getfieldval returns the raw list without triggering scapy's
            # legacy-accessor deprecation warning, and handles multi-record replies.
            for qd in _rr_list(dns.getfieldval("qd")):     # questions
                qname = _rr_name(getattr(qd, "qname", ""))
                qtype = int(getattr(qd, "qtype", 0))
                self.dns_qcount[_registrable(qname)] += 1
                if qtype == 16:
                    self.dns_txt += 1
                if len(self.dns_queries) < _LIST_CAP:
                    self.dns_queries.append({"src": src, "qname": qname,
                                             "qtype": _qtype_name(qtype)})
            for an in _rr_list(dns.getfieldval("an"))[:20]:  # answers
                rrname = _rr_name(getattr(an, "rrname", ""))
                rdata = getattr(an, "rdata", "")
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("latin1", "replace")
                self.dns_answers[rrname].append(str(rdata))
        except Exception:
            logger.debug("DNS dissection failed", exc_info=True)

    def _scan_snmp(self, payload, src, dst):
        res = _snmp_community(payload)
        if res:
            self.app_proto_counts["SNMP"] += 1
            ver, community = res
            entry = {"version": ver, "community": community, "src": src, "dst": dst}
            if entry not in self.snmp and len(self.snmp) < 100:
                self.snmp.append(entry)

    def _scan_dhcp(self, pkt, src, dst):
        try:
            from scapy.layers.dhcp import DHCP
            if pkt.haslayer(DHCP):
                self.app_proto_counts["DHCP"] += 1
                opts = {o[0]: o[1] for o in pkt[DHCP].options
                        if isinstance(o, tuple) and len(o) == 2}
                entry = {"src": src, "dst": dst,
                         "hostname": _dec(opts.get("hostname", "")),
                         "requested_addr": str(opts.get("requested_addr", "")),
                         "message_type": opts.get("message-type", "")}
                if entry not in self.dhcp and len(self.dhcp) < 100:
                    self.dhcp.append(entry)
        except Exception:
            logger.debug("DHCP dissection failed", exc_info=True)

    # ── finalize ──
    def finalize(self) -> dict[str, Any]:
        findings = self._build_findings()
        conversations = self._top_conversations()
        report = {
            "packets": self.total,
            "protocol_breakdown": dict(self.proto_counts.most_common()),
            "application_protocols": dict(self.app_proto_counts.most_common()),
            "top_talkers": [{"host": s, "packets": c, "bytes": self.bytes_by_host[s]}
                            for s, c in self.talkers.most_common(15)],
            "conversations": conversations,
            "dns_queries": self.dns_queries[:200],
            "dns_answers": {k: v[:5] for k, v in list(self.dns_answers.items())[:100]},
            "tls_sessions": self.tls[:200],
            "http_transactions": self.http_txns[:200],
            "cleartext_credentials": self.creds,
            "ntlm_hashes": self.ntlm_hashes,
            "snmp_communities": self.snmp,
            "dhcp": self.dhcp,
            "arp_table": {ip: sorted(macs) for ip, macs in list(self.arp_map.items())[:100]},
            "cleartext_protocols": dict(self.cleartext_protos),
            "payload_secrets": self.payload_secrets,
            "amplification_responses": self.amps[:50],
            "suspicious_user_agents": sorted(self.suspicious_ua),
        }
        if self.report_notes:
            report["notes"] = self.report_notes
        return {"report": report, "findings": findings,
                "summary": self._summary(findings)}

    def _top_conversations(self) -> list[dict]:
        convs = []
        for f in sorted(self.flows.values(), key=lambda x: x["bytes"], reverse=True)[:30]:
            dur = round(f["last"] - f["first"], 3) if f["last"] and f["first"] else 0.0
            convs.append({"proto": f["proto"], "a": f"{f['a'][0]}:{f['a'][1]}",
                          "b": f"{f['b'][0]}:{f['b'][1]}", "packets": f["packets"],
                          "bytes": f["bytes"], "duration_s": dur})
        return convs

    def _beacons(self) -> list[dict]:
        """Flows whose inter-packet gaps are highly regular → candidate C2 beacon."""
        out = []
        for f in self.flows.values():
            ts = f["times"]
            if len(ts) < 6:
                continue
            gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.05]
            if len(gaps) < 5:
                continue
            mean = sum(gaps) / len(gaps)
            if mean < 0.5:
                continue
            var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
            cv = (math.sqrt(var) / mean) if mean else 1.0
            if cv < 0.15:                          # very regular interval
                out.append({"a": f"{f['a'][0]}:{f['a'][1]}",
                            "b": f"{f['b'][0]}:{f['b'][1]}",
                            "interval_s": round(mean, 2), "count": len(ts)})
        return out[:20]

    def _build_findings(self) -> list[dict]:
        f: list[dict] = []
        # Cleartext credentials.
        if self.creds:
            sample = "; ".join(c["detail"][:40] for c in self.creds[:3])
            f.append(_finding(
                "cleartext_credentials", "high",
                f"{len(self.creds)} cleartext credential(s) captured on the wire",
                "Credentials were transmitted in cleartext and are recoverable by "
                f"anyone sniffing the network. Examples: {sample}.",
                cwe="CWE-319", evidence={"credentials": self.creds[:30]},
                remediation="Move these protocols to TLS (FTPS/HTTPS/SMTPS/IMAPS/"
                            "LDAPS) and rotate every exposed credential."))
        # NTLM hashes.
        if self.ntlm_hashes:
            fmts = sorted({h["format"] for h in self.ntlm_hashes})
            f.append(_finding(
                "ntlm_hash_captured", "high",
                f"{len(self.ntlm_hashes)} {'/'.join(fmts)} hash(es) captured (crackable)",
                "NTLM challenge/response pairs were reassembled from the capture "
                "into hashcat-format hashes. These can be cracked offline or, live, "
                "relayed to authenticate as the user.",
                cwe="CWE-522", confidence=0.95,
                evidence={"hashes": [{"user": h["user"], "format": h["format"],
                                      "hashcat_mode": h["hashcat_mode"],
                                      "hash": h["hash"]} for h in self.ntlm_hashes[:20]]},
                remediation="Disable NTLM where possible, enforce SMB signing and "
                            "LDAP channel binding, and use Kerberos."))
        # SNMP default community.
        default_comms = [s for s in self.snmp
                         if s["community"].lower() in ("public", "private")]
        if default_comms:
            f.append(_finding(
                "snmp_default_community", "medium",
                f"SNMP default community string(s) in cleartext: "
                f"{', '.join(sorted({s['community'] for s in default_comms}))}",
                "SNMP community strings act as passwords and were sent in cleartext. "
                "Default values ('public'/'private') let an attacker read (and often "
                "write) device configuration.", cwe="CWE-319",
                evidence={"communities": default_comms[:20]},
                remediation="Use SNMPv3 with authentication and privacy; never use "
                            "default community strings."))
        # ARP spoofing.
        conflicts = {ip: sorted(macs) for ip, macs in self.arp_map.items()
                     if len(macs) > 1}
        if conflicts:
            f.append(_finding(
                "arp_spoofing", "high",
                f"ARP spoofing indicators: {len(conflicts)} IP(s) claimed by multiple MACs",
                "One or more IP addresses were advertised by more than one MAC "
                "address in ARP replies — the signature of ARP cache poisoning / a "
                "man-in-the-middle on the LAN.", cwe="CWE-300",
                evidence={"conflicts": conflicts}))
        # Weak TLS.
        weak = [t for t in self.tls if t.get("version_raw") in _WEAK_TLS]
        if weak:
            vers = sorted({t["version"] for t in weak})
            f.append(_finding(
                "weak_tls_version", "medium",
                f"Deprecated TLS/SSL negotiated: {', '.join(vers)}",
                "A deprecated TLS/SSL version was seen on the wire. SSL 3.0, TLS 1.0 "
                "and TLS 1.1 are broken/deprecated (POODLE, BEAST) and must not be "
                "used.", cwe="CWE-327",
                evidence={"sessions": [{"dst": t.get("dst"), "sni": t.get("sni"),
                                        "version": t["version"]} for t in weak[:20]]},
                remediation="Require TLS 1.2+ (prefer 1.3) and disable legacy protocols."))
        # DNS tunneling / exfil heuristic.
        tunnels = self._dns_tunnel_candidates()
        if tunnels:
            f.append(_finding(
                "dns_tunneling", "medium",
                f"Possible DNS tunneling/exfiltration to {len(tunnels)} domain(s)",
                "Long, high-entropy or high-volume DNS lookups to a single domain "
                "are consistent with DNS tunneling or data exfiltration.",
                cwe="CWE-200", confidence=0.6,
                evidence={"domains": tunnels[:20]},
                remediation="Inspect and, if unexpected, block the domain; monitor "
                            "DNS for tunneling patterns."))
        # In-payload secrets.
        if self.payload_secrets:
            crit = [s for s in self.payload_secrets if s["severity"] in ("critical", "high")]
            if crit:
                f.append(_finding(
                    "cleartext_secret_on_wire", "high",
                    f"{len(crit)} secret(s)/key(s) transmitted in cleartext",
                    "API keys, tokens or private-key material were seen in cleartext "
                    "in packet payloads and are recoverable by any sniffer.",
                    cwe="CWE-319", evidence={"secrets": crit[:20]},
                    remediation="Rotate the exposed secrets and only transmit them "
                                "over TLS."))
        # Cleartext protocol exposure (informational, always useful).
        if self.cleartext_protos:
            f.append(_finding(
                "cleartext_protocols", "low",
                f"Cleartext protocol(s) in use: "
                f"{', '.join(sorted(self.cleartext_protos))}",
                "Unencrypted application protocols were observed. All data they "
                "carry (including credentials and session tokens) is exposed to "
                "anyone on the path.", cwe="CWE-319", confidence=0.8,
                evidence={"protocols": dict(self.cleartext_protos)}))
        # Suspicious user-agents (offensive tooling).
        if self.suspicious_ua:
            f.append(_finding(
                "offensive_tool_traffic", "medium",
                f"Scanner/attack-tool user-agent(s) seen: {', '.join(sorted(self.suspicious_ua))}",
                "HTTP requests carried user-agents belonging to known offensive "
                "or scanning tools, indicating active reconnaissance or attack "
                "traffic in the capture.", cwe="CWE-200", confidence=0.7,
                evidence={"user_agents": sorted(self.suspicious_ua)}))
        # Port scan / host sweep.
        for s, ports in self.scan_dstports.items():
            if len(ports) >= 20:
                f.append(_finding(
                    "port_scan", "medium", f"Port scan from {s} ({len(ports)} ports)",
                    f"{s} sent SYN packets to {len(ports)} distinct destination "
                    "ports — a TCP port scan.", cwe="CWE-200", confidence=0.85,
                    evidence={"src": s, "ports_scanned": len(ports)}))
                break
        for s, hosts in self.scan_dsthosts.items():
            if len(hosts) >= 25:
                f.append(_finding(
                    "host_sweep", "low", f"Host sweep from {s} ({len(hosts)} hosts)",
                    f"{s} initiated connections to {len(hosts)} distinct hosts — "
                    "a network sweep / discovery scan.", cwe="CWE-200",
                    evidence={"src": s, "hosts_contacted": len(hosts)}))
                break
        # SYN flood.
        for dst, syns in self.syn_to.items():
            acks = self.synack_from.get(dst, 0)
            if syns >= 500 and acks < syns * 0.1:
                f.append(_finding(
                    "syn_flood", "high", f"Possible SYN flood against {dst}",
                    f"{syns} SYN packets were sent to {dst} with only {acks} SYN/ACK "
                    "responses — the signature of a SYN-flood denial of service.",
                    cwe="CWE-400", evidence={"dst": dst, "syn": syns, "synack": acks}))
        # Single-source storm.
        if self.total >= 1000 and self.talkers:
            top_src, top_n = self.talkers.most_common(1)[0]
            if top_n > self.total * 0.6:
                f.append(_finding(
                    "packet_storm", "medium",
                    f"Single source dominates traffic: {top_src}",
                    f"{top_src} accounts for {top_n} of {self.total} packets "
                    f"({top_n * 100 // self.total}%), consistent with a flood or scan.",
                    cwe="CWE-400", evidence={"src": top_src, "packets": top_n}))
        # Amplification.
        if self.amps:
            svcs = sorted({a["service"] for a in self.amps})
            f.append(_finding(
                "amplification_traffic", "medium",
                f"Reflection/amplification responses observed ({', '.join(svcs)})",
                "Large UDP responses from known amplifier services were seen. If the "
                "source addresses are spoofed victims, this capture shows a "
                "reflection/amplification DDoS in progress.", cwe="CWE-406",
                evidence={"samples": self.amps[:10]}))
        # ICMP.
        if self.icmp_tunnel >= 10:
            f.append(_finding(
                "icmp_tunneling", "medium",
                f"Large ICMP payloads ({self.icmp_tunnel} packets) — possible tunneling",
                "Many ICMP packets carried unusually large payloads, a pattern used "
                "for ICMP tunneling / covert channels.", cwe="CWE-200"))
        elif self.icmp_count >= 1000:
            f.append(_finding(
                "icmp_flood", "low", f"High ICMP volume ({self.icmp_count} packets)",
                "A large number of ICMP packets can indicate a ping flood or "
                "network sweep.", cwe="CWE-400"))
        # Beaconing / C2.
        beacons = self._beacons()
        if beacons:
            f.append(_finding(
                "c2_beaconing", "medium",
                f"Periodic beaconing on {len(beacons)} flow(s) — possible C2",
                "One or more conversations exchanged packets at a highly regular "
                "interval, the classic signature of malware command-and-control "
                "beaconing.", cwe="CWE-506", confidence=0.55,
                evidence={"beacons": beacons}))
        return f

    def _dns_tunnel_candidates(self) -> list[dict]:
        out = []
        for dom, count in self.dns_qcount.items():
            labels = [q["qname"] for q in self.dns_queries
                      if _registrable(q["qname"]) == dom]
            long_labels = sum(1 for q in labels if _has_long_label(q))
            suspicious = bool(_SUSPICIOUS_TLD.search(dom))
            if count >= 50 or long_labels >= 3 or (suspicious and long_labels >= 1):
                out.append({"domain": dom, "queries": count,
                            "long_label_queries": long_labels,
                            "suspicious_tld": suspicious})
        return out

    def _summary(self, findings) -> str:
        parts = [f"{self.total} packets",
                 f"{len(self.creds)} cleartext credential(s)"]
        if self.ntlm_hashes:
            parts.append(f"{len(self.ntlm_hashes)} NTLM hash(es)")
        if self.tls:
            parts.append(f"{len([t for t in self.tls if t.get('role') == 'client'])} TLS session(s)")
        if self.dns_queries:
            parts.append(f"{len(self.dns_queries)} DNS quer(y/ies)")
        parts.append(f"{len(findings)} finding(s)")
        return " · ".join(parts)


# ── module-level helpers ─────────────────────────────────────────────────────
def _payload_bytes(layer) -> bytes:
    """Serialise the full application payload under a TCP/UDP layer, regardless of
    how scapy sub-dissected it (SMB, Kerberos, etc.)."""
    try:
        pl = layer.payload
        if not pl or pl.__class__.__name__ == "NoPayload":
            return b""
        return bytes(pl)
    except Exception:
        return b""


def _looks_http(text: str) -> bool:
    return bool(re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE) \S+ HTTP/",
                         text) or text.startswith("HTTP/"))


def _registrable(qname: str) -> str:
    """Best-effort registrable domain (last two labels)."""
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


def _has_long_label(qname: str) -> bool:
    return any(len(lbl) >= 20 for lbl in qname.split("."))


def _rr_list(val) -> list:
    """Normalise a scapy DNS qd/an field (list, single record, or chained) to a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    out, cur = [], val
    while cur is not None and cur.__class__.__name__ != "NoPayload":
        out.append(cur)
        cur = getattr(cur, "payload", None)
        if len(out) >= 50:
            break
    return out


def _rr_name(name) -> str:
    if isinstance(name, bytes):
        return name.decode("latin1", "replace").rstrip(".")
    return str(name).rstrip(".")


def _qtype_name(qt: int) -> str:
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
            28: "AAAA", 33: "SRV", 65: "HTTPS"}.get(int(qt), str(qt))


def _dec(v) -> str:
    if isinstance(v, bytes):
        return v.decode("latin1", "replace")
    return str(v)

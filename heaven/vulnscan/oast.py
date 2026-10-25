"""HEAVEN: in-house OAST collaborator (out-of-band application security testing).

Provable blind-vulnerability detection **without any external service**, no Burp
Collaborator, no interactsh, no third-party DNS. HEAVEN binds a local HTTP
listener; each out-of-band probe embeds a unique correlation token in the URL it
asks the target to fetch. If the target is vulnerable (SSRF, XXE with an external
SYSTEM entity, blind command injection with a curl/wget, …) then *the target*
connects back to us and we record the interaction against that token. That turns
a timing/heuristic guess into hard evidence: "your server fetched
http://<us>/<token>, here is the request it sent."

Everything here is Python standard library (``http.server`` in a background
thread), so it adds zero dependencies and runs anywhere HEAVEN runs. It binds to
loopback by default; point ``host`` at a routable address only when the target
lives on another machine and you have authorization to receive its callbacks.
"""

from __future__ import annotations

import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.oast")

# A 1x1 gif, some SSRF sinks only follow the fetch if the response looks like an
# image; returning a tiny valid body keeps those callbacks from erroring out.
_PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02"
    b"\x02D\x01\x00;"
)


@dataclass
class Interaction:
    """A single inbound callback recorded by the collaborator.

    ``channel`` is ``"http"`` for a web callback recorded by the HTTP listener
    and ``"dns"`` for a name-resolution callback recorded by the DNS listener.
    A DNS interaction stores the queried hostname in ``path`` (so the existing
    ``token in path`` correlation works unchanged across both channels) and the
    query type (``A``/``AAAA``/``TXT``/…) in ``method``.
    """

    token: str
    method: str
    path: str
    client_ip: str
    at: float
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    channel: str = "http"


class _Handler(BaseHTTPRequestHandler):
    # server.listener is set by OASTListener before serving.
    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        listener: "OASTListener" = self.server.listener  # type: ignore[attr-defined]
        body = ""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            try:
                body = self.rfile.read(length).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - never let a probe body crash the listener
                body = ""
        listener._record(  # noqa: SLF001 - internal by design
            Interaction(
                token=self.path.strip("/").split("/")[0].split("?")[0],
                method=self.command,
                path=self.path,
                client_ip=self.client_address[0] if self.client_address else "",
                at=time.monotonic(),
                headers={k: v for k, v in self.headers.items()},
                body=body,
            )
        )

    def _respond(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(_PIXEL)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(_PIXEL)
        except Exception:  # noqa: BLE001
            logger.debug("suppressed non-fatal exception", exc_info=True)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._record()
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        self._respond()

    # http.server logs every request to stderr by default, silence it.
    def log_message(self, *_args) -> None:  # noqa: D401
        return


# ── DNS wire format (stdlib only, no dnspython) ──────────────────────────────
# Enough of RFC 1035 to parse an inbound query and answer a single A record.
# A blind-vuln DNS probe only needs the target's resolver to *reach us*; the
# record we hand back just keeps the resolver happy so the lookup completes.

_DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS QNAME starting at ``offset``; return (name, next_offset).

    Questions never use compression pointers, but we tolerate one defensively so
    a malformed packet can never spin the parser.
    """
    labels: list[str] = []
    guard = 0
    while offset < len(data) and guard < 128:
        guard += 1
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression pointer, stop (not expected in a question)
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def _looks_like_ipv4(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except OSError:
        return False


def _build_dns_response(query: bytes, ip: str, answer_a: bool) -> bytes:
    """Build an authoritative A-record response echoing ``query``'s question."""
    txn_id = query[:2]
    flags = b"\x84\x00"  # QR=1, AA=1, RCODE=0
    qdcount = query[4:6]
    _name, end = _decode_qname(query, 12)
    question = query[12:end + 4]  # qname + qtype(2) + qclass(2)
    ancount = 1 if answer_a else 0
    header = txn_id + flags + qdcount + struct.pack(">HHH", ancount, 0, 0)
    packet = header + question
    if answer_a:
        # NAME compression pointer to the question (0x0c), TYPE A, CLASS IN.
        packet += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return packet


class OASTListener:
    """A loopback HTTP collaborator that records out-of-band callbacks.

    Use as a context manager::

        with OASTListener() as oast:
            token = oast.new_token()
            probe_url = oast.url_for(token)      # hand this to the target
            ...                                   # trigger the potential SSRF/XXE
            if oast.poll(token, timeout=3.0):    # did the target call us back?
                # proven out-of-band interaction, collect the evidence
                hits = oast.interactions(token)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 advertised_host: str = "", dns_zone: str = "",
                 dns_bind: str = "", dns_port: int = 53,
                 public_ip: str = "") -> None:
        # ``host`` is the address we BIND to; ``advertised_host`` is the address
        # we tell the target to call back on. They differ when the operator
        # binds all interfaces (0.0.0.0) but must advertise a routable IP /
        # hostname the target can reach (NAT, port-forward, cloud egress). When
        # unset the advertised host is the bind host (loopback/lab default).
        self._host = host
        self._advertised = advertised_host or host
        self._want_port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._interactions: list[Interaction] = []
        self._lock = threading.Lock()

        # DNS channel. It is active only when a zone is configured, the target
        # resolves ``<token>.<zone>`` and its recursive resolver reaches us, so
        # for internet callbacks the zone's NS must be delegated to this box
        # (see ``heaven oast``). ``public_ip`` is the A-record we answer with;
        # it falls back to the advertised host when that is an IPv4 literal, else
        # to loopback (fine for a local two-channel correlation test).
        self._dns_zone = dns_zone.strip().strip(".").lower()
        self._dns_bind = dns_bind or ("0.0.0.0" if self._host == "0.0.0.0" else self._host)  # noqa: S104
        self._want_dns_port = dns_port
        if public_ip and _looks_like_ipv4(public_ip):
            self._public_ip = public_ip
        elif _looks_like_ipv4(self._advertised):
            self._public_ip = self._advertised
        else:
            self._public_ip = "127.0.0.1"
        self._dns_sock: Optional[socket.socket] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._dns_running = False

    @classmethod
    def from_env(cls) -> "OASTListener":
        """Build a collaborator honouring the OAST environment variables:

        * ``HEAVEN_OAST_HOST``, the routable address advertised to targets.
        * ``HEAVEN_OAST_BIND``, the local address to bind (defaults to the
          advertised host; set to ``0.0.0.0`` to accept callbacks on every
          interface behind NAT/port-forward).
        * ``HEAVEN_OAST_PORT``, a fixed port (defaults to an OS-assigned one),
          useful when you have to punch a specific hole in a firewall.

        DNS channel (active only when a zone is set):

        * ``HEAVEN_OAST_DNS_ZONE``, the zone delegated to this box, e.g.
          ``oast.example.com``; blind probes resolve ``<token>.<zone>``.
        * ``HEAVEN_OAST_DNS_BIND``, the local address to bind the UDP DNS
          listener (defaults to the HTTP bind address).
        * ``HEAVEN_OAST_DNS_PORT``, the UDP port to listen on (default ``53``;
          real resolvers only ever query 53, so override it only for local
          tests where binding 53 needs privileges).
        * ``HEAVEN_OAST_PUBLIC_IP``, the IPv4 address answered in A records
          (defaults to the advertised host when it is an IPv4 literal).

        With no variables set it returns a loopback HTTP collaborator, the safe
        default that already covers localhost/lab targets.
        """
        import os
        adv = os.getenv("HEAVEN_OAST_HOST", "").strip()
        bind = os.getenv("HEAVEN_OAST_BIND", "").strip()
        try:
            port = int(os.getenv("HEAVEN_OAST_PORT", "0").strip() or "0")
        except ValueError:
            port = 0
        dns_zone = os.getenv("HEAVEN_OAST_DNS_ZONE", "").strip()
        dns_bind = os.getenv("HEAVEN_OAST_DNS_BIND", "").strip()
        try:
            dns_port = int(os.getenv("HEAVEN_OAST_DNS_PORT", "53").strip() or "53")
        except ValueError:
            dns_port = 53
        public_ip = os.getenv("HEAVEN_OAST_PUBLIC_IP", "").strip()
        if adv:
            return cls(host=bind or adv, port=port, advertised_host=adv,
                       dns_zone=dns_zone, dns_bind=dns_bind, dns_port=dns_port,
                       public_ip=public_ip)
        return cls(port=port, dns_zone=dns_zone, dns_bind=dns_bind,
                   dns_port=dns_port, public_ip=public_ip)

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> "OASTListener":
        if self._server is not None:
            return self
        self._server = ThreadingHTTPServer((self._host, self._want_port), _Handler)
        self._server.listener = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        )
        self._thread.start()
        logger.debug("OAST collaborator listening on %s", self.base_url)
        if self._dns_zone:
            self._start_dns()
        return self

    def _start_dns(self) -> None:
        """Bind the UDP DNS listener; degrade to HTTP-only if the bind fails.

        Binding port 53 needs privileges, and the port may already be taken, so
        a failure here is logged and swallowed, the HTTP channel still works.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._dns_bind, self._want_dns_port))
            sock.settimeout(0.2)
        except OSError as exc:
            logger.warning(
                "OAST DNS listener could not bind %s:%s (%s), HTTP channel only",
                self._dns_bind, self._want_dns_port, exc,
            )
            self._dns_sock = None
            return
        self._dns_sock = sock
        self._dns_running = True
        self._dns_thread = threading.Thread(target=self._dns_serve, daemon=True)
        self._dns_thread.start()
        logger.debug(
            "OAST DNS collaborator listening on %s:%s for zone %s",
            self._dns_bind, self.dns_port, self._dns_zone,
        )

    def _dns_serve(self) -> None:
        sock = self._dns_sock
        if sock is None:
            return
        while self._dns_running:
            try:
                data, addr = sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 13:
                continue
            try:
                qname, end = _decode_qname(data, 12)
                qtype = struct.unpack(">H", data[end:end + 2])[0] if len(data) >= end + 2 else 1
            except Exception:  # noqa: BLE001 - never let a malformed packet kill the thread
                logger.debug("malformed DNS query ignored", exc_info=True)
                continue
            qname_l = qname.lower()
            # Only queries landing inside our delegated zone are ours to record.
            if not (qname_l == self._dns_zone or qname_l.endswith("." + self._dns_zone)):
                continue
            self._record(Interaction(
                token=self._token_from_qname(qname_l),
                method=_DNS_QTYPES.get(qtype, str(qtype)),
                path=qname_l,
                client_ip=addr[0] if addr else "",
                at=time.monotonic(),
                channel="dns",
            ))
            try:
                sock.sendto(_build_dns_response(data, self._public_ip, qtype == 1), addr)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed non-fatal DNS response error", exc_info=True)

    @staticmethod
    def _token_from_qname(qname: str) -> str:
        """Correlation token from a queried name: the leftmost ``oob…`` label
        (exfil techniques may prepend data labels), else the leftmost label."""
        labels = qname.split(".")
        for lab in labels:
            if lab.startswith("oob"):
                return lab
        return labels[0] if labels else qname

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._dns_running = False
        if self._dns_sock is not None:
            try:
                self._dns_sock.close()
            except OSError:
                pass
            self._dns_sock = None
        if self._dns_thread is not None:
            self._dns_thread.join(timeout=5)
            self._dns_thread = None

    def __enter__(self) -> "OASTListener":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # ── addressing ───────────────────────────────────────────────────────────
    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return self._server.server_address[1]

    @property
    def advertised_host(self) -> str:
        return self._advertised

    @property
    def base_url(self) -> str:
        # Uses the ADVERTISED host so the callback URL is reachable by the target
        # even when we bound a different (e.g. all-interfaces) local address.
        return f"http://{self._advertised}:{self.port}"

    @property
    def dns_enabled(self) -> bool:
        """True once the DNS listener is bound and recording."""
        return self._dns_sock is not None

    @property
    def dns_zone(self) -> str:
        return self._dns_zone

    @property
    def dns_port(self) -> int:
        if self._dns_sock is None:
            return 0
        try:
            return self._dns_sock.getsockname()[1]
        except OSError:
            return 0

    @staticmethod
    def new_token() -> str:
        """A unique, URL-safe correlation token for one probe."""
        return "oob" + secrets.token_hex(8)

    def url_for(self, token: str) -> str:
        """The full callback URL to hand to a target for the given token."""
        return f"{self.base_url}/{token}"

    def hostname_for(self, token: str) -> str:
        """The DNS callback hostname for ``token`` (``<token>.<zone>``).

        Returns ``""`` when no zone is configured, so callers can treat an empty
        string as "DNS channel unavailable" and skip DNS-only payloads.
        """
        if not self._dns_zone:
            return ""
        return f"{token}.{self._dns_zone}"

    # ── evidence ─────────────────────────────────────────────────────────────
    def _record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)
        logger.info(
            "OAST callback: %s %s from %s (token=%s)",
            interaction.method, interaction.path, interaction.client_ip, interaction.token,
        )

    def interactions(self, token: str, channel: Optional[str] = None) -> list[Interaction]:
        with self._lock:
            return [
                i for i in self._interactions
                if token and token in i.path and (channel is None or i.channel == channel)
            ]

    def hit(self, token: str, channel: Optional[str] = None) -> bool:
        return bool(self.interactions(token, channel=channel))

    def poll(self, token: str, timeout: float = 3.0, interval: float = 0.05,
             channel: Optional[str] = None) -> bool:
        """Block up to ``timeout`` seconds waiting for a callback for ``token``.

        Pass ``channel="dns"`` or ``channel="http"`` to wait for a specific
        channel; the default accepts either. Safe to call from an executor
        thread inside an async detector, it never touches the event loop.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            if self.hit(token, channel=channel):
                return True
            time.sleep(interval)
        return self.hit(token, channel=channel)

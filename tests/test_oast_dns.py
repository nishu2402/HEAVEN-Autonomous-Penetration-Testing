"""Phase 1 — in-house DNS + routable HTTP OAST collaborator.

Covers the DNS listener added to :mod:`heaven.vulnscan.oast` (records and
answers A queries inside its delegated zone, correlates the probe token across
channels, ignores out-of-zone traffic), the channel-aware polling, and the
DNS-channel payloads wired into the OOB scanner and the injection scanner's
blind-SQLi path. Each positive assertion is paired with a negative one so a
benign / HTTP-only / collaborator-less run keeps its original behaviour and no
finding is ever invented without an observed callback.
"""

from __future__ import annotations

import re
import socket
import struct

import pytest

from heaven.vulnscan.oast import OASTListener

ZONE = "oast.local"


# ─────────────────────────────────────────────────────────────────────────────
# Low-level DNS helpers for the tests (a resolver the "target" uses).
# ─────────────────────────────────────────────────────────────────────────────

def _dns_query(hostname: str, qtype: int = 1) -> bytes:
    header = b"\x12\x34" + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in hostname.split("."))
    return header + q + b"\x00" + struct.pack(">HH", qtype, 1)


def _resolve(hostname: str, port: int, qtype: int = 1) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(_dns_query(hostname, qtype), ("127.0.0.1", port))
        resp, _ = s.recvfrom(512)
        return resp
    except OSError:
        return None
    finally:
        s.close()


def _http_raw(port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """Send raw bytes to the HTTP listener and return the full response, so a
    test can forge a hostile request line / headers the stdlib client cannot."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        chunks = []
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# DNS listener
# ─────────────────────────────────────────────────────────────────────────────

def test_dns_listener_records_and_answers_a():
    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        assert oast.dns_enabled is True
        token = oast.new_token()
        host = oast.hostname_for(token)
        assert host == f"{token}.{ZONE}"

        resp = _resolve(host, oast.dns_port)
        assert resp is not None
        ancount = struct.unpack(">H", resp[6:8])[0]
        assert ancount == 1                                   # an A answer
        assert ".".join(str(b) for b in resp[-4:]) == "127.0.0.1"

        assert oast.poll(token, timeout=2.0, channel="dns") is True
        hits = oast.interactions(token, channel="dns")
        assert len(hits) == 1 and hits[0].channel == "dns" and hits[0].method == "A"


def test_dns_listener_correlates_prepended_exfil_labels():
    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        token = oast.new_token()
        # Exfil techniques prepend data labels to the probe hostname.
        _resolve(f"deadbeef.{oast.hostname_for(token)}", oast.dns_port, qtype=16)
        assert oast.hit(token, channel="dns") is True


def test_dns_listener_ignores_out_of_zone():
    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        _resolve("evil.example.net", oast.dns_port)
        _resolve("oast.local.evil.net", oast.dns_port)        # zone as a prefix only
        assert oast.interactions("evil") == []
        assert len(oast._interactions) == 0  # nothing recorded outside the zone


def test_http_only_listener_has_no_dns_channel():
    # Backward compatibility: no zone ⇒ DNS entirely inactive, hostname_for empty.
    with OASTListener() as oast:
        assert oast.dns_enabled is False
        assert oast.dns_zone == ""
        assert oast.hostname_for(oast.new_token()) == ""
        assert oast.dns_port == 0


def test_channel_filter_separates_http_and_dns():
    import urllib.request
    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        token = oast.new_token()
        urllib.request.urlopen(oast.url_for(token), timeout=2).read()
        assert oast.hit(token, channel="http") is True
        assert oast.hit(token, channel="dns") is False
        assert oast.hit(token) is True                        # either channel


def test_single_token_correlates_http_and_dns_channels():
    # One probe token called back on BOTH channels is recorded and correlated as a
    # single interaction set, so a target that resolves the hostname AND fetches
    # the URL is proven out of band on either signal.
    import urllib.request
    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        token = oast.new_token()
        _resolve(oast.hostname_for(token), oast.dns_port)          # DNS callback
        urllib.request.urlopen(oast.url_for(token), timeout=2).read()  # HTTP callback
        assert oast.poll(token, timeout=2.0) is True
        channels = {h.channel for h in oast.interactions(token)}
        assert channels == {"dns", "http"}, channels
        assert oast.hit(token, channel="dns") and oast.hit(token, channel="http")


def test_public_ip_falls_back_to_loopback_for_non_ipv4():
    oast = OASTListener(dns_zone=ZONE, advertised_host="collab.example.com")
    assert oast._public_ip == "127.0.0.1"                     # hostname is not an A literal
    oast2 = OASTListener(dns_zone=ZONE, advertised_host="203.0.113.5")
    assert oast2._public_ip == "203.0.113.5"                  # IPv4 advertised host is used


# ─────────────────────────────────────────────────────────────────────────────
# OOB scanner + injection scanner DNS paths (end to end, via a target whose
# resolver IS the collaborator)
# ─────────────────────────────────────────────────────────────────────────────

async def _vulnerable_server(dns_port: int):
    """An app that resolves any in-zone hostname it is handed — models blind
    cmdi (nslookup), SSRF and SQLi (xp_dirtree/LOAD_FILE) that escape via DNS."""
    from aiohttp import web

    host_re = re.compile(r"([a-z0-9.\-]*oob[0-9a-f]+\.%s)" % re.escape(ZONE))

    async def handler(request):
        for _k, v in request.query.items():
            m = host_re.search(v)
            if m:
                _resolve(m.group(1), dns_port)
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


@pytest.mark.asyncio
async def test_oob_scanner_proves_dns_ssrf_and_cmdi():
    pytest.importorskip("aiohttp")
    from heaven.vulnscan.oob_scanner import scan_oob

    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        runner, port = await _vulnerable_server(oast.dns_port)
        try:
            url = f"http://127.0.0.1:{port}/app?host=1&cmd=1"
            res = await scan_oob([url], oast=oast, timeout=6.0)
        finally:
            await runner.cleanup()

    types = {f["vuln_type"] for f in res["findings"]}
    assert "ssrf" in types and "command_injection" in types
    # Every finding was proven out of band, here over the DNS channel.
    assert res["findings"]
    assert all(f["evidence"]["callback_channel"] == "dns" for f in res["findings"])


@pytest.mark.asyncio
async def test_injection_scanner_proves_oob_dns_sqli():
    pytest.importorskip("aiohttp")
    from heaven.vulnscan.injection_scanner import scan_for_injections

    with OASTListener(dns_zone=ZONE, dns_bind="127.0.0.1", dns_port=0,
                      public_ip="127.0.0.1") as oast:
        runner, port = await _vulnerable_server(oast.dns_port)
        try:
            url = f"http://127.0.0.1:{port}/item?id=1"
            res = await scan_for_injections([url], oast=oast)
        finally:
            await runner.cleanup()

    oob = [f for f in res["findings"] if f.get("evidence", {}).get("technique") == "oob_dns"]
    assert oob, "expected an out-of-band DNS-exfil SQLi finding"
    assert oob[0]["severity"] == "critical"
    assert oob[0]["evidence"]["channels"] == ["dns"]


@pytest.mark.asyncio
async def test_injection_scanner_without_oast_skips_oob_dns():
    pytest.importorskip("aiohttp")
    from heaven.vulnscan.injection_scanner import scan_for_injections

    runner, port = await _vulnerable_server(0)  # dns_port irrelevant, no collaborator
    try:
        url = f"http://127.0.0.1:{port}/item?id=1"
        res = await scan_for_injections([url], oast=None)   # no collaborator supplied
    finally:
        await runner.cleanup()

    # No collaborator ⇒ the OOB DNS probe is a no-op; nothing is invented.
    assert [f for f in res["findings"] if f.get("evidence", {}).get("technique") == "oob_dns"] == []


# ─────────────────────────────────────────────────────────────────────────────
# HTTP listener hardening. A routable collaborator (``heaven oast`` on a public
# box) parses untrusted inbound requests from real targets AND internet noise,
# so it must not leak the runtime, crash, hang a worker thread, or grow without
# bound. Each test pairs the hardened behaviour with the preserved good path.
# ─────────────────────────────────────────────────────────────────────────────

def test_http_response_hides_server_and_date_banner():
    # The stdlib http.server would answer every callback with
    # ``Server: BaseHTTP/x Python/x.y.z`` (+ Date), advertising the exact runtime
    # to whoever connects. The collaborator response must disclose neither, while
    # still serving the 1x1 gif body some SSRF sinks require.
    with OASTListener() as oast:
        token = oast.new_token()
        resp = _http_raw(
            oast.port,
            f"GET /{token} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode(),
        )
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1").lower()
    assert resp.startswith(b"HTTP/1.1 200 OK")
    assert "server:" not in head and "date:" not in head
    assert "python/" not in head and "basehttp" not in head
    assert b"GIF89a" in resp                                   # good path intact
    assert oast.hit(token, channel="http") is True


def test_http_malformed_content_length_is_recorded_not_crashed():
    # ``Content-Length: abc`` used to raise ValueError BEFORE the interaction was
    # recorded, silently losing a genuine callback (and dumping a traceback to
    # stderr). The callback must still be recorded and answered; the unparseable
    # length simply yields no body.
    with OASTListener() as oast:
        token = oast.new_token()
        resp = _http_raw(
            oast.port,
            (f"POST /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n"
             f"Connection: close\r\n\r\nhello").encode(),
        )
        assert resp.startswith(b"HTTP/1.1 200 OK")
        assert oast.poll(token, timeout=1.0, channel="http") is True
        assert oast.interactions(token)[0].body == ""


def test_http_negative_content_length_does_not_hang():
    # ``Content-Length: -1`` used to reach rfile.read(-1), which blocks until EOF
    # and pins the worker thread. It must short-circuit and answer promptly.
    import time
    with OASTListener() as oast:
        token = oast.new_token()
        t0 = time.monotonic()
        resp = _http_raw(
            oast.port,
            (f"POST /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n"
             f"Connection: close\r\n\r\nAB").encode(),
        )
        elapsed = time.monotonic() - t0
    assert resp.startswith(b"HTTP/1.1 200 OK")
    assert elapsed < 2.0                                       # no hang
    assert oast.hit(token, channel="http") is True


def test_http_oversized_body_is_capped():
    from heaven.vulnscan.oast import _MAX_CALLBACK_BODY
    # A huge declared body must never be buffered in full; it is capped so a
    # hostile caller cannot exhaust memory, and the callback is still recorded.
    with OASTListener() as oast:
        token = oast.new_token()
        big = b"A" * (_MAX_CALLBACK_BODY + 4096)
        _http_raw(
            oast.port,
            (f"POST /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(big)}\r\n"
             f"Connection: close\r\n\r\n").encode() + big,
        )
        assert oast.poll(token, timeout=2.0, channel="http") is True
        assert len(oast.interactions(token)[0].body) == _MAX_CALLBACK_BODY


def test_http_handler_enforces_a_request_timeout():
    from heaven.vulnscan.oast import _Handler, _REQUEST_TIMEOUT_S
    # A per-request socket timeout bounds a slow-loris connection that never
    # finishes its request line; without it the stdlib handler waits forever.
    assert _Handler.timeout == _REQUEST_TIMEOUT_S
    assert _Handler.timeout and _Handler.timeout > 0


def test_interactions_are_capped_and_recent_callback_survives():
    import time

    from heaven.vulnscan.oast import Interaction, _MAX_INTERACTIONS
    # A long-running public collaborator sees internet background noise; the
    # interaction store must stay bounded, while a just-arrived token still
    # correlates (a detector polls within seconds of sending its probe).
    with OASTListener() as oast:
        early = "oobEARLYSENTINEL"
        oast._record(Interaction(token=early, method="GET", path=f"/{early}",
                                 client_ip="1.2.3.4", at=time.monotonic()))
        for i in range(_MAX_INTERACTIONS + 300):
            oast._record(Interaction(token=f"oob{i:x}", method="GET", path=f"/oob{i:x}",
                                     client_ip="1.2.3.4", at=time.monotonic()))
        recent = "oobRECENTSENTINEL"
        oast._record(Interaction(token=recent, method="GET", path=f"/{recent}",
                                 client_ip="1.2.3.4", at=time.monotonic()))
        assert len(oast._interactions) == _MAX_INTERACTIONS
        assert oast.hit(recent) is True                        # in-flight correlation kept
        assert oast.hit(early) is False                        # oldest evicted

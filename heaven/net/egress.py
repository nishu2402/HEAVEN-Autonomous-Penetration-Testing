"""Egress routing / source-IP anonymisation for HEAVEN's outbound traffic.

The web dashboard and API stay bound to **localhost**; only the *target-bound
scanning* traffic is pushed through the operator-configured egress path. This is
legitimate OPSEC for an **authorized** engagement (hide the assessor's real IP
from the target, or exit from an in-scope network) — it is deliberately not
attribution-evasion tooling: every scan still requires explicit authorization.

Two mechanisms, chosen by ``HEAVEN_EGRESS_MODE``:

``wireguard`` — **tunnel mode, network layer.** The complete path. A WireGuard
    interface (``wg-quick up <conf>``) routes *every* tool transparently — nmap
    raw SYN/UDP/OS scans, the nuclei binary, and every in-process aiohttp/httpx
    check — with no per-tool configuration and **no extra Python dependency**.
    Bringing the interface up needs root, handled through the same passwordless
    ``sudo -n`` policy nmap already uses (``HEAVEN_EGRESS_SUDO``).

``http`` / ``socks5`` / ``tor`` — **proxy mode, application layer.** Covers:
      * external tools via native flags — nuclei (``-proxy``), ffuf (``-x``);
      * nmap via **proxychains** (TCP *connect* scans only — raw SYN/UDP/OS
        cannot traverse a proxy, so we auto-switch to ``-sT``);
      * in-process *target* scanning over aiohttp via :func:`client_session`:
        HTTP proxies through ``trust_env``; **SOCKS5/Tor through a small built-in
        SOCKS5 connector** that speaks the RFC 1928 CONNECT handshake on a raw
        asyncio socket — so aiohttp routes through SOCKS with **no new
        dependency** (no ``aiohttp_socks`` / ``socksio`` / ``PySocks``) and DNS
        is resolved at the proxy (``socks5h`` semantics — no local leak). Only
        *no-auth* SOCKS is honoured in-process; an auth-requiring proxy, or a
        connector that can't be built, *fails closed* under the kill-switch
        rather than leaking the real IP;
      * enrichment traffic (NVD / OSV / threat-intel / LLM over httpx) is **not**
        target-bound and is deliberately left direct under a proxy — routing it
        through the *target's* proxy would be wrong; ``wireguard`` covers it at
        the network layer. (This is why a SOCKS URL is never exported to
        ``*_PROXY``: httpx/requests would try to import a missing SOCKS backend
        and crash — the built-in connector handles target aiohttp instead.)

``off`` (default / unset) is byte-for-byte the historical behaviour: every
helper here is a transparent no-op, so existing scans and tests are unaffected.

No new dependencies. The public IP-confirmation check reaches out to a small,
well-known set of plaintext IP-echo services purely to prove the egress works —
that is the whole point of the check and it is operator-initiated.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess  # nosec B404 -- fixed argv, no shell; see _sudo_prefix / tunnel_*
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Modes that push traffic through an application-layer proxy vs. a tunnel.
_PROXY_MODES = ("http", "socks5", "tor")
_VALID_MODES = ("off", *_PROXY_MODES, "wireguard")
_TOR_DEFAULT = "socks5://127.0.0.1:9050"

# Plaintext "what's my IP" echoes used only by confirm_egress(). Kept short and
# reputable; tried in order until one answers.
_IP_ECHO_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
)

# Hosts that must NEVER be proxied — the local dashboard/API and loopback, so a
# proxy can never accidentally route HEAVEN's own control plane.
_NO_PROXY_HOSTS = "localhost,127.0.0.1,::1,0.0.0.0"  # nosec B104 -- NO_PROXY list, not a bind


class EgressError(RuntimeError):
    """A configured egress could not be satisfied (misconfig / tool missing)."""


class EgressBlocked(EgressError):
    """Fail-closed: an in-process client cannot honour the armed egress, and the
    kill-switch forbids falling back to the real IP. Scanners catch this and
    skip the check rather than leak."""


@dataclass(frozen=True)
class EgressConfig:
    """The resolved, validated egress configuration for this process."""
    mode: str = "off"
    proxy_url: Optional[str] = None       # normalised proxy URL for proxy modes
    wg_config: Optional[str] = None       # path to a WireGuard .conf
    wg_interface: Optional[str] = None     # derived interface name (wg0, …)
    killswitch: bool = True                # fail closed when the path is unusable
    sudo_policy: str = "auto"              # auto | always | never (for wg-quick)
    error: Optional[str] = None            # non-fatal misconfig note, surfaced in status

    # ── predicates ──────────────────────────────────────────────────────────
    @property
    def armed(self) -> bool:
        return self.mode != "off"

    @property
    def is_proxy(self) -> bool:
        return self.mode in _PROXY_MODES

    @property
    def is_tunnel(self) -> bool:
        return self.mode == "wireguard"

    @property
    def is_socks(self) -> bool:
        # tor is always SOCKS; a socks5:// URL under any proxy mode is SOCKS too.
        return self.mode in ("socks5", "tor") or (
            bool(self.proxy_url) and str(self.proxy_url).lower().startswith("socks")
        )

    @property
    def in_process_proxyable(self) -> bool:
        """True when an in-process aiohttp client can honour this egress without a
        new dependency: off / tunnel (network layer), HTTP proxies (via
        ``trust_env``), and SOCKS/Tor (the built-in SOCKS5 connector in
        :func:`client_session`). False only for a misconfigured proxy (no URL)."""
        if self.mode in ("off", "wireguard"):
            return True
        return self.is_proxy and bool(self.proxy_url)


# ── configuration resolution (cached; reset on settings change) ─────────────

_cache: Optional[EgressConfig] = None


def _bool_env(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on", "enabled"):
        return True
    if raw in ("0", "false", "no", "off", "disabled"):
        return False
    return default


def _normalise_proxy_url(raw: str, *, default_scheme: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    p = urlparse(raw)
    if not p.hostname or not p.port:
        return None
    scheme = p.scheme.lower()
    # curl/proxychains understand socks5h; normalise the common aliases.
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    return f"{scheme}://{p.hostname}:{p.port}"


def _derive_interface(wg_config: Optional[str], explicit: str) -> Optional[str]:
    if explicit.strip():
        return explicit.strip()
    if wg_config:
        return Path(wg_config).stem or None
    return None


def resolve_egress(refresh: bool = False) -> EgressConfig:
    """Return the process-wide :class:`EgressConfig`, reading it from the
    environment once and caching it. ``refresh=True`` (or :func:`reset_egress`)
    re-reads — the Settings page / ``heaven config`` call that after a change."""
    global _cache
    if _cache is not None and not refresh:
        return _cache

    mode = (os.environ.get("HEAVEN_EGRESS_MODE") or "off").strip().lower()
    if mode in ("", "none", "direct", "disabled"):
        mode = "off"
    if mode not in _VALID_MODES:
        logger.warning("Unknown HEAVEN_EGRESS_MODE=%r — treating as 'off'", mode)
        _cache = EgressConfig(error=f"unknown mode {mode!r}")
        return _cache

    killswitch = _bool_env("HEAVEN_EGRESS_KILLSWITCH", default=True)
    sudo_policy = (os.environ.get("HEAVEN_EGRESS_SUDO") or "auto").strip().lower()
    if sudo_policy not in ("auto", "always", "never"):
        sudo_policy = "auto"

    proxy_url: Optional[str] = None
    wg_config: Optional[str] = None
    wg_interface: Optional[str] = None
    error: Optional[str] = None

    if mode == "tor":
        proxy_url = _normalise_proxy_url(
            os.environ.get("HEAVEN_TOR_SOCKS") or _TOR_DEFAULT, default_scheme="socks5")
        if not proxy_url:
            error = "invalid HEAVEN_TOR_SOCKS"
    elif mode == "http":
        proxy_url = _normalise_proxy_url(
            os.environ.get("HEAVEN_EGRESS_PROXY") or "", default_scheme="http")
        if not proxy_url:
            error = "HEAVEN_EGRESS_PROXY not set (need e.g. http://127.0.0.1:8080)"
    elif mode == "socks5":
        proxy_url = _normalise_proxy_url(
            os.environ.get("HEAVEN_EGRESS_PROXY") or "", default_scheme="socks5")
        if not proxy_url:
            error = "HEAVEN_EGRESS_PROXY not set (need e.g. socks5://127.0.0.1:1080)"
    elif mode == "wireguard":
        wg_config = (os.environ.get("HEAVEN_WG_CONFIG") or "").strip() or None
        wg_interface = _derive_interface(wg_config, os.environ.get("HEAVEN_WG_INTERFACE") or "")
        if not wg_config and not wg_interface:
            error = "set HEAVEN_WG_CONFIG to a WireGuard .conf path"
        elif wg_config and not Path(wg_config).expanduser().exists():
            error = f"WireGuard config not found: {wg_config}"

    _cache = EgressConfig(
        mode=mode, proxy_url=proxy_url, wg_config=wg_config,
        wg_interface=wg_interface, killswitch=killswitch,
        sudo_policy=sudo_policy, error=error,
    )
    # Keep process env in sync so env-honouring clients + subprocess tools pick
    # up (or lose) the proxy immediately, without a restart.
    _apply_proxy_env(_cache)
    return _cache


def reset_egress() -> EgressConfig:
    """Drop the cache and re-read from the environment. Call after a settings
    change (wired into :func:`heaven.settings_catalog.apply_settings`)."""
    return resolve_egress(refresh=True)


def _apply_proxy_env(cfg: EgressConfig) -> None:
    """Export / clear the standard ``*_PROXY`` variables so httpx (trusts env by
    default), ``requests``, curl and the pentest binaries inherit the egress.

    **HTTP proxies only** are exported (to ``HTTP_PROXY``/``HTTPS_PROXY``/
    ``ALL_PROXY``). A **SOCKS** URL is deliberately *not* exported to any
    ``*_PROXY`` var: httpx/requests would try to import a SOCKS backend we don't
    bundle and crash, and nothing of ours reads it via env anyway — nuclei/ffuf
    take it as an explicit flag, nmap via a proxychains config, curl via
    ``--socks5-hostname``, and target aiohttp via the built-in SOCKS connector.
    ``NO_PROXY`` always shields loopback / the dashboard."""
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        os.environ.pop(var, None)

    if cfg.is_proxy and cfg.proxy_url and not cfg.is_socks:
        os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = cfg.proxy_url
        os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = cfg.proxy_url
        os.environ["ALL_PROXY"] = os.environ["all_proxy"] = cfg.proxy_url

    if cfg.armed:
        os.environ.setdefault("NO_PROXY", _NO_PROXY_HOSTS)
        os.environ.setdefault("no_proxy", _NO_PROXY_HOSTS)


# ── external-tool helpers (native proxy flags / proxychains) ────────────────

def nuclei_proxy_args() -> list[str]:
    """``["-proxy", <url>]`` for the nuclei binary under a proxy mode, else
    ``[]`` (tunnel mode needs nothing — nuclei rides the network tunnel)."""
    cfg = resolve_egress()
    if cfg.is_proxy and cfg.proxy_url:
        return ["-proxy", cfg.proxy_url]
    return []


def ffuf_proxy_args() -> list[str]:
    """``["-x", <url>]`` for ffuf under a proxy mode, else ``[]``."""
    cfg = resolve_egress()
    if cfg.is_proxy and cfg.proxy_url:
        return ["-x", cfg.proxy_url]
    return []


_proxychains_conf: Optional[str] = None


def _write_proxychains_conf(proxy_url: str) -> Optional[str]:
    """Write (once) a minimal proxychains config pointing at ``proxy_url`` and
    return its path, or ``None`` if the URL can't be parsed."""
    global _proxychains_conf
    p = urlparse(proxy_url)
    if not p.hostname or not p.port:
        return None
    ptype = "socks5" if p.scheme.lower().startswith("socks") else "http"
    if _proxychains_conf and Path(_proxychains_conf).exists():
        return _proxychains_conf
    body = (
        "# generated by HEAVEN — routes wrapped TCP through the egress proxy\n"
        "strict_chain\n"
        "proxy_dns\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "[ProxyList]\n"
        f"{ptype} {p.hostname} {p.port}\n"
    )
    fd, path = tempfile.mkstemp(prefix="heaven-proxychains-", suffix=".conf")
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    _proxychains_conf = path
    return path


def proxychains_prefix() -> list[str]:
    """argv prefix that wraps a subprocess (e.g. nmap ``-sT``) so its TCP exits
    through the egress proxy. ``[]`` when not in proxy mode, or when neither
    ``proxychains4`` nor ``proxychains`` is installed (the scan-level guard then
    decides whether to fail closed)."""
    cfg = resolve_egress()
    if not (cfg.is_proxy and cfg.proxy_url):
        return []
    binary = shutil.which("proxychains4") or shutil.which("proxychains")
    if not binary:
        return []
    conf = _write_proxychains_conf(cfg.proxy_url)
    if not conf:
        return []
    return [binary, "-q", "-f", conf]


def nmap_forces_connect_scan() -> bool:
    """Raw SYN/UDP/OS scans can't traverse a proxy — under proxy mode nmap must
    use a TCP connect scan (``-sT``). Tunnel mode keeps full raw capability."""
    return resolve_egress().is_proxy


def tcp_proxy_available() -> bool:
    """True when a subprocess's TCP can actually be forced through the proxy —
    i.e. ``proxychains`` is installed. Always True when not in proxy mode (off /
    WireGuard need no wrapper)."""
    cfg = resolve_egress()
    if not cfg.is_proxy:
        return True
    return bool(shutil.which("proxychains4") or shutil.which("proxychains"))


def port_scan_blocked() -> bool:
    """Fail-closed guard for the port scanner. Under a proxy/Tor egress with the
    kill-switch on, an nmap connect scan (or the raw-socket connect fallback)
    that *can't* be wrapped in proxychains would send packets straight from the
    real IP — so the caller must SKIP the port scan rather than leak. nuclei and
    HTTP checks still route via the proxy; a WireGuard tunnel is never blocked
    (it carries raw nmap at the network layer)."""
    cfg = resolve_egress()
    return cfg.is_proxy and cfg.killswitch and not tcp_proxy_available()


# ── aiohttp integration ─────────────────────────────────────────────────────

def aiohttp_session_kwargs() -> dict[str, Any]:
    """Extra kwargs to merge into an ``aiohttp.ClientSession(**...)`` so *target*
    traffic honours the egress. ``{"trust_env": True}`` for HTTP-proxy mode
    (aiohttp then reads ``HTTPS_PROXY`` per request); ``{}`` for off / tunnel /
    SOCKS (tunnels are network-layer; SOCKS gets a dedicated connector from
    :func:`client_session`, not env). Safe to splat unconditionally."""
    cfg = resolve_egress()
    if cfg.is_proxy and cfg.proxy_url and not cfg.is_socks:
        return {"trust_env": True}
    return {}


# ── in-process SOCKS5 connector (dependency-free) ───────────────────────────
# aiohttp/httpx ship no SOCKS support. Rather than add aiohttp_socks / PySocks we
# implement the tiny RFC 1928 SOCKS5 CONNECT handshake directly on a raw asyncio
# socket and hand the tunnelled socket to aiohttp — so *target* aiohttp scans
# route through socks5:// / tor with no new dependency. No-auth only (RFC 1929):
# a local Tor / SOCKS listener needs none, and an auth-requiring proxy replies
# "no acceptable methods" so we fail closed. The hostname is sent to the proxy
# (socks5h semantics) — DNS never resolves locally, so it can't leak.

_SOCKS5_ERRORS = {
    0x01: "general SOCKS server failure", 0x02: "connection not allowed",
    0x03: "network unreachable", 0x04: "host unreachable",
    0x05: "connection refused", 0x06: "TTL expired",
    0x07: "command not supported", 0x08: "address type not supported",
}


def _socks5_addr(host: str) -> tuple[int, bytes]:
    """Encode ``host`` as a SOCKS5 (ATYP, addr) pair — IPv4/IPv6 literal when it
    parses as one, else a domain name (resolved at the proxy = no local leak)."""
    import socket as _socket
    try:
        return 0x01, _socket.inet_pton(_socket.AF_INET, host)
    except OSError:
        pass
    try:
        return 0x04, _socket.inet_pton(_socket.AF_INET6, host)
    except OSError:
        pass
    try:
        encoded = host.encode("ascii")
    except UnicodeEncodeError:
        encoded = host.encode("idna")
    if len(encoded) > 255:
        raise OSError("hostname too long for SOCKS5")
    return 0x03, bytes([len(encoded)]) + encoded


_socks_connector_cls: Optional[type] = None


def _socks_connector_class() -> Optional[type]:
    """Build (once) an ``aiohttp.TCPConnector`` subclass that tunnels every
    connection through a SOCKS5 proxy. Returns ``None`` if aiohttp's connection
    seam is unavailable (a future aiohttp could rename it) — the caller then
    fails closed instead of leaking."""
    global _socks_connector_cls
    if _socks_connector_cls is not None:
        return _socks_connector_cls
    try:
        import socket as _socket
        import sys as _sys

        import aiohttp
        from aiohttp.client_exceptions import ClientConnectorError

        if not hasattr(aiohttp.TCPConnector, "_wrap_create_connection"):
            return None

        class _Socks5Connector(aiohttp.TCPConnector):  # type: ignore[misc]
            def __init__(self, *, socks_host: str, socks_port: int, **kw: Any) -> None:
                super().__init__(**kw)
                self._socks_host = socks_host
                self._socks_port = int(socks_port)

            async def _recv_exact(self, sock: Any, n: int) -> bytes:
                buf = b""
                while len(buf) < n:
                    chunk = await self._loop.sock_recv(sock, n - len(buf))
                    if not chunk:
                        raise OSError("SOCKS5 proxy closed the connection")
                    buf += chunk
                return buf

            async def _socks5_connect(self, host: str, port: int) -> Any:
                loop = self._loop
                infos = await loop.getaddrinfo(
                    self._socks_host, self._socks_port, type=_socket.SOCK_STREAM)
                family, stype, proto, _canon, sa = infos[0]
                sock = _socket.socket(family, stype, proto)
                sock.setblocking(False)
                try:
                    await loop.sock_connect(sock, sa)
                    await loop.sock_sendall(sock, b"\x05\x01\x00")   # greet: no-auth
                    greet = await self._recv_exact(sock, 2)
                    if greet[0] != 0x05 or greet[1] == 0xFF:
                        raise OSError("SOCKS5 proxy rejected the no-auth handshake "
                                      "(does it require a username/password?)")
                    if greet[1] != 0x00:
                        raise OSError(f"SOCKS5 proxy asked for unsupported auth "
                                      f"method {greet[1]:#x}")
                    atyp, addr = _socks5_addr(host)
                    request = (b"\x05\x01\x00" + bytes([atyp]) + addr
                               + int(port).to_bytes(2, "big"))
                    await loop.sock_sendall(sock, request)
                    reply = await self._recv_exact(sock, 4)
                    if reply[0] != 0x05:
                        raise OSError("bad SOCKS5 reply version")
                    if reply[1] != 0x00:
                        raise OSError("SOCKS5 CONNECT failed: "
                                      + _SOCKS5_ERRORS.get(reply[1], f"code {reply[1]:#x}"))
                    bnd = reply[3]
                    if bnd == 0x01:
                        await self._recv_exact(sock, 4 + 2)
                    elif bnd == 0x03:
                        ln = (await self._recv_exact(sock, 1))[0]
                        await self._recv_exact(sock, ln + 2)
                    elif bnd == 0x04:
                        await self._recv_exact(sock, 16 + 2)
                    else:
                        raise OSError("bad SOCKS5 bound-address type")
                    return sock
                except BaseException:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    raise

            async def _wrap_create_connection(  # type: ignore[override]
                self, *args: Any, addr_infos: Any, req: Any, timeout: Any,
                client_error: type[Exception] = ClientConnectorError, **kwargs: Any,
            ) -> Any:
                import asyncio as _asyncio
                port = req.port or (443 if req.is_ssl() else 80)
                try:
                    tmo = getattr(timeout, "sock_connect", None)
                    coro = self._socks5_connect(req.host, port)
                    sock = await (_asyncio.wait_for(coro, tmo) if tmo else coro)
                except Exception as exc:  # noqa: BLE001 — map to aiohttp's error
                    raise client_error(req.connection_key, OSError(str(exc))) from exc
                try:
                    if (kwargs.get("ssl")
                            and getattr(self, "_ssl_shutdown_timeout", None)
                            and _sys.version_info >= (3, 11)):
                        kwargs["ssl_shutdown_timeout"] = self._ssl_shutdown_timeout
                    return await self._loop.create_connection(*args, **kwargs, sock=sock)
                except OSError as exc:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    raise client_error(req.connection_key, exc) from exc

        _socks_connector_cls = _Socks5Connector
        return _socks_connector_cls
    except Exception:  # noqa: BLE001 — any import/API mismatch → fail closed
        logger.debug("SOCKS5 connector unavailable", exc_info=True)
        return None


def _make_socks_connector(cfg: EgressConfig, existing: Any):  # noqa: ANN201
    """Build a SOCKS5-tunnelling connector for ``cfg``, inheriting the SSL and
    connection-limit intent of any connector the caller already supplied (so a
    scanner's ``TCPConnector(ssl=False, limit=N)`` keeps its behaviour but now
    routes through SOCKS instead of connecting direct). ``None`` on failure."""
    p = urlparse(cfg.proxy_url or "")
    if not p.hostname or not p.port:
        return None
    cls = _socks_connector_class()
    if cls is None:
        return None
    ssl_intent = getattr(existing, "_ssl", True) if existing is not None else True
    limit = getattr(existing, "_limit", 100) if existing is not None else 100
    try:
        return cls(socks_host=p.hostname, socks_port=int(p.port),
                   ssl=ssl_intent, limit=limit)
    except Exception:  # noqa: BLE001
        logger.debug("could not construct SOCKS5 connector", exc_info=True)
        return None


def _install_throttle(kwargs: dict) -> None:
    """Attach HEAVEN's global per-target request throttle to a session's kwargs.
    Kept best-effort: a throttle problem must never stop a scan from running."""
    try:
        from heaven.net.throttle import instrument_session_kwargs
        instrument_session_kwargs(kwargs)
    except Exception:  # noqa: BLE001
        logger.debug("throttle install unavailable", exc_info=True)


def client_session(*args: Any, **kwargs: Any):  # noqa: ANN201 -> aiohttp.ClientSession
    """Drop-in replacement for ``aiohttp.ClientSession`` that routes *target*
    traffic through the egress. Identical to a plain session when egress is off
    or in tunnel mode. Under an HTTP proxy it adds ``trust_env``. Under SOCKS/Tor
    it installs the built-in :func:`_socks_connector_class` so aiohttp tunnels
    through the proxy with no new dependency (transparently replacing any
    caller-supplied connector, preserving its SSL/limit intent). Only if the
    connector genuinely can't be built does it fall back: raise
    :class:`EgressBlocked` when the kill-switch is on (caller skips, no leak), or
    warn once and proceed direct when it's off (operator-accepted)."""
    import aiohttp

    cfg = resolve_egress()
    if cfg.is_proxy and cfg.is_socks:
        caller_connector = kwargs.pop("connector", None)
        connector = _make_socks_connector(cfg, caller_connector)
        if connector is not None:
            _warn_socks_routed_once()
            kwargs["connector"] = connector
            _install_throttle(kwargs)
            return aiohttp.ClientSession(*args, **kwargs)
        # Connector could not be built (bad proxy URL / aiohttp seam gone).
        if cfg.killswitch:
            _warn_socks_blocked_once()
            raise EgressBlocked(
                f"in-process HTTP check cannot use the {cfg.mode} proxy "
                "(built-in SOCKS connector unavailable); skipped by the "
                "kill-switch. Use WireGuard tunnel mode for full coverage.")
        _warn_socks_bypass_once()
        if caller_connector is not None:
            kwargs["connector"] = caller_connector   # restore for direct fallback
    else:
        for k, v in aiohttp_session_kwargs().items():
            kwargs.setdefault(k, v)
    _install_throttle(kwargs)
    return aiohttp.ClientSession(*args, **kwargs)


_socks_routed_warned = False
_socks_bypass_warned = False
_socks_blocked_warned = False


def _warn_socks_routed_once() -> None:
    global _socks_routed_warned
    if not _socks_routed_warned:
        _socks_routed_warned = True
        logger.info(
            "Egress SOCKS/Tor: in-process HTTP checks route through the proxy via "
            "the built-in SOCKS5 connector (no-auth). Raw SYN/UDP nmap scans and "
            "authenticated SOCKS proxies still need WireGuard.")


def _warn_socks_bypass_once() -> None:
    global _socks_bypass_warned
    if not _socks_bypass_warned:
        _socks_bypass_warned = True
        logger.warning(
            "Egress kill-switch is OFF and the built-in SOCKS connector is "
            "unavailable: in-process HTTP checks run DIRECT (real IP). Enable "
            "the kill-switch or use WireGuard for full coverage.")


def _warn_socks_blocked_once() -> None:
    global _socks_blocked_warned
    if not _socks_blocked_warned:
        _socks_blocked_warned = True
        logger.warning(
            "Egress mode is SOCKS/Tor with the kill-switch on but the built-in "
            "SOCKS connector is unavailable: in-process HTTP checks are SKIPPED "
            "so they can't leak your real IP. nuclei and nmap still route via "
            "the proxy. Use WireGuard tunnel mode for full in-process coverage.")


# ── WireGuard tunnel lifecycle ──────────────────────────────────────────────

def _is_root() -> bool:
    getuid = getattr(os, "geteuid", None)
    return bool(getuid and getuid() == 0)


def _sudo_prefix(policy: str) -> tuple[str, ...]:
    """``sudo -n`` prefix for privileged wg-quick, mirroring nmap's policy.
    ``sudo -n`` never prompts — it fails fast if a password would be needed."""
    if policy == "never" or _is_root():
        return ()
    sudo = shutil.which("sudo")
    if not sudo:
        return ()
    if policy == "always":
        return (sudo, "-n")
    try:
        probe = subprocess.run(  # nosec B603 -- fixed argv, no shell
            [sudo, "-n", "true"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False)
        return (sudo, "-n") if probe.returncode == 0 else ()
    except (OSError, subprocess.SubprocessError):
        return ()


def _wg_quick_target(cfg: EgressConfig) -> Optional[str]:
    """wg-quick accepts either a .conf path or a bare interface name."""
    if cfg.wg_config:
        return str(Path(cfg.wg_config).expanduser())
    return cfg.wg_interface


def _run(argv: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(  # nosec B603 -- fixed argv, no shell
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False, text=True)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timed out"
    except OSError as e:
        return 1, "", str(e)


def tunnel_up() -> dict:
    """Bring the WireGuard interface up (``wg-quick up``). Idempotent-ish: if the
    interface already shows up, reports success without re-adding."""
    cfg = resolve_egress()
    if not cfg.is_tunnel:
        return {"ok": False, "error": "egress mode is not 'wireguard'"}
    if not shutil.which("wg-quick"):
        return {"ok": False, "error": "wg-quick not installed (install wireguard-tools)"}
    target = _wg_quick_target(cfg)
    if not target:
        return {"ok": False, "error": cfg.error or "no WireGuard config/interface set"}
    if cfg.error:
        return {"ok": False, "error": cfg.error}
    if tunnel_status().get("up"):
        return {"ok": True, "already_up": True, "interface": cfg.wg_interface}
    sudo = list(_sudo_prefix(cfg.sudo_policy))
    rc, out, err = _run([*sudo, "wg-quick", "up", target], timeout=45)
    if rc != 0:
        detail = (err or out).strip()
        if rc == 1 and "sudo" in detail.lower() or (sudo and rc == 1 and not detail):
            detail = detail or "needs root — passwordless sudo unavailable; run `sudo wg-quick up` once"
        return {"ok": False, "error": detail or f"wg-quick up failed (rc={rc})"}
    return {"ok": True, "interface": cfg.wg_interface, "detail": (out or "interface up").strip()}


def tunnel_down() -> dict:
    """Tear the WireGuard interface down (``wg-quick down``)."""
    cfg = resolve_egress()
    if not shutil.which("wg-quick"):
        return {"ok": False, "error": "wg-quick not installed"}
    target = _wg_quick_target(cfg)
    if not target:
        return {"ok": False, "error": "no WireGuard config/interface set"}
    sudo = list(_sudo_prefix(cfg.sudo_policy))
    rc, out, err = _run([*sudo, "wg-quick", "down", target], timeout=30)
    if rc != 0:
        return {"ok": False, "error": (err or out).strip() or f"wg-quick down failed (rc={rc})"}
    return {"ok": True, "detail": (out or "interface down").strip()}


def tunnel_status() -> dict:
    """Parse ``wg show`` for the configured interface. Reports up/down, peer
    count and the (public) endpoint — never the private key."""
    cfg = resolve_egress()
    iface = cfg.wg_interface
    if not shutil.which("wg"):
        return {"up": False, "available": False, "error": "wg not installed"}
    # `wg show <iface> dump` → tab-separated; first line is the interface.
    argv = ["wg", "show", iface, "dump"] if iface else ["wg", "show", "all", "dump"]
    rc, out, err = _run(argv, timeout=10)
    if rc != 0 or not out.strip():
        return {"up": False, "available": True, "interface": iface}
    lines = [ln for ln in out.splitlines() if ln.strip()]
    peers = 0
    endpoint = None
    seen_iface = iface
    for ln in lines:
        cols = ln.split("\t")
        if not iface and len(cols) >= 1 and not seen_iface:
            seen_iface = cols[0]
        # A peer row has an endpoint column (index 2 for `wg show all dump` is
        # public-key; the endpoint sits at a later column). Count non-interface
        # rows conservatively as peers.
        if len(cols) >= 4:
            peers += 1
            ep = next((c for c in cols if ":" in c and "." in c), None)
            if ep and not endpoint:
                endpoint = ep
    return {"up": True, "available": True, "interface": seen_iface,
            "peers": max(peers - (1 if iface is None else 0), 0),
            "endpoint": endpoint}


# ── public-IP confirmation (leak check) ─────────────────────────────────────

_baseline_ip: Optional[str] = None


def _clean_ip(text: str) -> Optional[str]:
    text = (text or "").strip().splitlines()[0].strip() if text else ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


async def _http_ip(proxy: Optional[str], timeout: float) -> Optional[str]:
    """Fetch the public IP over httpx, optionally through an HTTP proxy."""
    import httpx
    kw: dict[str, Any] = {"timeout": timeout, "trust_env": proxy is None}
    if proxy:
        kw["proxy"] = proxy
    try:
        async with httpx.AsyncClient(**kw) as client:
            for url in _IP_ECHO_URLS:
                try:
                    r = await client.get(url)
                    ip = _clean_ip(r.text)
                    if ip:
                        return ip
                except Exception:  # noqa: BLE001  # nosec B112 -- try the next echo service
                    continue
    except Exception as e:  # noqa: BLE001
        logger.debug("egress IP fetch failed: %s", e)
    return None


async def _curl_socks_ip(proxy_url: str, timeout: float) -> Optional[str]:
    """Fetch the public IP through a SOCKS proxy via curl (no Python SOCKS dep)."""
    curl = shutil.which("curl")
    if not curl:
        return None
    p = urlparse(proxy_url)
    socks = f"{p.hostname}:{p.port}"
    for url in _IP_ECHO_URLS:
        rc, out, _ = _run(
            [curl, "-s", "--max-time", str(int(timeout)),
             "--socks5-hostname", socks, url], timeout=timeout + 3)
        ip = _clean_ip(out) if rc == 0 else None
        if ip:
            return ip
    return None


async def _aiohttp_socks_ip(cfg: EgressConfig, timeout: float) -> Optional[str]:
    """Fetch the public IP through the SOCKS proxy using the *same* built-in
    connector real scans use — the most faithful leak check, and it needs no curl.
    Returns ``None`` if the connector can't be built or nothing answers."""
    connector = _make_socks_connector(cfg, None)
    if connector is None:
        return None
    try:
        import aiohttp
    except Exception:  # noqa: BLE001
        return None
    try:
        ct = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=ct) as session:
            for url in _IP_ECHO_URLS:
                try:
                    async with session.get(url) as resp:
                        ip = _clean_ip(await resp.text())
                        if ip:
                            return ip
                except Exception:  # noqa: BLE001  # nosec B112 — try the next echo
                    continue
    except Exception as e:  # noqa: BLE001
        logger.debug("aiohttp SOCKS IP fetch failed: %s", e)
    return None


async def baseline_ip(timeout: float = 8.0) -> Optional[str]:
    """The direct (un-tunnelled) WAN IP, captured once and cached. Best-effort:
    once a tunnel is up this can't be re-measured from userspace, so we snapshot
    it lazily the first time egress is off / before a tunnel is raised."""
    global _baseline_ip
    if _baseline_ip:
        return _baseline_ip
    ip = await _http_ip(proxy=None, timeout=timeout)
    if ip and not resolve_egress().is_tunnel:
        _baseline_ip = ip
    return ip


async def confirm_egress(timeout: float = 10.0) -> dict:
    """Fetch the apparent public IP *through the active egress* and compare it to
    the direct baseline. This is the leak check: run it before scanning.

    Returns ``{mode, ok, public_ip, baseline_ip, changed, via, detail}``. ``ok``
    means the path is usable AND (for armed modes) the exit IP differs from the
    direct baseline — i.e. traffic really is leaving via the egress.
    """
    cfg = resolve_egress()
    base = await baseline_ip(timeout)

    if cfg.mode == "off":
        return {"mode": "off", "ok": True, "public_ip": base, "baseline_ip": base,
                "changed": False, "via": "direct",
                "detail": "no egress configured — traffic exits directly"}

    if cfg.error:
        return {"mode": cfg.mode, "ok": False, "public_ip": None, "baseline_ip": base,
                "changed": False, "via": cfg.mode, "detail": cfg.error}

    if cfg.is_tunnel:
        st = tunnel_status()
        # With the tunnel up, a *direct* fetch already exits via the tunnel.
        ip = await _http_ip(proxy=None, timeout=timeout) if st.get("up") else None
        changed = bool(ip and base and ip != base)
        ok = bool(st.get("up") and ip and (changed or base is None))
        detail = ("tunnel up" if st.get("up") else "tunnel is DOWN — run `heaven egress up`")
        if st.get("up") and base and not changed:
            detail = "tunnel up but exit IP == baseline (possible leak / split tunnel)"
        return {"mode": "wireguard", "ok": ok, "public_ip": ip, "baseline_ip": base,
                "changed": changed, "via": f"wireguard:{st.get('interface') or cfg.wg_interface}",
                "detail": detail, "interface": st.get("interface")}

    # proxy modes
    if not cfg.proxy_url:
        return {"mode": cfg.mode, "ok": False, "public_ip": None, "baseline_ip": base,
                "changed": False, "via": cfg.mode, "detail": "no proxy URL configured"}
    if cfg.is_socks:
        # curl is fast when present; otherwise fall back to the in-process SOCKS
        # connector (the exact path scans use) so verification never needs curl.
        ip = await _curl_socks_ip(cfg.proxy_url, timeout) if shutil.which("curl") else None
        if ip is None:
            ip = await _aiohttp_socks_ip(cfg, timeout)
        via = f"{cfg.mode}:{cfg.proxy_url}"
    else:
        ip = await _http_ip(proxy=cfg.proxy_url, timeout=timeout)
        via = f"http:{cfg.proxy_url}"

    changed = bool(ip and base and ip != base)
    ok = bool(ip and (changed or base is None))
    if ip is None:
        detail = f"proxy {cfg.proxy_url} did not return an IP — is it reachable?"
    elif base and not changed:
        detail = "proxy reachable but exit IP == baseline (not actually anonymising)"
    else:
        detail = "proxy exit confirmed"
    return {"mode": cfg.mode, "ok": ok, "public_ip": ip, "baseline_ip": base,
            "changed": changed, "via": via, "detail": detail}


# ── scan-time guard (fail-closed) ───────────────────────────────────────────

async def assert_ready(timeout: float = 10.0) -> dict:
    """Raise :class:`EgressError` when the kill-switch is on and the armed egress
    is not actually carrying traffic. Call once at scan start so a mis-set or
    dropped tunnel/proxy aborts the scan instead of leaking the real IP. Returns
    the :func:`confirm_egress` result on success (or when off / kill-switch off)."""
    cfg = resolve_egress()
    result = await confirm_egress(timeout)
    if not cfg.armed or not cfg.killswitch:
        return result
    if not result.get("ok"):
        raise EgressError(
            f"egress kill-switch: {cfg.mode} path not confirmed — {result.get('detail')}. "
            "Fix the egress or disable the kill-switch to scan directly.")
    return result


# ── status snapshot (CLI / API / UI) ────────────────────────────────────────

def tool_availability() -> dict:
    """Which egress-related binaries are present, so the UI can guide the user."""
    return {
        "wg": bool(shutil.which("wg")),
        "wg-quick": bool(shutil.which("wg-quick")),
        "proxychains": bool(shutil.which("proxychains4") or shutil.which("proxychains")),
        "curl": bool(shutil.which("curl")),
        "tor": bool(shutil.which("tor")),
    }


def status(include_confirm: bool = False) -> dict:
    """A synchronous snapshot of the egress configuration + capability, without
    reaching out to the network (that's :func:`confirm_egress`)."""
    cfg = resolve_egress()
    snap: dict[str, Any] = {
        "mode": cfg.mode,
        "armed": cfg.armed,
        "killswitch": cfg.killswitch,
        "proxy_url": cfg.proxy_url,
        "wg_config": cfg.wg_config,
        "wg_interface": cfg.wg_interface,
        "in_process_proxyable": cfg.in_process_proxyable,
        "error": cfg.error,
        "tools": tool_availability(),
    }
    if cfg.is_tunnel:
        snap["tunnel"] = tunnel_status()
    return snap

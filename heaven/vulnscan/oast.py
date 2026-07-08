"""HEAVEN — in-house OAST collaborator (out-of-band application security testing).

Provable blind-vulnerability detection **without any external service** — no Burp
Collaborator, no interactsh, no third-party DNS. HEAVEN binds a local HTTP
listener; each out-of-band probe embeds a unique correlation token in the URL it
asks the target to fetch. If the target is vulnerable (SSRF, XXE with an external
SYSTEM entity, blind command injection with a curl/wget, …) then *the target*
connects back to us and we record the interaction against that token. That turns
a timing/heuristic guess into hard evidence: "your server fetched
http://<us>/<token> — here is the request it sent."

Everything here is Python standard library (``http.server`` in a background
thread), so it adds zero dependencies and runs anywhere HEAVEN runs. It binds to
loopback by default; point ``host`` at a routable address only when the target
lives on another machine and you have authorization to receive its callbacks.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.oast")

# A 1x1 gif — some SSRF sinks only follow the fetch if the response looks like an
# image; returning a tiny valid body keeps those callbacks from erroring out.
_PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02"
    b"\x02D\x01\x00;"
)


@dataclass
class Interaction:
    """A single inbound callback recorded by the collaborator."""

    token: str
    method: str
    path: str
    client_ip: str
    at: float
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


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
            pass

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._record()
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        self._respond()

    # http.server logs every request to stderr by default — silence it.
    def log_message(self, *_args) -> None:  # noqa: D401
        return


class OASTListener:
    """A loopback HTTP collaborator that records out-of-band callbacks.

    Use as a context manager::

        with OASTListener() as oast:
            token = oast.new_token()
            probe_url = oast.url_for(token)      # hand this to the target
            ...                                   # trigger the potential SSRF/XXE
            if oast.poll(token, timeout=3.0):    # did the target call us back?
                # proven out-of-band interaction — collect the evidence
                hits = oast.interactions(token)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._want_port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._interactions: list[Interaction] = []
        self._lock = threading.Lock()

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
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

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
    def base_url(self) -> str:
        return f"http://{self._host}:{self.port}"

    @staticmethod
    def new_token() -> str:
        """A unique, URL-safe correlation token for one probe."""
        return "oob" + secrets.token_hex(8)

    def url_for(self, token: str) -> str:
        """The full callback URL to hand to a target for the given token."""
        return f"{self.base_url}/{token}"

    # ── evidence ─────────────────────────────────────────────────────────────
    def _record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)
        logger.info(
            "OAST callback: %s %s from %s (token=%s)",
            interaction.method, interaction.path, interaction.client_ip, interaction.token,
        )

    def interactions(self, token: str) -> list[Interaction]:
        with self._lock:
            return [i for i in self._interactions if token and token in i.path]

    def hit(self, token: str) -> bool:
        return bool(self.interactions(token))

    def poll(self, token: str, timeout: float = 3.0, interval: float = 0.05) -> bool:
        """Block up to ``timeout`` seconds waiting for a callback for ``token``.

        Safe to call from an executor thread inside an async detector — it never
        touches the event loop.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            if self.hit(token):
                return True
            time.sleep(interval)
        return self.hit(token)

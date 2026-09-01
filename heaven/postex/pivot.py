"""HEAVEN — network pivoting (single and double) over authorized SSH jumps.

Reproduces the CPENT pivot / double-pivot workflow: once you hold credentials
on a foothold host, you tunnel *through* it to reach subnets your own machine
cannot route to, then scan (and, with the exploit engine, exploit) the hosts
behind it. A second jump chains through the first for a double pivot.

Implementation uses asyncssh's connection multiplexing:

* ``conn.open_connection(host, port)`` opens a TCP stream *from the jump host*
  to an internal target — a connect-scan through the pivot.
* ``conn.connect_ssh(host2, ...)`` opens a further SSH connection tunnelled
  inside the first — the double pivot.
* ``conn.forward_socks(...)`` exposes a local SOCKS proxy so external tools can
  ride the same tunnel.

Every hop requires credentials the operator supplies (or that HEAVEN's exploit
engine already proved), and the whole module is authorized-gated.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("postex.pivot")


@dataclass
class JumpSpec:
    host: str
    port: int = 22
    username: str = ""
    password: str = ""
    key_path: str = ""

    def label(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


@dataclass
class PivotResult:
    chain: list[str] = field(default_factory=list)          # jump labels, in order
    established: bool = False
    socks_port: Optional[int] = None
    reachable: list[dict] = field(default_factory=list)     # {host,port,open,banner}
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain, "established": self.established,
            "socks_port": self.socks_port, "reachable": self.reachable,
            "open_count": sum(1 for r in self.reachable if r["open"]),
            "errors": self.errors,
        }


class PivotChain:
    """A chain of SSH connections forming a (possibly multi-hop) pivot."""

    def __init__(self, authorized: bool = False):
        if not authorized:
            raise PermissionError("PivotChain requires authorized=True")
        self._conns: list[Any] = []
        self.labels: list[str] = []

    async def _connect_one(self, prev, spec: JumpSpec):
        import warnings
        try:
            import asyncssh
        except ImportError as e:
            raise RuntimeError("asyncssh not installed") from e
        kwargs: dict[str, Any] = {
            "username": spec.username, "known_hosts": None,
            "connect_timeout": 12, "config": None,
        }
        if spec.key_path:
            kwargs["client_keys"] = [spec.key_path]
        if spec.password:
            kwargs["password"] = spec.password
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # legacy-server FFDH noise
            if prev is None:
                conn = await asyncssh.connect(spec.host, port=spec.port, **kwargs)
            else:
                # Tunnel the next SSH connection through the previous hop.
                conn = await prev.connect_ssh(spec.host, port=spec.port, **kwargs)
        return conn

    async def establish(self, jumps: list[JumpSpec]) -> None:
        prev = None
        for spec in jumps:
            conn = await self._connect_one(prev, spec)
            self._conns.append(conn)
            self.labels.append(spec.label())
            prev = conn

    @property
    def _last(self):
        return self._conns[-1] if self._conns else None

    async def scan_through(self, targets: list[str], ports: list[int],
                           timeout: float = 6.0, concurrency: int = 32) -> list[dict]:
        """Connect-scan (host, port) pairs *from the last jump host*."""
        conn = self._last
        if conn is None:
            return []
        sem = asyncio.Semaphore(concurrency)
        results: list[dict] = []

        async def _one(host: str, port: int) -> None:
            async with sem:
                banner = ""
                is_open = False
                try:
                    reader, writer = await asyncio.wait_for(
                        conn.open_connection(host, port), timeout=timeout)
                    is_open = True
                    with contextlib.suppress(asyncio.TimeoutError, Exception):
                        data = await asyncio.wait_for(reader.read(80), timeout=1.5)
                        # Keep printable ASCII only — service banners carry binary
                        # that would otherwise corrupt display / JSON.
                        banner = "".join(
                            c for c in data.decode("latin1", "replace")
                            if 32 <= ord(c) < 127).strip()
                    writer.close()
                except Exception:
                    is_open = False
                if is_open:
                    results.append({"host": host, "port": port, "open": True,
                                    "banner": banner})

        await asyncio.gather(*[_one(h, p) for h in targets for p in ports])
        results.sort(key=lambda r: (r["host"], r["port"]))
        return results

    async def start_socks(self, listen_port: int = 0) -> Optional[int]:
        """Expose a local SOCKS proxy that rides the last hop. Returns the port."""
        conn = self._last
        if conn is None:
            return None
        try:
            listener = await conn.forward_socks("127.0.0.1", listen_port)
            self._socks_listener = listener
            return listener.get_port()
        except Exception as e:  # noqa: BLE001
            logger.debug("SOCKS forward failed: %s", e)
            return None

    async def close(self) -> None:
        for conn in reversed(self._conns):
            with contextlib.suppress(Exception):
                conn.close()
                await conn.wait_closed()


async def run_pivot(*, authorized: bool = False, jumps: list[JumpSpec],
                    targets: Optional[list[str]] = None,
                    ports: Optional[list[int]] = None,
                    socks: bool = False) -> dict[str, Any]:
    """Establish a pivot chain, optionally scan targets through it, and return
    a summary. Safe: it only opens tunnels and connect-scans (read-only)."""
    if not authorized:
        raise PermissionError("run_pivot requires authorized=True")
    if not jumps:
        return PivotResult(errors=["no jump hosts supplied"]).to_dict()

    result = PivotResult()
    chain = PivotChain(authorized=True)
    try:
        await chain.establish(jumps)
        result.established = True
        result.chain = list(chain.labels)
        logger.info("Pivot established: %s", " -> ".join(chain.labels))
        if socks:
            result.socks_port = await chain.start_socks()
        if targets:
            scan_ports = ports or [21, 22, 23, 25, 80, 139, 445, 3306, 3389, 8080]
            result.reachable = await chain.scan_through(targets, scan_ports)
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"{type(e).__name__}: {e}")
    finally:
        if not socks:      # keep the chain open only if a SOCKS proxy is live
            await chain.close()
    return result.to_dict()

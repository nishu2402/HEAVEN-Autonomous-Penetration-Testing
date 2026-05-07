"""
HEAVEN — Metasploit RPC Client
Connects to a running msfrpcd instance via MSGPACK-RPC.
Only invoked when --enable-exploitation flag is explicitly set.

Environment variables:
  HEAVEN_MSF_HOST      (default: 127.0.0.1)
  HEAVEN_MSF_PORT      (default: 55553)
  HEAVEN_MSF_PASSWORD  (required)
  HEAVEN_MSF_SSL       (default: true)
"""

from __future__ import annotations

import asyncio
import os
from typing import Any


class MetasploitClient:

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        password: str | None = None,
        ssl: bool | None = None,
    ):
        self.host = host or os.environ.get("HEAVEN_MSF_HOST", "127.0.0.1")
        self.port = int(port or os.environ.get("HEAVEN_MSF_PORT", "55553"))
        self.password = password or os.environ.get("HEAVEN_MSF_PASSWORD", "")
        self.ssl = ssl if ssl is not None else os.environ.get("HEAVEN_MSF_SSL", "true").lower() != "false"
        self._token: str = ""
        self._client: Any = None

    def _require_pymetasploit(self):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            return MsfRpcClient
        except ImportError:
            raise RuntimeError(
                "pymetasploit3 is not installed. "
                "Install it with: pip install pymetasploit3"
            )

    async def connect(self) -> None:
        if not self.password:
            raise ValueError("HEAVEN_MSF_PASSWORD environment variable is required.")
        MsfRpcClient = self._require_pymetasploit()
        loop = asyncio.get_event_loop()
        self._client = await loop.run_in_executor(
            None,
            lambda: MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=self.ssl,
            )
        )

    async def search_exploit(self, cve_id: str) -> list[dict]:
        """Search for Metasploit modules matching a CVE ID."""
        if not self._client:
            await self.connect()
        loop = asyncio.get_event_loop()
        try:
            modules = await loop.run_in_executor(
                None,
                lambda: self._client.modules.search(cve_id)
            )
            return [
                {
                    "fullname": m.get("fullname", ""),
                    "name": m.get("name", ""),
                    "rank": m.get("rank", ""),
                    "type": m.get("type", ""),
                    "description": m.get("description", "")[:200],
                }
                for m in (modules or [])
                if "exploit" in m.get("type", "")
            ]
        except Exception as exc:
            return [{"error": str(exc)}]

    async def run_exploit(
        self,
        module: str,
        rhosts: str,
        lhost: str,
        options: dict | None = None,
        payload: str = "generic/shell_reverse_tcp",
        dry_run: bool = False,
    ) -> dict:
        """
        Execute a Metasploit exploit module.
        dry_run=True validates options without firing — use for pre-flight checks.
        """
        if not self._client:
            await self.connect()

        loop = asyncio.get_event_loop()
        try:
            exploit = await loop.run_in_executor(
                None,
                lambda: self._client.modules.use("exploit", module)
            )
            exploit["RHOSTS"] = rhosts
            exploit["LHOST"] = lhost
            if options:
                for k, v in options.items():
                    exploit[k] = v

            if dry_run:
                missing = await loop.run_in_executor(None, lambda: exploit.missing_required)
                return {"dry_run": True, "missing_required": missing, "module": module}

            pl = await loop.run_in_executor(
                None,
                lambda: self._client.modules.use("payload", payload)
            )
            job_id = await loop.run_in_executor(
                None,
                lambda: exploit.execute(payload=pl)
            )
            return {
                "module": module,
                "job_id": job_id,
                "rhosts": rhosts,
                "payload": payload,
                "status": "launched",
            }
        except Exception as exc:
            return {"error": str(exc), "module": module}

    async def get_sessions(self) -> list[dict]:
        """Return all open Metasploit sessions."""
        if not self._client:
            await self.connect()
        loop = asyncio.get_event_loop()
        try:
            sessions = await loop.run_in_executor(None, lambda: self._client.sessions.list)
            return [
                {
                    "id": sid,
                    "type": info.get("type", ""),
                    "tunnel_peer": info.get("tunnel_peer", ""),
                    "via_exploit": info.get("via_exploit", ""),
                    "platform": info.get("platform", ""),
                }
                for sid, info in (sessions or {}).items()
            ]
        except Exception as exc:
            return [{"error": str(exc)}]

    async def kill_session(self, session_id: str) -> bool:
        if not self._client:
            await self.connect()
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: self._client.sessions.session(session_id).stop()
            )
            return True
        except Exception:
            return False

    @classmethod
    def is_available(cls) -> bool:
        """Check if msfrpcd connectivity is configured."""
        return bool(os.environ.get("HEAVEN_MSF_PASSWORD"))

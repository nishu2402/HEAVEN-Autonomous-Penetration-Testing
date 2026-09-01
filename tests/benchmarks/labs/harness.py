"""Shared bring-up/tear-down harness for HEAVEN's domain labs.

Each lab is a small ``docker compose`` stack of genuinely-vulnerable services
(see the compose files in this directory). ``LabStack`` brings one up, waits for
it to be reachable, and always tears it down (``down -v``) afterwards, so a test
never leaks a container or a published loopback port.

Gating mirrors the DVWA benchmark: the live labs only run when
``HEAVEN_RUN_BENCHMARKS=1`` is set and Docker is on PATH; otherwise the test is
skipped with a clear reason.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

LABS_DIR = Path(__file__).resolve().parent


def benchmarks_enabled() -> bool:
    return os.environ.get("HEAVEN_RUN_BENCHMARKS", "").lower() in ("1", "true", "yes")


def docker_available() -> bool:
    return shutil.which("docker") is not None


def skip_reason() -> str | None:
    """Return a skip reason if the live labs cannot run here, else None."""
    if not benchmarks_enabled():
        return ("Live domain-lab benchmark gated by HEAVEN_RUN_BENCHMARKS=1. "
                "Run with: HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/")
    if not docker_available():
        return "docker not on PATH — install Docker to run this lab benchmark"
    return None


class LabStack:
    """A docker-compose lab stack, brought up for the duration of a ``with``."""

    def __init__(self, compose_file: str, *, build: bool = False):
        self.compose_path = LABS_DIR / compose_file
        self.build = build

    def _cmd(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.compose_path), *args]

    def up(self) -> str:
        args = ["up", "-d"]
        if self.build:
            args.append("--build")
        proc = subprocess.run(self._cmd(*args), capture_output=True, text=True,
                              timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(
                f"docker compose up failed for {self.compose_path.name}: "
                f"{(proc.stderr or proc.stdout).strip()}")
        return proc.stdout

    def down(self) -> None:
        subprocess.run(self._cmd("down", "-v"), capture_output=True, text=True,
                       timeout=180)

    def __enter__(self) -> "LabStack":
        self.up()
        return self

    def __exit__(self, *exc) -> None:
        self.down()


def wait_until(predicate: Callable[[], bool], timeout_s: float = 90.0,
               interval_s: float = 2.0) -> bool:
    """Poll ``predicate`` until it returns True or the timeout elapses."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval_s)
    return False


def http_status(url: str, timeout: float = 3.0) -> int:
    """Return the HTTP status for a GET, or 0 on any connection error."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def http_body(url: str, timeout: float = 3.0) -> str:
    """Return the response body for a GET, or '' on any error."""
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return ""

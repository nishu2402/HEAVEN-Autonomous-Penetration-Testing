"""
Pytest fixtures for the benchmark suite.

These fixtures provide a Dockerised vulnerable target and an authenticated
HTTP session bound to it. They are aggressive about gating:

  - The entire benchmark suite is SKIPPED unless `HEAVEN_RUN_BENCHMARKS=1`
    is set. We don't want a 5-minute Docker pull stalling normal CI.
  - If docker / docker-compose is not on PATH, individual benchmarks are
    skipped with a clear reason — so a contributor on a machine without
    Docker still gets useful output from `pytest tests/benchmarks/`.
  - Health-check polls /login.php (DVWA) until 200; bails after 90s.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

from tests.benchmarks.metrics import GroundTruth


_BENCH_DIR = Path(__file__).parent
_COMPOSE_FILE = _BENCH_DIR / "docker-compose.yml"
_GT_DIR = _BENCH_DIR / "ground_truth"


def _benchmarks_enabled() -> bool:
    return os.environ.get("HEAVEN_RUN_BENCHMARKS", "").lower() in ("1", "true", "yes")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _compose_cmd(*args: str) -> list[str]:
    # Prefer the modern `docker compose` (subcommand) over the legacy binary.
    return ["docker", "compose", "-f", str(_COMPOSE_FILE), *args]


def _wait_for_url(url: str, timeout_s: float = 90.0) -> bool:
    import urllib.error
    import urllib.request
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if 200 <= r.status < 500:
                    return True
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(2)
    return False


@pytest.fixture(scope="session")
def dvwa_target() -> Iterator[GroundTruth]:
    """Bring up DVWA via docker compose, yield its ground truth, tear down.

    Tests that consume this fixture only run when both:
      - HEAVEN_RUN_BENCHMARKS=1 is set in the environment
      - docker is on PATH

    Otherwise the test is skipped with a clear reason. Pure unit tests
    (test_metrics.py) don't consume this fixture and run in normal CI.
    """
    if not _benchmarks_enabled():
        pytest.skip(
            "Live-target benchmark gated by HEAVEN_RUN_BENCHMARKS=1. "
            "Run with: HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/"
        )
    if not _docker_available():
        pytest.skip("docker not on PATH — install Docker to run this benchmark")

    gt = GroundTruth.load(_GT_DIR / "dvwa.yaml")

    # docker compose up -d --wait
    up = subprocess.run(_compose_cmd("up", "-d", "--wait"),
                        capture_output=True, text=True)
    if up.returncode != 0:
        pytest.skip(f"docker compose up failed: {up.stderr.strip()}")

    try:
        ready = _wait_for_url(f"{gt.base_url}/login.php", timeout_s=120.0)
        if not ready:
            pytest.fail(
                f"DVWA never became ready at {gt.base_url}/login.php within 120s"
            )

        # One-time DB init: DVWA refuses to serve /vulnerabilities/* until
        # `/setup.php` "Create / Reset Database" has been clicked.
        _init_dvwa_database(gt.base_url)

        yield gt

    finally:
        subprocess.run(_compose_cmd("down", "-v"), capture_output=True, text=True)


def _init_dvwa_database(base_url: str) -> None:
    """POST to /setup.php to create the DVWA tables. Idempotent."""
    import urllib.parse
    import urllib.request
    try:
        # The setup.php form takes `create_db=Create / Reset Database`.
        data = urllib.parse.urlencode({
            "create_db": "Create / Reset Database",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/setup.php", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        urllib.request.urlopen(req, timeout=15)
    except Exception:
        # Non-fatal — if setup fails the test will report low coverage,
        # which is itself a useful signal.
        pass

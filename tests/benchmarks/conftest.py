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
import tempfile
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


# When the live benchmark isn't explicitly enabled, don't even *collect* the
# DVWA test — so the default `pytest` run reports 0 skipped instead of a
# permanent "1 skipped". The genuine unit tests in this dir (test_metrics.py,
# test_adapters.py) are unaffected and always run. Enable the live run with
# HEAVEN_RUN_BENCHMARKS=1 (exactly what CI's benchmark job sets), which both
# un-ignores this file and lets the fixture bring the Docker target up.
collect_ignore: list[str] = []
if not _benchmarks_enabled():
    collect_ignore.append("test_dvwa_baseline.py")


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

    # Bring the stack up. We intentionally do NOT pass `--wait`: the DVWA image's
    # in-container healthcheck is unreliable (its curl can report the container
    # "unhealthy" even while the app serves fine), which made `up --wait` return
    # non-zero and spuriously skip the whole benchmark. The authoritative
    # readiness signal is the host-side HTTP probe below.
    up = subprocess.run(_compose_cmd("up", "-d"), capture_output=True, text=True)
    if up.returncode != 0:
        pytest.skip(f"docker compose up failed: {(up.stderr or up.stdout).strip()}")

    cookie_file: "Path | None" = None
    try:
        ready = _wait_for_url(f"{gt.base_url}/login.php", timeout_s=120.0)
        if not ready:
            pytest.skip(
                f"DVWA never became ready at {gt.base_url}/login.php within 120s "
                f"(compose: {(up.stdout or up.stderr).strip()[:200]})"
            )

        # One-time DB init: DVWA refuses to serve /vulnerabilities/* until
        # `/setup.php` "Create / Reset Database" has been clicked.
        _init_dvwa_database(gt.base_url)

        # Authenticated benchmark: log in and stash a cookie jar (session +
        # security=low) on the ground-truth object so the scan reaches DVWA's
        # /vulnerabilities/* endpoints. Falls back to unauthenticated if login
        # can't be completed (recall will just be low — still a valid baseline).
        cookie_file = _authenticate_dvwa(gt.base_url)
        if cookie_file is not None:
            gt.auth["cookie_file"] = str(cookie_file)

        yield gt

    finally:
        subprocess.run(_compose_cmd("down", "-v"), capture_output=True, text=True)
        if cookie_file is not None:
            cookie_file.unlink(missing_ok=True)


def _http_opener():
    """A urllib opener with its own cookie jar (so session cookies persist across
    the GET-token → POST-form handshake DVWA requires)."""
    import http.cookiejar
    import urllib.request
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


def _scrape_user_token(html: str) -> str:
    """Pull DVWA's hidden anti-CSRF `user_token` out of a form page."""
    import re
    m = re.search(
        r"name=['\"]user_token['\"][^>]*value=['\"]([A-Fa-f0-9]+)['\"]", html
    )
    return m.group(1) if m else ""


def _init_dvwa_database(base_url: str) -> None:
    """POST /setup.php to create the DVWA tables (idempotent). Newer images gate
    this behind the CSRF `user_token`, so scrape it from the setup page first."""
    import urllib.parse
    import urllib.request
    try:
        opener, _ = _http_opener()
        with opener.open(f"{base_url}/setup.php", timeout=15) as r:
            token = _scrape_user_token(r.read().decode("utf-8", "replace"))
        data = urllib.parse.urlencode({
            "create_db": "Create / Reset Database",
            "user_token": token,
        }).encode("utf-8")
        opener.open(
            urllib.request.Request(
                f"{base_url}/setup.php", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=20,
        ).read()
    except Exception:
        # Non-fatal — if setup fails the test will report low coverage,
        # which is itself a useful signal.
        pass


def _authenticate_dvwa(base_url: str) -> "Path | None":
    """Log in as admin/password and write a Netscape cookie file carrying the
    session cookie **and** `security=low`.

    DVWA's vulnerable endpoints live behind the login, and DVWA defaults to the
    'impossible' security level unless a `security` cookie says otherwise — so a
    scan without both cookies reaches nothing exploitable. Returns the cookie
    file path, or None if login could not be completed (the benchmark then falls
    back to an unauthenticated run rather than failing outright).
    """
    import urllib.parse
    import urllib.request
    try:
        opener, jar = _http_opener()
        with opener.open(f"{base_url}/login.php", timeout=15) as r:
            token = _scrape_user_token(r.read().decode("utf-8", "replace"))
        data = urllib.parse.urlencode({
            "username": "admin", "password": "password",
            "user_token": token, "Login": "Login",
        }).encode("utf-8")
        opener.open(
            urllib.request.Request(f"{base_url}/login.php", data=data),
            timeout=15,
        ).read()
        sid = next((c.value for c in jar if c.name == "PHPSESSID"), "")
        if not sid:
            return None
        host = urllib.parse.urlparse(base_url).hostname or "localhost"
        fd, name = tempfile.mkstemp(prefix="heaven_dvwa_", suffix=".cookies")
        os.close(fd)
        path = Path(name)
        path.write_text(
            "# Netscape HTTP Cookie File\n"
            f"{host}\tFALSE\t/\tFALSE\t0\tPHPSESSID\t{sid}\n"
            f"{host}\tFALSE\t/\tFALSE\t0\tsecurity\tlow\n",
            encoding="utf-8",
        )
        return path
    except Exception:
        return None

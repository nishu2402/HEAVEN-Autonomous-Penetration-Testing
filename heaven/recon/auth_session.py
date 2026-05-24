"""
HEAVEN — Authenticated-scan session

Two input modes for getting past a login wall:

  1. --cookie-file PATH   Netscape cookie format (curl -c / wget cookies.txt /
                          browser extension export). Any cookies in the file
                          are loaded into the aiohttp cookie jar and replayed
                          on every scanner request.

  2. --auth url=/login,user=admin,pass=password[,csrf_field=token]
                          HEAVEN performs the form login itself, captures the
                          resulting Set-Cookie, and uses it for every scan.

The active session is exposed as a process-wide singleton (`get_active_session`)
that the web-crawler, injection-scanner, validator, and dir-fuzzer all read
when they construct their aiohttp ClientSession. Modules that don't know
about auth still work — they just get an unauthenticated session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Any, Optional

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("recon.auth")


@dataclass
class AuthSession:
    """Authenticated-scan state shared across all scanner modules."""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    origin: str = ""               # the URL the session is bound to
    label: str = "unauthenticated" # human-readable description for logs

    def to_aiohttp_jar(self) -> Optional[Any]:
        """Build an aiohttp.CookieJar pre-populated with our cookies."""
        if aiohttp is None or not self.cookies:
            return None
        jar = aiohttp.CookieJar(unsafe=True)
        # unsafe=True lets jar accept cookies for raw IPs / localhost — needed
        # for benchmark targets like http://localhost:8080.
        for k, v in self.cookies.items():
            jar.update_cookies({k: v})
        return jar


_active: Optional[AuthSession] = None


def get_active_session() -> Optional[AuthSession]:
    """Return the process-wide active auth session, if any."""
    return _active


def set_active_session(session: Optional[AuthSession]) -> None:
    global _active
    _active = session
    if session:
        logger.info(f"auth session activated: {session.label} "
                    f"(cookies={len(session.cookies)} headers={len(session.headers)})")
    else:
        logger.info("auth session cleared")


def clear_active_session() -> None:
    set_active_session(None)


# ── Loaders ────────────────────────────────────────────────────────────────

def load_cookie_file(path: Path, origin: str = "") -> AuthSession:
    """Parse a Netscape-format cookie file into an AuthSession.

    Accepts files produced by:
      curl --cookie-jar cookies.txt ...
      wget --save-cookies cookies.txt ...
      "Get cookies.txt" browser extensions
    """
    if not path.exists():
        raise FileNotFoundError(f"cookie file not found: {path}")

    jar = MozillaCookieJar(str(path))
    # ignore_discard=True picks up session cookies; ignore_expires=True is
    # required for cookies a browser export may have already expired.
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except Exception as e:
        raise ValueError(f"could not parse cookie file {path}: {e}") from e

    cookies = {c.name: c.value or "" for c in jar}
    if not cookies:
        logger.warning(f"cookie file {path} parsed but yielded zero cookies")

    return AuthSession(
        cookies=cookies, origin=origin,
        label=f"cookie-file:{path.name}({len(cookies)} cookies)",
    )


def parse_auth_string(spec: str) -> dict[str, str]:
    """Parse `--auth url=/login,user=admin,pass=password,csrf_field=token`.

    Returns a dict with at least 'url', 'user', 'pass'. Optional keys:
      username_field (default 'username')
      password_field (default 'password')
      csrf_field     (when set, scrape the page for a hidden input of this
                      name and submit it back — handles Django / Laravel /
                      Rails CSRF protection)
    """
    out: dict[str, str] = {}
    for part in spec.split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    if "url" not in out:
        raise ValueError("--auth requires url=<path-or-full-url>")
    if "user" not in out or "pass" not in out:
        raise ValueError("--auth requires user= and pass=")
    out.setdefault("username_field", "username")
    out.setdefault("password_field", "password")
    return out


async def perform_form_login(base_url: str, spec: dict[str, str]) -> AuthSession:
    """Submit a form login and capture the resulting cookies.

    Supports:
      - Plain POST username/password forms
      - CSRF-token-protected forms (set csrf_field=<input_name> in spec)
      - Absolute or path-only login URLs (resolved against base_url)
    """
    if aiohttp is None:
        raise RuntimeError("aiohttp not installed — cannot perform form login")

    login_url = spec["url"]
    if login_url.startswith("/"):
        login_url = base_url.rstrip("/") + login_url

    user_field = spec["username_field"]
    pass_field = spec["password_field"]
    csrf_field = spec.get("csrf_field")

    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        form_data: dict[str, str] = {
            user_field: spec["user"],
            pass_field: spec["pass"],
        }

        # Step 1: GET the login page (sets initial cookies + scrapes CSRF)
        if csrf_field:
            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                body = await r.text()
                m = re.search(
                    rf'<input[^>]+name=["\']{re.escape(csrf_field)}["\'][^>]+value=["\']([^"\']+)["\']',
                    body,
                )
                if not m:
                    raise RuntimeError(
                        f"csrf_field='{csrf_field}' not found on {login_url}"
                    )
                form_data[csrf_field] = m.group(1)

        # Step 2: POST the form
        async with session.post(
            login_url, data=form_data,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as r:
            # The success/failure detector is intentionally loose — many apps
            # redirect to / on success, but some return 200 on the login page
            # with an error banner. We trust that we got SOMETHING with the
            # session cookie set; the scanner will reveal auth failure later.
            if r.status >= 500:
                raise RuntimeError(f"login returned {r.status}; check creds and URL")

        cookies = {c.key: c.value for c in jar}

    if not cookies:
        raise RuntimeError(
            "form login completed but no cookies were set — check that the "
            "login URL and field names are correct"
        )

    return AuthSession(
        cookies=cookies, origin=base_url,
        label=f"form-login:{spec.get('user','?')}({len(cookies)} cookies)",
    )


# ── Convenience: build a ClientSession kwargs dict ──────────────────────────

def aiohttp_session_kwargs() -> dict[str, Any]:
    """Return kwargs for `aiohttp.ClientSession(**...)` that honour the
    active auth session. Returns an empty dict when no session is active —
    scanner code can splat this unconditionally.
    """
    s = get_active_session()
    if not s:
        return {}
    out: dict[str, Any] = {}
    jar = s.to_aiohttp_jar()
    if jar is not None:
        out["cookie_jar"] = jar
    if s.headers:
        out["headers"] = dict(s.headers)
    return out

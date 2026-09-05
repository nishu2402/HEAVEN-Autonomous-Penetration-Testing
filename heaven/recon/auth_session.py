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


# ── Second (low-privilege) session — for multi-role Broken Access Control ────
# The primary session above is the higher-privilege / admin identity the crawler
# uses. A second, deliberately LOWER-privilege session lets the access-control
# audit prove that a lower role can reach content the app gates from anonymous
# users. It is optional; when unset, the audit still runs its anonymous-vs-
# privileged differential.
_low_priv: Optional["AuthSession"] = None


def get_low_priv_session() -> Optional["AuthSession"]:
    """Return the low-privilege session used for access-control differential
    testing, if the operator supplied one."""
    return _low_priv


def set_low_priv_session(session: Optional["AuthSession"]) -> None:
    global _low_priv
    _low_priv = session
    if session:
        logger.info(f"low-priv session set: {session.label} "
                    f"(cookies={len(session.cookies)} headers={len(session.headers)})")
    else:
        logger.info("low-priv session cleared")


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
      submit_field   (name of the submit button to send, e.g. 'Login'; the
                      login page's submit button is auto-mirrored, so this is
                      only needed to force a specific one)
      submit_value   (value paired with submit_field, default empty)
      cookies        (extra cookies to seed onto the session AFTER login, as
                      `name=value` pairs separated by `;` — the comma is the
                      spec delimiter. Needed for apps that gate behaviour on a
                      non-auth cookie, e.g. DVWA's `security=low` which selects
                      the vulnerability level; without it DVWA stays on the
                      hardened `impossible` level and nothing is exploitable.)
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


def _parse_cookie_pairs(raw: str) -> dict[str, str]:
    """Parse `name=value;name2=value2` into a cookie dict.

    Used for operator-seeded session cookies (the `cookies=` auth-spec key).
    The value may itself contain `=` (rare, but base64 tokens do), so we split
    each pair on the FIRST `=` only. Blank / malformed segments are skipped.
    """
    out: dict[str, str] = {}
    for pair in (raw or "").split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def _login_form_defaults(html: str, pass_field: str) -> dict[str, str]:
    """Mirror a login form's hidden inputs and submit button(s).

    A browser submits every hidden control plus the submit button that was
    clicked, and apps frequently gate the login on exactly those: DVWA checks
    `isset($_POST['Login'])` (the submit button's name), and Django / Laravel /
    Rails carry a hidden CSRF or state token. Posting only user+pass leaves the
    session UNauthenticated, after which every "authenticated" scan probes
    protected pages blind and reports nothing. We locate the form that carries
    the password field and return its hidden + submit name=value pairs; the
    caller overrides user/pass/csrf on top. Best-effort and regex-based (no bs4
    dependency), so a malformed page simply yields fewer defaults.
    """
    if not html:
        return {}
    block = ""
    for f in re.findall(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        if re.search(rf'name=["\']{re.escape(pass_field)}["\']', f, re.I) or \
                re.search(r'type=["\']password["\']', f, re.I):
            block = f
            break
    # No recognisable password form: fall back to the whole page so a single
    # login form still contributes its hidden token and submit button.
    block = block or html
    out: dict[str, str] = {}
    for tag in re.findall(r"<(?:input|button)\b[^>]*>", block, re.I):
        name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        if not name_m:
            continue
        typ_m = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
        typ = typ_m.group(1).lower() if typ_m else ""
        is_button = tag[:7].lower().startswith("<button")
        # Buttons default to type=submit; carry hidden state + submit controls.
        if typ in ("hidden", "submit") or (is_button and typ in ("", "submit")):
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            out[name_m.group(1)] = val_m.group(1) if val_m else ""
    return out


async def perform_form_login(base_url: str, spec: dict[str, str]) -> AuthSession:
    """Submit a form login and capture the resulting cookies.

    Submits like a real browser: GETs the login page, mirrors the password
    form's hidden inputs and submit button(s), then overrides user/pass (and an
    optional CSRF field) with the operator spec. Supports:
      - Plain POST username/password forms, including apps that gate on the
        submit button name (e.g. DVWA's `isset($_POST['Login'])`)
      - CSRF-token forms (auto-carried when the token is a hidden input; set
        csrf_field=<input_name> to require/override it explicitly)
      - Optional submit_field / submit_value spec keys for an explicit override
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
        # Always GET the login page first: it establishes the initial session
        # cookie AND lets us mirror the real form (hidden state + submit button).
        page = ""
        try:
            async with session.get(
                login_url, timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                page = await r.text()
        except Exception:  # noqa: BLE001 - a fetch failure just means no mirror
            logger.debug("login-page GET failed; posting bare form", exc_info=True)

        form_data: dict[str, str] = _login_form_defaults(page, pass_field)

        # CSRF: an explicit field must resolve to a value (from the mirrored
        # hidden inputs, or a direct scrape) or we fail loudly rather than post a
        # login the app will silently reject.
        if csrf_field:
            token = form_data.get(csrf_field)
            if token is None:
                m = re.search(
                    rf'<input[^>]+name=["\']{re.escape(csrf_field)}["\'][^>]+'
                    rf'value=["\']([^"\']+)["\']',
                    page,
                )
                token = m.group(1) if m else None
            if token is None:
                raise RuntimeError(
                    f"csrf_field='{csrf_field}' not found on {login_url}"
                )
            form_data[csrf_field] = token

        # Operator-supplied creds win over the mirrored defaults.
        form_data[user_field] = spec["user"]
        form_data[pass_field] = spec["pass"]
        if spec.get("submit_field"):
            form_data[spec["submit_field"]] = spec.get("submit_value", "")

        # POST the form
        async with session.post(
            login_url, data=form_data,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as r:
            # The success/failure detector is intentionally loose: many apps
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

    # Operator-seeded cookies (the `cookies=` spec key) go on AFTER the login
    # succeeded, so a non-auth mode cookie can't mask a failed login above. They
    # override any same-named cookie the login set — e.g. DVWA's `security=low`.
    extra = _parse_cookie_pairs(spec.get("cookies", ""))
    if extra:
        cookies.update(extra)
        logger.info("seeded %d operator cookie(s) onto session: %s",
                    len(extra), ", ".join(sorted(extra)))

    return AuthSession(
        cookies=cookies, origin=base_url,
        label=f"form-login:{spec.get('user','?')}({len(cookies)} cookies)",
    )


# ── Mid-scan re-authentication ──────────────────────────────────────────────
# A long authenticated scan can outlive its session (idle timeout, rotation),
# after which every scanner silently probes UNAUTHENTICATED and finds nothing.
# When the operator used a form login we remember the spec so the session can be
# transparently renewed instead of the scan going blind halfway through.
_login_memo: Optional[tuple[str, dict[str, str]]] = None


def remember_login(base_url: str, spec: dict[str, str]) -> None:
    """Store the form-login parameters so the active session can be renewed
    later with :func:`refresh_active_session`."""
    global _login_memo
    _login_memo = (base_url, dict(spec))


def session_looks_expired(body: str, status: int = 200) -> bool:
    """Heuristic: does a response look like the app bounced us back to a login
    wall (session died)? Used to decide when to re-authenticate mid-scan."""
    if status in (401, 403):
        return True
    low = (body or "").lower()
    return any(m in low for m in (
        'name="password"', "name='password'", "please log in", "please login",
        "sign in to continue", "session expired", "your session has expired",
        "login required", "authentication required",
    ))


async def refresh_active_session() -> bool:
    """Re-run the remembered form login and replace the active session.

    Returns ``True`` when the session was renewed, ``False`` when there is no
    remembered login (cookie-file sessions can't be renewed) or the re-login
    failed. Never raises — a failed renewal must not crash the scan.
    """
    if _login_memo is None:
        return False
    base, spec = _login_memo
    try:
        sess = await perform_form_login(base, spec)
    except Exception as e:  # noqa: BLE001 — renewal failure must not abort the scan
        logger.warning(f"session refresh failed: {e}")
        return False
    set_active_session(sess)
    logger.info("active session refreshed via remembered login")
    return True


# ── Convenience: build a ClientSession kwargs dict ──────────────────────────

def aiohttp_session_kwargs() -> dict[str, Any]:
    """Return kwargs for `aiohttp.ClientSession(**...)` that honour the
    active auth session *and* the configured network egress (proxy/tunnel).
    Returns an empty dict when neither applies — scanner code can splat this
    unconditionally.
    """
    out: dict[str, Any] = {}
    # Egress first (adds `trust_env` under an HTTP proxy so target traffic exits
    # via the operator's anonymity path). No-op when egress is off / tunnelled.
    try:
        from heaven.net.egress import aiohttp_session_kwargs as _egress_kw
        out.update(_egress_kw())
    except Exception:  # noqa: BLE001 — egress must never break a scan
        logger.debug("egress session kwargs unavailable", exc_info=True)
    # Install the global per-target throttle (adaptive per-host concurrency) so
    # every scanner that splats these kwargs is a good citizen against a fragile
    # target. No-op when disabled / aiohttp missing.
    try:
        from heaven.net.throttle import instrument_session_kwargs
        instrument_session_kwargs(out)
    except Exception:  # noqa: BLE001 — throttle must never break a scan
        logger.debug("throttle install unavailable", exc_info=True)
    s = get_active_session()
    if not s:
        return out
    # Pass cookies as the session-level `cookies=` dict, NOT a pre-filled
    # cookie_jar. A jar built with `update_cookies({k: v})` (no response_url)
    # leaves the cookies with an empty domain, and aiohttp then never sends
    # them — so scanners silently hit protected pages UNAUTHENTICATED and find
    # nothing. The flat `cookies=` dict is attached to every request regardless
    # of host (works for localhost / IP targets) — the approach the crawler
    # already uses successfully.
    if s.cookies:
        out["cookies"] = dict(s.cookies)
    if s.headers:
        out["headers"] = dict(s.headers)
    return out

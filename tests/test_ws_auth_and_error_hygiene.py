"""HEAVEN — WebSocket auth centralisation + 500 error hygiene.

Two hardening changes are covered here:

1. Token -> session validation is now a single method,
   ``AuthManager.validate_session``, shared by the HTTP dependency and every
   WebSocket handshake via ``server._ws_authenticate``. Previously each socket
   re-implemented the check by reaching into the private ``_sessions`` store,
   and ``/api/ws/logs`` had drifted to skip the expiry check entirely. These
   tests pin the shared behaviour so an expired token can never stream again.

2. 500 responses no longer interpolate the raw exception into the client-facing
   body (CWE-209). ``server._server_error`` logs the detail server-side under a
   short reference id and returns a stable, generic message.

Modules are resolved at call time (``import ... as`` inside each test) because
other suites reset ``sys.modules['heaven*']``; binding at import time would risk
pointing at an orphaned copy. Behaviour, not object identity, is asserted.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import time


def test_validate_session_accepts_live_rejects_expired_and_unknown():
    from heaven.security.auth import AuthManager, Role, Session

    am = AuthManager()
    live = Session(token="tok-live", user_id="u", role=Role.VIEWER,
                   expires_at=time.time() + 1000)
    am._sessions["tok-live"] = live
    am._sessions["tok-old"] = Session(token="tok-old", user_id="u", role=Role.VIEWER,
                                      expires_at=time.time() - 1)

    assert am.validate_session("tok-live") is live          # live token → session
    assert am.validate_session("tok-old") is None            # expired → rejected
    assert am.validate_session("never-issued") is None       # unknown → rejected
    assert am.validate_session("") is None                   # empty → rejected
    assert am.validate_session(None) is None                 # missing → rejected


class _FakeWS:
    """Minimal stand-in that records a single close(code, reason)."""

    def __init__(self) -> None:
        self.closed: tuple[int, str] | None = None

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


def test_ws_authenticate_enforces_token_and_expiry(monkeypatch):
    monkeypatch.delenv("HEAVEN_DISABLE_AUTH", raising=False)
    import heaven.api.server as srv
    from heaven.security.auth import Role, Session

    auth = srv.get_auth_manager()
    auth._sessions["ws-live"] = Session(token="ws-live", user_id="u", role=Role.VIEWER,
                                        expires_at=time.time() + 1000)
    auth._sessions["ws-exp"] = Session(token="ws-exp", user_id="u", role=Role.VIEWER,
                                       expires_at=time.time() - 1)

    # A live token is admitted and the socket is left open for accept().
    ws = _FakeWS()
    assert asyncio.run(srv._ws_authenticate(ws, "ws-live")) is True
    assert ws.closed is None

    # A missing token is refused with the WS auth close code.
    ws = _FakeWS()
    assert asyncio.run(srv._ws_authenticate(ws, None)) is False
    assert ws.closed is not None and ws.closed[0] == 4401

    # An EXPIRED token is refused — the behaviour /api/ws/logs used to skip.
    ws = _FakeWS()
    assert asyncio.run(srv._ws_authenticate(ws, "ws-exp")) is False
    assert ws.closed is not None and ws.closed[0] == 4401


def test_ws_authenticate_allows_when_auth_disabled(monkeypatch):
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    import heaven.api.server as srv

    ws = _FakeWS()
    assert asyncio.run(srv._ws_authenticate(ws, None)) is True
    assert ws.closed is None


def test_server_error_hides_exception_text_but_names_the_operation():
    import heaven.api.server as srv

    exc = RuntimeError("boom at /etc/heaven/secret.key: connection to 10.1.2.3 refused")
    http_exc = srv._server_error("report generation failed", exc)

    assert http_exc.status_code == 500
    detail = str(http_exc.detail)
    # The operator learns WHAT failed …
    assert "report generation failed" in detail
    # … but none of the raw exception internals leak to the client.
    assert "boom" not in detail
    assert "/etc/heaven/secret.key" not in detail
    assert "10.1.2.3" not in detail
    # A correlation id is present so the client message maps to the server log.
    assert "ref " in detail


def test_no_raw_exception_interpolated_into_500_responses():
    """Source guard: every 500 must route through _server_error, so no future
    edit can reintroduce a raw ``f"...{e}"`` / ``{exc}`` in a 500 body."""
    import heaven.api.server as srv

    src = pathlib.Path(srv.__file__).read_text(encoding="utf-8")
    offenders = re.findall(r'HTTPException\(\s*(?:status_code=)?500[^\n]*f"[^"]*\{(?:e|exc)\}', src)
    assert not offenders, f"raw-exception 500s must use _server_error(): {offenders}"


def test_ws_error_hides_exception_text_but_names_the_operation():
    """The streaming analogue of the 500 check: a socket worker's catch-all must
    not relay the raw exception into an 'error' frame (CWE-209)."""
    import heaven.api.server as srv

    exc = RuntimeError("boom at /etc/heaven/secret.key: connection to 10.1.2.3 refused")
    msg = srv._ws_error("model pull failed", exc)

    # The operator learns WHAT failed …
    assert "model pull failed" in msg
    # … but none of the raw exception internals reach the browser.
    assert "boom" not in msg
    assert "/etc/heaven/secret.key" not in msg
    assert "10.1.2.3" not in msg
    # … and a correlation id maps the frame to the server log.
    assert "ref " in msg


def test_no_raw_exception_in_websocket_error_frames():
    """Source guard: a WS worker's catch-all error frame must go through
    ``_ws_error`` — no ``{"error": str(e)}`` may creep back into a socket."""
    import heaven.api.server as srv

    src = pathlib.Path(srv.__file__).read_text(encoding="utf-8")
    offenders = re.findall(r'"error":\s*str\(\s*(?:e|exc)\s*\)\s*\}\s*\)', src)
    assert not offenders, f"WS error frames must use _ws_error(): {offenders}"

"""HEAVEN — access-log secret redaction (CWE-532).

The Web UI passes the session token in the WebSocket URL query string (browsers
cannot set headers on a WS open), so uvicorn's access log would otherwise record
the token in cleartext. These tests lock in the redaction filter that strips it.
"""

from __future__ import annotations

import logging

from heaven.utils.logger import (
    _AccessLogRedactor,
    _redact_qs_secrets,
    install_access_log_redaction,
)


def test_redacts_token_query_param():
    s = '127.0.0.1:5000 - "WebSocket /api/chat/stream?token=abc123SECRET" [accepted]'
    out = _redact_qs_secrets(s)
    assert "abc123SECRET" not in out
    assert "token=<redacted>" in out


def test_redacts_multiple_secret_params_keeps_others():
    s = "/x?token=AAA&engagement=prod&api_key=BBB&limit=20"
    out = _redact_qs_secrets(s)
    assert "AAA" not in out and "BBB" not in out
    assert "token=<redacted>" in out and "api_key=<redacted>" in out
    # Non-secret params are preserved verbatim.
    assert "engagement=prod" in out and "limit=20" in out


def test_non_secret_line_unchanged():
    s = '127.0.0.1:5000 - "GET /api/findings?limit=20 HTTP/1.1" 200'
    assert _redact_qs_secrets(s) == s


def test_filter_preserves_http_access_arity_and_types():
    """uvicorn's access formatter unpacks a fixed 5-tuple; the filter must keep
    that arity and the int status code intact while redacting the path."""
    record = logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname=__file__, lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:5000", "GET", "/api/chat/stream?token=LEAKME", "1.1", 200),
        exc_info=None,
    )
    assert _AccessLogRedactor().filter(record) is True
    assert isinstance(record.args, tuple) and len(record.args) == 5
    assert record.args[4] == 200  # status code untouched, still an int
    assert "LEAKME" not in record.args[2]
    # The final rendered line no longer carries the token.
    assert "LEAKME" not in record.getMessage()
    assert "token=<redacted>" in record.getMessage()


def test_install_is_idempotent():
    install_access_log_redaction()
    install_access_log_redaction()
    lg = logging.getLogger("uvicorn.access")
    redactors = [f for f in lg.filters if isinstance(f, _AccessLogRedactor)]
    assert len(redactors) == 1

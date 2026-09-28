"""NoSQL-injection detector: precision guards against length-only false positives.

Live regression (DVWA, a PHP/MySQL app with no NoSQL backend): probing the
`file` param on /vulnerabilities/javascript/ with a MongoDB operator
(`file[$exists]=true`) bounced the request to the login page. The detector saw a
raw length jump (436 -> 1342 bytes) and filed a CRITICAL NoSQL injection. The
fix requires the response to be real served data (not a login/auth page) and to
beat a non-matching operator-shaped negative control, not merely the baseline.
"""

from __future__ import annotations

import pytest

from heaven.vulnscan.anomaly_probe import WebAnomalyProbe

DVWA_LOGIN = (
    "<html><head><title>Login :: Damn Vulnerable Web Application (DVWA)</title>"
    "</head><body><form><input name=\"username\"><input type=\"password\">"
    "</form></body></html>"
)


class _Resp:
    def __init__(self, status: int, body: str):
        self._status = status
        self._body = body

    @property
    def status(self) -> int:
        return self._status

    async def text(self) -> str:
        return self._body

    async def read(self) -> bytes:
        return self._body.encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    """Maps (a rule over params) -> _Resp. `rule` receives the merged params dict."""

    def __init__(self, rule):
        self._rule = rule

    def request(self, method, url, params=None, **kw):
        return self._rule(params or {})

    def post(self, url, data=None, **kw):
        return self._rule({"__json__": data})


@pytest.mark.asyncio
async def test_nosql_fp_login_redirect_not_flagged():
    # Baseline (specific value) serves a short real page; any operator param
    # bounces to the much larger login page. Must NOT be flagged.
    def rule(params):
        if any("[$" in k for k in params):
            return _Resp(200, DVWA_LOGIN)                 # operator -> login page
        return _Resp(200, "<html>short real page</html>")  # baseline
    probe = WebAnomalyProbe()
    out = await probe._test_nosql_injection(_Session(rule), "http://t/p", "file", "GET")
    assert out == [], "a login-page response must not be scored as NoSQL injection"


@pytest.mark.asyncio
async def test_nosql_fp_any_bracket_param_returns_big_page():
    # The app returns the SAME large page for any bracketed param (including the
    # non-matching negative control), so a large response is not operator
    # semantics. Must NOT be flagged.
    big = "<html>" + "DATA" * 500 + "</html>"
    def rule(params):
        if any("[$" in k for k in params):
            return _Resp(200, big)      # every operator-shaped param -> big
        return _Resp(200, "<html>base</html>")
    probe = WebAnomalyProbe()
    out = await probe._test_nosql_injection(_Session(rule), "http://t/p", "q", "GET")
    assert out == [], "a uniformly-large response is not operator injection"


@pytest.mark.asyncio
async def test_nosql_true_positive_still_detected():
    # Genuine operator semantics: a non-matching value (baseline + $eq control)
    # returns little; a return-all operator ($ne/$gt/$regex/$exists) returns many
    # records. This MUST still be flagged.
    small = "<html>one record</html>"
    many = "<html>" + "record" * 400 + "</html>"
    def rule(params):
        keys = list(params)
        if any(op in "".join(keys) for op in ("[$ne]", "[$gt]", "[$regex]", "[$exists]", "[$where]")):
            return _Resp(200, many)          # return-all operator -> lots of data
        return _Resp(200, small)             # baseline + [$eq] control -> little
    probe = WebAnomalyProbe()
    out = await probe._test_nosql_injection(_Session(rule), "http://t/p", "user", "GET")
    assert out, "a real return-all differential must still be detected"
    assert out[0].category == "nosql_injection"

"""Live-audit (certifiedhacker cPanel panels) regression tests for two web-fuzzer
false positives surfaced by a full on-the-wire re-scan.

The cPanel service ports (2083/2087/2096) exposed two detectors the earlier
DVWA/module sweeps never exercised, and both over-claimed:

1. ``method_override_accepted`` fired on ANY non-{404,405,501} status change
   between a plain POST and a POST carrying ``X-HTTP-Method-Override: DELETE``.
   On the wire a plain POST 200 that flipped to a 401 on the override (the server
   REJECTING the header) was reported as "Method Override Accepted" medium, as was
   the reverse 401->200 flap on an auth-challenged endpoint. "Accepted" means the
   server PROCESSED the overridden method, so both the baseline and the override
   response must be success/redirect (200-399) and differ.

2. ``hidden_parameter_discovered`` fired on a length/status delta measured against
   the unmodified page only. Pages that echo the query string into a canonical
   ``<link>``/form action grow the body by a constant amount for ANY appended
   param, and auth-gated panels flip to 401 for any query, so three unrelated
   names (debug/internal/test) were each "discovered" with an identical
   ``len_diff=121``. A junk-param negative control now subtracts that structural
   reaction: a real parameter must move the response MORE than a random name does,
   or produce a status/reflection the random name does not.

Nothing here touches the network: the HTTP surface is a tiny in-process fake.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan.web_fuzzer import _fuzz_method_override, _fuzz_parameters


# ── in-process HTTP fake (supports GET + POST, .read() and .text()) ───────────
class _Resp:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self._body = body
        self.headers: dict = {}
        self.url = ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body

    async def read(self, *a, **k):
        return self._body.encode()


class _Session:
    """Dispatch GET through get_handler(url) and POST through
    post_handler(url, headers)."""

    def __init__(self, get_handler=None, post_handler=None):
        self._get = get_handler
        self._post = post_handler

    def get(self, url, params=None, **kwargs):
        return self._get(url)

    def post(self, url, headers=None, **kwargs):
        return self._post(url, headers or {})


_OVERRIDE_KEYS = {"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "_method"}


def _has_override(headers: dict) -> bool:
    return any(k in headers for k in _OVERRIDE_KEYS)


# ── 1. method override: a denial on the override request is NOT acceptance ────
@pytest.mark.asyncio
async def test_method_override_rejected_with_401_is_not_accepted():
    # Plain POST succeeds (200); adding the override header makes the server REJECT
    # the request (401). The override was refused, not honoured -> no finding.
    def post_handler(url, headers):
        return _Resp(401 if _has_override(headers) else 200)

    findings = await _fuzz_method_override(_Session(post_handler=post_handler), "http://t/")
    assert findings == [], "a 200->401 denial on the override request is not acceptance"


@pytest.mark.asyncio
async def test_method_override_flappy_denied_baseline_is_not_accepted():
    # Plain POST is itself denied (401, an auth-challenged endpoint); the override
    # happens to return 200. That 401->200 flip is auth-state noise, not a method
    # bypass, because the documented scenario is "POST allowed, DELETE/PUT blocked"
    # -> a success baseline. No finding.
    def post_handler(url, headers):
        return _Resp(200 if _has_override(headers) else 401)

    findings = await _fuzz_method_override(_Session(post_handler=post_handler), "http://t/")
    assert findings == [], "a flip from a denied baseline is not a method override"


@pytest.mark.asyncio
async def test_method_override_genuine_processed_method_still_fires():
    # Plain POST 200 (POST is allowed); the override is PROCESSED and returns a
    # different success status (204 No Content from the executed DELETE). This is
    # the genuine firewall-bypass signal and must still be reported.
    def post_handler(url, headers):
        return _Resp(204 if _has_override(headers) else 200)

    findings = await _fuzz_method_override(_Session(post_handler=post_handler), "http://t/")
    assert any(f["vuln_type"] == "method_override_accepted" for f in findings), (
        "a plain-POST success that the override turns into a different success is a bypass"
    )


# ── 2. hidden parameter: a junk-param control subtracts structural reactions ──
def _base_body(n: int) -> str:
    return "<html><body>" + ("z" * n) + "</body></html>"


@pytest.mark.asyncio
async def test_hidden_param_constant_lendiff_for_any_param_is_not_discovery():
    # The page grows the body by a CONSTANT +121 bytes for any appended query param
    # (query echoed into a canonical link), with no reflection. A real param moves
    # the body no more than a random junk name does -> structural, not a discovery.
    base_n = 1000
    base_len = len(_base_body(base_n))

    def get_handler(url):
        if "HEAVEN_PROBE" in url:                       # any appended param (incl. control)
            return _Resp(200, _base_body(base_n) + ("x" * 121))
        return _Resp(200, _base_body(base_n))           # both baseline fetches identical

    findings = await _fuzz_parameters(_Session(get_handler=get_handler), "http://t/panel")
    kinds = {f["vuln_type"] for f in findings}
    assert "hidden_parameter_discovered" not in kinds, (
        "an identical constant length delta for every param is structural noise"
    )
    assert base_len > 0  # guard the fixture is sane


@pytest.mark.asyncio
async def test_hidden_param_any_param_flips_to_401_is_not_discovery():
    # An auth-gated panel returns 401 for ANY appended query param, with the body
    # kept the same length as the baseline. The status change is produced by the
    # junk control too, so it names no hidden parameter.
    base_n = 1000

    def get_handler(url):
        if "HEAVEN_PROBE" in url:
            return _Resp(401, _base_body(base_n))       # same length -> only status differs
        return _Resp(200, _base_body(base_n))

    findings = await _fuzz_parameters(_Session(get_handler=get_handler), "http://t/panel")
    kinds = {f["vuln_type"] for f in findings}
    assert "hidden_parameter_discovered" not in kinds, (
        "a status flip that every param (incl. the control) triggers is not a discovery"
    )


@pytest.mark.asyncio
async def test_hidden_param_signal_beyond_control_still_fires():
    # Junk params add a small structural +50 bytes, but 'debug' enables a verbose
    # code path that adds +5000 bytes -- a signal clearly BEYOND the control, which
    # must still be reported (recall preserved).
    base_n = 1000

    def get_handler(url):
        if "debug=HEAVEN_PROBE" in url:
            return _Resp(200, _base_body(base_n) + ("v" * 5000))
        if "HEAVEN_PROBE" in url:                        # control + other probed names
            return _Resp(200, _base_body(base_n) + ("x" * 50))
        return _Resp(200, _base_body(base_n))

    findings = await _fuzz_parameters(_Session(get_handler=get_handler), "http://t/panel")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert "debug" in params, "a length change well beyond the junk control is a discovery"


@pytest.mark.asyncio
async def test_hidden_param_unique_status_beyond_control_still_fires():
    # The junk control stays 200, but 'admin' uniquely flips the response to 403 --
    # a status the control does not produce, so it is a genuine processed-param
    # signal and still fires.
    base_n = 1000

    def get_handler(url):
        if "admin=HEAVEN_PROBE" in url:
            return _Resp(403, _base_body(base_n))        # unique status, same length
        if "HEAVEN_PROBE" in url:
            return _Resp(200, _base_body(base_n))        # control + others: unchanged
        return _Resp(200, _base_body(base_n))

    findings = await _fuzz_parameters(_Session(get_handler=get_handler), "http://t/panel")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert "admin" in params, "a status the control does not produce is a discovery"


# ── 3. hidden parameter: a load-shed under the concurrent burst is not discovery ─
#
# The sequentially-measured negative control cannot cancel a reaction the server
# only has UNDER load. The discovery phase fans probes out ~10 at a time; a
# throttling host answers part of that wave with a load-shed variant (observed live
# on cPanel login ports: random junk names flipped to a 401 page exactly 121 bytes
# longer than the 200 baseline, purely for riding in the burst) while every request
# made on its own returns a clean 200. Baseline and control are fetched alone, so
# they never see the shed and cannot subtract it, and every probed name is
# "discovered". A sequential re-confirmation re-fetches each candidate alone, where
# the artifact does not reproduce, so the storm collapses to nothing.
class _LoadShedResp:
    """A response whose status/length depends on whether it was issued inside a
    concurrent burst. Any probe (URL carrying HEAVEN_PROBE) issued while another
    request overlaps sheds to a longer 401; issued alone it returns a clean 200.
    Baseline fetches (no HEAVEN_PROBE) always return the clean 200 body."""

    def __init__(self, state: dict, url: str):
        self._state = state
        self._url = url
        self.status = 200
        self._body = state["base"]
        self.headers: dict = {}
        self.url = url

    async def __aenter__(self):
        st = self._state
        st["inflight"] += 1
        # Hold the slot briefly so genuinely concurrent peers register before the
        # shed decision is made; a lone request sees only itself.
        await asyncio.sleep(0.01)
        st["peak"] = max(st["peak"], st["inflight"])
        probe = "HEAVEN_PROBE" in self._url
        genuine = st.get("genuine") and f'{st["genuine"]}=HEAVEN_PROBE' in self._url
        if genuine:
            # a real hidden parameter: distinct response regardless of load
            self.status, self._body = 200, st["base"] + ("v" * 5000)
        elif probe and st["inflight"] > 1:
            # load-shed artifact: only under the concurrent burst
            self.status, self._body = 401, st["base"] + ("x" * 121)
        else:
            self.status, self._body = 200, st["base"]
        return self

    async def __aexit__(self, *a):
        self._state["inflight"] -= 1
        return False

    async def text(self, *a, **k):
        return self._body

    async def read(self, *a, **k):
        return self._body.encode()


def _load_shed_session(genuine: str | None = None):
    state = {"base": _base_body(1000), "inflight": 0, "peak": 0, "genuine": genuine}
    sess = _Session(get_handler=lambda url: _LoadShedResp(state, url))
    return sess, state


@pytest.mark.asyncio
async def test_hidden_param_concurrent_load_shed_is_not_discovery():
    # Every probe in the concurrent burst sheds to 401/+121; alone, every request
    # is a clean 200. Without the sequential re-confirmation this reported dozens of
    # bogus parameters (one per probed name). It must now report none.
    sess, state = _load_shed_session()
    findings = await _fuzz_parameters(sess, "http://t/panel")
    kinds = [f for f in findings if f["vuln_type"] == "hidden_parameter_discovered"]
    assert state["peak"] > 1, "fixture must actually exercise concurrent probing"
    assert kinds == [], (
        "a load-shed that only happens inside the concurrent burst, and vanishes "
        "when each candidate is re-fetched alone, names no hidden parameter"
    )


@pytest.mark.asyncio
async def test_hidden_param_genuine_survives_concurrent_load_shed():
    # Same load-shed storm, but 'debug' is a REAL parameter: its distinct +5000-byte
    # response reproduces whether it rode the burst or is re-fetched alone, so it
    # survives the confirmation while the load-shed junk names are dropped.
    sess, state = _load_shed_session(genuine="debug")
    findings = await _fuzz_parameters(sess, "http://t/panel")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert state["peak"] > 1, "fixture must actually exercise concurrent probing"
    assert params == {"debug"}, (
        "only the parameter whose signal reproduces in a lone request is reported; "
        "the load-shed names must not survive"
    )

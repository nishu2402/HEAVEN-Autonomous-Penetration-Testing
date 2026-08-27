"""RFI evidence must name our probe host — not merely mention a PHP directive.

The Remote File Inclusion check fires when the app *processes* the unroutable
remote URL we supply (an unroutable host always fails to fetch, so PHP emits a
`Failed opening 'http://<host>/...'` / `failed to open stream: ... <host>` warning
that names it). A page that only *mentions* ``allow_url_include`` /
``allow_url_fopen`` — PHP documentation, a phpinfo dump, or DVWA's own File
Inclusion help page — is NOT evidence of RFI. Keying on that bare directive was a
live false-positive source (it fired on DVWA's instructions.php). These tests pin
the soundness of the RFI patterns so that regression can't return.

See heaven/vulnscan/injection_scanner.py (RFI_PATTERNS, _RFI_HOST).
"""

from __future__ import annotations

import asyncio

from heaven.vulnscan.injection_scanner import (
    RFI_BLOCKED_PATTERNS,
    RFI_PATTERNS,
    InjectionScanner,
    _RFI_HOST,
)


def _matches(body: str) -> bool:
    return any(p.search(body) for p in RFI_PATTERNS)


def test_directive_mention_alone_is_not_rfi() -> None:
    # DVWA's instructions.php / a phpinfo page: mentions the directive, but our
    # probe host is nowhere in the response → the app never fetched our URL.
    doc = (
        "<p><code>allow_url_include = on</code> - Allows for Remote File "
        "Inclusion</p><pre>allow_url_fopen On\nallow_url_include On</pre>"
    )
    assert _matches(doc) is False


def test_stream_open_failure_naming_host_is_rfi() -> None:
    # PHP could not open the remote include (unroutable host) and names it.
    warn = (
        "Warning: include(http://%s/h3av3n.txt): failed to open stream: "
        "php_network_getaddresses: getaddrinfo failed in /var/www/x.php on line 9"
    ) % _RFI_HOST
    assert _matches(warn) is True


def test_failed_opening_for_inclusion_naming_host_is_rfi() -> None:
    # The second PHP warning form, host inside the quoted URL.
    warn = (
        "Warning: include(): Failed opening 'http://%s/h3av3n.txt' for inclusion "
        "(include_path='.:/usr/share/php') in /var/www/x.php on line 9"
    ) % _RFI_HOST
    assert _matches(warn) is True


def test_unrelated_stream_error_without_host_is_not_rfi() -> None:
    # A local file-not-found error that does not name our host is not RFI.
    warn = "Warning: include(docs/copying): failed to open stream: No such file or directory"
    assert _matches(warn) is False


# ── Refusal guard: allow_url_include=Off is NOT RFI (live DVWA false positive) ──
#
# When allow_url_include is Off (the PHP default since 5.2) the interpreter still
# echoes an `include(http://<our host>/…)` warning naming the probe host — so the
# body matches RFI_PATTERNS — but it REFUSED to fetch, printing "URL file-access
# is disabled in the server configuration" / "no suitable wrapper could be
# found". Reporting that as RFI was a live false positive on DVWA/PHP 5.2. The
# scanner must recognise the refusal and stay silent, while a genuine RFI (a
# host that fails on the NETWORK, not on config) still fires.

# Real bytes DVWA/PHP 5.2 returns for `?page=http://<host>/h3av3n.txt`.
_DVWA_REFUSED = (
    "<b>Warning</b>:  include() [function.include]: URL file-access is disabled "
    "in the server configuration in <b>/var/www/dvwa/vulnerabilities/fi/index.php"
    "</b> on line <b>35</b><br />\n"
    "<b>Warning</b>:  include(http://%s/h3av3n.txt) [function.include]: failed to "
    "open stream: no suitable wrapper could be found in <b>/var/www/dvwa/"
    "vulnerabilities/fi/index.php</b> on line <b>35</b><br />"
) % _RFI_HOST

# An allow_url_include=On host: PHP TRIES the fetch and fails on the network
# (unroutable probe), with no disabled-wrapper notice → genuinely RFI-capable.
_RFI_CAPABLE = (
    "Warning: include(http://%s/h3av3n.txt): failed to open stream: "
    "php_network_getaddresses: getaddrinfo failed in /var/www/x.php on line 9"
) % _RFI_HOST


class _FakeResp:
    def __init__(self, status: int, body: str) -> None:
        self._status, self._body = status, body

    async def __aenter__(self) -> "_FakeResp":
        return self

    async def __aexit__(self, *_a: object) -> bool:
        return False

    @property
    def status(self) -> int:
        return self._status

    async def text(self, errors: str = "replace") -> str:
        return self._body


class _FakeSession:
    """Returns one canned (status, body) for every GET/POST — no network."""

    def __init__(self, body: str, status: int = 200) -> None:
        self._body, self._status = body, status

    def get(self, *_a: object, **_k: object) -> _FakeResp:
        return _FakeResp(self._status, self._body)

    def post(self, *_a: object, **_k: object) -> _FakeResp:
        return _FakeResp(self._status, self._body)


def _rfi_findings(body: str) -> list[dict]:
    scanner = InjectionScanner(concurrency=2)
    asyncio.run(scanner._test_inclusion_param(
        _FakeSession(body), "http://t/dvwa/vulnerabilities/fi/?page=include.php",
        "page", baseline_body=""))
    return [f for f in scanner._findings if f.get("vuln_type") == "rfi"]


def test_refused_remote_include_is_not_rfi() -> None:
    # The raw patterns DO match the refusal body — that was exactly the FP.
    assert _matches(_DVWA_REFUSED) is True
    # …but a blocked-wrapper guard also matches, so the scanner suppresses it.
    assert any(g.search(_DVWA_REFUSED) for g in RFI_BLOCKED_PATTERNS)
    assert _rfi_findings(_DVWA_REFUSED) == []


def test_network_fetch_failure_is_still_rfi() -> None:
    # No disabled-wrapper notice → the app genuinely tried to fetch → RFI stands.
    assert not any(g.search(_RFI_CAPABLE) for g in RFI_BLOCKED_PATTERNS)
    found = _rfi_findings(_RFI_CAPABLE)
    assert len(found) == 1 and found[0]["vuln_type"] == "rfi"

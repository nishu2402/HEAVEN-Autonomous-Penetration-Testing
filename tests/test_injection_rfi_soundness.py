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

from heaven.vulnscan.injection_scanner import RFI_PATTERNS, _RFI_HOST


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

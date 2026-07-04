"""Regression tests for boolean-blind SQLi precision.

These pin the fix for the false positives observed live against DVWA (2026-07-04):
the old length-only heuristic flagged `sqli` on reflective / echoing endpoints
(`xss_r`, `fi`, `brute`) whose response length changed for reasons unrelated to
any SQL result. The pure decision function `_boolean_sqli_confirmed` must:

  * still confirm a genuine boolean-blind oracle (row appears on TRUE, vanishes
    on FALSE) — even when the differing content is tiny relative to page size, and
  * reject pages that merely reflect the injected payload.

All fixtures are synthetic (no network / no DVWA) so the contract is fast and
deterministic.
"""

from heaven.vulnscan.injection_scanner import (
    _boolean_sqli_confirmed,
    _diff_char_count,
    _strip_reflection,
)

# A realistically-sized page wrapper so we exercise page-size independence:
# the boolean signal (a single result row) is tiny next to the chrome.
_CHROME = "<html><head><title>DVWA</title></head><body>" + ("x" * 4000)
_FOOT = ("y" * 400) + "</body></html>"

# DVWA-style SQLi payloads (true condition, false condition)
TRUE_PL = "1) AND (1=1)--"
FALSE_PL = "1) AND (1=2)--"


def _page(body: str) -> str:
    return _CHROME + body + _FOOT


# ── True positive: a real boolean-blind oracle ─────────────────────

def test_confirms_real_boolean_blind_sqli():
    # TRUE reproduces the baseline row; FALSE hides it. The id value is not
    # echoed in the output (DVWA sqli-low shows the *query result*, not input).
    row = "<pre>First name: admin\nSurname: admin</pre>"
    baseline = _page(row)
    body_true = _page(row)          # 1 AND 1=1 → row still returned
    body_false = _page("")          # 1 AND 1=2 → no row
    assert _boolean_sqli_confirmed(baseline, body_true, body_false, TRUE_PL, FALSE_PL)


def test_confirms_even_when_signal_is_tiny_relative_to_page():
    # The whole-page-ratio approach used to miss this (a ~40-char delta in a
    # ~4500-char page is >0.99 similar). The absolute-delta check catches it.
    row = "<pre>First name: admin Surname: admin</pre>"
    baseline = _page(row)
    assert _boolean_sqli_confirmed(baseline, _page(row), _page(""), TRUE_PL, FALSE_PL)


# ── False positives that must now be rejected ──────────────────────

def test_rejects_reflected_xss_page():
    # xss_r echoes the `name` param. TRUE/FALSE differ ONLY by the reflected
    # payload text — not by any SQL result.
    baseline = _page("<p>Hello 1</p>")
    body_true = _page(f"<p>Hello {TRUE_PL}</p>")
    body_false = _page(f"<p>Hello {FALSE_PL}</p>")
    assert not _boolean_sqli_confirmed(baseline, body_true, body_false, TRUE_PL, FALSE_PL)


def test_rejects_html_escaped_reflected_payload():
    # PHP's htmlspecialchars escapes reflected input (' -> &#039;), which used to
    # defeat the verbatim reflection strip and leak a false positive on DVWA's
    # xss_d / fi endpoints. HTML-decoding first neutralises it.
    def esc(p: str) -> str:
        return p.replace("'", "&#039;")

    baseline = _page("<p>Search: 1</p>")
    body_true = _page(f"<p>Search: {esc(TRUE_PL)}</p>")
    body_false = _page(f"<p>Search: {esc(FALSE_PL)}</p>")
    assert not _boolean_sqli_confirmed(baseline, body_true, body_false, TRUE_PL, FALSE_PL)


def test_rejects_file_inclusion_warning_that_echoes_payload():
    # fi names the missing "file" (the payload) in its warning — reflection.
    baseline = _page("<p>Warning: include(1): failed to open stream</p>")
    body_true = _page(f"<p>Warning: include({TRUE_PL}): failed to open stream</p>")
    body_false = _page(f"<p>Warning: include({FALSE_PL}): failed to open stream</p>")
    assert not _boolean_sqli_confirmed(baseline, body_true, body_false, TRUE_PL, FALSE_PL)


def test_rejects_generic_login_error_same_for_both():
    # brute returns the same "incorrect" page regardless of the injected value.
    err = _page("<p>Username and/or password incorrect.</p>")
    assert not _boolean_sqli_confirmed(err, err, err, TRUE_PL, FALSE_PL)


def test_rejects_whitespace_only_difference():
    body_true = _page("<div>\n  result\n</div>")
    body_false = _page("<div>result</div>")
    assert not _boolean_sqli_confirmed(body_true, body_true, body_false, TRUE_PL, FALSE_PL)


# ── Edge cases ─────────────────────────────────────────────────────

def test_rejects_empty_bodies():
    assert not _boolean_sqli_confirmed("", "", "", TRUE_PL, FALSE_PL)
    assert not _boolean_sqli_confirmed(_page("x"), "", _page("y"), TRUE_PL, FALSE_PL)


def test_rejects_identical_true_false():
    p = _page("<pre>data</pre>")
    assert not _boolean_sqli_confirmed(p, p, p, TRUE_PL, FALSE_PL)


def test_min_delta_boundary():
    # Exactly at the 12-char floor with true==baseline → confirm; just under → reject.
    base = _page("")
    body_true = _page("")
    assert _boolean_sqli_confirmed(base, body_true, _page("A" * 12), TRUE_PL, FALSE_PL)
    assert not _boolean_sqli_confirmed(base, body_true, _page("A" * 11), TRUE_PL, FALSE_PL)


# ── Helper unit checks ─────────────────────────────────────────────

def test_strip_reflection_removes_payload():
    assert _strip_reflection("a 1) AND (1=1)-- b", TRUE_PL) == "a  b"
    assert _strip_reflection("no payload here", TRUE_PL) == "no payload here"


def test_strip_reflection_handles_html_escaped_payload():
    escaped = "x 1&#039; OR &#039;1&#039;=&#039;1 y"
    assert _strip_reflection(escaped, "1' OR '1'='1") == "x  y"


def test_diff_char_count_basics():
    assert _diff_char_count("abc", "abc") == 0
    assert _diff_char_count("abc", "abXc") > 0

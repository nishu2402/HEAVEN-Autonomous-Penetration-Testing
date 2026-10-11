"""sqlmap output parsing — precision of the confirmation oracle.

sqlmap is run only as the *confirmation* step for a SQLi candidate, so its
verdict must be read correctly. The previous parser keyed on a bare
"parameter ... injectable" substring, which matches sqlmap's NEGATIVE line
"all tested parameters do not appear to be injectable" and inverted a clean
result into a confirmed critical at confidence 1.0. These tests pin the real
behaviour: a negative run yields NO finding, a positive run still yields one.
"""

from __future__ import annotations

from heaven.vulnscan.sqlmap_runner import _parse_sqlmap_output

_URL = "http://127.0.0.1/item.php?id=1"

_NEGATIVE = """\
[*] starting @ 12:00:00 /2026-10-10/
[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing if GET parameter 'id' is dynamic
[12:00:05] [WARNING] GET parameter 'id' does not seem to be injectable
[12:00:06] [CRITICAL] all tested parameters do not appear to be injectable.
[*] ending @ 12:00:06 /2026-10-10/
"""

_POSITIVE = """\
[*] starting @ 12:00:00 /2026-10-10/
[12:00:03] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable
[12:00:07] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 54 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 2956=2956
---
[12:00:08] [INFO] the back-end DBMS: MySQL >= 5.6
current database: 'shopdb'
[*] ending @ 12:00:08 /2026-10-10/
"""


def test_negative_sqlmap_run_yields_no_finding(tmp_path):
    res = _parse_sqlmap_output(_NEGATIVE, _URL, tmp_path)
    assert res["findings"] == [], res
    assert res["injectable_params"] == []


def test_positive_sqlmap_run_still_confirms(tmp_path):
    res = _parse_sqlmap_output(_POSITIVE, _URL, tmp_path)
    assert len(res["findings"]) == 1, res
    f = res["findings"][0]
    assert f["vuln_type"] == "sqli_confirmed"
    assert f["severity"] == "critical"
    assert f["confidence"] == 1.0
    assert f["evidence"]["dbms"].startswith("MySQL")
    assert f["evidence"]["current_db"] == "shopdb"


def test_injectable_appears_only_in_negation_is_not_confirmed(tmp_path):
    # A line that contains both "parameter" and "injectable" but only as a
    # negation must never be treated as a positive.
    only_negation = (
        "[WARNING] all tested parameters do not appear to be injectable, "
        "sqlmap was unable to find any injection point\n"
    )
    res = _parse_sqlmap_output(only_negation, _URL, tmp_path)
    assert res["findings"] == []

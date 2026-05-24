"""
sqlmap output → list[Finding] adapter.

sqlmap has two parsable outputs:
  1. Session SQLite (`~/.local/share/sqlmap/output/<target>/session.sqlite`)
     — most reliable, machine-readable
  2. Console transcript — fragile but useful when only the log file is saved

We support both. The transcript parser is forgiving: any line matching
the canonical "Parameter: X (METHOD)" + a "Type: ..." block produces
one Finding. Confidence is fixed at 0.99 because sqlmap only reports
confirmed injection points.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from tests.benchmarks.metrics import Finding


_INJECTION_TYPE_TO_VULN = {
    "boolean-based blind": "sqli_boolean",
    "time-based blind": "sqli_time",
    "error-based": "sqli_error",
    "union query": "sqli_union",
    "stacked queries": "sqli_stacked",
    "inline queries": "sqli",
}


def _normalise_type(s: str) -> str:
    s = s.lower()
    for k, v in _INJECTION_TYPE_TO_VULN.items():
        if k in s:
            return v
    return "sqli"


def _load_from_transcript(path: Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []

    # Look for URL banner near top of run
    url_match = re.search(r"testing URL\s*['\"]?(https?://[^\s'\"]+)", text)
    base_url = url_match.group(1) if url_match else ""

    # Block pattern: Parameter: <name> (<method>)
    #                Type: <type>
    pat = re.compile(
        r"Parameter:\s+(?P<param>\S+)\s+\((?P<method>\w+)\).*?Type:\s+(?P<type>[^\n\r]+)",
        re.DOTALL,
    )
    for m in pat.finditer(text):
        findings.append(Finding(
            url=base_url,
            vuln_type=_normalise_type(m.group("type")),
            parameter=m.group("param"),
            confidence=0.99,
            severity="critical",
        ))
    return findings


def _load_from_session_sqlite(path: Path) -> list[Finding]:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    findings: list[Finding] = []
    try:
        cur = conn.execute(
            "SELECT url, parameter, type FROM injections "
        )
        for row in cur:
            findings.append(Finding(
                url=row["url"] or "",
                vuln_type=_normalise_type(row["type"] or ""),
                parameter=row["parameter"] or "",
                confidence=0.99,
                severity="critical",
            ))
    except sqlite3.OperationalError:
        # Schema may differ across sqlmap versions; transcript fallback
        # is the operator's option.
        pass
    finally:
        conn.close()
    return findings


def load_sqlmap(path: Path) -> list[Finding]:
    """Parse sqlmap output. Detects session.sqlite vs. transcript by extension."""
    p = Path(path)
    if p.suffix == ".sqlite":
        return _load_from_session_sqlite(p)
    return _load_from_transcript(p)

"""
Burp Scanner XML export → list[Finding] adapter.

Burp Suite Professional emits scan results as XML via:
  Target → Site map → right-click → Issues → Save selected issues

The relevant XPath is /issues/issue with fields:
  - name (issue type), severity, host/ip, location, request/response
  - The request element contains the param name in the body / query
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from tests.benchmarks.metrics import Finding


def _norm_severity(burp_sev: str) -> str:
    s = (burp_sev or "").strip().lower()
    return {
        "high": "high", "medium": "medium", "low": "low",
        "information": "info", "info": "info",
    }.get(s, s or "info")


def _confidence(burp_conf: str) -> float:
    return {
        "certain": 0.99, "firm": 0.85, "tentative": 0.55,
    }.get((burp_conf or "").lower(), 0.5)


def _extract_param(issue_elem) -> str:
    """Burp's XML doesn't always tag the vulnerable parameter explicitly.

    Heuristic: look for issueDetail or the response body for "parameter X"
    style strings. Returns the first reasonable candidate or empty string.
    """
    detail_elem = issue_elem.find("issueDetail")
    detail = (detail_elem.text or "") if detail_elem is not None else ""
    import re
    m = re.search(r"parameter [`'\"]?([A-Za-z_][\w-]+)", detail)
    if m:
        return m.group(1)
    # Try the request element's body
    req_elem = issue_elem.find("requestresponse/request")
    if req_elem is not None and req_elem.text:
        body = req_elem.text
        # Common form: "Param=value" or "?id=1"
        m2 = re.search(r"[?&]([A-Za-z_][\w-]+)=", body)
        if m2:
            return m2.group(1)
    return ""


def load_burp(path: Path) -> list[Finding]:
    """Parse a Burp Scanner XML export. Returns a list of Findings."""
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    root = tree.getroot()

    findings: list[Finding] = []
    for issue in root.iter("issue"):
        name_elem = issue.find("name")
        host_elem = issue.find("host")
        loc_elem  = issue.find("location")
        sev_elem  = issue.find("severity")
        conf_elem = issue.find("confidence")

        host = host_elem.text if host_elem is not None and host_elem.text else ""
        loc = loc_elem.text if loc_elem is not None and loc_elem.text else ""
        url = (host + loc) if (host and loc and not loc.startswith("http")) else (loc or host)

        findings.append(Finding(
            url=url,
            vuln_type=(name_elem.text or "") if name_elem is not None else "",
            parameter=_extract_param(issue),
            confidence=_confidence(conf_elem.text if conf_elem is not None else ""),
            severity=_norm_severity(sev_elem.text if sev_elem is not None else ""),
        ))
    return findings

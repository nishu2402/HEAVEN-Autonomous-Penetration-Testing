"""
OWASP ZAP JSON report → list[Finding] adapter.

ZAP report shape (from `zap-cli report -o report.json -f json`):
  {
    "site": [
      {
        "@name": "http://target",
        "alerts": [
          {
            "name": "SQL Injection",
            "riskdesc": "High (Medium)",
            "confidence": "Medium",
            "instances": [{"uri": "...", "param": "id", ...}],
            ...
          }
        ]
      }
    ]
  }

Each alert may contain multiple instances; we emit one Finding per instance.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.benchmarks.metrics import Finding


_CONFIDENCE_MAP = {
    "high": 0.85, "medium": 0.65, "low": 0.4,
    "false positive": 0.0, "confirmed": 0.95,
}


def _norm_severity(riskdesc: str) -> str:
    # ZAP `riskdesc` looks like "High (Medium)" — first token is severity
    return riskdesc.split()[0].lower() if riskdesc else "info"


def _confidence(conf: str) -> float:
    return _CONFIDENCE_MAP.get((conf or "").lower(), 0.5)


def load_zap(path: Path) -> list[Finding]:
    """Parse a ZAP JSON report. Returns a list of Findings."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings: list[Finding] = []

    sites = data.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]   # ZAP sometimes ships a single dict
    for site in sites:
        alerts = site.get("alerts") or []
        for alert in alerts:
            name = alert.get("name", "")
            severity = _norm_severity(alert.get("riskdesc", ""))
            conf = _confidence(alert.get("confidence", ""))

            instances = alert.get("instances") or [{}]
            for inst in instances:
                findings.append(Finding(
                    url=inst.get("uri", "") or site.get("@name", ""),
                    vuln_type=name,
                    parameter=inst.get("param", ""),
                    confidence=conf,
                    severity=severity,
                ))
    return findings

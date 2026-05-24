"""
HEAVEN benchmark — scanner output adapters.

Convert third-party scanner output into the common Finding shape so the
existing metrics layer can do head-to-head comparison.

Supported scanners:
  Burp Scanner   — burp.py    (XML export from Burp's Audit / Issue Activity)
  OWASP ZAP      — zap.py     (JSON report via `zap-cli report -o`)
  sqlmap         — sqlmap.py  (session log .sqlite or stdout transcript)

Each adapter exposes a single function:
  load_<tool>(path: Path) -> list[Finding]

Usage:
  from tests.benchmarks.adapters import load_burp
  from tests.benchmarks.metrics import GroundTruth, evaluate

  findings = load_burp(Path("burp.xml"))
  result   = evaluate(findings, GroundTruth.load(Path(".../dvwa.yaml")))
"""

from tests.benchmarks.adapters.burp import load_burp
from tests.benchmarks.adapters.zap import load_zap
from tests.benchmarks.adapters.sqlmap import load_sqlmap

__all__ = ["load_burp", "load_zap", "load_sqlmap"]

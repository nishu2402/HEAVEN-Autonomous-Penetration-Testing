"""
HEAVEN — Post-Exploitation Modules (Gap 5)

After initial access, a real pen-test continues to:
  1. Enumerate privilege escalation paths    → linpeas_runner
  2. Map Active Directory attack paths       → bloodhound_collector
  3. Detect credential reuse across services → cred_validator

These modules require valid credentials and explicit authorization;
they are NOT invoked from the default scan pipeline. The CLI exposes
them under `heaven postex <subcommand>` so the operator chooses when
to run them and against what.

Authorization gating:
  Every module checks an `authorized=True` flag on construction. The
  CLI layer is responsible for translating --i-have-authorization into
  this flag.
"""

from heaven.postex.linpeas_runner import LinpeasRunner, LinpeasResult
from heaven.postex.bloodhound_collector import BloodHoundCollector
from heaven.postex.cred_validator import CredentialValidator, CredentialHit
from heaven.postex.lateral import (
    SSHKeyReuseScanner, SMBLateralExecutor,
    LateralSummary, LateralHop, run_lateral,
)

__all__ = [
    "LinpeasRunner", "LinpeasResult",
    "BloodHoundCollector",
    "CredentialValidator", "CredentialHit",
    "SSHKeyReuseScanner", "SMBLateralExecutor",
    "LateralSummary", "LateralHop", "run_lateral",
]

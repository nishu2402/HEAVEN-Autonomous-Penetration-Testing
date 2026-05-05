"""
HEAVEN — Tamper-Proof Audit Logging
HMAC-chained audit log with CEF/JSON export for SIEM integration.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("security.audit")


class AuditAction(str, Enum):
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    TARGET_ADDED = "target.added"
    TARGET_SCANNED = "target.scanned"
    VULN_DISCOVERED = "vuln.discovered"
    VULN_VALIDATED = "vuln.validated"
    EXPLOIT_ATTEMPTED = "exploit.attempted"
    VAULT_UNLOCKED = "vault.unlocked"
    VAULT_LOCKED = "vault.locked"
    VAULT_CREDENTIAL_STORED = "vault.credential.stored"
    VAULT_CREDENTIAL_ACCESSED = "vault.credential.accessed"
    VAULT_KEY_ROTATED = "vault.key.rotated"
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILED = "auth.login.failed"
    AUTH_TOKEN_ISSUED = "auth.token.issued"
    AUTH_BRUTE_FORCE_DETECTED = "auth.brute_force.detected"
    API_REQUEST = "api.request"
    API_RATE_LIMITED = "api.rate_limited"
    CONFIG_CHANGED = "config.changed"
    SYSTEM_STARTUP = "system.startup"
    SELF_AUDIT_RUN = "security.self_audit"
    INTEGRITY_VIOLATION = "security.integrity_violation"
    UNAUTHORIZED_ACCESS = "security.unauthorized_access"
    MITRE_MAPPING_GENERATED = "mitre.mapping.generated"
    AD_RECON_STARTED = "ad.recon.started"
    AD_ATTACK_SIMULATED = "ad.attack.simulated"


class AuditSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ALERT = "alert"


@dataclass
class AuditEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    action: str = ""
    severity: str = AuditSeverity.INFO.value
    actor: str = "system"
    target: str = ""
    details: dict = field(default_factory=dict)
    source_ip: str = ""
    session_id: str = ""
    chain_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp, timezone.utc).isoformat(),
            "action": self.action, "severity": self.severity,
            "actor": self.actor, "target": self.target,
            "details": self.details, "source_ip": self.source_ip,
            "chain_hash": self.chain_hash, "entry_hash": self.entry_hash,
        }

    def to_cef(self) -> str:
        sev_map = {"info": 1, "warning": 5, "critical": 8, "alert": 10}
        details_str = " ".join(f"{k}={v}" for k, v in self.details.items())
        return (
            f"CEF:0|HEAVEN|PenTestPlatform|1.0|{self.action}|"
            f"{self.action}|{sev_map.get(self.severity, 1)}|"
            f"src={self.source_ip} suser={self.actor} dst={self.target} "
            f"msg={details_str} rt={int(self.timestamp * 1000)}"
        )


class AuditLogger:
    """
    Tamper-proof audit logging with HMAC chain integrity.
    Every entry is HMAC-linked to the previous (blockchain-like).
    Supports CEF (Splunk/ArcSight) and JSON (ELK) export.
    """

    def __init__(self, log_dir: Optional[Path] = None, hmac_key: Optional[bytes] = None,
                 retention_days: int = 365):
        self._log_dir = log_dir or Path("data/audit")
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._hmac_key = hmac_key or os.urandom(32)
        self._retention_days = retention_days
        self._entries: list[AuditEntry] = []
        self._last_hash: str = "GENESIS"
        self._current_file: Optional[Path] = None

    def log(self, action: AuditAction, target: str = "", details: Optional[dict] = None,
            actor: str = "system", severity: AuditSeverity = AuditSeverity.INFO,
            source_ip: str = "") -> AuditEntry:
        entry = AuditEntry(
            action=action.value, severity=severity.value,
            actor=actor, target=target, details=details or {},
            source_ip=source_ip,
        )
        chain_data = f"{self._last_hash}:{entry.id}:{entry.timestamp}:{entry.action}"
        entry.chain_hash = hmac.new(
            self._hmac_key, chain_data.encode(), hashlib.sha256
        ).hexdigest()
        entry_data = json.dumps(entry.to_dict(), sort_keys=True, default=str)
        entry.entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        self._last_hash = entry.chain_hash
        self._entries.append(entry)
        self._write_entry(entry)
        if severity in (AuditSeverity.CRITICAL, AuditSeverity.ALERT):
            logger.warning(f"AUDIT [{severity.value.upper()}] {action.value}: {target}")
        return entry

    def verify_chain(self) -> dict:
        prev_hash = "GENESIS"
        violations = []
        for i, entry in enumerate(self._entries):
            expected = f"{prev_hash}:{entry.id}:{entry.timestamp}:{entry.action}"
            expected_hash = hmac.new(self._hmac_key, expected.encode(), hashlib.sha256).hexdigest()
            if entry.chain_hash != expected_hash:
                violations.append({"index": i, "entry_id": entry.id, "error": "Chain hash mismatch"})
            prev_hash = entry.chain_hash
        return {"valid": len(violations) == 0, "checked": len(self._entries), "violations": violations}

    def search(self, action: Optional[str] = None, actor: Optional[str] = None,
               severity: Optional[str] = None, limit: int = 100) -> list[dict]:
        results = []
        for entry in reversed(self._entries):
            if action and entry.action != action:
                continue
            if actor and entry.actor != actor:
                continue
            if severity and entry.severity != severity:
                continue
            results.append(entry.to_dict())
            if len(results) >= limit:
                break
        return results

    def export_cef(self, output_path: Optional[Path] = None) -> str:
        lines = [e.to_cef() for e in self._entries]
        output = "\n".join(lines)
        if output_path:
            output_path.write_text(output)
        return output

    def export_json(self, output_path: Optional[Path] = None) -> str:
        data = json.dumps([e.to_dict() for e in self._entries], indent=2, default=str)
        if output_path:
            output_path.write_text(data)
        return data

    def _write_entry(self, entry: AuditEntry) -> None:
        if not self._current_file:
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            self._current_file = self._log_dir / f"audit_{date_str}.jsonl"
        try:
            with open(self._current_file, "a") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        except OSError as e:
            logger.error(f"Failed to write audit entry: {e}")

    def summary(self) -> dict:
        action_counts: dict[str, int] = {}
        for entry in self._entries:
            action_counts[entry.action] = action_counts.get(entry.action, 0) + 1
        return {
            "total_entries": len(self._entries),
            "chain_valid": self.verify_chain()["valid"],
            "top_actions": dict(sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        }


_audit_logger: Optional[AuditLogger] = None

def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger

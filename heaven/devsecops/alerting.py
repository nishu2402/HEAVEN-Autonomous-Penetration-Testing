"""
HEAVEN — Alerting
Two layers of notifications:

  1. WebhookAlerter — human-readable summaries to Slack / Discord / Teams.
     Existing behaviour. Triggered when a scan ends with critical findings.

  2. SIEMNotifier — machine-readable events to Splunk HEC and Elastic.
     New. Blue-team coordination: pre-scan "we're starting" so SOC
     ignores the alerts, post-scan "we're done" so SOC re-enables
     monitoring, and per-critical-finding events for live triage.

The SIEM layer is config-driven via env vars and silently no-ops when
the target SIEM is not configured — so HEAVEN's existing behaviour
doesn't change unless the operator opts in.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.alerting")


class WebhookAlerter:
    """Handles sending scan summaries to external webhooks (Slack/Discord/Teams)."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")

    def send_alert(self, summary_data: dict[str, Any]) -> bool:
        """Send a formatted alert to the configured webhook. Returns True on success."""
        if not self.webhook_url:
            logger.debug("No WEBHOOK_URL configured, skipping alert.")
            return False

        criticals = summary_data.get("critical", 0)
        highs = summary_data.get("high", 0)

        if criticals == 0 and highs == 0:
            return True

        message = (
            f"** HEAVEN Penetration Test Alert **\n"
            f"Scan completed with critical vulnerabilities detected!\n\n"
            f"Critical Findings: {criticals}\n"
            f"High Findings: {highs}\n"
            f"Total Targets Scanned: {summary_data.get('total_assets', 0)}\n\n"
            f"Check the HEAVEN dashboard or generated reports for details."
        )

        payload = {
            "content": message,  # Discord format
            "text": message,     # Slack format
        }

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self._post_async(payload))
                return True
            return loop.run_until_complete(self._post_async(payload))
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    async def send_alert_async(self, summary_data: dict[str, Any]) -> bool:
        """Async version — use inside async code."""
        if not self.webhook_url:
            logger.debug("No WEBHOOK_URL configured, skipping alert.")
            return False

        criticals = summary_data.get("critical", 0)
        highs = summary_data.get("high", 0)
        if criticals == 0 and highs == 0:
            return True

        message = (
            f"** HEAVEN Penetration Test Alert **\n"
            f"Scan completed with critical vulnerabilities detected!\n\n"
            f"Critical Findings: {criticals}\n"
            f"High Findings: {highs}\n"
            f"Total Targets Scanned: {summary_data.get('total_assets', 0)}\n\n"
            f"Check the HEAVEN dashboard or generated reports for details."
        )

        return await self._post_async({"content": message, "text": message})

    async def _post_async(self, payload: dict) -> bool:
        """POST payload to webhook using aiohttp."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,  # type: ignore[arg-type]
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    resp.raise_for_status()
                    logger.info("Webhook alert sent successfully.")
                    return True
        except Exception as e:
            logger.error(f"Webhook POST failed: {e}")
            return False


# ═══════════════════════════════════════════════════════════════════════════
# SIEM / SOC INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SplunkHECAlerter:
    """Splunk HTTP Event Collector. Env: HEAVEN_SPLUNK_HEC_URL, HEAVEN_SPLUNK_HEC_TOKEN."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 sourcetype: str = "heaven:event", index: Optional[str] = None,
                 verify_tls: bool = True):
        self.url = url or os.getenv("HEAVEN_SPLUNK_HEC_URL", "")
        self.token = token or os.getenv("HEAVEN_SPLUNK_HEC_TOKEN", "")
        self.sourcetype = sourcetype
        self.index = index or os.getenv("HEAVEN_SPLUNK_HEC_INDEX") or None
        self.verify_tls = verify_tls

    @property
    def available(self) -> bool:
        return bool(self.url and self.token)

    async def emit(self, event_type: str, payload: dict[str, Any]) -> bool:
        """Send one HEC event. Returns True on 200, False otherwise."""
        if not self.available:
            return False
        body: dict[str, Any] = {
            "time": payload.get("ts") or _now(),
            "sourcetype": self.sourcetype,
            "source": "heaven",
            "event": {"event_type": event_type, **payload},
        }
        if self.index:
            body["index"] = self.index

        try:
            import aiohttp
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_tls)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.url.rstrip('/')}/services/collector",
                    json=body,
                    headers={"Authorization": f"Splunk {self.token}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    resp.raise_for_status()
                    return True
        except Exception as e:
            logger.error(f"Splunk HEC emit failed: {e}")
            return False


class ElasticAlerter:
    """Elasticsearch bulk index. Env: HEAVEN_ELASTIC_URL, HEAVEN_ELASTIC_INDEX, HEAVEN_ELASTIC_API_KEY."""

    def __init__(self, url: Optional[str] = None, index: Optional[str] = None,
                 api_key: Optional[str] = None, verify_tls: bool = True):
        self.url = url or os.getenv("HEAVEN_ELASTIC_URL", "")
        self.index = index or os.getenv("HEAVEN_ELASTIC_INDEX", "heaven-events")
        self.api_key = api_key or os.getenv("HEAVEN_ELASTIC_API_KEY", "")
        self.verify_tls = verify_tls

    @property
    def available(self) -> bool:
        return bool(self.url and self.index)

    async def emit(self, event_type: str, payload: dict[str, Any]) -> bool:
        if not self.available:
            return False
        doc = {
            "@timestamp": payload.get("ts") or _now(),
            "event_type": event_type,
            **payload,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        try:
            import aiohttp
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_tls)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.url.rstrip('/')}/{self.index}/_doc",
                    json=doc, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    resp.raise_for_status()
                    return True
        except Exception as e:
            logger.error(f"Elastic emit failed: {e}")
            return False


class SIEMNotifier:
    """Multiplex events across all configured SIEMs.

    Three event types are conventional but free-form:
      - scan.start    payload = {scan_id, mode, targets, operator?, expected_duration_s?}
      - scan.complete payload = {scan_id, total_findings, critical, high, duration_s, ...}
      - finding.critical payload = {scan_id, target, vuln_type, severity, confidence, ...}

    Construct once and call emit() throughout the scan lifecycle. The notifier
    silently no-ops on every backend that isn't configured, so the same call
    site works for operators with zero, one, or both SIEMs wired up.
    """

    def __init__(self, *backends: Any):
        if backends:
            self._backends = list(backends)
        else:
            self._backends = [SplunkHECAlerter(), ElasticAlerter()]

    @property
    def configured_backends(self) -> list[str]:
        return [type(b).__name__ for b in self._backends if getattr(b, "available", False)]

    async def emit(self, event_type: str, payload: dict[str, Any]) -> dict[str, bool]:
        """Fan out one event to every available backend.

        Returns {backend_name: True/False} so callers can log per-backend status.
        """
        results: dict[str, bool] = {}
        coros = []
        names = []
        for b in self._backends:
            if not getattr(b, "available", False):
                continue
            coros.append(b.emit(event_type, payload))
            names.append(type(b).__name__)
        if not coros:
            return results
        outcomes = await asyncio.gather(*coros, return_exceptions=True)
        for name, outcome in zip(names, outcomes):
            results[name] = bool(outcome) and not isinstance(outcome, Exception)
        return results

    # ── Convenience event helpers — encode the canonical schema ─────────

    async def scan_start(self, scan_id: str, mode: str, targets: dict[str, Any],
                         operator: str = "", note: str = "") -> dict[str, bool]:
        return await self.emit("scan.start", {
            "scan_id": scan_id, "mode": mode, "targets": targets,
            "operator": operator, "note": note, "ts": _now(),
        })

    async def scan_complete(self, scan_id: str, summary: dict[str, Any]) -> dict[str, bool]:
        return await self.emit("scan.complete", {
            "scan_id": scan_id,
            "total_findings": summary.get("total_findings", 0),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "duration_s": summary.get("elapsed_seconds", 0),
            "ts": _now(),
        })

    async def critical_finding(self, scan_id: str, finding: dict[str, Any]) -> dict[str, bool]:
        return await self.emit("finding.critical", {
            "scan_id": scan_id,
            "target": finding.get("target", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "confidence": finding.get("confidence", 0),
            "cve_id": finding.get("cve_id", ""),
            "ts": _now(),
        })

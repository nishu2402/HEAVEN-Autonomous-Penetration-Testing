"""
HEAVEN — Webhook Alerting
Sends real-time notifications to Slack/Discord/Teams for critical findings.
"""

from __future__ import annotations

import asyncio
import os
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

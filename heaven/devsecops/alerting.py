"""
HEAVEN — Webhook Alerting
Sends real-time notifications to Slack/Discord/Teams for critical findings.
"""

from __future__ import annotations

import json
import os
import requests
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.alerting")

class WebhookAlerter:
    """Handles sending scan summaries to external webhooks."""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")
        
    def send_alert(self, summary_data: dict[str, Any]) -> bool:
        """Send a formatted alert message based on scan findings."""
        if not self.webhook_url:
            logger.debug("No WEBHOOK_URL configured, skipping alerts.")
            return False
            
        criticals = summary_data.get("critical", 0)
        highs = summary_data.get("high", 0)
        
        # Only alert if there are high/critical findings
        if criticals == 0 and highs == 0:
            return True
            
        message = (
            f"🚨 **HEAVEN Penetration Test Alert** 🚨\n"
            f"A scan has completed and discovered critical vulnerabilities!\n\n"
            f"**Critical Findings:** {criticals}\n"
            f"**High Findings:** {highs}\n"
            f"**Total Targets Scanned:** {summary_data.get('total_assets', 0)}\n\n"
            f"Please check the HEAVEN dashboard or the generated reports for details."
        )
        
        payload = {
            "content": message, # Discord format
            "text": message     # Slack format
        }
        
        try:
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            response.raise_for_status()
            logger.info("Successfully sent webhook alert.")
            return True
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

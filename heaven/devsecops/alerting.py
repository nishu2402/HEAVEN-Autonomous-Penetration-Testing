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


# ═══════════════════════════════════════════
# TICKETING — Jira + Linear
# Configured by env vars; no-op when not set.
#
#   HEAVEN_JIRA_URL          https://yourorg.atlassian.net
#   HEAVEN_JIRA_USER         email@org.com
#   HEAVEN_JIRA_TOKEN        Atlassian API token
#   HEAVEN_JIRA_PROJECT      ABC (project key)
#   HEAVEN_JIRA_ISSUE_TYPE   Bug (default)
#
#   HEAVEN_LINEAR_TOKEN      lin_api_xxx
#   HEAVEN_LINEAR_TEAM_ID    UUID of the Linear team
# ═══════════════════════════════════════════


class JiraAlerter:
    """Create Jira issues from HEAVEN findings.

    Uses the Cloud REST API v3 (works against Server with minor URL change).
    Authenticates with email + API token via Basic auth, the supported
    auth flow for Atlassian Cloud.
    """

    def __init__(self,
                 base_url: Optional[str] = None,
                 user: Optional[str] = None,
                 token: Optional[str] = None,
                 project: Optional[str] = None,
                 issue_type: Optional[str] = None):
        self.base_url = (base_url or os.getenv("HEAVEN_JIRA_URL") or "").rstrip("/")
        self.user = user or os.getenv("HEAVEN_JIRA_USER") or ""
        self.token = token or os.getenv("HEAVEN_JIRA_TOKEN") or ""
        self.project = project or os.getenv("HEAVEN_JIRA_PROJECT") or ""
        self.issue_type = issue_type or os.getenv("HEAVEN_JIRA_ISSUE_TYPE") or "Bug"

    @property
    def configured(self) -> bool:
        return all([self.base_url, self.user, self.token, self.project])

    async def create_issue(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Create a Jira issue from a finding. Returns {ok, key, url, error}."""
        if not self.configured:
            return {"ok": False, "error": "JiraAlerter not configured"}
        try:
            import aiohttp
        except ImportError:
            return {"ok": False, "error": "aiohttp not installed"}

        # Severity → Jira priority. Jira ships with these names by default;
        # customised projects may have different priority IDs — the API
        # accepts name lookups too.
        sev = (finding.get("severity") or "medium").lower()
        priority = {"critical": "Highest", "high": "High",
                    "medium": "Medium", "low": "Low",
                    "info": "Lowest"}.get(sev, "Medium")

        summary = f"[HEAVEN/{sev}] {finding.get('vuln_type', 'finding')} on {finding.get('target','?')}"
        # Body is Atlassian Document Format (ADF) for v3 issue.create — but
        # v3 also accepts plain text via the `description` shortcut when the
        # field is configured to plain. We use a robust ADF v1 doc.
        description_text = (
            f"Finding ID: {finding.get('id','')}\n"
            f"Target:     {finding.get('target','')}\n"
            f"Severity:   {sev}\n"
            f"Confidence: {finding.get('confidence', 0):.2f}\n"
            f"CVE:        {finding.get('cve_id','—')}\n"
            f"Title:      {finding.get('title','')}\n\n"
            f"Detected by HEAVEN. Open the finding for evidence + curl repro."
        )
        adf = {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph",
                         "content": [{"type": "text", "text": description_text}]}],
        }

        payload = {
            "fields": {
                "project":    {"key": self.project},
                "summary":    summary[:240],
                "description": adf,
                "issuetype":  {"name": self.issue_type},
                "priority":   {"name": priority},
                "labels":     ["heaven", f"heaven-sev-{sev}",
                               f"heaven-vt-{(finding.get('vuln_type') or 'unknown')[:30]}"],
            }
        }

        try:
            auth = aiohttp.BasicAuth(self.user, self.token)
            url = f"{self.base_url}/rest/api/3/issue"
            async with aiohttp.ClientSession(auth=auth) as session:
                async with session.post(
                    url, json=payload,
                    headers={"Accept": "application/json",
                             "Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as r:
                    body = await r.json(content_type=None)
                    if r.status in (200, 201):
                        key = body.get("key", "")
                        logger.info(f"Jira issue created: {key}")
                        return {"ok": True, "key": key,
                                "url": f"{self.base_url}/browse/{key}"}
                    return {"ok": False, "status": r.status,
                            "error": str(body)[:300]}
        except Exception as e:
            logger.error(f"Jira create failed: {e}")
            return {"ok": False, "error": str(e)}


class LinearAlerter:
    """Create Linear issues via the GraphQL API."""

    def __init__(self, token: Optional[str] = None, team_id: Optional[str] = None):
        self.token = token or os.getenv("HEAVEN_LINEAR_TOKEN") or ""
        self.team_id = team_id or os.getenv("HEAVEN_LINEAR_TEAM_ID") or ""

    @property
    def configured(self) -> bool:
        return bool(self.token and self.team_id)

    async def create_issue(self, finding: dict[str, Any]) -> dict[str, Any]:
        if not self.configured:
            return {"ok": False, "error": "LinearAlerter not configured"}
        try:
            import aiohttp
        except ImportError:
            return {"ok": False, "error": "aiohttp not installed"}

        sev = (finding.get("severity") or "medium").lower()
        # Linear priority: 0 = no priority, 1 = urgent, 2 = high, 3 = medium, 4 = low
        priority = {"critical": 1, "high": 2, "medium": 3,
                    "low": 4, "info": 0}.get(sev, 3)

        title = f"[HEAVEN/{sev}] {finding.get('vuln_type','?')} on {finding.get('target','?')}"
        description = (
            f"**Finding ID:** {finding.get('id','')}\n"
            f"**Target:** `{finding.get('target','')}`\n"
            f"**Severity:** {sev}\n"
            f"**Confidence:** {finding.get('confidence', 0):.2f}\n"
            f"**CVE:** {finding.get('cve_id','—')}\n\n"
            f"Detected by HEAVEN. Open the finding evidence for repro details."
        )
        query = """
        mutation IssueCreate($input: IssueCreateInput!) {
          issueCreate(input: $input) {
            success
            issue { id identifier url }
          }
        }
        """
        variables = {
            "input": {
                "teamId": self.team_id,
                "title": title[:240],
                "description": description,
                "priority": priority,
                "labelIds": [],  # operator can configure label mapping
            }
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.linear.app/graphql",
                    json={"query": query, "variables": variables},
                    headers={"Authorization": self.token,
                             "Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as r:
                    body = await r.json()
                    if r.status == 200 and not body.get("errors"):
                        issue = (body.get("data") or {}).get("issueCreate", {}).get("issue", {}) or {}
                        logger.info(f"Linear issue created: {issue.get('identifier')}")
                        return {"ok": True,
                                "key": issue.get("identifier", ""),
                                "url": issue.get("url", "")}
                    return {"ok": False,
                            "status": r.status,
                            "error": str(body.get("errors") or body)[:300]}
        except Exception as e:
            logger.error(f"Linear create failed: {e}")
            return {"ok": False, "error": str(e)}


class TicketingDispatcher:
    """Auto-dispatch findings to whichever ticketing backends are configured.

    Usage:
        d = TicketingDispatcher()
        if d.has_any:
            for f in critical_findings:
                await d.dispatch(f)
    """

    def __init__(self):
        self.jira = JiraAlerter()
        self.linear = LinearAlerter()

    @property
    def has_any(self) -> bool:
        return self.jira.configured or self.linear.configured

    @property
    def configured_backends(self) -> list[str]:
        out = []
        if self.jira.configured:
            out.append("jira")
        if self.linear.configured:
            out.append("linear")
        return out

    async def dispatch(self, finding: dict[str, Any]) -> dict[str, dict]:
        """Push one finding to every configured backend. Returns per-backend result."""
        out: dict[str, dict] = {}
        if self.jira.configured:
            out["jira"] = await self.jira.create_issue(finding)
        if self.linear.configured:
            out["linear"] = await self.linear.create_issue(finding)
        return out

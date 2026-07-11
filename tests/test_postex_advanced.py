"""Tests for HEAVEN's advanced post-exploitation engine.

The SSH runners are exercised only through their *pure parsers* (``parse_*``),
which take canned command/file output — so these tests need no live host and no
``asyncssh``. The session/auth gating and the redaction guarantee are tested
directly.
"""

from __future__ import annotations

import asyncio
import json

from heaven.postex import gtfobins, mitre_attack as mitre
from heaven.postex.enum_engine import parse_enumeration
from heaven.postex.loot import parse_loot, redact
from heaven.postex.session import PostExReport, PostExSession, build_kill_chain


# ── MITRE tagging ────────────────────────────────────────────────────────────
def test_mitre_tag_attaches_techniques_and_tactics():
    f: dict = {"title": "x", "evidence": {}}
    mitre.tag(f, mitre.T_SUID, mitre.T_CREDS_IN_FILES)
    assert f["mitre"]["techniques"][0]["id"] == "T1548.001"
    assert "Privilege Escalation" in f["mitre"]["tactics"]
    assert "Credential Access" in f["mitre"]["tactics"]
    # evidence carries the ids for the DB
    assert "T1548.001" in f["evidence"]["mitre_techniques"]


def test_mitre_describe_base_technique_fallback():
    # sub-technique id falls back to its base when uncatalogued
    d = mitre.describe("T1548.001")
    assert d["id"] == "T1548.001"
    assert d["url"].endswith("/T1548/001/")


# ── GTFOBins lookup ──────────────────────────────────────────────────────────
def test_gtfobins_version_aware_lookup():
    assert gtfobins.lookup("/usr/bin/python3.10").name == "python3"
    assert gtfobins.lookup("vim.basic").name == "vim"
    assert gtfobins.lookup("find").suid is True
    assert gtfobins.lookup("nonexistent") is None
    assert gtfobins.is_privesc("/usr/bin/find", "sudo") is True
    assert gtfobins.is_privesc("passwd", "suid") is False  # not in catalog


# ── Enumeration parser ───────────────────────────────────────────────────────
def _enum_outputs() -> dict:
    return {
        "id": "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy),999(docker)\n"
              "::GROUPS::\ndeploy docker",
        "os": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"',
        "kernel": "Linux web01 5.15.0-88-generic x86_64",
        "hostname": "web01",
        "sudo": "    (root) NOPASSWD: /usr/bin/find",
        "suid": "/usr/bin/find\n/usr/bin/passwd\n/usr/bin/pkexec",
        "caps": "/usr/bin/python3.10 = cap_setuid+ep",
        "sensitive_perms": "-rw-rw-rw- 1 root root 2801 /etc/passwd",
        "docker_sock": "srw-rw---- 1 root docker 0 /var/run/docker.sock",
        "path_writable": "WRITABLE_PATH:/usr/local/bin",
        "cron": "",
        "users": "root:x:0:0::/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash",
        "net_listen": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
        "net_iface": "2: eth0    inet 10.0.5.12/24",
        "nfs": "",
    }


def test_enum_parses_facts():
    r = parse_enumeration("10.0.5.12", "deploy", _enum_outputs())
    assert r.success
    assert r.facts.hostname == "web01"
    assert r.facts.os == "Ubuntu 22.04.3 LTS"
    assert r.facts.kernel == "5.15.0"
    assert r.facts.uid == 1000
    assert r.facts.is_root is False
    assert "docker" in r.facts.groups
    assert 22 in r.facts.listening_ports
    assert "10.0.5.12" in r.facts.interfaces


def test_enum_detects_critical_vectors():
    r = parse_enumeration("10.0.5.12", "deploy", _enum_outputs())
    titles = [v["title"] for v in r.vectors]
    assert any("docker" in t.lower() for t in titles)         # container escape
    assert any("NOPASSWD" in t for t in titles)               # sudo find
    assert any("/etc/passwd is writable" in t for t in titles)
    assert any("docker.sock" in t for t in titles)
    # deterministic GTFOBins SUID is high-confidence
    find_vec = next(v for v in r.vectors if v["title"] == "SUID GTFOBins binary: find")
    assert find_vec["confidence"] >= 0.9
    # pkexec is a hint → needs manual confirm
    pk = next(v for v in r.vectors if "pkexec" in v["title"])
    assert pk["needs_manual_confirm"] is True


def test_enum_root_user_reports_no_escalation():
    outs = _enum_outputs()
    outs["id"] = "uid=0(root) gid=0(root) groups=0(root)\n::GROUPS::\nroot"
    r = parse_enumeration("10.0.5.12", "root", outs)
    assert r.facts.is_root is True
    assert r.vectors == []  # already root — nothing to escalate


def test_enum_findings_are_mitre_tagged():
    r = parse_enumeration("10.0.5.12", "deploy", _enum_outputs())
    findings = r.to_findings()
    assert findings
    assert all(f["vuln_type"] == "privesc" for f in findings)
    assert any(f.get("mitre", {}).get("techniques") for f in findings)


# ── Loot parser + redaction ──────────────────────────────────────────────────
def _loot_outputs() -> dict:
    return {
        "ssh_keys": "KEY:/root/.ssh/id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----",
        "aws": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
               "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "gcloud": "", "azure": "",
        "kube": "server: https://10.0.0.1:6443\ntoken: eyJhbGciOiJSUzI1NiIsuperlongtoken",
        "docker": '{"auths":{"reg":{"auth":"dXNlcjpwYXNz"}}}',
        "netrc": "machine github.com login bot password ghp_verysecrettoken",
        "pgpass": "db.internal:5432:app:appuser:PgSecret2024",
        "git_creds": "https://ci:glpat-token123@gitlab.internal",
        "env_files": "ENVFILE:/app/.env\nDB_PASSWORD=Sup3rDbP@ss\nAPI_KEY=sk_live_xyz",
        "history": "sshpass -p H0stPass ubuntu@10.0.0.9 uptime",
        "app_configs": "",
    }


def test_loot_extracts_items_and_credentials():
    r = parse_loot("10.0.5.12", "deploy", _loot_outputs())
    cats = {i.category for i in r.items}
    assert "aws_credentials" in cats
    assert "ssh_private_key" in cats
    assert "pgpass" in cats
    assert "netrc" in cats
    creds = r.harvested_credentials()
    users = {u for u, _ in creds}
    assert "appuser" in users        # pgpass
    assert "bot" in users            # netrc
    assert "ubuntu" in users         # sshpass history


def test_loot_ssh_hint_filter():
    r = parse_loot("h", "u", _loot_outputs())
    ssh_creds = r.harvested_credentials(service_hint="ssh")
    # pgpass (postgres) filtered out; sshpass (ssh) + netrc (hintless) kept
    hosts = {u for u, _ in ssh_creds}
    assert "ubuntu" in hosts
    assert "appuser" not in hosts


def test_loot_redaction_never_leaks_plaintext():
    r = parse_loot("10.0.5.12", "deploy", _loot_outputs())
    serialized = json.dumps(r.to_dict()) + json.dumps(r.to_findings())
    for secret in ("wJalrXUtnFEMI", "PgSecret2024", "ghp_verysecrettoken",
                   "Sup3rDbP@ss", "glpat-token123", "H0stPass"):
        assert secret not in serialized, f"plaintext {secret!r} leaked!"


def test_redact_helper():
    assert redact("") == ""
    assert redact("abc") == "•••"
    assert redact("AKIAIOSFODNN7EXAMPLE").startswith("AKI")
    assert "…" in redact("AKIAIOSFODNN7EXAMPLE")


# ── Kill chain ───────────────────────────────────────────────────────────────
def test_build_kill_chain_orders_by_tactic():
    findings = []
    f1: dict = {"title": "loot", "evidence": {}}
    mitre.tag(f1, mitre.T_CREDS_IN_FILES)
    f2: dict = {"title": "privesc", "evidence": {}}
    mitre.tag(f2, mitre.T_SUID)
    findings = [f1, f2]
    chain = build_kill_chain(findings)
    tactics = [step["tactic"] for step in chain]
    # Privilege Escalation precedes Credential Access in ATT&CK order
    assert tactics.index("Privilege Escalation") < tactics.index("Credential Access")


# ── Session gating ───────────────────────────────────────────────────────────
def test_session_requires_authorization():
    s = PostExSession("10.0.0.5", "deploy", password="x", authorized=False)
    rep = asyncio.run(s.run_full_postex())
    assert rep.success is False
    assert "not authorized" in rep.error


def test_report_never_serializes_reusable_credentials():
    rep = PostExReport("h", "u", True)
    rep.reusable_credentials = [("root", "TopSecretPlaintext")]
    d = json.dumps(rep.to_dict())
    assert "TopSecretPlaintext" not in d
    assert "reusable_credentials" not in d


def test_reusable_credentials_survive_leak_vectors():
    """The sanctioned serializers redact; the reflection-based ones must too.

    Because ``reusable_credentials`` is deliberately NOT a dataclass field,
    every reflection-based serializer (``dataclasses.asdict``, ``fields``,
    default ``repr``) must be blind to the plaintext. The property is the only
    legitimate access path.
    """
    import dataclasses
    rep = PostExReport("h", "u", True)
    rep.reusable_credentials = [("root", "PlaintextSecret42")]

    # 1. dataclasses.asdict — the classic serialization footgun.
    d = dataclasses.asdict(rep)
    assert "reusable_credentials" not in d
    assert "_reusable_credentials" not in d
    assert "PlaintextSecret42" not in json.dumps(d)

    # 2. dataclasses.fields — reflection over declared fields.
    field_names = {f.name for f in dataclasses.fields(rep)}
    assert "reusable_credentials" not in field_names

    # 3. Default repr() / str() — auto-generated dataclass repr should not
    #    include the plaintext-carrying attribute at all; our override redacts.
    assert "PlaintextSecret42" not in repr(rep)
    assert "PlaintextSecret42" not in str(rep)
    assert "redacted" in repr(rep)

    # 4. Property still returns the value (defensive copy — caller mutation
    #    can't poison the in-memory record).
    creds = rep.reusable_credentials
    creds.append(("evil", "MutateAttempt"))
    assert rep.reusable_credentials == [("root", "PlaintextSecret42")]

    # 5. wipe_secrets() clears the in-memory copy.
    rep.wipe_secrets()
    assert rep.reusable_credentials == []


def test_loot_item_survives_leak_vectors():
    """Same guarantee at the LootItem layer."""
    import dataclasses
    from heaven.postex.loot import LootItem

    item = LootItem(category="pgpass", path="~/.pgpass",
                    secret_preview="user:Pg…24@db")
    item.credentials.append(("user", "PgPlaintextSecretXYZ", "postgres"))

    # dataclasses.asdict never surfaces the plaintext
    d = dataclasses.asdict(item)
    assert "PgPlaintextSecretXYZ" not in json.dumps(d)
    assert "credentials" not in d

    # dataclasses.fields does not declare `credentials`
    field_names = {f.name for f in dataclasses.fields(item)}
    assert "credentials" not in field_names

    # repr / str redact
    assert "PgPlaintextSecretXYZ" not in repr(item)
    assert "PgPlaintextSecretXYZ" not in str(item)
    assert "redacted" in repr(item)

    # to_dict remains redacted (unchanged contract)
    dd = item.to_dict()
    assert "PgPlaintextSecretXYZ" not in json.dumps(dd)
    assert dd["credential_count"] == 1
    assert dd["credential_users"] == ["user"]

    # wipe_secrets clears the in-memory copy
    item.wipe_secrets()
    assert item.credentials == []
    assert item.to_dict()["credential_count"] == 0


def test_loot_result_wipes_all_items():
    from heaven.postex.loot import LootItem, LootResult

    item = LootItem(category="aws_credentials")
    item.credentials.append(("AKIA…", "SecretShouldVanish", "aws"))
    r = LootResult(host="h", user="u", success=True, items=[item])
    assert len(r.harvested_credentials()) == 1
    r.wipe_secrets()
    assert r.harvested_credentials() == []
    # And repr does not leak either
    assert "SecretShouldVanish" not in repr(r)


def test_session_ai_gated_without_key(monkeypatch):
    # No provider configured → available_ai is False, playbook still runs enum.
    from heaven.ai import llm_gateway
    monkeypatch.setattr(llm_gateway.LLMGateway, "available", property(lambda self: False))
    s = PostExSession("h", "u", password="x", authorized=True)
    assert s.available_ai is False

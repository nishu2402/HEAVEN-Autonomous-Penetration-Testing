"""Dependency-confusion auditor — offline, deterministic.

Every test stubs the registry/OSV network seams, so nothing here touches the
real npm/PyPI/etc. endpoints. The behaviours pinned are exactly the
false-positive guards the module promises: definitive-404-only, local-name
suppression, unknown-is-silent (offline-safe), ecosystem scoping, and
signal-graded severity.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from heaven.vulnscan import dep_confusion as dc
from heaven.vulnscan.osv_client import Package


# ── fakes ────────────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status: int):
        self.status_code = status


class _Session:
    """Minimal async stand-in for httpx.AsyncClient: URL-substring → status."""

    def __init__(self, mapping: dict[str, int], raise_on: set[str] | None = None):
        self.mapping = mapping
        self.raise_on = raise_on or set()
        self.calls: list[str] = []

    async def get(self, url: str, headers=None):
        self.calls.append(url)
        for frag in self.raise_on:
            if frag in url:
                raise RuntimeError("network down")
        for frag, status in self.mapping.items():
            if frag in url:
                return _Resp(status)
        return _Resp(404)


class _StubExistsClient:
    """A RegistryClient replacement that answers from a dict (name → bool/None)."""

    available = True
    timeout = 5.0

    def __init__(self, answers: dict[str, object]):
        self.answers = answers

    async def exists(self, session, name, ecosystem):
        return self.answers.get(name)


def _run(coro):
    return asyncio.run(coro)


# ── RegistryClient.exists: status → tri-state, caching, encoding ─────────────

def test_registry_exists_status_mapping():
    client = dc.RegistryClient()
    sess = _Session({"present-pkg": 200, "gone-pkg": 404, "rl-pkg": 429})
    assert _run(client.exists(sess, "present-pkg", "PyPI")) is True
    assert _run(client.exists(sess, "gone-pkg", "PyPI")) is False
    # 429 / 5xx / 403 are inconclusive → None, never a (false) "absent".
    assert _run(client.exists(sess, "rl-pkg", "PyPI")) is None


def test_registry_exists_network_error_is_unknown():
    client = dc.RegistryClient()
    sess = _Session({}, raise_on={"boom-pkg"})
    assert _run(client.exists(sess, "boom-pkg", "npm")) is None


def test_registry_exists_unsupported_ecosystem_is_none():
    client = dc.RegistryClient()
    sess = _Session({"x": 404})
    assert _run(client.exists(sess, "github.com/a/b", "Go")) is None
    assert _run(client.exists(sess, "g:a", "Maven")) is None


def test_registry_exists_is_memoised():
    client = dc.RegistryClient()
    sess = _Session({"dup": 404})
    assert _run(client.exists(sess, "dup", "PyPI")) is False
    assert _run(client.exists(sess, "dup", "PyPI")) is False  # served from cache
    assert len(sess.calls) == 1                                # one physical GET


def test_registry_scoped_npm_url_encoding():
    client = dc.RegistryClient()
    sess = _Session({"registry.npmjs.org": 404})
    _run(client.exists(sess, "@acme/secret", "npm"))
    url = sess.calls[0]
    assert "registry.npmjs.org/@acme%2Fsecret" in url


def test_registry_nuget_lowercases_and_packagist_keeps_slash():
    client = dc.RegistryClient()
    sess = _Session({"api.nuget.org": 404, "repo.packagist.org": 404})
    _run(client.exists(sess, "MyCompany.Secret", "NuGet"))
    _run(client.exists(sess, "acme/secret", "Packagist"))
    nuget = next(u for u in sess.calls if "nuget" in u)
    packagist = next(u for u in sess.calls if "packagist" in u)
    assert "mycompany.secret" in nuget                 # lowercased
    assert "repo.packagist.org/p2/acme/secret.json" in packagist  # slash kept


# ── audit_packages: FP guards ────────────────────────────────────────────────

def _audit(pkgs, **kw):
    kw.setdefault("http", object())
    return _run(dc.audit_packages(pkgs, **kw))


def test_present_package_yields_no_finding():
    pkgs = [Package("requests", "2.31.0", "PyPI", "requirements.txt")]
    out = _audit(pkgs, client=_StubExistsClient({"requests": True}))
    assert out == []


def test_absent_package_is_flagged_medium_without_signal():
    pkgs = [Package("acme-internal", "1.0.0", "PyPI", "requirements.txt")]
    out = _audit(pkgs, client=_StubExistsClient({"acme-internal": False}))
    assert len(out) == 1
    f = out[0]
    assert f["vuln_type"] == "dependency_confusion"
    assert f["severity"] == "medium"
    assert f["confidence"] == 0.6
    assert f["cwe"] == "CWE-427"
    assert f["owasp"].startswith("A03:2025")
    assert f["evidence"]["registry_status"] == 404
    assert "public_registry_absent" in f["evidence"]["signals"]
    # medium band vector is internally consistent
    assert f["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    assert f["cvss"] == 6.5
    assert "404" in f["evidence"]["proof"]


def test_unknown_result_is_silent_offline_safe():
    # None (network error / rate-limit) must never fabricate a finding.
    pkgs = [Package("maybe-gone", "1.0.0", "npm", "package.json")]
    out = _audit(pkgs, client=_StubExistsClient({"maybe-gone": None}))
    assert out == []


def test_local_name_is_suppressed():
    pkgs = [Package("@acme/ui", "1.0.0", "npm", "package.json")]
    out = _audit(pkgs, client=_StubExistsClient({"@acme/ui": False}),
                 local_names=frozenset({"@acme/ui"}))
    assert out == []


def test_non_checkable_ecosystem_is_skipped():
    pkgs = [
        Package("github.com/x/y", "1.0.0", "Go", "go.mod"),
        Package("org:artifact", "1.0.0", "Maven", "pom.xml"),
    ]
    # exists() would never even be consulted; result is empty.
    out = _audit(pkgs, client=_StubExistsClient({}))
    assert out == []


def test_private_registry_signal_escalates_to_high():
    pkgs = [Package("acme-internal", "1.0.0", "PyPI", "requirements.txt")]
    out = _audit(pkgs, client=_StubExistsClient({"acme-internal": False}),
                 private_registry=True,
                 private_registry_signals=["npmrc_private_registry"])
    assert len(out) == 1
    f = out[0]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.85
    assert "npmrc_private_registry" in f["evidence"]["signals"]
    assert f["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    assert f["cvss"] == 8.1


def test_scoped_package_records_scope_signal():
    pkgs = [Package("@acme/secret", "1.0.0", "npm", "package.json")]
    out = _audit(pkgs, client=_StubExistsClient({"@acme/secret": False}))
    assert any(s == "scoped_package:@acme" for s in out[0]["evidence"]["signals"])


def test_httpx_absent_returns_empty(monkeypatch):
    monkeypatch.setattr(dc, "httpx", None)
    pkgs = [Package("acme-internal", "1.0.0", "PyPI", "requirements.txt")]
    # real RegistryClient → available False → no findings, no crash
    out = _run(dc.audit_packages(pkgs, client=dc.RegistryClient(), http=object()))
    assert out == []


def test_audit_with_real_client_and_fake_session():
    # Exercise the real RegistryClient.exists over a fake HTTP session end-to-end.
    pkgs = [
        Package("real-pkg", "1.0.0", "PyPI", "requirements.txt"),   # 200 → skip
        Package("ghost-pkg", "1.0.0", "PyPI", "requirements.txt"),  # 404 → flag
    ]
    sess = _Session({"real-pkg/json": 200, "ghost-pkg/json": 404})
    out = _run(dc.audit_packages(pkgs, client=dc.RegistryClient(), http=sess))
    assert [f["evidence"]["package"] for f in out] == ["ghost-pkg"]


# ── collect_local_signals ────────────────────────────────────────────────────

def test_collect_local_signals_names_and_private_registry(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "@acme/root", "dependencies": {"@acme/ui": "1.0.0"}}))
    (tmp_path / ".npmrc").write_text(
        "@acme:registry=https://npm.internal.acme/\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "acme-svc"\n')
    (tmp_path / "setup.cfg").write_text("[metadata]\nname = acme-legacy\n")
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "acme-rs"\n')
    (tmp_path / "x.gemspec").write_text('Gem::Specification.new do |s|\n  s.name = "acme_gem"\nend\n')
    # workspace sub-package + a node_modules dir that must be ignored
    sub = tmp_path / "packages" / "ui"
    sub.mkdir(parents=True)
    (sub / "package.json").write_text(json.dumps({"name": "@acme/ui"}))
    nm = tmp_path / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"name": "third-party"}))

    sig = dc.collect_local_signals(str(tmp_path))
    names = sig["local_names"]
    assert {"@acme/root", "@acme/ui", "acme-svc", "acme-legacy",
            "acme-rs", "acme_gem"} <= names
    assert "third-party" not in names          # node_modules skipped
    assert sig["private_registry"] is True
    assert "npmrc_private_registry" in sig["signals"]


def test_collect_local_signals_no_private_registry(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "plain-app"}))
    sig = dc.collect_local_signals(str(tmp_path))
    assert sig["private_registry"] is False
    assert sig["signals"] == []


def test_collect_local_signals_pip_conf_and_poetry_source(tmp_path):
    (tmp_path / "pip.conf").write_text(
        "[global]\nindex-url = https://pypi.internal/simple\n")
    (tmp_path / "pyproject.toml").write_text(
        '[[tool.poetry.source]]\nname = "internal"\nurl = "https://pypi.internal/"\n')
    sig = dc.collect_local_signals(str(tmp_path))
    assert sig["private_registry"] is True
    assert "pip_index_url" in sig["signals"]
    assert "poetry_private_source" in sig["signals"]


def test_collect_local_signals_missing_path_is_safe(tmp_path):
    sig = dc.collect_local_signals(str(tmp_path / "does-not-exist"))
    assert sig["local_names"] == frozenset()
    assert sig["private_registry"] is False


# ── scan_path integration (dep-confusion wired into SCA) ─────────────────────

def test_scan_path_merges_confusion_findings(monkeypatch, tmp_path):
    from heaven.vulnscan import sca_scanner

    (tmp_path / "requirements.txt").write_text("acme-ext-lib==1.0.0\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "acme-service"\n')
    (tmp_path / "pip.conf").write_text(
        "[global]\nindex-url = https://pypi.internal/simple\n")

    async def _fake_exists(self, session, name, ecosystem):
        return False                      # everything 404 → claimable

    monkeypatch.setattr(dc.RegistryClient, "exists", _fake_exists)

    class _FakeOSV:
        available = True

        async def query(self, packages):
            return []                     # no vulnerable-dependency findings

    res = _run(sca_scanner.scan_path(str(tmp_path), client=_FakeOSV()))
    confusion = [f for f in res["findings"]
                 if f["vuln_type"] == "dependency_confusion"]
    assert len(confusion) == 1
    f = confusion[0]
    assert f["evidence"]["package"] == "acme-ext-lib"
    assert f["severity"] == "high"        # pip.conf private feed present
    assert res["summary"]["dependency_confusion"] == 1


def test_scan_path_confusion_can_be_disabled(monkeypatch, tmp_path):
    from heaven.vulnscan import sca_scanner

    (tmp_path / "requirements.txt").write_text("acme-ext-lib==1.0.0\n")

    async def _fake_exists(self, session, name, ecosystem):
        return False

    monkeypatch.setattr(dc.RegistryClient, "exists", _fake_exists)

    class _FakeOSV:
        available = True

        async def query(self, packages):
            return []

    res = _run(sca_scanner.scan_path(
        str(tmp_path), client=_FakeOSV(), check_confusion=False))
    assert res["summary"]["dependency_confusion"] == 0
    assert not any(f["vuln_type"] == "dependency_confusion"
                   for f in res["findings"])


def test_scan_path_local_dependency_not_flagged(monkeypatch, tmp_path):
    # A monorepo: the dependency IS a locally-defined package → suppressed even
    # though it 404s on the public registry.
    from heaven.vulnscan import sca_scanner

    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "@acme/root", "dependencies": {"@acme/ui": "1.0.0"}}))
    sub = tmp_path / "packages" / "ui"
    sub.mkdir(parents=True)
    (sub / "package.json").write_text(json.dumps(
        {"name": "@acme/ui", "version": "1.0.0"}))

    async def _fake_exists(self, session, name, ecosystem):
        return False

    monkeypatch.setattr(dc.RegistryClient, "exists", _fake_exists)

    class _FakeOSV:
        available = True

        async def query(self, packages):
            return []

    res = _run(sca_scanner.scan_path(str(tmp_path), client=_FakeOSV()))
    assert res["summary"]["dependency_confusion"] == 0

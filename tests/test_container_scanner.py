"""Container scanner precision: a 200 on a k8s/docker/etcd path is only a
finding when the body is genuinely that service.

The remote probes used to raise a *critical* on ``status == 200`` alone — the
``/api/v1/secrets`` check did not even parse the body — so a non-Kubernetes host
answering 200 on the probed path manufactured a bogus "Cluster Secrets
Accessible". The kube-apiserver and kubelet always stamp ``kind`` on a list
response, and Docker/etcd ``/version`` always carry their signature field, so the
scanner now gates on that. These tests drive the probes with a scripted
aiohttp-style session (no live cluster needed).
"""
from __future__ import annotations

import asyncio
import json as _json
from contextlib import asynccontextmanager

import heaven.recon.container_scanner as cs
from heaven.recon.container_scanner import DockerScanner, KubernetesScanner


class _Resp:
    def __init__(self, status: int, body: str = "", headers: dict | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors="replace"):
        return self._body

    async def json(self, content_type=None):
        return _json.loads(self._body)  # raises on non-JSON, like aiohttp


class _Session:
    """Returns a scripted response for each requested URL via ``route(url)``."""

    def __init__(self, route):
        self._route = route

    def get(self, url, **kwargs):
        return self._route(url)


def _patch_session(monkeypatch, route) -> None:
    @asynccontextmanager
    async def _fake_cs(*a, **k):
        yield _Session(route)

    monkeypatch.setattr(cs, "_egress_cs", _fake_cs)


def _run(coro):
    return asyncio.run(coro)


# ── k8s: a non-cluster host answering 200 must not raise criticals ───────────

def test_k8s_non_cluster_200_json_raises_no_findings(monkeypatch):
    # Every probed path answers 200 with valid-but-unrelated JSON. None of it is
    # a real NamespaceList / SecretList / PodList, so nothing must be reported.
    def route(url):
        return _Resp(200, '{"ok": true}')

    _patch_session(monkeypatch, route)
    findings = _run(KubernetesScanner.check_api_server("10.0.0.5", 6443))
    assert findings == [], [f.vuln_type for f in findings]


def test_k8s_secrets_non_json_200_not_flagged(monkeypatch):
    # /api/v1/secrets answers 200 but with an HTML body (a catch-all proxy):
    # the old code flagged this critical on status alone; it must not now.
    def route(url):
        if url.endswith("/api/v1/secrets"):
            return _Resp(200, "<html>hello</html>")
        return _Resp(404, "nope")

    _patch_session(monkeypatch, route)
    findings = _run(KubernetesScanner.check_api_server("10.0.0.5", 6443))
    assert not any(f.vuln_type == "k8s_secrets_exposed" for f in findings)


def test_k8s_real_apiserver_flags_anon_and_secrets(monkeypatch):
    # A real anonymous apiserver returns properly-kinded list resources.
    def route(url):
        if url.endswith("/api/v1/namespaces") and ":6443" in url:
            return _Resp(200, '{"kind":"NamespaceList","apiVersion":"v1","items":[{},{}]}')
        if url.endswith("/api/v1/secrets"):
            return _Resp(200, '{"kind":"SecretList","apiVersion":"v1","items":[{}]}')
        return _Resp(404, "not found")

    _patch_session(monkeypatch, route)
    types = {f.vuln_type for f in _run(KubernetesScanner.check_api_server("10.0.0.5", 6443))}
    assert "k8s_anon_auth" in types
    assert "k8s_secrets_exposed" in types


# ── docker: /version must actually be Docker's ───────────────────────────────

def test_docker_api_non_docker_200_not_flagged(monkeypatch):
    def route(url):
        return _Resp(200, '{"service":"not-docker"}')  # valid JSON, no ApiVersion

    _patch_session(monkeypatch, route)
    findings = _run(DockerScanner.check_docker_socket("10.0.0.5", is_local=False))
    assert not any(f.vuln_type == "docker_api_exposed" for f in findings)


def test_docker_api_real_version_flagged(monkeypatch):
    def route(url):
        if url.endswith("/version"):
            return _Resp(200, '{"Version":"24.0.7","ApiVersion":"1.43"}')
        return _Resp(404, "")

    _patch_session(monkeypatch, route)
    findings = _run(DockerScanner.check_docker_socket("10.0.0.5", is_local=False))
    assert any(f.vuln_type == "docker_api_exposed" for f in findings)
    f = next(f for f in findings if f.vuln_type == "docker_api_exposed")
    assert f.evidence["api"] == "1.43"

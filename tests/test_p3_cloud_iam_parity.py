"""P3 — Multi-cloud authenticated IAM/RBAC parity (GCP + Azure to match AWS).

HEAVEN already audited the authenticated AWS identity. P3 brings GCP and Azure to
parity:

* **GCP** — reads the project IAM policy and flags public bindings
  (allUsers/allAuthenticatedUsers) and primitive Owner/Editor grants;
* **Azure** — reads subscription-scope RBAC and flags Owner / Contributor /
  User Access Administrator assignments and legacy classic administrators.

All read-only. The GCP path is exercised end-to-end with a monkeypatched google
SDK; the Azure RBAC logic is exercised via the pure RBAC helper with a mock
management client, plus graceful-degradation checks on the dispatcher for both
the SDK-absent and the credential-less paths.
"""
from __future__ import annotations

import sys
import types


from heaven.devsecops.vuln_kb import enrich_finding
from heaven.recon.cloud_iam import (
    _azure_rbac_findings,
    _gcp_iam_policy_findings,
    audit_cloud_iam,
    audit_gcp_iam,
)


# ── GCP: pure IAM-policy analysis ────────────────────────────────────────────

def test_gcp_public_binding_flagged():
    policy = {"bindings": [
        {"role": "roles/viewer", "members": ["allUsers"]},
    ]}
    out = _gcp_iam_policy_findings(policy, "my-proj")
    assert len(out) == 1
    assert out[0]["vuln_type"] == "cloud_iam_public_access"
    assert out[0]["severity"] == "high"
    assert "allUsers" in out[0]["evidence_members"]


def test_gcp_primitive_owner_flagged():
    policy = {"bindings": [
        {"role": "roles/owner", "members": ["user:a@x.com", "user:b@x.com"]},
    ]}
    out = _gcp_iam_policy_findings(policy, "my-proj")
    assert len(out) == 1
    assert out[0]["vuln_type"] == "cloud_iam_overprivileged"
    assert out[0]["evidence_member_count"] == 2


def test_gcp_public_primitive_binding_yields_both():
    policy = {"bindings": [
        {"role": "roles/editor", "members": ["allAuthenticatedUsers", "user:a@x.com"]},
    ]}
    kinds = sorted(f["vuln_type"] for f in _gcp_iam_policy_findings(policy, "p"))
    assert kinds == ["cloud_iam_overprivileged", "cloud_iam_public_access"]


def test_gcp_least_privilege_policy_is_silent():
    policy = {"bindings": [
        {"role": "roles/run.invoker", "members": ["user:svc@x.com"]},
        {"role": "roles/storage.objectViewer", "members": ["serviceAccount:s@x.iam"]},
    ]}
    assert _gcp_iam_policy_findings(policy, "p") == []


# ── GCP: full audit path with a monkeypatched google SDK ─────────────────────

def _install_mock_google(monkeypatch, *, project, policy, sa_email=None):
    import google.auth  # real module present in this env

    class _Creds:
        service_account_email = sa_email

    monkeypatch.setattr(google.auth, "default",
                        lambda scopes=None: (_Creds(), project))

    class _Req:
        def __init__(self, resp):
            self._resp = resp

        def execute(self):
            return self._resp

    class _Projects:
        def getIamPolicy(self, resource, body):  # noqa: N802 — mirrors google API
            return _Req(policy)

    class _CRM:
        def projects(self):
            return _Projects()

    import googleapiclient.discovery as disc
    monkeypatch.setattr(disc, "build",
                        lambda *a, **k: _CRM())


def test_audit_gcp_iam_end_to_end(monkeypatch):
    _install_mock_google(
        monkeypatch, project="prod-proj", sa_email="ci@prod.iam.gserviceaccount.com",
        policy={"bindings": [
            {"role": "roles/owner", "members": ["allUsers", "user:admin@x.com"]}]})
    res = audit_gcp_iam()
    assert res["authenticated"] is True
    assert res["project"] == "prod-proj"
    assert res["principal_type"] == "service_account"
    vts = {f["vuln_type"] for f in res["findings"]}
    assert "cloud_iam_authenticated" in vts
    assert "cloud_iam_public_access" in vts and "cloud_iam_overprivileged" in vts


def test_audit_gcp_iam_clean_project(monkeypatch):
    _install_mock_google(monkeypatch, project="p",
                         policy={"bindings": [
                             {"role": "roles/viewer", "members": ["user:a@x.com"]}]})
    res = audit_gcp_iam()
    issues = [f for f in res["findings"] if f["vuln_type"] != "cloud_iam_authenticated"]
    assert res["authenticated"] and issues == []


# ── Azure: pure RBAC analysis via a mock management client ────────────────────

def _mock_azure_client(assignments, role_defs, classic=()):
    def _obj(**kw):
        return types.SimpleNamespace(**kw)

    class _RoleDefs:
        def list(self, scope):
            return [_obj(name=guid, role_name=nm) for guid, nm in role_defs.items()]

    class _RoleAssignments:
        def list_for_subscription(self):
            return [_obj(role_definition_id=rid, scope=sc) for rid, sc in assignments]

    class _Classic:
        def list(self):
            return list(classic)

    return types.SimpleNamespace(
        role_definitions=_RoleDefs(),
        role_assignments=_RoleAssignments(),
        classic_administrators=_Classic())


def test_azure_owner_at_subscription_flagged():
    sub = "0000-sub"
    defs = {"gd-owner": "Owner", "gd-reader": "Reader"}
    assigns = [
        (f"/subscriptions/{sub}/providers/.../gd-owner", f"/subscriptions/{sub}"),
        (f"/subscriptions/{sub}/providers/.../gd-reader", f"/subscriptions/{sub}"),
    ]
    out = _azure_rbac_findings(_mock_azure_client(assigns, defs), sub)
    assert len(out) == 1
    assert out[0]["vuln_type"] == "cloud_iam_overprivileged"
    assert out[0]["severity"] == "high"
    assert out[0]["evidence_role"] == "Owner"


def test_azure_classic_admins_flagged():
    sub = "s"
    client = _mock_azure_client([], {}, classic=[object(), object()])
    out = _azure_rbac_findings(client, sub)
    assert len(out) == 1 and out[0]["evidence_classic_admin_count"] == 2


def test_azure_reader_only_is_silent():
    sub = "s"
    defs = {"gd-reader": "Reader"}
    assigns = [(f"/subscriptions/{sub}/providers/.../gd-reader", f"/subscriptions/{sub}")]
    assert _azure_rbac_findings(_mock_azure_client(assigns, defs), sub) == []


# ── dispatcher + graceful degradation ────────────────────────────────────────

def test_dispatcher_unknown_provider():
    r = audit_cloud_iam("digitalocean")
    assert r["authenticated"] is False and "unknown provider" in r["skipped_reason"]


def test_dispatcher_azure_without_sdk_is_graceful(monkeypatch):
    # Simulate the optional azure SDK being absent (it lives in the [cloud-azure]
    # extra) → honest skip, never a crash. Forcing the module to None makes the
    # in-function `from azure.identity import ...` raise ImportError regardless of
    # whether the SDK happens to be installed in this environment.
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    r = audit_cloud_iam("azure")
    assert r["authenticated"] is False
    assert "azure SDK not installed" in r["skipped_reason"]
    assert r["provider"] == "azure"


def test_dispatcher_azure_without_credentials_is_graceful(monkeypatch):
    # SDK present but no usable credentials: the token probe fails, so the audit
    # degrades to authenticated=False with an honest reason — and never emits a
    # false "authenticated to Azure" finding (no overclaim).
    import azure.identity

    def _no_creds(*_a, **_k):
        raise RuntimeError("no Azure credentials configured")

    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", _no_creds)
    r = audit_cloud_iam("azure")
    assert r["authenticated"] is False
    assert r["provider"] == "azure"
    assert "no valid Azure credentials" in r["skipped_reason"]
    assert r["findings"] == []


# ── taxonomy ─────────────────────────────────────────────────────────────────

def test_public_access_taxonomy_complete():
    f = enrich_finding({"vuln_type": "cloud_iam_public_access", "severity": "high"})
    assert f["cwe"].startswith("CWE-")
    assert "Broken Access Control" in f["owasp"]
    assert f["cvss_vector"].startswith("CVSS:3.1/")

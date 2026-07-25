"""Tests for the authenticated AWS IAM privilege audit (heaven/recon/cloud_iam).

Every path is exercised with in-process fakes — no real AWS calls, no network,
no credentials. Confirms: the pure policy analysers, caller-identity parsing,
graceful behaviour without credentials, provable finding generation for a weak
identity, near-zero false positives for a hardened identity, and that every
finding enriches to complete OWASP-2025 taxonomy.
"""

from __future__ import annotations

import datetime

import pytest

from heaven.recon import cloud_iam as ci
from heaven.devsecops.vuln_kb import enrich_finding

_NOW = datetime.datetime.now(datetime.timezone.utc)


# ── Pure policy analysers ────────────────────────────────────────────────────

def test_statement_is_admin_true_only_for_unconditional_wildcard():
    assert ci._statement_is_admin({"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert ci._statement_is_admin(
        {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]})
    # Scoped action / resource is not admin.
    assert not ci._statement_is_admin(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    # A Deny is never an admin grant.
    assert not ci._statement_is_admin({"Effect": "Deny", "Action": "*", "Resource": "*"})
    # A Condition meaningfully restricts the grant.
    assert not ci._statement_is_admin(
        {"Effect": "Allow", "Action": "*", "Resource": "*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})


def test_policy_doc_is_admin_handles_single_and_list_statements():
    assert ci._policy_doc_is_admin(
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    assert ci._policy_doc_is_admin({"Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert not ci._policy_doc_is_admin({"Statement": []})
    assert not ci._policy_doc_is_admin("not a dict")


# ── Caller identity parsing ──────────────────────────────────────────────────

class _STS:
    def __init__(self, arn):
        self._arn = arn

    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": self._arn, "UserId": "AIDAEXAMPLE"}


class _STSFails:
    def get_caller_identity(self):
        raise RuntimeError("Unable to locate credentials")


@pytest.mark.parametrize("arn,expected", [
    ("arn:aws:iam::123456789012:user/Alice", "user"),
    ("arn:aws:sts::123456789012:assumed-role/DeployRole/session", "role"),
    ("arn:aws:iam::123456789012:root", "root"),
])
def test_caller_identity_principal_type(arn, expected):
    ident = ci.caller_identity(_STS(arn))
    assert ident["account"] == "123456789012"
    assert ident["principal_type"] == expected


def test_caller_identity_empty_on_failure():
    assert ci.caller_identity(_STSFails()) == {}


# ── Fake IAM clients + session injection ─────────────────────────────────────

class _FakeSession:
    """A boto3-session stand-in whose ``client()`` returns our fakes."""
    def __init__(self, sts, iam, **_):
        self._sts, self._iam = sts, iam

    def client(self, svc):
        return self._sts if svc == "sts" else self._iam


def _patch_session(monkeypatch, sts, iam):
    import boto3
    monkeypatch.setattr(
        boto3.session, "Session",
        lambda **kw: _FakeSession(sts, iam, **kw))


class _WeakIAM:
    """An account/identity riddled with issues — every check should fire."""
    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": [
            {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
             "PolicyName": "AdministratorAccess"}]}

    def list_user_policies(self, UserName):
        return {"PolicyNames": []}

    def get_user_policy(self, **k):
        return {"PolicyDocument": {}}

    def get_login_profile(self, UserName):
        return {"LoginProfile": {"UserName": UserName}}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA1234567890ABCD", "Status": "Active",
             "CreateDate": _NOW - datetime.timedelta(days=400)}]}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountAccessKeysPresent": 1}}

    def get_account_password_policy(self):
        raise RuntimeError("NoSuchEntity: password policy does not exist")


class _HardenedIAM:
    """A least-privileged, well-configured identity — no issues should fire."""
    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": [
            {"PolicyArn": "arn:aws:iam::123456789012:policy/ReadOnlyScoped",
             "PolicyName": "ReadOnlyScoped"}]}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::app-bucket/*"}]}}}

    def list_user_policies(self, UserName):
        return {"PolicyNames": []}

    def get_user_policy(self, **k):
        return {"PolicyDocument": {}}

    def get_login_profile(self, UserName):
        raise RuntimeError("NoSuchEntity: no login profile (no console access)")

    def list_mfa_devices(self, UserName):
        return {"MFADevices": [{"SerialNumber": "arn:aws:iam::...:mfa/Alice"}]}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIAFRESH0000000000", "Status": "Active",
             "CreateDate": _NOW - datetime.timedelta(days=5)}]}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountAccessKeysPresent": 0}}

    def get_account_password_policy(self):
        return {"PasswordPolicy": {
            "MinimumPasswordLength": 16, "MaxPasswordAge": 90,
            "RequireSymbols": True, "RequireNumbers": True}}


# ── Graceful behaviour without credentials ───────────────────────────────────

def test_no_credentials_is_graceful(monkeypatch):
    _patch_session(monkeypatch, _STSFails(), _WeakIAM())
    res = ci.audit_aws_iam()
    assert res["authenticated"] is False
    assert res["findings"] == []
    assert "skipped_reason" in res


# ── A weak identity yields the full, provable finding set ────────────────────

def test_weak_identity_produces_all_findings(monkeypatch):
    _patch_session(monkeypatch, _STS("arn:aws:iam::123456789012:user/Alice"),
                   _WeakIAM())
    res = ci.audit_aws_iam()
    assert res["authenticated"] is True
    assert res["account"] == "123456789012"
    types = {f["vuln_type"] for f in res["findings"]}
    assert {
        "cloud_iam_authenticated",
        "cloud_iam_overprivileged",
        "cloud_iam_no_mfa",
        "cloud_iam_stale_access_key",
        "cloud_iam_root_access_keys",
        "cloud_iam_weak_password_policy",
    } <= types
    # The over-privilege finding names the offending policy (provable evidence).
    over = next(f for f in res["findings"]
                if f["vuln_type"] == "cloud_iam_overprivileged")
    assert "AdministratorAccess" in over["evidence_policies"]
    assert over["severity"] == "high"


# ── A hardened identity yields no issue findings (near-zero FP) ──────────────

def test_hardened_identity_has_no_issue_findings(monkeypatch):
    _patch_session(monkeypatch, _STS("arn:aws:iam::123456789012:user/Bob"),
                   _HardenedIAM())
    res = ci.audit_aws_iam()
    assert res["authenticated"] is True
    issues = [f for f in res["findings"]
              if f["vuln_type"] != "cloud_iam_authenticated"]
    assert issues == [], f"hardened identity should produce no issues, got {issues}"


# ── Every finding enriches to complete OWASP-2025 taxonomy ───────────────────

def test_iam_findings_enrich_to_2025_taxonomy(monkeypatch):
    _patch_session(monkeypatch, _STS("arn:aws:iam::123456789012:user/Alice"),
                   _WeakIAM())
    res = ci.audit_aws_iam()
    by_type = {f["vuln_type"]: enrich_finding(f) for f in res["findings"]}
    for vt, e in by_type.items():
        assert e.get("cwe"), vt
        assert e.get("owasp", "").endswith(("2025",)) or ":2025" in e.get("owasp", ""), vt
        assert e.get("mitre_technique"), vt
    # Privilege issues map to Broken Access Control; credential hygiene to Auth.
    assert "A01:2025" in by_type["cloud_iam_overprivileged"]["owasp"]
    assert "A07:2025" in by_type["cloud_iam_no_mfa"]["owasp"]

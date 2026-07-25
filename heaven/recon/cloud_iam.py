"""HEAVEN — Authenticated AWS IAM privilege audit (read-only).

When valid AWS credentials are supplied (via the **standard AWS credential
chain** — ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` env vars, a shared
``~/.aws/credentials`` profile, or an instance/role), this audits the *identity*
you are authenticated as, from the inside:

  • Who am I?         — STS ``GetCallerIdentity`` (account, ARN, principal type)
  • What can I do?    — the caller's attached / inline IAM policy documents,
                        flagged when they grant ``*:*`` (full administrator)
  • Account hygiene   — root access keys present, weak / missing password
                        policy, users without MFA, stale access keys

Everything here is **strictly READ-ONLY** — STS ``GetCallerIdentity`` plus IAM
``List*`` / ``Get*``. HEAVEN never reads or logs the secret key: boto3 resolves
it from the environment, and only the (non-secret) account id / ARN is ever
surfaced. A least-privileged key returns few or no findings — the desired
outcome — because every finding fires only on **positive evidence** (a policy
that literally grants ``*``/``*``, a console user with zero MFA devices, an
access key past its rotation window), so false positives are near zero. Every
IAM call is wrapped so a key with partial read permissions still yields partial
results (an ``AccessDenied`` is skipped, never fatal).

The module is import-safe without boto3 (the AWS SDK is an optional runtime
dependency); ``audit_aws_iam`` then returns an empty, ``authenticated=False``
result rather than raising.
"""

from __future__ import annotations

import datetime
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.cloud_iam")

# A managed policy whose name/ARN is one of these is administrator-equivalent
# without needing to fetch and parse its document.
_ADMIN_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

# Access-key rotation windows (days). Past ``_KEY_STALE_DAYS`` is worth flagging;
# past ``_KEY_VERY_STALE_DAYS`` is escalated a severity band.
_KEY_STALE_DAYS = 90
_KEY_VERY_STALE_DAYS = 180
# NIST-aligned minimum console-password length; shorter is a weak policy.
_MIN_PW_LENGTH = 14


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _age_days(when: Any) -> Optional[int]:
    """Whole days between ``when`` (a tz-aware datetime) and now, or None."""
    if not isinstance(when, datetime.datetime):
        return None
    ref = when if when.tzinfo else when.replace(tzinfo=datetime.timezone.utc)
    return max(0, (_now_utc() - ref).days)


def _as_list(value: Any) -> list[str]:
    """Normalise a JSON string-or-list field to a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _statement_is_admin(stmt: dict) -> bool:
    """True when a single IAM policy statement grants full ``*`` action on ``*``
    resources with ``Effect: Allow`` (and no restricting Condition)."""
    if not isinstance(stmt, dict):
        return False
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    if stmt.get("Condition"):
        # A condition (MFA, source-IP, …) meaningfully restricts the grant, so a
        # conditional wildcard is not treated as unrestricted admin.
        return False
    actions = [a.strip() for a in _as_list(stmt.get("Action"))]
    resources = [r.strip() for r in _as_list(stmt.get("Resource"))]
    return "*" in actions and "*" in resources


def _policy_doc_is_admin(document: Any) -> bool:
    """True when a policy document contains any administrator (``*``/``*``)
    Allow statement. ``document`` is the decoded JSON dict boto3 returns."""
    if not isinstance(document, dict):
        return False
    stmts = document.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return False
    return any(_statement_is_admin(s) for s in stmts)


def _finding(vuln_type: str, severity: str, title: str, target: str,
             description: str, impact: str = "", remediation: str = "",
             **extra: Any) -> dict:
    """Assemble a HEAVEN finding dict; taxonomy (CWE/OWASP/MITRE/CVSS) is filled
    downstream by ``vuln_kb.enrich_finding`` from the ``vuln_type``."""
    ev: dict[str, Any] = {"description": description}
    if impact:
        ev["impact"] = impact
    if remediation:
        ev["remediation"] = remediation
    f = {
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "target": target,
        "confidence": 0.95,
        "evidence": ev,
        "source": "cloud_iam",
    }
    f.update(extra)
    return f


def caller_identity(sts_client: Any) -> dict[str, str]:
    """STS ``GetCallerIdentity`` → ``{account, arn, user_id, principal_type,
    principal_name}``, or ``{}`` when the call fails (invalid / absent creds)."""
    try:
        resp = sts_client.get_caller_identity()
    except Exception as e:  # noqa: BLE001 — any failure means "not authenticated"
        logger.debug("STS GetCallerIdentity failed: %s", e)
        return {}
    arn = str(resp.get("Arn", ""))
    # arn:aws:iam::123456789012:user/Alice   → user / Alice
    # arn:aws:sts::123456789012:assumed-role/Role/Sess → role / Role
    # arn:aws:iam::123456789012:root         → root / root
    principal_type, principal_name = "unknown", ""
    tail = arn.rsplit(":", 1)[-1] if ":" in arn else arn
    if tail == "root":
        principal_type, principal_name = "root", "root"
    elif tail.startswith("user/"):
        principal_type, principal_name = "user", tail.split("/", 1)[1]
    elif tail.startswith("assumed-role/") or tail.startswith("role/"):
        principal_type = "role"
        parts = tail.split("/")
        principal_name = parts[1] if len(parts) > 1 else ""
    return {
        "account": str(resp.get("Account", "")),
        "arn": arn,
        "user_id": str(resp.get("UserId", "")),
        "principal_type": principal_type,
        "principal_name": principal_name,
    }


def _attached_admin_policies(iam: Any, list_fn: Any, get_doc_for: Any,
                             **list_kwargs: Any) -> list[str]:
    """Return the names of attached managed policies that grant administrator.

    ``list_fn`` is e.g. ``iam.list_attached_user_policies``; ``get_doc_for`` maps
    a policy ARN → its default-version document (or None). Well-known AWS admin
    policies are matched by ARN without a document fetch."""
    admin: list[str] = []
    try:
        resp = list_fn(**list_kwargs)
    except Exception as e:  # noqa: BLE001
        logger.debug("list attached policies failed: %s", e)
        return admin
    for pol in resp.get("AttachedPolicies", []):
        arn, name = str(pol.get("PolicyArn", "")), str(pol.get("PolicyName", ""))
        if arn in _ADMIN_MANAGED or name in ("AdministratorAccess", "IAMFullAccess"):
            admin.append(name or arn)
            continue
        doc = get_doc_for(arn)
        if doc is not None and _policy_doc_is_admin(doc):
            admin.append(name or arn)
    return admin


def _managed_policy_doc(iam: Any, arn: str) -> Optional[dict]:
    """Fetch a managed policy's default-version document (read-only), or None."""
    try:
        ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver)
        return doc["PolicyVersion"]["Document"]  # boto3 decodes to a dict
    except Exception as e:  # noqa: BLE001
        logger.debug("get_policy_version failed for %s: %s", arn, e)
        return None


def _inline_admin_policies(iam: Any, list_fn: Any, get_fn: Any,
                           doc_key: str, **kwargs: Any) -> list[str]:
    """Names of inline policies (user/role) whose document grants administrator."""
    admin: list[str] = []
    try:
        names = list_fn(**kwargs).get("PolicyNames", [])
    except Exception as e:  # noqa: BLE001
        logger.debug("list inline policies failed: %s", e)
        return admin
    for name in names:
        try:
            doc = get_fn(PolicyName=name, **kwargs).get(doc_key)
        except Exception as e:  # noqa: BLE001
            logger.debug("get inline policy %s failed: %s", name, e)
            continue
        if _policy_doc_is_admin(doc):
            admin.append(str(name))
    return admin


def _audit_user_privileges(iam: Any, user: str, account: str,
                           arn: str) -> list[dict]:
    """Over-privilege (admin) findings for an IAM *user* principal."""
    findings: list[dict] = []
    target = f"aws:{account}:user/{user}"

    def _doc_for(policy_arn: str) -> Optional[dict]:
        return _managed_policy_doc(iam, policy_arn)

    admin = _attached_admin_policies(
        iam, iam.list_attached_user_policies, _doc_for, UserName=user)
    admin += _inline_admin_policies(
        iam, iam.list_user_policies, iam.get_user_policy,
        "PolicyDocument", UserName=user)
    if admin:
        pol = ", ".join(sorted(set(admin)))
        findings.append(_finding(
            "cloud_iam_overprivileged", "high",
            f"IAM user '{user}' has administrator-equivalent privileges", target,
            f"The authenticated IAM user '{user}' ({arn}) is granted "
            f"administrator-equivalent access through: {pol}. At least one policy "
            f"allows every action (Action \"*\") on every resource (Resource "
            f"\"*\") without a restricting condition.",
            impact="A compromise of this identity's credentials yields full "
                   "control of the AWS account — every service, every resource.",
            remediation=(
                "1. Replace the administrator grant with a least-privilege policy "
                "scoped to only the actions and resources this identity needs. "
                "2. Require MFA for any privileged action via an aws:MultiFactorAuthPresent "
                "condition. "
                "3. Prefer short-lived role assumption over long-lived user keys "
                "for administrative tasks."),
            evidence_policies=sorted(set(admin))))
    return findings


def _audit_role_privileges(iam: Any, role: str, account: str,
                           arn: str) -> list[dict]:
    """Over-privilege (admin) findings for an IAM *role* principal."""
    findings: list[dict] = []
    target = f"aws:{account}:role/{role}"

    def _doc_for(policy_arn: str) -> Optional[dict]:
        return _managed_policy_doc(iam, policy_arn)

    admin = _attached_admin_policies(
        iam, iam.list_attached_role_policies, _doc_for, RoleName=role)
    admin += _inline_admin_policies(
        iam, iam.list_role_policies, iam.get_role_policy,
        "PolicyDocument", RoleName=role)
    if admin:
        pol = ", ".join(sorted(set(admin)))
        findings.append(_finding(
            "cloud_iam_overprivileged", "high",
            f"IAM role '{role}' has administrator-equivalent privileges", target,
            f"The assumed IAM role '{role}' ({arn}) grants administrator-equivalent "
            f"access through: {pol} (an Allow of Action \"*\" on Resource \"*\").",
            impact="Any principal able to assume this role gains full control of "
                   "the AWS account.",
            remediation=(
                "1. Scope the role's policies to least privilege. "
                "2. Tighten the role's trust policy so only intended principals "
                "can assume it. "
                "3. Add an aws:MultiFactorAuthPresent / external-id condition where "
                "the role is human-assumable."),
            evidence_policies=sorted(set(admin))))
    return findings


def _audit_user_hygiene(iam: Any, user: str, account: str) -> list[dict]:
    """MFA + access-key-rotation findings for an IAM user."""
    findings: list[dict] = []
    target = f"aws:{account}:user/{user}"

    # No MFA on a console-enabled user.
    has_console = False
    try:
        iam.get_login_profile(UserName=user)
        has_console = True
    except Exception:  # noqa: BLE001 — NoSuchEntity == no console access
        has_console = False
    if has_console:
        try:
            devices = iam.list_mfa_devices(UserName=user).get("MFADevices", [])
        except Exception as e:  # noqa: BLE001
            logger.debug("list_mfa_devices failed: %s", e)
            devices = [{"_unknown": True}]  # avoid a false "no MFA" on AccessDenied
        if not devices:
            findings.append(_finding(
                "cloud_iam_no_mfa", "medium",
                f"IAM user '{user}' has console access without MFA", target,
                f"IAM user '{user}' can sign in to the AWS console (a login "
                f"profile exists) but has no MFA device registered.",
                impact="A stolen or phished console password is sufficient to "
                       "authenticate — there is no second factor.",
                remediation="Enforce MFA for all console users and add an IAM "
                            "policy that denies actions unless "
                            "aws:MultiFactorAuthPresent is true."))

    # Stale / unrotated access keys.
    try:
        keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
    except Exception as e:  # noqa: BLE001
        logger.debug("list_access_keys failed: %s", e)
        keys = []
    for k in keys:
        if str(k.get("Status")) != "Active":
            continue
        age = _age_days(k.get("CreateDate"))
        if age is None or age < _KEY_STALE_DAYS:
            continue
        key_id = str(k.get("AccessKeyId", ""))
        masked = f"…{key_id[-4:]}" if len(key_id) >= 4 else key_id
        sev = "medium" if age >= _KEY_VERY_STALE_DAYS else "low"
        findings.append(_finding(
            "cloud_iam_stale_access_key", sev,
            f"IAM user '{user}' has an access key {age} days old", target,
            f"Active access key {masked} for IAM user '{user}' was created "
            f"{age} days ago and has not been rotated (rotation window: "
            f"{_KEY_STALE_DAYS} days).",
            impact="Long-lived static credentials widen the exposure window if "
                   "the key is leaked in code, logs, or a backup.",
            remediation="Rotate the key: create a new one, update consumers, then "
                        "deactivate and delete the old key. Prefer short-lived "
                        "role credentials over static user keys."))
    return findings


def _audit_account(iam: Any, account: str) -> list[dict]:
    """Account-wide IAM hygiene: root access keys + password policy. Each check
    is best-effort — a caller without account-read permission simply gets fewer
    findings, never an error."""
    findings: list[dict] = []
    target = f"aws:{account}"

    # Root account access keys present.
    try:
        summ = iam.get_account_summary().get("SummaryMap", {})
        if int(summ.get("AccountAccessKeysPresent", 0)) > 0:
            findings.append(_finding(
                "cloud_iam_root_access_keys", "high",
                "AWS root account has active access keys", target,
                "The AWS account root user has one or more access keys. Root "
                "keys grant unrestricted, unconditional access and cannot be "
                "scoped by IAM policy.",
                impact="A leaked root key is a full, unrecoverable account "
                       "compromise — root cannot be restricted by IAM.",
                remediation="Delete all root access keys. Perform routine work "
                            "with least-privileged IAM roles/users and reserve "
                            "root for the few tasks that require it (with MFA)."))
    except Exception as e:  # noqa: BLE001
        logger.debug("get_account_summary failed: %s", e)

    # Password policy: missing or weak.
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        weak: list[str] = []
        if int(policy.get("MinimumPasswordLength", 0)) < _MIN_PW_LENGTH:
            weak.append(f"minimum length {policy.get('MinimumPasswordLength', 0)} "
                        f"(< {_MIN_PW_LENGTH})")
        if not policy.get("MaxPasswordAge"):
            weak.append("no maximum password age (passwords never expire)")
        if not policy.get("RequireSymbols") or not policy.get("RequireNumbers"):
            weak.append("does not require both symbols and numbers")
        if weak:
            findings.append(_finding(
                "cloud_iam_weak_password_policy", "medium",
                "AWS account password policy is weak", target,
                "The account IAM password policy is weaker than recommended: "
                + "; ".join(weak) + ".",
                impact="Weak console passwords are easier to brute-force or guess.",
                remediation="Set a password policy with a 14+ character minimum, "
                            "complexity requirements, rotation, and reuse "
                            "prevention."))
    except Exception as e:  # noqa: BLE001 — NoSuchEntity == no custom policy at all
        msg = str(e)
        if "NoSuchEntity" in msg or "not set" in msg.lower():
            findings.append(_finding(
                "cloud_iam_weak_password_policy", "medium",
                "AWS account has no IAM password policy", target,
                "No IAM account password policy is configured, so console "
                "passwords are governed only by AWS defaults.",
                impact="No enforced minimum length, complexity, rotation, or "
                       "reuse prevention for console users.",
                remediation="Configure an IAM password policy (14+ character "
                            "minimum, complexity, rotation, reuse prevention)."))
        else:
            logger.debug("get_account_password_policy failed: %s", e)
    return findings


def audit_aws_iam(profile: Optional[str] = None,
                  region: Optional[str] = None) -> dict[str, Any]:
    """Read-only IAM privilege audit of the currently-authenticated AWS identity.

    Credentials come from the standard AWS chain (env vars / shared profile /
    instance role); pass ``profile`` to select a named profile. Returns a dict
    ``{authenticated, account, arn, principal_type, findings, ...}``. Never
    raises: an absent SDK or absent/invalid credentials yields
    ``authenticated=False`` with an empty ``findings`` list.
    """
    result: dict[str, Any] = {
        "authenticated": False, "findings": [], "account": "", "arn": "",
        "principal_type": "", "provider": "aws",
    }
    try:
        import boto3  # optional runtime dependency (base install ships it)
    except Exception:  # noqa: BLE001
        result["skipped_reason"] = "boto3 not installed"
        return result

    try:
        session = boto3.session.Session(
            profile_name=profile, region_name=region or "us-east-1")
        ident = caller_identity(session.client("sts"))
    except Exception as e:  # noqa: BLE001
        logger.debug("AWS session/STS init failed: %s", e)
        result["skipped_reason"] = "no valid AWS credentials"
        return result

    if not ident.get("account"):
        result["skipped_reason"] = "no valid AWS credentials"
        return result

    account, arn = ident["account"], ident["arn"]
    ptype, pname = ident["principal_type"], ident["principal_name"]
    result.update(authenticated=True, account=account, arn=arn,
                  principal_type=ptype)
    logger.info("AWS IAM audit authenticated to account %s (%s)", account, ptype)

    findings: list[dict] = [_finding(
        "cloud_iam_authenticated", "info",
        f"Authenticated to AWS account {account}", f"aws:{account}",
        f"Valid AWS credentials authenticate as {arn} (principal type: {ptype}) "
        f"in account {account}. This maps the identity surface reachable with the "
        f"supplied key; the checks below assess its privilege and hygiene.",
        impact="", remediation="",
        cloud_account=account, cloud_principal=arn)]

    iam = session.client("iam")
    if ptype == "user" and pname:
        findings += _audit_user_privileges(iam, pname, account, arn)
        findings += _audit_user_hygiene(iam, pname, account)
    elif ptype == "role" and pname:
        findings += _audit_role_privileges(iam, pname, account, arn)
    # Account-wide hygiene (best-effort; skipped silently without permission).
    findings += _audit_account(iam, account)

    result["findings"] = findings
    result["total"] = len(findings)
    return result


async def recon_aws_iam(profile: Optional[str] = None,
                        region: Optional[str] = None, **_: Any) -> dict[str, Any]:
    """Async wrapper (runs the blocking boto3 audit in a worker thread) so the
    orchestrator can schedule it alongside the other RECON tasks."""
    import asyncio
    return await asyncio.to_thread(audit_aws_iam, profile, region)


__all__ = [
    "audit_aws_iam", "recon_aws_iam", "caller_identity",
    "_policy_doc_is_admin", "_statement_is_admin",
]

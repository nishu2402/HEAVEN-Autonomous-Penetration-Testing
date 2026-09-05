"""K8s RBAC over-privilege classification — the FP-safe core of analyze_rbac.

The old analyzer only counted ServiceAccount cluster-admins and only fired at
>3, so the single most dangerous RBAC misconfiguration — cluster-admin bound to
system:anonymous / system:unauthenticated (a User/Group, not a ServiceAccount) —
was missed entirely. These tests lock the corrected behaviour AND the crucial
false-positive boundary: the legitimate break-glass group system:masters must
never be flagged.
"""

from __future__ import annotations

from heaven.recon.container_scanner import KubernetesScanner


def _assess(bindings):
    return KubernetesScanner._assess_cluster_admin_bindings(bindings)


def test_anonymous_cluster_admin_is_flagged():
    dangerous, sa = _assess([
        ("heaven-anon", [("User", "system:anonymous", ""),
                         ("Group", "system:unauthenticated", "")]),
    ])
    principals = {d["principal"] for d in dangerous}
    assert principals == {"system:anonymous", "system:unauthenticated"}
    assert sa == []


def test_all_authenticated_admin_is_flagged():
    dangerous, _ = _assess([("x", [("Group", "system:authenticated", "")])])
    assert dangerous and dangerous[0]["principal"] == "system:authenticated"


def test_system_masters_is_not_a_false_positive():
    # The built-in cluster-admin binding grants system:masters — legitimate.
    dangerous, sa = _assess([
        ("cluster-admin", [("Group", "system:masters", "")]),
    ])
    assert dangerous == []
    assert sa == []


def test_service_account_sprawl_is_separate_signal():
    dangerous, sa = _assess([
        ("b1", [("ServiceAccount", "deployer", "ci")]),
        ("b2", [("ServiceAccount", "robot", "prod")]),
    ])
    assert dangerous == []
    assert sa == ["ci/deployer", "prod/robot"]


def test_mixed_binding_flags_only_the_dangerous_principal():
    dangerous, sa = _assess([
        ("mix", [("Group", "system:masters", ""),
                 ("User", "system:anonymous", ""),
                 ("ServiceAccount", "admin", "kube-system")]),
    ])
    assert [d["principal"] for d in dangerous] == ["system:anonymous"]
    assert sa == ["kube-system/admin"]

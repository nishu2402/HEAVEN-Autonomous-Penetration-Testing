"""The in-house remediation knowledge base must cover every detected class and
give real guidance with no LLM configured (HEAVEN's default, offline path)."""
from __future__ import annotations

import pytest

from heaven.devsecops import vuln_kb as kb


@pytest.mark.parametrize("emitted,canonical_title", [
    ("sqli", "SQL Injection"),
    ("sqli_confirmed", "SQL Injection"),
    ("cmdi", "OS Command Injection"),
    ("lfi", "File Inclusion (LFI/RFI)"),
    ("rfi", "File Inclusion (LFI/RFI)"),
    ("cors", "CORS Misconfiguration"),
    ("cors_misconfig", "CORS Misconfiguration"),
    ("security_headers", "Missing Security Headers"),
    ("jwt_alg_none", "JWT Accepts alg:none"),
    ("jwt_weak_secret", "JWT Signed With a Weak Secret"),
    ("xxe", "XML External Entity (XXE) Injection"),
    ("insecure_cookie", "Insecure Session Cookie"),
    ("open_redirect", "Open Redirect"),
    ("ssrf", "Server-Side Request Forgery"),
])
def test_every_detected_type_resolves(emitted, canonical_title):
    entry = kb.lookup(emitted)
    assert entry.get("title") == canonical_title
    # a real entry always carries actionable remediation + a reference
    assert entry.get("remediation")
    assert entry.get("references")


def test_remediation_text_is_structured_and_specific():
    txt = kb.remediation_text({
        "vuln_type": "jwt_weak_secret", "target": "http://h/login",
        "title": "JWT signed with a weak secret",
    })
    assert "## How to fix it" in txt
    assert "## Impact" in txt
    assert "http://h/login" in txt
    assert "asymmetric" in txt.lower()  # a concrete, class-specific instruction


def test_remediation_text_unknown_class_still_actionable():
    txt = kb.remediation_text({"vuln_type": "some_novel_thing", "severity": "high"})
    # not a bare one-liner — the standard drill with numbered steps
    assert "1." in txt and "2." in txt
    assert "Apply standard security patches for this vulnerability." not in txt


def test_ai_remediation_offline_uses_kb_not_generic_string():
    from heaven.devsecops.ai_remediation import AIRemediationEngine
    eng = AIRemediationEngine()
    eng.available = False  # force the in-house (no-LLM) path deterministically
    out = eng.generate_patch({"vuln_type": "xxe", "target": "http://h/x", "title": "XXE"})
    assert "## How to fix it" in out
    assert "external entity" in out.lower()
    assert out != "Apply standard security patches for this vulnerability."

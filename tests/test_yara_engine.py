"""Tests for the malware / webshell signature engine (heaven/vulnscan/yara_engine).

Deterministic and offline. The builtin matcher is always exercised (yara-python
is optional in CI); every sample is a real, well-known malicious pattern or a
clearly-benign control, so both recall and the false-positive floor are proven.
"""

from __future__ import annotations

from heaven.vulnscan import yara_engine as Y


def _rules(matches):
    return {m.rule for m in matches}


def test_named_php_webshell_detected():
    body = "<?php /* WSO 2.5 web shell by orb */ echo 'FilesMan'; ?>"
    hits = Y.scan_bytes(body)
    assert "PHP_Webshell_Named" in _rules(hits)
    assert Y.worst_severity(hits) == "critical"


def test_generic_eval_superglobal_shell_detected():
    # A one-liner backdoor the fixed named-signature list would miss.
    body = "<?php system($_GET['cmd']); ?>"
    assert "PHP_Webshell_Eval_Superglobal" in _rules(Y.scan_bytes(body))


def test_obfuscated_loader_detected():
    body = "<?php eval(gzinflate(base64_decode('H4sIA...'))); ?>"
    assert "PHP_Obfuscated_Loader" in _rules(Y.scan_bytes(body))


def test_china_chopper_detected():
    body = "<?php @eval($_POST['x']); ?>"
    rules = _rules(Y.scan_bytes(body))
    assert "China_Chopper" in rules or "PHP_Webshell_Eval_Superglobal" in rules


def test_jsp_webshell_detected():
    body = ('<% Runtime.getRuntime().exec(request.getParameter("c")); %>')
    assert "JSP_Webshell" in _rules(Y.scan_bytes(body))


def test_benign_content_has_no_critical_match():
    body = ("<?php\n// A normal controller.\n"
            "function index($request) { return view('home', ['user' => $request]); }\n?>")
    hits = [m for m in Y.scan_bytes(body) if m.severity in ("critical", "high")]
    assert hits == [], hits


def test_high_entropy_blob_is_informational_only():
    import base64
    import os
    blob = base64.b64encode(os.urandom(400)).decode()
    body = f"const data = '{blob}';"
    hits = Y.scan_bytes(body)
    sev = {m.rule: m.severity for m in hits}
    # A random blob is at most informational — never critical/high on its own.
    assert all(v == "info" for v in sev.values()), sev


def test_scan_file_roundtrips(tmp_path):
    p = tmp_path / "shell.php"
    p.write_text("<?php passthru($_REQUEST['q']); ?>")
    assert "PHP_Webshell_Eval_Superglobal" in _rules(Y.scan_file(str(p)))
    assert Y.scan_file(str(tmp_path / "missing.php")) == []


def test_engine_label_is_honest():
    # Whatever backend fired, the match names it; builtin is always available.
    hits = Y.scan_bytes("<?php eval($_POST['a']); ?>")
    assert hits and all(m.engine in ("yara", "builtin") for m in hits)
    # yara_available() must be a bool and must not raise regardless of install.
    assert isinstance(Y.yara_available(), bool)

"""Tests for the dependency-free native SAST engine."""

from __future__ import annotations

from heaven.vulnscan.native_sast import run_native_sast, scan_text


def test_python_findings():
    code = (
        "import hashlib, pickle, random, subprocess, yaml, requests\n"
        "def f(uid):\n"
        "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n"
        "    subprocess.run('ping ' + uid, shell=True)\n"
        "    token = random.randint(0, 9)\n"
        "    hashlib.md5(b'x')\n"
        "    pickle.loads(uid)\n"
        "    yaml.load(uid)\n"
        "    requests.get(uid, verify=False)\n"
    )
    vts = {f.rule_id.split(".")[-1] for f in scan_text("a.py", code)}
    assert "py-sql-injection" in vts
    assert "py-command-injection" in vts
    assert "py-pickle-load" in vts
    assert "py-yaml-load" in vts
    assert "py-tls-verify-off" in vts
    assert "py-weak-hash" in vts


def test_php_findings():
    code = ("<?php\n"
            "system('ls ' . $_GET['d']);\n"
            "include($_GET['p']);\n"
            "echo $_REQUEST['m'];\n")
    fs = scan_text("x.php", code)
    vts = {f.rule_id.split(".")[-1] for f in fs}
    assert "php-command-injection" in vts
    assert "php-file-inclusion" in vts
    assert "php-xss-echo" in vts
    # command injection with request source is critical
    assert any(f.severity == "critical" for f in fs)


def test_java_and_go_findings():
    jv = ('class M { void f(String s) throws Exception {\n'
          '  Runtime.getRuntime().exec("sh " + s);\n'
          '  new ObjectInputStream(in).readObject();\n} }\n')
    gv = ('package main\nimport ("crypto/tls")\n'
          'func f(){ _ = tls.Config{InsecureSkipVerify: true} }\n')
    jvts = {f.rule_id.split(".")[-1] for f in scan_text("M.java", jv)}
    gvts = {f.rule_id.split(".")[-1] for f in scan_text("m.go", gv)}
    assert "java-runtime-exec" in jvts
    assert "java-deserialization" in jvts
    assert "go-tls-insecure" in gvts


def test_hardcoded_secret_detected_and_placeholder_suppressed():
    real = 'password = "S3cr3tP@ssw0rd!"\n'
    placeholder = 'password = "changeme"\n'
    env = 'password = os.environ["PW"]\n'
    assert any(f.rule_id == "heaven.native.hardcoded-secret"
               for f in scan_text("a.py", real))
    assert not any(f.rule_id == "heaven.native.hardcoded-secret"
                   for f in scan_text("a.py", placeholder))
    assert not any(f.rule_id == "heaven.native.hardcoded-secret"
                   for f in scan_text("a.py", env))


def test_interpolated_secret_value_is_not_flagged():
    # A line that *reports* a secret found on a target is not a hardcoded secret:
    # the quoted "value" is an interpolation field, never a literal. Both lines
    # below match the generic-credential shape `secret: '<value>'` yet the value
    # is only a template token — the native scanner's own false positive on
    # advanced_attacks.py (an f-string field) and its %-format sibling.
    for code in (
        "title = f\"JWT Weak Signing Secret: '{cracked_secret}'\"\n",
        "msg = \"api_key='%(api_key_value)s'\"\n",
    ):
        assert not any(f.rule_id == "heaven.native.hardcoded-secret"
                       for f in scan_text("a.py", code)), code
    # …but a real quoted literal in the same shape still flags.
    assert any(f.rule_id == "heaven.native.hardcoded-secret"
               for f in scan_text("a.py", 'password = "S3cr3tP@ssw0rd!"\n'))


def test_weak_hash_guard_on_a_continuation_line_is_honored():
    # A long ``hashlib.md5(...)`` that a formatter (Black/PEP8) wrapped across
    # lines keeps its ``usedforsecurity=False`` guard on a *continuation* line.
    # A strictly per-line ``unless`` check misses it and flags a false weak-hash;
    # the guard must be read against the whole bracketed statement.
    wrapped = (
        "import hashlib\n"
        "def h(x):\n"
        "    return hashlib.md5(\n"
        "        x.encode(),\n"
        "        usedforsecurity=False,\n"
        "    ).hexdigest()\n"
    )
    assert not any(f.rule_id.endswith("py-weak-hash")
                   for f in scan_text("a.py", wrapped))
    # …but an unguarded weak hash still flags, and the classic same-line guard
    # still suppresses — the widened window only removes false positives.
    assert any(f.rule_id.endswith("py-weak-hash")
               for f in scan_text("a.py", "import hashlib\nhashlib.md5(pw.encode())\n"))
    assert not any(f.rule_id.endswith("py-weak-hash") for f in scan_text(
        "a.py", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"))


def test_aws_example_key_suppressed_but_real_flagged():
    # The canonical AWS *example* key must be suppressed as a placeholder.
    assert not any(f.rule_id == "heaven.native.hardcoded-secret"
                   for f in scan_text("a.py", 'k = "AKIAIOSFODNN7EXAMPLE"\n'))
    assert any(f.rule_id == "heaven.native.hardcoded-secret"
               for f in scan_text("a.py", 'k = "AKIA1234567890ABCDEF"\n'))


def test_comment_lines_are_not_flagged():
    assert scan_text("a.py", "# os.system('rm -rf ' + x)\n") == []


def test_run_native_sast_walks_dir(tmp_path):
    (tmp_path / "a.py").write_text("eval(userinput)\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.php").write_text("<?php system($_GET['x']);\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.js").write_text("eval(x)\n")
    r = run_native_sast(str(tmp_path))
    assert r.success
    assert r.files_scanned == 2      # node_modules skipped
    assert any(f.rule_id.endswith("php-command-injection") for f in r.findings)


def test_missing_path_errors():
    r = run_native_sast("/nonexistent/xyz")
    assert not r.success
    assert "path not found" in r.error

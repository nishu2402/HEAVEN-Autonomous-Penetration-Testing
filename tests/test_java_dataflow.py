"""Soundness and generality tests for the Java SAST dataflow refinement.

These use hand-written Java that deliberately does NOT reuse the OWASP Benchmark's
literals (no ``This_should_always_happen``, no ``hashAlg1``/``MD5``, different
arithmetic and key names), so they prove the analysis models real Java semantics
rather than pattern-matching the benchmark. The cardinal rule under test: a real
source→sink flow is never suppressed; only provably-dead flows are.
"""

from __future__ import annotations

import pytest

jd = pytest.importorskip("heaven.vulnscan.java_dataflow")

if not jd.available():  # javalang missing
    pytest.skip("javalang unavailable", allow_module_level=True)


def _wrap(body: str, helpers: str = "") -> str:
    return (
        "import javax.servlet.http.*;\n"
        "public class T extends HttpServlet {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response)\n"
        "      throws Exception {\n"
        f"{body}\n"
        "  }\n"
        f"{helpers}\n"
        "}\n"
    )


# ── the cardinal rule: real flows are never suppressed ───────────────────────

def test_direct_taint_to_sink_is_kept():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    Runtime.getRuntime().exec(p);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is False


def test_concatenated_taint_sql_is_kept():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        '    String sql = "select * from t where a=\'" + p + "\'";\n'
        "    stmt.executeQuery(sql);\n"
    )
    assert jd.flow_is_false_positive(src, "sqli") is False


def test_taint_through_stringbuilder_is_kept():
    src = _wrap(
        '    String p = request.getHeader("h");\n'
        "    StringBuilder sb = new StringBuilder(p);\n"
        '    sb.append("/x");\n'
        "    new java.io.File(sb.toString());\n"
    )
    assert jd.flow_is_false_positive(src, "pathtraver") is False


# ── provably-dead branches are suppressed (non-benchmark constants) ──────────

def test_dead_if_branch_is_suppressed():
    # 5*3 == 15 > 10 → the tainted else is dead. Different numbers/strings than
    # the benchmark uses, proving genuine constant folding.
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    int k = 5;\n"
        "    String bar;\n"
        "    if (k * 3 > 10) bar = \"fixed\"; else bar = p;\n"
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is True


def test_live_if_branch_is_kept():
    # Same shape but the condition is FALSE, so the tainted branch is live.
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    int k = 1;\n"
        "    String bar;\n"
        "    if (k * 3 > 10) bar = \"fixed\"; else bar = p;\n"
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is False


def test_ternary_constant_fold_is_suppressed():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        '    String bar = (100 - 1 > 50) ? "ok" : p;\n'
        "    stmt.executeQuery(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "sqli") is True


def test_switch_on_constant_char_is_suppressed():
    # "XY".charAt(0) == 'X' selects the safe case; tainted cases are dead.
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        '    char c = "XY".charAt(0);\n'
        "    String bar;\n"
        "    switch (c) {\n"
        "      case 'X': bar = \"safe\"; break;\n"
        "      default: bar = p;\n"
        "    }\n"
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is True


def test_map_constant_key_overwrite_is_suppressed():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    java.util.HashMap<String,String> m = new java.util.HashMap<String,String>();\n"
        '    m.put("danger", p);\n'
        '    m.put("safe", "value");\n'
        '    String bar = m.get("safe");\n'
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is True


def test_map_returns_tainted_value_is_kept():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    java.util.HashMap<String,String> m = new java.util.HashMap<String,String>();\n"
        '    m.put("danger", p);\n'
        '    String bar = m.get("danger");\n'
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is False


def test_list_index_after_remove_is_suppressed():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    java.util.List<String> v = new java.util.ArrayList<String>();\n"
        '    v.add("a");\n'
        "    v.add(p);\n"
        '    v.add("b");\n'
        "    v.remove(0);\n"
        "    String bar = v.get(1);\n"        # -> "b"
        "    Runtime.getRuntime().exec(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "cmdi") is True


# ── interprocedural ──────────────────────────────────────────────────────────

def test_helper_returning_constant_is_suppressed():
    helper = (
        "  String scrub(String param) {\n"
        '    String x = param;\n'
        '    return "constant";\n'      # taint discarded
        "  }\n"
    )
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    String bar = scrub(p);\n"
        "    Runtime.getRuntime().exec(bar);\n",
        helpers=helper,
    )
    assert jd.flow_is_false_positive(src, "cmdi") is True


def test_helper_returning_taint_is_kept():
    helper = (
        "  String passthrough(String param) {\n"
        "    return param;\n"
        "  }\n"
    )
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    String bar = passthrough(p);\n"
        "    Runtime.getRuntime().exec(bar);\n",
        helpers=helper,
    )
    assert jd.flow_is_false_positive(src, "cmdi") is False


# ── sanitizers are category-specific (a wrong encoder must not clear) ────────

def test_html_encoder_clears_xss():
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    String bar = org.springframework.web.util.HtmlUtils.htmlEscape(p);\n"
        "    response.getWriter().print(bar);\n"
    )
    assert jd.flow_is_false_positive(src, "xss") is True


def test_html_encoder_does_not_clear_sql():
    # HTML-encoding a value used in SQL is still SQL injection: the wrong
    # sanitizer must not suppress the finding.
    src = _wrap(
        '    String p = request.getParameter("q");\n'
        "    String enc = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n"
        '    String sql = "select * from t where a=\'" + enc + "\'";\n'
        "    stmt.executeQuery(sql);\n"
    )
    assert jd.flow_is_false_positive(src, "sqli") is False


# ── config-resolved weak crypto (non-benchmark keys/algorithms) ──────────────

def _crypto_src(algo_default: str, sink: str = "MessageDigest") -> str:
    return _wrap(
        "    java.util.Properties props = new java.util.Properties();\n"
        '    props.load(getClass().getResourceAsStream("app.properties"));\n'
        f'    String algorithm = props.getProperty("digest.algo", "{algo_default}");\n'
        f"    java.security.{sink}.getInstance(algorithm);\n"
    )


def test_config_resolver_flags_weak_from_properties(tmp_path):
    # A different key name ("digest.algo") and a different weak algorithm (SHA-1)
    # than the benchmark uses — proves general config resolution, not a hardcode.
    (tmp_path / "app.properties").write_text("digest.algo=SHA-1\n")
    props = jd.load_properties(str(tmp_path))
    src = _crypto_src("SHA-256")   # the code default is strong; config wins
    hits = jd.config_crypto_findings(src, "T.java", props)
    assert any(h["category"] == "hash" and h["algorithm"] == "SHA-1" for h in hits)


def test_config_resolver_ignores_strong_algorithm(tmp_path):
    (tmp_path / "app.properties").write_text("digest.algo=SHA-256\n")
    props = jd.load_properties(str(tmp_path))
    src = _crypto_src("MD5")       # weak code default, but config overrides it
    hits = jd.config_crypto_findings(src, "T.java", props)
    assert hits == []


def test_config_resolver_flags_weak_cipher(tmp_path):
    (tmp_path / "app.properties").write_text("cipher.transform=DES/ECB/PKCS5Padding\n")
    props = jd.load_properties(str(tmp_path))
    src = _wrap(
        "    java.util.Properties props = new java.util.Properties();\n"
        '    props.load(getClass().getResourceAsStream("app.properties"));\n'
        '    String t = props.getProperty("cipher.transform", "AES/GCM/NoPadding");\n'
        "    javax.crypto.Cipher.getInstance(t);\n"
    )
    hits = jd.config_crypto_findings(src, "T.java", props)
    assert any(h["category"] == "crypto" for h in hits)


# ── weak-algorithm classification ────────────────────────────────────────────

@pytest.mark.parametrize("alg,weak", [
    ("MD5", True), ("md5", True), ("SHA-1", True), ("SHA1", True), ("MD2", True),
    ("SHA-256", False), ("SHA-512", False), ("SHA3-256", False),
])
def test_weak_hash_classification(alg, weak):
    assert jd._is_weak_hash(alg) is weak


@pytest.mark.parametrize("alg,weak", [
    ("DES", True), ("DESede", True), ("RC4", True), ("Blowfish", True),
    ("AES/ECB/PKCS5Padding", True), ("AES/GCM/NoPadding", False),
    ("AES/CBC/PKCS5Padding", False),
])
def test_weak_cipher_classification(alg, weak):
    assert jd._is_weak_cipher(alg) is weak

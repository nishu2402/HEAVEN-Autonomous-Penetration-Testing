"""Regression tests for the Nuclei JSONL parser.

Guards the fix for the class of bug where a non-object JSON line or a null
``info`` block aborted the whole scan with an AttributeError (the old code
only caught ``json.JSONDecodeError``).
"""

from heaven.vulnscan.nuclei_scanner import _parse_nuclei_output


def _b(*lines: str) -> bytes:
    return "\n".join(lines).encode()


def test_parses_well_formed_line():
    out = _parse_nuclei_output(_b(
        '{"host":"h1","template-id":"cve-x","matched-at":"h1/x",'
        '"info":{"severity":"high","name":"Thing","description":"d"}}'
    ))
    assert len(out) == 1
    f = out[0]
    assert f["target"] == "h1"
    assert f["severity"] == "high"
    assert f["title"] == "Thing"
    assert f["evidence"]["template"] == "cve-x"
    assert f["confidence"] == 0.9


def test_non_object_lines_are_skipped_not_crash():
    # bare string / array / number are valid JSON but not objects
    out = _parse_nuclei_output(_b('"a string"', "[1,2,3]", "42", "true"))
    assert out == []


def test_null_info_does_not_crash():
    out = _parse_nuclei_output(_b('{"host":"h","info":null}'))
    assert len(out) == 1
    assert out[0]["severity"] == "info"          # default when info missing
    assert out[0]["title"] == "Nuclei Finding"


def test_invalid_json_lines_skipped():
    out = _parse_nuclei_output(_b("not json at all", "", "   "))
    assert out == []


def test_mixed_stream_keeps_only_valid_findings():
    out = _parse_nuclei_output(_b(
        '"noise"',
        '{"host":"good","info":{"severity":"critical","name":"C"}}',
        "garbage",
        '{"host":"good2","info":{}}',
    ))
    assert [f["target"] for f in out] == ["good", "good2"]
    assert out[0]["severity"] == "critical"
    assert out[1]["severity"] == "info"


def test_tolerates_invalid_utf8_bytes():
    # a matched banner with invalid UTF-8 must not raise UnicodeDecodeError
    raw = b'{"host":"h","info":{"severity":"low","name":"N"}}\n\xff\xfe'
    out = _parse_nuclei_output(raw)
    assert len(out) == 1
    assert out[0]["severity"] == "low"


def test_wordlist_helper_templates_are_dropped():
    # `top-xss-params` is a parameter wordlist that feeds other templates, not a
    # vulnerability — it must not surface as a finding (it did live, as a HIGH
    # "Top 38 Parameters - Cross-Site Scripting" with empty vuln_type).
    out = _parse_nuclei_output(_b(
        '{"host":"h","template-id":"top-xss-params",'
        '"info":{"severity":"high","name":"Top 38 Parameters - Cross-Site Scripting"}}',
        # a real finding on the same stream must still come through
        '{"host":"h","template-id":"cve-2021-1","info":{"severity":"high","name":"Real CVE"}}',
    ))
    assert [f["title"] for f in out] == ["Real CVE"]


def test_wordlist_by_name_pattern_is_dropped():
    # match on the "Top NN Parameters" name even if the template-id is unknown
    out = _parse_nuclei_output(_b(
        '{"host":"h","template-id":"misc-x",'
        '"info":{"severity":"info","name":"Top 100 Parameters - SQLi"}}'
    ))
    assert out == []


def test_real_finding_carries_nonempty_vuln_type():
    # every emitted nuclei finding must have a concrete vuln_type so it never
    # resolves to empty downstream in the report/persist path
    out = _parse_nuclei_output(_b(
        '{"host":"h","template-id":"cve-x","info":{"severity":"high","name":"T"}}'
    ))
    assert out[0]["vuln_type"] == "nuclei"


def test_classification_is_lifted_onto_finding():
    # A template's own classification (cwe/cvss/cve) must land on the finding so
    # the report taxonomy reflects real metadata instead of going blank.
    out = _parse_nuclei_output(_b(
        '{"host":"h","template-id":"CVE-2021-44228","matched-at":"h/api",'
        '"info":{"severity":"critical","name":"Log4Shell",'
        '"classification":{"cve-id":["cve-2021-44228"],"cwe-id":["cwe-502"],'
        '"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",'
        '"cvss-score":10.0}}}'
    ))
    assert len(out) == 1
    f = out[0]
    assert f["cwe"] == "CWE-502"                 # normalised from lowercase
    assert f["cve"] == "CVE-2021-44228"
    assert f["cvss_vector"].startswith("CVSS:3.1")
    assert f["predicted_cvss_score"] == 10.0
    assert f["evidence"]["cve"] == "CVE-2021-44228"


def test_missing_classification_leaves_taxonomy_fields_absent():
    # No classification → no fabricated CWE/CVSS on the finding (the KB fallback
    # supplies OWASP + remediation at enrich time instead).
    out = _parse_nuclei_output(_b(
        '{"host":"h","template-id":"git-config",'
        '"info":{"severity":"medium","name":"Git Config Exposure"}}'
    ))
    assert len(out) == 1
    f = out[0]
    assert "cwe" not in f and "cvss_vector" not in f and "cve" not in f
    from heaven.devsecops import vuln_kb as kb
    enriched = kb.enrich_finding(dict(f))
    ev = enriched.get("evidence", {})
    assert enriched.get("owasp") or ev.get("owasp")       # OWASP floor present
    assert ev.get("remediation")                          # actionable guidance present

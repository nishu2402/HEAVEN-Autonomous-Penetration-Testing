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

"""Tests for the unauthenticated cloud-misconfiguration scanner.

All parsers are pure — no network. The one async path (``CloudStorageScanner``)
degrades gracefully without aiohttp and is exercised via its pure helpers.
"""

from __future__ import annotations

import json

from heaven.vulnscan.cloud_scanner import (
    BucketResult,
    CloudStorageResult,
    base_names_from_target,
    classify_bucket_response,
    classify_metadata_response,
    generate_bucket_candidates,
    metadata_finding,
    metadata_ssrf_candidates,
)


def test_base_names_registrable_label():
    assert base_names_from_target("https://app.acmecorp.com:8443/x")[0] == "acmecorp"
    assert "app" in base_names_from_target("app.acmecorp.com")


def test_base_names_skip_reserved_labels():
    # RFC 2606 / 6761 reserved or non-distinctive registrable labels must not
    # produce bucket candidates — a "example-images" match is coincidental, not
    # the target's asset (guards the mis-attributed critical FP).
    assert base_names_from_target("example.com") == []
    assert base_names_from_target("test.local") == []
    assert generate_bucket_candidates("example.com") == []


def test_base_names_multi_part_tld():
    # acme.co.uk → registrable label is 'acme', not 'co'.
    bases = base_names_from_target("shop.acme.co.uk")
    assert bases[0] == "acme"
    assert "co" not in bases


def test_candidate_generation_valid_bucket_names():
    cands = generate_bucket_candidates("acmecorp.com", extra=["acmecorpdata"], limit=100)
    assert "acmecorp" in cands
    assert "acmecorp-backups" in cands
    assert "acmecorpdata" in cands
    # S3 naming rules: 3-63 chars, no trailing hyphen.
    for c in cands:
        assert 3 <= len(c) <= 63
        assert not c.endswith("-")


def test_classify_s3_open_vs_private_vs_absent():
    open_xml = ('<?xml version="1.0"?><ListBucketResult><Contents><Key>a</Key>'
                "</Contents><Contents><Key>b</Key></Contents></ListBucketResult>")
    state, detail = classify_bucket_response("s3", 200, open_xml)
    assert state == "open" and "2 keys" in detail
    assert classify_bucket_response("s3", 403,
                                    "<Error><Code>AccessDenied</Code></Error>")[0] == "exists"
    assert classify_bucket_response("s3", 404,
                                    "<Error><Code>NoSuchBucket</Code></Error>")[0] == "absent"


def test_classify_gcs_and_azure():
    assert classify_bucket_response("gcs", 200,
                                    "<ListBucketResult><Key>x</Key></ListBucketResult>")[0] == "open"
    assert classify_bucket_response(
        "azure", 200,
        "<EnumerationResults><Blob><Name>x</Name></Blob></EnumerationResults>")[0] == "open"
    assert classify_bucket_response(
        "azure", 404, "<Error><Code>PublicAccessNotPermitted</Code></Error>")[0] == "exists"
    assert classify_bucket_response("azure", 404,
                                    "<Error><Code>ContainerNotFound</Code></Error>")[0] == "absent"


def test_open_listing_requires_real_xml_root_not_just_200():
    # A 200 with unrelated HTML must NOT be classified as an open bucket.
    state, _ = classify_bucket_response("s3", 200, "<html><body>hello</body></html>")
    assert state != "open"


def test_metadata_classifier_confirms_only_on_credential_marker():
    assert classify_metadata_response("aws", 200, '{"AccessKeyId":"ASIA...","x":1}')
    assert classify_metadata_response("gcp", 200, '{"access_token":"ya29..."}')
    assert classify_metadata_response("azure", 200, '{"compute":{"name":"vm"}}')
    # Non-200 or missing marker → not confirmed.
    assert not classify_metadata_response("aws", 200, "<html>404 not found</html>")
    assert not classify_metadata_response("gcp", 404, '{"access_token":"x"}')


def test_metadata_candidates_cover_three_clouds():
    provs = {c["provider"] for c in metadata_ssrf_candidates()}
    assert provs == {"aws", "gcp", "azure"}


def test_metadata_finding_is_critical_and_mitre_tagged():
    f = metadata_finding("aws", "http://169.254.169.254/...", "https://t.example")
    assert f["severity"] == "critical"
    assert f["vuln_type"] == "ssrf_cloud_metadata"
    assert f["mitre"]["techniques"][0]["id"] == "T1552.005"


def test_storage_result_findings_and_redaction_of_state():
    res = CloudStorageResult("app.example.com", True, 60, [
        BucketResult("s3", "example-backups", "https://u", "open", "3 keys"),
        BucketResult("gcs", "example", "https://u", "exists", "private"),
    ])
    fs = res.to_findings()
    sevs = {f["severity"] for f in fs}
    assert "critical" in sevs  # open bucket
    assert res.open_buckets and len(res.existing_buckets) == 2
    d = res.to_dict()
    assert d["open_count"] == 1
    # to_dict is JSON-safe.
    assert json.loads(json.dumps(d))["candidates_tried"] == 60

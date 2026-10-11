"""Regression: JS secret extraction must not report template placeholders or
example stubs as leaked credentials (FP Audit 16).

``extract_js_secrets`` scans JavaScript bundles for hardcoded secrets. Its only
false-positive filter was ``len < 8`` plus a few JS literals, so a config
template baked into a bundle (``password: "${API_PASSWORD}"``) or a doc example
(``apiKey: "example-api-key-value"``) was reported as a 0.8-confidence leaked
secret. The screen now drops template interpolation and obvious example fillers
while keeping real high-entropy values and embedded-credential DB URIs.
"""

from __future__ import annotations

import asyncio

from heaven.recon.deep_recon import _js_secret_is_placeholder, extract_js_secrets


class _Resp:
    def __init__(self, body: str):
        self._body = body
        self.status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._body


class _FakeSession:
    def __init__(self, body: str):
        self._body = body

    def get(self, url, **kw):
        return _Resp(self._body)


_JS = """
const config = {
  password: "${API_PASSWORD}",
  sessionToken: "{{ runtime_token }}",
  apiKey: "example-api-key-value-123",
  clientSecret: "<your-secret-here>",
  liveToken: "R3al_Live_T0ken_abcdef123456",
  stripe_key: "sk_live_abcdefghij1234567890",
  db: "postgres://admin:S3cretPw@db.internal:5432/app",
};
"""


def _secrets():
    sess = _FakeSession(_JS)
    assets = asyncio.run(extract_js_secrets(sess, "https://app.test",
                                            js_urls=["https://app.test/app.js"]))
    return [a.value for a in assets if a.asset_type == "secret"]


def test_template_placeholders_and_examples_not_reported():
    vals = _secrets()
    joined = " ".join(vals)
    assert "${API_PASSWORD}" not in joined
    assert "runtime_token" not in joined
    assert "example-api-key" not in joined
    assert "your-secret" not in joined


def test_real_secrets_still_reported():
    vals = _secrets()
    joined = " ".join(vals)
    assert "R3al_Live_T0ken_abcdef123456" in joined
    assert "sk_live_abcdefghij1234567890" in joined
    # The embedded-credential DB URI is still caught.
    assert any(v.startswith("postgres://admin:") for v in vals)


def test_js_secret_placeholder_helper():
    assert _js_secret_is_placeholder("${SECRET}")
    assert _js_secret_is_placeholder("{{ token }}")
    assert _js_secret_is_placeholder("<your-key>")
    assert _js_secret_is_placeholder("%(password)s")
    assert _js_secret_is_placeholder("example_api_key")
    assert _js_secret_is_placeholder("placeholder-value")
    # Real values and test-mode keys must survive (bare '$'/'<' and 'test'/'xxx'
    # are not signals on the value).
    assert not _js_secret_is_placeholder("R3al_Live_T0ken_abcdef")
    assert not _js_secret_is_placeholder("sk_test_abcdefghij123456")
    assert not _js_secret_is_placeholder("attestation_token_xyz99")

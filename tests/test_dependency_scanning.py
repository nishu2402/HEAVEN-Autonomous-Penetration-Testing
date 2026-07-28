"""Tests for HEAVEN's dependency / Software-Composition-Analysis layer.

Covers the CVSS v3.1 calculator, every manifest parser, the OSV finding shape,
CVE de-duplication, and a codebase walk — all offline (a fake OSV client stands
in for the network so the contract is fast and deterministic).
"""
from __future__ import annotations

import pytest

from heaven.utils.cvss import base_score_from_vector, severity_from_score
from heaven.vulnscan.osv_client import OSVVuln, Package
from heaven.vulnscan import sca_scanner


# ── CVSS v3.1 calculator (reference vectors from first.org) ──────────────────

@pytest.mark.parametrize("vector, expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
])
def test_cvss_reference_scores(vector, expected):
    assert base_score_from_vector(vector) == pytest.approx(expected, abs=0.05)


def test_cvss_missing_metrics_returns_zero():
    assert base_score_from_vector("") == 0.0
    assert base_score_from_vector("CVSS:3.1/AV:N") == 0.0


# ── CVSS v4.0 base scoring (reference lib; routed by the CVSS:4.0 prefix) ─────

@pytest.mark.parametrize("vector, expected", [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    # The real react-router GHSA-qwww-vcr4-c8h2 vector (RSC CSRF, integrity-only).
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
])
def test_cvss_v4_reference_scores(vector, expected):
    pytest.importorskip("cvss")  # reference-grade v4.0 scoring (base dependency)
    assert base_score_from_vector(vector) == pytest.approx(expected, abs=0.1)


def test_osv_parse_v4_vector_scores_real_not_flat_label():
    """A CVSS v4.0 advisory must score its real base — not the flat label constant.

    This is the react-router bug: the v3.1-only calculator couldn't parse the
    v4.0 vector, so every such 'high' advisory fell back to score_from_label →
    a flat 8.0. It must now compute the genuine v4.0 score (7.1 here).
    """
    pytest.importorskip("cvss")
    from heaven.vulnscan.osv_client import _parse_severity
    rec = {
        "severity": [{
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
        }],
        "database_specific": {"severity": "HIGH"},
    }
    vector, score, label = _parse_severity(rec)
    assert vector.startswith("CVSS:4.0")
    assert score == pytest.approx(7.1, abs=0.1)
    assert score != 8.0  # not the flat 'high' label constant
    assert label == "high"


# ── Per-finding CVSS resolver + no-flat-per-severity (the two reported bugs) ──

def test_objective_base_score_precedence_and_per_class():
    from heaven.utils.cvss import objective_base_score
    # 1. a real published score always wins.
    assert objective_base_score({"vuln_type": "sql_injection", "cvss_base": 6.4}) == 6.4
    # 2/3. class vector → genuinely per-class scores; different classes differ.
    sqli = objective_base_score({"vuln_type": "sql_injection"})
    xss = objective_base_score({"vuln_type": "reflected_xss"})
    assert sqli > 0 and xss > 0 and sqli != xss
    # An unknown class with no vector yields 0.0 — never a fabricated constant.
    assert objective_base_score({"vuln_type": "nonexistent_zzz_type"}) == 0.0


def test_ml_features_vary_by_class_not_flat_per_severity():
    """Two different classes at the *same* severity must no longer collapse to an
    identical feature vector (which is what produced the flat per-severity CVSS)."""
    from heaven.ml.risk_model import _extract_nvd_features
    sqli = _extract_nvd_features({"vuln_type": "sql_injection", "severity": "high"})
    xss = _extract_nvd_features({"vuln_type": "reflected_xss", "severity": "high"})
    hdr = _extract_nvd_features({"vuln_type": "missing_security_headers", "severity": "high"})
    assert sqli != xss != hdr
    assert sqli["conf_impact"] >= xss["conf_impact"]  # sqli hits confidentiality harder


def test_ml_predicted_cvss_spreads_within_a_severity_band():
    """The reported bug: every 'high' finding predicted the same CVSS. They must
    now span a genuine range driven by their real class vectors.

    This asserts on the *model's* output, so it needs the trained NVD regressor
    (data/models/NVD_model.pkl, ~50 MB). That file is intentionally gitignored and
    fetched with `heaven download-model`, so a fresh checkout and CI don't have it
    — there ``predict_cvss_score`` returns a constant fallback by design, and
    asserting a spread would be asserting model behaviour that legitimately can't
    exist. Skip in that case. The class-vector spread that actually fixed the bug
    is guarded model-free by ``test_ml_features_vary_by_class_not_flat_per_severity``
    above, which runs everywhere.
    """
    from heaven.ml.risk_model import get_model, _extract_nvd_features
    model = get_model()
    if not model.get_metrics().get("regression_mode"):
        pytest.skip("trained NVD model not present (run `heaven download-model`)")
    classes = ["sql_injection", "reflected_xss", "ssrf", "open_redirect",
               "idor", "clickjacking", "command_injection"]
    preds = {
        c: round(model.predict_cvss_score(
            _extract_nvd_features({"vuln_type": c, "severity": "high"})), 1)
        for c in classes
    }
    assert len(set(preds.values())) >= 3, preds  # not one flat number


@pytest.mark.parametrize("score, sev", [
    (9.8, "critical"), (7.5, "high"), (5.5, "medium"), (2.0, "low"), (0.0, "info"),
])
def test_severity_bands(score, sev):
    assert severity_from_score(score) == sev


# ── manifest parsers ─────────────────────────────────────────────────────────

def test_parse_requirements_txt():
    text = ("Flask==0.12.2\nJinja2 == 2.4.1\nrequests>=2.0\n# a comment\n"
            "django==2.2.0 ; python_version>'3'\n-e .\nhttps://x/y.whl\n"
            "uvicorn[standard]==0.17.0\n")
    got = {(p.name, p.version) for p in sca_scanner.parse_manifest("requirements.txt", text)}
    assert ("Flask", "0.12.2") in got
    assert ("Jinja2", "2.4.1") in got
    assert ("django", "2.2.0") in got
    assert ("uvicorn", "0.17.0") in got
    assert all(name != "requests" for name, _ in got)  # unpinned dropped


def test_parse_package_lock_v3_and_v1():
    v3 = ('{"lockfileVersion":3,"packages":{"":{"name":"a"},'
          '"node_modules/lodash":{"version":"4.17.4"},'
          '"node_modules/@scope/x":{"version":"1.2.3"}}}')
    got = {(p.name, p.version) for p in sca_scanner.parse_manifest("package-lock.json", v3)}
    assert ("lodash", "4.17.4") in got and ("@scope/x", "1.2.3") in got

    v1 = ('{"lockfileVersion":1,"dependencies":{"minimist":{"version":"1.2.0",'
          '"dependencies":{"nested":{"version":"0.1.0"}}}}}')
    got1 = {(p.name, p.version) for p in sca_scanner.parse_manifest("package-lock.json", v1)}
    assert ("minimist", "1.2.0") in got1 and ("nested", "0.1.0") in got1


def test_parse_yarn_lock():
    text = ('lodash@^4.17.0:\n  version "4.17.4"\n  resolved "x"\n\n'
            '"@babel/core@^7.0.0":\n  version "7.1.0"\n')
    got = {(p.name, p.version) for p in sca_scanner.parse_manifest("yarn.lock", text)}
    assert ("lodash", "4.17.4") in got and ("@babel/core", "7.1.0") in got


def test_parse_pipfile_and_poetry_and_gemfile():
    pip = ('{"default":{"flask":{"version":"==0.12.2"}},'
           '"develop":{"pytest":{"version":"==7.0.0"}}}')
    got = {(p.name, p.version) for p in sca_scanner.parse_manifest("Pipfile.lock", pip)}
    assert ("flask", "0.12.2") in got and ("pytest", "7.0.0") in got

    poetry = '[[package]]\nname = "requests"\nversion = "2.19.0"\n'
    gp = {(p.name, p.version) for p in sca_scanner.parse_manifest("poetry.lock", poetry)}
    assert ("requests", "2.19.0") in gp

    gem = "GEM\n  specs:\n    rails (5.2.0)\n    nokogiri (1.8.1)\n\nPLATFORMS\n"
    gg = {(p.name, p.version) for p in sca_scanner.parse_manifest("Gemfile.lock", gem)}
    assert ("rails", "5.2.0") in gg and ("nokogiri", "1.8.1") in gg


def test_parse_go_sum_and_pom_and_composer():
    go = ("github.com/gin-gonic/gin v1.6.2 h1:aaa=\n"
          "github.com/gin-gonic/gin v1.6.2/go.mod h1:bbb=\n")
    gg = {(p.name, p.version) for p in sca_scanner.parse_manifest("go.sum", go)}
    assert ("github.com/gin-gonic/gin", "1.6.2") in gg
    assert len(gg) == 1  # module@version deduped

    pom = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
           '<dependency><groupId>org.apache.logging.log4j</groupId>'
           '<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>'
           '<dependency><groupId>g</groupId><artifactId>a</artifactId>'
           '<version>${skip.me}</version></dependency></dependencies></project>')
    gp = {(p.name, p.version) for p in sca_scanner.parse_manifest("pom.xml", pom)}
    assert ("org.apache.logging.log4j:log4j-core", "2.14.1") in gp
    assert all("skip" not in v for _, v in gp)  # property version skipped

    comp = '{"packages":[{"name":"monolog/monolog","version":"v1.0.0"}]}'
    gc = {(p.name, p.version) for p in sca_scanner.parse_manifest("composer.lock", comp)}
    assert ("monolog/monolog", "1.0.0") in gc  # leading v stripped


def test_pom_xxe_cannot_read_local_files(tmp_path):
    """A hostile pom.xml (from a repo we're auditing) must not be able to read
    files off the analyst's host via an XML external entity. defusedxml rejects
    the entity, so the parser returns no packages and never leaks the secret."""
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENTS")
    malicious = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE project [<!ENTITY xxe SYSTEM "file://{secret}">]>'
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
        '<dependency><groupId>&xxe;</groupId><artifactId>a</artifactId>'
        '<version>1.0</version></dependency></dependencies></project>'
    )
    # Must not raise and must not surface the file contents anywhere.
    pkgs = sca_scanner.parse_manifest("pom.xml", malicious)
    assert all("TOP-SECRET" not in p.name and "TOP-SECRET" not in p.version
               for p in pkgs)


def test_parse_nuget_lock():
    text = ('{"version":1,"dependencies":{".NETCoreApp,Version=v6.0":{'
            '"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"},'
            '"Serilog":{"type":"Transitive","resolved":"2.10.0"}}}}')
    got = {(p.name, p.version, p.ecosystem)
           for p in sca_scanner.parse_manifest("packages.lock.json", text)}
    assert ("Newtonsoft.Json", "12.0.1", "NuGet") in got
    assert ("Serilog", "2.10.0", "NuGet") in got


def test_unsupported_manifest_returns_empty():
    assert sca_scanner.parse_manifest("README.md", "# hi") == []
    assert not sca_scanner.is_supported_manifest("random.txt")
    assert sca_scanner.is_supported_manifest("requirements.txt")


# ── OSV → finding shape + de-duplication ─────────────────────────────────────

class _FakeOSVClient:
    def __init__(self, vulns):
        self._vulns = vulns

    @property
    def available(self):
        return True

    async def query(self, packages):
        # Stamp the source of the first package (mirrors real behaviour) and
        # return the canned advisories.
        src = packages[0].source if packages else ""
        for v in self._vulns:
            v.source = src or v.source
        return list(self._vulns)


@pytest.mark.asyncio
async def test_scan_packages_finding_shape():
    vuln = OSVVuln(
        osv_id="GHSA-xxxx", package="flask", version="0.12.2", ecosystem="PyPI",
        summary="Example flaw", aliases=["CVE-2018-1000656"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_score=7.5, severity="high", fixed_version="0.12.3",
        source="requirements.txt",
    )
    pkgs = [Package("flask", "0.12.2", "PyPI", source="requirements.txt")]
    findings = await sca_scanner.scan_packages(pkgs, client=_FakeOSVClient([vuln]))
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "vulnerable_dependency"
    assert f["severity"] == "high"
    assert f["cve_id"] == "CVE-2018-1000656"
    assert f["cvss"] == 7.5
    # OWASP 2025: Vulnerable & Outdated Components → A03 Software Supply Chain Failures
    assert f["owasp"].startswith("A03")
    assert "0.12.3" in f["remediation"]
    assert f["evidence"]["signals"] == ["osv_advisory_version_match"]
    assert "proof" in f["evidence"]


@pytest.mark.asyncio
async def test_scan_packages_dedupes_same_cve_keeping_highest():
    # Same CVE reported by two advisory sources (GHSA scored, PYSEC unscored).
    ghsa = OSVVuln(osv_id="GHSA-1", package="flask", version="0.12.2",
                   ecosystem="PyPI", aliases=["CVE-2018-1000656"],
                   cvss_score=7.5, severity="high", fixed_version="0.12.3")
    pysec = OSVVuln(osv_id="PYSEC-1", package="flask", version="0.12.2",
                    ecosystem="PyPI", aliases=["CVE-2018-1000656"],
                    cvss_score=0.0, severity="info")
    pkgs = [Package("flask", "0.12.2", "PyPI", source="requirements.txt")]
    findings = await sca_scanner.scan_packages(
        pkgs, client=_FakeOSVClient([ghsa, pysec]))
    assert len(findings) == 1                 # collapsed to one
    assert findings[0]["severity"] == "high"  # kept the scored record
    assert findings[0]["evidence"]["fixed_version"] == "0.12.3"


@pytest.mark.asyncio
async def test_scan_path_walks_and_skips_vendor_dirs(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"}}}')

    captured = {}

    class _CapturingClient(_FakeOSVClient):
        async def query(self, packages):
            captured["names"] = sorted(p.name for p in packages)
            return []

    result = await sca_scanner.scan_path(str(tmp_path), client=_CapturingClient([]))
    # The vendored manifest under node_modules/ must be skipped.
    assert captured["names"] == ["flask"]
    assert result["manifests"] == ["requirements.txt"]


def test_vuln_kb_alias_resolves():
    from heaven.devsecops.vuln_kb import cvss_vector_for, lookup
    kb = lookup("vulnerable_dependency")
    assert kb.get("owasp", "").startswith("A03")  # 2025 Software Supply Chain Failures
    assert cvss_vector_for("vulnerable_dependency").startswith("CVSS:3.1")

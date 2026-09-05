"""Tests for the expanded SCA manifest parsers + enrichment helpers."""

from __future__ import annotations

from heaven.vulnscan.sca_scanner import (
    _concrete_version, _summarize, is_supported_manifest, parse_manifest,
)


def _names(pkgs):
    return {(p.name, p.version, p.ecosystem) for p in pkgs}


def test_pyproject_pep621_and_poetry():
    text = (
        '[project]\nname="x"\n'
        'dependencies=["requests==2.19.1","flask>=1.0,<2","urllib3"]\n'
        '[tool.poetry.dependencies]\npython="^3.10"\ndjango="3.2.0"\n'
        'jinja2={version="2.10.1"}\n'
    )
    got = _names(parse_manifest("pyproject.toml", text))
    assert ("requests", "2.19.1", "PyPI") in got
    assert ("flask", "1.0", "PyPI") in got
    assert ("django", "3.2.0", "PyPI") in got
    assert ("jinja2", "2.10.1", "PyPI") in got
    # python constraint is skipped, urllib3 has no concrete version
    assert not any(n == "python" for n, _, _ in got)


def test_package_json():
    text = '{"dependencies":{"lodash":"^4.17.11"},"devDependencies":{"jest":"~26.0.0"}}'
    got = _names(parse_manifest("package.json", text))
    assert ("lodash", "4.17.11", "npm") in got
    assert ("jest", "26.0.0", "npm") in got


def test_go_mod_block_and_single():
    text = ("module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.2\n"
            "\tgolang.org/x/text v0.3.2 // indirect\n)\n"
            "require github.com/foo/bar v1.0.0\n")
    got = _names(parse_manifest("go.mod", text))
    assert ("github.com/gin-gonic/gin", "1.6.2", "Go") in got
    assert ("golang.org/x/text", "0.3.2", "Go") in got
    assert ("github.com/foo/bar", "1.0.0", "Go") in got


def test_gradle_and_csproj():
    gradle = "dependencies {\n implementation 'org.springframework:spring-core:5.2.0'\n}"
    csproj = '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
    assert ("org.springframework:spring-core", "5.2.0", "Maven") in _names(
        parse_manifest("build.gradle", gradle))
    assert ("Newtonsoft.Json", "12.0.1", "NuGet") in _names(
        parse_manifest("MyApp.csproj", csproj))
    assert is_supported_manifest("MyApp.csproj")
    assert is_supported_manifest("build.gradle.kts")


def test_pipfile():
    text = '[packages]\nrequests = "==2.20.0"\ndjango = {version="==2.2.0"}\n'
    got = _names(parse_manifest("Pipfile", text))
    assert ("requests", "2.20.0", "PyPI") in got
    assert ("django", "2.2.0", "PyPI") in got


def test_concrete_version():
    assert _concrete_version("^4.17.0") == "4.17.0"
    assert _concrete_version(">=1.2,<2") == "1.2"
    assert _concrete_version("git+https://x") == ""
    assert _concrete_version("*") == ""


def test_summarize_rollup():
    findings = [
        {"severity": "high", "in_kev": True,
         "evidence": {"ecosystem": "PyPI", "package": "requests",
                      "installed_version": "2.19.1", "fixed_version": "2.20.0"}},
        {"severity": "medium",
         "evidence": {"ecosystem": "npm", "package": "lodash",
                      "installed_version": "4.17.11", "fixed_version": "4.17.21"}},
    ]
    s = _summarize(findings)
    assert s["by_ecosystem"] == {"PyPI": 1, "npm": 1}
    assert s["kev_count"] == 1
    assert {"package": "requests", "from": "2.19.1", "to": "2.20.0"} in s["safe_upgrades"]

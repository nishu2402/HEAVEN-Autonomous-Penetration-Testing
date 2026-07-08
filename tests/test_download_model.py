"""HEAVEN — tests for `heaven download-model` and the model search path.

The 48 MB NVD CVSS model is not shipped in the wheel or committed to git, so pip
and clone users fetch it with `heaven download-model`. These tests exercise the
fetch/verify/atomic-install logic offline (via `file://` URLs) and confirm the
loader search path includes the cache dir the download lands in — so a fetched
model is actually picked up.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _serve(tmp_path: Path, data: bytes) -> str:
    """Write `data` to a temp file and return a file:// URL for it."""
    src = tmp_path / "asset.bin"
    src.write_bytes(data)
    return src.as_uri()


# ── fetch_model core ─────────────────────────────────────────────────────────

def test_fetch_model_verifies_and_installs(tmp_path):
    from heaven.cli.train import fetch_model

    data = b"NVD-MODEL-CONTENT"
    url = _serve(tmp_path, data)
    dest = tmp_path / "out" / "NVD_model.pkl"

    fetch_model(url, dest, _sha(data))

    assert dest.exists()
    assert dest.read_bytes() == data


def test_fetch_model_rejects_bad_checksum_no_leftovers(tmp_path):
    import click

    from heaven.cli.train import fetch_model

    url = _serve(tmp_path, b"tampered-bytes")
    dest = tmp_path / "out" / "NVD_model.pkl"

    with pytest.raises(click.ClickException):
        fetch_model(url, dest, _sha(b"the-real-model"))

    # Bad download must never land where the loader would pick it up …
    assert not dest.exists()
    # … and no partial temp file may linger.
    assert list((tmp_path / "out").glob(".NVD_model.*")) == []


def test_fetch_model_no_verify_installs_anything(tmp_path):
    from heaven.cli.train import fetch_model

    data = b"unverified-but-installed"
    dest = tmp_path / "NVD_model.pkl"
    fetch_model(_serve(tmp_path, data), dest, None)
    assert dest.read_bytes() == data


def test_fetch_model_refuses_non_web_scheme(tmp_path):
    import click

    from heaven.cli.train import fetch_model

    with pytest.raises(click.ClickException):
        fetch_model("gopher://evil/model", tmp_path / "x.pkl", None)


# ── download-model command ───────────────────────────────────────────────────

def test_download_cmd_installs_with_sha_override(tmp_path):
    from click.testing import CliRunner

    from heaven.cli.train import download_model_cmd

    data = b"CLI-MODEL"
    url = _serve(tmp_path, data)
    dest = tmp_path / "cache" / "NVD_model.pkl"

    r = CliRunner().invoke(
        download_model_cmd,
        ["--url", url, "--dest", str(dest), "--sha256", _sha(data)],
    )
    assert r.exit_code == 0, r.output
    assert dest.read_bytes() == data
    assert "installed" in r.output.lower()


def test_download_cmd_already_present_skips(tmp_path):
    from click.testing import CliRunner

    from heaven.cli.train import download_model_cmd

    data = b"ALREADY-HERE"
    dest = tmp_path / "NVD_model.pkl"
    dest.write_bytes(data)

    # A never-openable URL proves we did NOT try to download.
    r = CliRunner().invoke(
        download_model_cmd,
        ["--url", "file:///nonexistent/should-not-be-read", "--dest", str(dest),
         "--sha256", _sha(data)],
    )
    assert r.exit_code == 0, r.output
    assert "already present" in r.output.lower()
    assert dest.read_bytes() == data


def test_download_cmd_bad_checksum_exits_nonzero(tmp_path):
    from click.testing import CliRunner

    from heaven.cli.train import download_model_cmd

    url = _serve(tmp_path, b"corrupt")
    dest = tmp_path / "NVD_model.pkl"
    r = CliRunner().invoke(
        download_model_cmd,
        ["--url", url, "--dest", str(dest), "--sha256", _sha(b"expected")],
    )
    assert r.exit_code != 0
    assert not dest.exists()


# ── loader search path ───────────────────────────────────────────────────────

def test_model_search_path_includes_cache_dir():
    from heaven.ml.risk_model import default_model_dir, model_search_paths

    paths = model_search_paths()
    assert default_model_dir() / "NVD_model.pkl" in paths


def test_model_search_path_honours_env_override(monkeypatch, tmp_path):
    override = tmp_path / "my_model.pkl"
    monkeypatch.setenv("HEAVEN_MODEL_PATH", str(override))
    from heaven.ml.risk_model import model_search_paths

    assert model_search_paths()[0] == override

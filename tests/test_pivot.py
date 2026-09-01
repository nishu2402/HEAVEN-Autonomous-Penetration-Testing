"""Tests for the network pivot module (gate + parsing + shape).

The live single/double-pivot proof runs against a lab SSH host via
`heaven pivot`; these tests cover everything that does not need a live SSH
server.
"""

from __future__ import annotations

import pytest

from heaven.cli.pivot import _parse_jump
from heaven.postex.pivot import JumpSpec, PivotChain, PivotResult, run_pivot


def test_pivotchain_requires_authorization():
    with pytest.raises(PermissionError):
        PivotChain(authorized=False)


@pytest.mark.asyncio
async def test_run_pivot_requires_authorization():
    with pytest.raises(PermissionError):
        await run_pivot(authorized=False, jumps=[JumpSpec(host="x", username="y")])


@pytest.mark.asyncio
async def test_run_pivot_no_jumps_is_error():
    r = await run_pivot(authorized=True, jumps=[])
    assert r["established"] is False
    assert r["errors"]


def test_jumpspec_label():
    j = JumpSpec(host="10.0.0.5", port=2222, username="root")
    assert j.label() == "root@10.0.0.5:2222"


def test_pivot_result_shape():
    r = PivotResult(chain=["a", "b"], established=True,
                    reachable=[{"host": "h", "port": 22, "open": True, "banner": ""}])
    d = r.to_dict()
    assert d["chain"] == ["a", "b"]
    assert d["open_count"] == 1


def test_parse_jump_user_pass_host_port():
    j = _parse_jump("msfadmin:msfadmin@192.168.0.162:22", None)
    assert j.host == "192.168.0.162"
    assert j.port == 22
    assert j.username == "msfadmin"
    assert j.password == "msfadmin"


def test_parse_jump_user_only_with_key():
    j = _parse_jump("root@10.0.0.9", "/tmp/id_rsa")
    assert j.username == "root"
    assert j.password == ""
    assert j.port == 22
    assert j.key_path == "/tmp/id_rsa"


def test_parse_jump_rejects_bad_format():
    import click
    with pytest.raises(click.BadParameter):
        _parse_jump("no-at-sign-here", None)

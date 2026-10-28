"""Phase 1 — the standalone ``heaven oast`` operator command.

The scanner starts a loopback collaborator on its own for localhost / lab
targets. For an internet-facing program the callback has to reach a box the
target can route to, so the operator runs the collaborator there with
``heaven oast`` and points a scan's OAST environment variables at it. This is
the operational nerve of the out-of-band proofs, so it gets the same coverage
as the listener itself: the command registers with the knobs an operator needs,
it actually binds both channels and reports an honest "listening" payload, and
a run with no zone degrades to HTTP-only without inventing any DNS fields.

Every positive assertion is paired with a negative one, matching the discipline
in :mod:`tests.test_oast_dns`.
"""

from __future__ import annotations

import types

import pytest
from click.testing import CliRunner

import heaven.cli.oast as oast_mod
from heaven.cli import cli


@pytest.fixture
def oast_cli(monkeypatch):
    """Drive the ``oast`` command deterministically and capture its payloads.

    Two things make the streaming command testable without blocking or relying
    on fragile process state:

    * ``time.sleep`` in the stream loop raises KeyboardInterrupt, so the command
      runs exactly one poll and then its normal clean-shutdown path.
    * ``emit_json`` / ``json_output`` are captured and forced on, so we assert on
      the structured payload the command produced rather than scraping stdout.
      (json_output() is a process-global set per CLI invocation; forcing it here
      keeps the test independent of whatever a prior test left it at, and of the
      Rich-vs-plain output branch.)

    Yields ``(runner, payloads)`` where ``payloads`` is the list of objects the
    command passed to ``emit_json`` during the invocation.
    """

    def _interrupt(*_a, **_k):
        raise KeyboardInterrupt

    payloads: list = []
    monkeypatch.setattr(oast_mod.time, "sleep", _interrupt)
    monkeypatch.setattr(oast_mod, "json_output", lambda: True)
    monkeypatch.setattr(oast_mod, "emit_json", payloads.append)
    yield CliRunner(), payloads


def _listening(payloads: list) -> dict:
    """The single ``status: listening`` object the command emitted on startup."""
    return next(p for p in payloads if p.get("status") == "listening")


# ─────────────────────────────────────────────────────────────────────────────
# Registration + operator guidance (no listener started).
# ─────────────────────────────────────────────────────────────────────────────

def test_oast_command_registered_with_operator_knobs():
    """`heaven oast` is wired and exposes every knob an operator needs to make
    an internet target call back: a routable advertised host, a bind address,
    a fixed port, and the DNS zone / public-IP pair for the DNS channel."""
    assert "oast" in cli.commands
    cmd = cli.commands["oast"]
    params = {p.name for p in cmd.params}
    assert {"advertised", "bind", "port",
            "dns_zone", "dns_bind", "dns_port", "public_ip"} <= params

    # The setup that lives "on the operator" (NS delegation, a public address)
    # must be surfaced in the option help, not just in prose docs. (rich-click
    # patches the Option class, so read .help off every param rather than
    # filtering by an isinstance that the patched class breaks.)
    help_by_opt = {p.name: (getattr(p, "help", "") or "") for p in cmd.params}
    assert "NS" in help_by_opt["dns_zone"]          # "...zone's NS delegated to this box"
    assert "public" in help_by_opt["advertised"].lower()  # routable address for internet targets


# ─────────────────────────────────────────────────────────────────────────────
# Positive: both channels come up and the reported state is honest.
# ─────────────────────────────────────────────────────────────────────────────

def test_oast_command_dns_channel_listening_json(oast_cli):
    """With a zone set, the command binds the UDP DNS listener (ephemeral port,
    so no privileges needed), advertises an HTTP callback base, and emits a
    `listening` payload describing both channels and an example probe host."""
    runner, payloads = oast_cli
    res = runner.invoke(
        cli,
        ["--json", "oast", "--host", "127.0.0.1", "--bind", "127.0.0.1",
         "--port", "0", "--dns-zone", "oast.test", "--dns-port", "0",
         "--public-ip", "127.0.0.1"],
    )
    assert res.exit_code == 0, res.output
    info = _listening(payloads)

    assert info["status"] == "listening"
    assert info["http_callback_base"].startswith("http://127.0.0.1:")
    assert info["dns_enabled"] is True
    assert info["dns_zone"] == "oast.test"
    assert info["dns_answer_ip"] == "127.0.0.1"
    # The probe hostname a blind payload would resolve is <token>.<zone>.
    assert info["example_dns_hostname"].endswith(".oast.test")
    assert info["example_dns_hostname"].split(".")[0].startswith("oob")


# ─────────────────────────────────────────────────────────────────────────────
# Negative: no zone -> HTTP-only, and nothing DNS is fabricated.
# ─────────────────────────────────────────────────────────────────────────────

def test_oast_command_degrades_to_http_only_json(oast_cli):
    """A run without --dns-zone still serves the HTTP channel but reports the
    DNS channel as off, with every DNS field blank. It never claims a DNS
    capability it did not bind."""
    runner, payloads = oast_cli
    res = runner.invoke(
        cli,
        ["--json", "oast", "--host", "127.0.0.1", "--bind", "127.0.0.1", "--port", "0"],
    )
    assert res.exit_code == 0, res.output
    info = _listening(payloads)

    assert info["http_callback_base"].startswith("http://127.0.0.1:")
    assert info["dns_enabled"] is False
    assert info["dns_zone"] == ""
    assert info["dns_answer_ip"] == ""
    assert info["example_dns_hostname"] == ""
    assert info["dns_bind"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# Callback rendering: each streamed line is the evidence, so its shape matters.
# ─────────────────────────────────────────────────────────────────────────────

def test_interaction_row_reports_channel_and_defaults_http():
    """A recorded DNS interaction keeps its channel; a bare interaction with no
    channel attribute is reported as HTTP (the original single-channel shape)."""
    dns_ix = types.SimpleNamespace(
        channel="dns", method="A", path="oobdeadbeef.oast.test",
        client_ip="198.51.100.7", token="oobdeadbeef",
    )
    row = oast_mod._interaction_row(dns_ix)
    assert row == {
        "channel": "dns", "method": "A", "path": "oobdeadbeef.oast.test",
        "from": "198.51.100.7", "token": "oobdeadbeef",
    }

    http_ix = types.SimpleNamespace(
        method="GET", path="/oobcafe", client_ip="203.0.113.9", token="oobcafe",
    )
    assert oast_mod._interaction_row(http_ix)["channel"] == "http"

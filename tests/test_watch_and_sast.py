"""
Tests for watch loop + SAST. Avoid network/subprocess where possible —
exercise the pure logic (config parsing, normalisation) and stub the
heavy pieces with monkeypatch.
"""

from __future__ import annotations

import pytest


# ═══════════════════════════════════════════
# WATCH — config + duration parser
# ═══════════════════════════════════════════


class TestWatchConfig:
    def test_next_sleep_no_jitter(self):
        from heaven.utils.watcher import WatchConfig
        c = WatchConfig(targets={}, engagement_name="x",
                        interval_s=120, jitter_pct=0.0)
        assert c.next_sleep() == 120.0

    def test_next_sleep_jitter_bounds(self):
        from heaven.utils.watcher import WatchConfig
        c = WatchConfig(targets={}, engagement_name="x",
                        interval_s=100, jitter_pct=0.2)
        # ±20% — every draw must fall in [80, 120]
        for _ in range(50):
            s = c.next_sleep()
            assert 80.0 <= s <= 120.0

    def test_next_sleep_minimum_one_second(self):
        from heaven.utils.watcher import WatchConfig
        c = WatchConfig(targets={}, engagement_name="x",
                        interval_s=1, jitter_pct=0.5)
        # Even with max jitter the floor is 1.0
        for _ in range(30):
            assert c.next_sleep() >= 1.0


class TestParseDuration:
    def test_seconds(self):
        from heaven.cli.watch import _parse_duration
        assert _parse_duration("30s") == 30

    def test_minutes(self):
        from heaven.cli.watch import _parse_duration
        assert _parse_duration("5m") == 300

    def test_hours(self):
        from heaven.cli.watch import _parse_duration
        assert _parse_duration("2h") == 7200

    def test_days(self):
        from heaven.cli.watch import _parse_duration
        assert _parse_duration("1d") == 86400

    def test_bare_digits_is_seconds(self):
        from heaven.cli.watch import _parse_duration
        assert _parse_duration("90") == 90

    def test_invalid_raises(self):
        from heaven.cli.watch import _parse_duration
        import click as _click
        with pytest.raises(_click.BadParameter):
            _parse_duration("forever")


class TestWatchIterationDTO:
    def test_summary_aggregates(self):
        from heaven.utils.watcher import WatchSummary, WatchIteration
        s = WatchSummary()
        s.iterations.append(WatchIteration(n=0, started_at=0,
                                            alert_dispatched=True, tickets_created=2))
        s.iterations.append(WatchIteration(n=1, started_at=1))
        s.iterations.append(WatchIteration(n=2, started_at=2,
                                            alert_dispatched=True, tickets_created=1))
        assert s.total_iterations == 3
        assert s.total_alerts == 2
        assert s.total_tickets == 3

    def test_iteration_to_dict_shape(self):
        from heaven.utils.watcher import WatchIteration
        it = WatchIteration(
            n=2, started_at=1.0, new=1, regressed=0, baseline=False,
            scan_id="abcdef1234", findings_total=7,
            changes=[{"kind": "new", "severity": "high", "vuln_type": "xss",
                      "target": "h", "title": "XSS"}],
        )
        d = it.to_dict()
        assert d["n"] == 2 and d["new"] == 1 and d["changed"] is True
        assert d["changes"][0]["kind"] == "new"
        # Every field the UI/API reads must be present.
        for key in ("scan_id", "resolved", "alert_dispatched", "baseline",
                    "findings_total", "error"):
            assert key in d

    def test_summary_to_dict_counts_changes(self):
        from heaven.utils.watcher import WatchSummary, WatchIteration
        s = WatchSummary()
        s.iterations.append(WatchIteration(n=0, started_at=0, baseline=True))
        s.iterations.append(WatchIteration(n=1, started_at=1, new=2))   # changed
        s.iterations.append(WatchIteration(n=2, started_at=2))          # unchanged
        d = s.to_dict()
        assert d["changes_detected"] == 1
        assert d["last_iteration"]["n"] == 2


# A tiny stand-in for diff_finder's DiffReport so the alerting hooks can be
# exercised without running a real scan.
class _Row:
    def __init__(self, severity="medium", vuln_type="vt", title="T", target="h"):
        self.id = "x"
        self.severity = severity
        self.vuln_type = vuln_type
        self.title = title
        self.target = target
        self.confidence = 0.5


class _Diff:
    def __init__(self, new=None, regressed=None, resolved=None):
        self.new = new or []
        self.regressed = regressed or []
        self.resolved = resolved or []

    @property
    def critical_new(self):
        return sum(1 for r in self.new if r.severity == "critical")

    @property
    def regressed_critical_or_high(self):
        return sum(1 for r in self.regressed if r.severity in ("critical", "high"))


class TestSummarizeChanges:
    def test_caps_and_labels(self):
        from heaven.utils.watcher import _summarize_changes
        diff = _Diff(new=[_Row(severity="high") for _ in range(10)],
                     regressed=[_Row(severity="critical")])
        out = _summarize_changes(diff, cap=5)
        assert len(out) == 5                      # cap honoured
        assert all(c["kind"] in ("new", "regressed") for c in out)

    def test_includes_both_kinds_when_room(self):
        from heaven.utils.watcher import _summarize_changes
        out = _summarize_changes(_Diff(new=[_Row()], regressed=[_Row(severity="critical")]))
        assert {c["kind"] for c in out} == {"new", "regressed"}


class TestWatchAlerting:
    """The core bug this feature had: a *change* that was only medium/low never
    actually pinged the webhook (send_alert_async short-circuits on 0 crit/high),
    and --heartbeat never sent at all. These prove the watch path now sends."""

    @pytest.mark.asyncio
    async def test_dispatch_alerts_sends_on_medium_only_change(self, monkeypatch):
        from heaven.utils import watcher
        from heaven.devsecops import alerting
        posted: list[dict] = []

        async def fake_post(self, payload):
            posted.append(payload)
            return True

        monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example/test")
        monkeypatch.setattr(alerting.WebhookAlerter, "_post_async", fake_post)

        diff = _Diff(new=[_Row(severity="medium")])
        it = watcher.WatchIteration(n=1, started_at=0.0, new=1,
                                    findings_total=5, scan_id="abcdef12")
        cfg = watcher.WatchConfig(targets={}, engagement_name="eng")
        ok = await watcher._dispatch_alerts(diff, it, cfg, heartbeat=False)
        assert ok is True
        assert posted, "webhook MUST POST for a medium-only change"
        body = posted[0]["text"]
        assert "New: 1" in body and "eng" in body

    @pytest.mark.asyncio
    async def test_heartbeat_first_run_sends(self, monkeypatch):
        from heaven.utils import watcher
        from heaven.devsecops import alerting
        posted: list[dict] = []

        async def fake_post(self, payload):
            posted.append(payload)
            return True

        monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example/test")
        monkeypatch.setattr(alerting.WebhookAlerter, "_post_async", fake_post)

        cfg = watcher.WatchConfig(targets={}, engagement_name="eng")
        ok = await watcher._heartbeat(cfg)
        assert ok is True and posted
        assert "started" in posted[0]["text"].lower()

    @pytest.mark.asyncio
    async def test_watch_alert_no_webhook_returns_false(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_URL", raising=False)
        from heaven.devsecops.alerting import WebhookAlerter
        w = WebhookAlerter()
        assert await w.send_watch_alert_async({"new": 1}) is False


# ═══════════════════════════════════════════
# SAST — result normaliser
# ═══════════════════════════════════════════


class TestSastNormaliser:
    def test_semgrep_result_to_sast_finding(self):
        from heaven.vulnscan.sast_runner import _parse_semgrep_result
        entry = {
            "check_id": "heaven.python.sqli-string-format",
            "path": "/src/app.py",
            "start": {"line": 42, "col": 8},
            "extra": {
                "severity": "ERROR",
                "message": "SQL injection via string format",
                "lines": "  cursor.execute(\"SELECT * FROM u WHERE id = \" + uid)",
                "metadata": {
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021 - Injection"],
                    "confidence": "HIGH",
                },
            },
        }
        f = _parse_semgrep_result(entry)
        assert f.rule_id == "heaven.python.sqli-string-format"
        assert f.severity == "high"
        assert f.file_path == "/src/app.py"
        assert f.line == 42
        assert f.column == 8
        assert f.cwe == "CWE-89"
        # A legacy 2021 semgrep tag is upgraded to the canonical 2025 label.
        assert f.owasp == "A05:2025 Injection"
        assert f.confidence == 0.9

    def test_severity_mapping(self):
        from heaven.vulnscan.sast_runner import _parse_semgrep_result
        for raw, expected in [("ERROR", "high"), ("WARNING", "medium"),
                              ("INFO", "low"), ("CRITICAL", "critical"),
                              ("unknown", "medium")]:
            f = _parse_semgrep_result({
                "check_id": "x", "path": "p", "start": {"line": 1},
                "extra": {"severity": raw, "message": "x"},
            })
            assert f.severity == expected

    def test_finding_normalises_to_heaven_format(self):
        from heaven.vulnscan.sast_runner import SastFinding
        f = SastFinding(
            rule_id="heaven.python.sqli-string-format",
            severity="critical",
            title="SQL injection",
            file_path="/src/app.py", line=42,
            cwe="CWE-89", owasp="A05:2025",
        )
        d = f.to_heaven_finding()
        assert d["target"] == "file:///src/app.py"
        assert d["vuln_type"] == "sast_sqli"
        assert d["severity"] == "critical"
        assert d["evidence"]["cwe"] == "CWE-89"
        assert d["evidence"]["source"] == "semgrep"

    def test_normalise_vuln_type_recognises_categories(self):
        from heaven.vulnscan.sast_runner import _normalise_vuln_type
        assert _normalise_vuln_type("heaven.python.sqli-string-format") == "sqli"
        assert _normalise_vuln_type("xss-react-dangerously") == "xss"
        assert _normalise_vuln_type("cmdi-shell-true") == "cmdi"
        assert _normalise_vuln_type("weak-crypto-md5") == "weak_crypto"
        assert _normalise_vuln_type("path-traversal") == "path_traversal"
        # Unknown → code_quality
        assert _normalise_vuln_type("random-string-thing") == "code_quality"

    def test_severity_breakdown(self):
        from heaven.vulnscan.sast_runner import SastFinding, SastRunResult
        r = SastRunResult(success=True, findings=[
            SastFinding(rule_id="a", severity="critical", title="x"),
            SastFinding(rule_id="b", severity="critical", title="x"),
            SastFinding(rule_id="c", severity="high", title="x"),
            SastFinding(rule_id="d", severity="medium", title="x"),
        ])
        b = r.severity_breakdown
        assert b == {"critical": 2, "high": 1, "medium": 1}


# ═══════════════════════════════════════════
# SAST RUNNER — error path (no semgrep)
# ═══════════════════════════════════════════


class TestSastRunnerErrors:
    @pytest.mark.asyncio
    async def test_missing_path_returns_error(self, monkeypatch):
        from heaven.vulnscan import sast_runner
        # Force the semgrep check to succeed so we hit the "path missing" branch
        monkeypatch.setattr(sast_runner, "has_semgrep", lambda: True)
        r = await sast_runner.run_sast("/nonexistent/path/xyz")
        assert r.success is False
        assert "path not found" in r.error

    @pytest.mark.asyncio
    async def test_missing_semgrep_returns_error(self, monkeypatch, tmp_path):
        from heaven.vulnscan import sast_runner
        monkeypatch.setattr(sast_runner, "has_semgrep", lambda: False)
        r = await sast_runner.run_sast(str(tmp_path))
        assert r.success is False
        assert "semgrep not installed" in r.error

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
        assert f.owasp == "A03:2021 - Injection"
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
            cwe="CWE-89", owasp="A03:2021",
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

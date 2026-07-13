"""Regression tests for `scan_display_name` — the target-based scan label.

A scan is named after what it assessed (e.g. "app.example.com +2") so it reads
identifiably in the Scans list, the dashboard and downloaded reports instead of
a bare id or the generic "HEAVEN Scan".
"""
from __future__ import annotations

from heaven.engagement import scan_display_name


def test_single_url_strips_scheme_and_path():
    assert scan_display_name(["https://app.example.com/login?x=1"], "web") == "app.example.com"


def test_multiple_targets_get_plus_count():
    assert scan_display_name(
        ["https://app.example.com", "10.0.0.5", "host2"], "web"
    ) == "app.example.com +2"


def test_bare_ip_and_cidr_kept_verbatim():
    assert scan_display_name(["10.0.0.5"], "network") == "10.0.0.5"
    # CIDR suffix must survive (not truncated at the slash like a URL path).
    assert scan_display_name(["10.0.0.0/24"], "network") == "10.0.0.0/24"


def test_no_targets_falls_back_to_mode_label():
    assert scan_display_name([], "network") == "network scan"
    assert scan_display_name(None, "") == "scan"


def test_blank_entries_are_ignored():
    assert scan_display_name(["", "  ", "example.com"], "web") == "example.com"

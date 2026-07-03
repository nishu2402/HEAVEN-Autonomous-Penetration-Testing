"""Defense-in-depth: the raw-SQL repositories interpolate column *names* into
INSERT/UPDATE statements, so those names must be restricted to the table's real
schema. These tests exercise the pure guard (no DB needed)."""

import pytest

from heaven.db.repository import (
    EngagementRepository,
    NotificationRepository,
    ReportRepository,
    WebPathRepository,
    _reject_unknown_columns,
)

RAW_SQL_REPOS = [
    EngagementRepository,
    WebPathRepository,
    NotificationRepository,
    ReportRepository,
]


@pytest.mark.parametrize("repo", RAW_SQL_REPOS)
def test_each_raw_repo_has_a_nonempty_allowlist(repo):
    assert repo._COLUMNS, f"{repo.__name__} has no column allowlist"
    assert "id" in repo._COLUMNS


def test_valid_columns_pass():
    _reject_unknown_columns(EngagementRepository, ["name", "status", "config"])  # no raise


def test_unknown_column_is_rejected():
    with pytest.raises(ValueError) as exc:
        _reject_unknown_columns(EngagementRepository, ["name", "not_a_column"])
    assert "not_a_column" in str(exc.value)


def test_sql_injection_via_key_is_rejected():
    # A crafted dict key must never reach the interpolated SQL.
    with pytest.raises(ValueError):
        _reject_unknown_columns(
            EngagementRepository,
            ["status = 'x'; DROP TABLE engagements; --"],
        )


def test_columns_are_table_specific():
    # web_paths has "url"; engagements does not — the guard must not share them.
    _reject_unknown_columns(WebPathRepository, ["url", "http_status"])  # no raise
    with pytest.raises(ValueError):
        _reject_unknown_columns(EngagementRepository, ["url"])


def test_empty_keys_are_fine():
    _reject_unknown_columns(NotificationRepository, [])  # no raise

"""Benchmark report generators — markdown for publication, CSV for comparison."""

from tests.benchmarks.reporters.markdown_report import render_markdown_report
from tests.benchmarks.reporters.comparison_csv import render_comparison_csv

__all__ = ["render_markdown_report", "render_comparison_csv"]

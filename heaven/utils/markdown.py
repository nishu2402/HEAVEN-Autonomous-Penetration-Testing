"""Small Markdown rendering helpers shared by the report exporters.

Reports embed target-influenced bytes (a scanned response body, a reflected
payload, a string pulled from a malicious forensic artifact) inside fenced code
blocks. A literal triple-backtick run in that content would break out of a
fixed three-backtick fence and render the rest of the deliverable as live
Markdown or HTML. `fenced_block` sizes the fence so that can never happen.
"""
from __future__ import annotations


def fenced_block(content: object, lang: str = "") -> list[str]:
    """Return ``content`` as a Markdown fenced code block, as a list of lines.

    CommonMark closes a fenced code block on the first line that is a run of the
    fence character at least as long as the opening fence. Sizing the fence to
    one backtick longer than the longest backtick run anywhere in the content
    (and never shorter than three) guarantees embedded backticks cannot close
    the block early, so untrusted bytes stay inside it instead of injecting live
    Markdown or HTML into the rendered report.
    """
    text = content if isinstance(content, str) else str(content)
    longest = run = 0
    for ch in text:
        if ch == "`":
            run += 1
            if run > longest:
                longest = run
        else:
            run = 0
    fence = "`" * (longest + 1 if longest >= 3 else 3)
    return [f"{fence}{lang}", text, fence]


def table_cell(value: object) -> str:
    """Render a value safe for a single Markdown table cell.

    A raw newline or carriage return ends the table row, so attacker-controlled
    external text (a service banner, a DNS record value) could otherwise inject
    extra rows, headings or arbitrary Markdown into the report after the row.
    A raw pipe adds a spurious column. Both are neutralised while the visible
    text is preserved.
    """
    text = value if isinstance(value, str) else str(value)
    return (text.replace("\r", " ").replace("\n", " ").replace("|", r"\|")).strip()

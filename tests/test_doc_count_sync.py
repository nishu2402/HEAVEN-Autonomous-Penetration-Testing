"""HEAVEN — the docs count-sync tool keeps the hero poster in step with reality.

`scripts/sync_test_count.py` rewrites the README's derived counts and, now, the
hero poster SVGs too (the marketing poster used to silently drift — it shipped a
stale "1856 tests" long after the suite had grown). This locks in that the poster
rewrite touches only the three collected counts and leaves the hand-set figures
(UI pages, scan modes) and the ML R² alone.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_test_count.py"


def _load():
    spec = importlib.util.spec_from_file_location("_sync_test_count", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# A faithful slice of the poster: the aria-label plus the x-anchored stat block.
_POSTER_SNIPPET = (
    '<svg aria-label="HEAVEN. 1856 tests, 55 CLI commands, 77 API routes, '
    '25 UI pages, 13 scan modes, CVSS ML predictor R-squared 0.91.">'
    '<g text-anchor="middle">'
    '<text x="155"  y="426" font-size="28">1856</text>'
    '<text x="349"  y="426" font-size="28">55</text>'
    '<text x="543"  y="426" font-size="28">77</text>'
    '<text x="737"  y="426" font-size="28">25</text>'
    '<text x="931"  y="426" font-size="28">13</text>'
    '<text x="1125" y="426" font-size="24">0.91</text>'
    '</g></svg>'
)


def test_sync_poster_updates_only_collected_counts():
    mod = _load()
    out = mod.sync_poster(_POSTER_SNIPPET, {"tests": 1909, "cli": 56, "routes": 82})

    # The three collected counts are rewritten in the stat block …
    assert '<text x="155"  y="426" font-size="28">1909</text>' in out
    assert '<text x="349"  y="426" font-size="28">56</text>' in out
    assert '<text x="543"  y="426" font-size="28">82</text>' in out
    # … and in the aria-label.
    assert "1909 tests, 56 CLI commands, 82 API routes" in out

    # The hand-set figures and the ML R² are untouched (no collector for them).
    assert '<text x="737"  y="426" font-size="28">25</text>' in out   # UI pages
    assert '<text x="931"  y="426" font-size="28">13</text>' in out   # scan modes
    assert ">0.91<" in out
    assert "25 UI pages, 13 scan modes" in out
    assert "1856" not in out and ">55<" not in out and ">77<" not in out


def test_sync_poster_is_idempotent():
    mod = _load()
    values = {"tests": 1909, "cli": 56, "routes": 82}
    once = mod.sync_poster(_POSTER_SNIPPET, values)
    twice = mod.sync_poster(once, values)
    assert once == twice


def test_sync_poster_matches_real_poster_markup():
    """Guard the x-anchor regexes against the ACTUAL poster markup (spacing and
    attribute order), so a poster restyle that breaks the anchors is caught here
    rather than silently leaving the counts unwritten. Poster freshness itself is
    enforced by CI's ``sync_test_count.py --check``, not a moving-target assert."""
    mod = _load()
    for poster in mod.POSTERS:
        original = poster.read_text()
        # Rewriting to deliberately-wrong values must change all three anchors +
        # the aria-label, proving the patterns still match this markup.
        bumped = mod.sync_poster(original, {"tests": 4242, "cli": 43, "routes": 41})
        assert bumped != original
        assert ">4242</text>" in bumped
        assert ">43</text>" in bumped
        assert ">41</text>" in bumped
        assert "4242 tests, 43 CLI commands, 41 API routes" in bumped
        # Hand-set figures survive the rewrite untouched.
        assert "25 UI pages, 16 scan modes" in bumped

"""Shared URL-surface classifiers for the active web fuzzers.

The heavy active injection / RCE / SSTI fuzzers (the anomaly probe, the advanced
exploitation tests, the web fuzzer) send a whole battery of payloads per URL,
several of them time-based: a server-side ``sleep 5`` or a malformed chunked
body that stalls to a connect/read timeout. Firing that battery at a static,
parameter-less document — a localized ``README.fr.md``, a ``.pdf`` manual, a
``robots.txt`` — costs seconds per URL and can never surface an injection
finding: there is no server-side code behind the file to inject into and no
parameter to carry a payload. A real app can ship dozens of such files (DVWA's
official ``:latest`` image alone ships 14 localized ``README.*.md`` files), so
an active fuzzer that walks every discovered URL burns minutes of wall-clock on
surface that categorically cannot be vulnerable.

``has_injectable_surface`` lets those fuzzers skip that surface without touching
recall: anything with a query string, a scripting/dynamic path, or an
extension-less route is still fuzzed; only clearly-static, parameter-less
document/asset URLs are skipped.

``origin_of`` collapses a URL to its ``scheme://host:port`` so origin-level
probes (HTTP request smuggling, whose desync is a front-end/back-end property
of the connection, not of any one path) run once per origin instead of once per
discovered path.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Extensions whose bytes are served as-is with no server-side parameter
# evaluation: documents, images, fonts, media, archives, source maps. A URL
# whose path ends in one of these AND carries no query string has no injectable
# surface for the active payload fuzzers. Scripting extensions (.php/.jsp/.asp…)
# are deliberately absent — those ARE dynamic and must still be fuzzed.
_STATIC_EXTS = frozenset({
    # documents
    "md", "markdown", "rst", "txt", "text", "pdf", "csv", "tsv",
    "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # images
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "avif", "svg", "ico", "tiff",
    # fonts + stylesheets + maps
    "css", "map", "woff", "woff2", "ttf", "eot", "otf",
    # archives
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar",
    # media
    "mp3", "mp4", "webm", "ogg", "oga", "wav", "flac", "avi", "mov", "mkv",
})


def _last_segment_ext(path: str) -> str:
    """Lower-cased extension of a URL path's final segment, or "" if none."""
    last = (path or "/").rsplit("/", 1)[-1]
    if "." not in last:
        return ""
    return last.rsplit(".", 1)[-1].lower()


def has_injectable_surface(url: str) -> bool:
    """True unless ``url`` is a static, parameter-less document/asset.

    The active payload fuzzers use this to skip URLs that cannot carry a
    server-side injection: a ``?param=`` (or any query string) keeps a URL in
    scope, an extension-less or scripting path keeps it in scope, and only a
    parameter-less path ending in a known static extension is skipped. Errs on
    the side of keeping a URL — an unparseable value returns True.
    """
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return True
    # Any query string is injectable surface regardless of the path extension
    # (e.g. /download.pdf?file=... is a classic LFI vector).
    if parts.query:
        return True
    ext = _last_segment_ext(parts.path)
    if not ext:
        return True  # directory or extension-less dynamic route — keep it
    return ext not in _STATIC_EXTS


def origin_of(url: str) -> str:
    """Collapse a URL to ``scheme://host[:port]`` (its origin).

    Used to run origin-level probes (e.g. HTTP request smuggling) once per
    origin rather than once per discovered path. Falls back to the raw string
    when the URL cannot be parsed, so distinct un-parseable values never collapse
    together.
    """
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return url or ""
    if not parts.scheme or not parts.netloc:
        return url or ""
    return f"{parts.scheme}://{parts.netloc}"

r"""client_audit must not mistake an equality COMPARISON for an assignment sink.

A live full scan of scanme.nmap.org flagged /shared/js/nst.js for "client-side
resource manipulation" (medium) on read-only nav-highlight code:

    if (document.location.href === a.href) { a.classList.add('active'); }

Here location.href (a taint source) flows into an ``===`` comparison, not into a
resource-loading sink. The sink pattern ``\.href\s*=`` matched the first ``=`` of
``===``, so a read-only comparison was reported as a sink write. The bare-"="
sinks now carry a ``(?!=)`` lookahead: a single-"=" assignment still matches, a
``==``/``===`` comparison does not.
"""
from __future__ import annotations

from heaven.vulnscan import client_audit as C


def _types(findings: list) -> set:
    return {f.get("vuln_type") for f in findings}


def test_href_equality_comparison_is_not_resource_manipulation():
    # The exact pattern observed on scanme.nmap.org's nst.js.
    js = ("navItems.forEach(function (a) {"
          "  if (document.location.href === a.href) { a.classList.add('active'); }"
          "});")
    out = C._analyse_js("https://scanme.nmap.org/", js, "linked:/shared/js/nst.js")
    assert "client_resource_manipulation" not in _types(out)


def test_src_equality_with_source_present_is_not_flagged():
    # A real taint source (location.hash) sits right next to `.src ==`/`.src ===`,
    # so only the lookahead — not the absence of a source — keeps this clean.
    for op in ("===", "=="):
        js = f"if (el.src {op} location.hash) {{ doThing(); }}"
        out = C._analyse_js("https://h/", js, "inline")
        assert "client_resource_manipulation" not in _types(out), op


def test_genuine_src_assignment_still_flagged():
    js = "var u = location.hash.slice(1); img.src = u;"
    out = C._analyse_js("https://h/", js, "inline")
    assert "client_resource_manipulation" in _types(out)


def test_genuine_href_and_action_assignment_still_flagged():
    js = "var u = location.search; form.action = u; link.href = location.href;"
    out = C._analyse_js("https://h/", js, "inline")
    assert "client_resource_manipulation" in _types(out)

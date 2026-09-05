"""HEAVEN — malware / webshell signature engine (YARA-backed, always-on).

Threat detection for HEAVEN's malware scan and file-forensics paths. It matches
content against a curated ruleset of **real** webshell, backdoor and obfuscated-
loader indicators.

Two backends, one API:

  * **yara-python** — when the native library is installed, a bundled ``.yar``
    ruleset is compiled and used (the industry-standard engine, so operators can
    drop in their own rules too).
  * **builtin signatures** — always present. A pure-Python matcher over the same
    indicators runs regardless, so detection is **never gated** on an optional
    native dependency. Every match reports which engine produced it, so the
    evidence is honest about what did the work.

Everything here is **read-only pattern matching** over bytes already fetched or
read from disk. Nothing is executed. This is threat *detection*, not an
antivirus and not a sandbox — the finding is "this content matches a known
malicious pattern", with the rule name and the matched excerpt as proof.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.yara_engine")


@dataclass(frozen=True)
class SignatureMatch:
    rule: str
    severity: str            # critical / high / medium / info
    description: str
    engine: str              # "yara" | "builtin"
    excerpt: str = ""        # short evidence snippet
    cwe: str = "CWE-506"
    mitre: str = "T1505.003"


# ── Builtin ruleset ──────────────────────────────────────────────────────────
# Each rule is a name + severity + description + a matcher. ``all_of`` requires
# every pattern; ``any_of`` requires at least one. Patterns are compiled
# case-insensitive over the decoded text. These are the same indicators the
# bundled YARA rules encode, so the builtin path is a faithful fallback.
@dataclass(frozen=True)
class _Rule:
    name: str
    severity: str
    description: str
    all_of: tuple[re.Pattern, ...] = ()
    any_of: tuple[re.Pattern, ...] = ()

    def match(self, text: str) -> Optional[str]:
        """Return the matched excerpt if the rule fires, else None."""
        excerpt = ""
        for pat in self.all_of:
            m = pat.search(text)
            if not m:
                return None
            excerpt = excerpt or m.group(0)
        if self.any_of:
            m = None
            for pat in self.any_of:
                m = pat.search(text)
                if m:
                    excerpt = excerpt or m.group(0)
                    break
            if not m:
                return None
        if not self.all_of and not self.any_of:
            return None
        return excerpt[:120]


def _ci(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I | re.S)


_RULES: tuple[_Rule, ...] = (
    _Rule("PHP_Webshell_Named", "critical",
          "Content matches a named PHP webshell (c99/r57/b374k/WSO/alfa/IndoXploit).",
          any_of=(_ci(r"c99shell"), _ci(r"r57shell"), _ci(r"b374k"),
                  _ci(r"WSO\s*\d"), _ci(r"FilesMan"), _ci(r"IndoXploit"),
                  _ci(r"alfa\s*team|AlfaShell"))),
    _Rule("PHP_Webshell_Eval_Superglobal", "critical",
          "Obfuscated PHP command execution: an exec/eval sink fed directly from "
          "an HTTP superglobal — the core of a generic webshell.",
          all_of=(_ci(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"),
                  _ci(r"\b(?:eval|assert|system|shell_exec|passthru|popen|proc_open"
                      r"|exec)\s*\(")),),
    _Rule("PHP_Obfuscated_Loader", "high",
          "Obfuscated PHP loader: gzinflate/str_rot13/base64_decode chained into "
          "eval — a common packer for malicious payloads.",
          all_of=(_ci(r"\beval\s*\("),
                  _ci(r"\b(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(")),),
    _Rule("PHP_PregReplace_Eval", "high",
          "preg_replace with the /e modifier — deprecated PHP code-execution "
          "primitive abused for RCE.",
          all_of=(_ci(r"preg_replace\s*\(\s*['\"].*?/e['\"]"),)),
    _Rule("China_Chopper", "critical",
          "China Chopper webshell one-liner (eval of a request parameter in "
          "PHP/ASPX).",
          any_of=(_ci(r"eval\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[\s*['\"].{0,3}['\"]\s*\]\s*\)"),
                  _ci(r"eval\s*\(\s*Request\s*\.?(?:Item)?\s*\[")),),
    _Rule("JSP_Webshell", "critical",
          "JSP webshell: Runtime.exec fed from a request parameter.",
          all_of=(_ci(r"Runtime\.getRuntime\(\)\.exec"),
                  _ci(r"request\.getParameter")),),
    _Rule("ASPX_Webshell", "critical",
          "ASP.NET webshell: process launch or code eval from a request value.",
          any_of=(_ci(r"System\.Diagnostics\.Process\.Start"),
                  _ci(r"eval\s*\(\s*Request")),),
    _Rule("EICAR_Test_File", "medium",
          "EICAR antivirus test string present. Not malware, but its presence in "
          "served content is a strong signal something is wrong.",
          any_of=(re.compile(re.escape(
              r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR")),)),
)

# A base64 blob longer than this with high Shannon entropy is flagged as a
# suspicious embedded payload (informational — many benign assets are base64 too).
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_ENTROPY_FLAG = 4.8


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _decode(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="ignore")


# ── YARA backend (optional) ──────────────────────────────────────────────────
_YARA_RULESET = r"""
rule PHP_Webshell_Named {
    strings:
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $b374k = "b374k" nocase
        $wso = "WSO " nocase
        $fm = "FilesMan" nocase
        $indo = "IndoXploit" nocase
    condition: any of them
}
rule PHP_Webshell_Eval_Superglobal {
    strings:
        $sg = /\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $sink = /(eval|assert|system|shell_exec|passthru|popen|proc_open|exec)\s*\(/ nocase
    condition: $sg and $sink
}
rule PHP_Obfuscated_Loader {
    strings:
        $eval = /eval\s*\(/ nocase
        $dec = /(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(/ nocase
    condition: $eval and $dec
}
rule China_Chopper {
    strings:
        $php = /eval\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $aspx = /eval\s*\(\s*Request/ nocase
    condition: any of them
}
rule JSP_Webshell {
    strings:
        $exec = "Runtime.getRuntime().exec"
        $param = "request.getParameter"
    condition: $exec and $param
}
"""

_YARA_COMPILED = None
_YARA_TRIED = False
# Map YARA rule name → (severity, description) so a YARA hit carries the same
# metadata as the builtin path.
_YARA_META = {r.name: (r.severity, r.description) for r in _RULES}


def _yara_rules():
    """Compile (once) the bundled YARA ruleset if yara-python is installed."""
    global _YARA_COMPILED, _YARA_TRIED
    if _YARA_TRIED:
        return _YARA_COMPILED
    _YARA_TRIED = True
    try:
        import yara  # optional native dependency
        _YARA_COMPILED = yara.compile(source=_YARA_RULESET)
        logger.debug("yara-python ruleset compiled")
    except Exception as e:  # noqa: BLE001 — absence/compile error → builtin only
        logger.debug("yara-python unavailable (%s); using builtin signatures", e)
        _YARA_COMPILED = None
    return _YARA_COMPILED


def yara_available() -> bool:
    """True when the native yara-python engine is usable."""
    return _yara_rules() is not None


# ── Public API ───────────────────────────────────────────────────────────────

def scan_bytes(data: bytes | str, *, include_entropy: bool = True
               ) -> list[SignatureMatch]:
    """Match content against the ruleset. Returns every distinct rule that fires,
    using yara-python when present plus the always-on builtin matcher (results
    are merged and de-duplicated by rule name)."""
    text = _decode(data)
    matches: dict[str, SignatureMatch] = {}

    # YARA backend (if available).
    rules = _yara_rules()
    if rules is not None:
        try:
            raw = data if isinstance(data, (bytes, bytearray)) else text.encode(
                "utf-8", errors="ignore")
            for m in rules.match(data=raw):
                sev, desc = _YARA_META.get(m.rule, ("high", m.rule))
                matches[m.rule] = SignatureMatch(
                    rule=m.rule, severity=sev, description=desc, engine="yara",
                    excerpt=_yara_excerpt(m))
        except Exception as e:  # noqa: BLE001
            logger.debug("yara match failed: %s", e)

    # Builtin matcher (always).
    for rule in _RULES:
        if rule.name in matches:
            continue
        excerpt = rule.match(text)
        if excerpt is not None:
            matches[rule.name] = SignatureMatch(
                rule=rule.name, severity=rule.severity,
                description=rule.description, engine="builtin", excerpt=excerpt)

    # Entropy heuristic (informational).
    if include_entropy and "Suspicious_HighEntropy_Blob" not in matches:
        blob = _B64_BLOB.search(text)
        if blob and _shannon_entropy(blob.group(0)) >= _ENTROPY_FLAG:
            matches["Suspicious_HighEntropy_Blob"] = SignatureMatch(
                rule="Suspicious_HighEntropy_Blob", severity="info",
                description="A long, high-entropy base64 blob is embedded in the "
                            "content — often an obfuscated or packed payload.",
                engine="builtin", excerpt=blob.group(0)[:60] + "…",
                cwe="CWE-506", mitre="T1027")
    return list(matches.values())


def _yara_excerpt(match) -> str:  # noqa: ANN001 — yara.Match
    try:
        for s in match.strings:
            # yara-python ≥4.3 StringMatch objects, older tuples.
            inst = getattr(s, "instances", None)
            if inst:
                return str(inst[0].matched_data[:80])
            if isinstance(s, tuple) and len(s) >= 3:
                data = s[2]
                return (data.decode("utf-8", "ignore") if isinstance(data, bytes)
                        else str(data))[:80]
    except Exception:  # noqa: BLE001
        logger.debug("could not extract YARA match string", exc_info=True)
    return ""


def scan_file(path: str, max_bytes: int = 4_000_000) -> list[SignatureMatch]:
    """Read a file (bounded) and scan it. Returns [] on any read error."""
    try:
        with open(path, "rb") as fh:
            return scan_bytes(fh.read(max_bytes))
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_file(%s) failed: %s", path, e)
        return []


def worst_severity(matches: list[SignatureMatch]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "info": 1}
    if not matches:
        return "info"
    return max(matches, key=lambda m: order.get(m.severity, 0)).severity


__all__ = [
    "SignatureMatch", "scan_bytes", "scan_file", "yara_available",
    "worst_severity",
]

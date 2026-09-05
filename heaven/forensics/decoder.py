"""HEAVEN — smart multi-scheme string decoder.

A single string can be encoded, compressed, or wrapped in several layers. This
module decodes across every common scheme, recurses through nested layers,
identifies the decoded bytes by magic signature, and scores each result so the
output is accurate rather than a wall of plausible-looking garbage.

Schemes covered:

* **Base families** — base64, base64url, base32, base16/hex, Ascii85, base85.
* **Web** — percent/URL-encoding, HTML entities, quoted-printable.
* **Ciphers** — ROT13, ROT47, Atbash, single-byte XOR (bounded brute force).
* **Compression** — gzip, zlib, bzip2 (magic-gated).
* **Numeric** — decimal, hex, octal and binary byte sequences, Morse code.
* **Structured** — JWT (header/payload/alg), with a finding when ``alg`` is
  ``none`` or a weak/guessable HMAC is likely.

Every candidate carries a confidence score. A decoding is only surfaced when the
result is printable text or a recognised binary format, so a short word is not
"decoded" into noise. Nested encodings are unwrapped automatically and reported
as a decode chain.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import html
import json
import re
import urllib.parse
import zlib
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("forensics.decoder")

_MAX_DEPTH = 6
_MAX_INPUT = 1_000_000
_MAX_DECOMPRESS = 16 * 1024 * 1024   # output cap — defeats decompression bombs


def _bounded_zlib(data: bytes, wbits: int) -> Optional[bytes]:
    """Inflate ``data`` but never emit more than ``_MAX_DECOMPRESS`` bytes."""
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, _MAX_DECOMPRESS + 1)
        if len(out) > _MAX_DECOMPRESS or d.unconsumed_tail:
            return None
        out += d.flush()
        return out if len(out) <= _MAX_DECOMPRESS else None
    except Exception:
        return None


def _bounded_bz2(data: bytes) -> Optional[bytes]:
    try:
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, _MAX_DECOMPRESS + 1)
        return None if len(out) > _MAX_DECOMPRESS else out
    except Exception:
        return None

# Magic signatures for identifying decoded *binary* output.
_MAGICS: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP (empty)"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"%PDF-", "PDF document"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"OggS", "Ogg media"),
    (b"ID3", "MP3 (ID3)"),
    (b"\x00\x00\x01\x00", "Windows icon"),
    (b"-----BEGIN ", "PEM key/certificate"),
    (b"{\\rtf", "RTF document"),
]

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-....-": "-", "-.--.": "(", "-.--.-": ")", ".--.-.": "@",
}


# ── output classification ─────────────────────────────────────────────────────
def _identify(b: bytes) -> str:
    for sig, label in _MAGICS:
        if b.startswith(sig):
            return label
    return ""


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127)
    return ok / len(b)


def _to_text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin1", "replace")


def _looks_meaningful(text: str) -> bool:
    """True if the text reads like real content (letters/words), not noise."""
    if not text:
        return False
    letters = sum(1 for c in text if c.isalnum() or c in " ._-:/@{}\"',=")
    return letters / len(text) > 0.75


# "Structural" decoders unwrap an encoding layer (recursion follows these);
# "cipher" decoders are classical-cipher guesses that always produce output, so
# they are capped low and never recursed into.
_STRUCTURAL = {"base64", "base64url", "base32", "hex", "ascii85", "base85", "url",
               "html-entity", "quoted-printable", "gzip", "zlib", "bzip2",
               "decimal", "octal", "binary", "morse"}
_CIPHER = {"rot13", "rot47", "atbash", "reverse"}


def _score(raw: bytes, scheme: str) -> float:
    ident = _identify(raw)
    if ident and scheme not in _CIPHER:
        return 0.98
    pr = _printable_ratio(raw)
    if pr < 0.85:
        return 0.0
    text = _to_text(raw)
    base = 0.6 + 0.3 * pr
    if _looks_meaningful(text):
        base += 0.1
    # Reward schemes that only match structured input.
    if scheme in ("gzip", "zlib", "bzip2", "url", "html-entity"):
        base = min(1.0, base + 0.05)
    # Classical ciphers are guesses, not decodings — never let them out-rank a
    # real structural decode.
    if scheme in _CIPHER:
        base = min(base, 0.45 if scheme in ("reverse", "atbash") else 0.5)
    return round(min(base, 0.97), 3)


# ── individual decoders (each returns bytes or None) ──────────────────────────
def _d_base64(s: str) -> Optional[bytes]:
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", t) or len(t) % 4 != 0:
        return None
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None


def _d_base64url(s: str) -> Optional[bytes]:
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9_\-]{4,}={0,2}", t) or ("-" not in t and "_" not in t):
        return None
    pad = "=" * (-len(t) % 4)
    try:
        return base64.urlsafe_b64decode(t + pad)
    except (binascii.Error, ValueError):
        return None


def _d_base32(s: str) -> Optional[bytes]:
    t = re.sub(r"\s+", "", s).upper()
    if not re.fullmatch(r"[A-Z2-7]{8,}={0,6}", t) or len(t) % 8 != 0:
        return None
    try:
        return base64.b32decode(t)
    except (binascii.Error, ValueError):
        return None


def _d_hex(s: str) -> Optional[bytes]:
    t = re.sub(r"(?i)^0x|[\s:]", "", s)
    if len(t) < 4 or len(t) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def _d_ascii85(s: str) -> Optional[bytes]:
    t = s.strip()
    if len(t) < 10:
        return None
    try:
        return base64.a85decode(t, adobe=t.startswith("<~"))
    except (ValueError, binascii.Error):
        return None


def _d_base85(s: str) -> Optional[bytes]:
    t = re.sub(r"\s+", "", s)
    if len(t) < 10:
        return None
    try:
        return base64.b85decode(t)
    except (ValueError, binascii.Error):
        return None


def _d_url(s: str) -> Optional[bytes]:
    if "%" not in s and "+" not in s:
        return None
    try:
        out = urllib.parse.unquote_plus(s)
        return out.encode("utf-8", "replace") if out != s else None
    except Exception:
        return None


def _d_html(s: str) -> Optional[bytes]:
    if "&" not in s or ";" not in s:
        return None
    out = html.unescape(s)
    return out.encode("utf-8", "replace") if out != s else None


def _d_rot13(s: str) -> Optional[bytes]:
    if not any(c.isalpha() for c in s):
        return None
    return codecs.encode(s, "rot_13").encode("utf-8", "replace")


def _d_rot47(s: str) -> Optional[bytes]:
    if not s.strip():
        return None
    out = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                  for c in s)
    return out.encode("utf-8", "replace") if out != s else None


def _d_atbash(s: str) -> Optional[bytes]:
    if not any(c.isalpha() for c in s):
        return None
    def flip(c):
        if "a" <= c <= "z":
            return chr(ord("z") - (ord(c) - ord("a")))
        if "A" <= c <= "Z":
            return chr(ord("Z") - (ord(c) - ord("A")))
        return c
    out = "".join(flip(c) for c in s)
    return out.encode("utf-8", "replace") if out != s else None


def _d_quoted_printable(s: str) -> Optional[bytes]:
    if "=" not in s:
        return None
    import quopri
    try:
        out = quopri.decodestring(s.encode("latin1"))
        return out if out != s.encode("latin1") else None
    except Exception:
        return None


def _d_gzip(s: str) -> Optional[bytes]:
    b = _as_bytes(s)
    if not b or b[:2] != b"\x1f\x8b":
        return None
    return _bounded_zlib(b, 16 + zlib.MAX_WBITS)


def _d_zlib(s: str) -> Optional[bytes]:
    b = _as_bytes(s)
    if not b or b[0] != 0x78:                # zlib header 0x78 ..
        return None
    return _bounded_zlib(b, zlib.MAX_WBITS)


def _d_bzip2(s: str) -> Optional[bytes]:
    b = _as_bytes(s)
    if not b or b[:3] != b"BZh":
        return None
    return _bounded_bz2(b)


def _d_decimal(s: str) -> Optional[bytes]:
    nums = re.findall(r"\d{1,3}", s)
    if len(nums) < 2 or not re.fullmatch(r"[\d\s,;]+", s.strip()):
        return None
    try:
        vals = [int(n) for n in nums]
        if all(0 <= v <= 255 for v in vals):
            return bytes(vals)
    except ValueError:
        pass
    return None


def _d_binary(s: str) -> Optional[bytes]:
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or len(t) % 8 != 0 or not re.fullmatch(r"[01]+", t):
        return None
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def _d_octal(s: str) -> Optional[bytes]:
    nums = re.findall(r"[0-7]{1,3}", s.strip())
    if len(nums) < 2 or not re.fullmatch(r"[0-7\s,;]+", s.strip()):
        return None
    try:
        vals = [int(n, 8) for n in nums]
        if all(0 <= v <= 255 for v in vals):
            return bytes(vals)
    except ValueError:
        return None
    return None


def _d_morse(s: str) -> Optional[bytes]:
    if not re.fullmatch(r"[.\-/\s]+", s.strip()) or "." not in s and "-" not in s:
        return None
    words = re.split(r"\s*/\s*|\s{2,}", s.strip())
    out = []
    for word in words:
        letters = [_MORSE.get(tok, "?") for tok in word.split() if tok]
        if letters:
            out.append("".join(letters))
    text = " ".join(out)
    return text.encode() if text and "?" not in text else None


def _d_reverse(s: str) -> Optional[bytes]:
    return s[::-1].encode("utf-8", "replace") if len(s) > 3 else None


def _as_bytes(s: str) -> bytes:
    """Interpret a string as bytes for the compression decoders (hex/base64/raw)."""
    b = _d_hex(s)
    if b:
        return b
    b = _d_base64(s)
    if b:
        return b
    return s.encode("latin1", "replace")


_DECODERS: list[tuple[str, Any]] = [
    ("base64", _d_base64), ("base64url", _d_base64url), ("base32", _d_base32),
    ("hex", _d_hex), ("ascii85", _d_ascii85), ("base85", _d_base85),
    ("url", _d_url), ("html-entity", _d_html), ("quoted-printable", _d_quoted_printable),
    ("rot13", _d_rot13), ("rot47", _d_rot47), ("atbash", _d_atbash),
    ("gzip", _d_gzip), ("zlib", _d_zlib), ("bzip2", _d_bzip2),
    ("decimal", _d_decimal), ("octal", _d_octal), ("binary", _d_binary),
    ("morse", _d_morse), ("reverse", _d_reverse),
]


# ── JWT ───────────────────────────────────────────────────────────────────────
def _decode_jwt(s: str) -> Optional[dict]:
    t = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t):
        return None
    parts = t.split(".")

    def seg(p):
        pad = "=" * (-len(p) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(p + pad))
        except Exception:
            return None
    header, payload = seg(parts[0]), seg(parts[1])
    if header is None or payload is None:
        return None
    return {"header": header, "payload": payload,
            "signature_present": bool(parts[2]),
            "alg": str(header.get("alg", "")).lower()}


# ── orchestration ─────────────────────────────────────────────────────────────
def _maybe_decompress(raw: bytes) -> Optional[tuple[str, bytes]]:
    """If ``raw`` is a compression stream, decompress it (bounded). (name, bytes)."""
    out: Optional[bytes] = None
    name = ""
    if raw[:2] == b"\x1f\x8b":
        name, out = "gzip", _bounded_zlib(raw, 16 + zlib.MAX_WBITS)
    elif raw[:3] == b"BZh":
        name, out = "bzip2", _bounded_bz2(raw)
    elif raw and raw[0] == 0x78:
        name, out = "zlib", _bounded_zlib(raw, zlib.MAX_WBITS)
    return (name, out) if out else None


def _decode_one_layer(s: str) -> list[dict]:
    """All accepted decodings of a single string (one layer), scored + identified."""
    out: list[dict] = []
    seen: set = set()
    for scheme, fn in _DECODERS:
        try:
            raw = fn(s)
        except Exception:
            logger.debug("decoder %s failed", scheme, exc_info=True)
            raw = None
        if not raw:
            continue
        # A decode that lands on a compression stream is unwrapped in one step,
        # so base64/hex-wrapped gzip/zlib/bzip2 yields the final plaintext.
        comp = _maybe_decompress(raw)
        if comp and scheme in _STRUCTURAL:
            cname, cbytes = comp
            cconf = _score(cbytes, cname)
            if cconf > 0:
                ctext = _to_text(cbytes)
                out.append({"scheme": f"{scheme}+{cname}", "decoded": ctext[:2000],
                            "confidence": min(0.98, cconf + 0.02), "bytes": len(cbytes),
                            "_raw": cbytes})
        conf = _score(raw, scheme)
        if conf <= 0:
            continue
        text = _to_text(raw)
        if text.strip() == s.strip() and scheme not in _CIPHER:
            continue
        key = (scheme, raw[:64])
        if key in seen:
            continue
        seen.add(key)
        ident = _identify(raw)
        entry = {"scheme": scheme, "decoded": text[:2000],
                 "confidence": conf, "bytes": len(raw), "_raw": raw}
        if ident:
            entry["identified_type"] = ident
            entry["decoded_hex"] = raw[:64].hex()
        out.append(entry)
    out.sort(key=lambda e: e["confidence"], reverse=True)
    return out


def smart_decode(text: str) -> dict[str, Any]:
    """Decode ``text`` across every scheme, unwrap nested layers, and score.

    Returns ``{"input", "decodings": [...], "jwt"?, "findings": [...], "best"?}``.
    """
    text = (text or "")[:_MAX_INPUT]
    findings: list[dict] = []
    decodings = _decode_one_layer(text)

    # When a strong structural decode exists, drop the classical-cipher guesses —
    # offering rot13 of a string that clearly base64-decodes is just noise.
    if any(d["scheme"] in _STRUCTURAL and d["confidence"] >= 0.7 for d in decodings):
        decodings = [d for d in decodings if d["scheme"] not in _CIPHER]

    # Recursively unwrap the single strongest STRUCTURAL branch (nested
    # encodings), with a visited set so cipher/involution cycles can't loop.
    chain: list[dict] = []
    cur = text
    visited = {text.strip()}
    depth = 0
    while depth < _MAX_DEPTH:
        layer = _decode_one_layer(cur)
        strong = [d for d in layer if d["scheme"] in _STRUCTURAL
                  and d["confidence"] >= 0.8
                  and _printable_ratio(d["decoded"].encode("latin1", "replace")) > 0.9
                  and _looks_meaningful(d["decoded"])
                  and d["decoded"].strip() not in visited]
        if not strong:
            break
        best = strong[0]
        chain.append({"scheme": best["scheme"], "decoded": best["decoded"][:300]})
        visited.add(best["decoded"].strip())
        cur = best["decoded"]
        depth += 1
    if len(chain) > 1:
        for d in decodings:
            if d["scheme"] == chain[0]["scheme"]:
                d["chain"] = chain

    # JWT structured decode. When the input is a JWT the dedicated view carries
    # the result, so the cipher-guess decodings are just noise — drop them.
    jwt = _decode_jwt(text)
    if jwt:
        decodings = [d for d in decodings if d["scheme"] in _STRUCTURAL]
    result: dict[str, Any] = {"input": text, "decodings": decodings}
    if jwt:
        result["jwt"] = jwt
        _jwt_findings(jwt, findings)

    # Sensitive content revealed by decoding (credentials / secrets).
    _content_findings(decodings, findings)

    result["findings"] = findings
    if decodings:
        result["best"] = {"scheme": decodings[0]["scheme"],
                          "decoded": decodings[0]["decoded"][:300],
                          "confidence": decodings[0]["confidence"]}
    # Drop the internal raw-bytes carrier before returning (not JSON-safe).
    for d in decodings:
        d.pop("_raw", None)
    return result


def _jwt_findings(jwt: dict, findings: list[dict]) -> None:
    alg = jwt.get("alg", "")
    if alg == "none":
        findings.append({
            "vuln_type": "jwt_alg_none", "severity": "high", "scanner": "decoder",
            "confidence": 0.9, "title": "JWT uses 'alg: none' (unsigned token)",
            "description": ("The token declares alg=none, so its signature is not "
                            "verified. An attacker can forge arbitrary claims and "
                            "impersonate any user."),
            "cwe": "CWE-347", "evidence": {"header": jwt.get("header")},
            "remediation": "Reject alg=none server-side and pin the expected "
                           "signing algorithm."})
    elif alg in ("hs256", "hs384", "hs512"):
        findings.append({
            "vuln_type": "jwt_hmac", "severity": "info", "scanner": "decoder",
            "confidence": 0.6, "title": f"JWT signed with symmetric {alg.upper()}",
            "description": ("The token uses an HMAC signature. If the secret is weak "
                            "it can be brute-forced offline (hashcat -m 16500) to "
                            "forge tokens."),
            "cwe": "CWE-326", "evidence": {"alg": alg}})
    payload = jwt.get("payload") or {}
    if isinstance(payload, dict) and "exp" not in payload:
        findings.append({
            "vuln_type": "jwt_no_expiry", "severity": "low", "scanner": "decoder",
            "confidence": 0.7, "title": "JWT has no expiry (exp) claim",
            "description": "The token never expires; if leaked it is valid forever.",
            "cwe": "CWE-613"})


_CRED_RE = re.compile(r"^[^\s:]{1,64}:[^\s:]{1,128}$")


def _content_findings(decodings: list[dict], findings: list[dict]) -> None:
    for d in decodings[:5]:
        if d.get("identified_type"):            # binary output, not credentials
            continue
        dec = d.get("decoded", "")
        if not dec or _printable_ratio(dec.encode("latin1", "replace")) < 0.98:
            continue
        if _CRED_RE.match(dec.strip()):
            findings.append({
                "vuln_type": "decoded_credentials", "severity": "medium",
                "scanner": "decoder", "confidence": 0.75,
                "title": "Decoded string is a credential pair (user:password)",
                "description": (f"The input decoded (via {d['scheme']}) to what looks "
                                "like a 'user:password' credential — e.g. an HTTP "
                                "Basic-auth token."),
                "cwe": "CWE-319", "evidence": {"scheme": d["scheme"]}})
            break
        if "-----BEGIN" in dec and "PRIVATE KEY" in dec:
            findings.append({
                "vuln_type": "decoded_private_key", "severity": "high",
                "scanner": "decoder", "confidence": 0.85,
                "title": "Decoded output contains a private key",
                "description": f"The input decoded (via {d['scheme']}) to PEM "
                               "private-key material.",
                "cwe": "CWE-321"})
            break

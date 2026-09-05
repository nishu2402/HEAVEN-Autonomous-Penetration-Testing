"""HEAVEN — offline hash / cryptography analysis.

Covers the CEH/CPENT offline-crypto workflow on operator-supplied material:

* **Hash identification** — recognise the algorithm from format/length.
* **Offline dictionary cracking** — recover plaintext for raw hashes
  (MD5/SHA1/SHA256/SHA512/NTLM) and Unix crypt (``$1$``/``$5$``/``$6$``/bcrypt)
  using a bundled small wordlist plus any operator-supplied wordlist. Parses
  ``/etc/shadow`` and ``user:hash`` dumps so a whole file can be cracked.
* **Weak-hash flagging** — unsalted MD5/SHA1 password storage.
* **Encoded-text decoding** — base64 / base32 / hex / ROT13.

Cracking is bounded (small default wordlist; the operator points at a bigger
one for depth) and, like everything in HEAVEN, honest: a plaintext is reported
only when a candidate actually reproduces the hash.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
from typing import Any, Optional, cast

from heaven.utils.logger import get_logger

logger = get_logger("forensics.crypto")

# A tiny built-in wordlist — enough to demonstrate weak passwords. Operators
# point --wordlist at rockyou.txt etc. for real depth.
_BUILTIN_WORDLIST = [
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "admin", "root", "toor", "letmein", "welcome", "monkey",
    "dragon", "master", "msfadmin", "user", "service", "changeme", "secret",
    "P@ssw0rd", "Password1", "Password123", "iloveyou", "sunshine", "football",
    "test", "test123", "guest", "oracle", "postgres", "mysql", "cisco",
]


# Prefixed hash formats keyed by their leading marker → (label, hashcat mode).
_PREFIX_FORMATS: list[tuple[str, str, Optional[int]]] = [
    ("$2a$", "bcrypt", 3200), ("$2b$", "bcrypt", 3200), ("$2y$", "bcrypt", 3200),
    ("$2x$", "bcrypt", 3200),
    ("$6$", "sha512crypt (Unix)", 1800), ("$5$", "sha256crypt (Unix)", 7400),
    ("$1$", "md5crypt (Unix)", 500), ("$apr1$", "Apache apr1-md5", 1600),
    ("$y$", "yescrypt (Unix)", None), ("$7$", "scrypt (Unix)", None),
    ("$argon2i$", "Argon2i", None), ("$argon2id$", "Argon2id", None),
    ("$argon2d$", "Argon2d", None),
    ("$pbkdf2-sha256$", "PBKDF2-HMAC-SHA256", 10900),
    ("$pbkdf2-sha512$", "PBKDF2-HMAC-SHA512", None),
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", 10000),
    ("sha1$", "Django SHA1", 124), ("md5$", "Django salted-MD5", None),
    ("$P$", "phpass (WordPress/phpBB)", 400), ("$H$", "phpass (WordPress)", 400),
    ("$S$", "Drupal7 (SHA-512)", 7900),
    ("{SSHA}", "LDAP salted-SHA1", 111), ("{SHA}", "LDAP SHA1", 101),
    ("{SSHA256}", "LDAP salted-SHA256", 1411), ("{SMD5}", "LDAP salted-MD5", None),
    ("$krb5tgs$", "Kerberos 5 TGS-REP (kerberoast)", 13100),
    ("$krb5asrep$", "Kerberos 5 AS-REP (asreproast)", 18200),
    ("$krb5pa$", "Kerberos 5 AS-REQ Pre-Auth", 7500),
    ("$NT$", "NTLM", 1000), ("$DCC2$", "Domain Cached Credentials 2 (mscash2)", 2100),
    ("0x0100", "MSSQL(2000)", 131), ("0x0200", "MSSQL(2012+)", 1731),
    ("$sha1$", "atlassian/pbkdf2-sha1", None), ("$ml$", "macOS PBKDF2-SHA512", 7100),
    ("$9$", "Juniper $9$ (reversible)", None), ("$8$", "Cisco IOS type 8 (PBKDF2)", 9200),
]


def identify_hash(h: str) -> list[str]:
    """Return candidate algorithm names for a hash string."""
    s = h.strip()
    for prefix, label, _mode in _PREFIX_FORMATS:
        if s.startswith(prefix):
            return [label]
    # NetNTLMv1/v2 captured hashes (user::domain:...:...).
    if re.match(r"^[^:]*::[^:]*:[0-9a-fA-F]{16,}:", s):
        if s.count(":") >= 5 and re.search(r":[0-9a-fA-F]{48,}$", s):
            return ["NetNTLMv2 (hashcat -m 5600)"]
        return ["NetNTLMv1 (hashcat -m 5500)"]
    if s.startswith("*") and re.fullmatch(r"\*[0-9A-Fa-f]{40}", s):
        return ["MySQL 4.1+ (SHA1(SHA1(pw)))"]
    if re.fullmatch(r"[0-9a-fA-F]{16}", s):
        return ["MySQL323 (old)", "LM-half", "CRC/DES"]
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return ["MD5", "NTLM", "MD4", "LM", "MD2"]
    if re.fullmatch(r"[0-9a-fA-F]{40}", s):
        return ["SHA1", "RIPEMD-160"]
    if re.fullmatch(r"[0-9a-fA-F]{56}", s):
        return ["SHA224", "SHA3-224"]
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return ["SHA256", "SHA3-256", "BLAKE2s", "Keccak-256"]
    if re.fullmatch(r"[0-9a-fA-F]{96}", s):
        return ["SHA384", "SHA3-384"]
    if re.fullmatch(r"[0-9a-fA-F]{128}", s):
        return ["SHA512", "SHA3-512", "BLAKE2b", "Whirlpool"]
    if re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", s):
        return ["JWT (JSON Web Token)"]
    if re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", s):
        return ["base64-encoded (not a raw hash)"]
    return ["unknown"]


def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 (OpenSSL 3 / LibreSSL drop it from the default provider,
    so hashlib.new('md4') is often unavailable). Used only for NTLM."""
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    ml = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += ml.to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    import struct as _st
    for off in range(0, len(msg), 64):
        x = list(_st.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in [0, 4, 8, 12]:
            a = lrot(a + ((b & c) | (~b & d)) + x[i], 3)
            d = lrot(d + ((a & b) | (~a & c)) + x[i + 1], 7)
            c = lrot(c + ((d & a) | (~d & b)) + x[i + 2], 11)
            b = lrot(b + ((c & d) | (~c & a)) + x[i + 3], 19)
        for i in [0, 1, 2, 3]:
            a = lrot(a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5A827999, 3)
            d = lrot(d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5A827999, 5)
            c = lrot(c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5A827999, 9)
            b = lrot(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5A827999, 13)
        for i in [0, 2, 1, 3]:
            a = lrot(a + (b ^ c ^ d) + x[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return _st.pack("<4I", a, b, c, d)


def _ntlm(password: str) -> str:
    raw = password.encode("utf-16le")
    try:
        # usedforsecurity=False: this hashes candidate passwords to CRACK a
        # captured NTLM (MD4) hash — modelling the attacker, not protecting data.
        return hashlib.new("md4", raw, usedforsecurity=False).hexdigest()
    except (ValueError, Exception):  # noqa: BLE001 — md4 often missing
        return _md4(raw).hex()


# usedforsecurity=False on every hasher: this table exists to RECOVER weak
# password hashes captured from a target, not to secure anything HEAVEN stores.
_RAW_HASHERS = {
    32: [("md5", lambda p: hashlib.md5(p.encode(), usedforsecurity=False).hexdigest()),
         ("ntlm", _ntlm)],
    40: [("sha1", lambda p: hashlib.sha1(p.encode(), usedforsecurity=False).hexdigest())],
    64: [("sha256", lambda p: hashlib.sha256(p.encode()).hexdigest())],
    128: [("sha512", lambda p: hashlib.sha512(p.encode()).hexdigest())],
}


def crack_hash(h: str, wordlist: list[str]) -> Optional[dict]:
    """Try each word against the hash. Return {plaintext, algorithm} or None."""
    s = h.strip()
    low = s.lower()

    # Unix crypt ($id$...) — verify via the crypt module.
    if s.startswith("$"):
        try:
            import crypt  # noqa: S415 — verification only, deprecated on 3.13
        except ImportError:
            crypt = None
        if crypt is not None:
            for w in wordlist:
                try:
                    if crypt.crypt(w, s) == s:
                        return {"plaintext": w, "algorithm": identify_hash(s)[0]}
                except Exception:
                    break
        return None

    hashers = _RAW_HASHERS.get(len(s))
    if not hashers:
        return None
    for w in wordlist:
        for algo, fn in hashers:
            try:
                if fn(w).lower() == low:
                    return {"plaintext": w, "algorithm": algo}
            except Exception:
                logger.debug("hasher %s failed on a candidate word", algo, exc_info=True)
                continue
    return None


def _decode_variants(s: str) -> list[dict]:
    out = []
    t = s.strip()
    # base64
    try:
        dec = base64.b64decode(t, validate=True)
        if dec and all(9 <= b < 127 or b in (10, 13) for b in dec):
            out.append({"scheme": "base64", "decoded": dec.decode("latin1")})
    except (binascii.Error, ValueError):
        pass
    # hex
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        try:
            dec = bytes.fromhex(t[2:] if t.startswith("0x") else t)
            if dec and all(9 <= b < 127 or b in (10, 13) for b in dec):
                out.append({"scheme": "hex", "decoded": dec.decode("latin1")})
        except ValueError:
            pass
    # base32
    try:
        dec = base64.b32decode(t)
        if dec and all(9 <= b < 127 or b in (10, 13) for b in dec):
            out.append({"scheme": "base32", "decoded": dec.decode("latin1")})
    except (binascii.Error, ValueError):
        pass
    # rot13
    if t.isascii() and any(c.isalpha() for c in t):
        out.append({"scheme": "rot13", "decoded": codecs.encode(t, "rot_13")})
    return out


def _parse_hash_lines(text: str) -> list[tuple[str, str]]:
    """Pull (user, hash) pairs from shadow / user:hash / bare-hash lines."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            parts = line.split(":")
            # /etc/shadow: user:$id$salt$hash:...   or  user:hash
            if len(parts) >= 2 and (parts[1].startswith("$") or
                                    re.fullmatch(r"[0-9a-fA-F]{16,}", parts[1] or "")):
                pairs.append((parts[0], parts[1]))
                continue
            # NTDS secretsdump: user:rid:lm:nt:::
            if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]{32}", parts[3] or ""):
                pairs.append((parts[0], parts[3]))
                continue
        if re.fullmatch(r"(\$.+|[0-9a-fA-F]{16,})", line):
            pairs.append(("", line))
    return pairs


def analyze_crypto(path: str, *, wordlist_path: Optional[str] = None,
                   decode_text: Optional[str] = None, **_: Any) -> dict[str, Any]:
    """Analyze a hash file (or decode a string). Returns report + findings."""
    if decode_text is not None:
        from heaven.forensics.decoder import smart_decode
        res = smart_decode(decode_text)
        report: dict[str, Any] = {"input": res["input"], "decodings": res["decodings"]}
        if res.get("jwt"):
            report["jwt"] = res["jwt"]
        if res.get("best"):
            report["best"] = res["best"]
        n = len(res["decodings"])
        best = res.get("best")
        jwt = res.get("jwt")
        if jwt and n == 0:
            summary = f"JWT decoded · alg: {jwt.get('alg') or 'unknown'}"
        else:
            summary = (f"{n} decoding(s)"
                       + (f" · best: {best['scheme']} ({int(best['confidence'] * 100)}%)"
                          if best else " · no confident decoding")
                       + (" · JWT" if jwt else ""))
        return {"report": report, "findings": res["findings"], "summary": summary}

    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    text = p.read_text(errors="replace")

    wordlist = list(_BUILTIN_WORDLIST)
    if wordlist_path:
        try:
            wl = Path(wordlist_path).read_text(errors="replace").splitlines()
            wordlist = [w.rstrip("\n") for w in wl if w.strip()][:5_000_000]
        except Exception as e:  # noqa: BLE001
            logger.warning("could not read wordlist: %s", e)

    pairs = _parse_hash_lines(text)
    results, cracked, weak = [], 0, 0
    for user, h in pairs:
        algos = identify_hash(h)
        is_weak = any(a in ("MD5", "SHA1", "NTLM", "LM-half") for a in algos)
        weak += 1 if is_weak else 0
        crk = crack_hash(h, wordlist)
        if crk:
            cracked += 1
        results.append({"user": user, "hash": h[:64], "algorithm": algos,
                        "weak_storage": is_weak, "cracked": crk})

    findings = []
    cracked_list = [r for r in results if r["cracked"]]
    if cracked_list:
        sample = ", ".join(f"{r['user'] or '?'}:{cast(dict, r['cracked'])['plaintext']}"
                           for r in cracked_list[:5])
        findings.append({
            "vuln_type": "weak_password_cracked", "severity": "high",
            "scanner": "crypto_analyzer", "confidence": 1.0,
            "title": f"{len(cracked_list)} password hash(es) cracked from a dictionary",
            "description": ("Password hashes were recovered to plaintext using a "
                            f"small dictionary in seconds. Examples: {sample}. Any "
                            "account whose hash falls this fast has an unacceptably "
                            "weak password."),
            "cwe": "CWE-521", "evidence": {"cracked": cracked_list[:50]},
            "remediation": "Enforce strong unique passwords, block common passwords, "
                           "and store with a slow salted KDF (bcrypt/argon2)."})
    if weak:
        findings.append({
            "vuln_type": "weak_hash_algorithm", "severity": "medium",
            "scanner": "crypto_analyzer", "confidence": 0.85,
            "title": f"{weak} hash(es) use a weak/unsalted algorithm (MD5/SHA1/NTLM)",
            "description": ("Fast unsalted hashes allow rapid offline cracking and "
                            "rainbow-table lookups."),
            "cwe": "CWE-916",
            "remediation": "Migrate to a slow salted password KDF (argon2id/bcrypt)."})

    return {"report": {"hashes": len(pairs), "cracked": cracked,
                       "weak_storage": weak, "results": results},
            "findings": findings,
            "summary": f"{len(pairs)} hash(es) · {cracked} cracked · {weak} weak"}

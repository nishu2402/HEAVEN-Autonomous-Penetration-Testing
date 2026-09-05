"""HEAVEN — offline X.509 certificate / key-material analysis.

Certificates (``.pem`` / ``.der`` / ``.crt`` / ``.cer``) and exported key files
turn up constantly in assessments — pulled from a TLS handshake, a firmware
image, a config backup, or a leaked bundle. This analyzer parses them offline
(no network) with the already-present ``cryptography`` library and reports the
posture problems that matter: an expired or not-yet-valid certificate, a weak
public key (RSA < 2048), a weak signature algorithm (MD5 / SHA-1), a self-signed
certificate, and — critically — a file that is actually private key material.

It never validates a chain against the internet or contacts a CA; everything is
derived from the bytes on disk.
"""

from __future__ import annotations

import datetime
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.certificate")

_WEAK_SIG = {"md5", "sha1", "md2", "md4"}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    """Coerce a possibly-naive datetime (older cryptography accessors) to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _not_after(cert: Any) -> datetime.datetime:
    try:
        return _aware(cert.not_valid_after_utc)
    except AttributeError:  # cryptography < 42
        return _aware(cert.not_valid_after)


def _not_before(cert: Any) -> datetime.datetime:
    try:
        return _aware(cert.not_valid_before_utc)
    except AttributeError:
        return _aware(cert.not_valid_before)


def _name(n: Any) -> str:
    try:
        return n.rfc4514_string()
    except Exception:  # noqa: BLE001
        return str(n)


def _key_info(cert: Any) -> tuple[str, int]:
    """Return (key_type, key_size_bits) for the certificate's public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA", pub.key_size
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return f"EC:{pub.curve.name}", pub.key_size
        return type(pub).__name__.replace("PublicKey", ""), getattr(pub, "key_size", 0)
    except Exception:  # noqa: BLE001
        return "unknown", 0


def _analyze_cert(cert: Any, path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []

    def add(vt: str, sev: str, title: str, desc: str, cwe: str = "",
            remediation: str = "") -> None:
        findings.append({
            "target": path, "vuln_type": vt, "severity": sev, "title": title,
            "description": desc, "scanner": "certificate_analyzer",
            "confidence": 0.95, "cwe": cwe, "remediation": remediation,
        })

    subject = _name(cert.subject)
    issuer = _name(cert.issuer)
    not_after = _not_after(cert)
    not_before = _not_before(cert)
    key_type, key_bits = _key_info(cert)
    try:
        sig_alg = (cert.signature_hash_algorithm.name or "").lower()
    except Exception:  # noqa: BLE001 — some algorithms (Ed25519) have none
        sig_alg = ""
    self_signed = subject == issuer
    now = _now()

    report = {
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "signature_algorithm": sig_alg or "unknown",
        "public_key": f"{key_type} {key_bits}-bit" if key_bits else key_type,
        "self_signed": self_signed,
        "version": getattr(cert.version, "name", str(cert.version)),
    }

    if not_after < now:
        days = (now - not_after).days
        add("certificate_expired", "medium", "Expired TLS certificate",
            f"The certificate expired {days} day(s) ago (notAfter "
            f"{not_after.date()}). Clients that enforce validity will refuse the "
            "connection; one that accepts it is not verifying expiry.",
            cwe="CWE-298",
            remediation="Reissue and deploy a current certificate; automate renewal.")
    elif not_before > now:
        add("certificate_not_yet_valid", "low", "Certificate not yet valid",
            f"notBefore is {not_before.date()}, in the future — the certificate "
            "is not valid yet and strict clients will reject it.",
            cwe="CWE-298",
            remediation="Check the issuing system clock and reissue if needed.")

    if key_type == "RSA" and 0 < key_bits < 2048:
        add("weak_certificate_key", "high",
            f"Weak certificate key (RSA {key_bits}-bit)",
            f"The certificate's RSA public key is only {key_bits} bits. Keys "
            "below 2048 bits are factorable by a resourced attacker, who could "
            "then impersonate the certificate holder.", cwe="CWE-326",
            remediation="Reissue with an RSA-2048+ or an ECDSA P-256 key.")

    if sig_alg in _WEAK_SIG:
        sev = "high" if sig_alg in ("md5", "md2", "md4") else "medium"
        add("weak_certificate_signature", sev,
            f"Weak certificate signature algorithm ({sig_alg.upper()})",
            f"The certificate is signed with {sig_alg.upper()}, which has "
            "practical collision attacks — a forged certificate can share the "
            "signature. Modern CAs sign with SHA-256 or better.", cwe="CWE-327",
            remediation="Reissue signed with SHA-256 (or SHA-384) and distrust the old one.")

    if self_signed:
        add("self_signed_certificate", "info", "Self-signed certificate",
            "The certificate's subject equals its issuer, so it is self-signed: "
            "no external CA vouches for it, and clients must be told explicitly to "
            "trust it. Acceptable for internal/pinned use, a warning sign on the "
            "public internet.", cwe="CWE-295",
            remediation="Use a CA-issued certificate for anything client-facing.")

    return report, findings


def analyze_certificate(path: str, **_: Any) -> dict[str, Any]:
    """Parse a certificate / key file and report its posture.

    Returns ``{"report": {...}, "findings": [...], "summary": "..."}`` like the
    other forensics analyzers. Gracefully degrades: a bundle reports every
    certificate in it, a private-key file is flagged as exposed key material, and
    unparseable ASN.1 comes back as a plain overview rather than an error.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": f"cannot read {path}: {e}"}

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return {"error": "cryptography library not available for certificate analysis"}

    certs: list[Any] = []
    is_pem = b"-----BEGIN" in data[:64] or b"-----BEGIN" in data
    # 1) Certificate(s): PEM bundle first (may hold a whole chain), then DER.
    try:
        if is_pem and hasattr(x509, "load_pem_x509_certificates"):
            certs = list(x509.load_pem_x509_certificates(data))
        elif is_pem:
            certs = [x509.load_pem_x509_certificate(data)]
        else:
            certs = [x509.load_der_x509_certificate(data)]
    except Exception:  # noqa: BLE001 — not a certificate; fall through to keys
        logger.debug("not an x509 certificate: %s", path, exc_info=True)

    if certs:
        reports: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        for c in certs:
            rep, fs = _analyze_cert(c, path)
            reports.append(rep)
            findings.extend(fs)
        lead = reports[0]
        summary = (f"X.509 · {lead['subject']} · {lead['public_key']} · "
                   f"sig={lead['signature_algorithm']} · expires {lead['not_after'][:10]}"
                   + (f" · +{len(reports) - 1} more in chain" if len(reports) > 1 else ""))
        return {"report": {"certificates": reports, "count": len(reports)},
                "findings": findings, "summary": summary}

    # 2) Private key material — a finding in its own right (exposed secret).
    for priv_loader in (serialization.load_pem_private_key,
                        serialization.load_der_private_key):
        try:
            key = priv_loader(data, password=None)
            ktype = type(key).__name__.replace("PrivateKey", "")
            bits = getattr(key, "key_size", 0)
            finding = {
                "target": path, "vuln_type": "exposed_private_key", "severity": "high",
                "title": f"Exposed private key ({ktype} {bits}-bit)".replace(" 0-bit", ""),
                "description": ("This file is private key material, not a certificate. "
                                "Anyone holding it can impersonate the owner and decrypt "
                                "traffic. Treat it as a compromised secret."),
                "scanner": "certificate_analyzer", "confidence": 0.95,
                "cwe": "CWE-312",
                "remediation": "Revoke and rotate the key; remove it from the artifact/repo.",
            }
            return {"report": {"key_type": ktype, "key_bits": bits},
                    "findings": [finding],
                    "summary": f"Private key material ({ktype} {bits}-bit)".replace(" 0-bit", "")}
        except Exception:  # noqa: BLE001 — try the next loader / fall through
            logger.debug("not a private key via %s: %s", priv_loader.__name__, path, exc_info=True)

    # 3) Public key, or ASN.1/DER we can't classify further — overview only.
    for pub_loader in (serialization.load_pem_public_key,
                       serialization.load_der_public_key):
        try:
            pubkey = pub_loader(data)
            ktype = type(pubkey).__name__.replace("PublicKey", "")
            bits = getattr(pubkey, "key_size", 0)
            return {"report": {"public_key": f"{ktype} {bits}-bit"}, "findings": [],
                    "summary": f"Public key ({ktype} {bits}-bit)".replace(" 0-bit", "")}
        except Exception:  # noqa: BLE001
            logger.debug("not a public key via %s: %s", pub_loader.__name__, path, exc_info=True)

    return {"report": {"note": "ASN.1/DER data (not a recognized certificate or key)"},
            "findings": [], "summary": "ASN.1/DER data"}

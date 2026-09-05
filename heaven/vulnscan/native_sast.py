"""HEAVEN — native, dependency-free SAST engine.

Semgrep is excellent and stays the primary SAST engine, but it is an external
binary that an air-gapped or minimal host may not have. This module is a
pure-Python static scanner that runs with zero external tools, so ``heaven sast``
always produces real findings. It also carries an always-on secret scanner
(pattern + Shannon-entropy) that catches hardcoded credentials Semgrep's default
packs miss.

It is honest about what it is: line-oriented pattern matching with light
same-line taint hints (a sink plus an attacker-source or string-building
operator on the same statement), not full inter-procedural dataflow. Confidence
is scored accordingly. Every finding points at a real file, line and code
excerpt read from disk.

Languages: Python, JavaScript/TypeScript, Java, PHP, Go, Ruby, C/C++.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger
from heaven.vulnscan.sast_runner import SastFinding, SastRunResult

logger = get_logger("vulnscan.native_sast")

_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 5000
_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv",
              "venv", "env", ".tox", "site-packages", "dist", "build",
              ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "vendor",
              "target", "bin", "obj"}

_PY = (".py", ".pyw")
_JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue")
_JAVA = (".java",)
_PHP = (".php", ".phtml", ".php5", ".inc")
_GO = (".go",)
_RB = (".rb", ".erb")
_C = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
_TEXT_EXTS = _PY + _JS + _JAVA + _PHP + _GO + _RB + _C + (
    ".yml", ".yaml", ".json", ".env", ".ini", ".cfg", ".conf", ".xml",
    ".properties", ".sh", ".tf", ".txt", ".toml")


def _ci(p: str) -> re.Pattern:
    return re.compile(p, re.I)


@dataclass(frozen=True)
class _Rule:
    id: str
    exts: tuple[str, ...]        # () = all languages
    pattern: re.Pattern
    severity: str
    title: str
    cwe: str
    owasp: str
    confidence: float
    why: str
    # optional: also require this pattern on the same line (crude taint hint)
    needs: Optional[re.Pattern] = None
    # optional: suppress if this pattern is on the same line (e.g. SafeLoader)
    unless: Optional[re.Pattern] = None


# Attacker-source and string-building hints used across languages.
_SRC_PHP = _ci(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)")
_BUILD = _ci(r"(\+|\.format|%\s|f['\"]|`|\$\{|fmt\.Sprintf|\.\.)")
_SECRETISH = _ci(r"(token|password|passwd|secret|api[_-]?key|nonce|salt|session|cookie)")

_OWASP_INJ = "A03:2025 Injection"
_OWASP_CRYPTO = "A02:2025 Cryptographic Failures"
_OWASP_SSRF = "A10:2025 Server-Side Request Forgery"
_OWASP_MISCFG = "A05:2025 Security Misconfiguration"
_OWASP_AUTHFAIL = "A07:2025 Authentication Failures"
_OWASP_DESER = "A08:2025 Software and Data Integrity Failures"

RULES: tuple[_Rule, ...] = (
    # ── Python ──
    _Rule("py-sql-injection", _PY,
          _ci(r"\.execute(?:many)?\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*%|['\"][^'\"]*['\"]\s*\.format|[^,)]*\+)"),
          "high", "SQL query built from a string (possible SQL injection)",
          "CWE-89", _OWASP_INJ, 0.6,
          "A DB cursor.execute() is called with an f-string / %-format / concatenation."),
    _Rule("py-command-injection", _PY,
          _ci(r"(os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\("),
          "high", "OS command execution", "CWE-78", _OWASP_INJ, 0.55,
          "A shell/command-exec sink; check the argument for attacker input.",
          needs=_ci(r"(\+|%|\.format|f['\"]|shell\s*=\s*True)")),
    _Rule("py-eval-exec", _PY, _ci(r"\b(eval|exec)\s*\("),
          "medium", "Dynamic code execution via eval/exec", "CWE-95", _OWASP_INJ, 0.5,
          "eval()/exec() run arbitrary code if the argument is influenced by input."),
    _Rule("py-pickle-load", _PY, _ci(r"\bpickle\.loads?\s*\("),
          "high", "Insecure deserialization (pickle)", "CWE-502", _OWASP_DESER, 0.65,
          "pickle.load(s) executes arbitrary code on untrusted data."),
    _Rule("py-yaml-load", _PY, _ci(r"\byaml\.load\s*\("),
          "high", "Unsafe yaml.load (use SafeLoader)", "CWE-502", _OWASP_DESER, 0.6,
          "yaml.load without SafeLoader can construct arbitrary Python objects.",
          unless=_ci(r"SafeLoader|Loader\s*=\s*yaml\.CSafeLoader")),
    _Rule("py-weak-hash", _PY, _ci(r"hashlib\.(md5|sha1)\s*\("),
          "low", "Weak hash function (MD5/SHA1)", "CWE-327", _OWASP_CRYPTO, 0.5,
          "MD5/SHA1 are broken for security use.",
          unless=_ci(r"usedforsecurity\s*=\s*False")),
    _Rule("py-weak-random", _PY, _ci(r"\brandom\.(random|randint|choice|randrange|getrandbits|sample)\b"),
          "medium", "Insecure RNG used for a secret", "CWE-330", _OWASP_CRYPTO, 0.5,
          "The random module is not cryptographically secure; use secrets/os.urandom.",
          needs=_SECRETISH),
    _Rule("py-tls-verify-off", _PY, _ci(r"verify\s*=\s*False"),
          "medium", "TLS certificate verification disabled", "CWE-295", _OWASP_MISCFG, 0.6,
          "verify=False disables certificate validation (MITM)."),
    _Rule("py-flask-debug", _PY, _ci(r"\.run\s*\([^)]*debug\s*=\s*True"),
          "low", "Flask debug mode enabled", "CWE-489", _OWASP_MISCFG, 0.55,
          "Werkzeug debugger allows RCE when reachable."),
    _Rule("py-tempfile-mktemp", _PY, _ci(r"\btempfile\.mktemp\s*\("),
          "low", "Insecure temp file (mktemp race)", "CWE-377", _OWASP_MISCFG, 0.6,
          "mktemp is race-prone; use mkstemp/NamedTemporaryFile."),
    _Rule("py-ssrf", _PY,
          _ci(r"(requests\.(get|post|put|delete|head|request)|urllib\.request\.urlopen|httpx\.(get|post))\s*\("),
          "medium", "Possible SSRF (request to a computed URL)", "CWE-918", _OWASP_SSRF, 0.4,
          "An HTTP client is called; verify the URL is not attacker-controlled.",
          needs=_ci(r"(request\.|params\[|args\[|\+|f['\"]|format\()")),

    # ── JavaScript / TypeScript ──
    _Rule("js-eval", _JS, _ci(r"\beval\s*\("),
          "medium", "Dynamic code execution via eval", "CWE-95", _OWASP_INJ, 0.5,
          "eval() runs arbitrary JS."),
    _Rule("js-child-process", _JS, _ci(r"child_process\.(exec|execSync)\s*\("),
          "high", "OS command execution (child_process.exec)", "CWE-78", _OWASP_INJ, 0.6,
          "exec runs a shell; concatenated input is command injection.",
          needs=_ci(r"(\+|`|\$\{)")),
    _Rule("js-innerhtml", _JS, _ci(r"\.innerHTML\s*=\s*[^'\"]"),
          "medium", "DOM XSS sink (innerHTML assignment)", "CWE-79", _OWASP_INJ, 0.45,
          "Assigning non-literal HTML to innerHTML can inject script."),
    _Rule("js-document-write", _JS, _ci(r"document\.write(ln)?\s*\("),
          "low", "DOM XSS sink (document.write)", "CWE-79", _OWASP_INJ, 0.4,
          "document.write with input reflects unsanitized HTML."),
    _Rule("js-sql", _JS, _ci(r"\.(query|execute)\s*\(\s*[`'\"][^`'\"]*(\$\{|['\"]\s*\+)"),
          "high", "SQL query built from a template/concatenation", "CWE-89", _OWASP_INJ, 0.55,
          "A SQL string is built with template interpolation/concatenation."),
    _Rule("js-tls-reject-off", _JS, _ci(r"rejectUnauthorized\s*:\s*false"),
          "medium", "TLS verification disabled (rejectUnauthorized:false)", "CWE-295",
          _OWASP_MISCFG, 0.65, "Node TLS certificate checks are disabled."),
    _Rule("js-weak-random", _JS, _ci(r"Math\.random\s*\("),
          "low", "Insecure RNG used for a secret", "CWE-330", _OWASP_CRYPTO, 0.45,
          "Math.random is not cryptographically secure.", needs=_SECRETISH),
    _Rule("js-settimeout-string", _JS, _ci(r"set(Timeout|Interval)\s*\(\s*['\"]"),
          "low", "Code execution via string setTimeout/setInterval", "CWE-95",
          _OWASP_INJ, 0.4, "A string first-arg is eval'd."),

    # ── Java ──
    _Rule("java-runtime-exec", _JAVA, _ci(r"Runtime\.getRuntime\(\)\.exec\s*\("),
          "high", "OS command execution (Runtime.exec)", "CWE-78", _OWASP_INJ, 0.6,
          "Runtime.exec runs an external command."),
    _Rule("java-sql", _JAVA, _ci(r"\.(executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+"),
          "high", "SQL built by concatenation", "CWE-89", _OWASP_INJ, 0.6,
          "A JDBC statement concatenates a string into SQL; use PreparedStatement."),
    _Rule("java-deserialization", _JAVA, _ci(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\("),
          "high", "Java deserialization of untrusted data", "CWE-502", _OWASP_DESER, 0.55,
          "ObjectInputStream.readObject on untrusted data enables RCE gadget chains."),
    _Rule("java-weak-cipher", _JAVA, _ci(r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|RC4|.*ECB.*|AES/ECB.*)\""),
          "medium", "Weak/ECB cipher", "CWE-327", _OWASP_CRYPTO, 0.6,
          "DES/RC4/ECB are insecure; use AES-GCM."),
    _Rule("java-weak-hash", _JAVA, _ci(r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\""),
          "low", "Weak hash function", "CWE-327", _OWASP_CRYPTO, 0.55,
          "MD5/SHA1 are broken for security use."),
    _Rule("java-xxe", _JAVA,
          _ci(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance"),
          "medium", "XML parser may be XXE-vulnerable", "CWE-611", _OWASP_INJ, 0.4,
          "The XML factory must disable DOCTYPE/external entities."),
    _Rule("java-trust-all", _JAVA, _ci(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"),
          "medium", "TrustManager accepts all certificates", "CWE-295", _OWASP_MISCFG, 0.6,
          "An empty checkServerTrusted disables TLS validation."),

    # ── PHP ──
    _Rule("php-command-injection", _PHP,
          _ci(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
          "critical", "OS command execution with user input", "CWE-78", _OWASP_INJ, 0.7,
          "A PHP command-exec sink receives request data.", needs=_SRC_PHP),
    _Rule("php-sql-injection", _PHP,
          _ci(r"(mysql_query|mysqli_query|->query|->exec)\s*\("),
          "high", "SQL query with user input", "CWE-89", _OWASP_INJ, 0.65,
          "A SQL query embeds superglobal request data.", needs=_SRC_PHP),
    _Rule("php-file-inclusion", _PHP,
          _ci(r"\b(include|require)(_once)?\s*\(?\s*.*\$_(GET|POST|REQUEST|COOKIE)"),
          "high", "Local/Remote file inclusion", "CWE-98", _OWASP_INJ, 0.7,
          "include/require of a request-controlled path (LFI/RFI)."),
    _Rule("php-deserialization", _PHP, _ci(r"\bunserialize\s*\("),
          "high", "PHP object injection (unserialize)", "CWE-502", _OWASP_DESER, 0.6,
          "unserialize on request data enables PHP object injection.", needs=_SRC_PHP),
    _Rule("php-eval", _PHP, _ci(r"\beval\s*\("),
          "high", "Dynamic code execution via eval", "CWE-95", _OWASP_INJ, 0.6,
          "eval() runs arbitrary PHP."),
    _Rule("php-xss-echo", _PHP, _ci(r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST)"),
          "high", "Reflected XSS (echo of request data)", "CWE-79", _OWASP_INJ, 0.6,
          "Request data is echoed without encoding."),
    _Rule("php-weak-hash", _PHP, _ci(r"\b(md5|sha1)\s*\("),
          "low", "Weak hash function", "CWE-327", _OWASP_CRYPTO, 0.45,
          "MD5/SHA1 are broken for security use."),

    # ── Go ──
    _Rule("go-command-injection", _GO, _ci(r"exec\.Command\s*\("),
          "high", "OS command execution (exec.Command)", "CWE-78", _OWASP_INJ, 0.5,
          "exec.Command with a computed argument can inject commands.",
          needs=_ci(r"(fmt\.Sprintf|\+|os\.Args|r\.(URL|Form))")),
    _Rule("go-sql", _GO, _ci(r"\.(Query|QueryRow|Exec)\s*\(\s*(fmt\.Sprintf|\"[^\"]*\"\s*\+)"),
          "high", "SQL built by concatenation/Sprintf", "CWE-89", _OWASP_INJ, 0.6,
          "Build SQL with parameter placeholders, not Sprintf/concatenation."),
    _Rule("go-tls-insecure", _GO, _ci(r"InsecureSkipVerify\s*:\s*true"),
          "medium", "TLS verification disabled (InsecureSkipVerify)", "CWE-295",
          _OWASP_MISCFG, 0.65, "TLS certificate validation is turned off."),
    _Rule("go-weak-hash", _GO, _ci(r"(md5|sha1)\.(New|Sum)\s*\("),
          "low", "Weak hash function", "CWE-327", _OWASP_CRYPTO, 0.45,
          "MD5/SHA1 are broken for security use."),

    # ── Ruby ──
    _Rule("rb-command-injection", _RB, _ci(r"(system|exec|`|%x|Open3\.|IO\.popen)\s*[\(`]"),
          "high", "OS command execution", "CWE-78", _OWASP_INJ, 0.45,
          "A Ruby command-exec sink; verify the argument.", needs=_BUILD),
    _Rule("rb-eval", _RB, _ci(r"\b(eval|instance_eval|class_eval)\s*\("),
          "medium", "Dynamic code execution via eval", "CWE-95", _OWASP_INJ, 0.5,
          "eval runs arbitrary Ruby."),
    _Rule("rb-yaml-load", _RB, _ci(r"YAML\.load\s*\("),
          "high", "Unsafe YAML.load", "CWE-502", _OWASP_DESER, 0.55,
          "YAML.load can instantiate arbitrary objects; use safe_load."),

    # ── C / C++ ──
    _Rule("c-dangerous-func", _C,
          _ci(r"\b(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|system|popen)\s*\("),
          "high", "Memory-unsafe / command-exec C function", "CWE-676", _OWASP_INJ, 0.55,
          "Unbounded string ops (gets/strcpy/…) and system() are classic overflow/"
          "command-injection sinks."),
)

# Secrets: (label, regex over the whole line, severity, requires-entropy).
_SECRET_RULES: tuple[tuple[str, re.Pattern, str, bool], ...] = (
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "high", False),
    ("AWS secret access key",
     re.compile(r"(?i)aws.{0,20}(secret|access).{0,20}['\"][A-Za-z0-9/+=]{40}['\"]"), "high", True),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high", False),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "high", False),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high", False),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), "high", False),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical", False),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"), "medium", False),
    ("Generic hardcoded credential",
     re.compile(r"""(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]([^'"\s]{8,80})['"]"""),
     "medium", True),
)
_SECRET_PLACEHOLDERS = re.compile(
    r"(?i)(example|placeholder|changeme|your[_-]?|xxx+|dummy|sample|redacted|<[^>]+>|\$\{|process\.env|getenv|os\.environ)")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _exts_for(path: str) -> str:
    return Path(path).suffix.lower()


def scan_text(file_path: str, text: str) -> list[SastFinding]:
    """Scan one file's text and return native SAST findings."""
    ext = _exts_for(file_path)
    findings: list[SastFinding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        if len(line) > 1000:
            line = line[:1000]
        stripped = line.strip()
        if not stripped:
            continue
        is_comment = stripped.startswith(("#", "//", "*", "/*", "--"))

        # ── code rules ──
        for rule in RULES:
            if rule.exts and ext not in rule.exts:
                continue
            if is_comment:
                continue
            if not rule.pattern.search(line):
                continue
            if rule.needs and not rule.needs.search(line):
                continue
            if rule.unless and rule.unless.search(line):
                continue
            findings.append(SastFinding(
                rule_id=f"heaven.native.{rule.id}",
                severity=rule.severity, title=rule.title,
                description=rule.why, file_path=file_path,
                line=lineno, column=max(1, line.find(stripped) + 1),
                code_excerpt=stripped[:300], cwe=rule.cwe, owasp=rule.owasp,
                confidence=rule.confidence,
                metadata={"engine": "native", "language": ext.lstrip(".")}))

        # ── secret rules (all files) ──
        for label, rx, sev, need_entropy in _SECRET_RULES:
            m = rx.search(line)
            if not m:
                continue
            value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            if _SECRET_PLACEHOLDERS.search(value):
                continue
            if need_entropy and _shannon(value) < 3.0:
                continue
            findings.append(SastFinding(
                rule_id="heaven.native.hardcoded-secret",
                severity=sev, title=f"Hardcoded secret: {label}",
                description=f"A {label} appears hardcoded in source. Anyone with "
                            "the code can read it; rotate and move it to a secret store.",
                file_path=file_path, line=lineno,
                column=max(1, m.start() + 1),
                code_excerpt=(stripped[:60] + " …")[:300],
                cwe="CWE-798", owasp=_OWASP_AUTHFAIL, confidence=0.6,
                metadata={"engine": "native", "secret_type": label}))
    return findings


def run_native_sast(source_path: str, *, include_secrets: bool = True,
                    max_files: int = _MAX_FILES) -> SastRunResult:
    """Walk ``source_path`` and run the native SAST + secret scan (no semgrep)."""
    t0 = time.time()
    result = SastRunResult(success=False)
    src = Path(source_path)
    if not src.exists():
        result.error = f"path not found: {source_path}"
        return result

    candidates: list[Path] = []
    if src.is_file():
        candidates = [src]
    else:
        for p in src.rglob("*"):
            if len(candidates) >= max_files:
                break
            if p.is_dir() or any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() in _TEXT_EXTS:
                candidates.append(p)

    scanned = 0
    for p in candidates:
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        fnd = scan_text(str(p), text)
        if not include_secrets:
            fnd = [f for f in fnd if f.rule_id != "heaven.native.hardcoded-secret"]
        result.findings.extend(fnd)

    result.files_scanned = scanned
    result.duration_s = time.time() - t0
    result.semgrep_version = "native"
    result.success = True
    logger.info("native sast: %d finding(s) across %d file(s) in %.2fs",
                len(result.findings), scanned, result.duration_s)
    return result

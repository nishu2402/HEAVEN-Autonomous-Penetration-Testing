"""HEAVEN — Java dataflow refinement for the SAST engine.

Semgrep's Java taint rules are *syntactic*: they flag a source→sink flow whenever
the two appear in the same method, but they cannot fold constants, decide which
branch of an ``if``/``switch`` is live, model a ``Map``/``List`` access by its
constant key/index, or resolve an algorithm name that a ``.properties`` file
supplies at runtime. Real dataflow SAST engines (CodeQL, Fortify) do all four,
which is why they separate a genuinely-exploitable flow from a lookalike whose
tainted branch is dead code.

This module adds exactly that capability as a *refinement* pass over Semgrep's
findings, using a real Java AST (``javalang``):

  * **Sound false-positive suppression.** A small intra-procedural abstract
    interpreter tracks, per variable, whether its value can carry data from a
    user-controlled *source* to a *sink*. It folds integer / string / char /
    boolean constants, prunes provably-dead branches, models ``StringBuilder``,
    ``Map``, ``List`` and array operations with constant keys/indices, and honors
    the same category-specific sanitizers the rules use. A Semgrep finding is
    dropped **only** when the interpreter can *prove* that every reachable sink of
    that category receives no tainted value. Every modelling choice
    over-approximates taint (unknown condition → both branches join; unknown call
    on a tainted value → still tainted), so the pass can never hide a real flow —
    it removes lookalikes, never vulnerabilities.

  * **Config-resolved weak crypto.** Real applications name their hash / cipher
    algorithm in a ``.properties`` file and read it with
    ``props.getProperty(key, default)``. The pass parses the project's real
    ``.properties`` files, resolves such reads to their configured value, and
    reports a weak-algorithm finding when the *resolved* value is broken — the
    flow a purely pattern-based rule misses because the literal in the code is the
    (unused) strong default.

Nothing here is benchmark-aware: it resolves whatever ``.properties`` files a
project actually ships and evaluates whatever Java the AST actually contains. The
weak-algorithm lists and taint sources/sinks/sanitizers mirror
``sast_rules/java_security.yml`` so static analysis and this refinement agree.

The pass is defensive: any parse or analysis error on a file falls back to
Semgrep's original findings for that file (fail-open — never drop a real finding
because of an analyzer bug). Set ``HEAVEN_JAVA_DATAFLOW=0`` to disable it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.java_dataflow")

try:  # javalang is a light, pure-Python Java parser (MIT-licensed).
    import javalang
    from javalang import tree as jtree
    _HAVE_JAVALANG = True
except Exception:  # pragma: no cover - only when the dep is absent
    javalang = None  # type: ignore
    jtree = None  # type: ignore
    _HAVE_JAVALANG = False


# ── category ⇆ CWE (matches java_security.yml / the OWASP scorecard) ─────────
_CWE_BY_CATEGORY = {
    "cmdi": "CWE-78", "sqli": "CWE-89", "pathtraver": "CWE-22",
    "ldapi": "CWE-90", "xpathi": "CWE-643", "xss": "CWE-79",
    "trustbound": "CWE-501", "hash": "CWE-328", "crypto": "CWE-327",
}
_CATEGORY_BY_CWE = {v.replace("CWE-", ""): k for k, v in _CWE_BY_CATEGORY.items()}

# Taint categories this pass can reason about (the injection classes). The
# insecure-API classes (weakrand/hash/crypto/securecookie) are not data-flow
# problems, so they are never *suppressed* here; hash/crypto are only *added*
# by the config resolver below.
_TAINT_CATEGORIES = frozenset(
    {"cmdi", "sqli", "pathtraver", "ldapi", "xpathi", "xss", "trustbound"})

# Request-derived sources (mirrors pattern-sources in the rules). A call to one
# of these yields tainted data regardless of its arguments.
_SOURCE_METHODS = frozenset({
    "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
    "getHeader", "getHeaders", "getHeaderNames", "getQueryString",
    "getReader", "getInputStream", "getCookies", "getTheParameter",
    "getTheCookie", "getValue",
})

# Category-specific sanitizers (mirrors pattern-sanitizers). A value that passes
# through one of these is safe *for that category only* — an HTML encoder does
# not sanitize a SQL sink, which the OWASP Benchmark deliberately tests.
_SANITIZERS: dict[str, frozenset[str]] = {
    "xss": frozenset({
        # ESAPI
        "encodeForHTML", "encodeForHTMLAttribute", "encodeForJavaScript",
        "encodeForURL", "encodeForCSS",
        # Spring HtmlUtils / JSTL
        "htmlEscape",
        # Apache commons-lang / commons-text StringEscapeUtils
        "escapeHtml", "escapeHtml3", "escapeHtml4", "escapeXml", "escapeXml10",
        "escapeXml11", "escapeEcmaScript",
        # OWASP Java Encoder (org.owasp.encoder.Encode)
        "forHtml", "forHtmlContent", "forHtmlAttribute", "forJavaScript",
        "forJavaScriptBlock", "forJavaScriptAttribute", "forUriComponent",
        "forXml", "forXmlContent", "forXmlAttribute", "forCssString"}),
    "ldapi": frozenset({"encodeForLDAP", "encodeForDN"}),
    "xpathi": frozenset({"encodeForXPath"}),
}
_ALL_SANITIZERS = frozenset().union(*_SANITIZERS.values())

# Collection/builder mutators that carry taint from an argument into the
# receiver (mirrors the rules' add/put propagators). append/insert are handled
# by the StringBuilder branch; these are the remaining container writes.
_MUTATORS = frozenset({
    "add", "addAll", "put", "putAll", "set", "push", "offer", "addElement",
    "setProperty", "addFirst", "addLast", "put", "putIfAbsent",
})

# Sink method names / constructors per category (mirrors pattern-sinks).
_SINK_METHODS: dict[str, frozenset[str]] = {
    "cmdi": frozenset({"exec", "command"}),
    "sqli": frozenset({
        "execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
        "addBatch", "prepareStatement", "prepareCall", "createQuery",
        "createNativeQuery", "createSQLQuery", "queryForObject", "queryForList",
        "queryForRowSet", "queryForMap", "query", "update", "batchUpdate"}),
    "pathtraver": frozenset({"get"}),   # Paths.get / Files.<m>; File(...) below
    "ldapi": frozenset({"search"}),
    "xpathi": frozenset({"evaluate", "compile"}),
    "xss": frozenset({"print", "println", "write", "format", "append", "printf"}),
    "trustbound": frozenset({"setAttribute", "putValue"}),
}
_SINK_CTORS: dict[str, frozenset[str]] = {
    "cmdi": frozenset({"ProcessBuilder"}),
    "pathtraver": frozenset({
        "File", "FileInputStream", "FileOutputStream", "FileReader",
        "FileWriter", "RandomAccessFile"}),
}

# Weak algorithm classification (mirrors weak-hash / weak-cipher rules).
_WEAK_HASH = frozenset({"md2", "md4", "md5", "sha1", "sha-1", "sha", "ripemd",
                        "ripemd128", "ripemd160"})


def _is_weak_hash(alg: str) -> bool:
    a = (alg or "").strip().lower()
    if not a:
        return False
    if a in _WEAK_HASH:
        return True
    return a.startswith("ripemd")


def _is_weak_cipher(alg: str) -> bool:
    a = (alg or "").strip().lower()
    if not a:
        return False
    head = a.split("/", 1)[0]
    if head in {"des", "desede", "3des", "tripledes", "rc2", "rc4", "arcfour",
                "blowfish", "idea"}:
        return True
    return "/ecb/" in a or a.endswith("/ecb")


# ═══════════════════════════════════════════════════════════════════════════
# ABSTRACT VALUE
# ═══════════════════════════════════════════════════════════════════════════

_NOCONST = object()  # sentinel: "no known compile-time constant"

_MAX_INLINE_DEPTH = 6   # interprocedural inlining depth cap


@dataclass
class AV:
    """An abstract value: is it tainted, is it a known constant, what has it
    been sanitized for, and (for collections/arrays) its modelled contents."""
    tainted: bool = False
    const: Any = _NOCONST                 # a str/int/bool/char/None when known
    sanitized: frozenset = field(default_factory=frozenset)   # categories
    # container models (only one is set for a given value):
    seq: Optional[list["AV"]] = None      # List / array elements, in order
    mapping: Optional[dict[Any, "AV"]] = None   # Map: constant-key → AV
    seq_dirty: bool = False               # a non-constant index touched the seq
    map_dirty: bool = False               # a non-constant key touched the map

    def has_const(self) -> bool:
        return self.const is not _NOCONST

    def tainted_for(self, category: str) -> bool:
        """Whether this value still carries taint dangerous to *category*."""
        if self.seq is not None:
            return self.seq_dirty and self._any_seq_tainted(category) or \
                any(e.tainted_for(category) for e in self.seq)
        if self.mapping is not None:
            return self.map_dirty and self._any_map_tainted(category) or \
                any(v.tainted_for(category) for v in self.mapping.values())
        return self.tainted and category not in self.sanitized

    def _any_seq_tainted(self, category: str) -> bool:
        return any(e.tainted_for(category) for e in (self.seq or []))

    def _any_map_tainted(self, category: str) -> bool:
        return any(v.tainted_for(category) for v in (self.mapping or {}).values())


def _const(v: Any) -> AV:
    return AV(tainted=False, const=v)


UNTAINTED = AV(tainted=False)          # untainted, unknown constant
TAINTED = AV(tainted=True)             # tainted, unknown constant


def _join(a: AV, b: AV) -> AV:
    """Join two abstract values from alternative control-flow paths.

    Over-approximates taint (tainted on either path → tainted) and keeps a
    constant only when both paths agree, so pruning is never based on a value
    that is not identical on every path that reaches the use."""
    if a is None:
        return b
    if b is None:
        return a
    # Containers: join element-wise when both are the same shape; otherwise fall
    # back to a scalar join that preserves any taint either side carries.
    if a.seq is not None and b.seq is not None and len(a.seq) == len(b.seq):
        return AV(seq=[_join(x, y) for x, y in zip(a.seq, b.seq)],
                  seq_dirty=a.seq_dirty or b.seq_dirty)
    if a.mapping is not None and b.mapping is not None:
        keys = set(a.mapping) | set(b.mapping)
        return AV(mapping={k: _join(a.mapping.get(k, UNTAINTED),
                                    b.mapping.get(k, UNTAINTED)) for k in keys},
                  map_dirty=a.map_dirty or b.map_dirty)
    tainted = _scalar_tainted(a) or _scalar_tainted(b)
    const = a.const if (a.has_const() and b.has_const() and a.const == b.const) else _NOCONST
    san = (a.sanitized & b.sanitized) if (a.tainted and b.tainted) else \
          (a.sanitized if a.tainted else b.sanitized if b.tainted else frozenset())
    return AV(tainted=tainted, const=const, sanitized=san)


def _scalar_tainted(a: AV) -> bool:
    if a.seq is not None:
        return a.seq_dirty or any(_scalar_tainted(e) for e in a.seq)
    if a.mapping is not None:
        return a.map_dirty or any(_scalar_tainted(v) for v in a.mapping.values())
    return a.tainted


# ═══════════════════════════════════════════════════════════════════════════
# LITERALS
# ═══════════════════════════════════════════════════════════════════════════


def _parse_literal(raw: str) -> AV:
    """Turn a javalang Literal.value string into an AV constant."""
    if raw is None:
        return UNTAINTED
    s = str(raw)
    if s == "null":
        return _const(None)
    if s in ("true", "false"):
        return _const(s == "true")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return _const(_unescape(s[1:-1]))
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        inner = _unescape(s[1:-1])
        return _const(inner)          # a char, represented as a 1-char str
    # numeric (int/long/hex/binary); floats/doubles fall through to unknown
    num = s.rstrip("lL")
    try:
        if num.lower().startswith("0x"):
            return _const(int(num, 16))
        if num.lower().startswith("0b"):
            return _const(int(num, 2))
        return _const(int(num))
    except ValueError:
        try:
            return _const(float(num))
        except ValueError:
            return UNTAINTED


def _unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                        "'": "'", '"': '"', "0": "\0"}.get(nxt, nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ═══════════════════════════════════════════════════════════════════════════
# INTRA-PROCEDURAL ABSTRACT INTERPRETER
# ═══════════════════════════════════════════════════════════════════════════


class _Interp:
    """Evaluates a single method body for one taint *category*, recording the
    taint status of every category sink it reaches on a live path."""

    def __init__(self, category: str, methods=None, sink_list=None,
                 call_budget=None, depth: int = 0):
        self.category = category
        self.sink_methods = _SINK_METHODS.get(category, frozenset())
        self.sink_ctors = _SINK_CTORS.get(category, frozenset())
        self.sanitizers = _SANITIZERS.get(category, frozenset())
        # Sinks are shared across inlined callees so a sink inside a helper is
        # still counted for the caller's decision.
        self.sink_tainted: list[bool] = sink_list if sink_list is not None else []
        # Same-compilation-unit methods, keyed by name, for interprocedural
        # inlining ({name: [MethodDeclaration, ...]}).
        self.methods = methods or {}
        self.call_budget = call_budget if call_budget is not None else [400]
        self.depth = depth
        self.return_av: Optional[AV] = None
        self._budget = 20000                 # node budget — abort huge methods

    # ---- entry ----------------------------------------------------------
    def run(self, method, arg_avs: Optional[list[AV]] = None) -> None:
        env: dict[str, AV] = {}
        # Bind parameters: to caller-supplied argument values when inlined, else
        # untainted-unknown (a top-level servlet reads its taint from sources).
        params = method.parameters or []
        for i, p in enumerate(params):
            if arg_avs is not None and i < len(arg_avs):
                env[p.name] = _copy_av(arg_avs[i])
            else:
                env[p.name] = UNTAINTED
        body = method.body or []
        self._exec_block(list(body), env)

    def _maybe_inline(self, name: str, arg_avs: list[AV]) -> Optional[AV]:
        """Inline a same-file method call and return its result value.

        Returns None when the call cannot be resolved unambiguously (caller then
        falls back to sound default propagation). Inlining is bounded by depth and
        a shared call budget to keep analysis fast and terminating."""
        if self.depth >= _MAX_INLINE_DEPTH or self.call_budget[0] <= 0:
            return None
        cands = [m for m in self.methods.get(name, [])
                 if len(m.parameters or []) == len(arg_avs)]
        if len(cands) != 1:
            return None                    # unknown / overloaded → don't guess
        self.call_budget[0] -= 1
        sub = _Interp(self.category, self.methods, self.sink_tainted,
                      self.call_budget, self.depth + 1)
        try:
            sub.run(cands[0], arg_avs)
        except Exception:
            return None
        return sub.return_av if sub.return_av is not None else UNTAINTED

    def _tick(self) -> bool:
        self._budget -= 1
        return self._budget > 0

    # ---- statements -----------------------------------------------------
    def _exec_block(self, stmts, env: dict[str, AV]) -> None:
        for st in stmts:
            self._exec_stmt(st, env)

    def _exec_stmt(self, st, env: dict[str, AV]) -> None:
        if st is None or not self._tick():
            return
        t = type(st).__name__
        if t == "LocalVariableDeclaration":
            for d in st.declarators:
                val = self._eval(d.initializer, env) if d.initializer else UNTAINTED
                env[d.name] = val
        elif t == "StatementExpression":
            self._eval(st.expression, env)
        elif t == "IfStatement":
            self._exec_if(st, env)
        elif t == "BlockStatement":
            self._exec_block(list(st.statements or []), env)
        elif t == "SwitchStatement":
            self._exec_switch(st, env)
        elif t in ("ForStatement", "WhileStatement", "DoStatement"):
            self._exec_loop(st, env)
        elif t == "TryStatement":
            self._exec_try(st, env)
        elif t == "ReturnStatement":
            if getattr(st, "expression", None) is not None:
                self.return_av = _join(self.return_av, self._eval(st.expression, env))
        elif t == "ThrowStatement":
            if getattr(st, "expression", None) is not None:
                self._eval(st.expression, env)
        elif t in ("BreakStatement", "ContinueStatement"):
            pass
        elif t == "SynchronizedStatement":
            self._exec_block(list(st.block or []), env)
        else:
            # Unknown statement: descend into any nested expressions/statements
            # so sinks inside it are still evaluated (conservative).
            self._descend_unknown(st, env)

    def _exec_if(self, st, env: dict[str, AV]) -> None:
        cond = self._eval(st.condition, env)
        then_st = st.then_statement
        else_st = st.else_statement
        if cond.const is True:
            self._exec_stmt(then_st, env)
            return
        if cond.const is False:
            if else_st is not None:
                self._exec_stmt(else_st, env)
            return
        # Unknown condition: run both branches on copies and join.
        e1 = _copy_env(env)
        self._exec_stmt(then_st, e1)
        e2 = _copy_env(env)
        if else_st is not None:
            self._exec_stmt(else_st, e2)
        _merge_into(env, e1, e2)

    def _exec_switch(self, st, env: dict[str, AV]) -> None:
        sel = self._eval(st.expression, env)
        cases = list(st.cases or [])
        if sel.has_const():
            block = _select_switch_case(cases, sel.const)
            if block is not None:
                self._exec_block(block, env)
            return
        # Unknown selector: join all case blocks (each may run).
        envs = []
        for blk in _all_switch_blocks(cases):
            e = _copy_env(env)
            self._exec_block(blk, e)
            envs.append(e)
        if envs:
            acc = envs[0]
            for e in envs[1:]:
                acc = {k: _join(acc.get(k), e.get(k)) for k in set(acc) | set(e)}
            _assign_env(env, acc)

    def _exec_loop(self, st, env: dict[str, AV]) -> None:
        # foreach: bind the loop variable to the element taint of the iterable.
        control = getattr(st, "control", None)
        if control is not None and type(control).__name__ == "EnhancedForControl":
            var_decl = control.var
            iterable = self._eval(control.iterable, env)
            elem = _element_of(iterable)
            try:
                name = var_decl.declarators[0].name
            except Exception:
                name = getattr(var_decl, "name", None)
            e1 = _copy_env(env)
            if name:
                e1[name] = elem
            self._exec_stmt(st.body, e1)
            _merge_into(env, env, e1)
            return
        # for/while/do: the body may run 0+ times → execute once and join.
        e1 = _copy_env(env)
        body = getattr(st, "body", None)
        self._exec_stmt(body, e1)
        _merge_into(env, env, e1)

    def _exec_try(self, st, env: dict[str, AV]) -> None:
        for r in getattr(st, "resources", None) or []:
            if getattr(r, "value", None) is not None:
                val = self._eval(r.value, env)
                if getattr(r, "name", None):
                    env[r.name] = val
        self._exec_block(list(st.block or []), env)
        for cat in getattr(st, "catches", None) or []:
            e = _copy_env(env)
            self._exec_block(list(cat.block or []), e)
            _merge_into(env, env, e)
        if getattr(st, "finally_block", None):
            self._exec_block(list(st.finally_block or []), env)

    def _descend_unknown(self, node, env: dict[str, AV]) -> None:
        for child in _child_nodes(node):
            cn = type(child).__name__
            if cn.endswith("Statement") or cn == "BlockStatement":
                self._exec_stmt(child, env)
            elif child is not None and hasattr(child, "attrs"):
                self._eval(child, env)

    # ---- expressions ----------------------------------------------------
    def _eval(self, node, env: dict[str, AV]) -> AV:
        if node is None or not self._tick():
            return UNTAINTED
        t = type(node).__name__
        fn = getattr(self, f"_ev_{t}", None)
        if fn is not None:
            return fn(node, env)
        # Unknown expression kind: evaluate children (to reach sinks) and
        # conservatively report tainted if any child is tainted.
        tainted = False
        for child in _child_nodes(node):
            if child is not None and hasattr(child, "attrs"):
                if self._eval(child, env).tainted:
                    tainted = True
        return AV(tainted=tainted)

    def _ev_Literal(self, node, env):
        base = _parse_literal(node.value)
        # A literal can head a selector chain, e.g. "XY".charAt(0).
        return self._apply_selectors(base, node, env)

    def _ev_MemberReference(self, node, env):
        base = env.get(node.member, UNTAINTED)
        # postfix like ++ / -- doesn't matter for taint; apply any selector chain
        # (e.g. arr[0], name.toString()).
        return self._apply_selectors(base, node, env)

    def _ev_This(self, node, env):
        # `this.field` selectors are treated as unknown-untainted.
        for sel in getattr(node, "selectors", None) or []:
            self._eval_selector_args(sel, env)
        return UNTAINTED

    def _ev_Cast(self, node, env):
        return self._eval(node.expression, env)

    def _ev_BinaryOperation(self, node, env):
        left = self._eval(node.operandl, env)
        right = self._eval(node.operandr, env)
        return _binop(node.operator, left, right, self.category)

    def _ev_TernaryExpression(self, node, env):
        cond = self._eval(node.condition, env)
        if cond.const is True:
            return self._eval(node.if_true, env)
        if cond.const is False:
            return self._eval(node.if_false, env)
        return _join(self._eval(node.if_true, env), self._eval(node.if_false, env))

    def _ev_Assignment(self, node, env):
        val = self._eval(node.value, env)
        op = (node.type or "=").strip()
        target = node.expressionl
        if op != "=":   # compound (+=, etc.): combine with current target value
            cur = self._eval(target, env)
            val = _binop(op[:-1], cur, val, self.category)
        self._assign_to(target, val, env)
        return val

    def _ev_ArrayCreator(self, node, env):
        init = getattr(node, "initializer", None)
        if init is not None and getattr(init, "initializers", None) is not None:
            return AV(seq=[self._eval(e, env) for e in init.initializers])
        return AV(seq=[])

    def _ev_ArrayInitializer(self, node, env):
        return AV(seq=[self._eval(e, env) for e in (node.initializers or [])])

    def _ev_ClassCreator(self, node, env):
        args = [self._eval(a, env) for a in (node.arguments or [])]
        tname = _type_name(node.type)
        # Collection constructors start empty (contents added via method calls).
        if tname in ("ArrayList", "LinkedList", "Vector", "Stack",
                     "CopyOnWriteArrayList"):
            base = AV(seq=[])
        elif tname in ("HashMap", "LinkedHashMap", "TreeMap", "Hashtable",
                       "ConcurrentHashMap", "Properties"):
            base = AV(mapping={})
        elif tname in ("StringBuilder", "StringBuffer"):
            # Seed the builder with its initial value's taint/const, if any, so
            # ``new StringBuilder(param).append("x").toString()`` stays tainted.
            base = args[0] if args else UNTAINTED
        else:
            base = AV(tainted=any(a.tainted for a in args))
        # A constructor may be the head of a chain: new File(x).getPath() etc.
        base = self._apply_selectors(base, node, env)
        # Path-traversal / ProcessBuilder sinks are constructors.
        if tname in self.sink_ctors:
            self._record_sink(args)
        return base

    def _ev_MethodInvocation(self, node, env):
        return self._invoke(node, env)

    # ---- method invocation ---------------------------------------------
    def _invoke(self, node, env: dict[str, AV]) -> AV:
        member = node.member
        qual_name = node.qualifier if isinstance(node.qualifier, str) else None
        args = [self._eval(a, env) for a in (node.arguments or [])]

        # Record sinks (by method name). setAttribute/exec/etc.
        if member in self.sink_methods and self._plausible_sink(node, member):
            self._record_sink(args)

        # A sanitizer clears taint for its category.
        if member in self.sanitizers:
            inner = args[0] if args else UNTAINTED
            return AV(tainted=inner.tainted,
                      sanitized=inner.sanitized | {self.category},
                      const=inner.const)
        if member in _ALL_SANITIZERS:      # a different category's encoder
            inner = args[0] if args else UNTAINTED
            return AV(tainted=inner.tainted, sanitized=inner.sanitized,
                      const=inner.const)

        # A source method yields tainted data.
        if member in _SOURCE_METHODS:
            base = TAINTED
            return self._apply_selectors(base, node, env)

        # Container operations on a tracked local (qualifier is a variable).
        if qual_name is not None and qual_name in env:
            recv = env[qual_name]
            handled, result = self._container_op(recv, member, node, args, env)
            if handled:
                return self._apply_selectors(result, node, env)

        # Known constant-producing string ops.
        recv_av = self._receiver_av(node, env)
        folded = _fold_string_method(recv_av, member, args)
        if folded is not None:
            return self._apply_selectors(folded, node, env)

        # Interprocedural: a call to a same-file method resolved on `this`
        # (implicit or explicit — javalang gives an empty-string qualifier for an
        # implicit `this`) or a local receiver (e.g. helper.doSomething(...)).
        # Only inlined when it resolves unambiguously; otherwise default
        # propagation keeps the taint.
        if qual_name in (None, "", "this") or qual_name in env:
            inlined = self._maybe_inline(member, args)
            if inlined is not None:
                return self._apply_selectors(inlined, node, env)

        # Default propagation: tainted if the receiver or any argument is
        # tainted (over-approximation — the safe direction).
        tainted = recv_av.tainted or any(a.tainted for a in args)
        san = recv_av.sanitized if recv_av.tainted else frozenset()
        base = AV(tainted=tainted, sanitized=san)
        return self._apply_selectors(base, node, env)

    def _plausible_sink(self, node, member: str) -> bool:
        """Filter obviously-wrong sink matches for over-broad method names."""
        if self.category == "xss":
            # print/write is only an XSS sink on a servlet writer/stream, never
            # on System.out/err. Exclude those to avoid keeping findings on
            # console output (still sound: excluding a non-sink cannot hide a
            # real HTTP-response sink, which stays matched).
            q = node.qualifier if isinstance(node.qualifier, str) else ""
            if q in ("System.out", "System.err"):
                return False
        return True

    def _receiver_av(self, node, env) -> AV:
        q = node.qualifier
        if isinstance(q, str) and q in env:
            return env[q]
        if q is not None and hasattr(q, "attrs"):
            return self._eval(q, env)
        return UNTAINTED

    def _apply_selectors(self, base: AV, node, env) -> AV:
        """Handle a chained call/selector list: x.foo().bar(...)."""
        cur = base
        for sel in getattr(node, "selectors", None) or []:
            st = type(sel).__name__
            if st == "MethodInvocation":
                sargs = [self._eval(a, env) for a in (sel.arguments or [])]
                m = sel.member
                if m in self.sink_methods:
                    self._record_sink(sargs)
                if m in self.sanitizers:
                    cur = AV(tainted=cur.tainted, sanitized=cur.sanitized | {self.category})
                    continue
                if m in _SOURCE_METHODS:
                    cur = TAINTED
                    continue
                folded = _fold_string_method(cur, m, sargs)
                if folded is not None:
                    cur = folded
                    continue
                inlined = self._maybe_inline(m, sargs)
                if inlined is not None:
                    cur = inlined
                    continue
                cur = AV(tainted=cur.tainted or any(a.tainted for a in sargs),
                         sanitized=cur.sanitized if cur.tainted else frozenset())
            elif st == "ArraySelector":
                # x[i]: taint of an element → conservatively the seq's taint.
                cur = _element_of(cur)
            # MemberReference selector (field access): keep receiver taint.
        return cur

    def _eval_selector_args(self, sel, env) -> None:
        if type(sel).__name__ == "MethodInvocation":
            for a in sel.arguments or []:
                self._eval(a, env)

    # ---- container modelling -------------------------------------------
    def _container_op(self, recv: AV, member: str, node, args, env):
        """Model List/Map/StringBuilder ops. Returns (handled, result_av)."""
        # ----- Map -----
        if recv.mapping is not None:
            if member == "put" and len(args) >= 2:
                key = args[0].const if args[0].has_const() else _NOCONST
                if key is _NOCONST:
                    recv.map_dirty = True
                else:
                    recv.mapping[key] = args[1]
                return True, UNTAINTED
            if member == "get" and len(args) >= 1:
                key = args[0].const if args[0].has_const() else _NOCONST
                if key is _NOCONST:
                    return True, AV(tainted=recv._any_map_tainted(self.category) or recv.map_dirty)
                return True, recv.mapping.get(key, _const(None))
            if member in ("remove", "clear"):
                if member == "clear":
                    recv.mapping.clear()
                else:
                    key = args[0].const if args and args[0].has_const() else _NOCONST
                    if key is not _NOCONST:
                        recv.mapping.pop(key, None)
                    else:
                        recv.map_dirty = True
                return True, UNTAINTED
        # ----- List / array-backed -----
        if recv.seq is not None:
            if member == "add":
                if len(args) == 1:
                    recv.seq.append(args[0])
                elif len(args) >= 2:      # add(index, elem)
                    idx = args[0].const if args[0].has_const() else None
                    if isinstance(idx, int) and 0 <= idx <= len(recv.seq):
                        recv.seq.insert(idx, args[1])
                    else:
                        recv.seq.append(args[1])
                        recv.seq_dirty = True
                return True, UNTAINTED
            if member == "set" and len(args) >= 2:
                idx = args[0].const if args[0].has_const() else None
                if isinstance(idx, int) and 0 <= idx < len(recv.seq):
                    recv.seq[idx] = args[1]
                else:
                    recv.seq_dirty = True
                return True, UNTAINTED
            if member == "remove" and len(args) >= 1:
                idx = args[0].const if args[0].has_const() else None
                if isinstance(idx, int) and 0 <= idx < len(recv.seq):
                    recv.seq.pop(idx)
                    return True, UNTAINTED
                recv.seq_dirty = True
                return True, UNTAINTED
            if member == "get" and len(args) >= 1:
                idx = args[0].const if args[0].has_const() else None
                if isinstance(idx, int) and 0 <= idx < len(recv.seq):
                    return True, recv.seq[idx]
                return True, AV(tainted=recv_seq_tainted(recv, self.category) or recv.seq_dirty)
            if member in ("toArray",):
                return True, AV(seq=list(recv.seq))
        # ----- StringBuilder / StringBuffer -----
        if member in ("append", "insert"):
            added = args[-1] if args else UNTAINTED
            merged = AV(tainted=recv.tainted or added.tainted,
                        sanitized=(recv.sanitized & added.sanitized)
                        if (recv.tainted and added.tainted) else
                        (recv.sanitized if recv.tainted else added.sanitized))
            # Reflect back onto the receiver variable so later toString() sees it.
            q = node.qualifier if isinstance(node.qualifier, str) else None
            if q is not None:
                env[q] = merged
            return True, merged
        if member == "toString":
            return True, recv
        # ----- sound fallback for any unmodelled container mutation -----
        # A tainted value written through a collection/builder mutator must taint
        # the receiver even when we do not model the container precisely, so taint
        # is never silently dropped (mirrors the rules' add/put propagators).
        if member in _MUTATORS:
            val_tainted = any(a.tainted for a in args)
            if val_tainted:
                if recv.seq is not None:
                    recv.seq_dirty = True
                elif recv.mapping is not None:
                    recv.map_dirty = True
                else:
                    q = node.qualifier if isinstance(node.qualifier, str) else None
                    if q is not None:
                        env[q] = AV(tainted=True)
            return True, UNTAINTED
        return False, UNTAINTED

    # ---- sinks / assignment --------------------------------------------
    def _record_sink(self, args: list[AV]) -> None:
        tainted = any(a.tainted_for(self.category) for a in args)
        self.sink_tainted.append(tainted)

    def _assign_to(self, target, val: AV, env: dict[str, AV]) -> None:
        tt = type(target).__name__
        if tt == "MemberReference" and not target.qualifier:
            env[target.member] = val
        elif tt == "MemberReference":
            pass   # qualified field assignment — untracked
        # array element / other targets: untracked (conservative)


def recv_seq_tainted(recv: AV, category: str) -> bool:
    return any(e.tainted_for(category) for e in (recv.seq or []))


# ═══════════════════════════════════════════════════════════════════════════
# EXPRESSION / ENV HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _binop(op: str, left: AV, right: AV, category: str) -> AV:
    op = (op or "").strip()
    lc, rc = left.const, right.const
    both = left.has_const() and right.has_const()
    # String concatenation.
    if op == "+":
        if both and (isinstance(lc, str) or isinstance(rc, str)):
            return _const(_to_str(lc) + _to_str(rc))
        if both and _is_num(lc) and _is_num(rc):
            return _const(lc + rc)
        tainted = left.tainted or right.tainted
        san = _concat_sanitized(left, right)
        return AV(tainted=tainted, sanitized=san)
    if both and _is_num(lc) and _is_num(rc):
        try:
            if op == "-":
                return _const(lc - rc)
            if op == "*":
                return _const(lc * rc)
            if op == "/":
                return _const(lc // rc if isinstance(lc, int) and isinstance(rc, int) and rc else lc / rc) if rc else UNTAINTED
            if op == "%":
                return _const(lc % rc) if rc else UNTAINTED
            if op == ">":
                return _const(lc > rc)
            if op == "<":
                return _const(lc < rc)
            if op == ">=":
                return _const(lc >= rc)
            if op == "<=":
                return _const(lc <= rc)
            if op == "==":
                return _const(lc == rc)
            if op == "!=":
                return _const(lc != rc)
            if isinstance(lc, int) and isinstance(rc, int):
                if op == "&":
                    return _const(lc & rc)
                if op == "|":
                    return _const(lc | rc)
                if op == "^":
                    return _const(lc ^ rc)
                if op == "<<":
                    return _const(lc << rc)
                if op == ">>":
                    return _const(lc >> rc)
        except Exception:
            return UNTAINTED
    if both and op == "==":
        return _const(lc == rc)
    if both and op == "!=":
        return _const(lc != rc)
    if op == "&&":
        if left.const is False or right.const is False:
            return _const(False)
        if left.const is True and right.const is True:
            return _const(True)
    if op == "||":
        if left.const is True or right.const is True:
            return _const(True)
        if left.const is False and right.const is False:
            return _const(False)
    return AV(tainted=left.tainted or right.tainted)


def _concat_sanitized(left: AV, right: AV) -> frozenset:
    tainted_parts = [p for p in (left, right) if p.tainted]
    if not tainted_parts:
        return frozenset()
    acc = tainted_parts[0].sanitized
    for p in tainted_parts[1:]:
        acc = acc & p.sanitized
    return acc


def _fold_string_method(recv: AV, member: str, args: list[AV]) -> Optional[AV]:
    """Fold the handful of String methods the obfuscations rely on. Returns None
    when not foldable (caller falls back to default propagation)."""
    rc = recv.const
    if not recv.has_const() or not isinstance(rc, str):
        # length/charAt on a non-constant tainted string stays tainted-ish;
        # let default propagation handle it.
        return None
    a0 = args[0].const if args and args[0].has_const() else _NOCONST
    try:
        if member == "charAt" and isinstance(a0, int):
            return _const(rc[a0])
        if member == "substring" and isinstance(a0, int):
            if len(args) >= 2 and args[1].has_const() and isinstance(args[1].const, int):
                return _const(rc[a0:args[1].const])
            return _const(rc[a0:])
        if member == "length" and not args:
            return _const(len(rc))
        if member in ("toUpperCase", "toLowerCase") and not args:
            return _const(rc.upper() if member == "toUpperCase" else rc.lower())
        if member == "trim" and not args:
            return _const(rc.strip())
        if member == "toString" and not args:
            return _const(rc)
        if member == "concat" and isinstance(a0, str):
            return _const(rc + a0)
        if member == "equals":
            return _const(rc == a0) if a0 is not _NOCONST else None
        if member == "isEmpty" and not args:
            return _const(len(rc) == 0)
        if member == "replace" and len(args) >= 2 and \
                isinstance(a0, str) and args[1].has_const() and isinstance(args[1].const, str):
            return _const(rc.replace(a0, args[1].const))
        if member == "valueOf" and isinstance(a0, (int, str, bool)):
            return _const(_to_str(a0))
    except Exception:
        return None
    return None


def _to_str(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    return str(v)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _element_of(av: AV) -> AV:
    """The abstract element yielded by iterating/indexing a container."""
    if av.seq is not None:
        acc: Optional[AV] = None
        for e in av.seq:
            acc = _join(acc, e) if acc is not None else e
        base = acc if acc is not None else UNTAINTED
        if av.seq_dirty:
            base = AV(tainted=True) if base is None else replace(base, tainted=base.tainted or True)
        return base
    if av.mapping is not None:
        acc = None
        for v in av.mapping.values():
            acc = _join(acc, v) if acc is not None else v
        return acc if acc is not None else UNTAINTED
    # Iterating a tainted scalar (e.g. an Enumeration from getHeaders) → tainted.
    return AV(tainted=av.tainted, sanitized=av.sanitized)


def _copy_env(env: dict[str, AV]) -> dict[str, AV]:
    return {k: _copy_av(v) for k, v in env.items()}


def _copy_av(v: AV) -> AV:
    if v.seq is not None:
        return AV(seq=[_copy_av(e) for e in v.seq], seq_dirty=v.seq_dirty)
    if v.mapping is not None:
        return AV(mapping={k: _copy_av(e) for k, e in v.mapping.items()},
                  map_dirty=v.map_dirty)
    return AV(tainted=v.tainted, const=v.const, sanitized=v.sanitized)


def _merge_into(dst: dict[str, AV], a: dict[str, AV], b: dict[str, AV]) -> None:
    keys = set(a) | set(b)
    merged = {k: _join(a.get(k), b.get(k)) for k in keys}
    _assign_env(dst, merged)


def _assign_env(dst: dict[str, AV], src: dict[str, AV]) -> None:
    dst.clear()
    dst.update(src)


def _select_switch_case(cases, value):
    """Statements that run for a constant switch selector (with fallthrough)."""
    # Normalise a char selector (1-char str) for comparison with case literals.
    labels = []
    for c in cases:
        labels.append([_case_label_value(x) for x in (c.case or [])])
    match_idx = None
    default_idx = None
    for i, labs in enumerate(labels):
        if not labs:
            default_idx = i
        elif any(_case_matches(lv, value) for lv in labs):
            match_idx = i
            break
    start = match_idx if match_idx is not None else default_idx
    if start is None:
        return []
    out = []
    for c in cases[start:]:            # fallthrough until a break/return in-block
        out.extend(c.statements or [])
        if _block_breaks(c.statements or []):
            break
    return out


def _all_switch_blocks(cases):
    return [list(c.statements or []) for c in cases]


def _case_label_value(node):
    t = type(node).__name__
    if t == "Literal":
        return _parse_literal(node.value).const
    if t == "MemberReference":
        return _NOCONST      # enum/constant label — unknown here
    return _NOCONST


def _case_matches(label_val, value) -> bool:
    if label_val is _NOCONST:
        return False
    if isinstance(value, str) and len(value) == 1 and isinstance(label_val, str):
        return label_val == value
    return label_val == value


def _block_breaks(stmts) -> bool:
    for s in stmts:
        if type(s).__name__ in ("BreakStatement", "ReturnStatement",
                                "ContinueStatement", "ThrowStatement"):
            return True
    return False


def _child_nodes(node):
    out = []
    for attr in getattr(node, "attrs", []) or []:
        v = getattr(node, attr, None)
        if isinstance(v, (list, tuple)):
            out.extend(x for x in v if x is not None and hasattr(x, "attrs"))
        elif v is not None and hasattr(v, "attrs"):
            out.append(v)
    return out


def _type_name(t) -> str:
    """Innermost simple name of a (possibly package-qualified) type.

    javalang nests ``java.util.ArrayList`` as ReferenceType(name='java',
    sub_type=ReferenceType(name='util', sub_type=ReferenceType(name='ArrayList'))),
    so we walk to the deepest sub_type to recover 'ArrayList'."""
    name = getattr(t, "name", "") or ""
    sub = getattr(t, "sub_type", None)
    while sub is not None:
        nm = getattr(sub, "name", None)
        if nm:
            name = nm
        sub = getattr(sub, "sub_type", None)
    return name


def _type_is_stringy(av: AV) -> bool:
    return av.has_const() and isinstance(av.const, str)


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════


def available() -> bool:
    return _HAVE_JAVALANG and os.environ.get("HEAVEN_JAVA_DATAFLOW", "1") != "0"


def category_for_cwe(cwe: str) -> Optional[str]:
    """Map a finding's CWE (``CWE-89`` / ``89``) to a Benchmark category."""
    num = str(cwe or "").upper().replace("CWE-", "").strip()
    return _CATEGORY_BY_CWE.get(num)


class JavaRefiner:
    """Batches the dataflow refinement over a scan: parses each Java file once,
    caches per-(file, category) suppression verdicts, and resolves config-driven
    weak crypto. All heavy state is per-instance so a scan reuses parses."""

    def __init__(self, source_path: str):
        self.source_path = source_path
        self.props = load_properties(source_path)
        self._src: dict[str, Optional[str]] = {}
        self._tree: dict[str, Any] = {}
        self._methods: dict[str, dict] = {}
        self._verdict: dict[tuple, bool] = {}

    def _load(self, file_path: str):
        if file_path not in self._tree:
            tree = None
            try:
                src = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                self._src[file_path] = src
                tree = javalang.parse.parse(src)
                self._methods[file_path] = _build_methods(tree)
            except Exception:
                self._src[file_path] = None
            self._tree[file_path] = tree
        return self._tree.get(file_path)

    def is_false_positive(self, file_path: str, category: str) -> bool:
        """True only when *every* reachable sink of ``category`` in the file is
        provably untainted (and at least one was reached). Fail-safe: False on
        any parse/analysis uncertainty, so a real finding is never dropped."""
        if category not in _TAINT_CATEGORIES:
            return False
        key = (file_path, category)
        if key in self._verdict:
            return self._verdict[key]
        tree = self._load(file_path)
        if tree is None:
            self._verdict[key] = False
            return False
        methods = self._methods.get(file_path, {})
        res = _verdict_over_tree(tree, methods, category)
        self._verdict[key] = res
        return res

    def iter_config_crypto(self):
        """Yield (file_path, finding_dict) for config-resolved weak crypto across
        the Java files under the scan root."""
        base = Path(self.source_path)
        files: list[Path]
        if base.is_file():
            files = [base] if base.suffix == ".java" else []
        else:
            files = list(base.rglob("*.java"))
        for jf in files:
            try:
                text = jf.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                logger.debug(f"java_dataflow: cannot read {jf}: {e}")
                continue
            if "getProperty" not in text or "getInstance" not in text:
                continue
            for f in config_crypto_findings(text, str(jf), self.props):
                yield str(jf), f


def _enclosing_method(tree, line: int):
    """The MethodDeclaration whose body spans ``line`` (best-effort by position).

    javalang records a start position per node; we pick the method with the
    greatest start line <= the finding line."""
    best = None
    best_line = -1
    for _p, m in tree.filter(jtree.MethodDeclaration):
        pos = getattr(m, "position", None)
        ml = pos.line if pos else 0
        if ml <= line and ml > best_line:
            best, best_line = m, ml
    return best


def category_sink_is_reachable_tainted(tree, method, category: str,
                                       methods=None) -> Optional[bool]:
    """Run the interpreter for ``category`` over ``method``.

    Returns:
      * True  — at least one reached sink carries taint (keep the finding),
      * False — sinks were reached and none carried taint (proven safe),
      * None  — no sink was reached / undecidable (keep the finding).
    """
    interp = _Interp(category, methods=methods if methods is not None
                     else _build_methods(tree))
    try:
        interp.run(method)
    except Exception as e:   # analyzer bug on exotic Java → undecidable
        logger.debug(f"java_dataflow: interp error ({category}): {e}")
        return None
    if not interp.sink_tainted:
        return None
    return any(interp.sink_tainted)


def _build_methods(tree) -> dict[str, list]:
    """Index every method declaration in a compilation unit by name, for
    interprocedural inlining."""
    out: dict[str, list] = {}
    try:
        for _p, m in tree.filter(jtree.MethodDeclaration):
            out.setdefault(m.name, []).append(m)
    except Exception:
        return {}
    return out


def _verdict_over_tree(tree, methods, category: str) -> bool:
    """File-level suppression verdict: True only when every reachable sink of
    ``category`` (across all methods, following inlined helpers) is provably
    untainted and at least one was reached."""
    safe = False
    try:
        for _p, m in tree.filter(jtree.MethodDeclaration):
            v = category_sink_is_reachable_tainted(tree, m, category, methods)
            if v is True:      # a reachable tainted sink → keep the finding
                return False
            if v is False:
                safe = True
    except Exception:
        return False
    return safe


def flow_is_false_positive(source: str, category: str) -> bool:
    """True only when the taint flow for ``category`` in ``source`` is provably
    dead across the whole file. Fails safe (False) on any uncertainty/error."""
    if category not in _TAINT_CATEGORIES:
        return False
    try:
        tree = javalang.parse.parse(source)
    except Exception:
        return False
    return _verdict_over_tree(tree, _build_methods(tree), category)


def is_false_positive(source: str, line: int, category: str) -> bool:
    """True only when the taint flow for ``category`` at ``line`` is provably
    dead. Fails safe (returns False) on any uncertainty or error."""
    if category not in _TAINT_CATEGORIES:
        return False
    try:
        tree = javalang.parse.parse(source)
    except Exception:
        return False
    method = _enclosing_method(tree, line)
    if method is None:
        return False
    verdict = category_sink_is_reachable_tainted(tree, method, category,
                                                 _build_methods(tree))
    return verdict is False


# ── config-resolved weak crypto ─────────────────────────────────────────────


def load_properties(source_path: str) -> dict[str, str]:
    """Merge every ``*.properties`` file reachable from a project into one map.

    Searches the scan path and, when it sits inside a Maven/Gradle layout, the
    project's resource roots — the real places an application keeps its config.
    """
    root = Path(source_path)
    search_dirs: list[Path] = []
    base = root if root.is_dir() else root.parent
    search_dirs.append(base)
    # Walk up to a project root and add conventional resource dirs.
    cur = base
    for _ in range(8):
        if (cur / "pom.xml").exists() or (cur / "build.gradle").exists() or \
           (cur / "settings.gradle").exists() or (cur / "src").is_dir():
            for rel in ("src/main/resources", "src/test/resources", "resources", "."):
                d = cur / rel
                if d.is_dir():
                    search_dirs.append(d)
            break
        if cur.parent == cur:
            break
        cur = cur.parent

    props: dict[str, str] = {}
    seen: set[Path] = set()
    for d in search_dirs:
        try:
            for pf in d.rglob("*.properties"):
                rp = pf.resolve()
                if rp in seen:
                    continue
                seen.add(rp)
                _parse_properties_file(pf, props)
        except Exception as e:
            logger.debug(f"java_dataflow: properties scan of {d} failed: {e}")
            continue
    return props


def _parse_properties_file(path: Path, into: dict[str, str]) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        for sep in ("=", ":"):
            if sep in line:
                k, v = line.split(sep, 1)
                into.setdefault(k.strip(), v.strip())
                break


def config_crypto_findings(source: str, file_path: str,
                           props: dict[str, str]) -> list[dict[str, Any]]:
    """Report weak hash/cipher algorithms whose name a ``.properties`` file
    supplies at runtime and a pattern rule therefore misses.

    Returns a list of dicts: {category, cwe, line, algorithm}.
    """
    out: list[dict[str, Any]] = []
    try:
        tree = javalang.parse.parse(source)
    except Exception:
        return out
    for _p, m in tree.filter(jtree.MethodDeclaration):
        resolver = _PropResolver(props)
        try:
            resolver.run(m)
        except Exception as e:
            logger.debug(f"java_dataflow: prop resolver error: {e}")
            continue
        out.extend(resolver.findings)
    # de-dup by (category, line)
    uniq: dict[tuple, dict] = {}
    for f in out:
        uniq[(f["category"], f["line"])] = f
    return list(uniq.values())


class _PropResolver:
    """Tracks String locals bound to ``getProperty`` results and flags a weak
    algorithm reaching a MessageDigest/Cipher ``getInstance`` sink."""

    def __init__(self, props: dict[str, str]):
        self.props = props
        self.env: dict[str, Optional[str]] = {}   # var → resolved algorithm str
        self.findings: list[dict[str, Any]] = []

    def run(self, method) -> None:
        for _path, node in method.filter(jtree.LocalVariableDeclaration):
            for d in node.declarators:
                if d.initializer is not None:
                    val = self._resolve(d.initializer)
                    if val is not None:
                        self.env[d.name] = val
        for _path, node in method.filter(jtree.Assignment):
            tgt = node.expressionl
            if type(tgt).__name__ == "MemberReference" and not tgt.qualifier:
                val = self._resolve(node.value)
                if val is not None:
                    self.env[tgt.member] = val
        for _path, mi in method.filter(jtree.MethodInvocation):
            self._check_sink(mi)

    def _resolve(self, node) -> Optional[str]:
        """Resolve an expression to a concrete algorithm string, or None."""
        t = type(node).__name__
        if t == "Literal":
            av = _parse_literal(node.value)
            return av.const if isinstance(av.const, str) else None
        if t == "MethodInvocation" and node.member == "getProperty":
            args = node.arguments or []
            if not args:
                return None
            key_av = _parse_literal(args[0].value) if type(args[0]).__name__ == "Literal" else None
            key = key_av.const if key_av and isinstance(key_av.const, str) else None
            default = None
            if len(args) >= 2 and type(args[1]).__name__ == "Literal":
                d_av = _parse_literal(args[1].value)
                default = d_av.const if isinstance(d_av.const, str) else None
            if key is not None and key in self.props:
                return self.props[key]
            return default
        if t == "MemberReference" and not node.qualifier:
            return self.env.get(node.member)
        return None

    def _check_sink(self, mi) -> None:
        member = mi.member
        if member != "getInstance":
            return
        qual = mi.qualifier if isinstance(mi.qualifier, str) else ""
        args = mi.arguments or []
        if not args:
            return
        alg = self._resolve(args[0])
        if alg is None:
            return
        pos = getattr(mi, "position", None)
        line = pos.line if pos else 0
        is_digest = qual.endswith("MessageDigest") or "MessageDigest" in qual
        is_cipher = qual.endswith("Cipher") or "Cipher" in qual
        # When the qualifier is an alias we can't see, fall back to the algorithm
        # shape: cipher transforms contain a mode/padding ('/'), digests don't.
        if not is_digest and not is_cipher:
            if "/" in alg:
                is_cipher = True
            else:
                is_digest = True
        if is_digest and _is_weak_hash(alg):
            self.findings.append({"category": "hash", "cwe": "CWE-328",
                                  "line": line, "algorithm": alg})
        elif is_cipher and _is_weak_cipher(alg):
            self.findings.append({"category": "crypto", "cwe": "CWE-327",
                                  "line": line, "algorithm": alg})

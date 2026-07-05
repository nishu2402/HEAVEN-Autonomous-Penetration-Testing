"""A tiny, native, DVWA-faithful vulnerable web app for offline scanner tests.

Why this exists
---------------
The Docker DVWA image is amd64 and only runs under QEMU emulation on arm64 Macs,
where it is slow and crash-prone — useless for *iterating* on scanner heuristics.
This module reproduces the exact behaviours HEAVEN's injection scanner cares
about, natively and deterministically, with **no Docker and no MySQL**:

* ``/vulnerabilities/sqli/``  — DVWA's classic ``id`` SQLi, faithful to the real
  thing including **MySQL comment semantics**: a bare ``--`` is *not* a comment
  (it must be ``-- `` with trailing whitespace, or ``#``). This is the subtle
  real-world behaviour that silently defeated HEAVEN's boolean oracle against
  DVWA, so the repro would be worthless without it.
* ``/vulnerabilities/xss_r/`` — reflected XSS (unescaped echo).
* ``/vulnerabilities/xss_d/`` — echo that is HTML-escaped (a *reflection* that is
  NOT an injection); used to prove the scanner does not raise SQLi/XSS false
  positives on pages that merely mirror input.

The "database" is a 5-row in-memory table evaluated through a comment-aware
processor that mimics MySQL, then executed on SQLite. String interpolation makes
it genuinely injectable (that is the whole point — it is a *test target*).
"""

from __future__ import annotations

import contextlib
import re
import sqlite3
import threading
from html import escape
from typing import Iterator

from flask import Flask, request

# DVWA's default users table (user_id → names). Row 1 is admin/admin.
_USERS = [
    (1, "admin", "admin"),
    (2, "Gordon", "Brown"),
    (3, "Hack", "Me"),
    (4, "Pablo", "Picasso"),
    (5, "Bob", "Smith"),
]


class _MySQLSyntaxError(Exception):
    """Stand-in for the DBMS error DVWA surfaces on a broken query."""


# The literal error string DVWA/MySQL prints — matched by HEAVEN's
# SQLI_ERROR_PATTERNS ("you have an error in your sql syntax").
_MYSQL_ERR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near '{near}' at line 1"
)


def _apply_mysql_comment_rules(sql: str) -> tuple[str, bool]:
    """Return (effective_sql, is_error) applying MySQL comment/quoting rules.

    MySQL only treats ``--`` as a comment when the second dash is followed by
    whitespace/control; a bare ``--foo`` is a parse error. ``#`` comments to end
    of line. Single-quoted strings escape an inner quote as ``''``. We honour
    those rules so that:

      * ``id=1' AND '1'='1'--``   → dangling quote → ERROR (the DVWA gotcha)
      * ``id=1' AND '1'='1'-- ``  → comment strips the rest → valid query
      * ``id=1' AND '1'='1'#``    → comment strips the rest → valid query
      * ``id='``                  → unterminated string → ERROR (error-based)
    """
    out: list[str] = []
    i, n = 0, len(sql)
    in_str = False
    while i < n:
        c = sql[i]
        if in_str:
            out.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":  # escaped '' inside a string
                    out.append("'")
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if c == "'":
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "#":
            break  # comment to end of line
        if c == "-" and i + 1 < n and sql[i + 1] == "-":
            nxt = sql[i + 2] if i + 2 < n else "\0"
            if nxt in " \t\r\n":
                break  # valid "-- " comment
            return "".join(out), True  # bare "--" → MySQL parse error
        out.append(c)
        i += 1
    if in_str:
        return "".join(out), True  # unterminated string literal
    return "".join(out), False


def _run_sqli(id_value: str) -> list[tuple[str, str]]:
    """Execute DVWA's sqli-low query for ``id_value``; raise on a broken query."""
    raw = f"SELECT first_name, last_name FROM users WHERE user_id = '{id_value}'"
    effective, err = _apply_mysql_comment_rules(raw)
    if err:
        raise _MySQLSyntaxError(id_value[-12:])
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE users (user_id INT, first_name TEXT, last_name TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, ?, ?)", _USERS)
        try:
            rows = conn.execute(effective).fetchall()
        except sqlite3.Error as e:
            raise _MySQLSyntaxError(str(e)[:40]) from e
        return [(str(r[0]), str(r[1])) for r in rows]
    finally:
        conn.close()


_PAGE = """<!doctype html><html><head><title>vuln-app</title></head><body>{body}</body></html>"""

_INDEX = _PAGE.format(
    body=(
        "<h1>vuln-app</h1><ul>"
        '<li><a href="/vulnerabilities/sqli/">SQL Injection</a></li>'
        '<li><a href="/vulnerabilities/sqli_blind/">Blind SQL Injection</a></li>'
        '<li><a href="/vulnerabilities/fi/">File Inclusion</a></li>'
        '<li><a href="/vulnerabilities/exec/">Command Injection</a></li>'
        '<li><a href="/vulnerabilities/xss_r/">Reflected XSS</a></li>'
        '<li><a href="/vulnerabilities/xss_d/">Escaped echo</a></li>'
        "</ul>"
    )
)

# A fake /etc/passwd — enough to trip HEAVEN's LFI content patterns (root:...:0:0:).
_ETC_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)


def _simulate_include(page: str) -> str | None:
    """Faithful DVWA-fi-low: include the named 'file'. Returns leaked content for
    a traversal/wrapper payload, else None (file-not-found → handled by caller)."""
    if "etc/passwd" in page:
        return _ETC_PASSWD
    if "win.ini" in page.lower():
        return "[fonts]\n[extensions]\n[mci extensions]\n"
    if page.startswith("php://filter"):
        return "PD9waHAgZWNobyAxOw=="  # base64 of "<?php echo 1;" → HEAVEN's PD9waHA
    return None


def _simulate_ping(ip: str) -> str:
    """Faithful DVWA-exec-low: shell_exec('ping -c 4 ' + ip). The raw ip is NOT
    reflected (so this endpoint only signals via genuine command output), and a
    chained `id` / `echo <marker>` executes just like an unsanitised shell."""
    lines = ["PING: 4 packets transmitted, 4 received, 0% packet loss"]
    if re.search(r"[;|&`]\s*id\b|\$\(\s*id\s*\)", ip):
        lines.append("uid=33(www-data) gid=33(www-data) groups=33(www-data)")
    m = re.search(r"echo\s+(\S+)", ip)
    if m:
        lines.append(m.group(1))
    return "\n".join(lines)

_SQLI_FORM = (
    '<form action="#" method="GET">'
    'User ID: <input type="text" name="id">'
    '<input type="submit" name="Submit" value="Submit">'
    "</form>"
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.logger.disabled = True

    @app.route("/")
    def index() -> str:
        return _INDEX

    @app.route("/vulnerabilities/sqli/")
    def sqli() -> str:
        rid = request.args.get("id")
        if rid is None or request.args.get("Submit") is None:
            return _PAGE.format(body=_SQLI_FORM)
        # DVWA echoes the raw id (reflection) then the query result rows. The raw
        # echo means the injected payload appears verbatim — exactly the case the
        # scanner's reflection-stripping must see through.
        parts = [_SQLI_FORM, f"<pre>ID: {rid}<br>"]
        try:
            rows = _run_sqli(rid)
        except _MySQLSyntaxError as e:
            parts.append(_MYSQL_ERR.format(near=escape(str(e))))
        else:
            for first, last in rows:
                parts.append(f"First name: {first}<br>Surname: {last}<br>")
        parts.append("</pre>")
        return _PAGE.format(body="".join(parts))

    @app.route("/vulnerabilities/sqli_blind/")
    def sqli_blind() -> str:
        # Blind SQLi: the query result is NOT shown and DB errors are SUPPRESSED
        # (an error looks identical to "no match"). The only observable signal is
        # exists/missing, so detection depends entirely on the boolean oracle —
        # which in turn depends on payloads that comment correctly on MySQL
        # ("-- " / "#"). A bare "--" would error on both branches, collapse the
        # oracle, and go undetected. Nothing is reflected here.
        form = ('<form action="#" method="GET">'
                'User ID: <input type="text" name="id">'
                '<input type="submit" name="Submit" value="Submit"></form>')
        rid = request.args.get("id")
        if rid is None or request.args.get("Submit") is None:
            return _PAGE.format(body=form)
        try:
            rows = _run_sqli(rid)
        except _MySQLSyntaxError:
            rows = []  # errors suppressed → indistinguishable from an empty result
        msg = ("User ID exists in the database."
               if rows else "User ID is MISSING from the database.")
        return _PAGE.format(body=f"{form}<pre>{msg}</pre>")

    @app.route("/vulnerabilities/fi/")
    def fi() -> str:
        # Local File Inclusion: include() the file named by `page`. A traversal or
        # php:// payload leaks file content; anything else is a "not found" whose
        # echo is HTML-escaped (reflection, NOT injection → must not false-positive).
        form = ('<form action="#" method="GET">'
                'Page: <input type="text" name="page">'
                '<input type="submit" name="Submit" value="Submit"></form>')
        page = request.args.get("page")
        if page is None or request.args.get("Submit") is None:
            return _PAGE.format(body=form)
        leaked = _simulate_include(page)
        if leaked is not None:
            return _PAGE.format(body=f"{form}<pre>{leaked}</pre>")
        return _PAGE.format(body=f"{form}<pre>File not found: {escape(page)}</pre>")

    @app.route("/vulnerabilities/exec/")
    def exec_() -> str:
        # OS Command Injection: shell_exec("ping -c 4 " + ip). No reflection.
        form = ('<form action="#" method="GET">'
                'IP: <input type="text" name="ip">'
                '<input type="submit" name="Submit" value="Submit"></form>')
        ip = request.args.get("ip")
        if ip is None or request.args.get("Submit") is None:
            return _PAGE.format(body=form)
        return _PAGE.format(body=f"{form}<pre>{_simulate_ping(ip)}</pre>")

    @app.route("/vulnerabilities/xss_r/")
    def xss_r() -> str:
        name = request.args.get("name")
        if name is None:
            return _PAGE.format(body='<form action="#" method="GET">'
                                     'Name: <input name="name"></form>')
        # Unescaped reflection → genuine reflected XSS.
        return _PAGE.format(body=f"<div>Hello {name}</div>")

    @app.route("/vulnerabilities/xss_d/")
    def xss_d() -> str:
        val = request.args.get("default")
        if val is None:
            return _PAGE.format(body='<form action="#" method="GET">'
                                     'Search: <input name="default"></form>')
        # HTML-escaped reflection → mirrors input but is NOT injectable. The
        # scanner must not raise SQLi/XSS here.
        return _PAGE.format(body=f"<div>Search: {escape(val)}</div>")

    return app


@contextlib.contextmanager
def serve(host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
    """Run the app in a background thread; yield its base URL. Docker-free."""
    import logging

    from werkzeug.serving import make_server

    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # silence request log
    server = make_server(host, port, create_app(), threaded=True)
    real_port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{real_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)

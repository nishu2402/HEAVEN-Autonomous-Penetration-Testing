"""HEAVEN — curated GTFOBins privilege-escalation catalog.

GTFOBins (https://gtfobins.github.io) documents how standard Unix binaries can
be abused to break out of a restricted context or escalate privileges. HEAVEN
does not ship the full project; it ships a *curated, offline* subset of the
binaries that matter for the three escalation surfaces the enum engine detects:

  - ``suid``          — the binary is SUID-root and can spawn a root shell / read
                        arbitrary files as root.
  - ``sudo``          — the binary is runnable via a ``sudo`` rule and can escape
                        to a root shell / write arbitrary files.
  - ``capabilities``  — the binary carries a Linux file capability (e.g.
                        ``cap_setuid+ep``) that grants elevated privileges.

Each entry records which surfaces apply plus a one-line abuse note the report
shows the operator. This is deterministic knowledge, not a guess: if a binary in
this table is SUID-root, that *is* a root escalation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GTFOEntry:
    name: str
    suid: bool = False
    sudo: bool = False
    capabilities: bool = False
    note: str = ""


def _e(name: str, *, suid: bool = False, sudo: bool = False,
       capabilities: bool = False, note: str = "") -> GTFOEntry:
    return GTFOEntry(name, suid=suid, sudo=sudo, capabilities=capabilities, note=note)


# ── The catalog (basename → entry) ──────────────────────────────────────────
# Shell-spawners: SUID *and* sudo both yield an interactive root shell.
_SHELL = "spawns an interactive shell that keeps the elevated euid/privileges"
_READ = "reads arbitrary files as root"
_WRITE = "writes/overwrites arbitrary files as root"

GTFOBINS: dict[str, GTFOEntry] = {e.name: e for e in (
    # classic shell escapes — abusable both SUID and via sudo
    _e("bash", suid=True, sudo=True, note=_SHELL),
    _e("sh", suid=True, sudo=True, note=_SHELL),
    _e("dash", suid=True, sudo=True, note=_SHELL),
    _e("zsh", suid=True, sudo=True, note=_SHELL),
    _e("ksh", suid=True, sudo=True, note=_SHELL),
    _e("csh", suid=True, sudo=True, note=_SHELL),
    _e("tcsh", suid=True, sudo=True, note=_SHELL),
    _e("fish", sudo=True, note=_SHELL),
    # editors / pagers with shell escape
    _e("vi", suid=True, sudo=True, note="`:!/bin/sh` shell escape"),
    _e("vim", suid=True, sudo=True, capabilities=True, note="`:!/bin/sh` / `-c ':py'` shell escape"),
    _e("rvim", suid=True, sudo=True, note="shell escape"),
    _e("view", suid=True, sudo=True, note="shell escape"),
    _e("nano", suid=True, sudo=True, note="^R^X command execution"),
    _e("pico", suid=True, sudo=True, note="command execution"),
    _e("ed", suid=True, sudo=True, note="`!/bin/sh` shell escape"),
    _e("emacs", sudo=True, note="`-Q -nw --eval` shell execution"),
    _e("less", suid=True, sudo=True, note="`!/bin/sh` from pager"),
    _e("more", suid=True, sudo=True, note="`!/bin/sh` from pager"),
    _e("man", suid=True, sudo=True, note="`!/bin/sh` from pager"),
    _e("pager", sudo=True, note="pager shell escape"),
    # interpreters
    _e("awk", suid=True, sudo=True, note="`system()` command execution"),
    _e("gawk", suid=True, sudo=True, note="`system()` command execution"),
    _e("mawk", suid=True, sudo=True, note="`system()` command execution"),
    _e("perl", suid=True, sudo=True, capabilities=True, note="`exec` / `-e` command execution"),
    _e("python", suid=True, sudo=True, capabilities=True, note="`os.system` / `os.setuid` execution"),
    _e("python2", suid=True, sudo=True, capabilities=True, note="`os.system` execution"),
    _e("python3", suid=True, sudo=True, capabilities=True, note="`os.system` / `os.setuid` execution"),
    _e("ruby", suid=True, sudo=True, capabilities=True, note="`exec` command execution"),
    _e("php", suid=True, sudo=True, capabilities=True, note="`system()` command execution"),
    _e("lua", suid=True, sudo=True, note="`os.execute` command execution"),
    _e("node", suid=True, sudo=True, capabilities=True, note="`child_process.exec` execution"),
    _e("tclsh", suid=True, sudo=True, note="`exec` command execution"),
    _e("expect", suid=True, sudo=True, note="`spawn` command execution"),
    # file utilities that read/write as root
    _e("find", suid=True, sudo=True, note="`-exec /bin/sh \\;` " + _SHELL),
    _e("nmap", suid=True, sudo=True, note="interactive/`--script` shell (legacy)"),
    _e("cp", sudo=True, note=_WRITE + " (overwrite /etc/passwd)"),
    _e("mv", sudo=True, note=_WRITE),
    _e("dd", sudo=True, capabilities=True, note=_WRITE),
    _e("tee", sudo=True, note=_WRITE),
    _e("cat", suid=True, sudo=True, note=_READ),
    _e("head", suid=True, sudo=True, note=_READ),
    _e("tail", suid=True, sudo=True, note=_READ),
    _e("sed", suid=True, sudo=True, note="`-e '1e exec sh'` " + _SHELL),
    _e("cut", suid=True, note=_READ),
    _e("grep", suid=True, sudo=True, note=_READ),
    _e("tar", suid=True, sudo=True, note="`--checkpoint-action=exec=sh` command execution"),
    _e("zip", suid=True, sudo=True, note="`-T -TT 'sh #'` command execution"),
    _e("gzip", sudo=True, note="`-f` " + _READ),
    _e("git", suid=True, sudo=True, note="`-p` pager / hooks command execution"),
    _e("rsync", suid=True, sudo=True, note="`-e sh` command execution"),
    _e("scp", sudo=True, note="`-S` command execution"),
    _e("socat", suid=True, sudo=True, note="`exec` shell"),
    _e("ftp", suid=True, sudo=True, note="`!/bin/sh` shell escape"),
    _e("gdb", suid=True, sudo=True, capabilities=True, note="`-ex 'call system'` execution"),
    _e("strace", sudo=True, note="`-f -e trace=... /bin/sh` execution"),
    _e("ltrace", sudo=True, note="command execution"),
    # env / wrappers that pass through to a shell
    _e("env", suid=True, sudo=True, note="`env /bin/sh` " + _SHELL),
    _e("nice", suid=True, sudo=True, note="`nice /bin/sh` " + _SHELL),
    _e("stdbuf", suid=True, sudo=True, note="command execution"),
    _e("timeout", suid=True, sudo=True, note="`timeout 7d /bin/sh` " + _SHELL),
    _e("xargs", suid=True, sudo=True, note="`-a /dev/null sh -c` execution"),
    _e("flock", suid=True, sudo=True, note="`-u / /bin/sh` " + _SHELL),
    _e("ionice", suid=True, sudo=True, note="`ionice /bin/sh` " + _SHELL),
    _e("taskset", suid=True, sudo=True, note="`taskset 1 /bin/sh` " + _SHELL),
    _e("watch", suid=True, sudo=True, note="`-x sh -c` command execution"),
    _e("make", suid=True, sudo=True, note="`-s --eval` command execution"),
    _e("ionice", suid=True, sudo=True, note=_SHELL),
    # system-level
    _e("systemctl", sudo=True, note="malicious unit ExecStart command execution"),
    _e("apt", sudo=True, note="`APT::Update::Pre-Invoke` command execution"),
    _e("apt-get", sudo=True, note="`APT::Update::Pre-Invoke` command execution"),
    _e("mount", suid=True, sudo=True, note="`-o bind` / helper command execution"),
    _e("openssl", suid=True, sudo=True, note="engine/`-engine` command execution"),
    _e("crontab", sudo=True, note="edit privileged crontab for execution"),
    _e("wget", sudo=True, note="`--use-askpass` / write-file as root"),
    _e("curl", sudo=True, note="write-file as root"),
    _e("busybox", suid=True, sudo=True, note="`busybox sh` " + _SHELL),
)}


def lookup(binary: str) -> GTFOEntry | None:
    """Return the GTFOBins entry for a binary path/basename, or ``None``.

    Handles common versioned/variant names (``python3.10`` → ``python3`` →
    ``python``; ``vim.basic`` → ``vim``) by progressively stripping suffixes.
    """
    name = binary.strip().rsplit("/", 1)[-1]
    entry = GTFOBINS.get(name)
    if entry is not None:
        return entry
    # ``vim.basic`` / ``lua5.1`` → drop the .suffix
    if "." in name:
        base = name.split(".", 1)[0]
        entry = GTFOBINS.get(base)
        if entry is not None:
            return entry
        name = base
    # ``python3`` → ``python``; strip a trailing version number
    stripped = name.rstrip("0123456789")
    if stripped and stripped != name:
        return GTFOBINS.get(stripped)
    return None


def is_privesc(binary: str, surface: str) -> bool:
    """True if ``binary`` is a known escalation on ``surface`` (suid/sudo/capabilities)."""
    entry = lookup(binary)
    return bool(entry and getattr(entry, surface, False))


__all__ = ["GTFOEntry", "GTFOBINS", "lookup", "is_privesc"]

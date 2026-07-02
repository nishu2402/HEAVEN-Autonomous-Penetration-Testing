"""Guard: no committed compose file may publish a host port on 0.0.0.0.

This locks in the Docker-exposure fix (the DVWA benchmark target — a
deliberately-vulnerable RCE app — was published on 0.0.0.0:8080). Every host
port in a committed compose file must bind to loopback (127.0.0.1 / ::1); an
operator who genuinely wants public exposure does it via a reverse proxy or an
explicit local override, never the tracked compose. Because CI runs pytest,
this doubles as the CI guard against the exposure class coming back.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parent.parent
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _compose_files() -> list[Path]:
    out: list[Path] = []
    for pat in ("docker-compose*.yml", "docker-compose*.yaml",
                "compose*.yml", "compose*.yaml"):
        for p in _REPO.rglob(pat):
            parts = set(p.parts)
            if parts & {"venv", ".venv", "node_modules", ".git"}:
                continue
            out.append(p)
    return sorted(set(out))


def _host_ip_is_loopback(entry) -> bool:
    """True if this `ports:` entry is either container-only or bound to loopback."""
    # Long form: {target, published, host_ip, ...}
    if isinstance(entry, dict):
        if "published" not in entry:      # target-only, not published to host
            return True
        return str(entry.get("host_ip", "")) in _LOOPBACK
    # Short form string: "IP:HOST:CONTAINER" | "HOST:CONTAINER" | "CONTAINER".
    # rsplit from the right so an IPv6 host IP (which contains colons) stays whole.
    parts = str(entry).rsplit(":", 2)
    if len(parts) == 3:                   # IP:HOST:CONTAINER
        return parts[0].strip("[]") in _LOOPBACK
    # "HOST:CONTAINER" or bare "CONTAINER" → published on 0.0.0.0 by default.
    return False


def test_no_compose_file_publishes_on_all_interfaces():
    offenders: list[str] = []
    files = _compose_files()
    assert files, "expected to find at least one compose file"
    for f in files:
        doc = yaml.safe_load(f.read_text()) or {}
        for svc_name, svc in (doc.get("services") or {}).items():
            for entry in (svc or {}).get("ports", []) or []:
                if not _host_ip_is_loopback(entry):
                    offenders.append(
                        f"{f.relative_to(_REPO)} :: service '{svc_name}' "
                        f"publishes {entry!r} on all interfaces — bind it to "
                        f"127.0.0.1 (e.g. '127.0.0.1:{entry}')."
                    )
    assert not offenders, "Publicly-exposed host ports found:\n" + "\n".join(offenders)


@pytest.mark.parametrize("entry,ok", [
    ("127.0.0.1:8080:80", True),
    ("::1:8080:80", True),
    ("8080:80", False),
    ("0.0.0.0:8080:80", False),
    ("80", False),
    ({"target": 80, "published": 8080, "host_ip": "127.0.0.1"}, True),
    ({"target": 80, "published": 8080}, False),
    ({"target": 80}, True),
])
def test_host_ip_loopback_classifier(entry, ok):
    assert _host_ip_is_loopback(entry) is ok

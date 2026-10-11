"""Regression tests for the git-secrets scanner (FP Audit 16).

Two report-facing false-positive classes are pinned here:

1. A connection string with NO embedded credential (``postgres://localhost/db``)
   is page furniture that litters docker-compose / config files, not a leaked
   secret. Only ``user:password@host`` forms carry a credential.
2. A templated placeholder (``${DB_PASSWORD}``, ``{{ token }}``, ``<your-pass>``)
   is config scaffolding, not a live credential — the same placeholder class
   the client_audit source review already screens.
"""

from __future__ import annotations

from pathlib import Path

from heaven.recon.git_secrets import _is_template_placeholder, scan_file


def _scan(tmp_path: Path, name: str, body: str):
    f = tmp_path / name
    f.write_text(body)
    return scan_file(f, tmp_path)


def test_database_url_without_credentials_not_flagged(tmp_path: Path):
    body = (
        'db_url = "postgres://localhost:5432/appdb"\n'
        "DATABASE_URL=mongodb://mongo:27017/orders\n"
        'cache = "postgresql://db-host:5432/analytics"\n'
    )
    findings = _scan(tmp_path, "config.env", body)
    db = [f for f in findings if f.secret_type == "database_url"]
    assert db == [], f"credential-less DB URLs flagged as secrets: {[f.snippet for f in db]}"


def test_database_url_with_embedded_credential_flagged(tmp_path: Path):
    body = 'conn = "postgresql://user:s3cr3tPass@db.internal:5432/prod"\n'
    findings = _scan(tmp_path, "settings.py", body)
    db = [f for f in findings if f.secret_type == "database_url"]
    assert len(db) == 1, "embedded-credential DB URL must still be caught"
    assert db[0].pattern_name == "Database URL"


def test_password_only_user_credential_form_flagged(tmp_path: Path):
    # scheme://:password@host (no username) still embeds a live credential.
    findings = _scan(tmp_path, "db.conf", 'url = "mysql://:rootpw@10.0.0.5/app"\n')
    assert any(f.secret_type == "database_url" for f in findings)


def test_templated_placeholder_password_not_flagged(tmp_path: Path):
    body = (
        'password = "${DATABASE_PASSWORD}"\n'
        'db_password: "{{ vault_db_password }}"\n'
        'pwd = "<your-password-here>"\n'
        'jwt_secret = "${JWT_SIGNING_KEY}" \n'
    )
    findings = _scan(tmp_path, "values.yaml", body)
    leaked = [f for f in findings if f.secret_type in ("password", "jwt_secret")]
    assert leaked == [], f"template placeholders flagged as secrets: {[f.snippet for f in leaked]}"


def test_real_password_assignment_still_flagged(tmp_path: Path):
    # A concrete value (including a leetspeak secret whose bare '$' must NOT be
    # read as a template delimiter) and a weak default both remain findings.
    body = (
        'password = "R3al!SecretValue99"\n'
        'passwd = "P@$$w0rd1234"\n'
        'password = "changeme"\n'
    )
    findings = _scan(tmp_path, "app.ini", body)
    pw = [f for f in findings if f.secret_type == "password"]
    assert len(pw) == 3, f"real/weak passwords must still fire: {[f.snippet for f in pw]}"


def test_is_template_placeholder_unit():
    assert _is_template_placeholder("${SECRET}")
    assert _is_template_placeholder("{{ token }}")
    assert _is_template_placeholder("<your-key>")
    assert _is_template_placeholder("%(password)s")
    assert _is_template_placeholder("YOUR_API_KEY")
    # Real values — a bare '$' or '<' alone is not a signal.
    assert not _is_template_placeholder("P@$$w0rd1234")
    assert not _is_template_placeholder("changeme")
    assert not _is_template_placeholder("R3al!SecretValue99")

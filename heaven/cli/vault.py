"""HEAVEN — `heaven vault` : AES-256-GCM encrypted credential store.

An optional, encrypted-at-rest home for the same API keys and tokens the
Settings page / `heaven config` manage in ``.env``. The two coexist: every
secret in HEAVEN is read from ``os.environ``, and an unlocked vault populates
``os.environ`` for the process, so a key kept in the vault drives the scanner,
the LLM gateway, NVD enrichment and SIEM/ticketing exactly as a ``.env`` value
would — but it never touches the disk in plaintext.

  heaven vault init                    # create the vault (prompts a master password)
  heaven vault import-env --purge      # move plaintext .env secrets into the vault
  heaven vault set OPENAI_API_KEY      # add / update one credential (prompts hidden)
  heaven vault list                    # keys + rotation status (never the values)
  heaven vault load                    # decrypt into this process's environment

For a long-running `heaven serve`, export ``HEAVEN_VAULT_PASSWORD`` and the
server auto-loads the vault at startup (no plaintext keys on disk).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _print, emit_json, json_output
from heaven.security import vault as vaultlib
from heaven.settings_catalog import SETTINGS, mask


def _master_password(confirm: bool = False) -> str:
    """Master password from ``HEAVEN_VAULT_PASSWORD`` or an interactive prompt."""
    env = os.environ.get("HEAVEN_VAULT_PASSWORD")
    if env:
        return env
    return click.prompt("Master password", hide_input=True,
                        confirmation_prompt=confirm)


def _unlock_or_die(path: Path) -> "vaultlib.CredentialVault":
    """Unlock the on-disk vault or exit with a clear message."""
    if not path.exists():
        _print(f"[red]No vault at {path}.[/red] [dim]Create one: heaven vault init[/dim]")
        raise SystemExit(1)
    vault = vaultlib.open_vault(_master_password(), path)
    if vault is None:
        _print("[red]✗ Unlock failed[/red] [dim](wrong password or tampered vault).[/dim]")
        raise SystemExit(1)
    return vault


@click.group(name="vault")
def vault_grp() -> None:
    """Encrypted credential store (AES-256-GCM, an alternative to plaintext .env)."""


@vault_grp.command(name="init")
def init_cmd() -> None:
    """Create a new encrypted vault (prompts for a master password)."""
    path = vaultlib.default_vault_path()
    if path.exists():
        _print(f"[yellow]A vault already exists at {path}.[/yellow]")
        _print("[dim]Delete it manually to start over, or use `heaven vault set` to add keys.[/dim]")
        raise SystemExit(1)
    if not vaultlib.HAS_CRYPTO:
        _print("[yellow]⚠ 'cryptography' is not installed; the vault would store "
               "credentials in PLAINTEXT.[/yellow]")
        _print("[dim]Install it first:  pip install cryptography[/dim]")
        raise SystemExit(1)
    password = _master_password(confirm=True)
    vault = vaultlib.CredentialVault(vault_path=path)
    vault.initialize(password)
    vault.save()
    _print(f"[green]✓ Vault created[/green] [dim]→ {path}[/dim]  "
           "(AES-256-GCM, PBKDF2 600k)")
    _print("[dim]Next: heaven vault import-env   (move existing .env secrets in)[/dim]")


@vault_grp.command(name="status")
def status_cmd() -> None:
    """Show vault presence, encryption mode and credential count."""
    path = vaultlib.default_vault_path()
    present = path.exists()
    info = {"path": str(path), "exists": present,
            "cryptography": vaultlib.HAS_CRYPTO, "credentials": None}
    if present:
        # JSON mode must never block on a prompt: unlock only if a password is
        # already available via HEAVEN_VAULT_PASSWORD, otherwise leave the count
        # unknown. Interactive mode may prompt.
        env_pw = os.environ.get("HEAVEN_VAULT_PASSWORD")
        vault = None
        if not json_output() or env_pw:
            vault = vaultlib.open_vault(env_pw or _master_password(), path)
        if vault is None and not json_output():
            _print("[red]✗ Unlock failed[/red] [dim](wrong password or tampered vault).[/dim]")
            raise SystemExit(1)
        if vault is not None:
            info["credentials"] = len(vault.list_keys())
            vault.lock()
    if json_output():
        emit_json(info)
        return
    if not present:
        _print(f"[dim]· No vault at {path}[/dim]")
        _print("[dim]Create one: heaven vault init[/dim]")
        return
    enc = "AES-256-GCM" if vaultlib.HAS_CRYPTO else "[red]PLAINTEXT (cryptography missing)[/red]"
    _print(f"[green]✓ Vault[/green] [dim]{path}[/dim]")
    _print(f"  Encryption: {enc}")
    _print(f"  Credentials: {info['credentials']}")


@vault_grp.command(name="set")
@click.argument("key")
@click.argument("value", required=False)
@click.option("--rotate-days", type=int, default=None,
              help="Flag the credential for rotation after N days.")
def set_cmd(key: str, value: Optional[str], rotate_days: Optional[int]) -> None:
    """Store or update KEY in the vault (prompts securely if VALUE is omitted)."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    if value is None:
        value = click.prompt(f"Value for {key}", hide_input=True, default="",
                            show_default=False)
    if not value.strip():
        _print("[yellow]Empty value; nothing stored.[/yellow]")
        raise SystemExit(1)
    vault.store(key, value, rotation_days=rotate_days)
    vault.lock()
    _print(f"[green]✓ Stored[/green] {key} [dim](encrypted → {path})[/dim]")
    _print("[dim]Live for the next CLI run; restart `heaven serve` to pick it up.[/dim]")


@vault_grp.command(name="get")
@click.argument("key")
@click.option("--reveal", is_flag=True, help="Print the real value (default: masked).")
def get_cmd(key: str, reveal: bool) -> None:
    """Show one credential (masked unless --reveal)."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    value = vault.retrieve(key)
    vault.lock()
    if value is None:
        _print(f"[dim]{key} is not in the vault.[/dim]")
        raise SystemExit(1)
    shown = value if reveal else mask(value)
    _print(f"{key} = {shown}")


@vault_grp.command(name="list")
def list_cmd() -> None:
    """List stored credential keys and rotation status (never the values)."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    keys = vault.list_keys()
    vault.lock()
    if json_output():
        emit_json({"credentials": keys})
        return
    if not keys:
        _print("[dim]Vault is empty. Add a key: heaven vault set <KEY>[/dim]")
        return
    _print(f"[bold]{len(keys)} credential(s)[/bold] [dim]in {path}[/dim]")
    for meta in sorted(keys, key=lambda m: m["key"]):
        flag = " [yellow](rotation due)[/yellow]" if meta.get("needs_rotation") else ""
        _print(f"  [green]✓[/green] {meta['key']}  [dim]used {meta.get('access_count', 0)}×[/dim]{flag}")


@vault_grp.command(name="rm")
@click.argument("key")
def rm_cmd(key: str) -> None:
    """Delete KEY from the vault."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    removed = vault.delete(key)
    vault.lock()
    if removed:
        _print(f"[green]✓ Removed[/green] {key}")
    else:
        _print(f"[dim]{key} was not in the vault.[/dim]")


@vault_grp.command(name="rotate")
def rotate_cmd() -> None:
    """Re-encrypt every credential under a new master password."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    new_password = click.prompt("New master password", hide_input=True,
                               confirmation_prompt=True)
    vault.rotate_key(new_password)
    vault.lock()
    _print("[green]✓ Master password rotated[/green] [dim](all credentials re-encrypted).[/dim]")
    if os.environ.get("HEAVEN_VAULT_PASSWORD"):
        _print("[yellow]Remember to update HEAVEN_VAULT_PASSWORD to the new password.[/yellow]")


@vault_grp.command(name="import-env")
@click.option("--purge", is_flag=True,
              help="After importing, remove the secrets from .env (recommended; "
                   "they then live only in the encrypted vault).")
def import_env_cmd(purge: bool) -> None:
    """Copy currently-set secret settings from .env / the environment into the vault."""
    path = vaultlib.default_vault_path()
    vault = _unlock_or_die(path)
    secret_keys = [s.key for s in SETTINGS if s.secret]
    imported: list[str] = []
    for key in secret_keys:
        val = (os.environ.get(key) or "").strip()
        if val:
            vault.store(key, val)
            imported.append(key)
    vault.lock()
    if not imported:
        _print("[dim]No secret settings are currently set; nothing to import.[/dim]")
        return
    _print(f"[green]✓ Imported[/green] {len(imported)} secret(s) into the vault: "
           f"[dim]{', '.join(imported)}[/dim]")
    if purge:
        from heaven.settings_catalog import apply_settings
        apply_settings({k: "" for k in imported})
        _print("[green]✓ Purged[/green] those secrets from .env "
               "[dim](they now live only in the encrypted vault).[/dim]")
        _print("[dim]Load them by setting HEAVEN_VAULT_PASSWORD before `heaven serve`, or run `heaven vault load`.[/dim]")
    else:
        _print("[dim]The plaintext copies remain in .env. Re-run with --purge to remove them.[/dim]")


@vault_grp.command(name="load")
@click.option("--override", is_flag=True,
              help="Let vault values replace ones already set in the environment.")
def load_cmd(override: bool) -> None:
    """Decrypt the vault into this process's environment (diagnostic).

    A CLI process is short-lived, so this mainly proves the vault unlocks and
    which keys it would supply. The real use is `heaven serve`, which auto-loads
    the vault at startup when HEAVEN_VAULT_PASSWORD is set.
    """
    path = vaultlib.default_vault_path()
    count, message = vaultlib.load_into_env(path=path, override=override)
    if json_output():
        emit_json({"loaded": count, "message": message})
        return
    if count:
        _print(f"[green]✓ {message}[/green]")
    else:
        _print(f"[yellow]· {message}[/yellow]")


def register(cli: click.Group) -> None:
    cli.add_command(vault_grp)


__all__ = ["vault_grp", "register"]

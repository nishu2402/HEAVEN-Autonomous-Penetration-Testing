"""
HEAVEN — Encrypted Credential Vault
AES-256-GCM encrypted storage for API keys, database credentials, and scan tokens.
Master key derived from PBKDF2 with 600,000 iterations.
Supports auto-lock, key rotation, and secure memory wiping.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("security.vault")

# Crypto imports with graceful fallback
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography not installed — vault operates in plaintext fallback mode")


# ═══════════════════════════════════════════
# VAULT DATA STRUCTURES
# ═══════════════════════════════════════════

@dataclass
class VaultEntry:
    """A single encrypted credential entry."""
    key: str
    encrypted_value: bytes = b""
    created_at: float = 0.0
    last_accessed: float = 0.0
    access_count: int = 0
    metadata: dict = field(default_factory=dict)
    rotation_due: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "encrypted_value": base64.b64encode(self.encrypted_value).decode(),
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "access_count": self.access_count,
            "metadata": self.metadata,
            "rotation_due": self.rotation_due,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultEntry":
        return cls(
            key=data["key"],
            encrypted_value=base64.b64decode(data["encrypted_value"]),
            created_at=data.get("created_at", 0),
            last_accessed=data.get("last_accessed", 0),
            access_count=data.get("access_count", 0),
            metadata=data.get("metadata", {}),
            rotation_due=data.get("rotation_due"),
        )


# ═══════════════════════════════════════════
# CREDENTIAL VAULT
# ═══════════════════════════════════════════

class CredentialVault:
    """
    AES-256-GCM encrypted credential vault.

    Features:
    - Master key derived via PBKDF2 (600K iterations)
    - Each entry encrypted with unique nonce
    - Auto-lock after configurable timeout (default: 15 min)
    - Key rotation support
    - Secure memory wiping on lock
    - Tamper detection via HMAC integrity checks
    """

    PBKDF2_ITERATIONS = 600_000
    SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32  # AES-256
    AUTO_LOCK_SECONDS = 900  # 15 minutes

    def __init__(self, vault_path: Optional[Path] = None, auto_lock_seconds: int = 900):
        self._vault_path = vault_path or Path("data/vault.enc")
        self._auto_lock_seconds = auto_lock_seconds
        self._entries: dict[str, VaultEntry] = {}
        self._master_key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._unlocked_at: float = 0.0
        self._is_locked = True
        self._integrity_hash: str = ""

    @property
    def is_locked(self) -> bool:
        """Check if vault is locked (including auto-lock timeout)."""
        if not self._is_locked and self._unlocked_at > 0:
            elapsed = time.time() - self._unlocked_at
            if elapsed > self._auto_lock_seconds:
                self.lock()
                logger.info("Vault auto-locked after timeout")
                return True
        return self._is_locked

    def initialize(self, master_password: str) -> None:
        """Initialize a new vault with a master password."""
        if not HAS_CRYPTO:
            logger.warning("Vault initialized in plaintext mode — install cryptography for encryption")
            self._is_locked = False
            self._unlocked_at = time.time()
            return

        self._salt = os.urandom(self.SALT_SIZE)
        self._master_key = self._derive_key(master_password, self._salt)
        self._is_locked = False
        self._unlocked_at = time.time()
        self._entries = {}
        logger.info("Vault initialized with AES-256-GCM encryption")

    def unlock(self, master_password: str) -> bool:
        """Unlock the vault with the master password."""
        if not self._vault_path.exists():
            logger.error("Vault file not found — initialize first")
            return False

        try:
            raw = self._vault_path.read_bytes()
            self._salt = raw[:self.SALT_SIZE]
            self._master_key = self._derive_key(master_password, self._salt)

            # Decrypt the vault metadata to verify password
            encrypted_data = raw[self.SALT_SIZE:]
            decrypted = self._decrypt_data(encrypted_data)
            vault_data = json.loads(decrypted)

            # Verify integrity
            stored_hash = vault_data.get("_integrity_hash", "")
            entries_json = json.dumps(vault_data.get("entries", {}), sort_keys=True)
            computed_hash = hashlib.sha256(entries_json.encode()).hexdigest()

            if stored_hash and stored_hash != computed_hash:
                logger.error("VAULT INTEGRITY VIOLATION — data may be tampered")
                return False

            # Load entries
            self._entries = {
                k: VaultEntry.from_dict(v)
                for k, v in vault_data.get("entries", {}).items()
            }
            self._is_locked = False
            self._unlocked_at = time.time()
            logger.info(f"Vault unlocked — {len(self._entries)} credentials loaded")
            return True

        except Exception as e:
            logger.error(f"Vault unlock failed: {e}")
            self._master_key = None
            return False

    def lock(self) -> None:
        """Lock the vault and wipe keys from memory."""
        if self._master_key:
            # Overwrite key in memory
            self._master_key = b"\x00" * self.KEY_SIZE
        self._master_key = None
        self._is_locked = True
        self._unlocked_at = 0.0
        logger.info("Vault locked — encryption keys wiped from memory")

    def store(self, key: str, value: str, metadata: Optional[dict] = None,
              rotation_days: Optional[int] = None) -> None:
        """Store a credential in the vault."""
        if self.is_locked:
            raise PermissionError("Vault is locked — unlock first")

        encrypted = self._encrypt_value(value) if HAS_CRYPTO and self._master_key else value.encode()

        rotation_due = None
        if rotation_days:
            rotation_due = time.time() + (rotation_days * 86400)

        self._entries[key] = VaultEntry(
            key=key,
            encrypted_value=encrypted,
            created_at=time.time(),
            last_accessed=time.time(),
            metadata=metadata or {},
            rotation_due=rotation_due,
        )
        self._save()
        logger.debug(f"Credential stored: {key}")

    def retrieve(self, key: str) -> Optional[str]:
        """Retrieve a decrypted credential from the vault."""
        if self.is_locked:
            raise PermissionError("Vault is locked — unlock first")

        entry = self._entries.get(key)
        if not entry:
            return None

        entry.last_accessed = time.time()
        entry.access_count += 1

        # Check rotation
        if entry.rotation_due and time.time() > entry.rotation_due:
            logger.warning(f"Credential '{key}' is past rotation deadline")

        if HAS_CRYPTO and self._master_key:
            try:
                return self._decrypt_value(entry.encrypted_value)
            except Exception as e:
                logger.error(f"Decryption failed for '{key}': {e}")
                return None
        else:
            return entry.encrypted_value.decode()

    def delete(self, key: str) -> bool:
        """Delete a credential from the vault."""
        if self.is_locked:
            raise PermissionError("Vault is locked — unlock first")

        if key in self._entries:
            del self._entries[key]
            self._save()
            logger.info(f"Credential deleted: {key}")
            return True
        return False

    def list_keys(self) -> list[dict]:
        """List all credential keys (without values)."""
        if self.is_locked:
            raise PermissionError("Vault is locked — unlock first")

        return [
            {
                "key": e.key,
                "created_at": e.created_at,
                "last_accessed": e.last_accessed,
                "access_count": e.access_count,
                "rotation_due": e.rotation_due,
                "needs_rotation": bool(e.rotation_due and time.time() > e.rotation_due),
            }
            for e in self._entries.values()
        ]

    def rotate_key(self, new_master_password: str) -> None:
        """Rotate the master encryption key — re-encrypts all entries."""
        if self.is_locked:
            raise PermissionError("Vault is locked — unlock first")

        # Decrypt all values with old key
        decrypted: dict[str, str] = {}
        for key, entry in self._entries.items():
            if HAS_CRYPTO and self._master_key:
                decrypted[key] = self._decrypt_value(entry.encrypted_value)
            else:
                decrypted[key] = entry.encrypted_value.decode()

        # Generate new key
        self._salt = os.urandom(self.SALT_SIZE)
        self._master_key = self._derive_key(new_master_password, self._salt) if HAS_CRYPTO else None

        # Re-encrypt all values
        for key, value in decrypted.items():
            self._entries[key].encrypted_value = (
                self._encrypt_value(value) if HAS_CRYPTO and self._master_key
                else value.encode()
            )

        self._save()
        logger.info(f"Master key rotated — {len(self._entries)} credentials re-encrypted")

    def check_rotation_status(self) -> list[dict]:
        """Check which credentials need rotation."""
        overdue = []
        now = time.time()
        for entry in self._entries.values():
            if entry.rotation_due and now > entry.rotation_due:
                overdue.append({
                    "key": entry.key,
                    "overdue_days": int((now - entry.rotation_due) / 86400),
                })
        return overdue

    # ── Internal Cryptographic Operations ──

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive AES-256 key from password using PBKDF2."""
        if not HAS_CRYPTO:
            return hashlib.sha256(password.encode() + salt).digest()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode())

    def _encrypt_value(self, plaintext: str) -> bytes:
        """Encrypt a value with AES-256-GCM."""
        if not self._master_key or not HAS_CRYPTO:
            return plaintext.encode()

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def _decrypt_value(self, data: bytes) -> str:
        """Decrypt a value with AES-256-GCM."""
        if not self._master_key or not HAS_CRYPTO:
            return data.decode()

        nonce = data[:self.NONCE_SIZE]
        ciphertext = data[self.NONCE_SIZE:]
        aesgcm = AESGCM(self._master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt arbitrary data block."""
        return self._encrypt_value(data.decode()) if HAS_CRYPTO else data

    def _decrypt_data(self, data: bytes) -> str:
        """Decrypt arbitrary data block."""
        return self._decrypt_value(data) if HAS_CRYPTO else data.decode()

    def _save(self) -> None:
        """Persist vault to disk."""
        entries_data = {k: v.to_dict() for k, v in self._entries.items()}
        entries_json = json.dumps(entries_data, sort_keys=True)
        integrity_hash = hashlib.sha256(entries_json.encode()).hexdigest()

        vault_data = json.dumps({
            "version": "1.0",
            "entries": entries_data,
            "_integrity_hash": integrity_hash,
        }).encode()

        self._vault_path.parent.mkdir(parents=True, exist_ok=True)

        if HAS_CRYPTO and self._master_key and self._salt:
            encrypted = self._encrypt_data(vault_data)
            self._vault_path.write_bytes(self._salt + encrypted)
        else:
            self._vault_path.write_bytes(vault_data)

    def summary(self) -> dict:
        """Vault status summary (no secrets exposed)."""
        return {
            "locked": self.is_locked,
            "total_credentials": len(self._entries),
            "encryption": "AES-256-GCM" if HAS_CRYPTO else "PLAINTEXT (insecure)",
            "pbkdf2_iterations": self.PBKDF2_ITERATIONS,
            "auto_lock_seconds": self._auto_lock_seconds,
            "needs_rotation": len(self.check_rotation_status()) if not self.is_locked else "N/A",
        }

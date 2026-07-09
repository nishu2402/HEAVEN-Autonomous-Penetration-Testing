"""
HEAVEN — RBAC Authentication & Authorization
JWT-based session management with role-based access control.
Supports: admin, operator, viewer, auditor roles.
Brute-force protection with exponential backoff.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("security.auth")

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    pyjwt = None  # type: ignore
    HAS_JWT = False


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"


# Permission matrix: role → allowed actions
PERMISSIONS = {
    Role.ADMIN: {"scan.create", "scan.cancel", "scan.view", "vuln.view", "vuln.create", "vuln.validate",
                 "vuln.update", "config.modify", "user.manage", "vault.access", "audit.view", "audit.export",
                 "report.generate", "report.view", "ad.scan", "mitre.view"},
    Role.OPERATOR: {"scan.create", "scan.cancel", "scan.view", "vuln.view", "vuln.create", "vuln.validate",
                    "vuln.update", "report.generate", "report.view", "ad.scan", "mitre.view"},
    Role.VIEWER: {"scan.view", "vuln.view", "report.view", "mitre.view"},
    Role.AUDITOR: {"scan.view", "vuln.view", "audit.view", "audit.export", "report.view", "mitre.view"},
}


@dataclass
class User:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    password_hash: str = ""
    role: Role = Role.VIEWER
    api_key: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_login: float = 0.0
    failed_attempts: int = 0
    locked_until: float = 0.0
    is_active: bool = True
    must_change_password: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id, "username": self.username, "role": self.role.value,
            "created_at": self.created_at, "last_login": self.last_login,
            "is_active": self.is_active, "has_api_key": bool(self.api_key),
            "must_change_password": self.must_change_password,
        }


@dataclass
class Session:
    token: str = ""
    user_id: str = ""
    role: Role = Role.VIEWER
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    source_ip: str = ""


class AuthManager:
    """
    RBAC authentication manager with JWT tokens and brute-force protection.
    """
    JWT_SECRET_SIZE = 64
    TOKEN_EXPIRY = 3600  # 1 hour
    REFRESH_EXPIRY = 86400  # 24 hours
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_BASE_SECONDS = 60

    def __init__(self, jwt_secret: Optional[str] = None):
        self._jwt_secret = jwt_secret or os.urandom(self.JWT_SECRET_SIZE).hex()
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._api_keys: dict[str, str] = {}  # api_key → user_id
        # A throwaway hash used to spend the same PBKDF2 time on a login for a
        # non-existent user as for a real one — closes the username-enumeration
        # timing side channel.
        self._dummy_hash = self._hash_password(os.urandom(16).hex())
        self._setup_default_admin()

    def _setup_default_admin(self) -> None:
        # The admin *identity* is configurable via env so the operator console
        # isn't stuck showing a generic "admin" forever. Set HEAVEN_ADMIN_USERNAME
        # in .env (or via `heaven init`) to brand it; defaults to "admin".
        admin_user = (os.environ.get("HEAVEN_ADMIN_USERNAME") or "admin").strip() or "admin"
        admin_pass = os.environ.get("HEAVEN_ADMIN_PASSWORD", "")
        if admin_pass:
            # Operator supplied a strong password via env — trust it, no forced change.
            self.create_user(admin_user, admin_pass, Role.ADMIN)
            return
        # No env password: generate a strong RANDOM admin password instead of a
        # weak static default (admin/admin). It is printed ONCE below so the
        # operator can sign in, and a password change is still forced on first
        # login. Zero-config onboarding with no shipped weak credential.
        import secrets
        generated = secrets.token_urlsafe(12)  # ~16 URL-safe chars
        user = self.create_user(admin_user, generated, Role.ADMIN)
        user.must_change_password = True
        logger.warning(
            "\n"
            "  ┌──────────────────────────────────────────────────────────────┐\n"
            "  │  HEAVEN — first-run admin credentials (shown once)             │\n"
            "  │  No HEAVEN_ADMIN_PASSWORD set, so a random one was generated.  │\n"
            "  ├──────────────────────────────────────────────────────────────┤\n"
            "  │  username: %-51s│\n"
            "  │  password: %-51s│\n"
            "  ├──────────────────────────────────────────────────────────────┤\n"
            "  │  You must change this password on first login. To pin a        │\n"
            "  │  persistent one, set HEAVEN_ADMIN_PASSWORD in .env / heaven init│\n"
            "  └──────────────────────────────────────────────────────────────┘",
            admin_user, generated,
        )

    def verify_user_password(self, username: str, password: str) -> bool:
        """Constant-time check of a user's current password (no token, no lockout
        side-effects). Used by the change-password flow."""
        user = next((u for u in self._users.values() if u.username == username), None)
        return bool(user and self._verify_password(password, user.password_hash))

    def set_password(self, username: str, new_password: str) -> bool:
        """Change a user's password and clear the must-change flag. Enforces a
        minimum strength so the forced change can't be a no-op (admin -> admin)."""
        user = next((u for u in self._users.values() if u.username == username), None)
        if not user:
            return False
        if not new_password or len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if new_password.lower() in {"admin", "password", "changeme", "admin123", "administrator"}:
            raise ValueError("Password is too common — choose a stronger one")
        user.password_hash = self._hash_password(new_password)
        user.must_change_password = False
        user.failed_attempts = 0
        user.locked_until = 0.0
        return True

    def _hash_password(self, password: str, salt: Optional[str] = None) -> str:
        salt = salt or os.urandom(16).hex()
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
        return f"{salt}${hashed.hex()}"

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        parts = stored_hash.split("$")
        if len(parts) != 2:
            return False
        salt, expected = parts
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
        return hmac.compare_digest(actual.hex(), expected)

    def create_user(self, username: str, password: str, role: Role = Role.VIEWER) -> User:
        user = User(
            username=username,
            password_hash=self._hash_password(password),
            role=role,
            api_key=f"hv4_{os.urandom(24).hex()}",
        )
        self._users[user.id] = user
        if user.api_key:
            self._api_keys[user.api_key] = user.id
        logger.info(f"User created: {username} (role={role.value})")
        return user

    def authenticate(self, username: str, password: str, source_ip: str = "") -> Optional[dict]:
        user = next((u for u in self._users.values() if u.username == username), None)
        if not user:
            # Spend the same PBKDF2 cost as a real login so response time does
            # not reveal whether the username exists.
            self._verify_password(password, self._dummy_hash)
            return None
        if not user.is_active:
            logger.warning(f"Login attempt for disabled user: {username}")
            return None
        # Check lockout
        if user.locked_until > time.time():
            remaining = int(user.locked_until - time.time())
            logger.warning(f"User {username} locked for {remaining}s more")
            return None
        if not self._verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                lockout = self.LOCKOUT_BASE_SECONDS * (2 ** (user.failed_attempts - self.MAX_FAILED_ATTEMPTS))
                user.locked_until = time.time() + min(lockout, 3600)
                logger.warning(f"BRUTE FORCE: User {username} locked for {lockout}s after {user.failed_attempts} failures")
            return None
        # Success
        user.failed_attempts = 0
        user.locked_until = 0
        user.last_login = time.time()
        token = self._issue_token(user, source_ip)
        return {"token": token, "user": user.to_dict(), "expires_in": self.TOKEN_EXPIRY,
                "must_change_password": user.must_change_password}

    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        user_id = self._api_keys.get(api_key)
        if user_id and user_id in self._users:
            user = self._users[user_id]
            if user.is_active:
                return user
        return None

    def authorize(self, token: str, permission: str) -> bool:
        session = self._sessions.get(token)
        if not session or session.expires_at < time.time():
            return False
        allowed = PERMISSIONS.get(session.role, set())
        return permission in allowed

    def check_permission(self, user: User, permission: str) -> bool:
        allowed = PERMISSIONS.get(user.role, set())
        return permission in allowed

    def _issue_token(self, user: User, source_ip: str = "") -> str:
        now = time.time()
        payload = {
            "sub": user.id, "username": user.username, "role": user.role.value,
            "iat": now, "exp": now + self.TOKEN_EXPIRY, "jti": str(uuid.uuid4()),
        }
        if HAS_JWT:
            token = pyjwt.encode(payload, self._jwt_secret, algorithm="HS256")
        else:
            token = f"hv4_session_{os.urandom(32).hex()}"
        # Opportunistically drop expired sessions so the in-memory store can't
        # grow without bound over a long-running server.
        if len(self._sessions) > 64:
            self._sessions = {t: s for t, s in self._sessions.items()
                              if s.expires_at > now}
        self._sessions[token] = Session(
            token=token, user_id=user.id, role=user.role,
            created_at=now, expires_at=now + self.TOKEN_EXPIRY, source_ip=source_ip,
        )
        return token

    def revoke_token(self, token: str) -> bool:
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def summary(self) -> dict:
        return {
            "total_users": len(self._users),
            "active_sessions": sum(1 for s in self._sessions.values() if s.expires_at > time.time()),
            "roles": {r.value: sum(1 for u in self._users.values() if u.role == r) for r in Role},
        }


_auth_manager: Optional[AuthManager] = None

def get_auth_manager() -> AuthManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager

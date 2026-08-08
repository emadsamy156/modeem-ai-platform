"""Password hashing and session-token utilities.

Password hashing uses Argon2id via argon2-cffi (the maintained Python
binding of the reference Argon2 implementation).

Session tokens are signed JWTs (HS256) carried in an HttpOnly cookie.
The signing secret comes from the AUTH_SECRET environment variable.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from app.core.config import get_settings

SESSION_COOKIE_NAME = "modeem_session"

_hasher = PasswordHasher()  # Argon2id by default


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, ValueError):
        return False


def create_session_token(
    user_id: uuid.UUID, tenant_id: uuid.UUID | None, *, expires_in_seconds: int | None = None
) -> str:
    settings = get_settings()
    if not settings.auth_secret:
        raise RuntimeError("AUTH_SECRET is not configured")
    ttl = expires_in_seconds or settings.session_ttl_seconds
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    if tenant_id is not None:
        payload["tid"] = str(tenant_id)
    return jwt.encode(payload, settings.auth_secret, algorithm="HS256")


def decode_session_token(token: str) -> dict[str, Any] | None:
    settings = get_settings()
    if not settings.auth_secret:
        return None
    try:
        return jwt.decode(token, settings.auth_secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

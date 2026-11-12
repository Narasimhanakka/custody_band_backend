"""
Security & Authentication Core
Password hashing and JWT generation / decoding.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import hashlib
import hmac
import jwt

try:
    import bcrypt
except ImportError:
    bcrypt = None


def _legacy_password_hash(password: str) -> str:
    return hashlib.sha256(("custody_salt_2026" + password).encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    if bcrypt is None:
        return _legacy_password_hash(password)
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False

    if len(hashed_password) == 64 and all(char in "0123456789abcdefABCDEF" for char in hashed_password):
        return hmac.compare_digest(_legacy_password_hash(plain_password), hashed_password.lower())

    if bcrypt is not None and hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8")[:72],
                hashed_password.encode("ascii"),
            )
        except (TypeError, ValueError):
            return False

    return False


from ..config import settings


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generates an encoded JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

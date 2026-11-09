"""
Authentication and Authorization Service.
Implements PBKDF2-HMAC-SHA256 password hashing, JWT creation & validation,
role-based access control, and time-bounded signed video access tokens.
"""

import datetime
import hashlib
import hmac
import os
import secrets
from typing import Optional, Dict, Any

import jwt
from fastapi import Depends, HTTPException, status, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.config import settings
from app.database.connection import get_db
from app.models.schema import User

bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """
    Secure password hashing using PBKDF2-HMAC-SHA256 with 100,000 iterations
    and a cryptographically secure 16-byte random salt.
    Format: pbkdf2_sha256$100000$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(16)
    iterations = 100000
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived_key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a hashed string.
    Supports secure PBKDF2-HMAC-SHA256 and provides backwards compatibility
    for legacy SHA-256 passwords.
    """
    if not hashed_password:
        return False

    if hashed_password.startswith("pbkdf2_sha256$"):
        parts = hashed_password.split("$")
        if len(parts) != 4:
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = parts[3]
        computed_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(computed_key.hex(), expected_hash)

    # Backwards compatibility check for plain sha256
    legacy_hash = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, hashed_password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    """
    Generates a cryptographically signed JWT access token.
    """
    to_encode = data.copy()
    now = datetime.datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "iat": now,
        "exp": expire,
        "iss": "surveilguard-ai",
    })
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a JWT access token.
    Returns decoded payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer="surveilguard-ai",
        )
        return payload
    except jwt.PyJWTError:
        return None


def create_signed_video_token(video_id: str, user_id: Optional[int] = None, expires_minutes: Optional[int] = None) -> str:
    """
    Creates a temporary signed token allowing browser playback of a specific evidence video.
    """
    mins = expires_minutes or settings.SIGNED_URL_EXPIRE_MINUTES
    now = datetime.datetime.utcnow()
    payload = {
        "sub": "video_access",
        "video_id": video_id,
        "user_id": user_id,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=mins),
        "iss": "surveilguard-ai-media",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_signed_video_token(token: str, video_id: str) -> bool:
    """
    Validates a temporary signed token against a specific video ID.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer="surveilguard-ai-media",
        )
        return payload.get("video_id") == video_id
    except jwt.PyJWTError:
        return False


def get_current_user_optional(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Extracts and validates the current user if token is provided, without failing if absent.
    """
    if not auth or not auth.credentials:
        return None

    payload = decode_access_token(auth.credentials)
    if not payload or "sub" not in payload:
        return None

    username = payload["sub"]
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    return user


def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Mandatory authentication dependency.
    Raises 401 Unauthorized if Bearer token is missing, expired, or invalid.
    """
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(auth.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload["sub"]
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists or is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Role-based authorization: Requires admin privilege.
    """
    if current_user.role.lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges are required for this action.",
        )
    return current_user


def require_operator_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Role-based authorization: Requires operator or admin privilege.
    """
    if current_user.role.lower() not in ("admin", "operator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator or Admin privileges are required for this action.",
        )
    return current_user

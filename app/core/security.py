"""RedPulse - Security Module.

Password hashing, JWT token creation/validation, and authentication utilities.
"""

import json
import time
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# Password hashing with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


# JWT token handling
def create_access_token(
    subject: str,
    expires_minutes: int = None,
) -> str:
    """Create a JWT access token.

    Args:
        subject: The subject of the token (usually user email or user ID)
        expires_minutes: Token expiry time in minutes. Uses JWT_ACCESS_TOKEN_EXPIRE_MINUTES from config if None.

    Returns:
        Encoded JWT string
    """
    if expires_minutes is None:
        expires_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES

    expires = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)

    to_encode = {"exp": expires, "sub": subject}

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )

    return encoded_jwt


def create_refresh_token(subject: str, expires_days: int = 30) -> str:
    """Create a JWT refresh token.

    Args:
        subject: The subject of the token (usually user email or user ID)
        expires_days: Token expiry time in days

    Returns:
        Encoded JWT string
    """
    expires = datetime.now(timezone.utc) + timedelta(days=expires_days)

    to_encode = {"exp": expires, "sub": subject}

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )

    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.

    Args:
        token: The JWT token string

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid or expired token: {e}")


def get_token_subject(token: str) -> str:
    """Extract the subject from a JWT token.

    Args:
        token: The JWT token string

    Returns:
        The subject string (usually user email)

    Raises:
        ValueError: If token is invalid
    """
    payload = decode_token(token)
    subject: str = payload.get("sub")
    if subject is None:
        raise ValueError("Token contains no subject")
    return subject


def is_token_expired(token: str) -> bool:
    """Check if a JWT token is expired.

    Args:
        token: The JWT token string

    Returns:
        True if token is expired, False otherwise
    """
    payload = decode_token(token)
    exp: float = payload.get("exp", 0)
    return datetime.now(timezone.utc).timestamp() > exp
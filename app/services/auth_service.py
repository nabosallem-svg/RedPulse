"""ReconPilot - Authentication Service.

Handles user creation, authentication, and token refresh operations.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import User
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token, decode_token


async def create_user(db: AsyncSession, email: str, password: str) -> User:
    """Create a new user with hashed password.

    Args:
        db: Async database session
        email: User email address
        password: Plain text password

    Returns:
        Created User instance

    Raises:
        IntegrityError: If email already exists (unique constraint)
    """
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise ValueError("Email already registered")

    # Hash password and create user
    hashed_password = get_password_hash(password)  # Note: this needs to be imported or defined

    user = User(
        email=email,
        hashed_password=hashed_password,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    """Authenticate a user by email and password.

    Args:
        db: Async database session
        email: User email address
        password: Plain text password

    Returns:
        User instance if authentication succeeds, None otherwise
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


async def refresh_access_token(refresh_token: str) -> str | None:
    """Refresh an access token using a refresh token.

    Args:
        refresh_token: The refresh JWT token

    Returns:
        New access token if refresh token is valid, None otherwise
    """
    try:
        payload = decode_token(refresh_token)
        subject: str = payload.get("sub")

        if subject is None:
            return None

        new_access_token = create_access_token(subject=subject)
        return new_access_token

    except ValueError:
        return None
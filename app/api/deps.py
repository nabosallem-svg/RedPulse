"""ReconPilot - API Dependencies.

Dependency injection for database sessions and authentication.
"""

from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_token
from app.db.session import async_session_factory, engine

from app.db.models import User
from app.db.base import Base


get_bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> Generator[AsyncSession, None, None]:
    """Dependency that provides an async database session.

    Yields:
        AsyncSession: A SQLAlchemy async session.
    """
    async with async_session_factory() as session:
        yield session


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(get_bearer_scheme),
) -> User:
    """Dependency that extracts and validates the JWT, returning the current User.

    Args:
        db: Database session dependency.
        credentials: Bearer token credentials from the Authorization header.

    Returns:
        User instance if the token is valid and the user exists.

    Raises:
        HTTPException: 401 if the token is missing, invalid, or the user is not found.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
        subject: str = payload.get("sub")

        if subject is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Look up the user by email (subject is the email)
        result = await db.execute(select(User).where(User.email == subject))
        user = result.scalar_one_or_none()

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Ensure user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
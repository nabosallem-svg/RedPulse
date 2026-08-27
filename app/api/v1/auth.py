"""RedPulse - Authentication Routes.

Handles user signup, login, and token refresh.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.auth_service import create_user, authenticate_user, refresh_access_token


class SignupSchema(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plain text password")


class LoginSchema(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plain text password")


class RefreshSchema(BaseModel):
    refresh_token: str = Field(..., description="The refresh JWT token")


router = APIRouter(tags=["auth"])


class UserSchema(BaseModel):
    id: str
    email: str
    is_active: bool


@router.get("/me", response_model=UserSchema)
async def get_me(current_user: User = Depends(get_current_user)) -> UserSchema:
    """Get current authenticated user info.

    Requires valid JWT Bearer token in Authorization header.

    Returns:
        User schema with id, email, and is_active status

    Raises:
        HTTPException: 401 if not authenticated or token invalid/expired
    """
    return UserSchema(
        id=current_user.id,
        email=current_user.email,
        is_active=current_user.is_active,
    )


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(
    data: SignupSchema,
    db = Depends(get_db),
):
    """Register a new user.

    Args:
        data: Signup data
        db: Database session

    Returns:
        Access and refresh tokens on successful registration

    Raises:
        HTTPException: 400 if email already registered
    """
    try:
        user = await create_user(db, email=data.email, password=data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Create access and refresh tokens
    from app.core.security import create_access_token, create_refresh_token

    access_token = create_access_token(subject=user.email)
    refresh_token = create_refresh_token(subject=user.email)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/login")
async def login(
    data: LoginSchema,
    db = Depends(get_db),
):
    """Login with email and password.

    Args:
        data: Login data
        db: Database session

    Returns:
        Access and refresh tokens on successful login

    Raises:
        HTTPException: 401 if email or password is incorrect
    """
    user = await authenticate_user(db, email=data.email, password=data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access and refresh tokens
    from app.core.security import create_access_token, create_refresh_token

    access_token = create_access_token(subject=user.email)
    refresh_token = create_refresh_token(subject=user.email)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
async def refresh(
    data: RefreshSchema,
    db = Depends(get_db),
):
    """Refresh an access token using a refresh token.

    Args:
        data: Refresh data
        db: Database session

    Returns:
        New access token if refresh token is valid

    Raises:
        HTTPException: 401 if refresh token is invalid or expired
    """
    new_access_token = await refresh_access_token(refresh_token=data.refresh_token)

    if new_access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.core.security import create_access_token

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }
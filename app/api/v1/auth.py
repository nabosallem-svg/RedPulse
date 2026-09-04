"""RedPulse - Authentication Routes.

Handles user signup, login, and token refresh.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.auth_service import create_user, authenticate_user, refresh_access_token


class SignupSchema(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Plain text password (min 8 chars)")


class LoginSchema(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plain text password")


class RefreshSchema(BaseModel):
    refresh_token: str | None = Field(None, description="The refresh JWT token (optional if sent as httpOnly cookie)")


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
    response: Response,
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

    # Fix: Store tokens in httpOnly Secure cookies to mitigate XSS token theft via localStorage (C-01)
    # Monorepo single-origin (frontend+API on same domain) — SameSite=Lax, no Bearer fallback needed
    import os as _os
    _is_prod = _os.getenv("ENVIRONMENT", "").lower() == "production"
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True if _is_prod else False,
        samesite="lax",
        max_age=60 * 30,  # 30 min matches ACCESS_TOKEN_EXPIRE_MINUTES
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True if _is_prod else False,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,  # 7 days
        path="/api/v1/auth",
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/login")
async def login(
    data: LoginSchema,
    response: Response,
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

    import os as _os2
    _is_prod2 = _os2.getenv("ENVIRONMENT", "").lower() == "production"
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True if _is_prod2 else False,
        samesite="lax",
        max_age=60 * 30,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True if _is_prod2 else False,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/api/v1/auth",
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
    data: RefreshSchema,
    db = Depends(get_db),
):
    """Refresh an access token using a refresh token.

    Accepts refresh_token via JSON body or httpOnly cookie (for frontend with withCredentials).
    Falls back to request.cookies.get('refresh_token') when body is empty — pure cookie flow.
    """
    # Try body first, then httpOnly cookie fallback (frontend with withCredentials:true sends it automatically)
    token = data.refresh_token
    if not token:
        token = request.cookies.get("refresh_token")

    new_access_token = await refresh_access_token(refresh_token=token or "")

    if new_access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.core.security import create_access_token

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 30,
        path="/",
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }


@router.post("/logout")
async def logout(response: Response):
    """Clear httpOnly auth cookies (defense-in-depth for XSS)."""
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/api/v1/auth")
    return {"detail": "Logged out"}
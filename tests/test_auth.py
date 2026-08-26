"""ReconPilot - Authentication Tests.

End-to-end tests for signup, login, token refresh, and protected routes.
Uses SQLite in-memory for test database isolation.
"""

from app.core.security import decode_token


def test_signup_success(client):
    """Signup with valid email/password should succeed."""
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": "user@example.com", "password": "securepassword123"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    payload = decode_token(data["access_token"])
    assert payload["sub"] == "user@example.com"


def test_signup_duplicate_email_rejected(client):
    """Signup with duplicate email should be rejected."""
    client.post(
        "/api/v1/auth/signup",
        json={"email": "user@example.com", "password": "securepassword123"},
    )
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": "user@example.com", "password": "anotherpassword"},
    )
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]


def test_login_success(client):
    """Login with correct credentials should succeed."""
    client.post(
        "/api/v1/auth/signup",
        json={"email": "login@example.com", "password": "password123"},
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "login@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    payload = decode_token(data["access_token"])
    assert payload["sub"] == "login@example.com"


def test_login_wrong_password_fails(client):
    """Login with wrong password should fail."""
    client.post(
        "/api/v1/auth/signup",
        json={"email": "wrongpass@example.com", "password": "correctpassword"},
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "wrongpass@example.com", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_refresh_access_token(client):
    """Refresh access token using valid refresh token."""
    signup_response = client.post(
        "/api/v1/auth/signup",
        json={"email": "refresh@example.com", "password": "password123"},
    )
    tokens = signup_response.json()
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh_response.status_code == 200
    payload = decode_token(refresh_response.json()["access_token"])
    assert payload["sub"] == "refresh@example.com"


def test_refresh_invalid_token_fails(client):
    """Refresh with invalid token should fail."""
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid.token.string"},
    )
    assert response.status_code == 401


def test_protected_route_no_token_fails(client):
    """Access protected route without token should fail."""
    response = client.get("/api/v1/me")
    assert response.status_code == 401


def test_protected_route_invalid_token_fails(client):
    """Access protected route with invalid token should fail."""
    response = client.get(
        "/api/v1/me",
        headers={"Authorization": "Bearer invalid.token.string"},
    )
    assert response.status_code == 401


def test_protected_route_valid_token_succeeds(client):
    """Access protected route with valid token should succeed."""
    signup_response = client.post(
        "/api/v1/auth/signup",
        json={"email": "protected@example.com", "password": "password123"},
    )
    tokens = signup_response.json()
    response = client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == "protected@example.com"

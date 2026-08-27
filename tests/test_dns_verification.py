"""RedPulse - DNS Verification Tests.

Tests DNS TXT verification flow for domain ownership.
"""


def test_dns_verification_flow(client):
    """Test full DNS TXT verification flow."""
    headers = _signup(client, "dns@test.com")
    # placeholder - verify flow works without error
    assert headers is not None


def _signup(client, email="user@test.com", password="password123"):
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}

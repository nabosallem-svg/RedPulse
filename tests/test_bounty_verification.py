"""RedPulse - Bug Bounty Verification Tests.

Tests bug bounty program verification flow with mock API responses.
"""


def test_bounty_verification_no_connection(client):
    """Test that verification fails when user has no platform connection."""
    headers = _signup(client, "bounty@test.com")
    proj_resp = client.post("/api/v1/projects/", json={"name": "Test Project"}, headers=headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    engagement_response = client.post(
        "/api/v1/engagements/",
        json={"name": "Bounty Test", "project_id": project_id},
        headers=headers,
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    auth_response = client.post(
        f"/api/v1/engagements/{engagement_id}/authorization",
        json={
            "method": "bug_bounty_program",
            "bounty_platform": "hackerone",
            "bounty_program_handle": "test-program",
        },
        headers=headers,
    )
    assert auth_response.status_code == 400


def test_bounty_verification_unsupported_method(client):
    """Test that unsupported bounty platforms are rejected."""
    headers = _signup(client, "bounty2@test.com")
    proj_resp = client.post("/api/v1/projects/", json={"name": "Test Project"}, headers=headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    engagement_response = client.post(
        "/api/v1/engagements/",
        json={"name": "Bounty Test", "project_id": project_id},
        headers=headers,
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    auth_response = client.post(
        f"/api/v1/engagements/{engagement_id}/authorization",
        json={
            "method": "bug_bounty_program",
            "bounty_platform": "unsupported_platform",
            "bounty_program_handle": "test-program",
        },
        headers=headers,
    )
    assert auth_response.status_code == 400


def _signup(client, email="user@test.com", password="password123"):
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}

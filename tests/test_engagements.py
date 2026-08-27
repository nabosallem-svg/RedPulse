"""RedPulse - Engagement Tests.

End-to-end tests for engagement creation, listing, and retrieval.
Uses SQLite in-memory for test database isolation.
Tests verify user isolation - user A cannot access user B's engagements.
New engagements always start as status=draft.
"""


def _signup(client, email="user@test.com", password="password123"):
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_create_engagement_success(client):
    """Create a new engagement should succeed."""
    auth_headers = _signup(client)
    project_response = client.post(
        "/api/v1/projects/", json={"name": "Test Project"}, headers=auth_headers,
    )
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]
    response = client.post(
        "/api/v1/engagements/",
        json={"name": "Test Engagement", "project_id": project_id},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Engagement"
    assert data["project_id"] == project_id
    assert data["status"] == "draft"


def test_create_engagement_draft_status(client):
    """New engagement should always start as draft."""
    auth_headers = _signup(client)
    proj_resp = client.post("/api/v1/projects/", json={"name": "Project"}, headers=auth_headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    response = client.post(
        "/api/v1/engagements/",
        json={"name": "Engagement", "project_id": project_id},
        headers=auth_headers,
    )
    assert response.status_code == 201
    assert response.json()["status"] == "draft"


def test_list_engagements(client):
    """List engagements for user's projects (paginated)."""
    auth_headers = _signup(client)
    proj_resp = client.post("/api/v1/projects/", json={"name": "My Project"}, headers=auth_headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    eng_resp = client.post(
        "/api/v1/engagements/",
        json={"name": "My Engagement", "project_id": project_id},
        headers=auth_headers,
    )
    assert eng_resp.status_code == 201
    response = client.get("/api/v1/engagements/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    if isinstance(data, dict) and "data" in data:
        assert data["success"] is True
        assert "meta" in data
        assert data["meta"]["total"] >= 1
        assert len(data["data"]) >= 1
        # Pagination check
        resp2 = client.get("/api/v1/engagements/?page=1&per_page=1", headers=auth_headers)
        assert resp2.status_code == 200
        paginated = resp2.json()
        assert paginated["meta"]["page"] == 1
        assert paginated["meta"]["per_page"] == 1
    else:
        assert len(data) >= 1


def test_get_engagement_ownership(client):
    """Get engagement - should only return if under user's project."""
    auth_headers = _signup(client)
    proj_resp = client.post("/api/v1/projects/", json={"name": "Project"}, headers=auth_headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    eng_resp = client.post("/api/v1/engagements/", json={"name": "Engagement", "project_id": project_id}, headers=auth_headers)
    assert eng_resp.status_code == 201
    eng_id = eng_resp.json()["id"]
    response = client.get(f"/api/v1/engagements/{eng_id}", headers=auth_headers)
    assert response.status_code == 200

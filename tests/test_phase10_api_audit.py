"""Phase 10 - Public API + API Keys + Custom Webhooks + Audit Logging

Tests for:
- ApiKey model & service (generation, hash, scopes, expiration, revocation, rotation)
- CustomWebhook model & service (CRUD, HMAC signing, dispatch, event filtering)
- AuditLog model & service (comprehensive trail for scans/exports)
- API endpoints: /api-keys, /workspaces/{id}/webhooks (custom), /audit-logs
- Public API via X-API-Key: projects, findings, scans, exports

Covers Prompt Set 3: #9 Public API + API Keys + Webhooks + #10 Audit Logging
"""
import uuid
import json
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from app.db.models import (
    User, Project, Engagement, Workspace, WorkspaceRole,
    ApiKey, CustomWebhook, AuditLog,
    Finding, FindingSeverity, FindingStatus,
)
from app.core.security import get_password_hash, create_access_token
from app.services.api_key_service import ApiKeyService, ALLOWED_SCOPES
from app.services.custom_webhook_service import CustomWebhookService, ALLOWED_EVENTS
from app.services.audit_service import AuditService
from app.services.workspace_service import WorkspaceService


# ---- helpers ----

async def _create_user(session, email, password="TestPass123!"):
    user = User(id=str(uuid.uuid4()), email=email, hashed_password=get_password_hash(password), is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user

async def _create_workspace(session, owner, name="Test WS", slug=None):
    slug = slug or f"ws-{str(uuid.uuid4())[:8]}"
    ws = await WorkspaceService.create_workspace(session, owner, name, slug, "desc")
    return ws

async def _create_project(session, owner_id, workspace_id=None, name="Proj"):
    proj = Project(id=str(uuid.uuid4()), name=name, description="test", owner_id=owner_id, workspace_id=workspace_id)
    session.add(proj)
    await session.commit()
    await session.refresh(proj)
    return proj

async def _create_engagement(session, project_id, name="Eng"):
    eng = Engagement(id=str(uuid.uuid4()), name=name, project_id=project_id)
    session.add(eng)
    await session.commit()
    await session.refresh(eng)
    return eng

def _token(user):
    return create_access_token(subject=user.email)


# ==================== ApiKey Service Tests ====================

class TestApiKeyService:

    @pytest.mark.asyncio
    async def test_create_api_key_basic(self, test_session):
        user = await _create_user(test_session, "ak1@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "my-key", ["read"])
        assert key.name == "my-key"
        assert plain.startswith("rp_")
        assert key.prefix == plain[:12]
        assert key.key_hash == hashlib.sha256(plain.encode()).hexdigest()
        assert key.scopes == ["read"]
        assert key.is_active is True

    @pytest.mark.asyncio
    async def test_create_api_key_workspace_bound(self, test_session):
        user = await _create_user(test_session, "ak2@test.com")
        ws = await _create_workspace(test_session, user)
        key, plain = await ApiKeyService.create_api_key(test_session, user, "ws-key", ["read", "write"], workspace_id=ws.id)
        assert key.workspace_id == ws.id

    @pytest.mark.asyncio
    async def test_create_api_key_invalid_scope(self, test_session):
        user = await _create_user(test_session, "ak3@test.com")
        with pytest.raises(ValueError, match="Invalid scopes"):
            await ApiKeyService.create_api_key(test_session, user, "bad", ["not_a_scope"])

    @pytest.mark.asyncio
    async def test_create_api_key_empty_name(self, test_session):
        user = await _create_user(test_session, "ak4@test.com")
        with pytest.raises(ValueError, match="name is required"):
            await ApiKeyService.create_api_key(test_session, user, "   ", ["read"])

    @pytest.mark.asyncio
    async def test_create_api_key_with_expiry(self, test_session):
        user = await _create_user(test_session, "ak5@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "exp-key", ["read"], expires_in_days=7)
        assert key.expires_at is not None
        exp = key.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        assert exp > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, test_session):
        user = await _create_user(test_session, "ak6@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "validate", ["read"])
        fetched = await ApiKeyService.validate_api_key(test_session, plain)
        assert fetched is not None
        assert fetched.id == key.id
        assert fetched.last_used_at is not None

    @pytest.mark.asyncio
    async def test_validate_api_key_invalid_prefix(self, test_session):
        res = await ApiKeyService.validate_api_key(test_session, "invalid_key")
        assert res is None

    @pytest.mark.asyncio
    async def test_validate_api_key_wrong_hash(self, test_session):
        user = await _create_user(test_session, "ak7@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["read"])
        # Tamper
        tampered = plain[:-1] + ("A" if plain[-1] != "A" else "B")
        res = await ApiKeyService.validate_api_key(test_session, tampered)
        assert res is None

    @pytest.mark.asyncio
    async def test_validate_inactive_key(self, test_session):
        user = await _create_user(test_session, "ak8@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["read"])
        await ApiKeyService.revoke_api_key(test_session, key.id, user.id)
        res = await ApiKeyService.validate_api_key(test_session, plain)
        assert res is None

    @pytest.mark.asyncio
    async def test_validate_expired_key(self, test_session):
        user = await _create_user(test_session, "ak9@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["read"], expires_in_days=1)
        # Manually expire
        key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        await test_session.commit()
        res = await ApiKeyService.validate_api_key(test_session, plain)
        assert res is None

    @pytest.mark.asyncio
    async def test_has_scope_exact(self, test_session):
        user = await _create_user(test_session, "ak10@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["scan:create"])
        assert ApiKeyService.has_scope(key, "scan:create") is True
        assert ApiKeyService.has_scope(key, "read") is False

    @pytest.mark.asyncio
    async def test_has_scope_admin_grants_all(self, test_session):
        user = await _create_user(test_session, "ak11@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["admin"])
        for scope in ["read", "scan:create", "finding:export", "webhook:manage"]:
            assert ApiKeyService.has_scope(key, scope) is True

    @pytest.mark.asyncio
    async def test_has_scope_write_grants_read(self, test_session):
        user = await _create_user(test_session, "ak12@test.com")
        key, plain = await ApiKeyService.create_api_key(test_session, user, "k", ["write"])
        assert ApiKeyService.has_scope(key, "read") is True
        assert ApiKeyService.has_scope(key, "scan:create") is True

    @pytest.mark.asyncio
    async def test_revoke_and_list(self, test_session):
        user = await _create_user(test_session, "ak13@test.com")
        k1, _ = await ApiKeyService.create_api_key(test_session, user, "k1", ["read"])
        k2, _ = await ApiKeyService.create_api_key(test_session, user, "k2", ["read"])
        all_keys = await ApiKeyService.list_api_keys(test_session, user.id)
        assert len(all_keys) == 2
        await ApiKeyService.revoke_api_key(test_session, k1.id, user.id)
        fetched = await ApiKeyService.get_api_key(test_session, k1.id, user.id)
        assert fetched.is_active is False

    @pytest.mark.asyncio
    async def test_rotate_key(self, test_session):
        user = await _create_user(test_session, "ak14@test.com")
        key, old_plain = await ApiKeyService.create_api_key(test_session, user, "k", ["read"])
        old_hash = key.key_hash
        rotated, new_plain = await ApiKeyService.rotate_api_key(test_session, key.id, user.id)
        assert rotated is not None
        assert new_plain != old_plain
        assert rotated.key_hash != old_hash
        assert new_plain.startswith("rp_")
        # Old plain should no longer validate, new should
        assert await ApiKeyService.validate_api_key(test_session, old_plain) is None
        assert await ApiKeyService.validate_api_key(test_session, new_plain) is not None

    @pytest.mark.asyncio
    async def test_delete_key(self, test_session):
        user = await _create_user(test_session, "ak15@test.com")
        key, _ = await ApiKeyService.create_api_key(test_session, user, "k", ["read"])
        ok = await ApiKeyService.delete_api_key(test_session, key.id, user.id)
        assert ok is True
        assert await ApiKeyService.get_api_key(test_session, key.id, user.id) is None


# ==================== Custom Webhook Service Tests ====================

class TestCustomWebhookService:

    @pytest.mark.asyncio
    async def test_create_webhook_basic(self, test_session):
        user = await _create_user(test_session, "wh1@test.com")
        ws = await _create_workspace(test_session, user)
        wh = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "my-hook", "https://example.com/hook", ["scan.completed"])
        assert wh.name == "my-hook"
        assert wh.url == "https://example.com/hook"
        assert wh.events == ["scan.completed"]
        assert wh.secret is not None
        assert wh.is_active is True

    @pytest.mark.asyncio
    async def test_create_webhook_invalid_url(self, test_session):
        user = await _create_user(test_session, "wh2@test.com")
        ws = await _create_workspace(test_session, user)
        with pytest.raises(ValueError, match="must start with http"):
            await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "bad", "ftp://bad", ["scan.completed"])

    @pytest.mark.asyncio
    async def test_create_webhook_invalid_event(self, test_session):
        user = await _create_user(test_session, "wh3@test.com")
        ws = await _create_workspace(test_session, user)
        with pytest.raises(ValueError, match="Invalid events"):
            await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "bad", "https://example.com", ["not.an.event"])

    @pytest.mark.asyncio
    async def test_create_webhook_wildcard(self, test_session):
        user = await _create_user(test_session, "wh4@test.com")
        ws = await _create_workspace(test_session, user)
        wh = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "wild", "https://example.com", ["*"])
        assert "*" in wh.events

    def test_hmac_sign_verify(self):
        payload = json.dumps({"event": "scan.completed"})
        secret = "s3cr3t"
        sig = CustomWebhookService.sign_payload(payload, secret)
        assert CustomWebhookService.verify_signature(payload, secret, sig) is True
        assert CustomWebhookService.verify_signature(payload, secret, "bad") is False
        # Tampered payload fails
        assert CustomWebhookService.verify_signature(payload + " ", secret, sig) is False

    @pytest.mark.asyncio
    async def test_list_and_get(self, test_session):
        user = await _create_user(test_session, "wh5@test.com")
        ws = await _create_workspace(test_session, user)
        wh1 = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "h1", "https://example.com/1", ["scan.completed"])
        wh2 = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "h2", "https://example.com/2", ["finding.created"])
        listed = await CustomWebhookService.list_webhooks(test_session, ws.id)
        assert len(listed) == 2
        fetched = await CustomWebhookService.get_webhook(test_session, wh1.id, ws.id)
        assert fetched.id == wh1.id

    @pytest.mark.asyncio
    async def test_update_webhook(self, test_session):
        user = await _create_user(test_session, "wh6@test.com")
        ws = await _create_workspace(test_session, user)
        wh = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "orig", "https://example.com", ["scan.completed"])
        updated = await CustomWebhookService.update_webhook(test_session, wh.id, ws.id, {"name": "updated", "is_active": False})
        assert updated.name == "updated"
        assert updated.is_active is False

    @pytest.mark.asyncio
    async def test_delete_webhook(self, test_session):
        user = await _create_user(test_session, "wh7@test.com")
        ws = await _create_workspace(test_session, user)
        wh = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "del", "https://example.com", ["scan.completed"])
        ok = await CustomWebhookService.delete_webhook(test_session, wh.id, ws.id)
        assert ok is True
        assert await CustomWebhookService.get_webhook(test_session, wh.id, ws.id) is None

    @pytest.mark.asyncio
    async def test_dispatch_filters_by_event_and_active(self, test_session):
        user = await _create_user(test_session, "wh8@test.com")
        ws = await _create_workspace(test_session, user)
        # Subscribed to scan.completed only
        wh_scan = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "scan-hook", "https://example.com/scan", ["scan.completed"])
        wh_find = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "find-hook", "https://example.com/find", ["finding.created"])
        # Inactive hook should not be dispatched
        wh_inactive = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "inactive", "https://example.com/inactive", ["scan.completed"])
        await CustomWebhookService.update_webhook(test_session, wh_inactive.id, ws.id, {"is_active": False})

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch("app.services.custom_webhook_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            results = await CustomWebhookService.dispatch(test_session, ws.id, "scan.completed", {"scan_id": "123"})
            # Only wh_scan should have been called
            assert len(results) == 1
            assert results[0]["webhook_id"] == wh_scan.id
            assert results[0]["success"] is True
            # Verify HMAC header was sent
            call_kwargs = mock_client.post.call_args
            assert call_kwargs is not None
            headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
            # headers check - ensure signature present
            assert "X-RedPulse-Signature" in headers

    @pytest.mark.asyncio
    async def test_dispatch_wildcard_receives_all(self, test_session):
        user = await _create_user(test_session, "wh9@test.com")
        ws = await _create_workspace(test_session, user)
        wh_wild = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "wild", "https://example.com/wild", ["*"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch("app.services.custom_webhook_service.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            results = await CustomWebhookService.dispatch(test_session, ws.id, "finding.created", {"finding_id": "f1"})
            assert len(results) == 1
            assert results[0]["webhook_id"] == wh_wild.id

    @pytest.mark.asyncio
    async def test_dispatch_retry_on_failure(self, test_session):
        user = await _create_user(test_session, "wh10@test.com")
        ws = await _create_workspace(test_session, user)
        wh = await CustomWebhookService.create_webhook(test_session, ws.id, user.id, "retry", "https://example.com/retry", ["scan.completed"])

        # First two attempts fail, third succeeds? Our mock will track calls
        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.text = "error"
        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.text = "ok"

        with patch("app.services.custom_webhook_service.httpx.AsyncClient") as mock_client_cls, \
             patch("asyncio.sleep", new=AsyncMock()):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            # Simulate failure then success
            mock_client.post = AsyncMock(side_effect=[fail_resp, success_resp])
            mock_client_cls.return_value = mock_client

            results = await CustomWebhookService.dispatch(test_session, ws.id, "scan.completed", {"scan_id": "1"}, max_retries=2)
            assert results[0]["success"] is True
            assert mock_client.post.call_count == 2
            assert results[0]["attempts"] == 2


# ==================== Audit Service Tests ====================

class TestAuditService:

    @pytest.mark.asyncio
    async def test_log_and_list(self, test_session):
        user = await _create_user(test_session, "audit1@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "AuditProj")

        entry = await AuditService.log(
            test_session, action="scan.create", resource_type="scan", resource_id="scan-1",
            user_id=user.id, workspace_id=ws.id, project_id=proj.id,
            details={"target": "example.com"}, status="success"
        )
        assert entry.action == "scan.create"
        assert entry.resource_type == "scan"

        logs, total = await AuditService.list_logs(test_session, workspace_id=ws.id)
        assert total >= 1
        assert any(l.id == entry.id for l in logs)

    @pytest.mark.asyncio
    async def test_log_scan_convenience(self, test_session):
        user = await _create_user(test_session, "audit2@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "P2")
        entry = await AuditService.log_scan(
            test_session, scan_id="scan-xyz", project_id=proj.id, workspace_id=ws.id,
            user_id=user.id, target="test.com", tool="nmap"
        )
        assert entry.action == "scan.create"
        assert entry.details["target"] == "test.com"

    @pytest.mark.asyncio
    async def test_log_export_convenience(self, test_session):
        user = await _create_user(test_session, "audit3@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "P3")
        entry = await AuditService.log_export(
            test_session, project_id=proj.id, workspace_id=ws.id, user_id=user.id,
            export_format="json", count=5
        )
        assert "export.json" in entry.action
        assert entry.details["count"] == 5

    @pytest.mark.asyncio
    async def test_audit_filters(self, test_session):
        user = await _create_user(test_session, "audit4@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "P4")
        await AuditService.log(test_session, action="scan.create", resource_type="scan", resource_id="s1", user_id=user.id, workspace_id=ws.id, project_id=proj.id)
        await AuditService.log(test_session, action="export.json", resource_type="export", resource_id="e1", user_id=user.id, workspace_id=ws.id, project_id=proj.id)
        await AuditService.log(test_session, action="scan.create", resource_type="scan", resource_id="s2", user_id=user.id, workspace_id=ws.id, project_id=proj.id, status="failure")

        logs, total = await AuditService.list_logs(test_session, workspace_id=ws.id, action="scan.create")
        assert total == 2
        logs2, _ = await AuditService.list_logs(test_session, workspace_id=ws.id, resource_type="export")
        assert len(logs2) == 1
        logs3, _ = await AuditService.list_logs(test_session, workspace_id=ws.id, status="failure")
        assert len(logs3) == 1

    @pytest.mark.asyncio
    async def test_audit_pagination(self, test_session):
        user = await _create_user(test_session, "audit5@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "P5")
        for i in range(5):
            await AuditService.log(test_session, action="scan.create", resource_type="scan", resource_id=f"s-{i}", user_id=user.id, workspace_id=ws.id, project_id=proj.id)
        logs, total = await AuditService.list_logs(test_session, workspace_id=ws.id, limit=2, offset=0)
        assert len(logs) == 2
        assert total >= 5
        logs2, _ = await AuditService.list_logs(test_session, workspace_id=ws.id, limit=2, offset=2)
        assert len(logs2) == 2
        assert logs[0].id != logs2[0].id

    @pytest.mark.asyncio
    async def test_sanitize_secrets(self, test_session):
        user = await _create_user(test_session, "audit6@test.com")
        ws = await _create_workspace(test_session, user)
        entry = await AuditService.log(
            test_session, action="api_key.create", resource_type="api_key",
            user_id=user.id, workspace_id=ws.id,
            details={"api_key": "rp_secret123", "name": "test", "password": "should_redact"}
        )
        assert entry.details["api_key"] == "***REDACTED***"
        assert entry.details["password"] == "***REDACTED***"
        assert entry.details["name"] == "test"

    @pytest.mark.asyncio
    async def test_recent_activity(self, test_session):
        user = await _create_user(test_session, "audit7@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "P7")
        await AuditService.log(test_session, action="scan.create", resource_type="scan", resource_id="s1", user_id=user.id, workspace_id=ws.id, project_id=proj.id)
        recent = await AuditService.get_recent_activity(test_session, ws.id, limit=5)
        assert len(recent) >= 1


# ==================== API Integration Tests (JWT) ====================

class TestApiKeysAPI:

    @pytest.mark.asyncio
    async def test_api_key_crud_via_jwt(self, client, test_session):
        user = await _create_user(test_session, "jwtak@test.com")
        token = _token(user)

        # Create
        resp = client.post("/api/v1/api-keys", json={"name": "my-key", "scopes": ["read", "scan:create"]}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201, resp.text
        data = resp.json()["data"]
        assert data["name"] == "my-key"
        assert "api_key" in data
        plain = data["api_key"]
        assert plain.startswith("rp_")
        key_id = data["id"]

        # List
        resp2 = client.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 200
        assert len(resp2.json()["data"]) == 1

        # Get single
        resp3 = client.get(f"/api/v1/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp3.status_code == 200
        assert resp3.json()["data"]["prefix"] == data["prefix"]

        # Revoke
        resp4 = client.post(f"/api/v1/api-keys/{key_id}/revoke", headers={"Authorization": f"Bearer {token}"})
        assert resp4.status_code == 200
        assert resp4.json()["data"]["is_active"] is False

        # Rotate (should reactivate)
        resp5 = client.post(f"/api/v1/api-keys/{key_id}/rotate", headers={"Authorization": f"Bearer {token}"})
        assert resp5.status_code == 200
        assert "api_key" in resp5.json()["data"]
        assert resp5.json()["data"]["is_active"] is True

        # Delete
        resp6 = client.delete(f"/api/v1/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp6.status_code == 200
        # Verify gone
        resp7 = client.get(f"/api/v1/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp7.status_code == 404

    @pytest.mark.asyncio
    async def test_api_key_invalid_scope_rejected(self, client, test_session):
        user = await _create_user(test_session, "jwtak2@test.com")
        token = _token(user)
        resp = client.post("/api/v1/api-keys", json={"name": "bad", "scopes": ["not_allowed"]}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_api_key_workspace_binding_check(self, client, test_session):
        user = await _create_user(test_session, "jwtak3@test.com")
        ws = await _create_workspace(test_session, user)
        token = _token(user)
        # Valid workspace binding
        resp = client.post("/api/v1/api-keys", json={"name": "ws-key", "workspace_id": ws.id}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201
        # Invalid workspace
        resp2 = client.post("/api/v1/api-keys", json={"name": "bad-ws", "workspace_id": "nonexistent"}, headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 404

    @pytest.mark.asyncio
    async def test_api_key_scopes_endpoint(self, client, test_session):
        user = await _create_user(test_session, "jwtak4@test.com")
        token = _token(user)
        resp = client.get("/api/v1/api-keys/meta/scopes", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "scopes" in resp.json()["data"]
        assert "read" in resp.json()["data"]["scopes"]


class TestCustomWebhooksAPI:

    @pytest.mark.asyncio
    async def test_custom_webhook_crud(self, client, test_session):
        user = await _create_user(test_session, "jwh1@test.com")
        ws = await _create_workspace(test_session, user)
        token = _token(user)

        # Create
        resp = client.post(f"/api/v1/workspaces/{ws.id}/webhooks", json={"name": "hook1", "url": "https://example.com/hook", "events": ["scan.completed"]}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201, resp.text
        data = resp.json()["data"]
        assert data["name"] == "hook1"
        assert "secret" in data
        hook_id = data["id"]

        # List
        resp2 = client.get(f"/api/v1/workspaces/{ws.id}/webhooks", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 200
        assert len(resp2.json()["data"]) == 1

        # Get
        resp3 = client.get(f"/api/v1/workspaces/{ws.id}/webhooks/{hook_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp3.status_code == 200
        assert resp3.json()["data"]["id"] == hook_id

        # Update
        resp4 = client.patch(f"/api/v1/workspaces/{ws.id}/webhooks/{hook_id}", json={"name": "updated"}, headers={"Authorization": f"Bearer {token}"})
        assert resp4.status_code == 200
        assert resp4.json()["data"]["name"] == "updated"

        # Delete
        resp5 = client.delete(f"/api/v1/workspaces/{ws.id}/webhooks/{hook_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp5.status_code == 200
        # Verify deleted
        resp6 = client.get(f"/api/v1/workspaces/{ws.id}/webhooks/{hook_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp6.status_code == 404

    @pytest.mark.asyncio
    async def test_custom_webhook_invalid_url_rejected(self, client, test_session):
        user = await _create_user(test_session, "jwh2@test.com")
        ws = await _create_workspace(test_session, user)
        token = _token(user)
        resp = client.post(f"/api/v1/workspaces/{ws.id}/webhooks", json={"name": "bad", "url": "ftp://bad", "events": ["scan.completed"]}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_custom_webhook_test_delivery_mocked(self, client, test_session):
        user = await _create_user(test_session, "jwh3@test.com")
        ws = await _create_workspace(test_session, user)
        token = _token(user)
        resp = client.post(f"/api/v1/workspaces/{ws.id}/webhooks", json={"name": "testhook", "url": "https://example.com/hook", "events": ["scan.completed"]}, headers={"Authorization": f"Bearer {token}"})
        hook_id = resp.json()["data"]["id"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"

        with patch("app.services.custom_webhook_service.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            resp2 = client.post(f"/api/v1/workspaces/{ws.id}/webhooks/{hook_id}/test", headers={"Authorization": f"Bearer {token}"})
            assert resp2.status_code == 200
            assert resp2.json()["data"]["success"] is True

    @pytest.mark.asyncio
    async def test_custom_webhook_viewer_cannot_create(self, client, test_session):
        owner = await _create_user(test_session, "jwh_owner@test.com")
        viewer = await _create_user(test_session, "jwh_viewer@test.com")
        ws = await _create_workspace(test_session, owner)
        # Invite viewer as VIEWER
        from app.db.models import WorkspaceRole
        await WorkspaceService.invite_member(test_session, ws.id, owner.id, viewer.email, WorkspaceRole.VIEWER)
        viewer_token = _token(viewer)
        resp = client.post(f"/api/v1/workspaces/{ws.id}/webhooks", json={"name": "hook", "url": "https://example.com", "events": ["scan.completed"]}, headers={"Authorization": f"Bearer {viewer_token}"})
        assert resp.status_code == 404  # 404 due to permission check mapping


class TestAuditLogsAPI:

    @pytest.mark.asyncio
    async def test_audit_logs_query(self, client, test_session):
        user = await _create_user(test_session, "auditapi1@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "AuditProj")
        token = _token(user)

        # Create some audit logs directly
        await AuditService.log(test_session, action="scan.create", resource_type="scan", resource_id="s1", user_id=user.id, workspace_id=ws.id, project_id=proj.id)
        await AuditService.log(test_session, action="export.json", resource_type="export", resource_id="e1", user_id=user.id, workspace_id=ws.id, project_id=proj.id)

        resp = client.get(f"/api/v1/workspaces/{ws.id}/audit-logs", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["meta"]["total"] >= 2
        assert len(data["data"]) >= 2

        # Filter by action
        resp2 = client.get(f"/api/v1/workspaces/{ws.id}/audit-logs?action=scan.create", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 200
        filtered = resp2.json()["data"]
        assert all(item["action"] == "scan.create" for item in filtered)

        # Recent activity
        resp3 = client.get(f"/api/v1/workspaces/{ws.id}/audit-logs/recent?limit=5", headers={"Authorization": f"Bearer {token}"})
        assert resp3.status_code == 200
        assert len(resp3.json()["data"]) >= 1

        # My activity (global)
        resp4 = client.get("/api/v1/audit-logs/my-activity", headers={"Authorization": f"Bearer {token}"})
        assert resp4.status_code == 200
        assert "data" in resp4.json()

    @pytest.mark.asyncio
    async def test_audit_logs_workspace_isolation(self, client, test_session):
        owner = await _create_user(test_session, "auditiso_owner@test.com")
        stranger = await _create_user(test_session, "auditiso_stranger@test.com")
        ws = await _create_workspace(test_session, owner)
        token_stranger = _token(stranger)
        resp = client.get(f"/api/v1/workspaces/{ws.id}/audit-logs", headers={"Authorization": f"Bearer {token_stranger}"})
        assert resp.status_code == 404


# ==================== Public API (X-API-Key) Tests ====================

class TestPublicAPI:

    @pytest.mark.asyncio
    async def test_public_api_projects_and_findings(self, client, test_session):
        user = await _create_user(test_session, "pub1@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "PublicProj")
        eng = await _create_engagement(test_session, proj.id, "PublicEng")
        # Create a finding for the project
        finding = Finding(
            id=str(uuid.uuid4()), engagement_id=eng.id, project_id=proj.id, asset_id=None,
            scan_id=None, user_id=user.id, title="Test XSS", template_id="xss-test",
            severity=FindingSeverity.HIGH, confidence=90, fingerprint="fp1",
            status=FindingStatus.NEW
        )
        test_session.add(finding)
        await test_session.commit()

        # Create API key with read scopes
        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "pub-key", ["read", "finding:read", "scan:create", "finding:export", "scan:read"], workspace_id=ws.id)

        # List projects via public API
        resp = client.get("/api/v1/public/projects", headers={"X-API-Key": plain})
        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        assert any(p["id"] == proj.id for p in data)

        # Get single project
        resp2 = client.get(f"/api/v1/public/projects/{proj.id}", headers={"X-API-Key": plain})
        assert resp2.status_code == 200
        assert resp2.json()["data"]["id"] == proj.id

        # List findings
        resp3 = client.get("/api/v1/public/findings", headers={"X-API-Key": plain}, params={"project_id": proj.id})
        assert resp3.status_code == 200
        assert len(resp3.json()["data"]) >= 1

    @pytest.mark.asyncio
    async def test_public_api_scan_and_export_audit(self, client, test_session):
        user = await _create_user(test_session, "pub2@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "ScanProj")
        eng = await _create_engagement(test_session, proj.id, "EngScan")

        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "scan-key", ["read", "scan:create", "scan:read", "finding:export", "finding:read"], workspace_id=ws.id)

        # Mock webhook dispatch to avoid network
        with patch("app.services.custom_webhook_service.CustomWebhookService.dispatch", new=AsyncMock(return_value=[])):
            # Create scan via public API
            resp = client.post("/api/v1/public/scans", json={"project_id": proj.id, "target": "https://example.com", "profile": "quick"}, headers={"X-API-Key": plain})
            assert resp.status_code == 201, resp.text
            scan_id = resp.json()["data"]["id"]

            # Verify scan exists via public get
            resp2 = client.get(f"/api/v1/public/scans/{scan_id}", headers={"X-API-Key": plain})
            assert resp2.status_code == 200

            # Export via public API
            resp3 = client.post("/api/v1/public/exports", json={"project_id": proj.id, "format": "json"}, headers={"X-API-Key": plain})
            assert resp3.status_code == 200
            assert resp3.json()["data"]["format"] == "json"

        # Verify audit logs were created for both scan and export
        logs, total = await AuditService.list_logs(test_session, workspace_id=ws.id)
        actions = [l.action for l in logs]
        assert "scan.create" in actions
        assert any("export" in a for a in actions)

    @pytest.mark.asyncio
    async def test_public_api_scope_enforcement(self, client, test_session):
        user = await _create_user(test_session, "pub3@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "ScopeProj")
        await _create_engagement(test_session, proj.id)

        # Key with only read scope tries to create scan (needs scan:create)
        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "read-only", ["read"], workspace_id=ws.id)
        resp = client.post("/api/v1/public/scans", json={"project_id": proj.id, "target": "https://example.com"}, headers={"X-API-Key": plain})
        assert resp.status_code == 403

        # Key with only read tries to export (needs finding:export)
        resp2 = client.post("/api/v1/public/exports", json={"project_id": proj.id, "format": "json"}, headers={"X-API-Key": plain})
        assert resp2.status_code == 403

    @pytest.mark.asyncio
    async def test_public_api_invalid_key(self, client, test_session):
        resp = client.get("/api/v1/public/projects", headers={"X-API-Key": "rp_invalid1234567890123456789012"})
        assert resp.status_code == 401

        # No header at all
        resp2 = client.get("/api/v1/public/projects")
        assert resp2.status_code == 401

    @pytest.mark.asyncio
    async def test_public_api_workspace_binding_enforced(self, client, test_session):
        user = await _create_user(test_session, "pub4@test.com")
        ws1 = await _create_workspace(test_session, user)
        # Second workspace owned by same user but separate
        user2 = await _create_user(test_session, "pub5@test.com")
        ws2 = await _create_workspace(test_session, user2, name="WS2", slug=f"ws2-{str(uuid.uuid4())[:6]}")
        # Projects in different workspaces
        proj1 = await _create_project(test_session, user.id, ws1.id, "P1")
        proj2 = await _create_project(test_session, user2.id, ws2.id, "P2")

        # Key bound to ws1 should not see proj2 (owned by user2 anyway) but even for shared user test isolation
        # Use same user but different ws1 binding: create proj in ws2 owned by same first user (use manual insert)
        proj_in_ws2 = Project(id=str(uuid.uuid4()), name="Other", owner_id=user.id, workspace_id=ws2.id)
        test_session.add(proj_in_ws2)
        await test_session.commit()

        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "ws-bound", ["read", "finding:read"], workspace_id=ws1.id)
        resp = client.get("/api/v1/public/projects", headers={"X-API-Key": plain})
        assert resp.status_code == 200
        ids = [p["id"] for p in resp.json()["data"]]
        assert proj1.id in ids
        assert proj_in_ws2.id not in ids  # Should be filtered by workspace binding

    @pytest.mark.asyncio
    async def test_public_api_bearer_fallback(self, client, test_session):
        user = await _create_user(test_session, "pub6@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "BearerProj")
        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "bearer-key", ["read", "finding:read"], workspace_id=ws.id)

        # Use Authorization: Bearer rp_... instead of X-API-Key
        resp = client.get("/api/v1/public/projects", headers={"Authorization": f"Bearer {plain}"})
        assert resp.status_code == 200
        assert any(p["id"] == proj.id for p in resp.json()["data"])

    @pytest.mark.asyncio
    async def test_audit_api_key_lifecycle_logged(self, client, test_session):
        user = await _create_user(test_session, "auditkey@test.com")
        token = _token(user)

        # Create key via JWT
        resp = client.post("/api/v1/api-keys", json={"name": "audited", "scopes": ["read"]}, headers={"Authorization": f"Bearer {token}"})
        key_id = resp.json()["data"]["id"]

        # Check audit log for creation
        logs, _ = await AuditService.list_logs(test_session, workspace_id=None)
        # Filter for this user's key creation
        key_logs = [l for l in logs if l.action == "api_key.create" and l.user_id == user.id]
        assert len(key_logs) >= 1
        assert key_logs[0].details["prefix"] is not None

        # Revoke and check logged
        client.post(f"/api/v1/api-keys/{key_id}/revoke", headers={"Authorization": f"Bearer {token}"})
        logs2, _ = await AuditService.list_logs(test_session, workspace_id=None)
        revoke_logs = [l for l in logs2 if l.action == "api_key.revoke" and l.resource_id == key_id]
        assert len(revoke_logs) >= 1

    @pytest.mark.asyncio
    async def test_audit_sanitize_on_export(self, client, test_session):
        user = await _create_user(test_session, "pubaudit2@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id, "ScrubProj")
        eng = await _create_engagement(test_session, proj.id)
        api_key, plain = await ApiKeyService.create_api_key(test_session, user, "key", ["read", "scan:create", "scan:read", "finding:export", "finding:read"], workspace_id=ws.id)

        with patch("app.services.custom_webhook_service.CustomWebhookService.dispatch", new=AsyncMock(return_value=[])):
            client.post("/api/v1/public/scans", json={"project_id": proj.id, "target": "https://example.com"}, headers={"X-API-Key": plain})

        logs, _ = await AuditService.list_logs(test_session, workspace_id=ws.id, action="scan.create")
        assert len(logs) >= 1
        # Ensure details don't contain raw api key
        for log in logs:
            if log.details and "api_key" in str(log.details).lower():
                assert "***REDACTED***" in str(log.details) or "api_key" not in log.details

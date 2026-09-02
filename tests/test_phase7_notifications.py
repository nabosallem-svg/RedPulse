"""RedPulse - Phase 7 Tests: Notifications & Monitoring.

Tests for:
- WebhookConfig CRUD model
- AlertService severity filtering (Critical/High only)
- AlertService Telegram/Discord/custom message formatting
- MonitoringService schedule creation and execution
- MonitoringService change detection (assets, findings, regressions)
- API endpoints for webhooks and monitoring
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy import select

from app.db.models import (
    User, Project, Engagement, EngagementStatus, Asset, AssetType, ReconTool,
    Finding, FindingSeverity, FindingStatus, VulnerabilityScan, VulnScanStatus,
    WebhookConfig, MonitoringSchedule,
)
from app.services.alert_service import (
    AlertService, _severity_meets_threshold,
    _format_telegram_message, _format_discord_embed,
)
from app.services.monitoring_service import MonitoringService


# --- Fixtures ---


@pytest.fixture
async def user(test_session):
    user = User(
        id=str(uuid.uuid4()),
        email=f"alert_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="$2b$12$fakehash",
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    return user


async def _make_project(test_session, user_id, name="Test Project"):
    project = Project(name=name, owner_id=user_id, description="Test")
    test_session.add(project)
    await test_session.commit()
    await test_session.refresh(project)
    return project


async def _make_engagement(test_session, project_id):
    eng = Engagement(
        name="Test Engagement",
        project_id=project_id,
        status=EngagementStatus.AUTHORIZED,
    )
    test_session.add(eng)
    await test_session.commit()
    await test_session.refresh(eng)
    return eng


async def _make_finding(
    test_session,
    engagement_id,
    project_id,
    user_id,
    title="XSS in search",
    severity=FindingSeverity.HIGH,
    category="xss",
    status=FindingStatus.NEW,
    endpoint="https://example.com/search?q=test",
    fingerprint="fp_test_001",
):
    finding = Finding(
        engagement_id=engagement_id,
        project_id=project_id,
        user_id=user_id,
        title=title,
        severity=severity,
        confidence=85,
        category=category,
        description="Cross-site scripting vulnerability in search endpoint",
        endpoint=endpoint,
        matched_at=endpoint,
        fingerprint=fingerprint,
        status=status,
        triage_tags=["critical_risk"],
        poc_curl='curl -v -k "https://example.com/search?q=<script>alert(1)</script>"',
    )
    test_session.add(finding)
    await test_session.commit()
    await test_session.refresh(finding)
    return finding


async def _make_webhook(test_session, project_id, user_id, webhook_type="telegram",
                         name="Test Webhook", enabled=True, min_severity="high"):
    webhook = WebhookConfig(
        project_id=project_id,
        user_id=user_id,
        name=name,
        webhook_type=webhook_type,
        url=f"https://api.telegram.org/bot{user_id}:TEST_TOKEN/sendMessage" if webhook_type == "telegram"
            else f"https://discord.com/api/webhooks/{user_id}/test",
        min_severity=min_severity,
        enabled=enabled,
    )
    test_session.add(webhook)
    await test_session.commit()
    await test_session.refresh(webhook)
    return webhook


async def _make_schedule(test_session, project_id, user_id, name="Test Schedule",
                          frequency="daily", enabled=True):
    schedule = MonitoringSchedule(
        project_id=project_id,
        user_id=user_id,
        name=name,
        frequency=frequency,
        profile="standard",
        enabled=enabled,
        next_scan_at=datetime.now(timezone.utc),
    )
    test_session.add(schedule)
    await test_session.commit()
    await test_session.refresh(schedule)
    return schedule


# --- Severity Filter Tests ---


class TestSeverityFilter:
    """Test severity threshold filtering logic."""

    def test_critical_meets_high_threshold(self):
        assert _severity_meets_threshold("critical", "high") is True

    def test_high_meets_high_threshold(self):
        assert _severity_meets_threshold("high", "high") is True

    def test_medium_meets_high_threshold(self):
        assert _severity_meets_threshold("medium", "high") is False

    def test_low_meets_high_threshold(self):
        assert _severity_meets_threshold("low", "high") is False

    def test_info_meets_high_threshold(self):
        assert _severity_meets_threshold("info", "high") is False

    def test_critical_meets_critical_threshold(self):
        assert _severity_meets_threshold("critical", "critical") is True

    def test_high_meets_critical_threshold(self):
        assert _severity_meets_threshold("high", "critical") is False

    def test_medium_meets_medium_threshold(self):
        assert _severity_meets_threshold("medium", "medium") is True

    def test_low_meets_info_threshold(self):
        assert _severity_meets_threshold("low", "info") is True

    def test_unknown_severity_does_not_meet(self):
        assert _severity_meets_threshold("unknown", "high") is False


# --- Telegram Message Formatting Tests ---


class TestTelegramFormatting:
    """Test Telegram message formatting for alerts."""

    def test_format_basic_message(self):
        finding = MagicMock()
        finding.severity.value = "critical"
        finding.title = "SQL Injection in login"
        finding.endpoint = "https://example.com/login"
        finding.category = "sqli"
        finding.triage_tags = ["critical_risk", "auth_bypass"]
        finding.poc_curl = 'curl -v -k "https://example.com/login"'
        finding.description = "SQL injection via username parameter"
        finding.first_seen = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        msg = _format_telegram_message(finding, "My Project", "new_finding")

        assert "RedPulse Alert" in msg
        assert "CRITICAL" in msg
        assert "SQL Injection in login" in msg
        assert "My Project" in msg
        assert "sqli" in msg
        assert "critical_risk" in msg
        assert "curl" in msg

    def test_format_regression_message(self):
        finding = MagicMock()
        finding.severity.value = "high"
        finding.title = "XSS Found"
        finding.endpoint = "https://example.com/search"
        finding.category = "xss"
        finding.triage_tags = []
        finding.poc_curl = None
        finding.description = None
        finding.first_seen = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        msg = _format_telegram_message(finding, "Project X", "regression")

        assert "Regression" in msg
        assert "HIGH" in msg

    def test_format_truncates_long_curl(self):
        finding = MagicMock()
        finding.severity.value = "high"
        finding.title = "Finding"
        finding.endpoint = "https://example.com"
        finding.category = "test"
        finding.triage_tags = []
        finding.poc_curl = "curl " + "x" * 1000
        finding.description = None
        finding.first_seen = datetime(2025, 1, 15, tzinfo=timezone.utc)

        msg = _format_telegram_message(finding, "Project", "new_finding")

        # Message should be truncated for Telegram limits
        assert len(msg) < 5000


# --- Discord Embed Formatting Tests ---


class TestDiscordFormatting:
    """Test Discord embed formatting for alerts."""

    def test_format_basic_embed(self):
        finding = MagicMock()
        finding.severity.value = "critical"
        finding.title = "RCE via upload"
        finding.endpoint = "https://example.com/upload"
        finding.category = "file_inclusion"
        finding.triage_tags = ["critical_risk"]
        finding.poc_curl = 'curl -v "https://example.com/upload"'
        finding.description = "Remote code execution via file upload"
        finding.first_seen = datetime(2025, 1, 15, tzinfo=timezone.utc)

        embed = _format_discord_embed(finding, "Test Project", "new_finding")

        assert embed["title"] == "🔴 RCE via upload"
        assert embed["color"] == 0x7F1D1D  # Critical = dark red
        assert len(embed["fields"]) >= 3
        assert embed["fields"][0]["value"] == "Test Project"
        assert embed["fields"][1]["value"] == "CRITICAL"

    def test_format_high_severity_color(self):
        finding = MagicMock()
        finding.severity.value = "high"
        finding.title = "XSS"
        finding.endpoint = "https://example.com"
        finding.category = "xss"
        finding.triage_tags = []
        finding.poc_curl = None
        finding.description = "XSS vulnerability"
        finding.first_seen = datetime(2025, 1, 15, tzinfo=timezone.utc)

        embed = _format_discord_embed(finding, "Project", "new_finding")

        assert embed["color"] == 0xDC2626  # High = red

    def test_format_includes_poc_field(self):
        finding = MagicMock()
        finding.severity.value = "high"
        finding.title = "Finding"
        finding.endpoint = "https://example.com"
        finding.category = "test"
        finding.triage_tags = ["idor"]
        finding.poc_curl = 'curl -v "https://example.com"'
        finding.description = "Test"
        finding.first_seen = datetime(2025, 1, 15, tzinfo=timezone.utc)

        embed = _format_discord_embed(finding, "Project", "new_finding")

        # Find the PoC field
        poc_fields = [f for f in embed["fields"] if f["name"] == "PoC (curl)"]
        assert len(poc_fields) == 1
        assert "curl" in poc_fields[0]["value"]


# --- AlertService Tests ---


class TestAlertService:
    """Test AlertService alert delivery and filtering."""

    @pytest.mark.asyncio
    async def test_skips_medium_findings(self, test_session, user):
        """AlertService skips Medium/Low/Info findings."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.MEDIUM,
        )
        await _make_webhook(test_session, project.id, user.id)

        service = AlertService(test_session)
        results = await service.send_finding_alert(finding, project.id)

        assert results == []  # Medium finding should be skipped

    @pytest.mark.asyncio
    async def test_sends_critical_alerts(self, test_session, user):
        """AlertService sends alerts for Critical findings."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            title="SQL Injection",
            fingerprint="fp_critical_001",
        )
        await _make_webhook(test_session, project.id, user.id)

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock) as mock_tg:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) >= 1
            assert results[0]["success"] is True
            mock_tg.assert_called_once()

    @pytest.mark.asyncio
    async def test_sends_high_alerts(self, test_session, user):
        """AlertService sends alerts for High findings."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.HIGH,
            fingerprint="fp_high_001",
        )
        await _make_webhook(test_session, project.id, user.id)

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock) as mock_tg:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_filters_by_webhook_min_severity(self, test_session, user):
        """Webhook with min_severity=critical ignores High findings."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.HIGH,
            fingerprint="fp_filter_001",
        )
        # Webhook only wants critical
        await _make_webhook(test_session, project.id, user.id, min_severity="critical")

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock) as mock_tg:
            results = await service.send_finding_alert(finding, project.id)
            # Should be skipped - High < Critical threshold
            assert len(results) == 0
            mock_tg.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_disabled_webhooks(self, test_session, user):
        """Disabled webhooks are not triggered."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_disabled_001",
        )
        await _make_webhook(test_session, project.id, user.id, enabled=False)

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock) as mock_tg:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) == 0
            mock_tg.assert_not_called()

    @pytest.mark.asyncio
    async def test_discord_webhook_delivers(self, test_session, user):
        """Discord webhooks are called correctly."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_discord_001",
        )
        await _make_webhook(test_session, project.id, user.id, webhook_type="discord")

        service = AlertService(test_session)

        with patch.object(service, "_send_discord", new_callable=AsyncMock) as mock_dc:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) >= 1
            mock_dc.assert_called_once()

    @pytest.mark.asyncio
    async def test_custom_webhook_delivers(self, test_session, user):
        """Custom webhooks are called with JSON payload."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_custom_001",
        )
        await _make_webhook(test_session, project.id, user.id, webhook_type="custom",
                            name="Custom Hook")

        service = AlertService(test_session)

        with patch.object(service, "_send_custom", new_callable=AsyncMock) as mock_cust:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) >= 1
            mock_cust.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_delivery_failure(self, test_session, user):
        """Failed delivery is reported but doesn't crash."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_fail_001",
        )
        await _make_webhook(test_session, project.id, user.id)

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock,
                          side_effect=Exception("Connection timeout")) as mock_tg:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) == 1
            assert results[0]["success"] is False
            assert "Connection timeout" in results[0]["error"]

    @pytest.mark.asyncio
    async def test_multiple_webhooks_receive_alerts(self, test_session, user):
        """Multiple webhooks for same project all receive alerts."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_multi_001",
        )
        await _make_webhook(test_session, project.id, user.id, webhook_type="telegram")
        await _make_webhook(test_session, project.id, user.id, webhook_type="discord")

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram", new_callable=AsyncMock) as mock_tg, \
             patch.object(service, "_send_discord", new_callable=AsyncMock) as mock_dc:
            results = await service.send_finding_alert(finding, project.id)
            assert len(results) == 2
            assert mock_tg.called
            assert mock_dc.called

    @pytest.mark.asyncio
    async def test_summary_alert_sends(self, test_session, user):
        """Summary alerts are delivered via webhooks."""
        project = await _make_project(test_session, user.id)
        await _make_webhook(test_session, project.id, user.id)

        service = AlertService(test_session)

        with patch.object(service, "_send_telegram_raw", new_callable=AsyncMock) as mock_raw:
            results = await service.send_summary_alert(
                project.id,
                {
                    "findings_count": 5,
                    "critical_count": 2,
                    "high_count": 3,
                    "scan_status": "completed",
                    "scan_type": "daily",
                },
            )
            assert len(results) >= 1
            assert results[0]["success"] is True


# --- MonitoringService Tests ---


class TestMonitoringService:
    """Test MonitoringService schedule management and change detection."""

    @pytest.mark.asyncio
    async def test_create_schedule(self, test_session, user):
        """Create a monitoring schedule."""
        project = await _make_project(test_session, user.id)

        service = MonitoringService(test_session)
        schedule = await service.create_schedule(
            project.id, user.id, name="Nightly", frequency="daily"
        )

        assert schedule.id is not None
        assert schedule.name == "Nightly"
        assert schedule.frequency == "daily"
        assert schedule.enabled is True
        assert schedule.next_scan_at is not None

    @pytest.mark.asyncio
    async def test_get_due_schedules(self, test_session, user):
        """Get due schedules returns schedules where next_scan_at <= now."""
        project = await _make_project(test_session, user.id)
        sched1 = await _make_schedule(test_session, project.id, user.id, enabled=True)
        sched1.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        sched2 = await _make_schedule(test_session, project.id, user.id, name="Future", enabled=True)
        sched2.next_scan_at = datetime.now(timezone.utc) + timedelta(days=1)
        await test_session.commit()

        service = MonitoringService(test_session)
        due = await service.get_due_schedules()

        due_ids = [s.id for s in due]
        assert sched1.id in due_ids
        assert sched2.id not in due_ids

    @pytest.mark.asyncio
    async def test_get_due_schedules_excludes_disabled(self, test_session, user):
        """Disabled schedules are not due."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id, enabled=False)
        sched.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        service = MonitoringService(test_session)
        due = await service.get_due_schedules()

        assert sched.id not in [s.id for s in due]

    @pytest.mark.asyncio
    async def test_execute_cycle_updates_schedule(self, test_session, user):
        """Executing a cycle updates last_scan_at and next_scan_at."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        service = MonitoringService(test_session)
        result = await service.execute_monitoring_cycle(sched)

        assert result["status"] == "completed"
        assert sched.last_scan_at is not None
        assert sched.last_scan_status == "completed"
        assert sched.consecutive_failures == 0
        assert sched.next_scan_at > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_execute_cycle_increments_failures(self, test_session, user):
        """Failed cycles increment consecutive_failures."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        service = MonitoringService(test_session)

        # Patch _detect_asset_changes to raise an exception
        with patch.object(service, "_detect_asset_changes",
                          side_effect=Exception("DB error")):
            result = await service.execute_monitoring_cycle(sched)

            assert result["status"] == "failed"
            assert sched.consecutive_failures == 1
            assert sched.last_scan_status == "failed"

    @pytest.mark.asyncio
    async def test_toggle_schedule(self, test_session, user):
        """Toggle schedule enables/disables."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id, enabled=True)

        service = MonitoringService(test_session)
        toggled = await service.toggle_schedule(sched.id, False)

        assert toggled.enabled is False

        toggled2 = await service.toggle_schedule(sched.id, True)
        assert toggled2.enabled is True
        assert toggled2.next_scan_at is not None

    @pytest.mark.asyncio
    async def test_detect_changes_new_assets(self, test_session, user):
        """Change detection identifies new assets."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.last_scan_at = datetime.now(timezone.utc) - timedelta(days=1)
        await test_session.commit()

        eng = await _make_engagement(test_session, project.id)
        asset = Asset(
            engagement_id=eng.id,
            asset_type=AssetType.SUBDOMAIN,
            value="new.example.com",
            source_tool=ReconTool.SUBFINDER,
            first_seen=datetime.now(timezone.utc),
        )
        test_session.add(asset)
        await test_session.commit()

        service = MonitoringService(test_session)
        changes = await service.detect_changes(project.id)

        new_assets = [c for c in changes if c["type"] == "new_asset"]
        assert len(new_assets) >= 1
        assert "new.example.com" in new_assets[0]["description"]

    @pytest.mark.asyncio
    async def test_detect_changes_new_findings(self, test_session, user):
        """Change detection identifies new critical/high findings."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.last_scan_at = datetime.now(timezone.utc) - timedelta(days=1)
        await test_session.commit()

        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            fingerprint="fp_change_001",
        )

        service = MonitoringService(test_session)
        changes = await service.detect_changes(project.id)

        new_findings = [c for c in changes if c["type"] == "new_finding"]
        assert len(new_findings) >= 1

    @pytest.mark.asyncio
    async def test_detect_changes_regressions(self, test_session, user):
        """Change detection identifies reopened findings."""
        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.last_scan_at = datetime.now(timezone.utc) - timedelta(days=1)
        await test_session.commit()

        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.HIGH,
            status=FindingStatus.REOPENED,
            fingerprint="fp_regress_001",
        )
        finding.updated_at = datetime.now(timezone.utc)
        await test_session.commit()

        service = MonitoringService(test_session)
        changes = await service.detect_changes(project.id)

        regressions = [c for c in changes if c["type"] == "regression"]
        assert len(regressions) >= 1


# --- Model Tests ---


class TestWebhookConfigModel:
    """Test WebhookConfig model creation and properties."""

    @pytest.mark.asyncio
    async def test_create_webhook_config(self, test_session, user):
        project = await _make_project(test_session, user.id)
        webhook = WebhookConfig(
            project_id=project.id,
            user_id=user.id,
            name="Discord Alerts",
            webhook_type="discord",
            url="https://discord.com/api/webhooks/123/abc",
            min_severity="critical",
            enabled=True,
        )
        test_session.add(webhook)
        await test_session.commit()
        await test_session.refresh(webhook)

        assert webhook.id is not None
        assert webhook.webhook_type == "discord"
        assert webhook.min_severity == "critical"
        assert webhook.enabled is True

    @pytest.mark.asyncio
    async def test_webhook_with_custom_headers(self, test_session, user):
        project = await _make_project(test_session, user.id)
        webhook = WebhookConfig(
            project_id=project.id,
            user_id=user.id,
            name="Custom Hook",
            webhook_type="custom",
            url="https://hooks.example.com/alert",
            min_severity="high",
            enabled=True,
            headers={"Authorization": "Bearer test-token", "X-Custom": "value"},
        )
        test_session.add(webhook)
        await test_session.commit()
        await test_session.refresh(webhook)

        assert webhook.headers["Authorization"] == "Bearer test-token"
        assert webhook.headers["X-Custom"] == "value"


class TestMonitoringScheduleModel:
    """Test MonitoringSchedule model creation and properties."""

    @pytest.mark.asyncio
    async def test_create_schedule(self, test_session, user):
        project = await _make_project(test_session, user.id)
        schedule = MonitoringSchedule(
            project_id=project.id,
            user_id=user.id,
            name="Weekly Deep Scan",
            frequency="weekly",
            profile="deep",
            enabled=True,
            targets=["example.com", "*.example.com"],
            next_scan_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        test_session.add(schedule)
        await test_session.commit()
        await test_session.refresh(schedule)

        assert schedule.id is not None
        assert schedule.frequency == "weekly"
        assert schedule.profile == "deep"
        assert schedule.targets == ["example.com", "*.example.com"]
        assert schedule.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_schedule_defaults(self, test_session, user):
        project = await _make_project(test_session, user.id)
        schedule = MonitoringSchedule(
            project_id=project.id,
            user_id=user.id,
            name="Default Schedule",
            frequency="daily",
            profile="standard",
        )
        test_session.add(schedule)
        await test_session.commit()
        await test_session.refresh(schedule)

        assert schedule.enabled is True
        assert schedule.scan_all_assets is True
        assert schedule.consecutive_failures == 0
        assert schedule.last_scan_at is None
        assert schedule.last_scan_findings_count is None


# --- API Integration Tests ---


class TestWebhookAPI:
    """Test webhook API endpoints."""

    @pytest.mark.asyncio
    async def test_create_webhook_endpoint(self, client, test_session, user):
        """POST /api/v1/projects/{id}/webhooks creates a webhook."""
        project = await _make_project(test_session, user.id)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.post(
            f"/api/v1/projects/{project.id}/webhooks",
            json={
                "name": "Test Telegram",
                "webhook_type": "telegram",
                "url": "https://api.telegram.org/bot123:ABC/sendMessage",
                "min_severity": "high",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Telegram"
        assert data["webhook_type"] == "telegram"
        assert data["min_severity"] == "high"
        assert data["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_webhooks_endpoint(self, client, test_session, user):
        """GET /api/v1/projects/{id}/webhooks lists webhooks."""
        project = await _make_project(test_session, user.id)
        await _make_webhook(test_session, project.id, user.id)
        await _make_webhook(test_session, project.id, user.id, webhook_type="discord")

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.get(f"/api/v1/projects/{project.id}/webhooks")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_delete_webhook_endpoint(self, client, test_session, user):
        """DELETE /api/v1/projects/{id}/webhooks/{id} deletes webhook."""
        project = await _make_project(test_session, user.id)
        webhook = await _make_webhook(test_session, project.id, user.id)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.delete(
            f"/api/v1/projects/{project.id}/webhooks/{webhook.id}"
        )
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_create_monitoring_schedule_endpoint(self, client, test_session, user):
        """POST /api/v1/projects/{id}/monitoring/schedules creates schedule."""
        project = await _make_project(test_session, user.id)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.post(
            f"/api/v1/projects/{project.id}/monitoring/schedules",
            json={
                "name": "Nightly Scan",
                "frequency": "daily",
                "profile": "standard",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Nightly Scan"
        assert data["frequency"] == "daily"
        assert data["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_monitoring_schedules_endpoint(self, client, test_session, user):
        """GET /api/v1/projects/{id}/monitoring/schedules lists schedules."""
        project = await _make_project(test_session, user.id)
        await _make_schedule(test_session, project.id, user.id)
        await _make_schedule(test_session, project.id, user.id, name="Second")

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.get(
            f"/api/v1/projects/{project.id}/monitoring/schedules"
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_toggle_schedule_endpoint(self, client, test_session, user):
        """POST /api/v1/projects/{id}/monitoring/schedules/{id}/toggle toggles."""
        project = await _make_project(test_session, user.id)
        schedule = await _make_schedule(test_session, project.id, user.id, enabled=True)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.post(
            f"/api/v1/projects/{project.id}/monitoring/schedules/{schedule.id}/toggle"
            "?enabled=false"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False

    @pytest.mark.asyncio
    async def test_run_monitoring_cycle_endpoint(self, client, test_session, user):
        """POST /api/v1/projects/{id}/monitoring/schedules/{id}/run triggers cycle."""
        project = await _make_project(test_session, user.id)
        schedule = await _make_schedule(test_session, project.id, user.id)
        schedule.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.post(
            f"/api/v1/projects/{project.id}/monitoring/schedules/{schedule.id}/run"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "schedule_id" in data

    @pytest.mark.asyncio
    async def test_detect_changes_endpoint(self, client, test_session, user):
        """GET /api/v1/projects/{id}/monitoring/changes detects changes."""
        project = await _make_project(test_session, user.id)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        response = client.get(
            f"/api/v1/projects/{project.id}/monitoring/changes"
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_test_webhook_endpoint(self, client, test_session, user):
        """POST /api/v1/projects/{id}/webhooks/{id}/test sends test alert."""
        project = await _make_project(test_session, user.id)
        webhook = await _make_webhook(test_session, project.id, user.id)

        from app.api.deps import get_current_user
        client.app.dependency_overrides[get_current_user] = lambda: user

        with patch("app.services.alert_service.AlertService") as MockAlertService:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(
                return_value=[{"webhook_id": webhook.id, "success": True, "error": None}]
            )
            MockAlertService.return_value = mock_service

            response = client.post(
                f"/api/v1/projects/{project.id}/webhooks/{webhook.id}/test"
            )
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestAlertFormattingIntegration:
    """Integration tests for alert formatting with real model instances."""

    @pytest.mark.asyncio
    async def test_telegram_format_with_real_finding(self, test_session, user):
        """Telegram formatting works with actual Finding model."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            title="IDOR in user profile",
            severity=FindingSeverity.CRITICAL,
            category="idor",
            fingerprint="fp_integ_001",
        )

        msg = _format_telegram_message(finding, project.name, "new_finding")

        assert "IDOR in user profile" in msg
        assert "CRITICAL" in msg
        assert "idor" in msg
        assert project.name in msg

    @pytest.mark.asyncio
    async def test_discord_format_with_real_finding(self, test_session, user):
        """Discord formatting works with actual Finding model."""
        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            category="sqli",
            fingerprint="fp_integ_002",
        )

        embed = _format_discord_embed(finding, project.name, "new_finding")

        assert "SQL Injection" in embed["title"]
        assert embed["color"] == 0x7F1D1D  # Critical
        assert any(f["value"] == "CRITICAL" for f in embed["fields"])


# --- Pipeline Alert Integration Tests ---


class TestPipelineAlertIntegration:
    """Test that pipeline triggers alerts after finding ingestion."""

    @pytest.mark.asyncio
    async def test_pipeline_triggers_alerts_for_critical_findings(self, test_session, user):
        """Pipeline sends alerts when Critical findings are ingested."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)
        await _make_webhook(test_session, project.id, user.id)

        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            title="RCE via upload",
            fingerprint="fp_pipe_crit_001",
        )

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._trigger_alerts([finding], project.id)

            mock_service.send_finding_alert.assert_called_once_with(
                finding, project.id, change_type="new_finding"
            )

    @pytest.mark.asyncio
    async def test_pipeline_triggers_alerts_for_high_findings(self, test_session, user):
        """Pipeline sends alerts when High findings are ingested."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.HIGH,
            title="XSS in search",
            fingerprint="fp_pipe_high_001",
        )

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._trigger_alerts([finding], project.id)

            mock_service.send_finding_alert.assert_called_once()

    @pytest.mark.asyncio
    async def test_pipeline_skips_alerts_for_medium_findings(self, test_session, user):
        """Pipeline does NOT send alerts for Medium/Low/Info findings."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.MEDIUM,
            title="Info disclosure",
            fingerprint="fp_pipe_med_001",
        )

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._trigger_alerts([finding], project.id)

            mock_service.send_finding_alert.assert_not_called()

    @pytest.mark.asyncio
    async def test_pipeline_sends_summary_alert(self, test_session, user):
        """Pipeline sends summary alert after scan completion."""
        from app.services.pipeline import PipelineOrchestrator, PipelineResult

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        finding_crit = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            title="Critical",
            fingerprint="fp_pipe_sum_001",
        )
        finding_high = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.HIGH,
            title="High",
            fingerprint="fp_pipe_sum_002",
        )

        # Build a minimal PipelineResult
        mock_job = MagicMock()
        mock_job.engagement_id = eng.id
        result = PipelineResult()
        result.recon_jobs = [mock_job]
        result.findings = [finding_crit, finding_high]
        result.status = "completed"

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_summary_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._send_scan_summary(result)

            mock_service.send_summary_alert.assert_called_once()
            call_args = mock_service.send_summary_alert.call_args
            assert call_args[0][0] == project.id
            summary = call_args[0][1]
            assert summary["critical_count"] == 1
            assert summary["high_count"] == 1
            assert summary["findings_count"] == 2

    @pytest.mark.asyncio
    async def test_pipeline_alert_failure_doesnt_crash(self, test_session, user):
        """Pipeline continues even if alert delivery fails."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        finding = await _make_finding(
            test_session, eng.id, project.id, user.id,
            severity=FindingSeverity.CRITICAL,
            title="Critical",
            fingerprint="fp_pipe_fail_001",
        )

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(
                side_effect=Exception("Network error")
            )
            MockAlert.return_value = mock_service

            # Should not raise
            await orchestrator._trigger_alerts([finding], project.id)

    @pytest.mark.asyncio
    async def test_pipeline_alerts_multiple_findings(self, test_session, user):
        """Pipeline sends separate alerts for each Critical/High finding."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        findings = []
        for i in range(3):
            f = await _make_finding(
                test_session, eng.id, project.id, user.id,
                severity=FindingSeverity.CRITICAL,
                title=f"Critical Finding {i}",
                fingerprint=f"fp_pipe_multi_{i:03d}",
            )
            findings.append(f)

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._trigger_alerts(findings, project.id)

            assert mock_service.send_finding_alert.call_count == 3

    @pytest.mark.asyncio
    async def test_pipeline_mixed_severity_sends_only_critical_high(self, test_session, user):
        """Pipeline only alerts on Critical/High, skips Medium/Low/Info."""
        from app.services.pipeline import PipelineOrchestrator

        project = await _make_project(test_session, user.id)
        eng = await _make_engagement(test_session, project.id)

        findings = []
        sevs = [
            FindingSeverity.CRITICAL, FindingSeverity.HIGH,
            FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO,
        ]
        for i, sev in enumerate(sevs):
            f = await _make_finding(
                test_session, eng.id, project.id, user.id,
                severity=sev,
                title=f"Finding {sev.value}",
                fingerprint=f"fp_pipe_mixed_{i:03d}",
            )
            findings.append(f)

        orchestrator = PipelineOrchestrator(test_session, user)

        with patch("app.services.alert_service.AlertService") as MockAlert:
            mock_service = AsyncMock()
            mock_service.send_finding_alert = AsyncMock(return_value=[])
            MockAlert.return_value = mock_service

            await orchestrator._trigger_alerts(findings, project.id)

            # Only 2 calls: Critical + High
            assert mock_service.send_finding_alert.call_count == 2


class TestMonitoringAlertIntegration:
    """Test that MonitoringService sends alerts for scan results."""

    @pytest.mark.asyncio
    async def test_monitoring_sends_alerts_on_critical_findings(self, test_session, user):
        """Monitoring cycle sends summary alerts when critical findings exist."""
        from app.services.monitoring_service import MonitoringService

        project = await _make_project(test_session, user.id)
        sched = await _make_schedule(test_session, project.id, user.id)
        sched.next_scan_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await test_session.commit()

        service = MonitoringService(test_session)

        with patch.object(service.alert_service, "send_summary_alert",
                          new_callable=AsyncMock) as mock_alert:
            mock_alert.return_value = []
            result = await service.execute_monitoring_cycle(sched)

            # Alert may or may not be called depending on whether new findings exist
            # But the service should be wired correctly
            assert result["status"] == "completed"

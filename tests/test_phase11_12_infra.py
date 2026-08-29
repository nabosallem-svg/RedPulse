"""Phase 11/12: Rate Limiting, Docker & Worker Tests.

Tests for:
- Rate limiter configuration and creation
- SlowAPI integration
- Celery app configuration
- Task definitions
- Docker healthcheck endpoints
- Security headers middleware
"""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestRateLimiterConfiguration:
    """Test rate limiter creation and configuration."""

    def test_create_limiter_memory_fallback(self):
        """Limiter falls back to in-memory when REDIS_URL not set."""
        with patch.dict(os.environ, {"REDIS_URL": "", "RATE_LIMIT_LIMIT": "true"}, clear=False):
            from app.core.rate_limit import create_limiter
            limiter = create_limiter()
            assert limiter is not None

    def test_create_limiter_redis_backend(self):
        """Limiter uses Redis when REDIS_URL is set."""
        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0", "RATE_LIMIT_ENABLED": "true"}, clear=False):
            from app.core.rate_limit import create_limiter
            limiter = create_limiter()
            assert limiter is not None

    def test_rate_limit_disabled(self):
        """Rate limiting can be disabled via env var."""
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "false"}, clear=False):
            from app.core.rate_limit import setup_rate_limiting
            from fastapi import FastAPI
            app = FastAPI()
            setup_rate_limiting(app)
            # Should not add limiter to app.state when disabled
            assert not hasattr(app.state, "limiter")

    def test_rate_limit_presets_defined(self):
        """All rate limit presets are defined."""
        from app.core.rate_limit import RATE_LIMITS
        assert "auth_login" in RATE_LIMITS
        assert "auth_signup" in RATE_LIMITS
        assert "pipeline_run" in RATE_LIMITS
        assert "scan_start" in RATE_LIMITS
        assert "default_api" in RATE_LIMITS

    def test_rate_limit_handler_returns_json(self):
        """Rate limit handler returns proper JSON response."""
        from app.core.rate_limit import rate_limit_handler
        from slowapi.errors import RateLimitExceeded
        from slowapi.wrappers import Limit
        from fastapi import Request

        limit = Limit(
            "5/minute",
            key_func=lambda: "test",
            scope=None,
            per_method=False,
            methods=None,
            error_message=None,
            exempt_when=None,
            cost=1,
            override_defaults=False,
        )
        exc = RateLimitExceeded(limit)
        mock_request = MagicMock(spec=Request)
        response = rate_limit_handler(mock_request, exc)
        assert response.status_code == 429
        assert "rate_limit_exceeded" in response.body.decode()


class TestSlowAPIIntegration:
    """Test SlowAPI middleware integration with FastAPI."""

    def test_app_has_limiter(self):
        """App created with setup_rate_limiting has limiter on state."""
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "true", "REDIS_URL": ""}, clear=False):
            from app.core.rate_limit import setup_rate_limiting
            from fastapi import FastAPI
            app = FastAPI()
            setup_rate_limiting(app)
            assert hasattr(app.state, "limiter")

    def test_limiter_key_func(self):
        """Limiter uses remote address as key function."""
        from app.core.rate_limit import limiter
        assert limiter is not None
        assert limiter._key_func is not None


class TestCeleryAppConfiguration:
    """Test Celery app configuration."""

    def test_celery_app_exists(self):
        """Celery app is properly configured."""
        from app.services.celery_app import celery_app
        assert celery_app is not None
        assert celery_app.main == "redpulse"

    def test_celery_broker_url(self):
        """Celery broker URL is configured."""
        from app.services.celery_app import celery_app
        broker = celery_app.conf.broker_url
        assert broker is not None
        assert "redis" in broker

    def test_celery_result_backend(self):
        """Celery result backend is configured."""
        from app.services.celery_app import celery_app
        backend = celery_app.conf.result_backend
        assert backend is not None

    def test_celery_serialization(self):
        """Celery uses JSON serialization."""
        from app.services.celery_app import celery_app
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.result_serializer == "json"

    def test_celery_time_limits(self):
        """Celery has proper time limits configured."""
        from app.services.celery_app import celery_app
        assert celery_app.conf.task_soft_time_limit == 300
        assert celery_app.conf.task_time_limit == 600

    def test_celery_queue_routing(self):
        """Scan tasks are routed to scans queue."""
        from app.services.celery_app import celery_app
        routes = celery_app.conf.task_routes
        assert "app.services.tasks.run_scan" in routes
        assert routes["app.services.tasks.run_scan"]["queue"] == "scans"

    def test_celery_worker_settings(self):
        """Worker settings are configured for heavy tasks."""
        from app.services.celery_app import celery_app
        assert celery_app.conf.worker_prefetch_multiplier == 1
        assert celery_app.conf.task_acks_late is True


class TestCeleryTasks:
    """Test Celery task definitions."""

    def test_run_scan_task_exists(self):
        """run_scan task is registered."""
        from app.services.tasks import run_scan
        assert run_scan is not None
        assert hasattr(run_scan, "delay")

    def test_run_recon_task_exists(self):
        """run_recon task is registered."""
        from app.services.tasks import run_recon
        assert run_recon is not None
        assert hasattr(run_recon, "delay")

    def test_run_pipeline_task_exists(self):
        """run_pipeline task is registered."""
        from app.services.tasks import run_pipeline
        assert run_pipeline is not None
        assert hasattr(run_pipeline, "delay")

    def test_send_notification_task_exists(self):
        """send_notification task is registered."""
        from app.services.tasks import send_notification
        assert send_notification is not None
        assert hasattr(send_notification, "delay")

    def test_task_names_match_routing(self):
        """Task names match the routing configuration."""
        from app.services.celery_app import celery_app
        from app.services.tasks import run_scan, run_recon, run_pipeline

        routes = celery_app.conf.task_routes
        assert run_scan.name in routes
        assert run_recon.name in routes
        assert run_pipeline.name in routes


class TestSecurityHeaders:
    """Test security headers middleware in the app."""

    def test_app_returns_security_headers(self, client):
        """All security headers are present in responses."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("x-xss-protection") == "1; mode=block"
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert "permissions-policy" in response.headers
        assert response.headers.get("x-api-version") == "0.1.0"


class TestHealthEndpoint:
    """Test health check endpoint for Docker healthcheck."""

    def test_health_returns_ok(self, client):
        """Health endpoint returns status ok."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_health_is_unauthenticated(self, client):
        """Health endpoint doesn't require authentication."""
        response = client.get("/health")
        assert response.status_code == 200


class TestDockerComposeConfig:
    """Test docker-compose.yml structure (static analysis)."""

    def _load_compose(self):
        """Load docker-compose.yml safely."""
        import yaml
        with open("docker-compose.yml") as f:
            content = f.read()
        # Use safe_load which handles multi-line strings
        return yaml.safe_load(content)

    def test_docker_compose_has_all_services(self):
        """docker-compose.yml defines all required services."""
        config = self._load_compose()
        services = config.get("services", {})
        assert "postgres" in services
        assert "redis" in services
        assert "api" in services
        assert "worker" in services

    def test_postgres_has_healthcheck(self):
        """Postgres service has healthcheck configured."""
        config = self._load_compose()
        pg = config["services"]["postgres"]
        assert "healthcheck" in pg
        assert pg["image"] == "postgres:16-alpine"

    def test_redis_has_healthcheck(self):
        """Redis service has healthcheck configured."""
        config = self._load_compose()
        redis = config["services"]["redis"]
        assert "healthcheck" in redis
        assert "redis:7-alpine" in redis["image"]

    def test_api_depends_on_healthy_services(self):
        """API service depends on postgres and redis being healthy."""
        config = self._load_compose()
        api = config["services"]["api"]
        deps = api.get("depends_on", {})
        assert "postgres" in deps
        assert "redis" in deps
        assert deps["postgres"]["condition"] == "service_healthy"
        assert deps["redis"]["condition"] == "service_healthy"

    def test_api_has_resource_limits(self):
        """API service has memory limits set."""
        config = self._load_compose()
        api = config["services"]["api"]
        deploy = api.get("deploy", {})
        resources = deploy.get("resources", {})
        limits = resources.get("limits", {})
        assert "memory" in limits

    def test_volumes_defined(self):
        """Named volumes are defined for data persistence."""
        config = self._load_compose()
        volumes = config.get("volumes", {})
        assert "postgres_data" in volumes
        assert "redis_data" in volumes

    def test_network_defined(self):
        """Custom network is defined."""
        config = self._load_compose()
        networks = config.get("networks", {})
        assert "default" in networks

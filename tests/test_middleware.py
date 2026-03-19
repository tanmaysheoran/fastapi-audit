"""Tests for the middleware module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fastapi_audit.config import AuditConfig
from fastapi_audit.middleware import AuditMiddleware


class TestAuditMiddleware:
    """Tests for AuditMiddleware."""

    def test_excluded_paths(self) -> None:
        """Test that excluded paths are not audited."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            exclude_paths={"/health"},
        )
        assert config.should_exclude("/health")
        assert not config.should_exclude("/api/users")

    def test_log_anonymous_disabled(self) -> None:
        """Test that anonymous requests are not logged when disabled."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            log_anonymous=False,
        )
        assert config.log_anonymous is False

    def test_log_anonymous_enabled(self) -> None:
        """Test that anonymous requests are logged when enabled."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            log_anonymous=True,
        )
        assert config.log_anonymous is True


class TestMiddlewareDispatch:
    """Tests for middleware dispatch."""

    @pytest.mark.asyncio
    async def test_middleware_excludes_path(self) -> None:
        """Test that middleware excludes configured paths."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            exclude_paths={"/health"},
        )

        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        request = MagicMock()
        request.url.path = "/health"
        request.method = "GET"
        request.headers = {}

        call_next = AsyncMock(return_value=MagicMock(status_code=200))

        await middleware.dispatch(request, call_next)
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_middleware_captures_request(self) -> None:
        """Test that middleware captures request data."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            capture_request_body=False,
            capture_response_body=False,
            capture_orm_diffs=False,
            log_anonymous=True,
        )

        app = MagicMock()
        middleware = AuditMiddleware(app, config)
        middleware._initialized = True
        middleware._writer = AsyncMock()

        request = MagicMock()
        request.url.path = "/api/users"
        request.method = "GET"
        request.headers = {"X-Request-ID": "test-123"}
        request.query_params = {}
        request.state = MagicMock()

        response = MagicMock()
        response.status_code = 200

        call_next = AsyncMock(return_value=response)

        await middleware.dispatch(request, call_next)
        middleware._writer.write.assert_called_once()

    def test_get_client_ip(self) -> None:
        """Test client IP extraction."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "192.168.1.1"

        ip = middleware._get_client_ip(request)
        assert ip == "192.168.1.1"

    def test_get_client_ip_forwarded(self) -> None:
        """Test client IP extraction from X-Forwarded-For."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
        request.client = MagicMock()

        ip = middleware._get_client_ip(request)
        assert ip == "10.0.0.1"

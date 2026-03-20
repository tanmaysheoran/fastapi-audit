"""Tests for the middleware module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

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


class TestMiddlewareIPExtraction:
    """Tests for client IP extraction with trusted proxy depth."""

    def test_get_client_ip_trusted_proxy_depth_zero(self) -> None:
        """Test that X-Forwarded-For is ignored when depth is 0."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            trusted_proxy_depth=0,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        scope = {"client": ("192.168.1.100", 8000)}
        headers = MagicMock()
        headers.get = MagicMock(return_value="10.0.0.1, 192.168.1.1")

        ip = middleware._get_client_ip(scope, headers)
        assert ip == "192.168.1.100"

    def test_get_client_ip_trusted_proxy_depth_one(self) -> None:
        """Test that last IP before proxy is extracted when depth is 1."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            trusted_proxy_depth=1,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        scope = {"client": ("127.0.0.1", 8000)}
        headers = MagicMock()
        headers.get = MagicMock(return_value="10.0.0.1, 192.168.1.1, 172.16.0.1")

        ip = middleware._get_client_ip(scope, headers)
        assert ip == "172.16.0.1"

    def test_get_client_ip_multi_proxy(self) -> None:
        """Test client IP extraction with multiple proxies."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            trusted_proxy_depth=2,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        scope = {"client": ("127.0.0.1", 8000)}
        headers = MagicMock()
        headers.get = MagicMock(return_value="10.0.0.1, 192.168.1.1, 172.16.0.1, 172.16.0.5")

        ip = middleware._get_client_ip(scope, headers)
        assert ip == "172.16.0.1"

    def test_get_client_ip_no_forwarded_header(self) -> None:
        """Test fallback to direct client when no X-Forwarded-For."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            trusted_proxy_depth=1,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        scope = {"client": ("192.168.1.100", 8000)}
        headers = MagicMock()
        headers.get = MagicMock(return_value=None)

        ip = middleware._get_client_ip(scope, headers)
        assert ip == "192.168.1.100"

    def test_get_client_ip_no_client_in_scope(self) -> None:
        """Test fallback when no client in scope."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            trusted_proxy_depth=0,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        scope = {}
        headers = MagicMock()

        ip = middleware._get_client_ip(scope, headers)
        assert ip == "unknown"


class TestMiddlewareExclusions:
    """Tests for path exclusion logic."""

    def test_should_exclude_path(self) -> None:
        """Test path exclusion logic."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        assert middleware._should_exclude_path("/health") is True
        assert middleware._should_exclude_path("/api/users") is False


class TestMiddlewareActorExtraction:
    """Tests for actor extraction from JWT."""

    def test_extract_actor_with_valid_token(self) -> None:
        """Test actor extraction from Authorization header."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            jwt_secret="secret",
            jwt_verify_signature=True,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        from jose import jwt
        token = jwt.encode(
            {"sub": "user123", "actor_type": "tenant_user", "email": "user@example.com"},
            "secret",
            algorithm="HS256",
        )

        headers = MagicMock()
        headers.get = MagicMock(return_value=f"Bearer {token}")

        actor = middleware._extract_actor(headers)
        assert actor is not None
        assert actor["actor_id"] == "user123"
        assert actor["actor_type"] == "tenant_user"
        assert actor["actor_email"] == "user@example.com"

    def test_extract_actor_no_auth_header(self) -> None:
        """Test that actor is None when no Authorization header."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        headers = MagicMock()
        headers.get = MagicMock(return_value=None)

        actor = middleware._extract_actor(headers)
        assert actor is None


class TestResponseBodyProcessing:
    """Tests for response body processing."""

    def test_process_response_body_json(self) -> None:
        """Test processing JSON response body."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            max_body_size_bytes=1000,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        body = b'{"user": "test", "password": "secret123"}'
        result = middleware._process_response_body(body)

        assert result is not None
        assert result["user"] == "test"
        assert result["password"] == "[REDACTED]"

    def test_process_response_body_truncation(self) -> None:
        """Test response body truncation when exceeding max size."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            max_body_size_bytes=20,
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        body = b'{"user": "john", "id": 123}'
        result = middleware._process_response_body(body)

        assert result is not None
        assert result.get("_truncated") is True

    def test_process_response_body_non_json(self) -> None:
        """Test processing non-JSON response body."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        body = b"Plain text response"
        result = middleware._process_response_body(body)

        assert result is not None
        assert result["_raw"] == "Plain text response"

    def test_process_response_body_empty(self) -> None:
        """Test processing empty response body."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        result = middleware._process_response_body(b"")
        assert result is None

    def test_process_response_body_redaction(self) -> None:
        """Test that sensitive fields are redacted in response body."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            redact_fields={"api_key", "token"},
        )
        app = MagicMock()
        middleware = AuditMiddleware(app, config)

        body = b'{"username": "admin", "api_key": "secret123", "token": "abc"}'
        result = middleware._process_response_body(body)

        assert result is not None
        assert result["username"] == "admin"
        assert result["api_key"] == "[REDACTED]"
        assert result["token"] == "[REDACTED]"

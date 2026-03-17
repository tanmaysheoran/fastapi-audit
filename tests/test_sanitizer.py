"""Tests for the sanitizer module."""

import pytest

from audit.config import AuditConfig
from audit.sanitizer import (
    redact_value,
    sanitize_body,
    sanitize_query_params,
)


class TestRedactValue:
    """Tests for redact_value function."""

    def test_redact_password_field(self) -> None:
        """Test that password field is redacted."""
        data = {"username": "john", "password": "secret123"}
        result = redact_value(data, {"password"})
        assert result["username"] == "john"
        assert result["password"] == "[REDACTED]"

    def test_redact_nested_password(self) -> None:
        """Test that nested password fields are redacted."""
        data = {"user": {"password": "secret", "name": "john"}}
        result = redact_value(data, {"password"})
        assert result["user"]["password"] == "[REDACTED]"
        assert result["user"]["name"] == "john"

    def test_redact_password_hash_partial_match(self) -> None:
        """Test that password_hash is redacted (partial match)."""
        data = {"password_hash": "abc123", "name": "john"}
        result = redact_value(data, {"password"})
        assert result["password_hash"] == "[REDACTED]"
        assert result["name"] == "john"

    def test_redact_case_insensitive(self) -> None:
        """Test that redaction is case-insensitive."""
        data = {"PASSWORD": "secret", "Password": "secret2"}
        result = redact_value(data, {"password"})
        assert result["PASSWORD"] == "[REDACTED]"
        assert result["Password"] == "[REDACTED]"

    def test_redact_list_items(self) -> None:
        """Test that list items are processed recursively."""
        data = [{"password": "secret1"}, {"password": "secret2"}]
        result = redact_value(data, {"password"})
        assert result[0]["password"] == "[REDACTED]"
        assert result[1]["password"] == "[REDACTED]"

    def test_no_redact_needed(self) -> None:
        """Test that non-matching fields are unchanged."""
        data = {"name": "john", "age": 30}
        result = redact_value(data, {"password"})
        assert result == data


class TestSanitizeBody:
    """Tests for sanitize_body function."""

    def test_sanitize_json_body(self) -> None:
        """Test sanitizing JSON body."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = b'{"username": "john", "password": "secret"}'
        result = sanitize_body(body, config)
        assert result["username"] == "john"
        assert result["password"] == "[REDACTED]"

    def test_sanitize_string_body(self) -> None:
        """Test sanitizing string body."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = '{"password": "secret"}'
        result = sanitize_body(body, config)
        assert result["password"] == "[REDACTED]"

    def test_sanitize_empty_body(self) -> None:
        """Test sanitizing empty body returns None."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert sanitize_body(b"", config) is None
        assert sanitize_body(None, config) is None

    def test_sanitize_invalid_json(self) -> None:
        """Test sanitizing invalid JSON returns raw string."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = b"not valid json"
        result = sanitize_body(body, config)
        assert result == {"_raw": "not valid json"}


class TestSanitizeQueryParams:
    """Tests for sanitize_query_params function."""

    def test_sanitize_query_params(self) -> None:
        """Test sanitizing query parameters."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        params = {"page": "1", "password": "secret"}
        result = sanitize_query_params(params, config)
        assert result["page"] == "1"
        assert result["password"] == "[REDACTED]"

    def test_empty_query_params(self) -> None:
        """Test empty query params."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        result = sanitize_query_params({}, config)
        assert result == {}


class TestAuditConfig:
    """Tests for AuditConfig redaction field merging."""

    def test_default_redact_fields(self) -> None:
        """Test that default redact fields are included."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert "password" in config.redact_fields
        assert "token" in config.redact_fields

    def test_custom_redact_fields_merged(self) -> None:
        """Test that custom fields are merged with defaults."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            redact_fields={"api_key"},
        )
        assert "api_key" in config.redact_fields
        assert "password" in config.redact_fields

    def test_redact_fields_case_insensitive_matching(self) -> None:
        """Test that redact_fields_lower works correctly."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            redact_fields={"MyField"},
        )
        assert "myfield" in config.redact_fields_lower

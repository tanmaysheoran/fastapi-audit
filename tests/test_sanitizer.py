"""Tests for the sanitizer module (sensitive field redaction)."""

from fastapi_audit.config import AuditConfig
from fastapi_audit.sanitizer import (
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

    def test_redact_partial_match(self) -> None:
        """Test that partial key matches trigger redaction."""
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

    def test_primitives_pass_through(self) -> None:
        """Test that primitive values are returned unchanged."""
        assert redact_value("hello", {"password"}) == "hello"
        assert redact_value(42, {"password"}) == 42
        assert redact_value(None, {"password"}) is None

    def test_deeply_nested(self) -> None:
        """Test redaction at multiple nesting levels."""
        data = {
            "top": {
                "middle": {
                    "bottom": {"password": "secret"},
                }
            }
        }
        result = redact_value(data, {"password"})
        assert result["top"]["middle"]["bottom"]["password"] == "[REDACTED]"

    def test_multiple_redact_fields(self) -> None:
        """Test matching multiple redact fields."""
        data = {"password": "p", "token": "t", "name": "john"}
        result = redact_value(data, {"password", "token"})
        assert result["password"] == "[REDACTED]"
        assert result["token"] == "[REDACTED]"
        assert result["name"] == "john"


class TestSanitizeBody:
    """Tests for sanitize_body function."""

    def test_sanitize_json_body(self) -> None:
        """Test sanitizing JSON body."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = b'{"username": "john", "password": "secret"}'
        result = sanitize_body(body, config)
        assert result is not None
        assert result["username"] == "john"
        assert result["password"] == "[REDACTED]"

    def test_sanitize_string_body(self) -> None:
        """Test sanitizing string body."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = '{"password": "secret"}'
        result = sanitize_body(body, config)
        assert result is not None
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

    def test_sanitize_long_invalid_json_truncated(self) -> None:
        """Test that long invalid JSON is truncated."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        body = b"x" * 2000
        result = sanitize_body(body, config)
        assert result is not None
        assert len(result["_raw"]) == 1000


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

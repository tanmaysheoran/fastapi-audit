"""Tests for AuditConfig defaults and validation."""

import pytest

from fastapi_audit import AuditConfig


class TestAuditConfigDefaults:
    """Tests for AuditConfig default values."""

    def test_control_db_url_required(self) -> None:
        """Test that control_db_url is required."""
        with pytest.raises(Exception):
            AuditConfig()  # type: ignore[call-arg]

    def test_default_redact_fields_present(self) -> None:
        """Test that default redact fields are present."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert "password" in config.redact_fields
        assert "token" in config.redact_fields
        assert "secret" in config.redact_fields
        assert "authorization" in config.redact_fields

    def test_default_exclude_paths_present(self) -> None:
        """Test that default exclude paths are present."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert "/health" in config.exclude_paths
        assert "/metrics" in config.exclude_paths
        assert "/docs" in config.exclude_paths

    def test_default_actor_type_aliases_empty(self) -> None:
        """Test that actor_type_aliases defaults to empty dict."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.actor_type_aliases == {}

    def test_default_capture_flags(self) -> None:
        """Test default capture flags."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.capture_request_body is True
        assert config.capture_response_body is True
        assert config.capture_orm_diffs is True
        assert config.log_anonymous is False


class TestAuditConfigCustomValues:
    """Tests for AuditConfig custom value overrides."""

    def test_custom_redact_fields_merged_with_defaults(self) -> None:
        """Test that custom redact fields are merged with defaults."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            redact_fields={"api_key", "private_key"},
        )
        assert "api_key" in config.redact_fields
        assert "private_key" in config.redact_fields
        assert "password" in config.redact_fields  # default still present

    def test_custom_exclude_paths_merged_with_defaults(self) -> None:
        """Test that custom exclude paths are merged with defaults."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            exclude_paths={"/admin"},
        )
        assert "/admin" in config.exclude_paths
        assert "/health" in config.exclude_paths  # default still present

    def test_custom_actor_type_aliases_normalized(self) -> None:
        """Test that custom actor type aliases are normalized to lowercase."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            actor_type_aliases={"Ops_Admin": "PLATFORM_ADMIN"},
        )
        assert "ops_admin" in config.actor_type_aliases_lower
        assert config.actor_type_aliases_lower["ops_admin"] == "platform_admin"

    def test_should_exclude_returns_true_for_excluded_paths(self) -> None:
        """Test should_exclude for excluded paths."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            exclude_paths={"/admin", "/api/secret"},
        )
        assert config.should_exclude("/admin") is True
        assert config.should_exclude("/api/secret") is True

    def test_should_exclude_returns_false_for_non_excluded_paths(self) -> None:
        """Test should_exclude for non-excluded paths."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.should_exclude("/api/users") is False
        assert config.should_exclude("/health") is True  # default excluded


class TestAuditConfigProperties:
    """Tests for AuditConfig computed properties."""

    def test_redact_fields_lower(self) -> None:
        """Test redact_fields_lower normalizes to lowercase."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            redact_fields={"PASSWORD", "API_Key"},
        )
        assert "password" in config.redact_fields_lower
        assert "api_key" in config.redact_fields_lower

    def test_canonical_actor_types(self) -> None:
        """Test canonical_actor_types property."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.canonical_actor_types == {
            "platform_admin",
            "tenant_user",
            "anonymous",
        }

    def test_actor_type_aliases_lower_empty_by_default(self) -> None:
        """Test actor_type_aliases_lower is empty by default."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.actor_type_aliases_lower == {}


class TestAuditConfigEnvVars:
    """Tests for environment variable overrides."""

    def test_env_var_control_db_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that AUDIT_CONTROL_DB_URL env var is read."""
        monkeypatch.setenv("AUDIT_CONTROL_DB_URL", "postgresql+asyncpg://env/db")
        config = AuditConfig()
        assert config.control_db_url == "postgresql+asyncpg://env/db"

    def test_env_var_capture_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that AUDIT_CAPTURE_ORM_DIFFS env var is read."""
        monkeypatch.setenv("AUDIT_CONTROL_DB_URL", "postgresql+asyncpg://test")
        monkeypatch.setenv("AUDIT_CAPTURE_ORM_DIFFS", "false")
        config = AuditConfig()
        assert config.capture_orm_diffs is False

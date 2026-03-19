"""Tests for the public import surface."""

from fastapi_audit import ActorType, AuditConfig, AuditLog, AuditMiddleware, audit_log


def test_public_import_surface() -> None:
    """Test that all public symbols are importable from fastapi_audit."""
    assert ActorType is not None
    assert AuditConfig is not None
    assert AuditLog is not None
    assert AuditMiddleware is not None
    assert audit_log is not None


def test_actor_type_enum_values() -> None:
    """Test that ActorType enum has expected values."""
    assert ActorType.PLATFORM_ADMIN.value == "platform_admin"
    assert ActorType.TENANT_USER.value == "tenant_user"
    assert ActorType.ANONYMOUS.value == "anonymous"


def test_create_tables_exported() -> None:
    """Test that create_tables is exported."""
    from fastapi_audit import create_tables

    assert callable(create_tables)

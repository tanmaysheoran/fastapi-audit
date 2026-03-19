"""Tests for public and compatibility import paths."""


def test_public_import_surface() -> None:
    """Test the preferred public import path."""
    from fastapi_audit import ActorType, AuditConfig, AuditLog, AuditMiddleware, audit_log

    assert ActorType is not None
    assert AuditConfig is not None
    assert AuditLog is not None
    assert AuditMiddleware is not None
    assert audit_log is not None


def test_compat_import_surface() -> None:
    """Test the compatibility import path."""
    from audit import ActorType, AuditConfig, AuditLog, AuditMiddleware, audit_log

    assert ActorType is not None
    assert AuditConfig is not None
    assert AuditLog is not None
    assert AuditMiddleware is not None
    assert audit_log is not None

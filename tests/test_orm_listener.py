"""Tests for the ORM listener module."""

import pytest

from audit.orm_listener import (
    clear_audit_context,
    get_orm_diffs,
    register_listeners,
    start_audit_context,
    unregister_listeners,
)


class TestOrmListenerContext:
    """Tests for context variable management."""

    def test_start_audit_context(self) -> None:
        """Test starting a new audit context."""
        diffs = start_audit_context()
        assert diffs == []
        retrieved = get_orm_diffs()
        assert retrieved == []

    def test_get_orm_diffs_outside_context(self) -> None:
        """Test getting diffs when not in audit context."""
        clear_audit_context()
        diffs = get_orm_diffs()
        assert diffs == []

    def test_clear_audit_context(self) -> None:
        """Test clearing audit context."""
        start_audit_context()
        clear_audit_context()
        diffs = get_orm_diffs()
        assert diffs == []


class TestListenerRegistration:
    """Tests for listener registration."""

    def test_register_listeners_idempotent(self) -> None:
        """Test that registering listeners is idempotent."""
        register_listeners()
        register_listeners()

    def test_unregister_listeners(self) -> None:
        """Test unregistering listeners."""
        register_listeners()
        unregister_listeners()

    def test_reregister_after_unregister(self) -> None:
        """Test re-registering after unregistering."""
        register_listeners()
        unregister_listeners()
        register_listeners()

"""Tests for the helpers module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from audit.helpers import audit_log
from audit.models import ActorType


class TestAuditLogHelper:
    """Tests for audit_log helper function."""

    @pytest.mark.asyncio
    async def test_audit_log_basic(self) -> None:
        """Test basic audit log creation."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await audit_log(
            db=db,
            action="tenant.provisioned",
            actor_id="user123",
            actor_type="platform_admin",
            actor_email="admin@example.com",
            tenant_id="tenant-456",
            tenant_slug="example-tenant",
        )

        db.add.assert_called_once()
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_with_metadata(self) -> None:
        """Test audit log with metadata."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await audit_log(
            db=db,
            action="tenant.provisioned",
            actor_id="user123",
            actor_type="platform_admin",
            metadata={"plan": "pro", "region": "us-east"},
        )

        db.add.assert_called_once()
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_anonymous_actor(self) -> None:
        """Test audit log with anonymous actor."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await audit_log(
            db=db,
            action="system.error",
            actor_id="anonymous",
            actor_type="anonymous",
        )

        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_actor_type_string(self) -> None:
        """Test audit log accepts string actor_type."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await audit_log(
            db=db,
            action="user.login",
            actor_id="user123",
            actor_type="tenant_user",
        )

        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_actor_type_alias(self) -> None:
        """Test audit log accepts aliased string actor_type."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        await audit_log(
            db=db,
            action="user.login",
            actor_id="user123",
            actor_type="hashira",
        )

        created = db.add.call_args.args[0]
        assert created.actor_type == ActorType.PLATFORM_ADMIN

    @pytest.mark.asyncio
    async def test_audit_log_actor_type_enum(self) -> None:
        """Test audit log accepts ActorType enum."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await audit_log(
            db=db,
            action="user.login",
            actor_id="user123",
            actor_type=ActorType.TENANT_USER,
        )

        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_failure_raises(self) -> None:
        """Test that audit log failures are raised."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("DB error"))
        db.rollback = AsyncMock()

        with pytest.raises(Exception):
            await audit_log(
                db=db,
                action="test.action",
                actor_id="user123",
                actor_type="platform_admin",
            )

        db.rollback.assert_called_once()

"""Tests for the create_tables helper."""

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_audit import create_tables
from fastapi_audit.models import AuditLog


@pytest.mark.asyncio
async def test_create_tables_creates_audit_logs_table(tmp_path: pytest.TempPathFactory) -> None:
    """Test that create_tables creates the audit_logs table."""
    db_path = tmp_path / "test.db"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    await create_tables(engine)

    async with engine.begin() as conn:
        tables = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())

    assert "audit_logs" in tables
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_tables_idempotent(tmp_path: pytest.TempPathFactory) -> None:
    """Test that create_tables is safe to call twice (idempotent)."""
    db_path = tmp_path / "test.db"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    await create_tables(engine)
    await create_tables(engine)

    async with engine.begin() as conn:
        tables = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())

    assert "audit_logs" in tables
    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_logs_table_has_columns(tmp_path: pytest.TempPathFactory) -> None:
    """Test that audit_logs table has expected columns."""
    db_path = tmp_path / "test.db"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    await create_tables(engine)

    async with engine.begin() as conn:
        columns = await conn.run_sync(
            lambda sync_conn: [col["name"] for col in inspect(sync_conn).get_columns("audit_logs")]
        )

    expected_columns = {
        "id",
        "request_id",
        "actor_id",
        "actor_type",
        "actor_email",
        "tenant_id",
        "tenant_slug",
        "method",
        "path",
        "route_pattern",
        "query_params",
        "ip_address",
        "user_agent",
        "request_snapshot",
        "response_snapshot",
        "status_code",
        "response_time_ms",
        "orm_diffs",
        "action",
        "extra_metadata",
        "created_at",
    }
    assert set(columns) == expected_columns
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_tables_with_audit_log_model(tmp_path: pytest.TempPathFactory) -> None:
    """Test that create_tables uses the AuditLog model."""
    db_path = tmp_path / "test.db"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    await create_tables(engine)

    async with engine.begin() as conn:
        await conn.run_sync(AuditLog.metadata.create_all)

    await engine.dispose()

"""Async fire-and-forget writer for audit logs."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from audit.config import AuditConfig
from audit.models import AuditLog

if TYPE_CHECKING:
    pass

logger = logging.getLogger("audit")


class AuditWriter:
    """Async writer for audit logs to the audit database.

    This class manages its own engine and session factory, separate from
    the consuming application's database sessions. It provides fire-and-
    forget writing to avoid impacting request latency.
    """

    def __init__(self, config: AuditConfig) -> None:
        """Initialize the writer with configuration.

        Args:
            config: Audit configuration including control_db_url.
        """
        self._config = config
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the async engine and session factory."""
        if self._initialized:
            return

        self._engine = create_async_engine(
            self._config.control_db_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            echo=False,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self._initialized = True
        logger.debug("AuditWriter initialized")

    async def write(self, audit_data: dict[str, Any]) -> None:
        """Write audit log entry asynchronously (fire-and-forget).

        Any exceptions are caught and logged to stderr only - this method
        never raises.

        Args:
            audit_data: Dictionary of audit log fields.
        """
        if not self._initialized:
            await self.initialize()

        asyncio.create_task(self._write_async(audit_data))

    async def _write_async(self, audit_data: dict[str, Any]) -> None:
        """Internal async write implementation.

        Args:
            audit_data: Dictionary of audit log fields.
        """
        if not self._session_factory:
            return

        async with self._session_factory() as session:
            try:
                audit_log = AuditLog(**audit_data)
                session.add(audit_log)
                await session.commit()
                logger.debug(f"Audit log written: {audit_data.get('request_id')}")
            except Exception as e:
                logger.error(
                    f"Failed to write audit log: {e}",
                    exc_info=True,
                )
                try:
                    await session.rollback()
                except Exception:
                    pass

    async def close(self) -> None:
        """Close the writer's engine and cleanup resources."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            self._initialized = False
            logger.debug("AuditWriter closed")

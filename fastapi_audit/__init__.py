"""fastapi-audit: Audit logging package for FastAPI applications.

This package provides comprehensive audit logging for FastAPI applications:

- HTTP request/response capture (method, path, status, timing, IP, user agent)
- JWT-based actor identification (actor_id, actor_type, email)
- ORM-level diff tracking (INSERT, UPDATE, DELETE operations)
- Tenant-aware context support
- Sensitive data redaction
- Fire-and-forget async writes to the audit DB
- Manual audit logging for background tasks and non-HTTP contexts

Usage::

    from fastapi import FastAPI
    from fastapi_audit import AuditMiddleware, AuditConfig

    app = FastAPI()
    app.add_middleware(
        AuditMiddleware,
        config=AuditConfig(control_db_url="postgresql+asyncpg://...")
    )
"""

from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_audit.config import AuditConfig
from fastapi_audit.helpers import audit_log
from fastapi_audit.models import ActorType, AuditLog
from fastapi_audit.middleware import AuditMiddleware

__version__ = "0.1.2"

__all__ = [
    "AuditConfig",
    "AuditMiddleware",
    "ActorType",
    "AuditLog",
    "audit_log",
    "create_tables",
]


async def create_tables(engine: AsyncEngine) -> None:
    """Create the ``audit_logs`` table and its associated enum type.

    Call this once during application startup (e.g., on first deploy or in a
    migration step) to provision the audit database schema.  Only the
    ``audit_logs`` table is required; all other tables belong to your application.

    Example usage with a lifespan::

        from contextlib import asynccontextmanager
        from sqlalchemy.ext.asyncio import create_async_engine

        from fastapi import FastAPI
        from fastapi_audit import AuditMiddleware, AuditConfig, create_tables

        engine = create_async_engine("postgresql+asyncpg://user:pass@host/audit_db")

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            await create_tables(engine)
            yield
            await engine.dispose()

        app = FastAPI(lifespan=lifespan)
        app.add_middleware(
            AuditMiddleware,
            config=AuditConfig(control_db_url=str(engine.url)),
        )

    Args:
        engine: An async SQLAlchemy engine connected to the audit database.
    """
    from fastapi_audit.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

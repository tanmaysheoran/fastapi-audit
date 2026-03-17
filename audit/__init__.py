"""audit: Multi-tenant audit logging for FastAPI.

This package provides comprehensive audit logging for FastAPI applications
with multi-tenant architecture. It captures:

- HTTP request/response metadata (method, path, status, timing, etc.)
- JWT-based actor identification
- ORM-level field diffs from any database session
- Manual audit entries for background tasks

Usage:
    from fastapi import FastAPI
    from audit import AuditMiddleware, AuditConfig

    app = FastAPI()
    app.add_middleware(
        AuditMiddleware,
        config=AuditConfig(control_db_url="postgresql+asyncpg://...")
    )
"""

from audit.config import AuditConfig
from audit.helpers import audit_log
from audit.middleware import AuditMiddleware
from audit.models import ActorType, AuditLog

__version__ = "0.1.0"

__all__ = [
    "AuditConfig",
    "AuditMiddleware",
    "ActorType",
    "AuditLog",
    "audit_log",
]

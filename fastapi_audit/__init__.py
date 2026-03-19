"""Public import surface for fastapi-audit.

This package re-exports the compatibility API from ``audit`` so users can
import from the preferred public module path:

    from fastapi_audit import AuditMiddleware, AuditConfig
"""

from audit import AuditConfig, AuditLog, AuditMiddleware, ActorType, audit_log

__all__ = [
    "AuditConfig",
    "AuditMiddleware",
    "ActorType",
    "AuditLog",
    "audit_log",
]

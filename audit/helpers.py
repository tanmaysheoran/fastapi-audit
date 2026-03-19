"""Manual audit logging helper for non-HTTP contexts."""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from audit.models import DEFAULT_ACTOR_TYPE_ALIASES, ActorType, AuditLog, normalize_actor_type

logger = logging.getLogger("audit")


async def audit_log(
    db: AsyncSession,
    action: str,
    actor_id: str,
    actor_type: ActorType | str,
    actor_email: str | None = None,
    tenant_id: str | None = None,
    tenant_slug: str | None = None,
    request_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor_type_aliases: dict[str, str] | None = None,
) -> AuditLog:
    """Create an audit log entry for non-HTTP contexts.

    Use this for background tasks, provisioners, or any events outside
    the normal HTTP request lifecycle.

    Args:
        db: Async SQLAlchemy session connected to the audit DB.
        action: Action name (e.g., "tenant.provisioned", "user.created").
        actor_id: ID of the actor performing the action.
        actor_type: Type of actor (platform_admin, tenant_user, anonymous).
        actor_email: Email of the actor, if available.
        tenant_id: Associated tenant ID, if applicable.
        tenant_slug: Associated tenant slug, if applicable.
        request_id: Request ID for correlation, if applicable.
        metadata: Additional metadata to store in extra_metadata.
        actor_type_aliases: Mapping of incoming values to canonical actor types.

    Returns:
        The created AuditLog instance.
    """
    actor_type = normalize_actor_type(
        actor_type,
        actor_type_aliases or DEFAULT_ACTOR_TYPE_ALIASES,
    )

    audit_entry = AuditLog(
        request_id=request_id or "",
        actor_id=actor_id,
        actor_type=actor_type,
        actor_email=actor_email,
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
        method="",
        path="",
        ip_address="",
        status_code=0,
        response_time_ms=0,
        action=action,
        extra_metadata=metadata,
        created_at=datetime.now(timezone.utc),
    )

    try:
        db.add(audit_entry)
        await db.commit()
        await db.refresh(audit_entry)
        logger.debug(f"Manual audit log created: {action}")
    except Exception as e:
        logger.error(f"Failed to create manual audit log: {e}", exc_info=True)
        await db.rollback()
        raise

    return audit_entry

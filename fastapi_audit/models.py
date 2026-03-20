import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ActorType(enum.Enum):
    """Enum representing the type of actor performing an action."""

    PLATFORM_ADMIN = "platform_admin"
    TENANT_USER = "tenant_user"
    ANONYMOUS = "anonymous"


def normalize_actor_type(
    actor_type: ActorType | str,
    aliases: dict[str, str] | None = None,
) -> str:
    """Normalize an actor type string to a canonical string value.

    Args:
        actor_type: The actor type to normalize (enum or string).
        aliases: Optional mapping of aliases to canonical types.

    Returns:
        The canonical actor type string value, or "anonymous" for unknown types.
    """
    if isinstance(actor_type, ActorType):
        return actor_type.value

    normalized = actor_type.strip().lower()
    resolved = (aliases or {}).get(normalized, normalized)
    return resolved


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""

    pass


class AuditLog(Base):
    """Audit log model for storing HTTP request/response and ORM diffs.

    This table is stored in the audit database and provides a unified view
    of audit events across the application.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tenant_slug: Mapped[str | None] = mapped_column(String(63), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    route_pattern: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    query_params: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    response_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    orm_diffs: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    action: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, request_id={self.request_id}, actor_id={self.actor_id})>"

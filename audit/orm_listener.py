"""ORM-level diff capture through SQLAlchemy session instrumentation.

Design Rationale
================

Why class-level AsyncSession listening over engine-level:
----------------------------------------------------------
Engine-level listeners (e.g., event.listen(engine, "after_flush", ...)) only capture
events for that specific engine. In applications with multiple databases or
dynamically-created engines, we cannot register listeners on every engine upfront.

By listening on AsyncSession.sync_session_class, we intercept ALL session flushes
regardless of which engine they connect to. This enables zero-configuration operation
where the package works automatically with any database session in the application.

Why ContextVar over threading.local:
------------------------------------
threading.local does not work reliably in async contexts. Async frameworks like FastAPI
may use greenlets or run on event loops (uvloop) where thread-local storage doesn't
provide proper isolation between concurrent requests.

contextvars.ContextVar is async-native:
- Each async task gets isolated context automatically
- Values are automatically cleaned up when the context exits
- Works correctly with taskspawn, asyncio.create_task, and greenlet switches
- No risk of data leaking between concurrent async requests

This is the correct primitive for FastAPI's async-first architecture.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.inspection import inspect

if TYPE_CHECKING:
    pass

logger = logging.getLogger("audit")

# Module-level flag to ensure listeners are registered only once
_registered: bool = False

# Sentinel value to indicate no context set
_NO_DIFFS: list[dict[str, Any]] = []

# Context variable to store ORM diffs for the current request lifecycle
# This is set by the middleware at the start of each request and read at the end
_orm_diffs_ctx: ContextVar[list[dict[str, Any]]] = ContextVar(
    "orm_diffs", default=_NO_DIFFS
)


def register_listeners() -> None:
    """Register SQLAlchemy event listeners for ORM diff capture.

    This function is idempotent - calling it multiple times is safe.
    Listeners are registered at the class level on AsyncSession, ensuring
    they capture flush events from ALL session instances across the application.

    Must be called once during middleware initialization if capture_orm_diffs
    is enabled.
    """
    global _registered
    if _registered:
        return

    event.listen(
        AsyncSession.sync_session_class,
        "after_flush",
        _capture_flush,
    )
    _registered = True
    logger.debug("ORM diff listeners registered on AsyncSession")


def unregister_listeners() -> None:
    """Unregister SQLAlchemy event listeners.

    Primarily useful for testing purposes.
    """
    global _registered
    if not _registered:
        return

    event.remove(
        AsyncSession.sync_session_class,
        "after_flush",
        _capture_flush,
    )
    _registered = False
    logger.debug("ORM diff listeners unregistered from AsyncSession")


def start_audit_context() -> list[dict[str, Any]]:
    """Start a new audit context for the current request.

    Called by the middleware at the start of each request to initialize
    the context variable for storing ORM diffs.

    Returns:
        A new empty list that will accumulate diffs for this request.
    """
    diffs: list[dict[str, Any]] = []
    _orm_diffs_ctx.set(diffs)
    return diffs


def get_orm_diffs() -> list[dict[str, Any]] | None:
    """Get the accumulated ORM diffs for the current request.

    Called by the middleware at the end of each request to retrieve
    the captured diffs.

    Returns:
        List of diff dicts, or None if not in an audited request context.
    """
    return _orm_diffs_ctx.get(None)


def clear_audit_context() -> None:
    """Clear the audit context.

    Called by the middleware after writing audit logs to clean up.
    """
    _orm_diffs_ctx.set(_NO_DIFFS)


def _capture_flush(
    session: AsyncSession,
    flush_context: Any,
) -> None:
    """Capture ORM changes after a flush.

    This listener is triggered after every flush on any AsyncSession.
    It checks if we're inside an audited request context (via ContextVar)
    and captures INSERT, UPDATE, DELETE operations.

    Args:
        session: The SQLAlchemy session that was flushed.
        flush_context: The flush context (unused, required by event API).
    """
    diffs = _orm_diffs_ctx.get(None)
    if diffs is None:
        return

    try:
        for obj in session.new:
            diffs.append(_extract_insert(obj))
        for obj in session.dirty:
            diffs.append(_extract_update(session, obj))
        for obj in session.deleted:
            diffs.append(_extract_delete(obj))
    except Exception as e:
        logger.error(f"Error capturing ORM diffs: {e}", exc_info=True)


def _extract_insert(obj: Any) -> dict[str, Any]:
    """Extract diff for a newly inserted object.

    Args:
        obj: The ORM object that was inserted.

    Returns:
        Diff dict with operation, table, record_id, before (null), and after.
    """
    mapper = inspect(obj)
    table = mapper.local_table.name
    pk = _extract_pk(mapper)
    after = _extract_attributes(mapper)

    return {
        "table": table,
        "record_id": str(pk),
        "operation": "INSERT",
        "before": None,
        "after": after,
    }


def _extract_update(session: Any, obj: Any) -> dict[str, Any]:
    """Extract diff for a modified object.

    Args:
        session: The SQLAlchemy session.
        obj: The ORM object that was modified.

    Returns:
        Diff dict with operation, table, record_id, before, and after.
    """
    mapper = inspect(obj)
    table = mapper.local_table.name
    pk = _extract_pk(mapper)

    before: dict[str, Any] = {}
    after: dict[str, Any] = {}

    for attr in mapper.attrs:
        key = attr.key
        history = attr.history
        if history.has_changes():
            before[key] = history.deleted[0] if history.deleted else None
            after[key] = history.added[0] if history.added else None

    return {
        "table": table,
        "record_id": str(pk),
        "operation": "UPDATE",
        "before": before,
        "after": after,
    }


def _extract_delete(obj: Any) -> dict[str, Any]:
    """Extract diff for a deleted object.

    Args:
        obj: The ORM object that was deleted.

    Returns:
        Diff dict with operation, table, record_id, before, and after (null).
    """
    mapper = inspect(obj)
    table = mapper.local_table.name
    pk = _extract_pk(mapper)
    before = _extract_attributes(mapper)

    return {
        "table": table,
        "record_id": str(pk),
        "operation": "DELETE",
        "before": before,
        "after": None,
    }


def _extract_pk(mapper: Any) -> Any:
    """Extract the primary key value from a mapper.

    Args:
        mapper: The SQLAlchemy mapper.

    Returns:
        The primary key value.
    """
    pk_cols = mapper.primary_key
    if len(pk_cols) == 1:
        return getattr(mapper.instance, pk_cols[0].key)
    return tuple(getattr(mapper.instance, col.key) for col in pk_cols)


def _extract_attributes(mapper: Any) -> dict[str, Any]:
    """Extract all attribute values from a mapper.

    Args:
        mapper: The SQLAlchemy mapper.

    Returns:
        Dict of attribute names to values.
    """
    return {attr.key: getattr(mapper.instance, attr.key) for attr in mapper.attrs}

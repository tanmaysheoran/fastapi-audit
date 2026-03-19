"""Recursive field redaction utilities for sensitive data."""

import json
from typing import Any, TypeVar, cast

from fastapi_audit.config import AuditConfig

T = TypeVar("T")


def redact_value(value: T, redact_fields: set[str]) -> T:
    """Recursively redact sensitive fields from a value.

    Handles dicts, lists, and primitives. Matching is case-insensitive partial.

    Args:
        value: The value to redact.
        redact_fields: Set of field names to redact (lowercase).

    Returns:
        The redacted value with sensitive fields replaced by "[REDACTED]".
    """
    if isinstance(value, dict):
        return {
            k: (
                "[REDACTED]"
                if _should_redact(k, redact_fields)
                else redact_value(v, redact_fields)
            )
            for k, v in value.items()
        }  # type: ignore[return-value]
    elif isinstance(value, list):
        return [redact_value(item, redact_fields) for item in value]  # type: ignore[return-value]
    else:
        return value


def _should_redact(key: str, redact_fields: set[str]) -> bool:
    """Check if a key should be redacted.

    Uses case-insensitive partial matching - e.g., "password_hash" matches "password".

    Args:
        key: The key to check.
        redact_fields: Set of field names to redact (lowercase).

    Returns:
        True if the key matches any redact field.
    """
    key_lower = key.lower()
    return any(redact_field in key_lower for redact_field in redact_fields)


def sanitize_body(
    body: bytes | str | None,
    config: AuditConfig,
) -> dict[str, Any] | None:
    """Sanitize and parse request/response body.

    Args:
        body: Raw body bytes or string.
        config: Audit configuration with redact_fields.

    Returns:
        Sanitized JSON dict, or None if body is empty/invalid.
    """
    if not body:
        return None

    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8")

        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_raw": body[:1000] if len(body) > 1000 else body}

    return cast(dict[str, Any] | None, redact_value(parsed, config.redact_fields_lower))


def sanitize_query_params(
    query_params: dict[str, Any],
    config: AuditConfig,
) -> dict[str, Any]:
    """Sanitize query parameters.

    Args:
        query_params: Raw query parameters.
        config: Audit configuration with redact_fields.

    Returns:
        Sanitized query parameters.
    """
    return redact_value(query_params, config.redact_fields_lower)

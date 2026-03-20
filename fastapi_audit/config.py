from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from fastapi_audit.models import ActorType


DEFAULT_REDACT_FIELDS: frozenset[str] = frozenset({
    "password",
    "token",
    "secret",
    "authorization",
    "credit_card",
    "ssn",
})

DEFAULT_EXCLUDE_PATHS: frozenset[str] = frozenset({
    "/health",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
})

DEFAULT_JWT_CLAIM_MAP: dict[str, str] = {
    "actor_id": "sub",
    "actor_type": "actor_type",
    "actor_email": "email",
}


class AuditConfig(BaseSettings):
    """Configuration for the audit middleware.

    Attributes:
        control_db_url: Async PostgreSQL connection URL for the audit DB.
        redact_fields: Fields to redact (merged with defaults). Case-insensitive partial match.
        exclude_paths: URL paths to exclude from audit logging.
        actor_type_aliases: Aliases mapped to canonical actor types during parsing.
        capture_request_body: Whether to capture request body snapshots.
        capture_response_body: Whether to capture response body snapshots.
        capture_orm_diffs: Whether to capture ORM-level field diffs.
        log_anonymous: Whether to log requests without authenticated actors.
        jwt_secret: Secret for JWT signature verification. If None, tokens are decoded
            without verification (WARNING: allows forged tokens in audit logs).
        jwt_verify_signature: If True, always verify JWT signatures. If False and
            jwt_secret is set, verification is attempted. Default is False for
            backward compatibility. Set to True in production.
        trusted_proxy_depth: Number of trusted proxies in front of the application.
            Used to safely extract client IP from X-Forwarded-For. If 0, X-Forwarded-For
            is ignored entirely. If >0, counts from the right of the IP list.
        max_body_size_bytes: Maximum size of request/response body to capture.
            Bodies larger than this are truncated and marked with {"_truncated": true}.
        jwt_claim_map: Mapping of audit field names to JWT claim keys. Allows remapping
            claim names when tokens use different field names (e.g., "user_id" instead of "sub").
            Merged with defaults - only override the keys you need.
    """

    model_config = SettingsConfigDict(
        env_prefix="AUDIT_",
        extra="forbid",
    )

    control_db_url: str
    redact_fields: set[str] = set(DEFAULT_REDACT_FIELDS)
    exclude_paths: set[str] = set(DEFAULT_EXCLUDE_PATHS)
    actor_type_aliases: dict[str, str] = {}
    capture_request_body: bool = True
    capture_response_body: bool = True
    capture_orm_diffs: bool = True
    log_anonymous: bool = False
    jwt_secret: str | None = None
    jwt_verify_signature: bool = False
    trusted_proxy_depth: int = 0
    max_body_size_bytes: int = 10_000
    jwt_claim_map: dict[str, str] = {}

    @model_validator(mode="before")
    @classmethod
    def merge_redact_fields(cls, data: dict[str, object]) -> dict[str, object]:
        """Merge custom redact_fields with defaults."""
        if isinstance(data, dict) and "redact_fields" in data:
            custom_fields = data["redact_fields"]
            if isinstance(custom_fields, set):
                data["redact_fields"] = DEFAULT_REDACT_FIELDS | custom_fields
        return data

    @model_validator(mode="before")
    @classmethod
    def merge_exclude_paths(cls, data: dict[str, object]) -> dict[str, object]:
        """Merge custom exclude_paths with defaults."""
        if isinstance(data, dict) and "exclude_paths" in data:
            custom_paths = data["exclude_paths"]
            if isinstance(custom_paths, set):
                data["exclude_paths"] = DEFAULT_EXCLUDE_PATHS | custom_paths
        return data

    @model_validator(mode="before")
    @classmethod
    def normalize_actor_type_aliases(cls, data: dict[str, object]) -> dict[str, object]:
        """Normalize actor type aliases to lowercase."""
        if isinstance(data, dict) and "actor_type_aliases" in data:
            custom_aliases = data["actor_type_aliases"]
            if isinstance(custom_aliases, dict):
                data["actor_type_aliases"] = {
                    str(key).lower(): str(value).lower()
                    for key, value in custom_aliases.items()
                }
        return data

    @model_validator(mode="after")
    def merge_jwt_claim_map(self) -> "AuditConfig":
        """Merge custom jwt_claim_map with defaults."""
        merged = dict(DEFAULT_JWT_CLAIM_MAP)
        merged.update(self.jwt_claim_map)
        object.__setattr__(self, "jwt_claim_map", merged)
        return self

    def should_exclude(self, path: str) -> bool:
        """Check if the given path should be excluded from audit logging."""
        return path in self.exclude_paths

    @property
    def redact_fields_lower(self) -> set[str]:
        """Return lowercase version of redact_fields for case-insensitive matching."""
        return {f.lower() for f in self.redact_fields}

    @property
    def actor_type_aliases_lower(self) -> dict[str, str]:
        """Return a normalized alias map with lowercase keys and values."""
        return {
            key.lower(): value.lower()
            for key, value in self.actor_type_aliases.items()
        }

    @property
    def canonical_actor_types(self) -> set[str]:
        """Return the supported canonical actor type values."""
        return {actor_type.value for actor_type in ActorType}

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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


class AuditConfig(BaseSettings):
    """Configuration for the audit middleware.

    Attributes:
        control_db_url: Async PostgreSQL connection URL for the control DB.
        redact_fields: Fields to redact (merged with defaults). Case-insensitive partial match.
        exclude_paths: URL paths to exclude from audit logging.
        capture_request_body: Whether to capture request body snapshots.
        capture_response_body: Whether to capture response body snapshots.
        capture_orm_diffs: Whether to capture ORM-level field diffs.
        log_anonymous: Whether to log requests without authenticated actors.
    """

    model_config = SettingsConfigDict(
        env_prefix="AUDIT_",
        extra="forbid",
    )

    control_db_url: str
    redact_fields: set[str] = set(DEFAULT_REDACT_FIELDS)
    exclude_paths: set[str] = set(DEFAULT_EXCLUDE_PATHS)
    capture_request_body: bool = True
    capture_response_body: bool = True
    capture_orm_diffs: bool = True
    log_anonymous: bool = False

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

    def should_exclude(self, path: str) -> bool:
        """Check if the given path should be excluded from audit logging."""
        return path in self.exclude_paths

    @property
    def redact_fields_lower(self) -> set[str]:
        """Return lowercase version of redact_fields for case-insensitive matching."""
        return {f.lower() for f in self.redact_fields}

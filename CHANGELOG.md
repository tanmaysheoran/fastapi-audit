# Changelog

## [0.2.0] - 2026-03-20

### Security

- **JWT Signature Verification Warning**: Added `jwt_secret` and `jwt_verify_signature` config options. When signature verification is disabled, a warning is logged at startup to alert developers of the security trade-off. (#1)

- **X-Forwarded-For Spoofing Prevention**: Added `trusted_proxy_depth` config option. When set to 0, X-Forwarded-For is ignored entirely and only `request.client.host` is used. When >0, the client IP is extracted from the correct position in the X-Forwarded-For list. (#2)

- **ORM Diffs Sanitization**: ORM diffs (INSERT/UPDATE/DELETE) now have sensitive fields redacted just like HTTP bodies. The `redact_fields` config option applies to all audit data. (#4)

### Features

- **Response Body Capture**: The middleware now captures and sanitizes response bodies. Bodies larger than `max_body_size_bytes` (default: 10,000) are truncated with a `_truncated: true` flag. (#3)

- **Streaming Response Support**: Replaced `BaseHTTPMiddleware` with a raw ASGI middleware class that properly supports streaming responses (SSE, WebSockets, large file streaming). Non-HTTP scope types (websocket, lifespan) pass through untouched. (#6)

- **Actor Type Extensibility**: Changed `actor_type` column from PostgreSQL ENUM to String(50). The `ActorType` enum remains as a set of well-known constants, but custom types can be used without migrations. The `normalize_actor_type` function now returns strings. (#7)

- **Configurable JWT Claim Mapping**: Added `jwt_claim_map` config option that maps audit field names (`actor_id`, `actor_type`, `actor_email`) to custom JWT claim keys. Allows tokens using different claim names (e.g., `user_id`, `role`, `mail`) to work without forking. (#8)

### Bug Fixes

- **Deprecated datetime.utcnow()**: Replaced `datetime.utcnow` with `datetime.now(timezone.utc)` to address Python 3.12+ deprecation warnings. (#5)

### Migration Notes

- **Actor Type**: Existing deployments should change the `actor_type` column from the `actor_type_enum` PostgreSQL enum to `VARCHAR(50)`. See `MIGRATION.md` for details.

- **JWT Configuration**: For production, set `jwt_secret` and `jwt_verify_signature=True` to enable proper JWT signature verification.

- **Proxy Configuration**: If behind a trusted proxy, set `trusted_proxy_depth` to the number of proxies in front of your application.

- **Custom JWT Claims**: If your tokens use non-standard claim names, set `jwt_claim_map` in your config:
  ```python
  AuditConfig(
      control_db_url="...",
      jwt_claim_map={"actor_id": "user_id", "actor_type": "role"},
  )
  ```

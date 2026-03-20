# Migration Guide

## Upgrading to 0.2.0

### Actor Type Column Change

In version 0.2.0, the `actor_type` column in the `audit_logs` table changed from a PostgreSQL ENUM (`actor_type_enum`) to a VARCHAR(50). This change allows custom actor types without requiring migrations.

#### For New Deployments

No changes needed - the table will be created with the correct schema.

#### For Existing Deployments

If you have an existing `audit_logs` table, you need to migrate the `actor_type` column:

```sql
-- 1. Add a temporary column
ALTER TABLE audit_logs ADD COLUMN actor_type_temp VARCHAR(50);

-- 2. Copy data from the enum column
UPDATE audit_logs SET actor_type_temp = actor_type::TEXT;

-- 3. Drop the old enum column (requires CASCADE if dependent objects exist)
ALTER TABLE audit_logs DROP COLUMN actor_type CASCADE;

-- 4. Rename the temporary column
ALTER TABLE audit_logs RENAME COLUMN actor_type_temp TO actor_type;

-- 5. Drop the old enum type (optional, if no longer needed)
DROP TYPE actor_type_enum;
```

### JWT Configuration

For production deployments, it is now recommended to enable JWT signature verification:

```python
config = AuditConfig(
    control_db_url="postgresql+asyncpg://...",
    jwt_secret="your-secret-key",
    jwt_verify_signature=True,  # Enable signature verification
)
```

### Proxy Configuration

If your application is behind a trusted proxy, configure the proxy depth:

```python
config = AuditConfig(
    control_db_url="postgresql+asyncpg://...",
    trusted_proxy_depth=1,  # Number of trusted proxies in front of your app
)
```

### Response Body Truncation

Response bodies larger than 10,000 bytes are now truncated with a `_truncated: true` flag. To customize this limit:

```python
config = AuditConfig(
    control_db_url="postgresql+asyncpg://...",
    max_body_size_bytes=50_000,  # Custom limit
)
```

### Streaming Response Support

The middleware now properly handles streaming responses (SSE, WebSockets, file downloads). This is a breaking change only if you were relying on `BaseHTTPMiddleware`-specific behavior, which is unlikely.

### Custom JWT Claim Names

If your JWT tokens use non-standard claim names for actor identification, you can now remap them:

```python
config = AuditConfig(
    control_db_url="postgresql+asyncpg://...",
    jwt_claim_map={
        "actor_id": "user_id",     # default: "sub"
        "actor_type": "role",       # default: "actor_type"
        "actor_email": "mail",      # default: "email"
    },
)
```

You can override just the claims you need - the others will use defaults.

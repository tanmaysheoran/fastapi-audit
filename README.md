# audit

Multi-tenant audit logging package for FastAPI applications.

## Features

- **HTTP Request/Response Capture**: Logs method, path, status code, response time, IP, user agent
- **JWT-based Actor Identification**: Extracts actor ID, type, and email from JWT tokens
- **ORM-level Diff Tracking**: Captures INSERT, UPDATE, DELETE operations across all databases
- **Multi-tenant Support**: Works with subdomain-based multi-tenancy architecture
- **Sensitive Data Redaction**: Automatic redaction of passwords, tokens, secrets, etc.
- **Fire-and-Forget Writes**: Non-blocking audit writes to avoid request latency impact
- **Manual Audit Logging**: Support for background tasks and non-HTTP contexts

## Installation

```bash
pip install audit
```

## Quick Start

```python
from fastapi import FastAPI
from audit import AuditMiddleware, AuditConfig

app = FastAPI()

app.add_middleware(
    AuditMiddleware,
    config=AuditConfig(
        control_db_url="postgresql+asyncpg://user:pass@localhost/audit_db"
    )
)
```

## Configuration

```python
from audit import AuditConfig

config = AuditConfig(
    # Required: Connection URL for the control database
    control_db_url="postgresql+asyncpg://user:pass@localhost/audit_db",
    
    # Optional: Fields to redact (merged with defaults)
    redact_fields={"password", "token", "secret", "custom_field"},
    
    # Optional: Paths to exclude from audit logging
    exclude_paths={"/health", "/metrics"},
    
    # Optional: Capture request/response bodies
    capture_request_body=True,
    capture_response_body=True,
    
    # Optional: Enable ORM diff capture
    capture_orm_diffs=True,
    
    # Optional: Log requests without authenticated actors
    log_anonymous=False,
)
```

## Database Migration

Create the `audit_logs` table in your control database:

```bash
# Using Alembic
alembic upgrade head

# Or run the SQL migration directly
# See migrations/versions/001_create_audit_logs.py
```

## Tenant Context

The middleware expects your tenant resolution middleware to set:

```python
# Example: In your TenantResolutionMiddleware
request.state.tenant = Tenant(tenant_id="...", tenant_slug="acme-corp")
```

The `tenant` object should have `tenant_id` and `tenant_slug` attributes.

## JWT Token Requirements

The middleware extracts actor information from JWT tokens in the `Authorization` header. Expected JWT claims:

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | User ID |
| `actor_type` | No | `hashira`, `tenant_user`, or `anonymous` (default) |
| `email` | No | User email address |

Example JWT payload:
```json
{
  "sub": "user-123",
  "actor_type": "tenant_user",
  "email": "user@example.com"
}
```

## Manual Audit Logging

For background tasks or events outside the HTTP lifecycle:

```python
from audit import audit_log, ActorType
from sqlalchemy.ext.asyncio import AsyncSession

async def provision_tenant(db: AsyncSession):
    await audit_log(
        db=db,
        action="tenant.provisioned",
        actor_id="admin-user-id",
        actor_type=ActorType.HASHIRA,
        actor_email="admin@example.com",
        tenant_id="tenant-uuid",
        tenant_slug="acme-corp",
        metadata={"plan": "pro", "region": "us-east"}
    )
```

## Environment Variables

All configuration can be set via environment variables with the `AUDIT_` prefix:

```bash
export AUDIT_CONTROL_DB_URL="postgresql+asyncpg://..."
export AUDIT_CAPTURE_ORM_DIFFS="true"
export AUDIT_LOG_ANONYMOUS="false"
```

## Architecture

### HTTP Layer

The middleware intercepts all requests and captures:
- Request metadata (method, path, query params)
- Response metadata (status code, response time)
- Actor information from JWT
- Tenant context from `request.state.tenant`

### ORM Layer

SQLAlchemy event listeners capture database changes:
- Class-level listeners on `AsyncSession` work with all databases
- Context variables isolate diffs per-request
- Supports INSERT, UPDATE, and DELETE operations

### Storage

All audit logs are written to a single `audit_logs` table in the control database, providing a unified view across all tenants.

## Requirements

- Python 3.11+
- FastAPI / Starlette
- SQLAlchemy 2.0+ with async support
- Pydantic v2
- asyncpg

## License

MIT

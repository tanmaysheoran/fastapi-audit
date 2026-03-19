# fastapi-audit

[![PyPI version](https://img.shields.io/pypi/v/fastapi-audit.svg)](https://pypi.org/project/fastapi-audit/)
[![Python versions](https://img.shields.io/pypi/pyversions/fastapi-audit.svg)](https://pypi.org/project/fastapi-audit/)
[![License](https://img.shields.io/pypi/l/fastapi-audit.svg)](https://pypi.org/project/fastapi-audit/)

Audit logging package for FastAPI applications.

## Features

- **HTTP Request/Response Capture**: Logs method, path, status code, response time, IP, and user agent
- **JWT-based Actor Identification**: Extracts actor ID, type, and email from JWT tokens
- **ORM-level Diff Tracking**: Captures INSERT, UPDATE, and DELETE operations across application sessions
- **Tenant-Aware Context Support**: Works with application-provided tenant context
- **Sensitive Data Redaction**: Automatically redacts passwords, tokens, secrets, and similar fields
- **Fire-and-Forget Writes**: Writes audit records asynchronously to avoid adding request latency
- **Manual Audit Logging**: Supports background tasks and non-HTTP contexts

## Installation

### From PyPI

```bash
# Core package (requires asyncpg for PostgreSQL)
pip install fastapi-audit[asyncpg]
```

### Local Development

```bash
pip install -e /path/to/audit[asyncpg]
```

### Database Driver

Only **PostgreSQL with asyncpg** is tested and supported at this time. Install it via the `[asyncpg]` extra:

```bash
pip install fastapi-audit[asyncpg]
```

## Quick Start

```python
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi import FastAPI
from fastapi_audit import AuditMiddleware, AuditConfig, create_tables

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/audit_db")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables(engine)
    yield
    await engine.dispose()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    AuditMiddleware,
    config=AuditConfig(control_db_url=str(engine.url))
)
```

## Database Setup

Before using the middleware, provision the `audit_logs` table in your audit database:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from fastapi_audit import create_tables

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/audit_db")
await create_tables(engine)
```

The `create_tables()` helper creates the `audit_logs` table and its associated enum type. Call it once during deployment or as part of a migration step.

## Configuration

```python
from fastapi_audit import AuditConfig

config = AuditConfig(
    # Required: Connection URL for the audit database
    control_db_url="postgresql+asyncpg://user:pass@localhost/audit_db",

    # Optional: Fields to redact (merged with defaults)
    redact_fields={"password", "token", "secret", "custom_field"},

    # Optional: Paths to exclude from audit logging
    exclude_paths={"/health", "/metrics"},

    # Optional: Map incoming actor_type values to canonical public values
    actor_type_aliases={"ops_admin": "platform_admin"},

    # Optional: Capture request/response bodies
    capture_request_body=True,
    capture_response_body=True,

    # Optional: Enable ORM diff capture
    capture_orm_diffs=True,

    # Optional: Log requests without authenticated actors
    log_anonymous=False,
)
```

## Tenant Context

If your application is tenant-aware, the middleware can read tenant context from:

```python
# Example: in your own tenant-resolution middleware
request.state.tenant = Tenant(tenant_id="...", tenant_slug="example-tenant")
```

The `tenant` object should have `tenant_id` and `tenant_slug` attributes.

## JWT Token Requirements

The middleware extracts actor information from JWT tokens in the `Authorization` header.
Expected JWT claims:

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | User ID |
| `actor_type` | No | `platform_admin`, `tenant_user`, or `anonymous` (default) |
| `email` | No | User email address |

Example JWT payload:

```json
{
  "sub": "user-123",
  "actor_type": "platform_admin",
  "email": "user@example.com"
}
```

Organization-specific actor types can be mapped to canonical public values via
`AuditConfig.actor_type_aliases`.

## Manual Audit Logging

For background tasks or events outside the HTTP lifecycle:

```python
from fastapi_audit import audit_log, ActorType
from sqlalchemy.ext.asyncio import AsyncSession

async def provision_tenant(db: AsyncSession):
    await audit_log(
        db=db,
        action="tenant.provisioned",
        actor_id="admin-user-id",
        actor_type=ActorType.PLATFORM_ADMIN,
        actor_email="admin@example.com",
        tenant_id="tenant-uuid",
        tenant_slug="example-tenant",
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

The middleware intercepts requests and captures:

- Request metadata such as method, path, and query params
- Response metadata such as status code and response time
- Actor information from JWT claims
- Optional tenant context from `request.state.tenant`

### ORM Layer

SQLAlchemy event listeners capture database changes:

- Class-level listeners on `AsyncSession` work across application sessions
- Context variables isolate diffs per request
- INSERT, UPDATE, and DELETE operations are recorded

### Storage

All audit logs are written to a single `audit_logs` table in the audit database,
providing a unified view of application activity.

## Requirements

- Python 3.11+
- FastAPI / Starlette
- SQLAlchemy 2.0+ with async support
- Pydantic v2
- asyncpg (via `pip install fastapi-audit[asyncpg]`)

## License

MIT

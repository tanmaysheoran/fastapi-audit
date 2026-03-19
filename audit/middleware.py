"""FastAPI middleware for audit logging."""

import logging
import time
import uuid
from typing import Any, Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from audit.config import AuditConfig
from audit.jwt_parser import extract_actor, extract_token_from_header
from audit.models import ActorType
from audit.orm_listener import (
    clear_audit_context,
    get_orm_diffs,
    register_listeners,
    start_audit_context,
)
from audit.sanitizer import sanitize_body, sanitize_query_params
from audit.writer import AuditWriter

logger = logging.getLogger("audit")


class AuditMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for comprehensive audit logging.

    Captures HTTP request/response metadata and ORM-level field diffs,
    writing to a centralized audit_logs table in the audit database.

    The middleware is non-blocking - audit writes are fire-and-forget
    to avoid impacting request latency.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: AuditConfig,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            config: Audit configuration.
        """
        super().__init__(app)
        self._config = config
        self._writer = AuditWriter(config)
        self._initialized = False

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process the request and capture audit data.

        Args:
            request: The incoming request.
            call_next: The next middleware or route handler.

        Returns:
            The response from the application.
        """
        if not self._initialized:
            await self._writer.initialize()
            if self._config.capture_orm_diffs:
                register_listeners()
            self._initialized = True

        if self._config.should_exclude(request.url.path):
            return await call_next(request)

        start_time = time.perf_counter()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        actor = self._extract_actor(request)

        if not self._config.log_anonymous and actor is None:
            return await call_next(request)

        if self._config.capture_orm_diffs:
            start_audit_context()

        request_body = None
        if self._config.capture_request_body:
            request_body = await self._capture_request_body(request)

        response = await call_next(request)

        response_body = None
        if self._config.capture_response_body:
            response_body = await self._capture_response_body(response)

        response_time_ms = int((time.perf_counter() - start_time) * 1000)

        audit_data = self._build_audit_data(
            request=request,
            request_id=request_id,
            actor=actor,
            request_body=request_body,
            response=response,
            response_body=response_body,
            response_time_ms=response_time_ms,
        )

        await self._writer.write(audit_data)

        if self._config.capture_orm_diffs:
            clear_audit_context()

        return response

    def _extract_actor(self, request: Request) -> dict[str, Any] | None:
        """Extract actor information from JWT.

        Args:
            request: The incoming request.

        Returns:
            Actor dict with actor_id, actor_type, actor_email, or None.
        """
        auth_header = request.headers.get("Authorization")
        token = extract_token_from_header(auth_header)

        if not token:
            return None

        actor = extract_actor(token, actor_type_aliases=self._config.actor_type_aliases_lower)
        if actor:
            return {
                "actor_id": actor.actor_id,
                "actor_type": actor.actor_type,
                "actor_email": actor.email,
            }
        return None

    async def _capture_request_body(self, request: Request) -> dict[str, Any] | None:
        """Capture and sanitize request body.

        Args:
            request: The incoming request.

        Returns:
            Sanitized request body, or None.
        """
        try:
            body = await request.body()
            return sanitize_body(body, self._config)
        except Exception as e:
            logger.warning(f"Failed to capture request body: {e}")
            return None

    async def _capture_response_body(
        self,
        response: Response,
    ) -> dict[str, Any] | None:
        """Capture and sanitize response body.

        Note: Starlette responses may not have body accessible after creation.
        This is a best-effort capture.

        Args:
            response: The response.

        Returns:
            Sanitized response body, or None.
        """
        return None

    def _build_audit_data(
        self,
        request: Request,
        request_id: str,
        actor: dict[str, Any] | None,
        request_body: dict[str, Any] | None,
        response: Response,
        response_body: dict[str, Any] | None,
        response_time_ms: int,
    ) -> dict[str, Any]:
        """Build the complete audit data dict.

        Args:
            request: The incoming request.
            request_id: Unique request identifier.
            actor: Actor info from JWT, or None.
            request_body: Sanitized request body.
            response: The response.
            response_body: Sanitized response body.
            response_time_ms: Response time in milliseconds.

        Returns:
            Complete audit data dict for writing to DB.
        """
        tenant = getattr(request.state, "tenant", None)

        if actor:
            actor_id = actor["actor_id"]
            actor_type = actor["actor_type"]
            actor_email = actor["actor_email"]
        else:
            actor_id = "anonymous"
            actor_type = ActorType.ANONYMOUS
            actor_email = None

        query_params = None
        if request.query_params:
            query_params = sanitize_query_params(
                dict(request.query_params),
                self._config,
            )

        orm_diffs = None
        if self._config.capture_orm_diffs:
            diffs = get_orm_diffs()
            if diffs:
                orm_diffs = diffs

        route_pattern = None
        if hasattr(request, "route") and request.route:
            route_pattern = str(request.route.path)

        return {
            "request_id": request_id,
            "actor_id": actor_id,
            "actor_type": actor_type,
            "actor_email": actor_email,
            "tenant_id": getattr(tenant, "tenant_id", None) if tenant else None,
            "tenant_slug": getattr(tenant, "tenant_slug", None) if tenant else None,
            "method": request.method,
            "path": str(request.url.path),
            "route_pattern": route_pattern,
            "query_params": query_params,
            "ip_address": self._get_client_ip(request),
            "user_agent": request.headers.get("User-Agent"),
            "request_snapshot": request_body,
            "response_snapshot": response_body,
            "status_code": response.status_code,
            "response_time_ms": response_time_ms,
            "orm_diffs": orm_diffs,
        }

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.

        Handles X-Forwarded-For header for proxied requests.

        Args:
            request: The incoming request.

        Returns:
            Client IP address string.
        """
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

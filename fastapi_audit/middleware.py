"""FastAPI middleware for audit logging."""

import json
import logging
import time
import uuid
from typing import Any

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastapi_audit.config import AuditConfig
from fastapi_audit.jwt_parser import extract_actor, extract_token_from_header
from fastapi_audit.orm_listener import (
    clear_audit_context,
    get_orm_diffs,
    register_listeners,
    set_audit_config,
    start_audit_context,
)
from fastapi_audit.sanitizer import redact_value, sanitize_body
from fastapi_audit.writer import AuditWriter

logger = logging.getLogger("audit")


class AuditMiddleware:
    """FastAPI middleware for comprehensive audit logging.

    Captures HTTP request/response metadata and ORM-level field diffs,
    writing to a centralized audit_logs table in the audit database.

    The middleware is non-blocking - audit writes are fire-and-forget
    to avoid impacting request latency.

    This is a raw ASGI middleware (not BaseHTTPMiddleware) to support
    streaming responses properly.
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
        self.app = app
        self._config = config
        self._writer: AuditWriter | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize async resources (called on first request)."""
        if not self._initialized:
            self._writer = AuditWriter(self._config)
            await self._writer.initialize()
            if self._config.capture_orm_diffs:
                register_listeners()
                set_audit_config(self._config)
            self._initialized = True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI interface method.

        Args:
            scope: The ASGI scope.
            receive: The ASGI receive function.
            send: The ASGI send function.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if not self._initialized:
            await self.initialize()

        if self._should_exclude_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        await self._handle_http_request(scope, receive, send)

    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded."""
        return self._config.should_exclude(path)

    async def _handle_http_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Handle an HTTP request with full audit logging."""
        start_time = time.perf_counter()
        request_id = ""
        actor: dict[str, Any] | None = None
        request_body: dict[str, Any] | None = None
        response_status: int = 0
        response_headers: list[tuple[bytes, bytes]] = []
        response_body_parts: list[bytes] = []
        orm_diffs: list[dict[str, Any]] | None = None

        client_ip: str | None = None

        async def audit_send(message: Message) -> None:
            """Intercept send to capture response data."""
            nonlocal response_status, response_headers, response_body_parts

            if message["type"] == "http.response.start":
                response_status = message["status"]
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    response_body_parts.append(body)

            await send(message)

        try:
            headers = Headers(scope=scope)
            request_id = headers.get("X-Request-ID", str(uuid.uuid4()))

            client_ip = self._get_client_ip(scope, headers)

            actor = self._extract_actor(headers)

            if not self._config.log_anonymous and actor is None:
                await self._pass_through(scope, receive, audit_send)
                return

            if self._config.capture_orm_diffs:
                start_audit_context()

            request_body_bytes = await self._get_request_body(scope, receive)

            if self._config.capture_request_body and request_body_bytes:
                request_body = sanitize_body(request_body_bytes, self._config)

            patched_receive = scope.get("_patched_receive", receive)
            await self._pass_through(scope, patched_receive, audit_send)

        except Exception as e:
            logger.error(f"Error in audit middleware: {e}", exc_info=True)
            patched_receive = scope.get("_patched_receive", receive)
            await self._pass_through(scope, patched_receive, send)
            return

        finally:
            if self._config.capture_orm_diffs:
                orm_diffs = get_orm_diffs()
                clear_audit_context()

        response_time_ms = int((time.perf_counter() - start_time) * 1000)

        response_body = None
        if self._config.capture_response_body and response_body_parts:
            response_body = self._process_response_body(b"".join(response_body_parts))

        audit_data = self._build_audit_data(
            method=scope.get("method", "UNKNOWN"),
            path=scope.get("path", ""),
            route_pattern=scope.get("route", {}).get("path") if isinstance(scope.get("route"), dict) else getattr(scope.get("route"), "path", None),
            query_string=scope.get("query_string", b"").decode("utf-8"),
            request_id=request_id,
            actor=actor,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_time_ms=response_time_ms,
            client_ip=client_ip,
            headers=headers,
            orm_diffs=orm_diffs,
        )

        if self._writer:
            await self._writer.write(audit_data)

    async def _pass_through(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Pass request through to the app without audit."""
        await self.app(scope, receive, send)

    async def _get_request_body(self, scope: Scope, receive: Receive) -> bytes | None:
        """Get and buffer the request body.

        Note: This consumes the request body stream. After calling this,
        the body is not available to the app. For full request body capture,
        the body is read here and re-built into a fake stream for the app.
        """
        body = b""
        if self._config.capture_request_body:
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                while more_body:
                    message = await receive()
                    if message["type"] == "http.request":
                        body += message.get("body", b"")
                        more_body = message.get("more_body", False)

            received_message = {"type": "http.request", "body": body, "more_body": False}
            _consumed = False

            async def replay_receive() -> Message:
                nonlocal _consumed
                if not _consumed:
                    _consumed = True
                    return received_message
                return await receive()

            scope["_patched_receive"] = replay_receive

        return body if body else None

    def _get_client_ip(self, scope: Scope, headers: Headers) -> str:
        """Extract client IP address respecting trusted proxy depth.

        Args:
            scope: The ASGI scope containing client info.
            headers: Request headers.

        Returns:
            Client IP address string.
        """
        client_from_scope = scope.get("client")
        direct_client_ip = client_from_scope[0] if client_from_scope else None

        if self._config.trusted_proxy_depth == 0:
            return direct_client_ip or "unknown"

        forwarded_for = headers.get("X-Forwarded-For")
        if forwarded_for:
            ips = [ip.strip() for ip in forwarded_for.split(",")]
            depth = self._config.trusted_proxy_depth
            if len(ips) >= depth:
                return ips[-depth]
            return direct_client_ip or "unknown"

        return direct_client_ip or "unknown"

    def _extract_actor(self, headers: Headers) -> dict[str, Any] | None:
        """Extract actor information from JWT.

        Args:
            headers: Request headers.

        Returns:
            Actor dict with actor_id, actor_type, actor_email, or None.
        """
        auth_header = headers.get("Authorization")
        token = extract_token_from_header(auth_header)

        if not token:
            return None

        actor = extract_actor(
            token,
            secret=self._config.jwt_secret or "",
            actor_type_aliases=self._config.actor_type_aliases_lower,
            verify_signature=self._config.jwt_verify_signature,
            claim_map=self._config.jwt_claim_map,
        )
        if actor:
            return {
                "actor_id": actor.actor_id,
                "actor_type": actor.actor_type,
                "actor_email": actor.email,
            }
        return None

    def _process_response_body(
        self,
        body: bytes,
    ) -> dict[str, Any] | None:
        """Process and sanitize response body.

        Args:
            body: Raw response body bytes.

        Returns:
            Sanitized response body dict, or None if empty/invalid.
        """
        if not body:
            return None

        max_size = self._config.max_body_size_bytes
        original_size = len(body)
        needs_truncation = original_size > max_size

        try:
            if needs_truncation:
                truncated_body = body[:max_size]
                parsed = json.loads(truncated_body.decode("utf-8"))
                result: dict[str, Any] = redact_value(parsed, self._config.redact_fields_lower)
                result["_truncated"] = True
            else:
                parsed = json.loads(body.decode("utf-8"))
                result = redact_value(parsed, self._config.redact_fields_lower)
        except (json.JSONDecodeError, UnicodeDecodeError):
            truncated_str = body.decode("utf-8", errors="replace")
            if needs_truncation:
                truncated_str = truncated_str[:max_size] + "..."
                result = {"_raw": truncated_str, "_truncated": True}
            else:
                result = {"_raw": truncated_str[:1000]}
            return result

        return result

    def _build_audit_data(
        self,
        method: str,
        path: str,
        route_pattern: str | None,
        query_string: str,
        request_id: str,
        actor: dict[str, Any] | None,
        request_body: dict[str, Any] | None,
        response_status: int,
        response_headers: list[tuple[bytes, bytes]],
        response_body: dict[str, Any] | None,
        response_time_ms: int,
        client_ip: str | None,
        headers: Headers,
        orm_diffs: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Build the complete audit data dict.

        Args:
            method: HTTP method.
            path: Request path.
            route_pattern: Route pattern if available.
            query_string: Raw query string.
            request_id: Unique request identifier.
            actor: Actor info from JWT, or None.
            request_body: Sanitized request body.
            response_status: HTTP status code.
            response_headers: Response headers.
            response_body: Sanitized response body.
            response_time_ms: Response time in milliseconds.
            client_ip: Client IP address.
            headers: Request headers.
            orm_diffs: ORM diffs if capture enabled.

        Returns:
            Complete audit data dict for writing to DB.
        """
        if actor:
            actor_id = actor["actor_id"]
            actor_type = actor["actor_type"]
            actor_email = actor["actor_email"]
        else:
            actor_id = "anonymous"
            actor_type = "anonymous"
            actor_email = None

        query_params: dict[str, Any] | None = None
        if query_string:
            params: list[tuple[str, str]] = []
            for pair in query_string.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params.append((k, v))
                elif pair:
                    params.append((pair, ""))
            if params:
                query_params = redact_value(dict(params), self._config.redact_fields_lower)

        return {
            "request_id": request_id,
            "actor_id": actor_id,
            "actor_type": actor_type,
            "actor_email": actor_email,
            "tenant_id": None,
            "tenant_slug": None,
            "method": method,
            "path": path,
            "route_pattern": route_pattern,
            "query_params": query_params,
            "ip_address": client_ip or "unknown",
            "user_agent": headers.get("User-Agent"),
            "request_snapshot": request_body,
            "response_snapshot": response_body,
            "status_code": response_status,
            "response_time_ms": response_time_ms,
            "orm_diffs": orm_diffs,
        }

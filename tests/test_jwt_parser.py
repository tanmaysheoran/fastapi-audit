"""Tests for the JWT parser module."""

import pytest
from jose import jwt

from audit.jwt_parser import extract_actor, extract_token_from_header
from audit.models import ActorType


class TestExtractTokenFromHeader:
    """Tests for extract_token_from_header function."""

    def test_extract_bearer_token(self) -> None:
        """Test extracting Bearer token."""
        header = "Bearer abc123token"
        result = extract_token_from_header(header)
        assert result == "abc123token"

    def test_extract_bearer_case_insensitive(self) -> None:
        """Test that matching is case-insensitive."""
        header = "bearer abc123token"
        result = extract_token_from_header(header)
        assert result == "abc123token"

    def test_extract_no_header(self) -> None:
        """Test with no header."""
        assert extract_token_from_header(None) is None

    def test_extract_invalid_format(self) -> None:
        """Test with invalid format."""
        assert extract_token_from_header("Basic abc123") is None
        assert extract_token_from_header("Bearer") is None


class TestExtractActor:
    """Tests for extract_actor function."""

    def _create_token(
        self,
        sub: str,
        actor_type: str = "tenant_user",
        email: str | None = None,
    ) -> str:
        """Create a JWT token for testing."""
        payload = {"sub": sub, "actor_type": actor_type}
        if email:
            payload["email"] = email
        return jwt.encode(payload, "secret", algorithm="HS256")

    def test_extract_actor_with_valid_token(self) -> None:
        """Test extracting actor from valid token."""
        token = self._create_token("user123", "tenant_user", "user@example.com")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_id == "user123"
        assert actor.actor_type == ActorType.TENANT_USER
        assert actor.email == "user@example.com"

    def test_extract_actor_platform_admin_type(self) -> None:
        """Test extracting canonical platform_admin actor type."""
        token = self._create_token("admin1", "platform_admin", "admin@example.com")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_id == "admin1"
        assert actor.actor_type == ActorType.PLATFORM_ADMIN

    def test_extract_actor_hashira_alias(self) -> None:
        """Test extracting legacy hashira actor type via alias mapping."""
        token = self._create_token("admin1", "hashira", "admin@example.com")
        actor = extract_actor(
            token,
            secret="secret",
            actor_type_aliases={"hashira": "platform_admin"},
        )
        assert actor is not None
        assert actor.actor_type == ActorType.PLATFORM_ADMIN

    def test_extract_actor_anonymous_type(self) -> None:
        """Test extracting anonymous actor type."""
        token = self._create_token("anon", "anonymous")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_type == ActorType.ANONYMOUS

    def test_extract_actor_invalid_type(self) -> None:
        """Test with invalid actor_type falls back to anonymous."""
        token = self._create_token("user1", "invalid_type")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_type == ActorType.ANONYMOUS

    def test_extract_actor_no_sub(self) -> None:
        """Test with token missing sub claim."""
        token = jwt.encode({"actor_type": "platform_admin"}, "secret", algorithm="HS256")
        actor = extract_actor(token, secret="secret")
        assert actor is None

    def test_extract_actor_no_token(self) -> None:
        """Test with None token."""
        assert extract_actor(None, secret="secret") is None

    def test_extract_actor_decode_only(self) -> None:
        """Test decode-only mode (no verification)."""
        token = self._create_token("user123", "tenant_user")
        actor = extract_actor(token, secret="")  # Empty secret = decode only
        assert actor is not None
        assert actor.actor_id == "user123"

    def test_extract_actor_strips_bearer(self) -> None:
        """Test that Bearer prefix is stripped."""
        token = "Bearer " + self._create_token("user123", "tenant_user")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_id == "user123"

    def test_extract_actor_invalid_token(self) -> None:
        """Test with invalid token."""
        assert extract_actor("invalid.token.here", secret="secret") is None

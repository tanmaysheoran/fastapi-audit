"""Tests for the JWT parser module."""

from jose import jwt

from fastapi_audit.jwt_parser import extract_actor, extract_token_from_header
from fastapi_audit.models import ActorType


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
        assert actor.actor_type == "tenant_user"
        assert actor.email == "user@example.com"

    def test_extract_actor_platform_admin_type(self) -> None:
        """Test extracting canonical platform_admin actor type."""
        token = self._create_token("admin1", "platform_admin", "admin@example.com")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_id == "admin1"
        assert actor.actor_type == "platform_admin"

    def test_extract_actor_anonymous_type(self) -> None:
        """Test extracting anonymous actor type."""
        token = self._create_token("anon", "anonymous")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_type == "anonymous"

    def test_extract_actor_invalid_type_defaults_to_anonymous(self) -> None:
        """Test with invalid actor_type falls back to anonymous."""
        token = self._create_token("user1", "invalid_type")
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_type == "anonymous"

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
        actor = extract_actor(token, secret="")
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

    def test_extract_actor_with_alias(self) -> None:
        """Test extracting actor with custom alias mapping."""
        token = self._create_token("admin1", "ops_admin", "admin@example.com")
        actor = extract_actor(
            token,
            secret="secret",
            actor_type_aliases={"ops_admin": "platform_admin"},
        )
        assert actor is not None
        assert actor.actor_type == "platform_admin"


class TestExtractActorClaimMapping:
    """Tests for extract_actor with claim_map parameter."""

    def _create_custom_token(
        self,
        user_id: str,
        role: str = "tenant_user",
        mail: str | None = None,
    ) -> str:
        """Create a JWT token with custom claim names."""
        payload = {"user_id": user_id, "role": role}
        if mail:
            payload["mail"] = mail
        return jwt.encode(payload, "secret", algorithm="HS256")

    def test_default_claim_map_no_regression(self) -> None:
        """Test that default mapping still works without passing claim_map."""
        token = jwt.encode(
            {"sub": "user123", "actor_type": "tenant_user", "email": "user@example.com"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(token, secret="secret")
        assert actor is not None
        assert actor.actor_id == "user123"
        assert actor.actor_type == "tenant_user"
        assert actor.email == "user@example.com"

    def test_partial_override_actor_id_only(self) -> None:
        """Test that only actor_id can be remapped, others use defaults."""
        token = jwt.encode(
            {"user_id": "custom_user", "actor_type": "platform_admin", "email": "test@example.com"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={"actor_id": "user_id"},
        )
        assert actor is not None
        assert actor.actor_id == "custom_user"
        assert actor.actor_type == "platform_admin"
        assert actor.email == "test@example.com"

    def test_full_override_all_claim_names(self) -> None:
        """Test that all three claim names can be remapped."""
        token = jwt.encode(
            {"uid": "user456", "role": "platform_admin", "mail": "admin@example.com"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={
                "actor_id": "uid",
                "actor_type": "role",
                "actor_email": "mail",
            },
        )
        assert actor is not None
        assert actor.actor_id == "user456"
        assert actor.actor_type == "platform_admin"
        assert actor.email == "admin@example.com"

    def test_missing_remapped_actor_id_returns_none(self) -> None:
        """Test that missing remapped actor_id claim falls back gracefully."""
        token = jwt.encode(
            {"actor_type": "tenant_user", "email": "test@example.com"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={"actor_id": "user_id"},
        )
        assert actor is None

    def test_missing_remapped_actor_type_defaults_to_anonymous(self) -> None:
        """Test that missing remapped actor_type claim defaults to anonymous."""
        token = jwt.encode(
            {"sub": "user123", "email": "test@example.com"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={"actor_type": "role"},
        )
        assert actor is not None
        assert actor.actor_id == "user123"
        assert actor.actor_type == "anonymous"
        assert actor.email == "test@example.com"

    def test_missing_remapped_email_returns_none(self) -> None:
        """Test that missing remapped email claim returns None."""
        token = jwt.encode(
            {"sub": "user123", "actor_type": "tenant_user"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={"actor_email": "mail"},
        )
        assert actor is not None
        assert actor.actor_id == "user123"
        assert actor.actor_type == "tenant_user"
        assert actor.email is None

    def test_claim_map_with_aliases_combined(self) -> None:
        """Test that claim_map and actor_type_aliases work together."""
        token = jwt.encode(
            {"uid": "admin1", "role": "ops_admin"},
            "secret",
            algorithm="HS256",
        )
        actor = extract_actor(
            token,
            secret="secret",
            claim_map={
                "actor_id": "uid",
                "actor_type": "role",
            },
            actor_type_aliases={"ops_admin": "platform_admin"},
        )
        assert actor is not None
        assert actor.actor_id == "admin1"
        assert actor.actor_type == "platform_admin"
        assert actor.email is None

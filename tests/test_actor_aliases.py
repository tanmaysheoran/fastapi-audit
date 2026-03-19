"""Tests for actor_type_aliases mapping."""

from jose import jwt

from fastapi_audit.config import AuditConfig
from fastapi_audit.jwt_parser import extract_actor
from fastapi_audit.models import ActorType, normalize_actor_type


class TestNormalizeActorType:
    """Tests for normalize_actor_type function."""

    def test_returns_enum_directly(self) -> None:
        """Test that ActorType enum values are returned unchanged."""
        result = normalize_actor_type(ActorType.PLATFORM_ADMIN)
        assert result == ActorType.PLATFORM_ADMIN

    def test_canonical_platform_admin(self) -> None:
        """Test normalizing platform_admin."""
        result = normalize_actor_type("platform_admin")
        assert result == ActorType.PLATFORM_ADMIN

    def test_canonical_tenant_user(self) -> None:
        """Test normalizing tenant_user."""
        result = normalize_actor_type("tenant_user")
        assert result == ActorType.TENANT_USER

    def test_canonical_anonymous(self) -> None:
        """Test normalizing anonymous."""
        result = normalize_actor_type("anonymous")
        assert result == ActorType.ANONYMOUS

    def test_unknown_type_defaults_to_anonymous(self) -> None:
        """Test that unknown actor types fall back to ANONYMOUS."""
        result = normalize_actor_type("unknown_type")
        assert result == ActorType.ANONYMOUS

    def test_alias_mapping(self) -> None:
        """Test that alias mapping resolves to canonical value."""
        aliases = {"ops_admin": "platform_admin", "internal_user": "tenant_user"}
        result = normalize_actor_type("ops_admin", aliases)
        assert result == ActorType.PLATFORM_ADMIN

    def test_alias_with_different_case(self) -> None:
        """Test that input is case-insensitive but alias keys must match."""
        aliases = {"ops_admin": "platform_admin"}
        result = normalize_actor_type("OPS_ADMIN", aliases)
        assert result == ActorType.PLATFORM_ADMIN

    def test_whitespace_trimmed(self) -> None:
        """Test that whitespace is trimmed before lookup."""
        result = normalize_actor_type("  tenant_user  ")
        assert result == ActorType.TENANT_USER

    def test_none_aliases(self) -> None:
        """Test with None aliases dict."""
        result = normalize_actor_type("anonymous", None)
        assert result == ActorType.ANONYMOUS

    def test_unknown_after_alias_fallback(self) -> None:
        """Test that unknown value without alias defaults to ANONYMOUS."""
        result = normalize_actor_type("random_value", {"foo": "bar"})
        assert result == ActorType.ANONYMOUS


class TestExtractActorWithAliases:
    """Tests for extract_actor with actor_type_aliases."""

    def _create_token(self, sub: str, actor_type: str, email: str | None = None) -> str:
        """Create a JWT token for testing."""
        payload = {"sub": sub, "actor_type": actor_type}
        if email:
            payload["email"] = email
        return jwt.encode(payload, "secret", algorithm="HS256")

    def test_actor_type_alias_mapping(self) -> None:
        """Test that custom alias is resolved in JWT extraction."""
        token = self._create_token("user1", "ops_admin", "admin@example.com")
        actor = extract_actor(
            token,
            secret="secret",
            actor_type_aliases={"ops_admin": "platform_admin"},
        )
        assert actor is not None
        assert actor.actor_type == ActorType.PLATFORM_ADMIN
        assert actor.actor_id == "user1"
        assert actor.email == "admin@example.com"

    def test_multiple_aliases(self) -> None:
        """Test that multiple aliases are all resolved."""
        aliases = {
            "superuser": "platform_admin",
            "member": "tenant_user",
        }
        token1 = self._create_token("u1", "superuser")
        token2 = self._create_token("u2", "member")

        actor1 = extract_actor(token1, secret="secret", actor_type_aliases=aliases)
        actor2 = extract_actor(token2, secret="secret", actor_type_aliases=aliases)

        assert actor1 is not None
        assert actor1.actor_type == ActorType.PLATFORM_ADMIN
        assert actor2 is not None
        assert actor2.actor_type == ActorType.TENANT_USER

    def test_no_alias_match_defaults_to_anonymous(self) -> None:
        """Test that unknown actor type falls back to ANONYMOUS."""
        token = self._create_token("user1", "unknown_type")
        actor = extract_actor(
            token,
            secret="secret",
            actor_type_aliases={"some_alias": "platform_admin"},
        )
        assert actor is not None
        assert actor.actor_type == ActorType.ANONYMOUS


class TestAuditConfigActorTypeAliases:
    """Tests for actor_type_aliases in AuditConfig."""

    def test_empty_aliases_by_default(self) -> None:
        """Test that actor_type_aliases defaults to empty."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert config.actor_type_aliases == {}
        assert config.actor_type_aliases_lower == {}

    def test_custom_aliases_passed_through(self) -> None:
        """Test that custom aliases are normalized."""
        config = AuditConfig(
            control_db_url="postgresql+asyncpg://test",
            actor_type_aliases={"ADMIN": "PLATFORM_ADMIN"},
        )
        assert config.actor_type_aliases_lower["admin"] == "platform_admin"

    def test_hashira_not_in_defaults(self) -> None:
        """Test that hashira is not a default alias."""
        config = AuditConfig(control_db_url="postgresql+asyncpg://test")
        assert "hashira" not in config.actor_type_aliases_lower

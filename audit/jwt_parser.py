"""JWT parsing utilities for actor extraction."""

from dataclasses import dataclass

from jose import JWTError, jwt

from audit.models import ActorType


@dataclass
class Actor:
    """Represents an authenticated actor extracted from JWT."""

    actor_id: str
    actor_type: ActorType
    email: str | None


def extract_actor(
    token: str | None,
    secret: str = "",
    algorithms: list[str] = ["HS256", "RS256"],
) -> Actor | None:
    """Extract actor information from JWT token.

    Args:
        token: JWT token string from Authorization header.
        secret: Secret/key for JWT verification (empty for decode-only mode).
        algorithms: List of allowed algorithms.

    Returns:
        Actor instance if token is valid, None otherwise.
    """
    if not token:
        return None

    try:
        if token.startswith("Bearer "):
            token = token[7:]

        if secret:
            payload = jwt.decode(
                token,
                secret,
                algorithms=algorithms,
                options={"verify_aud": False, "verify_iss": False},
            )
        else:
            payload = jwt.get_unverified_claims(token)

    except JWTError:
        return None

    sub = payload.get("sub")
    if not sub:
        return None

    actor_type_str = payload.get("actor_type", "anonymous")
    try:
        actor_type = ActorType(actor_type_str)
    except ValueError:
        actor_type = ActorType.ANONYMOUS

    email = payload.get("email")

    return Actor(
        actor_id=str(sub),
        actor_type=actor_type,
        email=email,
    )


def extract_token_from_header(authorization: str | None) -> str | None:
    """Extract token from Authorization header.

    Args:
        authorization: Authorization header value.

    Returns:
        Token string if header is valid, None otherwise.
    """
    if not authorization:
        return None

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]

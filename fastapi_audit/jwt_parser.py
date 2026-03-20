"""JWT parsing utilities for actor extraction."""

import logging
from dataclasses import dataclass

from jose import JWTError, jwt

from fastapi_audit.models import ActorType, normalize_actor_type

logger = logging.getLogger("audit")

_signature_warning_logged: bool = False


@dataclass
class Actor:
    """Represents an authenticated actor extracted from JWT."""

    actor_id: str
    actor_type: str
    email: str | None


def extract_actor(
    token: str | None,
    secret: str = "",
    actor_type_aliases: dict[str, str] | None = None,
    algorithms: list[str] = ["HS256", "RS256"],
    verify_signature: bool = False,
    claim_map: dict[str, str] | None = None,
) -> Actor | None:
    """Extract actor information from JWT token.

    SECURITY WARNING: When verify_signature=False and no secret is provided,
    the token's signature is NOT verified. This means any client can forge
    tokens with arbitrary actor information. Only use decode-only mode when
    signature verification is handled by a trusted upstream component (e.g.,
    an API gateway that has already validated the token).

    Args:
        token: JWT token string from Authorization header.
        secret: Secret/key for JWT verification (empty for decode-only mode).
        actor_type_aliases: Mapping of incoming values to canonical actor types.
        algorithms: List of allowed algorithms.
        verify_signature: If True, always verify the token signature. If False
            and no secret is provided, decode without verification (WARNING:
            allows forged tokens). Default is False for backward compatibility.
        claim_map: Mapping of audit field names to JWT claim keys. Defaults to
            {"actor_id": "sub", "actor_type": "actor_type", "actor_email": "email"}.

    Returns:
        Actor instance if token is valid, None otherwise.
    """
    global _signature_warning_logged

    if not token:
        return None

    claim_map = claim_map or {}
    actor_id_key = claim_map.get("actor_id", "sub")
    actor_type_key = claim_map.get("actor_type", "actor_type")
    email_key = claim_map.get("actor_email", "email")

    try:
        if token.startswith("Bearer "):
            token = token[7:]

        if secret and verify_signature:
            payload = jwt.decode(
                token,
                secret,
                algorithms=algorithms,
                options={"verify_aud": False, "verify_iss": False},
            )
        else:
            if not secret and not verify_signature:
                if not _signature_warning_logged:
                    logger.warning(
                        "JWT signature verification is disabled. "
                        "Forged tokens can inject arbitrary actor data into audit logs. "
                        "Provide jwt_secret and set jwt_verify_signature=True for production."
                    )
                    _signature_warning_logged = True
            payload = jwt.get_unverified_claims(token)

    except JWTError:
        return None

    actor_id = payload.get(actor_id_key)
    if not actor_id:
        return None

    actor_type = normalize_actor_type(
        str(payload.get(actor_type_key, "anonymous")),
        actor_type_aliases,
    )

    email = payload.get(email_key)

    return Actor(
        actor_id=str(actor_id),
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

"""Bearer-token (JWT, HS256) authentication.

The accepted algorithm list is pinned, so ``alg: none`` and algorithm-confusion tokens
are rejected, and ``exp`` and ``sub`` are mandatory. Failure reasons are precise for
the audit log but the HTTP response only ever says ``invalid_token``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt

ALGORITHM = "HS256"
ADMIN = "admin"
VIEWER = "viewer"
ROLES = frozenset({ADMIN, VIEWER})


class AuthError(Exception):
    def __init__(self, reason: str, status: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str


class JwtVerifier:
    def __init__(
        self,
        secret: str,
        *,
        leeway_s: int = 0,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        self._secret = secret
        self._leeway = leeway_s
        self._issuer = issuer
        self._audience = audience

    def authenticate(self, authorization_header: str | None) -> Principal:
        return self.verify(extract_bearer_token(authorization_header))

    def verify(self, token: str) -> Principal:
        required = ["exp", "sub"]
        if self._issuer:
            required.append("iss")
        if self._audience:
            required.append("aud")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self._secret,
                algorithms=[ALGORITHM],
                leeway=self._leeway,
                issuer=self._issuer,
                audience=self._audience,
                options={"require": required},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token_expired") from None
        except jwt.ImmatureSignatureError:
            raise AuthError("token_not_yet_valid") from None
        except jwt.InvalidSignatureError:
            raise AuthError("bad_signature") from None
        except jwt.InvalidAlgorithmError:
            raise AuthError("disallowed_algorithm") from None
        except jwt.MissingRequiredClaimError:
            raise AuthError("missing_claim") from None
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError):
            raise AuthError("wrong_issuer_or_audience") from None
        except jwt.DecodeError:
            raise AuthError("malformed_token") from None
        except jwt.InvalidTokenError:
            raise AuthError("invalid_token") from None

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise AuthError("missing_claim")
        role = claims.get("role")
        if not isinstance(role, str) or role not in ROLES:
            # Authenticated but not a role this gateway understands.
            raise AuthError("unknown_role", status=403)
        return Principal(subject=subject, role=role)


def extract_bearer_token(header: str | None) -> str:
    if not header:
        raise AuthError("missing_credentials")
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        raise AuthError("malformed_header")
    return token


def mint_token(
    secret: str,
    *,
    subject: str,
    role: str,
    ttl_s: int = 3600,
    now: float | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> str:
    issued_at = int(time.time() if now is None else now)
    claims: dict[str, Any] = {"sub": subject, "role": role, "iat": issued_at, "exp": issued_at + ttl_s}
    if issuer:
        claims["iss"] = issuer
    if audience:
        claims["aud"] = audience
    return jwt.encode(claims, secret, algorithm=ALGORITHM)

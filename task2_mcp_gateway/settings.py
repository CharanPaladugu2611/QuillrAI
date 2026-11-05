"""Gateway configuration, loaded from the environment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

MIN_SECRET_LENGTH = 32


class ConfigError(ValueError):
    """The gateway refuses to start with an unsafe or incomplete configuration."""


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    downstream_url: str
    downstream_token: str | None = None
    downstream_timeout_s: float = 30.0
    max_body_bytes: int = 1_048_576
    jwt_leeway_s: int = 0
    jwt_issuer: str | None = None
    jwt_audience: str | None = None

    def __post_init__(self) -> None:
        if len(self.jwt_secret) < MIN_SECRET_LENGTH:
            raise ConfigError(f"GATEWAY_JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        parsed = urlparse(self.downstream_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ConfigError("DOWNSTREAM_URL must be an absolute http(s) URL")
        if self.downstream_timeout_s <= 0:
            raise ConfigError("DOWNSTREAM_TIMEOUT_S must be positive")
        if self.max_body_bytes <= 0:
            raise ConfigError("MAX_BODY_BYTES must be positive")
        if self.jwt_leeway_s < 0:
            raise ConfigError("JWT_LEEWAY_S must not be negative")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        secret = env.get("GATEWAY_JWT_SECRET")
        if not secret:
            raise ConfigError("GATEWAY_JWT_SECRET is required")
        try:
            return cls(
                jwt_secret=secret,
                downstream_url=env.get("DOWNSTREAM_URL", "http://127.0.0.1:9000"),
                downstream_token=env.get("DOWNSTREAM_TOKEN") or None,
                downstream_timeout_s=float(env.get("DOWNSTREAM_TIMEOUT_S", "30")),
                max_body_bytes=int(env.get("MAX_BODY_BYTES", str(1_048_576))),
                jwt_leeway_s=int(env.get("JWT_LEEWAY_S", "0")),
                jwt_issuer=env.get("JWT_ISSUER") or None,
                jwt_audience=env.get("JWT_AUDIENCE") or None,
            )
        except ValueError as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"invalid numeric setting: {exc}") from None

"""Run the router: ``python -m task4_llm_router``.

Without ``PRIMARY_URL`` it starts in demo mode with two mock providers; ``DEMO_PRIMARY``
selects how the mock primary misbehaves (``ok``, ``rate_limited`` or ``slow``) so the
failover path can be exercised by hand.
"""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .app import create_app
from .errors import UpstreamRateLimited
from .limiter import DEFAULT_LIMIT_TOKENS, SlidingWindowLimiter
from .providers import HttpProvider, MockProvider, Provider
from .router import DEFAULT_PROVIDER_TIMEOUT_S, ModelRouter


def _providers_from_env() -> list[Provider]:
    if os.environ.get("PRIMARY_URL"):
        providers: list[Provider] = [
            HttpProvider(
                "primary",
                os.environ["PRIMARY_URL"],
                os.environ.get("PRIMARY_API_KEY", ""),
                os.environ.get("PRIMARY_MODEL", "primary-model"),
            )
        ]
        if os.environ.get("BACKUP_URL"):
            providers.append(
                HttpProvider(
                    "backup",
                    os.environ["BACKUP_URL"],
                    os.environ.get("BACKUP_API_KEY", ""),
                    os.environ.get("BACKUP_MODEL", "backup-model"),
                )
            )
        return providers

    mode = os.environ.get("DEMO_PRIMARY", "ok")
    primary = MockProvider("primary")
    if mode == "rate_limited":
        primary = MockProvider("primary", fail_with=UpstreamRateLimited())
    elif mode == "slow":
        primary = MockProvider("primary", latency_s=10.0)
    return [primary, MockProvider("backup")]


def main() -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    keys = [k.strip() for k in os.environ.get("GATEWAY_API_KEYS", "").split(",") if k.strip()]
    allow_unconfigured = os.environ.get("ALLOW_UNCONFIGURED_API_KEYS", "0") == "1"
    if not keys and not allow_unconfigured:
        logging.getLogger(__name__).error(
            "GATEWAY_API_KEYS is required; set ALLOW_UNCONFIGURED_API_KEYS=1 only for a local demo"
        )
        return 2
    if not keys:
        logging.getLogger(__name__).warning(
            "unsafe development mode: any non-empty API key is accepted"
        )

    limiter = SlidingWindowLimiter(
        os.environ.get("RATE_LIMIT_DB", "rate_limit.db"),
        limit=int(os.environ.get("RATE_LIMIT_TOKENS_PER_MINUTE", str(DEFAULT_LIMIT_TOKENS))),
    )
    router = ModelRouter(
        _providers_from_env(),
        limiter,
        timeout_s=float(os.environ.get("PROVIDER_TIMEOUT_S", str(DEFAULT_PROVIDER_TIMEOUT_S))),
        failover_on_server_errors=os.environ.get("FAILOVER_ON_SERVER_ERRORS", "0") == "1",
    )
    app = create_app(
        router,
        api_keys=keys,
        allow_unconfigured_api_keys=allow_unconfigured,
    )
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8081")), log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

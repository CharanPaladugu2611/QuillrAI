"""Run the gateway: ``python -m task2_mcp_gateway`` (configuration comes from the environment)."""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .proxy import create_app
from .settings import ConfigError, Settings


def main() -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(
        create_app(settings),
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

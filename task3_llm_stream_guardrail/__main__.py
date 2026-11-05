"""Run the guardrail gateway: ``python -m task3_llm_stream_guardrail``.

Without ``UPSTREAM_URL`` it serves a mock provider that replies with PII-laden text in
tiny chunks, which is the quickest way to watch the redaction happen:

    curl -N localhost:8082/v1/chat/completions -H 'content-type: application/json' \
         -d '{"messages":[{"role":"user","content":"hi"}],"stream":true}'
"""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .app import create_app
from .providers import HttpChatProvider, MockChatProvider


def main() -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if os.environ.get("UPSTREAM_URL"):
        provider = HttpChatProvider(
            os.environ["UPSTREAM_URL"],
            os.environ.get("UPSTREAM_API_KEY", ""),
            os.environ.get("UPSTREAM_MODEL", "gpt-4o-mini"),
        )
    else:
        provider = MockChatProvider(delay_s=float(os.environ.get("MOCK_DELAY_S", "0.03")))
    uvicorn.run(
        create_app(provider),
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8082")),
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

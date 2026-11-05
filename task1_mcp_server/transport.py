"""stdio transport wrapper that fills two gaps in the stock transport.

* Unreadable input. The SDK drops a line that is not valid JSON-RPC without replying.
  JSON-RPC 2.0 requires an error response, so the wrapper answers with ``-32700``
  (not JSON) or ``-32600`` (JSON, but not a Request) and an ``id`` of ``null``.
* Piped input. When stdin reaches EOF the SDK closes the output side immediately and
  responses to requests still being handled are lost. The wrapper waits (bounded)
  for in-flight requests to be answered, so ``cat requests.jsonl | python -m ...`` works.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any

import anyio
import mcp_types as types
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from pydantic import ValidationError

logger = logging.getLogger(__name__)

DRAIN_TIMEOUT_SECONDS = 5.0
_DRAIN_POLL_SECONDS = 0.01


def error_for_unreadable_input(exc: Exception) -> types.JSONRPCError:
    is_json_syntax_error = isinstance(exc, ValidationError) and any(
        err["type"] == "json_invalid" for err in exc.errors(include_url=False, include_input=False)
    )
    if is_json_syntax_error:
        error = types.ErrorData(code=types.PARSE_ERROR, message="Parse error")
    else:
        error = types.ErrorData(code=types.INVALID_REQUEST, message="Invalid Request")
    return types.JSONRPCError(jsonrpc="2.0", id=None, error=error)


class _TrackingWriter:
    """Write-stream proxy that notes which request ids have been answered."""

    def __init__(self, inner: Any, pending: set[Any]) -> None:
        self._inner = inner
        self._pending = pending

    async def send(self, item: SessionMessage, /) -> None:
        await self._inner.send(item)
        message = item.message
        if isinstance(message, (types.JSONRPCResponse, types.JSONRPCError)):
            self._pending.discard(message.id)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> _TrackingWriter:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()


@asynccontextmanager
async def stdio_with_protocol_errors() -> AsyncIterator[tuple[Any, Any]]:
    pending: set[Any] = set()
    async with stdio_server() as (read_stream, write_stream):
        writer = _TrackingWriter(write_stream, pending)
        forward_send, forward_receive = anyio.create_memory_object_stream[SessionMessage | Exception](0)

        async def pump() -> None:
            async with forward_send:
                async for item in read_stream:
                    if isinstance(item, Exception):
                        logger.warning("unreadable input line: %s", type(item).__name__)
                        await writer.send(SessionMessage(error_for_unreadable_input(item)))
                        continue
                    if isinstance(item.message, types.JSONRPCRequest):
                        pending.add(item.message.id)
                    await forward_send.send(item)
                with anyio.move_on_after(DRAIN_TIMEOUT_SECONDS):
                    while pending:
                        await anyio.sleep(_DRAIN_POLL_SECONDS)

        async with anyio.create_task_group() as tg:
            tg.start_soon(pump)
            try:
                yield forward_receive, writer
            finally:
                tg.cancel_scope.cancel()

"""LLM gateway endpoint that streams the provider's reply back with PII redacted in flight."""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .errors import ERROR_CATALOG, UpstreamError, UpstreamTimeout, error_body
from .guardrail import StreamGuard, guard_stream
from .providers import ChatProvider
from .redactor import redact_text
from .sse import SSEProtocolError, format_event

logger = logging.getLogger(__name__)

_STREAM_HEADERS = {"cache-control": "no-cache", "x-accel-buffering": "no", "connection": "keep-alive"}


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[Any] | None = None


class ChatRequest(BaseModel):
    """Only what the gateway needs to validate; every other field is passed through."""

    model_config = ConfigDict(extra="allow")

    messages: list[ChatMessage] = Field(min_length=1, max_length=512)
    stream: bool = False


def _redact_completion(payload: dict[str, Any]) -> dict[str, Any]:
    """Non-streaming replies are a single bounded JSON document, redacted in one pass."""
    for choice in payload.get("choices", []):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"] = redact_text(message["content"])[0]
        if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
            for call in message["tool_calls"]:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    function["arguments"] = redact_text(function["arguments"])[0]
        if isinstance(choice.get("text"), str):
            choice["text"] = redact_text(choice["text"])[0]
    return payload


def create_app(provider: ChatProvider, *, redact: bool = True) -> FastAPI:
    """``redact=False`` turns the guard into a plain pass-through (used to measure its overhead)."""
    app = FastAPI(title="LLM gateway with stream guardrail", docs_url=None, redoc_url=None, openapi_url=None)

    def failure(code: str, request: Request) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        return JSONResponse(error_body(code, request_id), status_code=ERROR_CATALOG[code][0], headers={"x-request-id": request_id})

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("unhandled error request_id=%s", request.state.request_id)
            return failure("internal_error", request)
        response.headers.setdefault("x-request-id", request.state.request_id)
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return failure("invalid_request", request)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code)
        return failure(code or ("invalid_request" if exc.status_code < 500 else "internal_error"), request)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat(request: Request, body: ChatRequest):
        payload = body.model_dump(exclude_none=True)
        started = time.perf_counter()

        if not body.stream:
            try:
                completion = await provider.complete(payload)
            except UpstreamTimeout:
                return failure("upstream_timeout", request)
            except UpstreamError:
                return failure("upstream_error", request)
            return JSONResponse(_redact_completion(completion) if redact else completion)

        guard = StreamGuard()
        source = provider.stream(payload)
        events = guard_stream(source, guard) if redact else source

        # Pull the first output before committing to a 200, so a provider that fails outright
        # (refused connection, 5xx) gets a proper error status instead of a broken stream.
        try:
            first = await anext(events)
        except StopAsyncIteration:
            return StreamingResponse(iter(()), media_type="text/event-stream", headers=_STREAM_HEADERS)
        except UpstreamTimeout:
            return failure("upstream_timeout", request)
        except (UpstreamError, SSEProtocolError):
            return failure("upstream_error", request)

        request_id = request.state.request_id

        async def body_iterator() -> AsyncIterator[bytes]:
            first_chunk_at = time.perf_counter()
            chunks = 1
            try:
                yield first
                async for chunk in events:
                    chunks += 1
                    yield chunk
            except (UpstreamError, SSEProtocolError):
                logger.warning("stream interrupted request_id=%s", request_id)
                for held in guard.finish(include_partial=False):  # text already received is still delivered, redacted
                    yield held
                notice = error_body("stream_interrupted", request_id)
                yield format_event(json.dumps(notice, separators=(",", ":")))
                yield format_event("[DONE]")
            finally:
                await events.aclose()  # propagates to the provider call (client disconnects land here)
                stats = guard.stats
                logger.info(
                    "stream done request_id=%s first_chunk_ms=%.1f total_ms=%.1f chunks=%d redactions=%d max_held=%d",
                    request_id,
                    (first_chunk_at - started) * 1000,
                    (time.perf_counter() - started) * 1000,
                    chunks,
                    stats.redactions,
                    stats.max_buffered,
                )

        return StreamingResponse(body_iterator(), media_type="text/event-stream", headers=_STREAM_HEADERS)

    return app

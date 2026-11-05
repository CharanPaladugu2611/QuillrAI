"""MCP security gateway: authenticates the caller, then forwards or intercepts JSON-RPC.

Request flow for ``POST /mcp``::

    Bearer JWT -> role  ->  parse JSON-RPC  ->  policy  -> forward | local JSON-RPC error

* ``tools/list`` and every other method are forwarded as the original bytes.
* ``tools/call`` on an ``admin_*`` tool by a non-admin is answered locally with
  ``-32001 Unauthorized Tool Call``; the downstream server is never contacted.
* The caller's bearer token is not forwarded. The gateway authenticates itself to the
  downstream with its own credential and passes the verified identity in headers.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import AuthError, JwtVerifier, Principal
from .jsonrpc import (
    BAD_GATEWAY,
    GATEWAY_TIMEOUT,
    INVALID_REQUEST,
    PARSE_ERROR,
    UNAUTHENTICATED,
    Kind,
    ParseError,
    classify,
    error_response,
    message_id,
    parse_body,
)
from .policy import authorize
from .settings import Settings

audit = logging.getLogger("mcp_gateway.audit")
logger = logging.getLogger(__name__)

MCP_PATH = "/mcp"

# Request headers worth forwarding. Everything else, Authorization and Cookie included, is dropped.
_FORWARD_REQUEST_HEADERS = (
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
    "traceparent",
    "tracestate",
)
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)


class BodyTooLarge(Exception):
    pass


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _downstream_headers(request: Request, principal: Principal, settings: Settings, request_id: str) -> dict[str, str]:
    headers = {name: request.headers[name] for name in _FORWARD_REQUEST_HEADERS if name in request.headers}
    if settings.downstream_token:
        headers["authorization"] = f"Bearer {settings.downstream_token}"
    headers["x-authenticated-user"] = principal.subject
    headers["x-authenticated-role"] = principal.role
    headers["x-request-id"] = request_id
    return headers


def _relay_headers(response: httpx.Response, request_id: str) -> dict[str, str]:
    headers = {k: v for k, v in response.headers.items() if k.lower() not in _HOP_BY_HOP}
    headers["x-request-id"] = request_id
    return headers


def _rpc_json(payload: Any, status: int, request_id: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"x-request-id": request_id, **(headers or {})})


def create_app(settings: Settings, *, http_client: httpx.AsyncClient | None = None) -> FastAPI:
    verifier = JwtVerifier(
        settings.jwt_secret,
        leeway_s=settings.jwt_leeway_s,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = http_client or httpx.AsyncClient(
            base_url=settings.downstream_url,
            timeout=httpx.Timeout(settings.downstream_timeout_s, connect=5.0),
            follow_redirects=False,
        )
        app.state.client = client
        try:
            yield
        finally:
            if http_client is None:
                await client.aclose()

    app = FastAPI(title="MCP security gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    if http_client is not None:
        app.state.client = http_client

    def _log(request_id: str, principal: Principal | None, **fields: Any) -> None:
        who = f"{principal.subject}/{principal.role}" if principal else "-"
        extra = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
        audit.info("request_id=%s principal=%s %s", request_id, who, extra)

    async def _forward(
        request: Request,
        principal: Principal,
        request_id: str,
        *,
        content: bytes | None,
        stream: bool,
    ) -> httpx.Response:
        client: httpx.AsyncClient = app.state.client
        url = httpx.URL(MCP_PATH)
        outgoing = client.build_request(
            request.method,
            url,
            content=content,
            headers=_downstream_headers(request, principal, settings, request_id),
            timeout=httpx.Timeout(None, connect=5.0) if request.method == "GET" else httpx.USE_CLIENT_DEFAULT,
        )
        return await client.send(outgoing, stream=stream)

    def _relay(response: httpx.Response, request_id: str) -> StreamingResponse:
        async def body() -> AsyncIterator[bytes]:
            try:
                if response.is_stream_consumed:  # transports that hand back an already-read response
                    yield response.content
                else:
                    async for chunk in response.aiter_raw():
                        yield chunk
            finally:
                await response.aclose()

        return StreamingResponse(
            body(),
            status_code=response.status_code,
            headers=_relay_headers(response, request_id),
        )

    def _downstream_failure(exc: Exception, rpc_id: Any, request_id: str) -> JSONResponse:
        logger.warning("downstream failure request_id=%s kind=%s", request_id, type(exc).__name__)
        if isinstance(exc, httpx.TimeoutException):
            return _rpc_json(error_response(rpc_id, GATEWAY_TIMEOUT, "Downstream server timed out"), 504, request_id)
        return _rpc_json(error_response(rpc_id, BAD_GATEWAY, "Downstream server unavailable"), 502, request_id)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route(MCP_PATH, methods=["GET", "POST", "DELETE"])
    async def mcp(request: Request) -> Response:
        started = time.perf_counter()
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex

        try:
            principal = verifier.authenticate(request.headers.get("authorization"))
        except AuthError as exc:
            _log(request_id, None, decision="auth_failed", reason=exc.reason)
            challenge = 'Bearer realm="mcp-gateway", error="invalid_token"'
            message = "Authentication required" if exc.status == 401 else "Forbidden"
            return _rpc_json(
                error_response(None, UNAUTHENTICATED, message),
                exc.status,
                request_id,
                {"www-authenticate": challenge} if exc.status == 401 else None,
            )

        if request.method != "POST":
            try:
                upstream = await _forward(request, principal, request_id, content=None, stream=True)
            except httpx.HTTPError as exc:
                return _downstream_failure(exc, None, request_id)
            _log(request_id, principal, decision="forwarded", http_method=request.method, status=upstream.status_code)
            return _relay(upstream, request_id)

        try:
            raw = await _read_capped(request, settings.max_body_bytes)
        except BodyTooLarge:
            return _rpc_json(error_response(None, INVALID_REQUEST, "Request body too large"), 413, request_id)

        try:
            payload = parse_body(raw)
        except ParseError:
            _log(request_id, principal, decision="rejected", reason="parse_error")
            return _rpc_json(error_response(None, PARSE_ERROR, "Parse error"), 400, request_id)

        if isinstance(payload, list):
            return await _handle_batch(request, payload, raw, principal, request_id, started)

        kind = classify(payload)
        if kind is Kind.INVALID:
            _log(request_id, principal, decision="rejected", reason="invalid_request")
            return _rpc_json(error_response(message_id(payload), INVALID_REQUEST, "Invalid Request"), 400, request_id)

        decision = authorize(payload, principal) if kind is not Kind.RESPONSE else None
        if decision is not None and not decision.allowed:
            _log(
                request_id,
                principal,
                decision="denied",
                rpc_method=payload.get("method"),
                tool=decision.tool,
                code=decision.code,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            if kind is Kind.NOTIFICATION:
                return Response(status_code=202, headers={"x-request-id": request_id})
            assert decision.code is not None and decision.message is not None
            return _rpc_json(error_response(payload["id"], decision.code, decision.message), 200, request_id)

        try:
            upstream = await _forward(request, principal, request_id, content=raw, stream=True)
        except httpx.HTTPError as exc:
            return _downstream_failure(exc, message_id(payload), request_id)
        _log(
            request_id,
            principal,
            decision="forwarded",
            rpc_method=payload.get("method"),
            tool=decision.tool if decision else None,
            status=upstream.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return _relay(upstream, request_id)

    async def _handle_batch(
        request: Request,
        items: list[Any],
        raw: bytes,
        principal: Principal,
        request_id: str,
        started: float,
    ) -> Response:
        if not items:
            return _rpc_json(error_response(None, INVALID_REQUEST, "Invalid Request"), 400, request_id)

        local: list[dict[str, Any]] = []
        forward: list[Any] = []
        for item in items:
            kind = classify(item)
            if kind is Kind.INVALID:
                local.append(error_response(message_id(item), INVALID_REQUEST, "Invalid Request"))
                continue
            decision = authorize(item, principal) if kind is not Kind.RESPONSE else None
            if decision is None or decision.allowed:
                forward.append(item)
                continue
            _log(request_id, principal, decision="denied", rpc_method=item.get("method"), tool=decision.tool, batch=True)
            if kind is Kind.REQUEST:
                assert decision.code is not None and decision.message is not None
                local.append(error_response(item["id"], decision.code, decision.message))

        if not forward:
            if not local:
                return Response(status_code=202, headers={"x-request-id": request_id})
            return _rpc_json(local, 200, request_id)

        untouched = not local and len(forward) == len(items)
        try:
            upstream = await _forward(
                request,
                principal,
                request_id,
                content=raw if untouched else json.dumps(forward).encode("utf-8"),
                stream=True,
            )
        except httpx.HTTPError as exc:
            return _downstream_failure(exc, None, request_id)

        _log(
            request_id,
            principal,
            decision="forwarded",
            batch=True,
            status=upstream.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        if untouched or upstream.status_code >= 300:
            return _relay(upstream, request_id)
        if upstream.status_code == 202:
            # Only notifications went downstream; the locally produced errors are the whole reply.
            if not local:
                return _relay(upstream, request_id)
            await upstream.aclose()
            return _rpc_json(local, 200, request_id)

        try:
            downstream_payload = json.loads(await upstream.aread())
        except ValueError:
            return _downstream_failure(httpx.DecodingError("non-JSON batch response"), None, request_id)
        finally:
            await upstream.aclose()
        if isinstance(downstream_payload, dict):
            downstream_payload = [downstream_payload]
        if not isinstance(downstream_payload, list):
            return _downstream_failure(httpx.DecodingError("unexpected batch response"), None, request_id)
        return _rpc_json(
            downstream_payload + local,
            200,
            request_id,
            {k: v for k, v in _relay_headers(upstream, request_id).items() if k.lower() == "mcp-session-id"},
        )

    return app

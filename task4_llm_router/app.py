"""HTTP surface for the router: ``POST /v1/chat/completions`` with a tenant API key."""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Collection

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .errors import GatewayError, error_payload
from .models import CompletionRequest
from .router import ModelRouter

logger = logging.getLogger(__name__)


def tenant_id(api_key: str) -> str:
    """Stable, non-reversible tenant identifier; raw keys are never stored or logged."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:32]


def _extract_key(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return request.headers.get("x-api-key") or None


def allowed_tenant_ids(
    api_keys: Collection[str] | None,
    *,
    allow_unconfigured_api_keys: bool = False,
) -> frozenset[str] | None:
    """Return hashed allowed tenants; ``None`` means explicit development wildcard."""
    configured = frozenset(tenant_id(k) for k in (api_keys or ()) if k)
    if allow_unconfigured_api_keys and not configured:
        return None
    return configured


def create_app(
    router: ModelRouter,
    *,
    api_keys: Collection[str] | None = None,
    allow_unconfigured_api_keys: bool = False,
) -> FastAPI:
    """Create the HTTP app.

    Authentication fails closed when no key allow-list is supplied. Local demos may
    deliberately accept any non-empty key by setting ``allow_unconfigured_api_keys``;
    callers must opt into that unsafe mode explicitly.
    """
    allowed = allowed_tenant_ids(
        api_keys,
        allow_unconfigured_api_keys=allow_unconfigured_api_keys,
    )
    app = FastAPI(title="LLM gateway router", docs_url=None, redoc_url=None, openapi_url=None)

    def respond(code: str, request: Request, retry_after_s: int | None = None) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        error = GatewayError(code, retry_after_s)
        headers = {"x-request-id": request_id}
        if retry_after_s is not None:
            headers["retry-after"] = str(retry_after_s)
        return JSONResponse(error_payload(code, request_id, retry_after_s), status_code=error.status, headers=headers)

    @app.middleware("http")
    async def assign_request_id(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("unhandled error request_id=%s", request.state.request_id)
            return respond("internal_error", request)
        response.headers.setdefault("x-request-id", request.state.request_id)
        return response

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        return respond(exc.code, request, exc.retry_after_s)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return respond("invalid_request", request)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "internal_error")
        return respond(code, request)

    async def authenticate(request: Request) -> str:
        key = _extract_key(request)
        tenant = tenant_id(key) if key else None
        if tenant is None or (allowed is not None and tenant not in allowed):
            raise GatewayError("unauthorized")
        return tenant

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def completions(request: Request, body: CompletionRequest, tenant: str = Depends(authenticate)):
        request_id = request.state.request_id
        routed = await router.complete(tenant, body, request_id)
        usage = routed.result.usage
        used = await router.limiter.usage(tenant)
        return JSONResponse(
            {
                "id": f"cmpl-{request_id}",
                "object": "chat.completion",
                "model": routed.result.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": routed.result.content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                },
                "gateway": {"served_by": routed.served_by, "request_id": request_id},
            },
            headers={
                "x-request-id": request_id,
                "x-ratelimit-limit-tokens": str(router.limiter.limit),
                "x-ratelimit-remaining-tokens": str(max(router.limiter.limit - used, 0)),
            },
        )

    return app

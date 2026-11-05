"""Rate-limited completion routing with timeout-bounded failover.

Flow for one request::

    reserve tokens (SQLite) -> primary (<= 3 s) --429/timeout--> backup (<= 3 s)
        |                                                            |
        denied -> 429                              success: settle to real usage
                                                   failure: release reservation, sanitised error

Failover triggers are exactly what the requirement names: an upstream 429 or a timeout.
Connection failures and 5xx responses fail over only when ``failover_on_server_errors``
is enabled, and any other failure is reported rather than retried.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from .errors import (
    GatewayError,
    UpstreamError,
    UpstreamRateLimited,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from .limiter import Denied, RequestTooLarge, Reservation, SlidingWindowLimiter
from .models import CompletionRequest, estimate_prompt_tokens
from .providers import Provider, ProviderResult

logger = logging.getLogger(__name__)

DEFAULT_PROVIDER_TIMEOUT_S = 3.0


@dataclass(frozen=True)
class RoutedCompletion:
    result: ProviderResult
    served_by: str
    attempts: int
    reservation: Reservation


class ModelRouter:
    def __init__(
        self,
        providers: Sequence[Provider],
        limiter: SlidingWindowLimiter,
        *,
        timeout_s: float = DEFAULT_PROVIDER_TIMEOUT_S,
        failover_on_server_errors: bool = False,
    ) -> None:
        if not providers:
            raise ValueError("at least one provider is required")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._providers = list(providers)
        self._limiter = limiter
        self._timeout_s = timeout_s
        self._failover_on_server_errors = failover_on_server_errors

    @property
    def limiter(self) -> SlidingWindowLimiter:
        return self._limiter

    async def complete(self, tenant: str, request: CompletionRequest, request_id: str) -> RoutedCompletion:
        estimate = estimate_prompt_tokens(request) + request.output_budget
        try:
            outcome = await self._limiter.reserve(tenant, estimate)
        except RequestTooLarge:
            raise GatewayError("request_too_large") from None
        if isinstance(outcome, Denied):
            raise GatewayError("rate_limit_exceeded", retry_after_s=outcome.retry_after_s)
        reservation = outcome

        try:
            index, result = await self._call_providers(request, request_id)
        except asyncio.CancelledError:
            # The caller went away mid-flight. An upstream call may already be billed, so the
            # reservation stays: over-counting is safer than letting a tenant dodge the limit.
            raise
        except BaseException:
            await asyncio.shield(self._limiter.release(reservation))
            raise

        await asyncio.shield(self._limiter.settle(reservation, result.usage.total_tokens))
        return RoutedCompletion(
            result=result,
            served_by="primary" if index == 0 else "fallback",
            attempts=index + 1,
            reservation=reservation,
        )

    async def _call_providers(self, request: CompletionRequest, request_id: str) -> tuple[int, ProviderResult]:
        for index, provider in enumerate(self._providers):
            failure = await self._attempt(provider, request, request_id)
            if isinstance(failure, ProviderResult):
                return index, failure
            if not self._should_fail_over(failure):
                raise GatewayError("upstream_error")
        raise GatewayError("upstream_unavailable")

    async def _attempt(
        self, provider: Provider, request: CompletionRequest, request_id: str
    ) -> ProviderResult | UpstreamError:
        try:
            # On expiry the in-flight provider call is cancelled; a reply that arrives after
            # the deadline is discarded, so the same request is never served twice.
            async with asyncio.timeout(self._timeout_s):
                return await provider.complete(request)
        except TimeoutError:
            failure: UpstreamError = UpstreamTimeout()
        except UpstreamError as exc:
            failure = exc
        except Exception:
            # Details stay in the server log; the client only ever sees a catalogue message.
            logger.exception("unexpected provider failure request_id=%s provider=%s", request_id, provider.name)
            failure = UpstreamUnavailable()
        logger.warning(
            "provider failed request_id=%s provider=%s reason=%s",
            request_id,
            provider.name,
            type(failure).__name__,
        )
        return failure

    def _should_fail_over(self, failure: UpstreamError) -> bool:
        if isinstance(failure, (UpstreamRateLimited, UpstreamTimeout)):
            return True
        return self._failover_on_server_errors and isinstance(failure, UpstreamUnavailable)

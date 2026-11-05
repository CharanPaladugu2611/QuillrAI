"""Model providers: an OpenAI-compatible HTTP client and a scriptable mock."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .errors import (
    UpstreamError,
    UpstreamRateLimited,
    UpstreamRejected,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from .models import CompletionRequest, Usage, estimate_prompt_tokens, estimate_tokens


@dataclass(frozen=True)
class ProviderResult:
    content: str
    usage: Usage
    model: str


class Provider(Protocol):
    name: str

    async def complete(self, request: CompletionRequest) -> ProviderResult: ...


class HttpProvider:
    """Calls an OpenAI-compatible ``/v1/chat/completions`` endpoint and maps failures to ``Upstream*``."""

    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str,
        model: str,
        *,
        client: httpx.AsyncClient | None = None,
        request_timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._model = model
        self._url = base_url.rstrip("/") + "/v1/chat/completions"
        self._headers = {"authorization": f"Bearer {api_key}"}
        self._client = client or httpx.AsyncClient(timeout=request_timeout_s)

    async def complete(self, request: CompletionRequest) -> ProviderResult:
        body = {
            "model": self._model,
            "messages": [m.model_dump() for m in request.messages],
            "max_tokens": request.output_budget,
        }
        if request.temperature is not None:
            body["temperature"] = request.temperature
        try:
            response = await self._client.post(self._url, json=body, headers=self._headers)
        except httpx.TimeoutException:
            raise UpstreamTimeout from None
        except httpx.HTTPError:
            raise UpstreamUnavailable from None

        if response.status_code == 429:
            raise UpstreamRateLimited(_retry_after(response))
        if response.status_code >= 500:
            raise UpstreamUnavailable
        if response.status_code >= 400:
            raise UpstreamRejected
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            usage = data["usage"]
            return ProviderResult(
                content=content,
                usage=Usage(prompt_tokens=int(usage["prompt_tokens"]), completion_tokens=int(usage["completion_tokens"])),
                model=str(data.get("model", self._model)),
            )
        except (ValueError, KeyError, IndexError, TypeError):
            raise UpstreamUnavailable from None

    async def aclose(self) -> None:
        await self._client.aclose()


def _retry_after(response: httpx.Response) -> float | None:
    try:
        return float(response.headers["retry-after"])
    except (KeyError, ValueError):
        return None


@dataclass
class MockProvider:
    """Deterministic provider for tests and demos.

    ``behaviour`` may be a callable ``(request, call_number) -> ProviderResult | None``
    that raises to simulate failures; ``latency_s`` delays every reply. The counters let
    tests assert what was called and that cancelled calls really were cancelled.
    """

    name: str
    latency_s: float = 0.0
    fail_with: UpstreamError | Exception | None = None
    behaviour: Callable[[CompletionRequest, int], ProviderResult | None] | None = None
    calls: int = field(default=0, init=False)
    cancelled: int = field(default=0, init=False)
    completed: int = field(default=0, init=False)

    async def complete(self, request: CompletionRequest) -> ProviderResult:
        self.calls += 1
        try:
            if self.latency_s:
                await asyncio.sleep(self.latency_s)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        if self.fail_with is not None:
            raise self.fail_with
        if self.behaviour is not None:
            produced = self.behaviour(request, self.calls)
            if produced is not None:
                self.completed += 1
                return produced
        self.completed += 1
        text = f"[{self.name}] reply to: {request.messages[-1].content[:80]}"
        return ProviderResult(
            content=text,
            usage=Usage(prompt_tokens=estimate_prompt_tokens(request), completion_tokens=estimate_tokens(text)),
            model=request.model or f"{self.name}-model",
        )

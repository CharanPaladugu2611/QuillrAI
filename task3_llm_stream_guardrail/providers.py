"""Upstream providers: a scriptable mock and an OpenAI-compatible HTTP client."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from .errors import UpstreamError, UpstreamTimeout

DEFAULT_REPLY = (
    "Sure! You can reach Jane at jane.doe@example.com. Her SSN is 123-45-6789 and the card on file "
    "is 4111 1111 1111 1111, expiring 12/30. Anything else I can help with?"
)


class ChatProvider(Protocol):
    def stream(self, body: dict[str, Any]) -> AsyncIterator[bytes]: ...

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]: ...


def _sse(obj: Any) -> bytes:
    payload = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))
    return f"data: {payload}\n\n".encode()


@dataclass
class MockChatProvider:
    """Emits a canned reply as OpenAI-style SSE chunks.

    ``piece_sizes`` is cycled to cut the reply into deltas (small odd sizes make PII
    straddle chunk boundaries), ``fragment_bytes`` re-cuts the byte stream the way a
    network would, and ``delay_s`` is the pause before each delta.
    """

    reply: str = DEFAULT_REPLY
    piece_sizes: tuple[int, ...] = (3, 1, 4, 2, 5)
    delay_s: float = 0.0
    fragment_bytes: int | None = None
    fail_before_stream: bool = False
    fail_after_deltas: int | None = None
    model: str = "mock-model"
    streams_started: int = field(default=0, init=False)
    streams_closed: int = field(default=0, init=False)

    def _pieces(self) -> list[str]:
        pieces, position, turn = [], 0, 0
        while position < len(self.reply):
            size = self.piece_sizes[turn % len(self.piece_sizes)]
            pieces.append(self.reply[position : position + size])
            position += size
            turn += 1
        return pieces

    def _chunk(self, delta: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
        return {
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }

    async def stream(self, body: dict[str, Any]) -> AsyncIterator[bytes]:
        self.streams_started += 1
        try:
            if self.fail_before_stream:
                raise UpstreamError("connection refused by 10.0.0.12:8443")
            events = [_sse(self._chunk({"role": "assistant", "content": ""}))]
            for payload in self._drain(events):
                yield payload
            for count, piece in enumerate(self._pieces()):
                if self.fail_after_deltas is not None and count == self.fail_after_deltas:
                    raise UpstreamError("upstream reset the connection (10.0.0.12)")
                if self.delay_s:
                    await asyncio.sleep(self.delay_s)
                events.append(_sse(self._chunk({"content": piece})))
                for payload in self._drain(events):
                    yield payload
            events.append(_sse(self._chunk({}, finish="stop")))
            events.append(_sse("[DONE]"))
            for payload in self._drain(events):
                yield payload
        finally:
            self.streams_closed += 1

    def _drain(self, events: list[bytes]) -> list[bytes]:
        data = b"".join(events)
        events.clear()
        if not self.fragment_bytes:
            return [data]
        return [data[i : i + self.fragment_bytes] for i in range(0, len(data), self.fragment_bytes)]

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        if self.fail_before_stream:
            raise UpstreamError("connection refused by 10.0.0.12:8443")
        return {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": 1700000000,
            "model": self.model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": self.reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": len(self.reply) // 4, "total_tokens": 10 + len(self.reply) // 4},
        }


class HttpChatProvider:
    """Proxies to an OpenAI-compatible ``/v1/chat/completions`` endpoint."""

    def __init__(self, base_url: str, api_key: str, model: str, *, client: httpx.AsyncClient | None = None) -> None:
        self._url = base_url.rstrip("/") + "/v1/chat/completions"
        self._headers = {"authorization": f"Bearer {api_key}"}
        self._model = model
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0, read=60.0))

    def _payload(self, body: dict[str, Any], stream: bool) -> dict[str, Any]:
        return {**body, "model": self._model, "stream": stream}

    async def stream(self, body: dict[str, Any]) -> AsyncIterator[bytes]:
        request = self._client.build_request("POST", self._url, json=self._payload(body, True), headers=self._headers)
        try:
            response = await self._client.send(request, stream=True)
        except httpx.TimeoutException:
            raise UpstreamTimeout from None
        except httpx.HTTPError:
            raise UpstreamError from None
        try:
            if response.status_code >= 400:
                raise UpstreamError(f"status {response.status_code}")
            async for chunk in response.aiter_bytes():
                yield chunk
        except httpx.TimeoutException:
            raise UpstreamTimeout from None
        except httpx.HTTPError:
            raise UpstreamError from None
        finally:
            await response.aclose()

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(self._url, json=self._payload(body, False), headers=self._headers)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            raise UpstreamTimeout from None
        except (httpx.HTTPError, ValueError):
            raise UpstreamError from None

    async def aclose(self) -> None:
        await self._client.aclose()

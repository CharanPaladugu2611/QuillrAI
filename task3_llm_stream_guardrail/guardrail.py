"""Applies the streaming redactor to an OpenAI-style chat completion event stream.

The guard inspects normal generated text (``choices[].delta.content`` and legacy
``choices[].text``) and streamed tool arguments
(``choices[].delta.tool_calls[].function.arguments``). Each choice and tool call has
an independent redactor, so PII remains protected when a provider splits it across
arbitrary SSE events. Held-back tails are released *before* ``finish_reason`` or the
closing ``[DONE]`` event, preserving ordering without accumulating the response.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import aclosing
from dataclasses import dataclass, field
from typing import Any

from .redactor import Engine, StreamRedactor, default_engine
from .sse import DEFAULT_MAX_EVENT_BYTES, SSEEvent, SSEParser, format_event

_TEXT = "text"
_TOOL = "tool"
RedactorKey = tuple[str, int, int]


@dataclass(frozen=True)
class GuardStats:
    events_in: int
    events_out: int
    redactions: int
    max_buffered: int
    by_detector: dict[str, int] = field(default_factory=dict)


class StreamGuard:
    """Feed upstream byte chunks to :meth:`process`; call :meth:`finish` when the stream ends.

    ``engine`` decides what is redacted (see :mod:`.detectors`); the default covers every
    built-in detector.
    """

    def __init__(self, max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES, engine: Engine | None = None) -> None:
        self._engine = engine or default_engine()
        self._parser = SSEParser(max_event_bytes)
        self._redactors: dict[RedactorKey, StreamRedactor] = {}
        self._template: dict[str, Any] = {}
        self._done = False
        self._events_in = 0
        self._events_out = 0

    @property
    def stats(self) -> GuardStats:
        redactors = self._redactors.values()
        by_detector: Counter[str] = Counter()
        for redactor in redactors:
            by_detector.update(redactor.stats.by_detector)
        return GuardStats(
            events_in=self._events_in,
            events_out=self._events_out,
            redactions=sum(r.stats.redactions for r in redactors),
            max_buffered=max((r.stats.max_buffered for r in redactors), default=0),
            by_detector=dict(by_detector),
        )

    # ------------------------------------------------------------------ public

    def process(self, chunk: bytes) -> list[bytes]:
        out: list[bytes] = []
        for event in self._parser.feed(chunk):
            out.extend(self._handle(event))
        return self._count(out)

    def finish(self, *, include_partial: bool = True) -> list[bytes]:
        """Release held text. ``include_partial=False`` drops a half-received event (after an error)."""
        out: list[bytes] = []
        trailing = self._parser.finish() if include_partial else None
        if trailing is not None:
            out.extend(self._handle(trailing))
        if not self._done:
            out.extend(self._release_tails())
        return self._count(out)

    # ------------------------------------------------------------------ internals

    def _count(self, out: list[bytes]) -> list[bytes]:
        self._events_out += len(out)
        return out

    def _redactor(self, key: RedactorKey) -> StreamRedactor:
        if key not in self._redactors:
            self._redactors[key] = StreamRedactor(self._engine)
        return self._redactors[key]

    @staticmethod
    def _text_key(choice_index: int) -> RedactorKey:
        return (_TEXT, choice_index, -1)

    @staticmethod
    def _tool_key(choice_index: int, tool_index: int) -> RedactorKey:
        return (_TOOL, choice_index, tool_index)

    def _release_tails(self) -> list[bytes]:
        events = []
        for (kind, choice_index, tool_index), redactor in sorted(self._redactors.items()):
            tail = redactor.flush()
            if not tail:
                continue
            if kind == _TEXT:
                delta = {"content": tail}
            else:
                delta = {"tool_calls": [{"index": tool_index, "function": {"arguments": tail}}]}
            chunk = {
                **self._template,
                "choices": [{"index": choice_index, "delta": delta, "finish_reason": None}],
            }
            events.append(format_event(json.dumps(chunk, separators=(",", ":"), ensure_ascii=False)))
        return events

    def _handle(self, event: SSEEvent) -> list[bytes]:
        self._events_in += 1
        if event.data is None:
            return [event.raw]  # comments / keep-alives
        payload = event.data.strip()
        if payload == "[DONE]":
            self._done = True
            return [*self._release_tails(), event.raw]
        try:
            chunk = json.loads(payload)
        except ValueError:
            return [event.raw]
        if not isinstance(chunk, dict) or not isinstance(chunk.get("choices"), list):
            return [event.raw]

        self._template = {k: v for k, v in chunk.items() if k not in ("choices", "usage")}
        changed = False
        all_empty = True
        for choice in chunk["choices"]:
            if not isinstance(choice, dict):
                all_empty = False
                continue
            choice_index = choice.get("index") if isinstance(choice.get("index"), int) else 0
            redactor = self._redactor(self._text_key(choice_index))
            holder = self._text_holder(choice)
            finished = choice.get("finish_reason") is not None
            if holder is not None:
                container, key = holder
                original = container[key]
                released = redactor.feed(original)
                if finished:
                    released += redactor.flush()
                if released != original:
                    container[key] = released
                    changed = True
            elif finished and redactor.pending:
                choice.setdefault("delta", {})["content"] = redactor.flush()
                changed = True

            for tool_index, function in self._tool_argument_holders(choice):
                tool_redactor = self._redactor(self._tool_key(choice_index, tool_index))
                original = function["arguments"]
                released = tool_redactor.feed(original)
                if finished:
                    released += tool_redactor.flush()
                if released != original:
                    function["arguments"] = released
                    changed = True

            if finished:
                changed = self._flush_tool_tails(choice, choice_index) or changed
            all_empty = all_empty and self._is_blank(choice)

        if not changed:
            return [event.raw]
        if all_empty and "usage" not in chunk and not event.extra_lines:
            return []  # everything in this event is being held back; nothing left to say
        return [format_event(json.dumps(chunk, separators=(",", ":"), ensure_ascii=False), event.extra_lines)]

    @staticmethod
    def _text_holder(choice: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
        delta = choice.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("content"), str):
            return delta, "content"
        if isinstance(choice.get("text"), str):
            return choice, "text"
        return None

    @staticmethod
    def _tool_argument_holders(choice: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
        delta = choice.get("delta")
        calls = delta.get("tool_calls") if isinstance(delta, dict) else None
        if not isinstance(calls, list):
            return []
        holders: list[tuple[int, dict[str, Any]]] = []
        for position, call in enumerate(calls):
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if not isinstance(function, dict) or not isinstance(function.get("arguments"), str):
                continue
            tool_index = call.get("index") if isinstance(call.get("index"), int) else position
            holders.append((tool_index, function))
        return holders

    def _flush_tool_tails(self, choice: dict[str, Any], choice_index: int) -> bool:
        """Attach any tool-argument tails to the choice's final event."""
        pending: list[tuple[int, str]] = []
        for (kind, owner, tool_index), redactor in sorted(self._redactors.items()):
            if kind == _TOOL and owner == choice_index and redactor.pending:
                tail = redactor.flush()
                if tail:
                    pending.append((tool_index, tail))
        if not pending:
            return False

        delta = choice.setdefault("delta", {})
        if not isinstance(delta, dict):
            delta = {}
            choice["delta"] = delta
        calls = delta.setdefault("tool_calls", [])
        if not isinstance(calls, list):
            calls = []
            delta["tool_calls"] = calls

        existing: dict[int, dict[str, Any]] = {}
        for position, call in enumerate(calls):
            if isinstance(call, dict):
                index = call.get("index") if isinstance(call.get("index"), int) else position
                existing[index] = call

        for tool_index, tail in pending:
            call = existing.get(tool_index)
            if call is None:
                call = {"index": tool_index, "function": {}}
                calls.append(call)
                existing[tool_index] = call
            function = call.setdefault("function", {})
            if not isinstance(function, dict):
                function = {}
                call["function"] = function
            function["arguments"] = str(function.get("arguments", "")) + tail
        return True

    @staticmethod
    def _is_blank(choice: dict[str, Any]) -> bool:
        """True when the choice now carries no text and nothing else worth sending."""
        if choice.get("finish_reason") is not None:
            return False
        delta = choice.get("delta")
        if isinstance(delta, dict):
            if set(delta) - {"content", "tool_calls"}:
                return False
            if delta.get("content") not in (None, ""):
                return False
            calls = delta.get("tool_calls", [])
            if not isinstance(calls, list):
                return False
            for call in calls:
                if not isinstance(call, dict) or set(call) - {"index", "function"}:
                    return False
                function = call.get("function")
                if not isinstance(function, dict) or set(function) - {"arguments"}:
                    return False
                if function.get("arguments") not in (None, ""):
                    return False
            return True
        return choice.get("text") == "" and set(choice) <= {"index", "text", "finish_reason", "logprobs"}


async def guard_stream(
    upstream: AsyncIterator[bytes], guard: StreamGuard | None = None
) -> AsyncIterator[bytes]:
    """Redact an upstream SSE byte stream, yielding as soon as output is safe to release."""
    guard = guard or StreamGuard()
    async with aclosing(upstream) as source:  # closes the provider call on early exit or disconnect
        async for chunk in source:
            for out in guard.process(chunk):
                yield out
        for out in guard.finish():
            yield out

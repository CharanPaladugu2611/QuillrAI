"""Applies the streaming redactor to an OpenAI-style chat completion event stream.

Every field a provider uses to carry generated text is inspected:

* ``choices[].delta.<field>`` for each name in :data:`TEXT_FIELDS` (the answer, a refusal and
  the reasoning a model exposes) and the legacy ``choices[].text``;
* streamed tool arguments (``choices[].delta.tool_calls[].function.arguments``) and the legacy
  ``choices[].delta.function_call.arguments``.

Each of those is a separate stream of text with its own redactor, so PII remains protected
when a provider splits it across arbitrary SSE events or interleaves fields. ``logprobs`` can
not be redacted token by token (a value spans several tokens and the token strings repeat the
text), so it is replaced by ``null``. Held-back tails are released *before* ``finish_reason``
or the closing ``[DONE]`` event, preserving ordering without accumulating the response.
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

TEXT_FIELDS = ("content", "refusal", "reasoning_content", "reasoning")
"""Names under which a delta, or a complete message, carries generated text."""

_TEXT = "text"
_FUNCTION = "function_call"
_TOOL = "tool"
RedactorKey = tuple[str, int, str | int]  # (kind, choice index, field name or tool index)
_BLANK_DELTA_KEYS = frozenset({*TEXT_FIELDS, "tool_calls", "function_call"})


@dataclass(frozen=True)
class GuardStats:
    events_in: int
    events_out: int
    redactions: int
    max_buffered: int
    by_detector: dict[str, int] = field(default_factory=dict)


def _joined(existing: Any, tail: str) -> str:
    return (existing if isinstance(existing, str) else "") + tail


def _tool_index(call: dict[str, Any], position: int) -> int:
    index = call.get("index")
    return index if isinstance(index, int) else position


def _place(choice: dict[str, Any], key: RedactorKey, tail: str) -> None:
    """Write a released ``tail`` where the stream for ``key`` carries its text."""
    kind, _, name = key
    if kind == _TEXT and name == "text":  # legacy completions keep the text on the choice itself
        choice["text"] = _joined(choice.get("text"), tail)
        return
    delta = choice.get("delta")
    if not isinstance(delta, dict):
        delta = choice["delta"] = {}
    if kind == _TEXT:
        delta[name] = _joined(delta.get(name), tail)
    elif kind == _FUNCTION:
        call = delta.get("function_call")
        if not isinstance(call, dict):
            call = delta["function_call"] = {}
        call["arguments"] = _joined(call.get("arguments"), tail)
    else:
        calls = delta.get("tool_calls")
        if not isinstance(calls, list):
            calls = delta["tool_calls"] = []
        for position, call in enumerate(calls):
            if isinstance(call, dict) and _tool_index(call, position) == name:
                function = call.get("function")
                if not isinstance(function, dict):
                    function = call["function"] = {}
                function["arguments"] = _joined(function.get("arguments"), tail)
                return
        calls.append({"index": name, "function": {"arguments": tail}})


def _string_holders(choice: dict[str, Any], choice_index: int) -> list[tuple[RedactorKey, dict[str, Any], str]]:
    """Every string in ``choice`` that is a piece of generated text, as (stream, container, key)."""
    holders: list[tuple[RedactorKey, dict[str, Any], str]] = []
    delta = choice.get("delta")
    if isinstance(delta, dict):
        for name in TEXT_FIELDS:
            if isinstance(delta.get(name), str):
                holders.append(((_TEXT, choice_index, name), delta, name))
        call = delta.get("function_call")
        if isinstance(call, dict) and isinstance(call.get("arguments"), str):
            holders.append(((_FUNCTION, choice_index, "arguments"), call, "arguments"))
        tool_calls = delta.get("tool_calls")
        if isinstance(tool_calls, list):
            for position, tool in enumerate(tool_calls):
                function = tool.get("function") if isinstance(tool, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    holders.append(((_TOOL, choice_index, _tool_index(tool, position)), function, "arguments"))
    if isinstance(choice.get("text"), str):
        holders.append(((_TEXT, choice_index, "text"), choice, "text"))
    return holders


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

    def _release_tails(self) -> list[bytes]:
        events = []
        for key, redactor in sorted(self._redactors.items()):
            tail = redactor.flush()
            if not tail:
                continue
            choice: dict[str, Any] = {"index": key[1]}
            _place(choice, key, tail)
            choice["finish_reason"] = None
            chunk = {**self._template, "choices": [choice]}
            events.append(format_event(json.dumps(chunk, separators=(",", ":"), ensure_ascii=False)))
        return events

    def _release_choice_tails(self, choice: dict[str, Any], choice_index: int, carried: set[RedactorKey]) -> bool:
        """On a choice's final event, add the held text of every stream that event did not carry."""
        placed = False
        for key, redactor in sorted(self._redactors.items()):
            if key[1] == choice_index and key not in carried and redactor.pending:
                tail = redactor.flush()
                if tail:
                    _place(choice, key, tail)
                    placed = True
        return placed

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
            finished = choice.get("finish_reason") is not None

            if choice.get("logprobs") is not None:
                choice["logprobs"] = None  # token strings repeat the text and cannot be redacted one by one
                changed = True

            carried: set[RedactorKey] = set()
            for key, container, name in _string_holders(choice, choice_index):
                redactor = self._redactor(key)
                carried.add(key)
                original = container[name]
                released = redactor.feed(original)
                if finished:
                    released += redactor.flush()
                if released != original:
                    container[name] = released
                    changed = True

            if finished:
                changed = self._release_choice_tails(choice, choice_index, carried) or changed
            all_empty = all_empty and self._is_blank(choice)

        if not changed:
            return [event.raw]
        if all_empty and "usage" not in chunk and not event.extra_lines:
            return []  # everything in this event is being held back; nothing left to say
        return [format_event(json.dumps(chunk, separators=(",", ":"), ensure_ascii=False), event.extra_lines)]

    @staticmethod
    def _is_blank(choice: dict[str, Any]) -> bool:
        """True when the choice now carries no text and nothing else worth sending."""
        if choice.get("finish_reason") is not None:
            return False
        delta = choice.get("delta")
        if isinstance(delta, dict):
            if set(delta) - _BLANK_DELTA_KEYS:
                return False
            if any(delta.get(name) not in (None, "") for name in TEXT_FIELDS):
                return False
            call = delta.get("function_call")
            if call is not None and (
                not isinstance(call, dict) or set(call) - {"arguments"} or call.get("arguments") not in (None, "")
            ):
                return False
            calls = delta.get("tool_calls", [])
            if not isinstance(calls, list):
                return False
            for tool in calls:
                if not isinstance(tool, dict) or set(tool) - {"index", "function"}:
                    return False
                function = tool.get("function")
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

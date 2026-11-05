"""Incremental Server-Sent Events parsing.

Network reads can end anywhere, including in the middle of an event or of a multi-byte
character. The parser therefore buffers *bytes* until a complete event terminator is
seen and only then decodes, so a split character can never corrupt a delta. Memory is
bounded by ``max_event_bytes``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

_TERMINATOR = re.compile(rb"\r\n\r\n|\n\n|\r\r")
DEFAULT_MAX_EVENT_BYTES = 1_048_576


class SSEProtocolError(Exception):
    """An event grew past the size limit without terminating."""


@dataclass
class SSEEvent:
    raw: bytes
    data: str | None = None
    extra_lines: list[str] = field(default_factory=list)  # event:, id:, retry: and comments


def format_event(data: str, extra_lines: list[str] | None = None) -> bytes:
    lines = [*(extra_lines or []), *(f"data: {part}" for part in data.split("\n"))]
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _parse_event(raw: bytes) -> SSEEvent:
    data_lines: list[str] = []
    extra: list[str] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line:
            continue
        if line.startswith(":"):
            extra.append(line)
            continue
        name, _, value = line.partition(":")
        if name == "data":
            data_lines.append(value[1:] if value.startswith(" ") else value)
        else:
            extra.append(line)
    return SSEEvent(raw=raw, data="\n".join(data_lines) if data_lines else None, extra_lines=extra)


class SSEParser:
    def __init__(self, max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES) -> None:
        self._buffer = bytearray()
        self._scan_from = 0
        self._max = max_event_bytes

    def feed(self, chunk: bytes) -> Iterator[SSEEvent]:
        self._buffer += chunk
        while True:
            match = _TERMINATOR.search(self._buffer, self._scan_from)
            if match is None:
                if len(self._buffer) > self._max:
                    raise SSEProtocolError("event exceeds size limit")
                self._scan_from = max(len(self._buffer) - 3, 0)  # a terminator may straddle the next read
                return
            raw = bytes(self._buffer[: match.end()])
            del self._buffer[: match.end()]
            self._scan_from = 0
            yield _parse_event(raw)

    def finish(self) -> SSEEvent | None:
        """A trailing event the upstream never terminated; delivered rather than dropped."""
        if not self._buffer.strip():
            return None
        raw = bytes(self._buffer)
        self._buffer.clear()
        return _parse_event(raw + b"\n\n")

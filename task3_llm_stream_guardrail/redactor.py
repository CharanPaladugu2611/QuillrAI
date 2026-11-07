"""Incremental redaction of sensitive values in text that arrives in arbitrary fragments.

What counts as sensitive is decided by *detectors* (see :mod:`.detectors`): e-mail
addresses, phone numbers, card and bank numbers, national ids, IP and MAC addresses, API
keys and other credentials, labelled values such as ``passport X1234567``, plus whatever
word lists, patterns or models an operator adds. The engine here knows nothing about any of
them; it only combines their answers. Each match becomes ``[REDACTED]``.

Streaming
---------
Every detector reports where a match might still be growing (``pending``). The engine holds
back the text from the earliest such point and releases everything before it, so in ordinary
prose only the last word is held and the cost is about one token of latency. A release point
is also never allowed to fall inside a match that is already complete, and detectors see a few
characters of already-released text so their look-behind assertions behave exactly as they
would on the whole text. The result is that the streamed output is identical to redacting the
whole text at once, whatever the chunk boundaries.

Memory never depends on the length of the response: no detector ever asks to hold more than
its ``max_span`` (plus a few characters of look-ahead), so the engine holds at most about
``2 * max_span``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from .detectors import Detector, default_detectors
from .detectors.base import LOOKAHEAD_CHARS, hold_floor
from .detectors.contact import (  # noqa: F401  (re-exported limits)
    MAX_EMAIL_DOMAIN_LABELS,
    MAX_EMAIL_LABEL_CHARS,
    MAX_EMAIL_LOCAL_CHARS,
    MAX_EMAIL_MATCH_CHARS,
    MAX_EMAIL_TLD_CHARS,
)
from .detectors.financial import MAX_CARD_DIGITS, MAX_CARD_MATCH_CHARS, MAX_SSN_MATCH_CHARS  # noqa: F401

REPLACEMENT = "[REDACTED]"

Found = tuple[int, int, str]  # begin, end, detector name


class Engine:
    """An immutable set of detectors plus the rules for combining them. Safe to share."""

    def __init__(self, detectors: Sequence[Detector], *, replacement: str = REPLACEMENT) -> None:
        if not detectors:
            raise ValueError("at least one detector is required")
        names = [d.name for d in detectors]
        if len(set(names)) != len(names):
            raise ValueError(f"detector names must be unique: {sorted(n for n in names if names.count(n) > 1)}")
        self.detectors = tuple(detectors)
        self.replacement = replacement
        self.max_span = max(d.max_span for d in self.detectors)
        self.hold_bound = 2 * (self.max_span + LOOKAHEAD_CHARS)
        self.context_chars = max(1, max(d.lookbehind for d in self.detectors))

    # ------------------------------------------------------------------ one-shot

    def find(self, text: str, start: int = 0) -> list[Found]:
        """Merged, ordered matches in ``text`` that begin at or after ``start``."""
        found: list[Found] = []
        for detector in self.detectors:
            found.extend((begin, end, detector.name) for begin, end in detector.spans(text, start))
        if not found:
            return []
        found.sort(key=lambda item: (item[0], -item[1]))
        merged = [found[0]]
        for begin, end, name in found[1:]:
            last_begin, last_end, last_name = merged[-1]
            if begin < last_end:
                if end > last_end:
                    merged[-1] = (last_begin, end, last_name)
            else:
                merged.append((begin, end, name))
        return merged

    def label(self, name: str) -> str:
        return self.replacement.replace("{label}", name)

    def redact(self, text: str) -> tuple[str, Counter[str]]:
        """Redact a complete string. Returns the text and the number of matches per detector."""
        return self.render(text, 0, len(text), self.find(text))

    def render(self, text: str, start: int, stop: int, found: list[Found]) -> tuple[str, Counter[str]]:
        pieces: list[str] = []
        counts: Counter[str] = Counter()
        position = start
        for begin, end, name in found:
            if end <= start:
                continue
            if begin >= stop:
                break
            pieces.append(text[position : max(begin, position)])
            pieces.append(self.label(name))
            counts[name] += 1
            position = max(position, end)
        pieces.append(text[position:stop])
        return "".join(pieces), counts

    # ------------------------------------------------------------------ streaming

    def stream(self) -> StreamRedactor:
        return StreamRedactor(self)

    def release_point(self, text: str, start: int, found: list[Found]) -> int:
        """Largest index such that ``text[:index]`` is final and no match can straddle it."""
        n = len(text)
        cut = n
        for detector in self.detectors:
            cut = min(cut, detector.pending(text, start))
        cut = max(cut, start, hold_floor(n, self.max_span))  # bounded hold, whatever a detector says
        for begin, end, _ in found:
            if begin < cut < end:
                return max(begin, start)
            if begin >= cut:
                break
        return cut


@dataclass
class RedactorStats:
    redactions: int = 0
    max_buffered: int = 0
    by_detector: Counter[str] = field(default_factory=Counter)


class StreamRedactor:
    """Feed fragments in, get redacted text out; call :meth:`flush` when the stream ends."""

    def __init__(self, engine: Engine | None = None) -> None:
        self._engine = engine or default_engine()
        self._context = ""  # the last few characters already released, for look-behind
        self._held = ""
        self.stats = RedactorStats()

    @property
    def pending(self) -> int:
        return len(self._held)

    def feed(self, fragment: str) -> str:
        if not fragment:
            return ""
        engine = self._engine
        start = len(self._context)
        text = self._context + self._held + fragment
        found = engine.find(text, start)
        cut = engine.release_point(text, start, found)
        released, counts = engine.render(text, start, cut, found)
        self._context = text[max(0, cut - engine.context_chars) : cut]
        self._held = text[cut:]
        self.stats.max_buffered = max(self.stats.max_buffered, len(self._held))
        self._count(counts)
        return released

    def flush(self) -> str:
        engine = self._engine
        start = len(self._context)
        text = self._context + self._held
        released, counts = engine.render(text, start, len(text), engine.find(text, start))
        self._context = ""
        self._held = ""
        self._count(counts)
        return released

    def _count(self, counts: Counter[str]) -> None:
        self.stats.by_detector.update(counts)
        self.stats.redactions += sum(counts.values())


# --------------------------------------------------------------------------- defaults


@lru_cache(maxsize=1)
def default_engine() -> Engine:
    return Engine(default_detectors())


def redact_text(text: str, engine: Engine | None = None) -> tuple[str, int]:
    """Redact a complete string. Returns ``(redacted, number_of_matches)``."""
    redacted, counts = (engine or default_engine()).redact(text)
    return redacted, sum(counts.values())


MAX_HOLD = default_engine().max_span
HOLD_BOUND = default_engine().hold_bound

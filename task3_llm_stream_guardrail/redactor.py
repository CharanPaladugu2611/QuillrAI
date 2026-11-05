"""Incremental PII redaction for text that arrives in arbitrary fragments.

Detected: e-mail addresses, US social security numbers (``123-45-6789``) and payment
card numbers (13-19 digits, optional single spaces or dashes between digits, Luhn
checked). Each match becomes ``[REDACTED]``.

Streaming strategy
------------------
Text is released as soon as no pattern can still be completed by future input, so the
only thing ever held back is a short tail:

* an e-mail address lives inside a maximal run of ``E`` characters (letters, digits and
  ``._%+-@``);
* a card or SSN lives inside a maximal run of ``D`` characters (digits, space, ``-``), from
  its first digit onward.

A run that touches the end of the buffer may still grow, so it is held; everything
before it is final. The release point is also never allowed to fall *inside* a run, which
is what keeps the output identical to redacting the whole text at once, whatever the
chunk boundaries. In ordinary prose the held tail is the last word, so latency cost is
roughly one token. Supported matches have explicit maximum lengths. Pathological input
with no delimiters at all is bounded by ``HOLD_BOUND`` characters (about 1.2 KB), so
memory never depends on response length. Inputs longer than the supported match limits
are not classified as PII merely because they contain a valid-looking suffix.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

REPLACEMENT = "[REDACTED]"

# Explicit detection limits. The longest supported e-mail is:
# 64 local chars + "@" + 8 labels of 63 chars and their dots + a 24-letter TLD.
MAX_EMAIL_LOCAL_CHARS = 64
MAX_EMAIL_DOMAIN_LABELS = 8
MAX_EMAIL_LABEL_CHARS = 63
MAX_EMAIL_TLD_CHARS = 24
MAX_EMAIL_MATCH_CHARS = 601
MAX_CARD_DIGITS = 19
MAX_CARD_MATCH_CHARS = 37  # 19 digits plus at most 18 one-character separators
MAX_SSN_MATCH_CHARS = 11
MAX_SUPPORTED_PII_CHARS = max(MAX_EMAIL_MATCH_CHARS, MAX_CARD_MATCH_CHARS, MAX_SSN_MATCH_CHARS)

MAX_MATCH_LEN = MAX_SUPPORTED_PII_CHARS
MAX_HOLD = MAX_MATCH_LEN
# A forced release may have to back up over one complete match that straddles it.
HOLD_BOUND = MAX_HOLD + MAX_MATCH_LEN

_EMAIL = (
    r"(?P<email>(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24})"
    r"(?!(?:[A-Za-z0-9_+%\-@]|\.[A-Za-z0-9]))"
)
_NUMBER_LEFT = r"(?<![0-9])(?<![0-9][ \-])"
_NUMBER_RIGHT = r"(?![0-9])(?![ \-][0-9])"
_CARD = rf"(?P<card>{_NUMBER_LEFT}(?:[0-9][ \-]?){{12,18}}[0-9]{_NUMBER_RIGHT})"
_SSN = rf"(?P<ssn>{_NUMBER_LEFT}[0-9]{{3}}-[0-9]{{2}}-[0-9]{{4}}{_NUMBER_RIGHT})"

_ALL = re.compile(f"{_EMAIL}|{_CARD}|{_SSN}")
_EMAIL_ONLY = re.compile(_EMAIL)
_NUMBERS_ONLY = re.compile(f"{_CARD}|{_SSN}")
_HAS_DIGIT = re.compile(r"[0-9]")

_E_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-@")
_D_CHARS = frozenset("0123456789 -")
_DIGITS = frozenset("0123456789")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_end(text: str, start: int, end: int) -> int | None:
    """End of the longest Luhn-valid card number starting at ``start`` inside the candidate.

    The candidate is greedy, so a valid number followed by a stray group of digits
    ("4111 1111 1111 1111 12") would otherwise slip through; shorter prefixes that end on
    a group boundary are tried too.
    """
    digit_ends = [i + 1 for i in range(start, end) if text[i] in _DIGITS]
    for count in range(len(digit_ends), 12, -1):
        stop = digit_ends[count - 1]
        if stop < end and text[stop] in _DIGITS:
            continue  # prefix would end mid-number
        digits = "".join(c for c in text[start:stop] if c in _DIGITS)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return stop
    return None


def _select_pattern(text: str) -> re.Pattern[str] | None:
    has_at = "@" in text
    has_digit = _HAS_DIGIT.search(text) is not None
    if has_at and has_digit:
        return _ALL
    if has_at:
        return _EMAIL_ONLY
    return _NUMBERS_ONLY if has_digit else None


def _iter_matches(text: str, pattern: re.Pattern[str]) -> Iterator[tuple[int, int]]:
    """Spans that will be redacted: regex hits, minus card-shaped numbers that fail Luhn."""
    scan_from = 0
    while True:
        match = pattern.search(text, scan_from)
        if match is None:
            return
        start, end = match.span()
        if match.lastgroup == "card":
            card_end = _card_end(text, start, end)
            if card_end is None:
                scan_from = start + 1  # not a card; allow other patterns to start inside it
                continue
            end = card_end
        yield start, end
        scan_from = end


def redact_text(text: str) -> tuple[str, int]:
    """Redact a complete string. Returns ``(redacted, number_of_matches)``."""
    pattern = _select_pattern(text)
    if pattern is None:
        return text, 0
    pieces: list[str] = []
    copied_to = count = 0
    for start, end in _iter_matches(text, pattern):
        pieces.append(text[copied_to:start])
        pieces.append(REPLACEMENT)
        copied_to = end
        count += 1
    pieces.append(text[copied_to:])
    return "".join(pieces), count


def _run_start(buffer: str, end: int, chars: frozenset[str]) -> int:
    while end > 0 and buffer[end - 1] in chars:
        end -= 1
    return end


def _number_anchor(buffer: str, end: int) -> int:
    """Start of the first digit in the run of digits/spaces/dashes ending at ``end``.

    Cards and SSNs begin and end with a digit, so spaces or dashes in front of the first
    digit can never be part of a match and need not be held back. Returns ``end`` when the
    run holds no digit.
    """
    start = _run_start(buffer, end, _D_CHARS)
    while start < end and buffer[start] not in _DIGITS:
        start += 1
    return start


def _release_point(buffer: str) -> int:
    """Largest index such that ``buffer[:index]`` is final and no pattern can straddle it."""
    size = len(buffer)
    cut = min(_run_start(buffer, size, _E_CHARS), _number_anchor(buffer, size))
    while 0 < cut < size:
        if buffer[cut - 1] in _E_CHARS and buffer[cut] in _E_CHARS:
            cut = _run_start(buffer, cut, _E_CHARS)
        elif buffer[cut - 1] in _D_CHARS and buffer[cut] in _D_CHARS and _number_anchor(buffer, cut) < cut:
            cut = _number_anchor(buffer, cut)
        else:
            break

    if size - cut > MAX_HOLD:
        # Delimiter-free input: stop holding, but never split a match that is already complete.
        cut = size - MAX_HOLD
        # Candidate spans are enough here (no Luhn pass): cheap, and at worst it holds a little more.
        for match in _ALL.finditer(buffer):
            if match.start() < cut < match.end():
                cut = match.start()
                break
    return cut


@dataclass
class RedactorStats:
    redactions: int = 0
    max_buffered: int = 0


class StreamRedactor:
    """Feed fragments in, get redacted text out; call :meth:`flush` when the stream ends."""

    def __init__(self) -> None:
        self._held = ""
        self.stats = RedactorStats()

    @property
    def pending(self) -> int:
        return len(self._held)

    def feed(self, fragment: str) -> str:
        if not fragment:
            return ""
        buffer = self._held + fragment
        cut = _release_point(buffer)
        self._held = buffer[cut:]
        self.stats.max_buffered = max(self.stats.max_buffered, len(self._held))
        if cut == 0:
            return ""
        released, count = redact_text(buffer[:cut])
        self.stats.redactions += count
        return released

    def flush(self) -> str:
        released, count = redact_text(self._held)
        self._held = ""
        self.stats.redactions += count
        return released

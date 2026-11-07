"""Payment cards, US social security numbers and IBANs."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .base import RegexDetector, Span, hold_floor, not_in, run_start

MAX_CARD_DIGITS = 19
MAX_CARD_MATCH_CHARS = 37  # 19 digits plus at most 18 one-character separators
MAX_SSN_MATCH_CHARS = 11
MAX_IBAN_CHARS = 42  # 34 characters plus the spaces that group them

_DIGITS = frozenset("0123456789")
_NOT_NUMBER = not_in(r"0-9 \-")

# A number must not be glued to more digits, nor continue after a separator.
_NUMBER_LEFT = r"(?<![0-9])(?<![0-9][ \-])"
_NUMBER_RIGHT = r"(?![0-9])(?![ \-][0-9])"
_CARD = re.compile(rf"{_NUMBER_LEFT}(?:[0-9][ \-]?){{12,18}}[0-9]{_NUMBER_RIGHT}")
_SSN = rf"{_NUMBER_LEFT}[0-9]{{3}}-[0-9]{{2}}-[0-9]{{4}}{_NUMBER_RIGHT}"
_HAS_DIGIT = re.compile(r"[0-9]")


def luhn_valid(digits: str) -> bool:
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
        if 13 <= len(digits) <= MAX_CARD_DIGITS and luhn_valid(digits):
            return stop
    return None


class CardDetector:
    """Payment card numbers: 13-19 digits, single spaces or dashes allowed, Luhn-checked."""

    name = "card"
    max_span = MAX_CARD_MATCH_CHARS
    lookbehind = 2

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        if _HAS_DIGIT.search(text, start) is None:
            return
        position = start
        while True:
            match = _CARD.search(text, position)
            if match is None:
                return
            begin, end = match.span()
            stop = _card_end(text, begin, end)
            if stop is None:
                position = begin + 1  # not a card; let anything starting inside it be tried
                continue
            yield begin, stop
            position = stop

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        i = run_start(text, start, hold_floor(n, self.max_span), _NOT_NUMBER)
        while i < n and text[i] not in _DIGITS:
            i += 1  # separators in front of the first digit cannot belong to a number
        return i


def ssn() -> RegexDetector:
    """US social security numbers written with dashes: ``123-45-6789``."""
    return RegexDetector(
        "ssn",
        _SSN,
        max_span=MAX_SSN_MATCH_CHARS,
        trigger=r"[0-9]-[0-9]",
        run=r"0-9 \-",
        anchor=r"0-9",
        lookbehind=2,
    )


# --------------------------------------------------------------------------- IBAN

_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])"
)
_IBAN_PREFIX = re.compile(
    r"(?<![A-Za-z0-9])[A-Z](?:[A-Z](?:[0-9](?:[0-9](?:(?: ?[A-Z0-9]{4}){0,7}(?: ?[A-Z0-9]{0,3})?)?)?)?)?\Z"
)


def iban_valid(candidate: str) -> bool:
    compact = candidate.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(char, 36)) for char in rearranged)
    return int(number) % 97 == 1


class IbanDetector:
    """International bank account numbers, validated with the ISO 13616 checksum."""

    name = "iban"
    max_span = MAX_IBAN_CHARS
    lookbehind = 1

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        while True:
            match = _IBAN.search(text, position)
            if match is None:
                return
            if iban_valid(match.group()):
                yield match.span()
                position = match.end()
            else:
                position = match.start() + 1

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        match = _IBAN_PREFIX.search(text, max(start, hold_floor(n, self.max_span)))
        return match.start() if match else n

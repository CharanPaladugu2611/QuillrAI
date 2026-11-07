"""How people can be reached: e-mail addresses (plain and disguised) and telephone numbers."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .base import RegexDetector, Span, hold_floor, not_in, prefix_pattern, run_start

# Explicit limits: values longer than these are not matched.
MAX_EMAIL_LOCAL_CHARS = 64
MAX_EMAIL_DOMAIN_LABELS = 8
MAX_EMAIL_LABEL_CHARS = 63
MAX_EMAIL_TLD_CHARS = 24
MAX_EMAIL_MATCH_CHARS = 601  # 64 + "@" + 8 labels of 63 chars and a dot each + a 24-letter TLD

_AT_SIGNS = "@＠﹫"  # @, full-width @, small @
_AT_SIGN = re.compile(f"[{_AT_SIGNS}]")

_LOCAL = r"[\w.%+\-]{1,64}"
_LABEL = r"[^\W_](?:[\w\-]{0,61}[^\W_])?"
_EMAIL = (
    rf"(?<![\w.%+\-]){_LOCAL}[{_AT_SIGNS}]"
    rf"(?:{_LABEL}\.){{1,8}}(?:[^\W\d_]{{2,24}}|xn--[A-Za-z0-9]{{1,20}})"
    rf"(?![\w+%\-{_AT_SIGNS}]|\.\w)"
)


class EmailDetector(RegexDetector):
    """Addresses such as ``jeff@aloha.com``; Unicode letters are fine, so is ``josé@münchen.de``."""

    def __init__(self) -> None:
        super().__init__(
            "email",
            _EMAIL,
            max_span=MAX_EMAIL_MATCH_CHARS,
            trigger=f"[{_AT_SIGNS}]",
            run=r"\w.%+\-" + _AT_SIGNS,
            lookbehind=1,
        )

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        s = super().pending(text, start)  # start of the trailing run of address characters
        # A match starts at the run start or right after an @ sign, and its local part is at most
        # 64 characters long: a longer stretch with no @ in reach cannot become an address.
        while s < n:
            at = _AT_SIGN.search(text, s)
            if at is None:
                return s if n - s <= MAX_EMAIL_LOCAL_CHARS else n
            if at.start() - s <= MAX_EMAIL_LOCAL_CHARS:
                return s
            s = at.end()
        return n


# --------------------------------------------------------------------------- disguised e-mail

_SP = r"[ \t ]"
_OPEN, _CLOSE = r"[\[({<]", r"[\])}>]"
_AT = (
    rf"(?:{_SP}{{0,2}}{_OPEN}{_SP}{{0,2}}at{_SP}{{0,2}}{_CLOSE}{_SP}{{0,2}}"
    rf"|{_SP}{{1,2}}at{_SP}{{1,2}}|[{_AT_SIGNS}])"
)
_DOT = (
    rf"(?:{_SP}{{0,2}}{_OPEN}{_SP}{{0,2}}dot{_SP}{{0,2}}{_CLOSE}{_SP}{{0,2}}"
    rf"|{_SP}{{1,2}}dot{_SP}{{1,2}}|\.)"
)
_OBFUSCATED = re.compile(
    rf"(?<![\w.%+\-])(?P<local>{_LOCAL})(?P<at>{_AT})"
    rf"(?P<rest>{_LABEL}(?:{_DOT}{_LABEL}){{0,3}}{_DOT}(?P<tld>[^\W\d_]{{2,24}}))(?!\w|\.\w)",
    re.IGNORECASE,
)
_WORD_DOT = re.compile(rf"{_SP}dot{_SP}", re.IGNORECASE)
_BRACKET_DOT = re.compile(rf"{_OPEN}{_SP}{{0,2}}dot", re.IGNORECASE)
_BRACKET_AT = re.compile(_OPEN)
_NOT_LOCAL = not_in(r"\w.%+\-")
_COMMON_TLDS = frozenset(
    "com org net edu gov mil int info biz io co ai app dev me us uk de fr es it nl ca au in jp cn ru br ch "
    "se no fi dk be pl eu xyz online site tech cloud ie nz za mx ar kr sg hk tw tv cc ly".split()
)
MAX_OBFUSCATED_EMAIL_CHARS = 410  # 64 + marker + 5 labels (63) + 4 markers (<=14) + 24-letter TLD, rounded up


def _partial_at() -> str:
    word = prefix_pattern([rf"{_SP}{{1,2}}", "a", "t", rf"{_SP}{{1,2}}"])
    bracket = prefix_pattern(
        [rf"{_SP}{{0,2}}", _OPEN, rf"{_SP}{{0,2}}", "a", "t", rf"{_SP}{{0,2}}", _CLOSE, rf"{_SP}{{0,2}}"]
    )
    return f"(?:{word}|{bracket})"


def _partial_dot() -> str:
    word = prefix_pattern([rf"{_SP}{{1,2}}", "d", "o", "t", rf"{_SP}{{1,2}}"])
    bracket = prefix_pattern(
        [rf"{_SP}{{0,2}}", _OPEN, rf"{_SP}{{0,2}}", "d", "o", "t", rf"{_SP}{{0,2}}", _CLOSE, rf"{_SP}{{0,2}}"]
    )
    return f"(?:{word}|{bracket})"


def _prefix_regex() -> re.Pattern[str]:
    """Matches, up to the end of the text, anything that could still grow into a disguised address."""
    label = r"[^\W_][\w\-]{0,62}"
    tail = ""
    for _ in range(5):  # label (dot label){0,3} dot tld
        tail = rf"(?:{label}(?:{_partial_dot()}|{_DOT}{tail})?)?"
    return re.compile(
        rf"(?<![\w.%+\-]){_LOCAL}(?:{_partial_at()}|{_AT}{tail})?\Z",
        re.IGNORECASE,
    )


class ObfuscatedEmailDetector:
    """Addresses written to dodge filters: ``jeff at aloha dot com``, ``jeff[at]aloha.com``.

    Ordinary phrases such as ``look at example.com`` are left alone: a bare ``at`` needs a
    spelled-out ``dot`` after it, and a bare word needs a well-known top-level domain.
    """

    name = "email_obfuscated"
    max_span = MAX_OBFUSCATED_EMAIL_CHARS
    lookbehind = 1

    def __init__(self) -> None:
        self._prefix = _prefix_regex()
        self._signs = re.compile(rf"(?<!\w)at(?!\w)|[{_AT_SIGNS}\[({{<]|{_SP}a\Z", re.IGNORECASE)

    @staticmethod
    def _accepted(match: re.Match[str]) -> bool:
        at, rest, tld = match["at"], match["rest"], match["tld"].lower()
        at_bracket = bool(_BRACKET_AT.search(at))
        dot_word = bool(_WORD_DOT.search(rest))
        dot_bracket = bool(_BRACKET_DOT.search(rest))
        if not (at_bracket or dot_word or dot_bracket):
            return False  # nothing is disguised ("a@b.com" is the e-mail detector's, "at x.com" is prose)
        return at_bracket or dot_bracket or tld in _COMMON_TLDS

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        while True:
            match = _OBFUSCATED.search(text, position)
            if match is None:
                return
            if self._accepted(match):
                yield match.span()
                position = match.end()
            else:
                position = match.start() + 1

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        low = max(start, hold_floor(n, self.max_span))
        if self._signs.search(text, low) is None:
            # only a plain local part (plus trailing spaces) can still become an address
            end = n
            while end > low and text[end - 1] in " \t ":
                end -= 1
            begin = run_start(text[:end], start, end - 64, _NOT_LOCAL)
            return begin if begin < end else n
        match = self._prefix.search(text, low)
        return match.start() if match else n


# --------------------------------------------------------------------------- telephone numbers

_PL = r"(?<![\w+])(?<!\d[ .\-])"
_PR = r"(?!\w)(?![ .\-]\d)"
_SEP = r"[ .\-]"
_PHONE = (
    rf"{_PL}(?:"
    rf"\+\d{{1,3}}(?:{_SEP}?\(?\d{{1,4}}\)?){{2,5}}"
    rf"|(?:\+?1{_SEP})?\(\d{{3}}\){_SEP}?\d{{3}}{_SEP}?\d{{4}}"
    rf"|(?:\+?1{_SEP})?\d{{3}}{_SEP}\d{{3}}{_SEP}\d{{4}}"
    rf"){_PR}"
)
MAX_PHONE_CHARS = 40


def _plausible_phone(text: str) -> bool:
    digits = sum(char.isdigit() for char in text)
    return 8 <= digits <= 15 if text.startswith("+") else 10 <= digits <= 11


def phone() -> RegexDetector:
    """Numbers written with a ``+`` country code, brackets or separators: ``(415) 555-0199``."""
    return RegexDetector(
        "phone",
        _PHONE,
        max_span=MAX_PHONE_CHARS,
        validate=_plausible_phone,
        trigger=r"\d",
        run=r"0-9 \-.()+",
        anchor=r"0-9(+",
        lookbehind=3,
    )

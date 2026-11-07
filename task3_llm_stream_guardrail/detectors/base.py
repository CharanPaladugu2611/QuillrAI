"""The detector contract, and the building blocks for writing new detectors.

A detector finds sensitive spans in text. Because the redactor works on a stream whose
tail is still growing, a detector answers two questions:

``spans(text, start)``
    Where are the matches? Yield non-overlapping ``(begin, end)`` pairs in order, each with
    ``begin >= start`` and ``end - begin <= max_span``. Text before ``start`` has already
    been released; it is passed only so look-behind assertions (and a label that precedes the
    value being redacted) can see it. At most ``lookbehind`` characters of it are kept.

``pending(text, start)``
    Where might a match still be in progress? Return an index ``p`` in ``[start, len(text)]``
    such that everything before ``p`` is settled: whatever text arrives next, the spans that
    begin before ``p`` stay exactly as ``spans(text)`` reports them. Return ``len(text)`` when
    nothing is in progress. The redactor holds ``text[p:]`` back, so a tight answer means low
    latency; a loose one is still safe. Never hold more than ``max_span + LOOKAHEAD_CHARS - 1``
    characters: a match can change until a few characters follow it (look-ahead assertions).

Detectors must be stateless and thread-safe. :func:`~.contract.verify_contract` fuzzes a
detector against these rules, so a new one can be checked in a few lines.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Protocol

Span = tuple[int, int]

# A match followed by this many characters cannot change any more: no detector here looks
# further ahead than that.
LOOKAHEAD_CHARS = 3


def hold_floor(length: int, max_span: int) -> int:
    """The lowest index a detector ever needs to hold from.

    A match that is still growing begins within ``max_span - 1`` characters of the end, and a
    complete one can still be changed by look-ahead until ``LOOKAHEAD_CHARS`` more follow it.
    """
    return length - max_span - LOOKAHEAD_CHARS + 1


class Detector(Protocol):
    name: str
    max_span: int
    lookbehind: int

    def spans(self, text: str, start: int = 0) -> Iterator[Span]: ...

    def pending(self, text: str, start: int = 0) -> int: ...


# --------------------------------------------------------------------------- helpers


def not_in(chars: str) -> re.Pattern[str]:
    """Pattern matching one character outside the regex character-class body ``chars``."""
    return re.compile(f"[^{chars}]")


def run_start(text: str, start: int, floor: int, outside: re.Pattern[str]) -> int:
    """Where the run of characters that ``outside`` does not match, ending at the end of ``text``, begins.

    The scan never goes below ``max(start, floor)``. It searches a reversed copy so the work
    happens in C, which keeps very long tokens cheap.
    """
    low = max(start, floor, 0)
    found = outside.search(text[low:][::-1])
    return len(text) - found.start() if found else low


def prefix_pattern(atoms: Sequence[str]) -> str:
    """``a b c`` -> ``a(?:b(?:c)?)?``: matches every non-empty prefix of the sequence."""
    pattern = ""
    for atom in reversed(atoms):
        pattern = atom + (f"(?:{pattern})?" if pattern else "")
    return pattern


def _label_atoms(label: str) -> list[str]:
    atoms: list[str] = []
    for index, word in enumerate(label.split()):
        if index:
            atoms.append(r"\s+")
        atoms.extend(re.escape(char) for char in word)
    return atoms


# --------------------------------------------------------------------------- regex detector


class RegexDetector:
    """A detector built from one regular expression.

    ``run`` is the body of a regex character class (for example ``r"0-9 \\-"``) listing the
    characters that can occur inside a match. Matches never contain anything else, so only a
    trailing run of them can still be growing. ``anchor`` (also a class body) trims the front of
    that run to the first character a match could start with. ``literals`` are strings every
    match begins with, ``literal_offset`` characters before the reported span: the run is then
    only held when it contains one, or the start of one, so long ordinary tokens cost nothing.
    Leave ``run`` unset when matches may contain anything; the last ``max_span`` characters are
    then held.
    """

    def __init__(
        self,
        name: str,
        pattern: str | re.Pattern[str],
        *,
        max_span: int,
        flags: int = 0,
        group: int | str = 0,
        validate: Callable[[str], bool] | None = None,
        trigger: str | None = None,
        run: str | None = None,
        anchor: str | None = None,
        literals: Sequence[str] | None = None,
        literal_offset: int = 0,
        lookbehind: int = 3,
    ) -> None:
        if max_span < 1:
            raise ValueError("max_span must be at least 1")
        if literals and (run is None or trigger):
            raise ValueError("literals need a run and replace the trigger")
        compiled = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
        if compiled.search("") is not None:
            raise ValueError(f"{name}: the pattern matches the empty string")
        self.name = name
        self.max_span = max_span
        self.lookbehind = lookbehind
        self._pattern = compiled
        self._group = group
        self._validate = validate
        self._outside = not_in(run) if run is not None else None
        self._anchor = re.compile(f"[{anchor}]") if anchor is not None else None
        self._literals = tuple(literals or ())
        self._literal_offset = literal_offset
        if self._literals:
            trigger = "|".join(re.escape(literal) for literal in self._literals)
            self._literal_prefixes = {lit[:k] for lit in self._literals for k in range(1, len(lit))}
            self._longest_literal = max(len(lit) for lit in self._literals)
        self._trigger = re.compile(trigger, flags) if trigger else None

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        if self._trigger is not None and self._trigger.search(text, max(0, start - self.lookbehind)) is None:
            return
        position = start
        while True:
            match = self._pattern.search(text, position)
            if match is None:
                return
            begin, end = match.span(self._group)
            if end > begin and (self._validate is None or self._validate(text[begin:end])):
                yield begin, end
                position = max(match.end(), position + 1)
            else:
                position = match.start() + 1  # let overlapping candidates be tried

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        floor = hold_floor(n, self.max_span)
        if self._outside is None:
            return max(start, floor)
        i = run_start(text, start, floor, self._outside)
        if self._literals:
            # the literal may sit just before the run (already released) when the span starts after it
            found = self._trigger.search(text, max(0, i - self._literal_offset))
            if found:
                return min(n, found.start() + self._literal_offset)
            for length in range(min(self._longest_literal - 1, n - i), 0, -1):
                if text[n - length :] in self._literal_prefixes:
                    return n - length  # the start of a prefix is still arriving
            return n
        if self._anchor is not None:
            found = self._anchor.search(text, i)
            return found.start() if found else n
        return i


# --------------------------------------------------------------------------- label + value


_GAP_LOOSE = r"[\s:=#\-]{0,6}(?:(?:is|are|was|number|num|no)\b\.?[\s:=#\-]{0,6}){0,2}"
_GAP_ASSIGNMENT = r"\s{0,2}[:=]\s{0,2}[\"']?"
_GAP_CHARS = {"loose": 32, "assignment": 6}


class LabelledValueDetector:
    """Redacts a value that follows a label, such as ``passport: X1234567``.

    Only the value is replaced; the label stays. ``gap`` is ``"loose"`` (``SSN is 123...``,
    ``passport no. A123...``) or ``"assignment"`` (``password=...``, ``token: ...``).
    The value pattern must end on its own boundary, for example with ``(?!\\d)``.
    """

    def __init__(
        self,
        name: str,
        labels: Sequence[str],
        value: str,
        *,
        value_max: int,
        gap: str = "loose",
        flags: int = re.IGNORECASE,
    ) -> None:
        if gap not in _GAP_CHARS:
            raise ValueError(f"gap must be one of {sorted(_GAP_CHARS)}")
        cleaned = sorted({label.strip().lower() for label in labels if label.strip()}, key=len, reverse=True)
        if not cleaned:
            raise ValueError(f"{name}: at least one label is required")
        label_patterns = []
        for label in cleaned:
            body = r"\s+".join(re.escape(word) for word in label.split())
            label_patterns.append(body + (r"(?!\w)" if label[-1].isalnum() else ""))
        label_re = r"(?<!\w)(?:" + "|".join(label_patterns) + ")"
        gap_re = _GAP_LOOSE if gap == "loose" else _GAP_ASSIGNMENT
        self.name = name
        # The label may already have been released when the value arrives; keep it in view.
        self.lookbehind = max(len(label) for label in cleaned) + _GAP_CHARS[gap]
        self.max_span = self.lookbehind + value_max
        self._full = re.compile(rf"{label_re}(?:{gap_re})(?P<value>{value})", flags)
        if self._full.search("") is not None:
            raise ValueError(f"{name}: the pattern matches the empty string")
        self._label = re.compile(label_re, flags)
        partial = "|".join(prefix_pattern(_label_atoms(label)) for label in cleaned)
        self._partial = re.compile(rf"(?<!\w)(?:{partial})\Z", flags)
        self._longest_label = max(len(label) for label in cleaned) + 1

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = max(0, start - self.lookbehind)  # the label may sit in the released context
        while True:
            match = self._full.search(text, position)
            if match is None:
                return
            begin, end = match.span("value")
            position = max(match.end(), position + 1)
            if end > begin and begin >= start:
                yield begin, end

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        low = max(start, hold_floor(n, self.max_span))
        earliest = n
        for label in self._label.finditer(text, low):
            match = self._full.match(text, label.start())
            if match is None or match.end() > n - LOOKAHEAD_CHARS:
                earliest = label.start()  # label seen, value still to come (or still growing)
                break
        partial = self._partial.search(text, max(low, n - self._longest_label))  # a label still being typed
        if partial is not None:
            earliest = min(earliest, partial.start())
        return earliest


# --------------------------------------------------------------------------- word lists


class TermsDetector:
    """Redacts whole-word occurrences of known terms (names, project codenames, customers).

    This is how names get blocked when you know them: no pattern can tell a person's name from
    any other capitalised word, but a list can.
    """

    def __init__(self, name: str, terms: Iterable[str], *, case_sensitive: bool = False) -> None:
        cleaned = sorted({term.strip() for term in terms if term.strip()}, key=len, reverse=True)
        if not cleaned:
            raise ValueError(f"{name}: at least one term is required")
        self.name = name
        self.lookbehind = 1
        self.max_span = max(len(term) for term in cleaned)
        flags = 0 if case_sensitive else re.IGNORECASE
        alternation = "|".join(re.escape(term) for term in cleaned)
        self._pattern = re.compile(rf"(?<!\w)(?:{alternation})(?!\w)", flags)
        self._fold: Callable[[str], str] = (lambda s: s) if case_sensitive else str.casefold
        self._prefixes = {self._fold(term[:k]) for term in cleaned for k in range(1, len(term) + 1)}

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        while True:
            match = self._pattern.search(text, position)
            if match is None:
                return
            yield match.span()
            position = match.end()

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        for length in range(min(self.max_span, n - start), 0, -1):
            begin = n - length
            if begin > 0 and (text[begin - 1].isalnum() or text[begin - 1] == "_"):
                continue  # inside a longer word: cannot be the start of a term
            if self._fold(text[begin:]) in self._prefixes:
                return begin
        return n


# --------------------------------------------------------------------------- external models


_SENTENCE_END = re.compile(r"[.!?][\"')\]]*\s|\n")


class CallableDetector:
    """Wraps any function ``find(text) -> [(begin, end), ...]``, such as an NER model.

    Models need a whole sentence to judge, so the unfinished sentence is held back (at most
    ``max_span`` characters of it). That is the price of context-sensitive detection, which is
    why this is opt-in. ``find`` must be thread-safe and quick, since it runs on every chunk.
    """

    def __init__(
        self,
        name: str,
        find: Callable[[str], Iterable[Span]],
        *,
        max_span: int = 400,
        lookbehind: int = 200,
    ) -> None:
        self.name = name
        self.max_span = max_span
        self.lookbehind = lookbehind
        self._find = find

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        for begin, end in sorted(self._find(text)):
            begin = max(begin, position)
            if begin >= start and end > begin and end - begin <= self.max_span:
                yield begin, end
                position = end

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        low = max(start, hold_floor(n, self.max_span))
        sentence_start = low
        for match in _SENTENCE_END.finditer(text, low):
            sentence_start = match.end()
        return min(sentence_start, n)

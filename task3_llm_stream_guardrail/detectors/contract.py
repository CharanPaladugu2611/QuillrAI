"""Check a detector against the streaming contract (see :mod:`.base`).

    problems = verify_contract(my_detector, ["sample text with a match", ...])
    assert not problems

For every sample and every point at which the text could be cut, the detector's ``pending``
answer must be honest: spans that begin before it must be exactly the spans the full text
ends up with, and it must not ask to hold more than ``max_span + LOOKAHEAD_CHARS - 1`` characters.
"""

from __future__ import annotations

from collections.abc import Iterable

from .base import LOOKAHEAD_CHARS, Detector


def verify_contract(detector: Detector, samples: Iterable[str]) -> list[str]:
    problems: list[str] = []
    for text in samples:
        final = sorted(detector.spans(text, 0))
        for span in final:
            if span[1] - span[0] > detector.max_span:
                problems.append(f"{detector.name}: span {span} is longer than max_span in {text!r}")
        for cut in range(len(text) + 1):
            prefix = text[:cut]
            pending = detector.pending(prefix, 0)
            if not 0 <= pending <= cut:
                problems.append(f"{detector.name}: pending={pending} outside [0, {cut}] for {prefix!r}")
                continue
            if cut - pending > detector.max_span + LOOKAHEAD_CHARS - 1:
                problems.append(f"{detector.name}: holds {cut - pending} chars, more than allowed, for {prefix!r}")
            seen = [s for s in sorted(detector.spans(prefix, 0)) if s[0] < pending]
            settled = [s for s in final if s[0] < pending]
            if seen != settled:
                problems.append(
                    f"{detector.name}: after {prefix!r} (pending={pending}) spans {seen} are not final; "
                    f"the full text {text!r} has {settled}"
                )
    return problems

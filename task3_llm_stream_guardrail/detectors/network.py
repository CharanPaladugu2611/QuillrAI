"""Network identifiers: IPv4 and IPv6 addresses, MAC addresses."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from .base import RegexDetector, Span, hold_floor, not_in, run_start

MAX_IPV4_CHARS = 15
MAX_IPV6_CHARS = 45
MAX_MAC_CHARS = 17

# "Version 1.2.3.4" has the shape of an address but is not one.
_IPV4 = r"(?<![\w.])(?<!\d\.)(?<!\bversion )(?<!\bver\. )(?<!\bver )(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\w)(?!\.[0-9])"


def _octets_in_range(text: str) -> bool:
    return all(int(part) <= 255 for part in text.split("."))


def ipv4() -> RegexDetector:
    """Dotted-quad addresses with every octet in range: ``192.168.1.10``."""
    return RegexDetector(
        "ipv4",
        _IPV4,
        max_span=MAX_IPV4_CHARS,
        validate=_octets_in_range,
        trigger=r"[0-9]\.[0-9]",
        run=r"0-9.",
        anchor=r"0-9",
        flags=re.IGNORECASE,
        lookbehind=8,
    )


_IPV6_CANDIDATE = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f.]*:[0-9A-Fa-f.:]*:)[0-9A-Fa-f:.]{3,45}(?!\w)")
_NOT_IPV6 = not_in(r"0-9A-Fa-f:.")


def _valid_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


class Ipv6Detector:
    """IPv6 addresses in full, compressed (``2001:db8::1``) or IPv4-mapped form."""

    name = "ipv6"
    max_span = MAX_IPV6_CHARS
    lookbehind = 2

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        while True:
            match = _IPV6_CANDIDATE.search(text, position)
            if match is None:
                return
            begin, end = match.span()
            candidate = match.group()
            for trimmed in (candidate, candidate.rstrip("."), candidate.rstrip(".:")):
                if trimmed and _valid_ipv6(trimmed):
                    yield begin, begin + len(trimmed)
                    position = begin + len(trimmed)
                    break
            else:
                position = begin + 1

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        i = run_start(text, start, hold_floor(n, self.max_span), _NOT_IPV6)
        while i < n and text[i] == ".":
            i += 1
        return i


_MAC = (
    r"(?<![\w:\-])(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}(?![\w:\-])"
    r"|(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])"
)


def mac() -> RegexDetector:
    """Hardware addresses: ``00:1A:2B:3C:4D:5E`` and ``001a.2b3c.4d5e``."""
    return RegexDetector(
        "mac",
        _MAC,
        max_span=MAX_MAC_CHARS,
        trigger=r"[0-9A-Fa-f][:\-.][0-9A-Fa-f]",
        run=r"0-9A-Fa-f:.\-",
        lookbehind=2,
    )

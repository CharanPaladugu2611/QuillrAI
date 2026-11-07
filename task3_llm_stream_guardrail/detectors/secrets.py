"""Credentials that should never appear in a model's output."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .base import RegexDetector, Span, hold_floor

MAX_API_KEY_CHARS = 270
MAX_JWT_CHARS = 4096
MAX_URL_CREDENTIAL_CHARS = 400
MAX_PRIVATE_KEY_CHARS = 8192

_API_KEY = (
    r"(?<![A-Za-z0-9_\-])(?:"
    r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}"  # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{36,255}"  # GitHub
    r"|github_pat_[A-Za-z0-9_]{22,255}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,250}"  # Slack
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}"  # Stripe
    r"|AIza[0-9A-Za-z_\-]{35}"  # Google
    r"|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_\-]{20,200}"  # sk- prefixed secret keys
    r")(?![A-Za-z0-9_\-])"
)
_API_KEY_PREFIXES = (
    "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "AIza", "sk-",
)


def api_key() -> RegexDetector:
    """Provider keys with a recognisable prefix: AWS, GitHub, Slack, Stripe, Google, ``sk-...``."""
    return RegexDetector(
        "api_key", _API_KEY, max_span=MAX_API_KEY_CHARS, run=r"\S", literals=_API_KEY_PREFIXES, lookbehind=1
    )


_JWT = (
    r"(?<![A-Za-z0-9_\-.])eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*(?![A-Za-z0-9_\-])"
)


def jwt() -> RegexDetector:
    """JSON Web Tokens (three dot-separated base64url parts, the first two starting ``eyJ``)."""
    return RegexDetector("jwt", _JWT, max_span=MAX_JWT_CHARS, run=r"\S", literals=("eyJ",), lookbehind=1)


_URL_CREDENTIALS = r"(?<=://)(?P<credentials>[^\s/@:]{1,128}:[^\s/@]{1,256})(?=@)"


def url_credentials() -> RegexDetector:
    """The ``user:password`` part of ``scheme://user:password@host``; the host stays visible."""
    return RegexDetector(
        "url_credentials",
        _URL_CREDENTIALS,
        group="credentials",
        max_span=MAX_URL_CREDENTIAL_CHARS,
        run=r"\S",
        literals=("://",),
        literal_offset=3,
        lookbehind=3,
    )


# --------------------------------------------------------------------------- private keys

_PEM = re.compile(
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]{0,%d}?-----END (?:[A-Z]+ )*PRIVATE KEY-----" % MAX_PRIVATE_KEY_CHARS
)
_PEM_HEADER = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")
_PEM_PARTIAL = re.compile(r"-{1,5}(?:B(?:E(?:G(?:I(?:N(?: [A-Z ]{0,24}(?:-{1,5})?)?)?)?)?)?)?\Z")


class PrivateKeyDetector:
    """PEM private key blocks, from the BEGIN line to the END line.

    An unfinished block is held back (up to ``MAX_PRIVATE_KEY_CHARS``) until its END line arrives.
    """

    name = "private_key"
    max_span = MAX_PRIVATE_KEY_CHARS + 120
    lookbehind = 1

    def spans(self, text: str, start: int = 0) -> Iterator[Span]:
        position = start
        while True:
            match = _PEM.search(text, position)
            if match is None:
                return
            yield match.span()
            position = match.end()

    def pending(self, text: str, start: int = 0) -> int:
        n = len(text)
        low = max(start, hold_floor(n, self.max_span))
        for header in _PEM_HEADER.finditer(text, low):
            if _PEM.match(text, header.start()) is None:
                return header.start()  # BEGIN seen, END still to come
        partial = _PEM_PARTIAL.search(text, max(low, n - 40))
        return partial.start() if partial else n

"""Values that give themselves away only through the words in front of them.

A bare nine-digit number, a seven-character code or a date is too ambiguous to redact on its
own, but ``SSN 123456789``, ``passport X1234567`` and ``born on 3 May 1990`` are not. Each
detector here pairs labels with the shape of the value that follows; only the value is replaced.
"""

from __future__ import annotations

import re

from .base import LabelledValueDetector

_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
_DATE = (
    r"(?:[0-9]{1,2}[/.\-][0-9]{1,2}[/.\-](?:[0-9]{4}|[0-9]{2})"
    r"|[0-9]{4}[/.\-][0-9]{1,2}[/.\-][0-9]{1,2}"
    rf"|{_MONTH}[ ]+[0-9]{{1,2}}(?:st|nd|rd|th)?,?[ ]+[0-9]{{4}}"
    rf"|[0-9]{{1,2}}(?:st|nd|rd|th)?[ ]+{_MONTH},?[ ]+[0-9]{{4}})(?![\w])"
)


def ssn_labelled() -> LabelledValueDetector:
    """Social security numbers after a label, with spaces or none: ``SSN 123 45 6789``."""
    return LabelledValueDetector(
        "ssn_labelled",
        ["ssn", "ss#", "social security number", "social security no", "social security"],
        r"[0-9]{3}[ \-]?[0-9]{2}[ \-]?[0-9]{4}(?![0-9])(?![ \-][0-9])",
        value_max=11,
    )


def phone_labelled() -> LabelledValueDetector:
    """Numbers after words like ``phone`` or ``call me at``, in any grouping."""
    return LabelledValueDetector(
        "phone_labelled",
        ["phone", "telephone", "tel", "mobile", "cell", "fax", "whatsapp", "call me at", "call me on", "call"],
        r"\+?[0-9][0-9 ().\-]{5,18}[0-9](?![0-9])",
        value_max=20,
    )


def date_of_birth() -> LabelledValueDetector:
    return LabelledValueDetector(
        "date_of_birth",
        ["dob", "d.o.b", "date of birth", "birth date", "birthdate", "birthday", "born on", "born"],
        _DATE,
        value_max=24,
    )


def passport() -> LabelledValueDetector:
    return LabelledValueDetector(
        "passport",
        ["passport"],
        r"(?=[A-Z0-9]*[0-9])[A-Z0-9]{6,9}(?![A-Za-z0-9])",
        value_max=9,
    )


def drivers_license() -> LabelledValueDetector:
    return LabelledValueDetector(
        "drivers_license",
        ["driver's license", "drivers license", "driver license", "driving licence", "driving license", "dl number"],
        r"(?=[A-Z0-9\- ]*[0-9])[A-Z0-9][A-Z0-9\- ]{3,14}[A-Z0-9](?![A-Za-z0-9])",
        value_max=16,
    )


def bank_account() -> LabelledValueDetector:
    return LabelledValueDetector(
        "bank_account",
        ["account number", "account no", "acct", "routing number", "routing no", "sort code"],
        r"[0-9][0-9 \-]{4,20}[0-9](?![0-9])",
        value_max=22,
    )


def credential() -> LabelledValueDetector:
    """``password=...``, ``api_key: ...``, ``token = ...``: the value after an assignment."""
    return LabelledValueDetector(
        "credential",
        ["password", "passwd", "pwd", "passphrase", "secret", "api key", "api_key", "apikey", "access token", "auth token", "token"],
        r"[^\s'\",;]{6,128}",
        value_max=128,
        gap="assignment",
    )


def stated_password() -> LabelledValueDetector:
    """``my password is hunter2``: the value must contain a digit so ordinary prose survives."""
    return LabelledValueDetector(
        "stated_password",
        ["password", "passcode", "pin"],
        r"(?=[^\s'\",;]*[0-9])[^\s'\",;]{4,64}",
        value_max=64,
    )


def bearer_token() -> LabelledValueDetector:
    return LabelledValueDetector(
        "bearer_token",
        ["bearer"],
        r"[A-Za-z0-9._~+/\-]{16,2048}=*",
        value_max=2100,
        gap="loose",
        flags=re.IGNORECASE,
    )

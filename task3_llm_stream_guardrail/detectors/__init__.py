"""The built-in detectors, and a registry to switch them on and off by name.

Every detector here follows the contract in :mod:`.base`. To add one, write a class (or a
:class:`~.base.RegexDetector`) that follows it, check it with :func:`~.contract.verify_contract`,
and either pass it to the engine directly or register a factory in ``_FACTORIES``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from . import contact, financial, labelled, network, secrets
from .base import (
    CallableDetector,
    Detector,
    LabelledValueDetector,
    RegexDetector,
    Span,
    TermsDetector,
)
from .contract import verify_contract

_FACTORIES: dict[str, Callable[[], Detector]] = {
    "email": contact.EmailDetector,
    "email_obfuscated": contact.ObfuscatedEmailDetector,
    "phone": contact.phone,
    "ssn": financial.ssn,
    "card": financial.CardDetector,
    "iban": financial.IbanDetector,
    "ipv4": network.ipv4,
    "ipv6": network.Ipv6Detector,
    "mac": network.mac,
    "api_key": secrets.api_key,
    "jwt": secrets.jwt,
    "url_credentials": secrets.url_credentials,
    "private_key": secrets.PrivateKeyDetector,
    "ssn_labelled": labelled.ssn_labelled,
    "phone_labelled": labelled.phone_labelled,
    "date_of_birth": labelled.date_of_birth,
    "passport": labelled.passport,
    "drivers_license": labelled.drivers_license,
    "bank_account": labelled.bank_account,
    "credential": labelled.credential,
    "stated_password": labelled.stated_password,
    "bearer_token": labelled.bearer_token,
}

DEFAULT_NAMES: tuple[str, ...] = tuple(_FACTORIES)


def available() -> list[str]:
    """Names accepted by :func:`build`."""
    return list(_FACTORIES)


def build(names: Iterable[str]) -> list[Detector]:
    detectors = []
    for name in names:
        try:
            detectors.append(_FACTORIES[name]())
        except KeyError:
            raise ValueError(f"unknown detector {name!r}; available: {', '.join(_FACTORIES)}") from None
    return detectors


def default_detectors() -> list[Detector]:
    return build(DEFAULT_NAMES)


__all__ = [
    "CallableDetector",
    "DEFAULT_NAMES",
    "Detector",
    "LabelledValueDetector",
    "RegexDetector",
    "Span",
    "TermsDetector",
    "available",
    "build",
    "default_detectors",
    "verify_contract",
]

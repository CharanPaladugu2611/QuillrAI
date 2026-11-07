"""Operator configuration: which detectors run, plus word lists, patterns and labelled values of your own.

Point ``GUARDRAIL_CONFIG`` at a JSON file. Every key is optional, unknown keys are rejected so a
typo cannot silently weaken the guardrail:

.. code-block:: json

    {
      "replacement": "[REDACTED]",
      "detectors": ["email", "card"],
      "disable": ["ipv4"],
      "terms": [{"name": "people", "terms": ["Jeff", "Aloha Corp"], "case_sensitive": false}],
      "patterns": [{"name": "employee_id", "regex": "EMP-[0-9]{6}", "max_length": 10}],
      "labelled": [{"name": "member_id", "labels": ["member id"], "value": "[A-Z0-9]{8}(?![A-Za-z0-9])",
                    "max_value_length": 8}]
    }

``detectors`` replaces the default list (names from :func:`.detectors.available`), ``disable``
removes names from whatever list is in force. ``replacement`` may contain ``{label}``, which
becomes the name of the detector that fired (``"[REDACTED:{label}]"``).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .detectors import DEFAULT_NAMES, LabelledValueDetector, RegexDetector, TermsDetector, available, build
from .detectors.base import Detector
from .redactor import REPLACEMENT, Engine, default_engine

CONFIG_ENV = "GUARDRAIL_CONFIG"
_KEYS = {"replacement", "detectors", "disable", "terms", "patterns", "labelled"}


class ConfigError(ValueError):
    """The guardrail configuration is invalid; the service must not start with it."""


def _section(config: Mapping[str, Any], key: str, allowed: set[str], required: set[str]) -> list[dict[str, Any]]:
    entries = config.get(key, [])
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise ConfigError(f"'{key}' must be a list of objects")
    for entry in entries:
        unknown = set(entry) - allowed
        missing = required - set(entry)
        if unknown or missing:
            raise ConfigError(f"'{key}' entry {entry.get('name', '?')!r}: unknown keys {sorted(unknown)}, missing {sorted(missing)}")
    return entries


def _string(entry: Mapping[str, Any], key: str) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{entry.get('name', '?')!r}: '{key}' must be a non-empty string")
    return value


def _integer(entry: Mapping[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = entry.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{entry.get('name', '?')!r}: '{key}' must be an integer from {low} to {high}")
    return value


def _names(config: Mapping[str, Any], key: str) -> list[str]:
    names = config.get(key, [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ConfigError(f"'{key}' must be a list of detector names")
    return names


def engine_from_config(config: Mapping[str, Any]) -> Engine:
    if not isinstance(config, Mapping):
        raise ConfigError("the configuration must be a JSON object")
    unknown = set(config) - _KEYS
    if unknown:
        raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")

    try:
        selected = _names(config, "detectors") if "detectors" in config else list(DEFAULT_NAMES)
        disabled = set(_names(config, "disable"))
        unknown_disabled = disabled - set(available())
        if unknown_disabled:
            raise ConfigError(f"'disable' names unknown detectors: {sorted(unknown_disabled)}")
        detectors: list[Detector] = build(name for name in selected if name not in disabled)

        for entry in _section(config, "terms", {"name", "terms", "case_sensitive"}, {"name", "terms"}):
            terms = entry["terms"]
            if not isinstance(terms, list) or not all(isinstance(term, str) for term in terms):
                raise ConfigError(f"{entry['name']!r}: 'terms' must be a list of strings")
            detectors.append(TermsDetector(_string(entry, "name"), terms, case_sensitive=bool(entry.get("case_sensitive", False))))

        for entry in _section(
            config,
            "patterns",
            {"name", "regex", "max_length", "ignore_case", "contains_whitespace", "lookbehind"},
            {"name", "regex", "max_length"},
        ):
            detectors.append(
                RegexDetector(
                    _string(entry, "name"),
                    _string(entry, "regex"),
                    max_span=_integer(entry, "max_length", 1, 1, 4096),
                    flags=re.IGNORECASE if entry.get("ignore_case") else 0,
                    run=None if entry.get("contains_whitespace") else r"\S",
                    lookbehind=_integer(entry, "lookbehind", 8, 0, 64),
                )
            )

        for entry in _section(
            config,
            "labelled",
            {"name", "labels", "value", "max_value_length", "gap"},
            {"name", "labels", "value", "max_value_length"},
        ):
            labels = entry["labels"]
            if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
                raise ConfigError(f"{entry['name']!r}: 'labels' must be a list of strings")
            detectors.append(
                LabelledValueDetector(
                    _string(entry, "name"),
                    labels,
                    _string(entry, "value"),
                    value_max=_integer(entry, "max_value_length", 1, 1, 2048),
                    gap=entry.get("gap", "loose"),
                )
            )

        replacement = config.get("replacement", REPLACEMENT)
        if not isinstance(replacement, str) or not replacement:
            raise ConfigError("'replacement' must be a non-empty string")
        return Engine(detectors, replacement=replacement)
    except (re.error, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(str(exc)) from None


def load_engine(path: str | os.PathLike[str]) -> Engine:
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from None
    except ValueError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from None
    return engine_from_config(config)


def engine_from_env(env: Mapping[str, str] | None = None) -> Engine:
    env = os.environ if env is None else env
    path = env.get(CONFIG_ENV)
    return load_engine(path) if path else default_engine()

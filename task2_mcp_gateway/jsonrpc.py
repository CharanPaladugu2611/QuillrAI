"""JSON-RPC 2.0 wire-format helpers: strict parsing, classification, error envelopes."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
UNAUTHENTICATED = -32000
UNAUTHORIZED_TOOL_CALL = -32001
BAD_GATEWAY = -32003
GATEWAY_TIMEOUT = -32004


class ParseError(Exception):
    """The body is not usable JSON."""


class Kind(Enum):
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    INVALID = "invalid"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Two parsers disagreeing on which duplicate wins is a classic authorization bypass.
            raise ParseError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ParseError(f"non-standard JSON constant {name}")


def parse_body(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except ParseError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ParseError(type(exc).__name__) from None


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def classify(message: Any) -> Kind:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return Kind.INVALID
    if "method" in message:
        if not isinstance(message["method"], str) or not message["method"]:
            return Kind.INVALID
        if "params" in message and not isinstance(message["params"], (dict, list)):
            return Kind.INVALID
        if "id" not in message:
            return Kind.NOTIFICATION
        return Kind.REQUEST if _valid_id(message["id"]) else Kind.INVALID
    if "id" in message and ("result" in message) != ("error" in message):
        return Kind.RESPONSE
    return Kind.INVALID


def message_id(message: Any) -> Any:
    """The id to echo in an error response; ``None`` when absent or unusable."""
    if isinstance(message, dict) and _valid_id(message.get("id")):
        return message["id"]
    return None


def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}

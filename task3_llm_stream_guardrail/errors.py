"""Gateway error catalogue; clients only ever see these fixed messages."""

from __future__ import annotations

ERROR_CATALOG: dict[str, tuple[int, str]] = {
    "invalid_request": (400, "The request body is invalid."),
    "upstream_error": (502, "The model service could not complete the request."),
    "upstream_timeout": (504, "The model service did not respond in time."),
    "stream_interrupted": (502, "The response stream was interrupted."),
    "not_found": (404, "Resource not found."),
    "method_not_allowed": (405, "Method not allowed."),
    "internal_error": (500, "An internal error occurred."),
}


class UpstreamError(Exception):
    """The model provider failed before or while streaming."""


class UpstreamTimeout(UpstreamError):
    pass


def error_body(code: str, request_id: str) -> dict:
    return {"error": {"code": code, "message": ERROR_CATALOG[code][1], "request_id": request_id}}

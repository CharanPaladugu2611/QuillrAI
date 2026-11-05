"""Error types.

``Upstream*`` exceptions are raised by providers and never leave the gateway.
``GatewayError`` is the only error the client ever sees: a fixed code, a fixed
message and an HTTP status, so nothing about upstream hosts, payloads or stack
traces can leak through an error response.
"""

from __future__ import annotations

from dataclasses import dataclass

# code -> (http status, client-facing message)
ERROR_CATALOG: dict[str, tuple[int, str]] = {
    "unauthorized": (401, "A valid API key is required."),
    "invalid_request": (400, "The request body is invalid."),
    "request_too_large": (413, "The request exceeds the maximum size a single request may use."),
    "rate_limit_exceeded": (429, "Token rate limit exceeded. Retry after the indicated delay."),
    "upstream_unavailable": (503, "The model service is temporarily unavailable. Please retry."),
    "upstream_error": (502, "The model service could not complete the request."),
    "not_found": (404, "Resource not found."),
    "method_not_allowed": (405, "Method not allowed."),
    "internal_error": (500, "An internal error occurred."),
}


class UpstreamError(Exception):
    """Base for failures talking to a model provider."""


class UpstreamRateLimited(UpstreamError):
    def __init__(self, retry_after_s: float | None = None) -> None:
        super().__init__("upstream returned 429")
        self.retry_after_s = retry_after_s


class UpstreamTimeout(UpstreamError):
    pass


class UpstreamUnavailable(UpstreamError):
    """Connection failure, 5xx or an unparseable reply."""


class UpstreamRejected(UpstreamError):
    """The provider refused the request itself (4xx other than 429)."""


@dataclass
class GatewayError(Exception):
    code: str
    retry_after_s: int | None = None

    def __post_init__(self) -> None:
        if self.code not in ERROR_CATALOG:
            raise ValueError(f"unknown gateway error code {self.code!r}")

    @property
    def status(self) -> int:
        return ERROR_CATALOG[self.code][0]

    @property
    def message(self) -> str:
        return ERROR_CATALOG[self.code][1]

    def __str__(self) -> str:
        return self.code


def error_payload(code: str, request_id: str, retry_after_s: int | None = None) -> dict:
    _, message = ERROR_CATALOG[code]
    error: dict = {"code": code, "message": message, "request_id": request_id}
    if retry_after_s is not None:
        error["retry_after_seconds"] = retry_after_s
    return {"error": error}

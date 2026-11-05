"""Method-level authorization for MCP JSON-RPC messages.

Only ``tools/call`` is gated: a tool whose name starts with ``admin_`` needs the
``admin`` role. Everything else, ``tools/list`` included, is forwarded untouched.

Names are compared after Unicode NFKC normalisation, trimming and case folding. The
spec's literal rule is a prefix match, but a downstream that normalises names more
loosely than the gateway would otherwise turn ``ADMIN_reset_key`` or `` admin_x`` into
a bypass, so the gateway fails closed on those variants.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

from .auth import ADMIN, Principal
from .jsonrpc import INVALID_PARAMS, UNAUTHORIZED_TOOL_CALL

ADMIN_TOOL_PREFIX = "admin_"
TOOLS_CALL = "tools/call"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    tool: str | None = None
    code: int | None = None
    message: str | None = None


ALLOW = Decision(allowed=True)


def _normalise(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def authorize(message: dict[str, Any], principal: Principal) -> Decision:
    method = message.get("method")
    if not isinstance(method, str) or _normalise(method) != TOOLS_CALL:
        return ALLOW

    params = message.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str):
        return Decision(False, code=INVALID_PARAMS, message="Invalid params: tools/call requires a string 'name'")

    if _normalise(name).startswith(ADMIN_TOOL_PREFIX) and principal.role != ADMIN:
        return Decision(False, tool=name, code=UNAUTHORIZED_TOOL_CALL, message="Unauthorized Tool Call")
    return Decision(True, tool=name)

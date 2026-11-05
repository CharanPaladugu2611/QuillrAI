"""Customer-operations MCP server: tool registry, validation and JSON-RPC error mapping.

Error mapping
-------------
Protocol errors are raised as ``MCPError`` and reach the client as JSON-RPC errors:

===========================  ======================================
Condition                    JSON-RPC error
===========================  ======================================
Malformed / missing params   -32602 Invalid params
Unknown tool name            -32602 Invalid params
Unknown method               -32601 Method not found (SDK)
Unexpected server failure    -32603 Internal error (details logged)
===========================  ======================================

A well-formed call that fails a business rule (for example an unknown customer) is
not a protocol error: it is returned as a normal result with ``isError: true`` so a
model can read the message and react.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp_types import INTERNAL_ERROR, INVALID_PARAMS
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel, ValidationError

from .models import GetCustomerRecordInput, TriggerRefundInput
from .store import CustomerStore, ToolExecutionError

logger = logging.getLogger(__name__)

SERVER_NAME = "customer-ops"
SERVER_VERSION = "1.0.0"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    model: type[BaseModel]
    run: Callable[[Any], dict[str, Any]]
    annotations: types.ToolAnnotations

    def to_tool(self) -> types.Tool:
        schema = self.model.model_json_schema()
        schema.pop("title", None)
        return types.Tool(
            name=self.name,
            description=self.description,
            input_schema=schema,
            annotations=self.annotations,
        )


def _summarize_validation_error(exc: ValidationError) -> list[dict[str, Any]]:
    """Field-level details without echoing the rejected input back to the caller."""
    return [
        {"field": ".".join(str(part) for part in err["loc"]) or "(root)", "type": err["type"], "message": err["msg"]}
        for err in exc.errors(include_url=False, include_input=False, include_context=False)
    ]


def build_tools(store: CustomerStore) -> dict[str, ToolSpec]:
    specs = [
        ToolSpec(
            name="get_customer_record",
            description="Look up a customer record by customer id (format CUST-XXXXX).",
            model=GetCustomerRecordInput,
            run=lambda args: store.get(args.customer_id),
            annotations=types.ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
        ),
        ToolSpec(
            name="trigger_refund",
            description="Issue a refund to a customer. Requires a customer id, a positive amount and a reason.",
            model=TriggerRefundInput,
            run=lambda args: store.refund(args.customer_id, args.amount, args.reason),
            annotations=types.ToolAnnotations(
                read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
            ),
        ),
    ]
    return {spec.name: spec for spec in specs}


def build_server(store: CustomerStore | None = None) -> Server:
    tools = build_tools(store or CustomerStore())

    async def on_list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[spec.to_tool() for spec in tools.values()])

    async def on_call_tool(ctx: ServerRequestContext, params: types.CallToolRequestParams) -> types.CallToolResult:
        spec = tools.get(params.name)
        if spec is None:
            logger.warning("rejected call to unknown tool %r", params.name)
            raise MCPError(INVALID_PARAMS, f"Unknown tool: {params.name}")

        try:
            args = spec.model.model_validate(params.arguments or {})
        except ValidationError as exc:
            details = _summarize_validation_error(exc)
            logger.info("rejected %s: %d invalid field(s)", spec.name, len(details))
            raise MCPError(INVALID_PARAMS, f"Invalid arguments for tool '{spec.name}'", {"errors": details}) from None

        try:
            payload = spec.run(args)
        except ToolExecutionError as exc:
            logger.info("%s failed: %s", spec.name, exc)
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(exc))], is_error=True)
        except Exception:
            # The SDK would surface str(exc) with code 0; keep internals off the wire.
            logger.exception("unexpected failure in %s", spec.name)
            raise MCPError(INTERNAL_ERROR, "Internal error") from None

        logger.info("%s ok", spec.name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
        )

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )

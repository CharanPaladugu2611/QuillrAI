"""A minimal downstream MCP server (HTTP, JSON-RPC) for exercising the gateway.

It records every call it receives in ``app.state.calls`` so tests can prove that a
request the gateway denied never reached it. When ``required_token`` is set it also
rejects any caller that does not present that credential, the way a downstream that
refuses to trust network position would.
"""

from __future__ import annotations

import hmac
import json
import os
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .jsonrpc import INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR, error_response

TOOLS = [
    {"name": "echo", "description": "Echo the supplied text.", "inputSchema": {"type": "object"}},
    {"name": "get_time", "description": "Return a fixed timestamp.", "inputSchema": {"type": "object"}},
    {"name": "admin_reset_key", "description": "Rotate an API key.", "inputSchema": {"type": "object"}},
    {"name": "admin_purge_cache", "description": "Flush all caches.", "inputSchema": {"type": "object"}},
]
SESSION_ID = "mock-session-1"


def _handle(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return error_response(None, INVALID_REQUEST, "Invalid Request")
    if "id" not in message:
        return None  # notification
    request_id, method = message["id"], message.get("method")
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-downstream", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if name not in {t["name"] for t in TOOLS}:
            return error_response(request_id, INVALID_PARAMS, f"Unknown tool: {name}")
        arguments = params.get("arguments") or {}
        result = {"content": [{"type": "text", "text": f"{name} executed with {json.dumps(arguments)}"}], "isError": False}
    elif method == "ping":
        result = {}
    else:
        return error_response(request_id, -32601, "Method not found")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def create_mock_downstream(*, required_token: str | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.calls = []

    def authorised(request: Request) -> bool:
        if required_token is None:
            return True
        presented = request.headers.get("authorization", "")
        return hmac.compare_digest(presented.encode(), f"Bearer {required_token}".encode())

    @app.post("/mcp")
    async def post_mcp(request: Request) -> Response:
        if not authorised(request):
            return JSONResponse(error_response(None, -32000, "Unauthorized"), status_code=401)
        raw = await request.body()
        try:
            payload = json.loads(raw)
        except ValueError:
            return JSONResponse(error_response(None, PARSE_ERROR, "Parse error"), status_code=400)

        messages = payload if isinstance(payload, list) else [payload]
        for message in messages:
            if isinstance(message, dict):
                params = message.get("params") if isinstance(message.get("params"), dict) else {}
                app.state.calls.append(
                    {
                        "method": message.get("method"),
                        "tool": params.get("name"),
                        "headers": dict(request.headers),
                    }
                )

        responses = [r for r in (_handle(m) for m in messages) if r is not None]
        headers = {"mcp-session-id": SESSION_ID}
        if not responses:
            return Response(status_code=202, headers=headers)
        body: Any = responses if isinstance(payload, list) else responses[0]
        return JSONResponse(body, headers=headers)

    @app.get("/mcp")
    async def get_mcp(request: Request) -> Response:
        if not authorised(request):
            return JSONResponse(error_response(None, -32000, "Unauthorized"), status_code=401)

        async def events():
            for index in range(3):
                yield f"id: {index}\ndata: {json.dumps({'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'n': index}})}\n\n".encode()

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.delete("/mcp")
    async def delete_mcp(request: Request) -> Response:
        if not authorised(request):
            return JSONResponse(error_response(None, -32000, "Unauthorized"), status_code=401)
        return Response(status_code=204)

    return app


def main() -> None:
    app = create_mock_downstream(required_token=os.environ.get("DOWNSTREAM_TOKEN") or None)
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("MOCK_PORT", "9000")))


if __name__ == "__main__":
    main()

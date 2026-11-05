"""Run the server over stdio: ``python -m task1_mcp_server``.

stdout carries JSON-RPC frames and nothing else. Logging is bound to stderr before
anything else happens, and the SDK's stdio transport points file descriptor 1 at
stderr while it serves, so a stray ``print`` or a child process cannot corrupt the
protocol stream.
"""

import logging
import os
import sys

import anyio

from .server import build_server
from .transport import stdio_with_protocol_errors


def configure_logging() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )


async def serve() -> None:
    server = build_server()
    async with stdio_with_protocol_errors() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    configure_logging()
    anyio.run(serve)


if __name__ == "__main__":
    main()

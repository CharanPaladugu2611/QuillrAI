"""Mint a gateway JWT for local testing: ``python -m task2_mcp_gateway.mint_token --role admin``."""

from __future__ import annotations

import argparse
import os
import sys

from .auth import ROLES, mint_token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint a signed bearer token for the MCP gateway.")
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    parser.add_argument("--sub", default="demo-user", help="subject claim (default: demo-user)")
    parser.add_argument("--ttl", type=int, default=3600, help="lifetime in seconds (default: 3600)")
    args = parser.parse_args(argv)

    secret = os.environ.get("GATEWAY_JWT_SECRET")
    if not secret:
        print("GATEWAY_JWT_SECRET must be set", file=sys.stderr)
        return 2
    print(
        mint_token(
            secret,
            subject=args.sub,
            role=args.role,
            ttl_s=args.ttl,
            issuer=os.environ.get("JWT_ISSUER") or None,
            audience=os.environ.get("JWT_AUDIENCE") or None,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

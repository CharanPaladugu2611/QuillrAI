"""Zero-trust troubleshooting for the MCP gateway deployment.

    python -m zero_trust diagnose --gateway https://gw.internal --downstream https://mcp.internal
    python -m zero_trust token <jwt> --secret-env GATEWAY_JWT_SECRET

Secrets are read from environment variables, never from the command line, so they do
not end up in shell history or process listings.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .netdiag import build_ssl_context
from .probes import ProbeContext, run_diagnostics
from .report import exit_code, render_json, render_text
from .token_inspector import inspect_token


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m zero_trust", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    diagnose = commands.add_parser("diagnose", help="probe a deployed gateway (and optionally its downstream)")
    diagnose.add_argument("--gateway", required=True, help="base URL of the gateway")
    diagnose.add_argument("--downstream", help="base URL of the downstream MCP server, to test it refuses direct access")
    diagnose.add_argument("--mcp-path", default="/mcp")
    diagnose.add_argument("--secret-env", default="GATEWAY_JWT_SECRET", help="env var holding the gateway signing secret")
    diagnose.add_argument("--downstream-token-env", default="DOWNSTREAM_TOKEN", help="env var holding the gateway-to-downstream credential")
    diagnose.add_argument("--issuer")
    diagnose.add_argument("--audience")
    diagnose.add_argument("--ca-bundle", help="PEM bundle for a private CA")
    diagnose.add_argument("--client-cert", help="client certificate for mTLS")
    diagnose.add_argument("--client-key", help="private key for --client-cert")
    diagnose.add_argument("--timeout", type=float, default=5.0)
    diagnose.add_argument("--json", action="store_true", help="machine-readable output")

    token = commands.add_parser("token", help="explain whether a bearer token will be accepted")
    token.add_argument("token", help="the JWT, or - to read it from stdin")
    token.add_argument("--secret-env", default=None, help="env var holding the signing secret, to verify the signature")
    return parser


def _diagnose(args: argparse.Namespace) -> int:
    try:
        verify = build_ssl_context(args.ca_bundle, args.client_cert, args.client_key)
    except (OSError, ValueError) as exc:
        print(f"cannot load TLS material: {exc}", file=sys.stderr)
        return 2
    ctx = ProbeContext(
        gateway_url=args.gateway.rstrip("/"),
        downstream_url=args.downstream.rstrip("/") if args.downstream else None,
        mcp_path=args.mcp_path,
        secret=os.environ.get(args.secret_env) or None,
        downstream_token=os.environ.get(args.downstream_token_env) or None,
        issuer=args.issuer,
        audience=args.audience,
        timeout_s=args.timeout,
        verify=verify,
    )
    results = asyncio.run(run_diagnostics(ctx))
    print(render_json(results) if args.json else render_text(results, f"Zero-trust diagnostics for {ctx.gateway_url}"))
    return exit_code(results)


def _token(args: argparse.Namespace) -> int:
    token = sys.stdin.read().strip() if args.token == "-" else args.token
    secret = os.environ.get(args.secret_env) if args.secret_env else None
    report = inspect_token(token, secret=secret)
    print(report.render())
    return 0 if report.acceptable else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return _diagnose(args) if args.command == "diagnose" else _token(args)


if __name__ == "__main__":
    raise SystemExit(main())

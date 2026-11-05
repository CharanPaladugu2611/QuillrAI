"""Black-box checks for an MCP gateway deployed in a zero-trust network.

Zero trust means no request is trusted for where it came from: every hop proves who it
is, every decision is re-made at the enforcement point, and a failure never reveals
internals. The probes below verify those properties from the outside and, when one
fails, say which layer is most likely at fault and how to fix it.

The checks only read (``tools/list``) or call a tool that does not exist
(``admin_zero_trust_probe``), so they are safe to run against a live deployment. Minting
test tokens needs the gateway's signing secret, so run them from an operator context.
"""

from __future__ import annotations

import email.utils
import hashlib
import re
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt

from task2_mcp_gateway.auth import mint_token

from .model import CheckResult, Status, failed, passed, skipped, warned
from .netdiag import classify_connection_error, inspect_tls, is_loopback

PROBE_TOOL = "admin_zero_trust_probe"
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
CALL_ADMIN_TOOL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": PROBE_TOOL, "arguments": {}}}
SKEW_WARN_S, SKEW_FAIL_S = 30, 300
CERT_WARN_DAYS = 14

_DOWNSTREAM_FIX = (
    "The downstream trusts network position. Require a credential from the gateway (mTLS or a service token) and "
    "restrict ingress to the gateway's identity with a network policy."
)

_LEAK_PATTERNS = {
    "stack trace": re.compile(r"Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.java:\d+\)"),
    "source path": re.compile(r"\bFile \"[^\"]+\"|[\w/\\.-]+\.py\b|site-packages|node_modules"),
    "exception class": re.compile(r"\b\w+(Error|Exception)\b: "),
    "private address": re.compile(r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    "connection string": re.compile(r"\b(postgres|mysql|mongodb|redis|amqp)(ql)?://", re.I),
}


@dataclass
class ProbeContext:
    gateway_url: str
    downstream_url: str | None = None
    mcp_path: str = "/mcp"
    secret: str | None = None
    downstream_token: str | None = None
    issuer: str | None = None
    audience: str | None = None
    timeout_s: float = 5.0
    verify: ssl.SSLContext | bool = True
    now: Callable[[], float] = time.time
    gateway_transport: httpx.AsyncBaseTransport | None = None  # injection points for tests
    downstream_transport: httpx.AsyncBaseTransport | None = None


@dataclass
class Reply:
    status: int | None = None
    body: Any = None
    text: str = ""
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    error: BaseException | None = None

    @property
    def rpc_error_code(self) -> int | None:
        if isinstance(self.body, dict) and isinstance(self.body.get("error"), dict):
            return self.body["error"].get("code")
        return None

    @property
    def rejected(self) -> bool:
        return self.status in (401, 403)

    @property
    def accepted(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:8]


class Prober:
    def __init__(self, ctx: ProbeContext, gateway: httpx.AsyncClient, downstream: httpx.AsyncClient | None) -> None:
        self.ctx = ctx
        self.gateway = gateway
        self.downstream = downstream
        self.date_header: str | None = None

    # ------------------------------------------------------------------ plumbing

    def mint(self, role: str, *, ttl_s: int = 300, offset_s: float = 0) -> str:
        assert self.ctx.secret
        return mint_token(
            self.ctx.secret,
            subject="zt-probe",
            role=role,
            ttl_s=ttl_s,
            now=self.ctx.now() + offset_s,
            issuer=self.ctx.issuer,
            audience=self.ctx.audience,
        )

    async def post(self, client: httpx.AsyncClient, path: str, body: Any, token: str | None = None, **extra: Any) -> Reply:
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        headers.update(extra.pop("headers", {}))
        if token:
            headers["authorization"] = f"Bearer {token}"
        kwargs = {"content": body} if isinstance(body, (bytes, str)) else {"json": body}
        try:
            response = await client.post(path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            return Reply(error=exc)
        try:
            parsed = response.json()
        except ValueError:
            parsed = None
        return Reply(response.status_code, parsed, response.text, response.headers)

    def gw(self, body: Any, token: str | None = None, **extra: Any) -> Awaitable[Reply]:
        return self.post(self.gateway, self.ctx.mcp_path, body, token, **extra)

    # ------------------------------------------------------------------ connectivity

    async def reachable(self) -> CheckResult:
        name = "gateway.reachable"
        try:
            response = await self.gateway.get("/healthz")
        except httpx.HTTPError as exc:
            diagnosis = classify_connection_error(exc)
            return failed(name, f"{diagnosis.kind}: {diagnosis.explanation}", diagnosis.remediation)
        self.date_header = response.headers.get("date")
        return passed(name, f"HTTP {response.status_code} from {self.ctx.gateway_url}")

    async def transport_security(self) -> CheckResult:
        name = "transport.security"
        parsed = urlparse(self.ctx.gateway_url)
        if parsed.scheme != "https":
            if is_loopback(parsed.hostname or ""):
                return passed(name, "plaintext HTTP on the loopback interface (acceptable for local development)")
            return warned(
                name,
                "plaintext HTTP: bearer tokens and tool traffic are readable by anything on the path",
                "Terminate TLS at the gateway, or put it behind a mesh sidecar that enforces mTLS on every hop.",
            )
        if self.ctx.gateway_transport is not None:
            return skipped(name, "custom transport in use; TLS not inspected")
        try:
            info = await inspect_tls(self.ctx.gateway_url, self.ctx.timeout_s, self.ctx.verify)
        except (OSError, ssl.SSLError) as exc:
            diagnosis = classify_connection_error(exc)
            return failed(name, f"{diagnosis.kind}: {diagnosis.explanation}", diagnosis.remediation)
        days_left = (info.not_after - _utc_now(self.ctx.now())).days
        if info.version in ("TLSv1", "TLSv1.1", "SSLv3"):
            return failed(name, f"{info.version} negotiated", "Disable protocol versions below TLS 1.2.")
        if days_left < 0:
            return failed(name, f"certificate expired {-days_left} days ago", "Renew the certificate.")
        if days_left < CERT_WARN_DAYS:
            return warned(name, f"{info.version}; certificate expires in {days_left} days", "Check automated certificate rotation.")
        return passed(name, f"{info.version}, {info.cipher}; certificate valid for another {days_left} days")

    async def clock_skew(self) -> CheckResult:
        name = "clock.skew"
        if not self.date_header:
            return skipped(name, "gateway sent no Date header")
        try:
            remote = email.utils.parsedate_to_datetime(self.date_header).timestamp()
        except (TypeError, ValueError):
            return skipped(name, "unparseable Date header")
        skew = remote - self.ctx.now()
        hint = "Sync both hosts with NTP/chrony. JWT exp/iat/nbf checks fail when clocks drift, which looks like random 401s."
        if abs(skew) > SKEW_FAIL_S:
            return failed(name, f"gateway clock differs by {skew:+.0f}s; tokens will be rejected as expired or not yet valid", hint)
        if abs(skew) > SKEW_WARN_S:
            return warned(name, f"gateway clock differs by {skew:+.0f}s", hint)
        return passed(name, f"gateway clock within {abs(skew):.0f}s of this machine")

    # ------------------------------------------------------------------ authentication

    def _expect_rejected(self, name: str, reply: Reply, what: str, fix: str | None = None) -> CheckResult:
        if reply.error is not None:
            diagnosis = classify_connection_error(reply.error)
            return failed(name, f"request failed: {diagnosis.kind}", diagnosis.remediation)
        if reply.rejected:
            return passed(name, f"{what} rejected with HTTP {reply.status}")
        if reply.accepted:
            return failed(
                name,
                f"{what} was ACCEPTED (HTTP {reply.status})",
                fix
                or "The gateway is not enforcing this check. Verify the verifier pins algorithms=[HS256], requires exp, and "
                "that no upstream proxy or mesh policy bypasses authentication for this route.",
            )
        return warned(name, f"{what} got unexpected HTTP {reply.status}", "Expected 401; inspect the gateway logs.")

    async def missing_token(self) -> CheckResult:
        return self._expect_rejected("auth.missing-token", await self.gw(LIST_TOOLS), "a request with no credentials")

    async def malformed_token(self) -> CheckResult:
        return self._expect_rejected("auth.malformed-token", await self.gw(LIST_TOOLS, "not.a.jwt"), "a malformed token")

    async def wrong_signature(self) -> CheckResult:
        forged = jwt.encode(
            {"sub": "zt-probe", "role": "admin", "exp": int(self.ctx.now()) + 300}, "zt-probe-" + "x" * 40, algorithm="HS256"
        )
        return self._expect_rejected("auth.wrong-signature", await self.gw(LIST_TOOLS, forged), "a token signed with the wrong key")

    async def alg_none(self) -> CheckResult:
        unsigned = jwt.encode({"sub": "zt-probe", "role": "admin", "exp": int(self.ctx.now()) + 300}, key=None, algorithm="none")
        return self._expect_rejected("auth.alg-none", await self.gw(LIST_TOOLS, unsigned), "an unsigned (alg=none) token")

    async def expired_token(self) -> CheckResult:
        if not self.ctx.secret:
            return skipped("auth.expired-token", "needs the signing secret to mint a validly signed expired token")
        reply = await self.gw(LIST_TOOLS, self.mint("viewer", ttl_s=60, offset_s=-3600))
        result = self._expect_rejected("auth.expired-token", reply, "a correctly signed but expired token")
        if result.status is Status.FAIL and reply.accepted:
            return failed(
                result.name,
                result.detail,
                "Expiry is not enforced: check JWT_LEEWAY_S (a large leeway makes old tokens live on) and that exp is required.",
            )
        return result

    async def valid_token(self) -> CheckResult:
        name = "auth.valid-token"
        if not self.ctx.secret:
            return skipped(name, "needs the signing secret; supply --secret-env")
        reply = await self.gw(LIST_TOOLS, self.mint("viewer"))
        if reply.error is not None:
            diagnosis = classify_connection_error(reply.error)
            return failed(name, f"request failed: {diagnosis.kind}", diagnosis.remediation)
        if reply.accepted:
            return passed(name, "a freshly minted viewer token is accepted and tools/list is forwarded")
        if reply.status == 403:
            return failed(name, "token verified but the gateway answered 403", "The role claim is missing or not one of the roles the gateway knows (admin, viewer).")
        if reply.status == 401:
            backdated = await self.gw(LIST_TOOLS, self.mint("viewer", ttl_s=900, offset_s=-300))
            if backdated.accepted:
                return failed(
                    name,
                    "rejected when issued now but accepted when issued 5 minutes earlier: the gateway clock is behind, "
                    "so fresh tokens look 'not yet valid'",
                    "Fix time sync on the gateway host (NTP), or set a small JWT_LEEWAY_S as a stop-gap.",
                )
            return failed(
                name,
                f"rejected with 401 (probe secret fingerprint {_fingerprint(self.ctx.secret)})",
                "Most likely a secret mismatch: compare the fingerprint of GATEWAY_JWT_SECRET on the gateway "
                "(sha256, first 8 hex characters) or an issuer/audience mismatch (JWT_ISSUER / JWT_AUDIENCE).",
            )
        return warned(name, f"unexpected HTTP {reply.status}", "Inspect the gateway logs.")

    # ------------------------------------------------------------------ authorization

    async def viewer_blocked(self) -> CheckResult:
        name = "authz.viewer-blocked-from-admin-tools"
        if not self.ctx.secret:
            return skipped(name, "needs the signing secret")
        reply = await self.gw(CALL_ADMIN_TOOL, self.mint("viewer"))
        if reply.rpc_error_code == -32001 or reply.status == 403:
            return passed(name, "denied at the gateway with -32001 Unauthorized Tool Call")
        if reply.status == 401:
            return warned(name, "token rejected, so authorization could not be evaluated", "Resolve auth.valid-token first.")
        if reply.error is not None:
            return warned(name, "request failed", classify_connection_error(reply.error).remediation)
        return failed(
            name,
            f"a viewer reached the admin tool path (HTTP {reply.status}, JSON-RPC code {reply.rpc_error_code})",
            "Authorization is not being enforced at the gateway. Do not rely on the downstream to refuse: enforce the "
            "tools/call policy at this hop.",
        )

    async def name_variants(self) -> CheckResult:
        name = "authz.admin-name-variants"
        if not self.ctx.secret:
            return skipped(name, "needs the signing secret")
        token, leaks = self.mint("viewer"), []
        for variant in (PROBE_TOOL.upper(), f" {PROBE_TOOL}", PROBE_TOOL.capitalize()):
            body = {**CALL_ADMIN_TOOL, "params": {"name": variant, "arguments": {}}}
            reply = await self.gw(body, token)
            if reply.status == 200 and reply.rpc_error_code != -32001:
                leaks.append(repr(variant))
        if leaks:
            return failed(
                name,
                f"viewer calls with altered tool names were not denied: {', '.join(leaks)}",
                "Compare tool names after normalisation (NFKC, trim, case-fold) so the gateway and downstream agree on what an admin tool is.",
            )
        return passed(name, "case, whitespace and capitalisation variants are denied")

    async def admin_allowed(self) -> CheckResult:
        name = "authz.admin-allowed"
        if not self.ctx.secret:
            return skipped(name, "needs the signing secret")
        reply = await self.gw(CALL_ADMIN_TOOL, self.mint("admin"))
        if reply.rpc_error_code == -32001 or reply.rejected:
            return failed(name, f"an admin token was refused (HTTP {reply.status})", "Check the role claim in tokens minted for admins and the gateway's role handling.")
        if reply.error is not None:
            return warned(name, "request failed", classify_connection_error(reply.error).remediation)
        return passed(name, f"an admin token passes the gateway (HTTP {reply.status}); the downstream decides the rest")

    # ------------------------------------------------------------------ information disclosure

    async def no_leakage(self) -> CheckResult:
        name = "errors.no-internal-detail"
        replies = [await self.gw(b"{broken json"), await self.gw(b"\xff\xfe", "x.y.z")]
        if self.ctx.secret:
            token = self.mint("viewer")
            replies += [await self.gw(b"{broken json", token), await self.gw({"jsonrpc": "2.0", "id": 9, "method": 5}, token)]
        found: set[str] = set()
        for reply in replies:
            haystack = reply.text + " " + " ".join(f"{k}: {v}" for k, v in reply.headers.items())
            found.update(label for label, pattern in _LEAK_PATTERNS.items() if pattern.search(haystack))
        if found:
            return failed(
                name,
                f"error responses expose: {', '.join(sorted(found))}",
                "Return fixed error bodies, log details server-side with a request id, and disable debug/traceback modes.",
            )
        return passed(name, f"{len(replies)} malformed requests produced no stack traces, paths, hosts or connection strings")

    # ------------------------------------------------------------------ downstream isolation

    async def downstream_checks(self) -> list[CheckResult]:
        assert self.downstream is not None
        path = self.ctx.mcp_path
        first = await self.post(self.downstream, path, LIST_TOOLS)
        if first.error is not None:
            diagnosis = classify_connection_error(first.error)
            return [
                passed("downstream.no-anonymous-access", f"not reachable from this vantage point ({diagnosis.kind}), consistent with network segmentation"),
                skipped("downstream.rejects-end-user-token", "downstream not reachable from here"),
                skipped("downstream.rejects-spoofed-identity", "downstream not reachable from here"),
                skipped("downstream.gateway-credential", "downstream not reachable from here"),
            ]

        results = []
        if first.accepted:
            results.append(
                failed(
                    "downstream.no-anonymous-access",
                    f"the downstream answered an unauthenticated request (HTTP {first.status})",
                    _DOWNSTREAM_FIX,
                )
            )
        else:
            results.append(self._expect_rejected("downstream.no-anonymous-access", first, "an anonymous request to the downstream", _DOWNSTREAM_FIX))

        if self.ctx.secret:
            reply = await self.post(self.downstream, path, LIST_TOOLS, self.mint("admin"))
            results.append(
                self._expect_rejected(
                    "downstream.rejects-end-user-token",
                    reply,
                    "an end-user admin JWT presented directly",
                    "The downstream accepts end-user tokens meant for the gateway, so a caller can skip the gateway's policy. "
                    "Give the downstream its own audience/credential and refuse tokens issued to end users.",
                )
            )
        else:
            results.append(skipped("downstream.rejects-end-user-token", "needs the signing secret"))

        spoofed = await self.post(
            self.downstream, path, LIST_TOOLS, headers={"x-authenticated-user": "root", "x-authenticated-role": "admin"}
        )
        results.append(
            self._expect_rejected(
                "downstream.rejects-spoofed-identity",
                spoofed,
                "identity headers without a credential",
                "The downstream believes X-Authenticated-* headers from anyone. Only honour them on connections that "
                "authenticated as the gateway, and strip them at the edge.",
            )
        )

        if self.ctx.downstream_token:
            reply = await self.post(self.downstream, path, LIST_TOOLS, self.ctx.downstream_token)
            if reply.accepted:
                results.append(passed("downstream.gateway-credential", "the configured gateway credential is accepted"))
            else:
                results.append(
                    failed(
                        "downstream.gateway-credential",
                        f"the gateway credential was refused (HTTP {reply.status})",
                        "The gateway would see 401 from its downstream: DOWNSTREAM_TOKEN differs between the two, or was rotated on one side only.",
                    )
                )
        else:
            results.append(skipped("downstream.gateway-credential", "no downstream credential supplied"))
        return results


def _utc_now(epoch: float):
    import datetime as dt

    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc)


async def _safe(name: str, check: Callable[[], Awaitable[CheckResult]]) -> CheckResult:
    try:
        return await check()
    except Exception as exc:  # a broken probe must never hide the rest of the report
        return failed(name, f"probe error: {type(exc).__name__}", "This is a bug in the diagnostic, not necessarily in the deployment.")


async def run_diagnostics(ctx: ProbeContext) -> list[CheckResult]:
    timeout = httpx.Timeout(ctx.timeout_s)
    async with httpx.AsyncClient(
        base_url=ctx.gateway_url, timeout=timeout, verify=ctx.verify, transport=ctx.gateway_transport
    ) as gateway:
        downstream_client = (
            httpx.AsyncClient(base_url=ctx.downstream_url, timeout=timeout, verify=ctx.verify, transport=ctx.downstream_transport)
            if ctx.downstream_url
            else None
        )
        try:
            prober = Prober(ctx, gateway, downstream_client)
            results = [await _safe("gateway.reachable", prober.reachable)]
            if results[0].status is Status.FAIL:
                blocked = "gateway unreachable"
                names = [
                    "transport.security", "clock.skew", "auth.missing-token", "auth.malformed-token", "auth.wrong-signature",
                    "auth.alg-none", "auth.expired-token", "auth.valid-token", "authz.viewer-blocked-from-admin-tools",
                    "authz.admin-name-variants", "authz.admin-allowed", "errors.no-internal-detail",
                ]
                results += [skipped(name, blocked) for name in names]
            else:
                for name, check in (
                    ("transport.security", prober.transport_security),
                    ("clock.skew", prober.clock_skew),
                    ("auth.missing-token", prober.missing_token),
                    ("auth.malformed-token", prober.malformed_token),
                    ("auth.wrong-signature", prober.wrong_signature),
                    ("auth.alg-none", prober.alg_none),
                    ("auth.expired-token", prober.expired_token),
                    ("auth.valid-token", prober.valid_token),
                    ("authz.viewer-blocked-from-admin-tools", prober.viewer_blocked),
                    ("authz.admin-name-variants", prober.name_variants),
                    ("authz.admin-allowed", prober.admin_allowed),
                    ("errors.no-internal-detail", prober.no_leakage),
                ):
                    results.append(await _safe(name, check))
            if downstream_client is not None:
                try:
                    results += await prober.downstream_checks()
                except Exception as exc:
                    results.append(failed("downstream.checks", f"probe error: {type(exc).__name__}", "This is a bug in the diagnostic."))
        finally:
            if downstream_client is not None:
                await downstream_client.aclose()
    return results

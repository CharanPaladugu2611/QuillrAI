"""Network-level diagnosis: why can't I connect, and what does the TLS layer look like."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ConnectionDiagnosis:
    kind: str
    explanation: str
    remediation: str


def _chain(exc: BaseException | None):
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def classify_connection_error(exc: BaseException) -> ConnectionDiagnosis:
    """Map a low-level failure onto the zero-trust layer that most likely caused it."""
    chain = list(_chain(exc))
    for error in chain:
        if isinstance(error, socket.gaierror):
            return ConnectionDiagnosis(
                "dns",
                "the host name did not resolve",
                "Check the URL and the resolver this machine uses. Internal names often exist only inside the "
                "service mesh or VPN, so run the probe from a vantage point that is allowed to resolve them.",
            )
        if isinstance(error, ssl.SSLCertVerificationError):
            reason = (error.verify_message or str(error)).lower()
            if "expired" in reason:
                return ConnectionDiagnosis("tls-expired", "the server certificate has expired", "Renew the certificate (check automated rotation).")
            if "hostname" in reason or "doesn't match" in reason or "does not match" in reason:
                return ConnectionDiagnosis(
                    "tls-hostname",
                    "the certificate does not cover the host name used",
                    "Reissue the certificate with the right SAN entries, or call the service by the name on the certificate.",
                )
            return ConnectionDiagnosis(
                "tls-untrusted",
                f"the certificate chain is not trusted ({error.verify_message or 'unknown issuer'})",
                "Provide the internal CA bundle (--ca-bundle) or install the CA; do not disable verification.",
            )
        if isinstance(error, ssl.SSLError):
            text = str(error).lower()
            if "certificate required" in text or "handshake failure" in text or "bad certificate" in text:
                return ConnectionDiagnosis(
                    "mtls",
                    "the server rejected the TLS handshake, which usually means it requires a client certificate",
                    "Supply --client-cert and --client-key issued by a CA the service trusts, and check that the certificate is not expired or revoked.",
                )
            return ConnectionDiagnosis(
                "tls-handshake",
                f"TLS handshake failed ({getattr(error, 'reason', None) or 'protocol error'})",
                "Check that both sides share a TLS version (>= 1.2) and cipher suite, and that the port really speaks TLS.",
            )
        if isinstance(error, ConnectionRefusedError):
            return ConnectionDiagnosis(
                "refused",
                "the connection was actively refused: nothing is listening on that address and port",
                "Check the service is running and bound to this interface, and that the port is correct.",
            )
        if isinstance(error, ConnectionResetError):
            return ConnectionDiagnosis(
                "reset",
                "the connection was reset after it was opened",
                "A policy engine or sidecar probably dropped the peer: check network policy / mesh authorization logs for this source identity.",
            )
    names = " ".join(type(e).__name__ for e in chain)
    if "Timeout" in names or any(isinstance(e, (TimeoutError, asyncio.TimeoutError)) for e in chain):
        return ConnectionDiagnosis(
            "timeout",
            "no answer within the timeout: packets are being dropped rather than rejected",
            "Silent drops typically come from a firewall or default-deny network policy. Confirm the source is allow-listed and the route exists.",
        )
    return ConnectionDiagnosis("unknown", f"connection failed ({type(exc).__name__})", "Inspect the service logs and the network path.")


def build_ssl_context(
    ca_bundle: str | None = None, client_cert: str | None = None, client_key: str | None = None
) -> ssl.SSLContext | bool:
    """Verification stays on; the context only adds a private CA and/or a client certificate."""
    if not (ca_bundle or client_cert):
        return True
    context = ssl.create_default_context(cafile=ca_bundle)
    if client_cert:
        context.load_cert_chain(client_cert, client_key)
    return context


def is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class TlsInfo:
    version: str
    cipher: str
    not_after: dt.datetime
    subject: str


def _inspect_tls_blocking(host: str, port: int, timeout: float, context: ssl.SSLContext) -> TlsInfo:
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            not_after = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
            subject = ", ".join("=".join(pair) for rdn in cert.get("subject", ()) for pair in rdn)
            return TlsInfo(tls.version() or "unknown", (tls.cipher() or ("unknown",))[0], not_after, subject)


async def inspect_tls(url: str, timeout: float, context: ssl.SSLContext | bool = True) -> TlsInfo:
    parsed = urlparse(url)
    ssl_context = context if isinstance(context, ssl.SSLContext) else ssl.create_default_context()
    return await asyncio.to_thread(_inspect_tls_blocking, parsed.hostname or "", parsed.port or 443, timeout, ssl_context)

"""Explain why a gateway bearer token is (or is not) going to be accepted.

Decoding never trusts the token: the payload is read without verifying anything, and
the signature is checked only when the signing secret is supplied.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import jwt

from task2_mcp_gateway.auth import ALGORITHM, ROLES

from .model import Status

LONG_LIVED_SECONDS = 24 * 3600
EXPIRING_SOON_SECONDS = 60


@dataclass(frozen=True)
class Finding:
    status: Status
    message: str


@dataclass
class TokenReport:
    header: dict[str, Any] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    signature: str = "not checked"

    @property
    def acceptable(self) -> bool:
        return not any(f.status is Status.FAIL for f in self.findings)

    def render(self) -> str:
        lines = [f"header     {self.header}", f"claims     {self.claims}", f"signature  {self.signature}", ""]
        lines += [f"[{f.status.value}] {f.message}" for f in self.findings]
        lines.append("")
        lines.append("verdict    " + ("the gateway should accept this token" if self.acceptable else "the gateway will reject this token"))
        return "\n".join(lines)


def _duration(seconds: float) -> str:
    seconds = int(abs(seconds))
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def inspect_token(token: str, *, secret: str | None = None, now: float | None = None) -> TokenReport:
    now = time.time() if now is None else now
    report = TokenReport()
    add = lambda status, message: report.findings.append(Finding(status, message))

    try:
        report.header = jwt.get_unverified_header(token)
        report.claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
    except jwt.PyJWTError:
        add(Status.FAIL, "not a JWT: expected three base64url segments (header.payload.signature)")
        return report

    algorithm = report.header.get("alg")
    if str(algorithm).lower() == "none":
        add(Status.FAIL, "unsigned token (alg=none); the gateway pins its algorithm list and will refuse it")
    elif algorithm != ALGORITHM:
        add(Status.FAIL, f"algorithm {algorithm!r} is not accepted; the gateway only verifies {ALGORITHM}")
    else:
        add(Status.PASS, f"algorithm {ALGORITHM}")

    claims = report.claims
    for required in ("sub", "exp"):
        if required not in claims:
            add(Status.FAIL, f"missing required claim '{required}'")
    role = claims.get("role")
    if role is None:
        add(Status.FAIL, "no 'role' claim; the gateway answers 403 for tokens without a recognised role")
    elif role not in ROLES:
        add(Status.FAIL, f"role {role!r} is not one of {sorted(ROLES)}; the gateway answers 403")
    else:
        add(Status.PASS, f"role {role!r}")

    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
    if isinstance(exp, (int, float)):
        remaining = exp - now
        if remaining <= 0:
            add(Status.FAIL, f"expired {_duration(remaining)} ago; if it was minted moments ago, issuer and gateway clocks disagree")
        elif remaining < EXPIRING_SOON_SECONDS:
            add(Status.WARN, f"expires in {_duration(remaining)}; long requests may outlive it")
        else:
            add(Status.PASS, f"valid for another {_duration(remaining)}")
        if isinstance(iat, (int, float)) and exp - iat > LONG_LIVED_SECONDS:
            add(Status.WARN, f"lifetime of {_duration(exp - iat)} is long for a bearer token; shorter lifetimes limit theft impact")
    for name, value in (("iat", iat), ("nbf", nbf)):
        if isinstance(value, (int, float)) and value - now > 0:
            add(
                Status.FAIL,
                f"'{name}' is {_duration(value - now)} in the future: not yet valid. "
                "Issuer clock is ahead of this machine, or this machine's clock is behind; check NTP on both",
            )
    if "iss" in claims or "aud" in claims:
        add(Status.PASS, "carries iss/aud; the gateway must be started with matching JWT_ISSUER / JWT_AUDIENCE")

    if secret is not None:
        try:
            jwt.decode(token, secret, algorithms=[ALGORITHM], options={"verify_exp": False, "verify_aud": False, "verify_iss": False, "verify_iat": False, "verify_nbf": False})
            report.signature = "valid for the supplied secret"
            add(Status.PASS, "signature verifies with the supplied secret")
        except jwt.InvalidSignatureError:
            report.signature = "INVALID"
            add(Status.FAIL, "signature does not verify: the gateway uses a different secret, or the token was altered")
        except jwt.PyJWTError as exc:
            report.signature = "unverifiable"
            add(Status.FAIL, f"signature could not be verified ({type(exc).__name__})")
    return report

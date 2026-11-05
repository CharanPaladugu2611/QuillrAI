"""Result types shared by the zero-trust diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    detail: str
    remediation: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "remediation": self.remediation,
        }


def passed(name: str, detail: str) -> CheckResult:
    return CheckResult(name, Status.PASS, detail)


def warned(name: str, detail: str, remediation: str) -> CheckResult:
    return CheckResult(name, Status.WARN, detail, remediation)


def failed(name: str, detail: str, remediation: str) -> CheckResult:
    return CheckResult(name, Status.FAIL, detail, remediation)


def skipped(name: str, detail: str) -> CheckResult:
    return CheckResult(name, Status.SKIP, detail)

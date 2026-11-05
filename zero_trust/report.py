"""Human and machine-readable rendering of diagnostic results."""

from __future__ import annotations

import json
import textwrap
from collections import Counter

from .model import CheckResult, Status

_MARKS = {Status.PASS: "PASS", Status.WARN: "WARN", Status.FAIL: "FAIL", Status.SKIP: "SKIP"}


def summarise(results: list[CheckResult]) -> Counter:
    return Counter(result.status for result in results)


def exit_code(results: list[CheckResult]) -> int:
    return 1 if any(r.status is Status.FAIL for r in results) else 0


def render_text(results: list[CheckResult], title: str) -> str:
    width = max((len(r.name) for r in results), default=10)
    lines = [title, ""]
    for result in results:
        lines.append(f"  {_MARKS[result.status]}  {result.name:<{width}}  {result.detail}")
        if result.remediation and result.status in (Status.FAIL, Status.WARN):
            prefix = " " * 8 + "fix: "
            lines.append(textwrap.fill(result.remediation, width=110, initial_indent=prefix, subsequent_indent=" " * len(prefix)))
    counts = summarise(results)
    lines += [
        "",
        f"{counts[Status.PASS]} passed, {counts[Status.WARN]} warnings, {counts[Status.FAIL]} failed, {counts[Status.SKIP]} skipped",
    ]
    return "\n".join(lines)


def render_json(results: list[CheckResult]) -> str:
    counts = summarise(results)
    return json.dumps(
        {"summary": {status.value.lower(): counts[status] for status in Status}, "checks": [r.as_dict() for r in results]},
        indent=2,
    )

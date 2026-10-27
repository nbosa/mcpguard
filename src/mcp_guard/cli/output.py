"""Shared CLI helpers: exit codes, IO and rendering."""

from __future__ import annotations

import json
import sys
from typing import Any, Iterable

from ..core.result import CheckReport

__all__ = [
    "EXIT_OK",
    "EXIT_FINDINGS",
    "EXIT_ERROR",
    "read_input",
    "write_output",
    "render_report",
    "render_json",
]

#: Everything went fine.
EXIT_OK = 0

#: The run found something that violates the policy.
EXIT_FINDINGS = 1

#: Usage error, unreadable input or an internal failure.
EXIT_ERROR = 2


def read_input(path: str | None, *, stdin_text: str | None = None) -> str:
    """Read a payload from ``path`` (``None``/``"-"`` means stdin)."""
    if path in (None, "-"):
        if stdin_text is not None:
            return stdin_text
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def write_output(text: str, path: str | None = None) -> None:
    """Write ``text`` to ``path`` or stdout."""
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return
    sys.stdout.write(text)


def render_json(payload: Any) -> str:
    """Serialise ``payload`` as indented JSON."""
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def render_report(report: CheckReport) -> str:
    """Render a check report as human readable text."""
    lines: list[str] = []
    lines.append(f"policy: {report.policy_name} ({report.policy_version})")
    highest = report.max_severity.value if report.max_severity else "-"
    lines.append(f"verdict: {report.verdict.value}  (max severity: {highest})")
    lines.append(f"findings: {len(report.findings)}")
    if report.findings:
        lines.append("")
    for finding in report.findings:
        lines.append(f"  [{finding.severity.value}] {finding.rule_id} ({finding.plugin}): {finding.message}")
        if finding.location:
            lines.append(f"      location: {finding.location}")
        if finding.evidence:
            lines.append(f"      evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"      fix: {finding.remediation}")
    return "\n".join(lines) + "\n"


def iter_lines(values: Iterable[str]) -> str:
    return "\n".join(f"  - {value}" for value in values)

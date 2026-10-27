"""Helpers shared by the CLI commands."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from ..core.policy import Policy, default_policy, load_policy
from ..core.severity import Severity, parse_severity

__all__ = [
    "load_policy_for_cli",
    "read_json_file",
    "read_text_argument",
    "override_fail_on",
    "fail",
]


def fail(message: str, code: int = 2) -> int:
    """Print ``message`` on stderr and return the exit code."""
    sys.stderr.write(f"mcp-guard: {message}\n")
    return code


def load_policy_for_cli(path: str | None) -> Policy:
    """Load a policy for the CLI, raising :class:`PolicyError` on failure."""
    if not path:
        return default_policy()
    return load_policy(path)


def override_fail_on(policy: Policy, value: str | None) -> Policy:
    """Return a copy of ``policy`` with ``fail_on`` replaced."""
    if not value:
        return policy
    severity = parse_severity(value)
    return dataclasses.replace(policy, fail_on=severity)


def read_json_file(path: str) -> Any:
    """Read and parse a JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_text_argument(path: str | None) -> str:
    """Read a text payload from a path or stdin (``-``/``None``)."""
    if path in (None, "-"):
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def severity_or_none(value: str | None) -> Severity | None:
    if not value:
        return None
    return parse_severity(value)

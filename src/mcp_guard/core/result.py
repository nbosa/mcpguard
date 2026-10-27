"""Finding, verdict and report data model.

Every plugin returns :class:`Finding` objects; the engine aggregates them into a
:class:`CheckReport` with an overall :class:`Verdict` that the CLI maps to an
exit code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .severity import Severity, max_severity

__all__ = ["Verdict", "Finding", "CheckReport"]


class Verdict(str, Enum):
    """Overall outcome of a guard run."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"

    def __str__(self) -> str:
        return self.value

    @property
    def ok(self) -> bool:
        """``True`` when the run did not fail."""
        return self in (Verdict.PASS, Verdict.WARN)


@dataclass
class Finding:
    """A single rule violation or observation produced by a plugin."""

    rule_id: str
    plugin: str
    severity: Severity
    message: str
    evidence: str = ""
    location: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "plugin": self.plugin,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
            "location": self.location,
            "remediation": self.remediation,
            "metadata": dict(self.metadata),
        }

    def to_text(self) -> str:
        """One-line human readable rendering."""
        head = f"[{self.severity.value}] {self.rule_id} ({self.plugin}): {self.message}"
        if self.location:
            head += f" @ {self.location}"
        if self.evidence:
            head += f" | {self.evidence}"
        return head


@dataclass
class CheckReport:
    """Aggregated result of a guard run."""

    findings: list[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.PASS
    policy_name: str = ""
    policy_version: str = ""
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def max_severity(self) -> Severity | None:
        return max_severity([finding.severity for finding in self.findings])

    @property
    def ok(self) -> bool:
        return self.verdict.ok

    def by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity, highest first."""
        buckets: dict[str, list[Finding]] = {}
        for finding in self.findings:
            buckets.setdefault(finding.severity.value, []).append(finding)
        ordered = sorted(
            buckets.items(),
            key=lambda item: Severity[item[0]].rank,
            reverse=True,
        )
        return {key: value for key, value in ordered}

    def count_by_plugin(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.plugin] = counts.get(finding.plugin, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "policy": {
                "name": self.policy_name,
                "version": self.policy_version,
            },
            "summary": {
                "total": len(self.findings),
                "max_severity": (self.max_severity.value if self.max_severity else None),
                "by_severity": {
                    key: len(value) for key, value in self.by_severity().items()
                },
                "by_plugin": self.count_by_plugin(),
            },
            "stats": dict(self.stats),
            "findings": [finding.to_dict() for finding in self.findings],
        }

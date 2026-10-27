"""Plugin base class, rule resolution and self-test contracts.

Every guard capability is a plugin. A plugin declares a catalogue of built-in
rules (``RULES``); a policy may enable, disable, re-severity or re-message any of
them without touching code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .policy import Policy
from .result import Finding
from .severity import Severity, parse_severity

__all__ = [
    "PluginContext",
    "ResolvedRule",
    "SelfTestCase",
    "GuardPlugin",
]


@dataclass(frozen=True)
class PluginContext:
    """Everything a plugin needs to run."""

    policy: Policy
    settings: Mapping[str, Any] = field(default_factory=dict)
    home_dir: str = ""

    def option(self, key: str, default: Any = None) -> Any:
        """Read a plugin setting, falling back to ``default``."""
        value = self.settings.get(key, default)
        return default if value is None else value


@dataclass(frozen=True)
class ResolvedRule:
    """A rule after merging the plugin default with the policy override."""

    id: str
    plugin: str
    enabled: bool
    severity: Severity
    message: str
    remediation: str = ""
    target: str = "any"
    regex: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "plugin": self.plugin,
            "enabled": self.enabled,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
            "target": self.target,
            "regex": self.regex,
        }


@dataclass
class SelfTestCase:
    """Result of one built-in self-test assertion."""

    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


class GuardPlugin:
    """Base class for all guard plugins."""

    #: Stable plugin identifier, also used as the policy settings block name.
    name: str = "base"

    #: Key of the ``[settings.<key>]`` policy block read by this plugin.
    settings_key: str = ""

    #: Plugin version, bumped independently of the release version.
    version: str = "0.0.0"

    #: Built-in rule catalogue: ``rule_id -> {severity, message, remediation}``.
    RULES: dict[str, dict[str, Any]] = {}

    def __init__(self, context: PluginContext) -> None:
        self.context = context
        self.settings: dict[str, Any] = dict(context.settings or {})

    @classmethod
    def settings_block(cls) -> str:
        """The policy settings key this plugin reads."""
        return cls.settings_key or cls.name

    # -- rule helpers -----------------------------------------------------
    def rule(self, rule_id: str) -> ResolvedRule:
        """Resolve ``rule_id`` against the plugin defaults and policy overrides.

        The policy lookup is scoped to *this* plugin: a rule id declared under
        a different plugin -- for instance ``plugin = "custom"`` reusing the
        id ``PATH-001`` -- cannot disable or re-severity a built-in rule
        (AUD-12).
        """
        base = dict(self.RULES.get(rule_id) or {})
        override = self.context.policy.rule(rule_id, self.name)
        severity = parse_severity(base.get("severity", Severity.MEDIUM), Severity.MEDIUM)
        if override is not None and override.severity is not None:
            severity = override.severity
        message = base.get("message", "")
        if override is not None and override.message:
            message = override.message
        enabled = True
        if override is not None:
            enabled = override.enabled
        target = base.get("target", "any")
        if override is not None and override.target:
            target = override.target
        regex = base.get("regex")
        if override is not None and override.regex:
            regex = override.regex
        return ResolvedRule(
            id=rule_id,
            plugin=self.name,
            enabled=enabled,
            severity=severity,
            message=message,
            remediation=base.get("remediation", ""),
            target=target,
            regex=regex,
        )

    def finding(
        self,
        rule_id: str,
        message: str | None = None,
        evidence: str = "",
        location: str = "",
        remediation: str | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
    ) -> Finding | None:
        """Create a finding for ``rule_id``; returns ``None`` when disabled."""
        rule = self.rule(rule_id)
        if not rule.enabled:
            return None
        return Finding(
            rule_id=rule.id,
            plugin=self.name,
            severity=severity if severity is not None else rule.severity,
            message=message or rule.message,
            evidence=evidence,
            location=location,
            remediation=remediation if remediation is not None else rule.remediation,
            metadata=dict(metadata or {}),
        )

    def emit(
        self,
        findings: list[Finding],
        rule_id: str,
        message: str | None = None,
        evidence: str = "",
        location: str = "",
        remediation: str | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
    ) -> None:
        """Append a finding to ``findings`` unless the rule is disabled."""
        finding = self.finding(
            rule_id,
            message=message,
            evidence=evidence,
            location=location,
            remediation=remediation,
            metadata=metadata,
            severity=severity,
        )
        if finding is not None:
            findings.append(finding)

    # -- plugin contract --------------------------------------------------
    def analyze(self, request) -> list[Finding]:
        """Inspect a request and return findings. Subclasses override this."""
        return []

    def self_test(self) -> list[SelfTestCase]:
        """Run built-in assertions; used by ``mcp-guard selftest``."""
        return []

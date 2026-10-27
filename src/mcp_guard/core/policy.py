"""Policy model and loader.

Policies are TOML documents (standard library :mod:`tomllib`, no third-party
dependency) with three top-level sections::

    [meta]      policy identity
    [settings]  global thresholds and per-plugin settings
    [[rule]]    optional per-rule overrides

Example::

    [meta]
    name = "prod"
    version = "1.0.0"

    [settings]
    fail_on = "HIGH"

    [settings.canary]
    tokens = ["CANARY-AAAA-1111"]

    [[rule]]
    id = "PATH-002"
    plugin = "path_shape"
    severity = "CRITICAL"
    enabled = true
"""

from __future__ import annotations

import copy
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .severity import Severity, parse_severity

__all__ = [
    "RuleSpec",
    "Policy",
    "PolicyIssue",
    "PolicyError",
    "parse_policy",
    "load_policy",
    "load_policy_text",
    "default_policy",
    "default_policy_doc",
    "DEFAULT_POLICY_DOC",
    "RULE_ID_RE",
]

#: Rule identifiers look like ``PATH-001``.
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*-\d{3}$")

#: Plugin identifier -> the key of its ``[settings.<key>]`` policy block.
PLUGIN_SETTINGS_KEYS: dict[str, str] = {
    "etdi_pinning": "etdi",
    "ansi_sanitize": "ansi",
    "path_shape": "path",
    "canary_exfil": "canary",
}

_TOP_LEVEL_KEYS = frozenset({"meta", "settings", "rule"})
_GLOBAL_SETTING_KEYS = frozenset(
    {
        "fail_on",
        "warn_on",
        "redact_evidence",
        "max_evidence_chars",
        "strict",
        "etdi",
        "path",
        "ansi",
        "canary",
    }
)
_RULE_KEYS = frozenset(
    {"id", "plugin", "enabled", "severity", "message", "regex", "target", "description"}
)
_RULE_TARGETS = frozenset({"any", "arguments", "content", "transcript", "calls", "results"})


@dataclass(frozen=True)
class RuleSpec:
    """A rule override declared in a policy file."""

    id: str
    plugin: str
    enabled: bool = True
    severity: Severity = Severity.MEDIUM
    message: str = ""
    regex: str | None = None
    target: str = "any"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "plugin": self.plugin,
            "enabled": self.enabled,
            "severity": self.severity.value,
            "message": self.message,
            "regex": self.regex,
            "target": self.target,
            "description": self.description,
        }


@dataclass(frozen=True)
class Policy:
    """A parsed, immutable policy."""

    name: str = "mcp-guard-default"
    version: str = "1.0.0"
    locale: str = "en"
    fail_on: Severity = Severity.HIGH
    warn_on: Severity = Severity.MEDIUM
    redact_evidence: bool = True
    max_evidence_chars: int = 240
    strict: bool = True
    settings: Mapping[str, Any] = field(default_factory=dict)
    rules: tuple[RuleSpec, ...] = ()
    source_path: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def rule(self, rule_id: str, plugin: str | None = None) -> RuleSpec | None:
        """Return the override for ``rule_id`` if the policy declares one.

        Rule ids are only unique *within* a plugin.  When ``plugin`` is given,
        only a spec that belongs to that very plugin is returned, so a rule
        that declares ``plugin = "custom"`` can never reach across and
        reconfigure a built-in rule of another plugin (AUD-12).

        Without ``plugin`` the first matching spec is returned; this keeps the
        lookup usable for tooling that genuinely wants "any rule with this
        id".
        """
        for spec in self.rules:
            if spec.id != rule_id:
                continue
            if plugin is not None and spec.plugin != plugin:
                continue
            return spec
        return None

    def plugin_settings(self, plugin_name: str) -> dict[str, Any]:
        """Return the settings block for ``plugin_name`` (never ``None``).

        Both the plugin identifier (``path_shape``) and the settings key
        (``path``) are accepted, so callers do not have to know which one the
        plugin uses internally.
        """
        key = PLUGIN_SETTINGS_KEYS.get(plugin_name, plugin_name)
        value = self.settings.get(key)
        if value is None and key != plugin_name:
            value = self.settings.get(plugin_name)
        return dict(value) if isinstance(value, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {"name": self.name, "version": self.version, "locale": self.locale},
            "settings": {
                "fail_on": self.fail_on.value,
                "warn_on": self.warn_on.value,
                "redact_evidence": self.redact_evidence,
                "max_evidence_chars": self.max_evidence_chars,
                "strict": self.strict,
                **{
                    key: value
                    for key, value in self.settings.items()
                    if key in ("etdi", "path", "ansi", "canary")
                },
            },
            "rule": [spec.to_dict() for spec in self.rules],
        }


@dataclass
class PolicyIssue:
    """A problem found while parsing or linting a policy."""

    severity: Severity
    code: str
    message: str
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }

    def to_text(self) -> str:
        location = f" [{self.path}]" if self.path else ""
        return f"[{self.severity.value}] {self.code}{location}: {self.message}"


class PolicyError(Exception):
    """Raised when a policy cannot be loaded."""

    def __init__(self, message: str, issues: list[PolicyIssue] | None = None) -> None:
        super().__init__(message)
        self.issues = list(issues or [])

    def to_text(self) -> str:
        lines = [str(self)]
        lines.extend(issue.to_text() for issue in self.issues)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# default policy
# ---------------------------------------------------------------------------

DEFAULT_POLICY_DOC: dict[str, Any] = {
    "meta": {
        "name": "mcp-guard-default",
        "version": "1.0.0",
        "locale": "en",
    },
    "settings": {
        "fail_on": "HIGH",
        "warn_on": "MEDIUM",
        "redact_evidence": True,
        "max_evidence_chars": 240,
        "strict": True,
        "etdi": {
            "require_pins": True,
            "fail_on_drift": True,
            "allow_unpinned": False,
        },
        "path": {
            "sensitive_names": [
                ".ssh",
                ".aws",
                ".gnupg",
                ".kube",
                ".docker",
                ".config",
                ".netrc",
                ".npmrc",
                ".pypirc",
                "credentials",
                "secrets",
            ],
            "sensitive_files": [
                "id_rsa",
                "id_ed25519",
                "id_ecdsa",
                "id_dsa",
                ".env",
                ".env.local",
                "*.pem",
                "*.key",
                "*.p12",
                "*.pfx",
                "*.keystore",
                "shadow",
                "authorized_keys",
                "known_hosts",
                "credentials",
            ],
            "system_prefixes": [
                "/etc",
                "/proc",
                "/sys",
                "/dev",
                "/boot",
                "/var/run",
                "/var/log",
                "/root",
            ],
            "allowed_roots": [],
            "sensitive_root": "~",
        },
        "ansi": {
            "allow_ansi": False,
            "max_output_chars": 100000,
            "strip_control_chars": True,
            "detect_bidi": True,
        },
        "canary": {
            "tokens": [],
            "egress_tools": [
                "http_fetch",
                "http_post",
                "http_request",
                "fetch",
                "web_search",
                "send_email",
                "slack_post",
                "github_create_issue",
                "upload_file",
            ],
            "entropy_threshold": 4.2,
            "min_blob_len": 40,
            "scan_results": True,
            "block_on_match": True,
        },
    },
    "rule": [],
}


def default_policy_doc() -> dict[str, Any]:
    """Return a deep copy of the built-in default policy document."""
    return copy.deepcopy(DEFAULT_POLICY_DOC)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _issue(severity: Severity, code: str, message: str, path: str = "") -> PolicyIssue:
    return PolicyIssue(severity=severity, code=code, message=message, path=path)


def parse_policy(
    doc: Mapping[str, Any],
    source_path: str | None = None,
) -> tuple[Policy, list[PolicyIssue]]:
    """Parse a policy document into a :class:`Policy` plus a list of issues.

    The function never raises for content problems; issues carry the severity so
    ``policy-lint`` can distinguish errors from warnings.
    """
    issues: list[PolicyIssue] = []

    if not isinstance(doc, Mapping):
        issues.append(_issue(Severity.CRITICAL, "POL-000", "policy must be a table"))
        return Policy(source_path=source_path), issues

    for key in doc:
        if key not in _TOP_LEVEL_KEYS:
            issues.append(
                _issue(Severity.LOW, "POL-001", f"unknown top-level key '{key}'", str(key))
            )

    meta = doc.get("meta") or {}
    if not isinstance(meta, Mapping):
        issues.append(_issue(Severity.CRITICAL, "POL-003", "[meta] must be a table", "meta"))
        meta = {}
    name = str(meta.get("name", "") or "")
    if not name:
        issues.append(_issue(Severity.HIGH, "POL-003", "[meta] name is required", "meta.name"))
    version = str(meta.get("version", "") or "")
    if version and not re.match(r"^\d+\.\d+\.\d+", version):
        issues.append(
            _issue(Severity.LOW, "POL-012", "meta.version should be semantic", "meta.version")
        )
    locale = str(meta.get("locale", "en") or "en")

    settings = doc.get("settings") or {}
    if not isinstance(settings, Mapping):
        issues.append(
            _issue(Severity.CRITICAL, "POL-013", "[settings] must be a table", "settings")
        )
        settings = {}

    for key in settings:
        if key not in _GLOBAL_SETTING_KEYS:
            issues.append(
                _issue(
                    Severity.LOW,
                    "POL-002",
                    f"unknown settings key '{key}'",
                    f"settings.{key}",
                )
            )

    fail_on = Severity.HIGH
    warn_on = Severity.MEDIUM
    for key, target in (("fail_on", "fail_on"), ("warn_on", "warn_on")):
        if key in settings:
            try:
                value = parse_severity(settings[key])
            except ValueError as exc:
                issues.append(
                    _issue(Severity.CRITICAL, "POL-004", str(exc), f"settings.{key}")
                )
                continue
            if key == "fail_on":
                fail_on = value
            else:
                warn_on = value
    if warn_on > fail_on:
        issues.append(
            _issue(
                Severity.LOW,
                "POL-011",
                f"warn_on ({warn_on.value}) is stricter than fail_on ({fail_on.value})",
                "settings.warn_on",
            )
        )

    redact_evidence = bool(settings.get("redact_evidence", True))
    strict = bool(settings.get("strict", True))
    max_evidence_chars = settings.get("max_evidence_chars", 240)
    if not isinstance(max_evidence_chars, int) or isinstance(max_evidence_chars, bool):
        issues.append(
            _issue(
                Severity.HIGH,
                "POL-013",
                "settings.max_evidence_chars must be an integer",
                "settings.max_evidence_chars",
            )
        )
        max_evidence_chars = 240
    elif max_evidence_chars < 0:
        issues.append(
            _issue(
                Severity.HIGH,
                "POL-013",
                "settings.max_evidence_chars must not be negative",
                "settings.max_evidence_chars",
            )
        )
        max_evidence_chars = 240

    plugin_settings: dict[str, Any] = {}
    for plugin in ("etdi", "path", "ansi", "canary"):
        if plugin in settings:
            block = settings[plugin]
            if not isinstance(block, Mapping):
                issues.append(
                    _issue(
                        Severity.HIGH,
                        "POL-013",
                        f"settings.{plugin} must be a table",
                        f"settings.{plugin}",
                    )
                )
                continue
            plugin_settings[plugin] = copy.deepcopy(dict(block))

    rules: list[RuleSpec] = []
    seen_ids: dict[str, int] = {}
    raw_rules = doc.get("rule") or []
    if isinstance(raw_rules, Mapping):
        raw_rules = [raw_rules]
    for index, raw_rule in enumerate(raw_rules):
        location = f"rule[{index}]"
        if not isinstance(raw_rule, Mapping):
            issues.append(
                _issue(Severity.CRITICAL, "POL-010", "rule entry must be a table", location)
            )
            continue
        for key in raw_rule:
            if key not in _RULE_KEYS:
                issues.append(
                    _issue(Severity.LOW, "POL-001", f"unknown rule key '{key}'", f"{location}.{key}")
                )
        rule_id = str(raw_rule.get("id", "") or "")
        if not rule_id:
            issues.append(
                _issue(Severity.CRITICAL, "POL-009", "rule id is required", f"{location}.id")
            )
            continue
        if not RULE_ID_RE.match(rule_id):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-014",
                    f"rule id '{rule_id}' must match [A-Z][A-Z0-9_]*-NNN",
                    f"{location}.id",
                )
            )
        if rule_id in seen_ids:
            issues.append(
                _issue(
                    Severity.CRITICAL,
                    "POL-005",
                    f"duplicate rule id '{rule_id}' (first seen at rule[{seen_ids[rule_id]}])",
                    f"{location}.id",
                )
            )
        else:
            seen_ids[rule_id] = index

        plugin_name = str(raw_rule.get("plugin", "") or "")
        if not plugin_name:
            issues.append(
                _issue(
                    Severity.CRITICAL,
                    "POL-010",
                    "rule plugin is required",
                    f"{location}.plugin",
                )
            )
            plugin_name = "custom"

        severity = Severity.MEDIUM
        if "severity" in raw_rule:
            try:
                severity = parse_severity(raw_rule["severity"])
            except ValueError as exc:
                issues.append(
                    _issue(Severity.CRITICAL, "POL-004", str(exc), f"{location}.severity")
                )

        enabled = raw_rule.get("enabled", True)
        if not isinstance(enabled, bool):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "rule enabled must be a boolean",
                    f"{location}.enabled",
                )
            )
            enabled = True

        regex = raw_rule.get("regex")
        if regex is not None:
            if not isinstance(regex, str):
                issues.append(
                    _issue(Severity.HIGH, "POL-013", "rule regex must be a string", f"{location}.regex")
                )
                regex = None
            else:
                try:
                    re.compile(regex)
                except re.error as exc:
                    issues.append(
                        _issue(
                            Severity.CRITICAL,
                            "POL-008",
                            f"invalid regex: {exc}",
                            f"{location}.regex",
                        )
                    )
                    regex = None

        target = str(raw_rule.get("target", "any") or "any")
        if target not in _RULE_TARGETS:
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-015",
                    f"unknown rule target '{target}'",
                    f"{location}.target",
                )
            )
            target = "any"

        rules.append(
            RuleSpec(
                id=rule_id,
                plugin=plugin_name,
                enabled=enabled,
                severity=severity,
                message=str(raw_rule.get("message", "") or ""),
                regex=regex,
                target=target,
                description=str(raw_rule.get("description", "") or ""),
            )
        )

    policy = Policy(
        name=name or "unnamed-policy",
        version=version or "0.0.0",
        locale=locale,
        fail_on=fail_on,
        warn_on=warn_on,
        redact_evidence=redact_evidence,
        max_evidence_chars=max_evidence_chars,
        strict=strict,
        settings=plugin_settings,
        rules=tuple(rules),
        source_path=source_path,
        raw=copy.deepcopy(dict(doc)),
    )
    return policy, issues


def load_policy_text(text: str, source_path: str | None = None) -> Policy:
    """Parse a policy from TOML text.

    The document is parsed *and* linted.  A policy that carries a blocking
    issue (severity ``HIGH`` or above) is refused: loading it would let a
    typo -- a mis-scoped rule id, a setting of the wrong type -- silently
    disable a guard (AUD-13).

    Raises:
        PolicyError: when the document is not valid TOML or contains errors.
    """
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in {source_path or '<string>'}: {exc}") from exc

    policy, issues = parse_policy(doc, source_path)

    # Imported lazily: ``core.lint`` imports this module, so a module level
    # import would be circular.
    from .lint import lint_policy

    issues = list(issues) + list(lint_policy(policy))
    errors = [issue for issue in issues if issue.severity >= Severity.HIGH]
    if errors:
        raise PolicyError(
            f"policy has {len(errors)} error(s)", issues=issues
        )
    return policy


def load_policy(path: str | Path) -> Policy:
    """Load and parse a policy file.

    Raises:
        PolicyError: on unreadable files, invalid TOML or policy errors.
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {file_path}: {exc}") from exc
    return load_policy_text(text, source_path=str(file_path))


def default_policy() -> Policy:
    """Return the built-in default policy."""
    policy, issues = parse_policy(default_policy_doc(), source_path=None)
    errors = [issue for issue in issues if issue.severity >= Severity.HIGH]
    if errors:  # pragma: no cover - defensive, the default policy is valid
        raise PolicyError("built-in default policy is invalid", issues=issues)
    return policy

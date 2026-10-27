"""Policy linter.

``parse_policy`` reports structural problems it can detect while parsing; this
module adds semantic checks that need to know the plugin surface (rule ids,
plugin names, setting types).
"""

from __future__ import annotations

from typing import Any, Mapping

from .policy import Policy, PolicyIssue, parse_policy
from .registry import plugin_rule_catalogue
from .severity import Severity

__all__ = ["lint_policy", "lint_policy_document", "lint_text"]


def _issue(severity: Severity, code: str, message: str, path: str = "") -> PolicyIssue:
    return PolicyIssue(severity=severity, code=code, message=message, path=path)


def lint_policy(policy: Policy) -> list[PolicyIssue]:
    """Run semantic checks over an already parsed policy."""
    issues: list[PolicyIssue] = []
    catalogue = plugin_rule_catalogue()
    known_plugins = set(catalogue) | {"custom"}

    # rule id -> the plugins that own it.  A rule id is only unique inside a
    # plugin, so this map is what lets us tell "this id does not exist" from
    # "this id exists, but it belongs to a different plugin" (AUD-12).
    owners: dict[str, set[str]] = {}
    for plugin_name, rules in catalogue.items():
        for rule_id in rules:
            owners.setdefault(rule_id, set()).add(plugin_name)

    for spec in policy.rules:
        location = f"rule[{spec.id}]"
        if spec.plugin not in known_plugins:
            issues.append(
                _issue(
                    Severity.CRITICAL,
                    "POL-007",
                    f"unknown plugin '{spec.plugin}' (known: {', '.join(sorted(known_plugins))})",
                    f"{location}.plugin",
                )
            )
            continue

        known_rules = catalogue.get(spec.plugin, {})
        rule_owners = owners.get(spec.id, set())

        if rule_owners and spec.plugin not in rule_owners:
            # The id belongs to a different plugin.  Scoping it here would try
            # to reconfigure a rule this plugin does not own; the runtime now
            # ignores such a rule, and the linter reports it as an error.
            owners_text = ", ".join(sorted(rule_owners))
            issues.append(
                _issue(
                    Severity.CRITICAL,
                    "POL-006",
                    f"rule id '{spec.id}' belongs to plugin '{owners_text}' and cannot be "
                    f"scoped to '{spec.plugin}'",
                    f"{location}.id",
                )
            )
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-018",
                    f"rule id '{spec.id}' is mis-scoped: it is owned by '{owners_text}', "
                    f"not by '{spec.plugin}'",
                    f"{location}.id",
                )
            )
            continue

        if spec.regex is None and spec.id not in known_rules:
            issues.append(
                _issue(
                    Severity.CRITICAL,
                    "POL-006",
                    f"rule id '{spec.id}' is not a known rule of plugin '{spec.plugin}' "
                    "and declares no regex",
                    f"{location}.id",
                )
            )
        if spec.regex is not None and spec.id in known_rules:
            issues.append(
                _issue(
                    Severity.LOW,
                    "POL-016",
                    f"rule id '{spec.id}' overrides a built-in rule of plugin "
                    f"'{spec.plugin}' and adds a regex; the built-in rule still runs",
                    f"{location}.regex",
                )
            )

    issues.extend(_lint_settings(policy))
    return issues


def _lint_settings(policy: Policy) -> list[PolicyIssue]:
    issues: list[PolicyIssue] = []

    etdi = policy.plugin_settings("etdi")
    for key in ("require_pins", "fail_on_drift", "allow_unpinned"):
        if key in etdi and not isinstance(etdi[key], bool):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    f"settings.etdi.{key} must be a boolean",
                    f"settings.etdi.{key}",
                )
            )

    ansi = policy.plugin_settings("ansi")
    if "allow_ansi" in ansi and not isinstance(ansi["allow_ansi"], bool):
        issues.append(
            _issue(
                Severity.HIGH,
                "POL-013",
                "settings.ansi.allow_ansi must be a boolean",
                "settings.ansi.allow_ansi",
            )
        )
    if "max_output_chars" in ansi:
        value = ansi["max_output_chars"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.ansi.max_output_chars must be a non-negative integer",
                    "settings.ansi.max_output_chars",
                )
            )

    canary = policy.plugin_settings("canary")
    if "tokens" in canary:
        tokens = canary["tokens"]
        if not isinstance(tokens, list) or not all(isinstance(item, str) for item in tokens):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.canary.tokens must be a list of strings",
                    "settings.canary.tokens",
                )
            )
        elif not tokens:
            issues.append(
                _issue(
                    Severity.LOW,
                    "POL-017",
                    "settings.canary.tokens is empty; only generic canary shapes are detected",
                    "settings.canary.tokens",
                )
            )
    if "entropy_threshold" in canary:
        value = canary["entropy_threshold"]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.canary.entropy_threshold must be a number",
                    "settings.canary.entropy_threshold",
                )
            )
        elif not 0 < float(value) <= 8:
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.canary.entropy_threshold must be within (0, 8]",
                    "settings.canary.entropy_threshold",
                )
            )
    if "min_blob_len" in canary:
        value = canary["min_blob_len"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 8:
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.canary.min_blob_len must be an integer >= 8",
                    "settings.canary.min_blob_len",
                )
            )
    if "egress_tools" in canary:
        tools = canary["egress_tools"]
        if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
            issues.append(
                _issue(
                    Severity.HIGH,
                    "POL-013",
                    "settings.canary.egress_tools must be a list of strings",
                    "settings.canary.egress_tools",
                )
            )

    path = policy.plugin_settings("path")
    for key in ("sensitive_names", "sensitive_files", "system_prefixes", "allowed_roots"):
        if key in path:
            values = path[key]
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                issues.append(
                    _issue(
                        Severity.HIGH,
                        "POL-013",
                        f"settings.path.{key} must be a list of strings",
                        f"settings.path.{key}",
                    )
                )

    return issues


def lint_policy_document(
    document: Mapping[str, Any],
    source_path: str | None = None,
) -> tuple[Policy, list[PolicyIssue]]:
    """Parse *and* lint a policy document."""
    policy, issues = parse_policy(document, source_path)
    issues.extend(lint_policy(policy))
    return policy, issues


def lint_text(text: str, source_path: str | None = None) -> list[PolicyIssue]:
    """Lint a policy given as TOML text."""
    import tomllib

    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [
            _issue(Severity.CRITICAL, "POL-000", f"invalid TOML: {exc}", source_path or "")
        ]
    _, issues = lint_policy_document(document, source_path)
    return issues

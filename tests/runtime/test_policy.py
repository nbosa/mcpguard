"""Tests for the policy model, the loader and the decision engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_guard.policy import (
    APPROVAL_REQUIRED,
    DENY,
    Policy,
    PolicyEngine,
    PolicyError,
    load_policy,
)

MINIMAL = """
version: 1
default_action: deny
tools:
  read_file:
    action: allow
"""


def test_load_policy_reads_a_valid_document(write_policy) -> None:
    path = write_policy(MINIMAL)
    policy = load_policy(path)
    assert policy.version == 1
    assert policy.default_action == "deny"
    assert set(policy.tools) == {"read_file"}
    assert policy.source == str(path)


def test_load_policy_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as error:
        load_policy(tmp_path / "nope.yaml")
    assert "not found" in str(error.value)
    assert "nope.yaml" in str(error.value)


def test_load_policy_reports_invalid_yaml(write_policy) -> None:
    path = write_policy("tools:\n  - this is not a mapping\n  bad: [")
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    assert "not valid YAML" in str(error.value)
    assert str(path) in str(error.value)


def test_load_policy_reports_a_non_mapping_document(write_policy) -> None:
    path = write_policy("- just\n- a list\n")
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    assert "must contain a mapping" in str(error.value)


def test_load_policy_reports_an_unknown_field(write_policy) -> None:
    path = write_policy("tools:\n  read_file:\n    action: allow\n    totally_unknown: 1\n")
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    message = str(error.value)
    assert "is invalid" in message
    assert "tools.read_file.totally_unknown" in message


def test_load_policy_reports_an_invalid_regex_with_context(write_policy) -> None:
    path = write_policy(
        "tools:\n"
        "  read_file:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      path:\n"
        "        regex: '[unclosed'\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    message = str(error.value)
    assert "tools.read_file.arguments.path.regex" in message
    assert "invalid regular expression" in message


def test_load_policy_reports_an_inverted_range(write_policy) -> None:
    path = write_policy(
        "tools:\n"
        "  read_file:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      size:\n"
        "        min: 10\n"
        "        max: 1\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    assert "min must be less than or equal to max" in str(error.value)


def test_load_policy_rejects_approval_on_a_denied_tool(write_policy) -> None:
    path = write_policy(
        "tools:\n  read_file:\n    action: deny\n    require_approval: true\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(path)
    assert "require_approval cannot be combined" in str(error.value)


def test_an_empty_policy_denies_every_tool() -> None:
    engine = PolicyEngine(Policy(), session_id="s")
    for name in ("read_file", "run_shell", "anything_at_all"):
        decision = engine.evaluate(name, {})
        assert decision.decision == DENY
        assert decision.is_error
        assert "default deny" in decision.reason


def test_a_missing_tool_rule_denies_the_call() -> None:
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("run_shell", {"cmd": "ls"})
    assert decision.decision == DENY
    assert "not listed in the policy" in decision.reason


def test_an_explicitly_denied_tool_is_denied() -> None:
    policy = Policy.model_validate(
        {"tools": {"run_shell": {"action": "deny", "reason": "no shell for you"}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("run_shell", {})
    assert decision.decision == DENY
    assert decision.reason == "no shell for you"


def test_require_approval_produces_the_approval_decision() -> None:
    policy = Policy.model_validate(
        {"tools": {"send_email": {"action": "allow", "require_approval": True}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("send_email", {"to": "a@example.com"})
    assert decision.decision == APPROVAL_REQUIRED
    assert decision.code == APPROVAL_REQUIRED
    assert decision.is_error


def test_an_allowed_tool_is_allowed() -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "allow_undeclared_arguments": True}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("read_file", {"path": "a.txt"})
    assert decision.decision == "allow"
    assert decision.allowed


def test_regex_constraints_are_anchored() -> None:
    policy = Policy.model_validate(
        {
            "tools": {
                "send_email": {
                    "action": "allow",
                    "arguments": {"to": {"regex": r"^[^@\s]+@[^@\s]+$"}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("send_email", {"to": "a@example.com"}).allowed
    assert not engine.evaluate("send_email", {"to": "not-an-address"}).allowed
    # A partial match is not enough: the regex must match the whole value.
    assert not engine.evaluate("send_email", {"to": "a@example.com and more"}).allowed


def test_enum_constraints_are_enforced() -> None:
    policy = Policy.model_validate(
        {"tools": {"fmt": {"action": "allow", "arguments": {"format": {"enum": ["json", "yaml"]}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("fmt", {"format": "json"}).allowed
    decision = engine.evaluate("fmt", {"format": "toml"})
    assert decision.decision == DENY
    assert "must be one of" in decision.reason


def test_numeric_range_constraints_are_enforced() -> None:
    policy = Policy.model_validate(
        {"tools": {"fetch": {"action": "allow", "arguments": {"port": {"min": 1, "max": 65535}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("fetch", {"port": 8080}).allowed
    assert engine.evaluate("fetch", {"port": 0}).decision == DENY
    assert engine.evaluate("fetch", {"port": 70000}).decision == DENY


def test_max_length_constraints_are_enforced() -> None:
    policy = Policy.model_validate(
        {"tools": {"echo": {"action": "allow", "arguments": {"text": {"max_length": 4}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("echo", {"text": "abcd"}).allowed
    assert engine.evaluate("echo", {"text": "abcde"}).decision == DENY


def test_a_required_argument_must_be_present() -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "arguments": {"path": {"required": True}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("read_file", {})
    assert decision.decision == DENY
    assert "required but missing" in decision.reason


def test_an_undeclared_argument_is_refused_by_default() -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "arguments": {"path": {"max_length": 4}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("read_file", {"other": "anything at all"})
    assert decision.decision == DENY
    assert "undeclared argument" in decision.reason


def test_an_unconstrained_argument_can_be_allowed_with_opt_in() -> None:
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {
                    "action": "allow",
                    "allow_undeclared_arguments": True,
                    "arguments": {"path": {"max_length": 4}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("read_file", {"other": "anything at all"}).allowed


def test_the_method_policy_can_deny_a_method() -> None:
    policy = Policy.model_validate({"methods": {"deny": ["resources/read"]}})
    engine = PolicyEngine(policy, session_id="s")
    allowed, reason = engine.method_allowed("resources/read")
    assert not allowed
    assert "denied by policy" in reason
    # G-13: the surfaces that relay upstream content are denied by default,
    # so a policy that wants them has to name them in methods.allow.
    assert not engine.method_allowed("resources/list")[0]
    assert "denied by default" in engine.method_allowed("resources/list")[1]


def test_a_content_relaying_method_can_be_named_explicitly() -> None:
    policy = Policy.model_validate({"methods": {"allow": ["resources/list", "tools/list"]}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.method_allowed("resources/list")[0]
    assert not engine.method_allowed("resources/read")[0]


def test_the_method_policy_can_allow_list() -> None:
    policy = Policy.model_validate({"methods": {"allow": ["resources/list"]}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.method_allowed("resources/list")[0]
    assert not engine.method_allowed("resources/read")[0]

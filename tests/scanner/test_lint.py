"""Tests for the policy linter."""

from __future__ import annotations

from mcp_guard.core.lint import lint_policy, lint_policy_document, lint_text
from mcp_guard.core.policy import default_policy, parse_policy
from mcp_guard.core.severity import Severity


def _codes(issues):
    return {issue.code for issue in issues}


def test_default_policy_lints_clean():
    issues = lint_policy(default_policy())
    assert not [issue for issue in issues if issue.severity >= Severity.HIGH]


def test_unknown_plugin_is_an_error():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "rule": [{"id": "X-001", "plugin": "nope"}]}
    )
    issues = lint_policy(policy)
    assert "POL-007" in _codes(issues)


def test_unknown_rule_id_without_regex_is_an_error():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "rule": [{"id": "X-001", "plugin": "path_shape"}]}
    )
    issues = lint_policy(policy)
    assert "POL-006" in _codes(issues)


def test_known_rule_id_is_accepted():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "rule": [{"id": "PATH-001", "plugin": "path_shape"}]}
    )
    issues = lint_policy(policy)
    assert "POL-006" not in _codes(issues)


def test_custom_plugin_with_regex_is_accepted():
    policy, _ = parse_policy(
        {
            "meta": {"name": "x"},
            "rule": [{"id": "X-001", "plugin": "custom", "regex": "secret"}],
        }
    )
    issues = lint_policy(policy)
    assert "POL-006" not in _codes(issues)


def test_canary_tokens_must_be_strings():
    policy, _ = parse_policy(
        {
            "meta": {"name": "x"},
            "settings": {"canary": {"tokens": [1, 2]}},
        }
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_empty_canary_tokens_is_a_warning():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"canary": {"tokens": []}}}
    )
    issues = lint_policy(policy)
    assert "POL-017" in _codes(issues)


def test_entropy_threshold_must_be_numeric():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"canary": {"entropy_threshold": "high"}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_entropy_threshold_out_of_range_is_reported():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"canary": {"entropy_threshold": 99}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_min_blob_len_must_be_reasonable():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"canary": {"min_blob_len": 2}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_ansi_max_output_chars_must_be_integer():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"ansi": {"max_output_chars": "big"}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_etdi_flags_must_be_booleans():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"etdi": {"require_pins": "yes"}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_path_lists_must_be_string_lists():
    policy, _ = parse_policy(
        {"meta": {"name": "x"}, "settings": {"path": {"sensitive_names": [1]}}}
    )
    issues = lint_policy(policy)
    assert "POL-013" in _codes(issues)


def test_lint_text_reports_invalid_toml():
    issues = lint_text("not = = toml")
    assert "POL-000" in _codes(issues)


def test_lint_text_on_valid_policy():
    issues = lint_text(
        '[meta]\nname = "x"\nversion = "1.0.0"\n[settings]\nfail_on = "HIGH"\n'
    )
    assert not [issue for issue in issues if issue.severity >= Severity.HIGH]


def test_lint_policy_document_combines_both_passes():
    doc = {"meta": {"name": "x"}, "settings": {"bogus": 1}}
    _, issues = lint_policy_document(doc)
    assert "POL-002" in _codes(issues)


def test_issue_to_dict_shape():
    _, issues = parse_policy({"meta": {"name": "x"}, "settings": {"bogus": 1}})
    issue = [i for i in issues if i.code == "POL-002"][0]
    assert set(issue.to_dict()) == {"severity", "code", "message", "path"}


def test_issue_to_text_includes_code():
    _, issues = parse_policy({"meta": {"name": "x"}, "settings": {"bogus": 1}})
    issue = [i for i in issues if i.code == "POL-002"][0]
    assert "POL-002" in issue.to_text()

"""Tests for policy parsing, loading and the default policy."""

from __future__ import annotations

import pytest

from mcp_guard.core.policy import (
    DEFAULT_POLICY_DOC,
    PolicyError,
    default_policy,
    default_policy_doc,
    load_policy,
    load_policy_text,
    parse_policy,
)
from mcp_guard.core.severity import Severity

VALID = """
[meta]
name = "unit"
version = "1.2.3"

[settings]
fail_on = "HIGH"
warn_on = "LOW"

[settings.canary]
tokens = ["CANARY-AAAA-1111"]

[[rule]]
id = "PATH-001"
plugin = "path_shape"
severity = "CRITICAL"
"""


def _codes(issues):
    return {issue.code for issue in issues}


def test_default_policy_has_a_name():
    assert default_policy().name == "mcp-guard-default"


def test_default_policy_version_matches_release():
    assert default_policy().version == "1.0.0"


def test_default_policy_fail_on_is_high():
    assert default_policy().fail_on is Severity.HIGH


def test_default_policy_redacts_evidence():
    assert default_policy().redact_evidence is True


def test_default_policy_doc_is_a_copy():
    doc = default_policy_doc()
    doc["meta"]["name"] = "mutated"
    assert DEFAULT_POLICY_DOC["meta"]["name"] == "mcp-guard-default"


def test_valid_policy_parses_without_errors():
    policy, issues = parse_policy(
        __import__("tomllib").loads(VALID)
    )
    assert not [issue for issue in issues if issue.severity >= Severity.HIGH]
    assert policy.name == "unit"


def test_valid_policy_reads_settings():
    policy, _ = parse_policy(__import__("tomllib").loads(VALID))
    assert policy.fail_on is Severity.HIGH
    assert policy.warn_on is Severity.LOW


def test_valid_policy_reads_plugin_settings():
    policy, _ = parse_policy(__import__("tomllib").loads(VALID))
    assert policy.plugin_settings("canary")["tokens"] == ["CANARY-AAAA-1111"]


def test_plugin_settings_of_unknown_plugin_is_empty_dict():
    assert default_policy().plugin_settings("nope") == {}


def test_rule_override_is_found():
    policy, _ = parse_policy(__import__("tomllib").loads(VALID))
    assert policy.rule("PATH-001").severity is Severity.CRITICAL


def test_rule_override_of_unknown_id_is_none():
    assert default_policy().rule("NOPE-999") is None


def test_missing_meta_name_is_an_error():
    policy, issues = parse_policy({"meta": {}})
    assert "POL-003" in _codes(issues)


def test_unknown_top_level_key_is_a_warning():
    policy, issues = parse_policy({"meta": {"name": "x"}, "bogus": 1})
    assert "POL-001" in _codes(issues)


def test_unknown_settings_key_is_a_warning():
    policy, issues = parse_policy({"meta": {"name": "x"}, "settings": {"bogus": 1}})
    assert "POL-002" in _codes(issues)


def test_invalid_fail_on_severity_is_an_error():
    policy, issues = parse_policy(
        {"meta": {"name": "x"}, "settings": {"fail_on": "EXTREME"}}
    )
    assert "POL-004" in _codes(issues)


def test_duplicate_rule_ids_are_an_error():
    doc = {
        "meta": {"name": "x"},
        "rule": [
            {"id": "PATH-001", "plugin": "path_shape"},
            {"id": "PATH-001", "plugin": "path_shape"},
        ],
    }
    _, issues = parse_policy(doc)
    assert "POL-005" in _codes(issues)


def test_rule_without_id_is_an_error():
    _, issues = parse_policy({"meta": {"name": "x"}, "rule": [{"plugin": "path_shape"}]})
    assert "POL-009" in _codes(issues)


def test_rule_without_plugin_is_an_error():
    _, issues = parse_policy({"meta": {"name": "x"}, "rule": [{"id": "PATH-001"}]})
    assert "POL-010" in _codes(issues)


def test_invalid_rule_regex_is_an_error():
    doc = {
        "meta": {"name": "x"},
        "rule": [{"id": "X-001", "plugin": "custom", "regex": "([unclosed"}],
    }
    _, issues = parse_policy(doc)
    assert "POL-008" in _codes(issues)


def test_invalid_rule_id_format_is_reported():
    doc = {"meta": {"name": "x"}, "rule": [{"id": "lower-1", "plugin": "custom"}]}
    _, issues = parse_policy(doc)
    assert "POL-014" in _codes(issues)


def test_unknown_rule_target_is_reported():
    doc = {
        "meta": {"name": "x"},
        "rule": [{"id": "X-001", "plugin": "custom", "target": "nowhere"}],
    }
    _, issues = parse_policy(doc)
    assert "POL-015" in _codes(issues)


def test_warn_on_stricter_than_fail_on_is_a_warning():
    doc = {
        "meta": {"name": "x"},
        "settings": {"fail_on": "LOW", "warn_on": "CRITICAL"},
    }
    _, issues = parse_policy(doc)
    assert "POL-011" in _codes(issues)


def test_negative_max_evidence_chars_is_reported():
    doc = {"meta": {"name": "x"}, "settings": {"max_evidence_chars": -5}}
    _, issues = parse_policy(doc)
    assert "POL-013" in _codes(issues)


def test_non_integer_max_evidence_chars_is_reported():
    doc = {"meta": {"name": "x"}, "settings": {"max_evidence_chars": "lots"}}
    _, issues = parse_policy(doc)
    assert "POL-013" in _codes(issues)


def test_non_semantic_meta_version_is_a_warning():
    _, issues = parse_policy({"meta": {"name": "x", "version": "beta"}})
    assert "POL-012" in _codes(issues)


def test_non_mapping_policy_is_rejected():
    _, issues = parse_policy(["not", "a", "table"])
    assert "POL-000" in _codes(issues)


def test_load_policy_text_returns_policy():
    assert load_policy_text(VALID).name == "unit"


def test_load_policy_text_rejects_invalid_toml():
    with pytest.raises(PolicyError):
        load_policy_text("this is not = = toml")


def test_load_policy_reads_a_file(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(VALID, encoding="utf-8")
    assert load_policy(path).name == "unit"


def test_load_policy_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "absent.toml")


def test_load_policy_with_errors_raises(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text('[meta]\nname = "x"\n[settings]\nfail_on = "NOPE"\n', encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_policy_error_carries_issues():
    with pytest.raises(PolicyError) as excinfo:
        load_policy_text('[meta]\nname = "x"\n[settings]\nfail_on = "NOPE"\n')
    assert excinfo.value.issues


def test_policy_to_dict_is_serialisable():
    payload = default_policy().to_dict()
    assert payload["meta"]["name"] == "mcp-guard-default"
    assert "fail_on" in payload["settings"]

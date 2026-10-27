"""Tests for ``mcp-guard policy-lint``.

The linter is the new command of the 0.5.0 release, and it is the one that
has to be right about *what a policy means* rather than about what a policy
does.  These tests therefore pin down two things for every rule: that it
fires on a policy that has the problem, and that it stays quiet on a policy
that does not.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mcp_guard.cli import main
from mcp_guard.lint import (
    ERROR,
    NOTE,
    RULES,
    WARNING,
    lint_policy,
    lint_text,
    render_human,
    to_sarif,
)

CLEAN_POLICY = """\
version: 1
default_action: deny
tools:
  read_file:
    action: allow
    arguments:
      path:
        type: string
        required: true
        path_prefix: "./workspace"
"""


def rule_ids(report) -> list[str]:
    """The rule ids of the findings of a report."""
    return [finding.rule_id for finding in report.findings]


def findings_for(report, rule_id: str):
    """The findings of one rule."""
    return [finding for finding in report.findings if finding.rule_id == rule_id]


def write(tmp_path: Path, text: str, name: str = "policy.yaml") -> Path:
    """Write a policy document and return its path."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def base(tmp_path: Path) -> Path:
    """A base directory that holds the ``./workspace`` the clean policy names."""
    (tmp_path / "workspace").mkdir()
    return tmp_path


# -- the clean case --------------------------------------------------------

def test_a_clean_policy_has_no_findings(base: Path) -> None:
    report = lint_text(CLEAN_POLICY, base_dir=base)
    assert report.findings == []


def test_a_clean_policy_exits_zero(
    base: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, CLEAN_POLICY)
    assert main(["policy-lint", str(path), "--base-dir", str(base)]) == 0
    assert "no findings" in capsys.readouterr().out


def test_the_empty_policy_is_a_note_not_an_error() -> None:
    report = lint_text("version: 1\ndefault_action: deny\n")
    assert rule_ids(report) == ["PL-NO-TOOLS"]
    assert report.findings[0].severity == NOTE


def test_a_policy_without_tools_is_reported_once() -> None:
    report = lint_text("version: 1\ndefault_action: deny\ntools:\n")
    assert len(findings_for(report, "PL-NO-TOOLS")) == 1


# -- the schema ------------------------------------------------------------

def test_broken_yaml_is_a_schema_error() -> None:
    report = lint_text("version: 1\ntools:\n  - this is not a mapping\n")
    assert "PL-SCHEMA" in rule_ids(report)


def test_a_yaml_syntax_error_is_a_schema_error() -> None:
    report = lint_text("version: 1\n\ttools: {}\n")
    assert "PL-SCHEMA" in rule_ids(report)


def test_a_document_that_is_not_a_mapping_is_a_schema_error() -> None:
    report = lint_text("- one\n- two\n")
    assert "PL-SCHEMA" in rule_ids(report)
    assert "mapping" in findings_for(report, "PL-SCHEMA")[0].message


def test_an_unknown_key_is_a_schema_error() -> None:
    report = lint_text("version: 1\ndefault_action: deny\nnot_a_key: 1\n")
    assert "PL-SCHEMA" in rule_ids(report)


def test_an_unknown_action_is_a_schema_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: maybe\n"
    )
    assert "PL-SCHEMA" in rule_ids(report)


def test_a_schema_error_names_the_offending_key() -> None:
    report = lint_text("version: 1\ndefault_action: allow\n")
    message = findings_for(report, "PL-SCHEMA")[0].message
    assert "default_action" in message


# -- R-01 ------------------------------------------------------------------

REDOS_POLICY = """\
version: 1
default_action: deny
tools:
  read_file:
    action: allow
    arguments:
      path:
        type: string
        regex: '(a+)+'
"""


def test_a_nested_quantifier_is_an_r01_error() -> None:
    report = lint_text(REDOS_POLICY)
    findings = findings_for(report, "PL-R01")
    assert len(findings) == 1
    assert findings[0].severity == ERROR
    assert "nested quantifier" in findings[0].message


def test_an_empty_group_is_an_r01_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '(a?)+'\n"
    )
    assert "PL-R01" in rule_ids(report)


def test_an_ambiguous_alternation_is_an_r01_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '(a|aa)+'\n"
    )
    assert "PL-R01" in rule_ids(report)


def test_a_safe_regex_is_not_an_r01_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '[a-z]+/[0-9]+'\n"
    )
    assert "PL-R01" not in rule_ids(report)


def test_a_bounded_repetition_is_not_an_r01_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '(ab){2}'\n"
    )
    assert "PL-R01" not in rule_ids(report)


def test_the_escape_hatch_is_reported_as_a_warning() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '(a+)+'\n"
        "        allow_unsafe_regex: true\n"
    )
    assert "PL-R01-ESCAPE" in rule_ids(report)
    assert "PL-R01" not in rule_ids(report)
    assert findings_for(report, "PL-R01-ESCAPE")[0].severity == WARNING


def test_the_r01_error_is_not_reported_twice() -> None:
    """The loader refuses an R-01 pattern, so the schema check fails too.

    The linter must not report the same problem once as a schema error and
    once as an R-01 error.
    """
    report = lint_text(REDOS_POLICY)
    assert len(findings_for(report, "PL-SCHEMA")) == 0
    assert len(findings_for(report, "PL-R01")) == 1


# -- the anchoring of a regex ----------------------------------------------

def test_an_unanchored_regex_is_a_warning() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: 'file[0-9]+'\n"
    )
    findings = findings_for(report, "PL-REGEX-UNANCHORED")
    assert len(findings) == 1
    assert findings[0].severity == WARNING


def test_a_regex_anchored_at_both_ends_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '^file[0-9]+$'\n"
    )
    assert "PL-REGEX-UNANCHORED" not in rule_ids(report)


def test_a_regex_anchored_with_a_backslash_a_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: '\\Afile[0-9]+\\Z'\n"
    )
    assert "PL-REGEX-UNANCHORED" not in rule_ids(report)


def test_an_escaped_dollar_is_not_an_anchor() -> None:
    """``\\$`` is a literal dollar, not the end of the pattern."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: 'cost\\$'\n"
    )
    assert "PL-REGEX-UNANCHORED" in rule_ids(report)


# -- the broad path prefix -------------------------------------------------

@pytest.mark.parametrize("prefix", ["/", ".", "./", "/.", "//"])
def test_a_broad_path_prefix_is_an_error(prefix: str) -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        f"    arguments:\n      p:\n        type: string\n        path_prefix: '{prefix}'\n"
    )
    findings = findings_for(report, "PL-PATH-PREFIX-BROAD")
    assert len(findings) == 1
    assert findings[0].severity == ERROR


def test_a_narrow_path_prefix_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './workspace'\n"
    )
    assert "PL-PATH-PREFIX-BROAD" not in rule_ids(report)


def test_an_absolute_narrow_prefix_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: '/srv/data'\n"
    )
    assert "PL-PATH-PREFIX-BROAD" not in rule_ids(report)


# -- the list element constraints -----------------------------------------

def test_an_unconstrained_list_is_an_error() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
    )
    findings = findings_for(report, "PL-LIST-ELEMENT-UNCONSTRAINED")
    assert len(findings) == 1
    assert findings[0].severity == ERROR
    assert "files" in findings[0].message


def test_a_list_with_a_path_prefix_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n        path_prefix: './workspace'\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" not in rule_ids(report)


def test_a_list_with_an_items_constraint_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" not in rule_ids(report)


def test_a_list_of_paths_without_a_path_constraint_is_a_warning() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    findings = findings_for(report, "PL-LIST-PATH-UNCONSTRAINED")
    assert len(findings) == 1
    assert findings[0].severity == WARNING


def test_a_list_of_paths_with_a_path_prefix_is_quiet() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
        "        items:\n          type: string\n          path_prefix: './workspace'\n"
    )
    assert "PL-LIST-PATH-UNCONSTRAINED" not in rule_ids(report)


def test_a_list_that_is_not_a_list_of_paths_is_not_warned_about() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      tags:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    assert "PL-LIST-PATH-UNCONSTRAINED" not in rule_ids(report)


def test_the_path_name_test_survives_camel_case() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      readFiles:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    assert "PL-LIST-PATH-UNCONSTRAINED" in rule_ids(report)


def test_the_path_name_test_survives_underscores() -> None:
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      read_files:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    assert "PL-LIST-PATH-UNCONSTRAINED" in rule_ids(report)


# -- the symlink escape ----------------------------------------------------

def test_a_symlink_out_of_the_prefix_is_a_warning(tmp_path: Path) -> None:
    base = tmp_path / "base"
    (base / "workspace").mkdir(parents=True)
    (base / "outside").mkdir()
    (base / "workspace" / "escape").symlink_to(base / "outside")
    policy = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './workspace'\n",
    )

    report = lint_policy(policy, base_dir=base)
    findings = findings_for(report, "PL-SYMLINK-ESCAPE")
    assert len(findings) == 1
    assert findings[0].severity == WARNING
    assert "escape" in findings[0].message


def test_a_prefix_that_does_not_exist_is_a_note(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    policy = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './nowhere'\n",
    )

    report = lint_policy(policy, base_dir=base)
    findings = findings_for(report, "PL-PATH-PREFIX-MISSING")
    assert len(findings) == 1
    assert findings[0].severity == NOTE


def test_a_prefix_without_an_escape_is_quiet(tmp_path: Path) -> None:
    base = tmp_path / "base"
    (base / "workspace").mkdir(parents=True)
    (base / "workspace" / "inside").symlink_to(base / "workspace")
    policy = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './workspace'\n",
    )

    report = lint_policy(policy, base_dir=base)
    assert "PL-SYMLINK-ESCAPE" not in rule_ids(report)


# -- the output ------------------------------------------------------------

def test_the_sarif_document_has_the_shape_of_sarif() -> None:
    report = lint_text(REDOS_POLICY)
    document = to_sarif(report)

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-guard policy-lint"
    assert run["tool"]["driver"]["version"] == "1.0.0"
    assert len(run["results"]) == len(report.findings)


def test_every_rule_is_described_in_the_sarif_document() -> None:
    document = to_sarif(lint_text(CLEAN_POLICY))
    described = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    assert described == set(RULES)


def test_a_sarif_result_carries_a_rule_a_level_a_message_and_a_place() -> None:
    document = to_sarif(lint_text(REDOS_POLICY))
    result = document["runs"][0]["results"][0]

    assert result["ruleId"] == "PL-R01"
    assert result["level"] == "error"
    assert result["message"]["text"]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] > 0


def test_the_line_number_points_at_the_offending_key() -> None:
    document = to_sarif(lint_text(REDOS_POLICY))
    result = document["runs"][0]["results"][0]
    line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert "regex" in REDOS_POLICY.splitlines()[line - 1]


def test_the_run_carries_the_counts_and_the_policy_path() -> None:
    document = to_sarif(lint_text(REDOS_POLICY, path="policy.yaml"))
    properties = document["runs"][0]["properties"]
    assert properties["policy"] == "policy.yaml"
    assert properties["counts"]["error"] >= 1


def test_the_human_output_names_every_finding() -> None:
    text = render_human(lint_text(REDOS_POLICY))
    assert "PL-R01" in text
    assert "error" in text


# -- the command line ------------------------------------------------------

def test_the_command_reports_the_errors_and_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, REDOS_POLICY)
    assert main(["policy-lint", str(path)]) == 1
    assert "PL-R01" in capsys.readouterr().out


def test_the_command_writes_sarif_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, REDOS_POLICY)
    assert main(["policy-lint", str(path), "--json"]) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["runs"][0]["results"][0]["ruleId"] == "PL-R01"


def test_a_warning_alone_does_not_fail_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: 'file[0-9]+'\n",
    )
    assert main(["policy-lint", str(path)]) == 0
    assert "PL-REGEX-UNANCHORED" in capsys.readouterr().out


def test_strict_lets_a_warning_fail_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        regex: 'file[0-9]+'\n",
    )
    assert main(["policy-lint", str(path), "--strict"]) == 1


def test_a_missing_policy_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["policy-lint", str(tmp_path / "nowhere.yaml")]) == 2
    assert "not found" in capsys.readouterr().err


def test_a_directory_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["policy-lint", str(tmp_path)]) == 2
    assert "directory" in capsys.readouterr().err


def test_a_second_positional_argument_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, CLEAN_POLICY)
    assert main(["policy-lint", str(path), "extra.yaml"]) == 2
    assert "no further arguments" in capsys.readouterr().err


def test_an_unknown_option_is_refused_with_a_suggestion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, CLEAN_POLICY)
    assert main(["policy-lint", str(path), "--jsonn"]) == 2
    captured = capsys.readouterr()
    assert "unrecognized argument" in captured.err
    assert "--json" in captured.err


def test_the_base_dir_is_used_for_the_symlink_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = tmp_path / "base"
    (base / "workspace").mkdir(parents=True)
    (base / "outside").mkdir()
    (base / "workspace" / "escape").symlink_to(base / "outside")
    path = write(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './workspace'\n",
    )

    assert main(["policy-lint", str(path), "--base-dir", str(base)]) == 0
    assert "PL-SYMLINK-ESCAPE" in capsys.readouterr().out


def test_the_example_policies_of_the_repository_lint_clean() -> None:
    """The examples are what an operator starts from, so they must be clean."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    for path in sorted(examples.glob("*.yaml")):
        report = lint_policy(path, base_dir=examples)
        assert report.errors == [], f"{path.name}: {report.errors}"


def test_g06_unconstrained_list_elements_reported() -> None:
    """G-06: A list whose elements only have type: string must be reported."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      args:\n        type: array\n        items:\n          type: string\n",
        path="p.yaml",
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" in {f.rule_id for f in report.findings}


def test_g07_nested_symlink_escape_reported(tmp_path: Path) -> None:
    """G-07: Nested symlinks below the top level of prefix are reported."""
    workspace = tmp_path / "workspace"
    (workspace / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, workspace / "sub" / "link")
    report = lint_text(
        f"version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        f"    arguments:\n      p:\n        type: string\n        path_prefix: {workspace}\n",
        path="p.yaml",
        base_dir=tmp_path,
    )
    assert "PL-SYMLINK-ESCAPE" in {f.rule_id for f in report.findings}


def test_g16_parent_prefix_is_reported_as_broad() -> None:
    """G-16: '..' must be recognised as broad prefix."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: '..'\n",
        path="p.yaml",
    )
    assert "PL-PATH-PREFIX-BROAD" in {f.rule_id for f in report.findings}


def test_g17_sarif_uri_reference_and_base_ids() -> None:
    """G-17: SARIF document must emit valid URI references and originalUriBaseIds."""
    document = to_sarif(lint_text(REDOS_POLICY, path="policy.yaml"))
    run = document["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith(("file://", "/")) or "://" in uri
    assert "originalUriBaseIds" in run

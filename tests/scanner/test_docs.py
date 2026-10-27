"""Tests for the bilingual documentation set and the shipped artifacts."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from mcp_guard.core.policy import default_policy, parse_policy
from mcp_guard.core.registry import PLUGIN_ORDER

DOC_TOPICS = ("architecture", "rules", "cli", "policy", "etdi", "security")
CLI_COMMANDS = (
    "check",
    "policy-lint",
    "selftest",
    "pin-manifest",
    "sanitize-output",
    "canary-check",
)
CJK_RE = re.compile(r"[\u4e00-\u9fff]")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _local_links(text: str) -> list[str]:
    links = []
    for target in LINK_RE.findall(text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        links.append(target)
    return links


@pytest.fixture(params=DOC_TOPICS)
def topic(request) -> str:
    return request.param


# --------------------------------------------------------------------------
# file presence
# --------------------------------------------------------------------------
def test_english_readme_exists(repo_root):
    assert (repo_root / "README.md").is_file()


def test_chinese_readme_exists(repo_root):
    assert (repo_root / "README.zh-CN.md").is_file()


def test_license_exists(repo_root):
    assert (repo_root / "LICENSE").is_file()


def test_changelog_exists(repo_root):
    assert (repo_root / "CHANGELOG.md").is_file()


def test_english_doc_exists(repo_root, topic):
    assert (repo_root / "docs" / "en" / f"{topic}.md").is_file()


def test_chinese_doc_exists(repo_root, topic):
    assert (repo_root / "docs" / "zh-CN" / f"{topic}.md").is_file()


def test_language_trees_have_the_same_files(repo_root):
    english = {path.name for path in (repo_root / "docs" / "en").glob("*.md")}
    chinese = {path.name for path in (repo_root / "docs" / "zh-CN").glob("*.md")}
    assert english == chinese
    assert english == {f"{topic}.md" for topic in DOC_TOPICS}


# --------------------------------------------------------------------------
# content
# --------------------------------------------------------------------------
def test_english_readme_is_not_empty(repo_root):
    assert len(_read(repo_root, "README.md")) > 1000


def test_chinese_readme_is_not_empty(repo_root):
    assert len(_read(repo_root, "README.zh-CN.md")) > 1000


def test_english_documents_have_headings(repo_root, topic):
    text = _read(repo_root, f"docs/en/{topic}.md")
    assert text.startswith("#")
    assert "## " in text


def test_chinese_documents_have_headings(repo_root, topic):
    text = _read(repo_root, f"docs/zh-CN/{topic}.md")
    assert text.startswith("#")
    assert "## " in text


def test_chinese_documents_contain_chinese_text(repo_root, topic):
    text = _read(repo_root, f"docs/zh-CN/{topic}.md")
    assert len(CJK_RE.findall(text)) > 100


def test_english_documents_are_actually_english(repo_root, topic):
    text = _read(repo_root, f"docs/en/{topic}.md")
    assert len(CJK_RE.findall(text)) == 0


def test_chinese_readme_contains_chinese_text(repo_root):
    assert len(CJK_RE.findall(_read(repo_root, "README.zh-CN.md"))) > 200


def test_english_readme_contains_no_chinese_text(repo_root):
    assert len(CJK_RE.findall(_read(repo_root, "README.md"))) == 0


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_english_readme_documents_every_command(repo_root, command):
    assert command in _read(repo_root, "README.md")


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_chinese_readme_documents_every_command(repo_root, command):
    assert command in _read(repo_root, "README.zh-CN.md")


@pytest.mark.parametrize("plugin", PLUGIN_ORDER)
def test_english_readme_documents_every_plugin(repo_root, plugin):
    assert plugin in _read(repo_root, "README.md")


@pytest.mark.parametrize("plugin", PLUGIN_ORDER)
def test_chinese_readme_documents_every_plugin(repo_root, plugin):
    assert plugin in _read(repo_root, "README.zh-CN.md")


def test_english_readme_links_resolve(repo_root):
    for target in _local_links(_read(repo_root, "README.md")):
        assert (repo_root / target).exists(), target


def test_chinese_readme_links_resolve(repo_root):
    for target in _local_links(_read(repo_root, "README.zh-CN.md")):
        assert (repo_root / target).exists(), target


def test_english_doc_links_resolve(repo_root, topic):
    base = repo_root / "docs" / "en"
    for target in _local_links(_read(repo_root, f"docs/en/{topic}.md")):
        assert (base / target).resolve().exists(), target


def test_chinese_doc_links_resolve(repo_root, topic):
    base = repo_root / "docs" / "zh-CN"
    for target in _local_links(_read(repo_root, f"docs/zh-CN/{topic}.md")):
        assert (base / target).resolve().exists(), target


def test_changelog_is_bilingual(repo_root):
    text = _read(repo_root, "CHANGELOG.md")
    assert len(CJK_RE.findall(text)) > 100
    assert "0.6.0" in text


def test_changelog_mentions_every_plugin(repo_root):
    text = _read(repo_root, "CHANGELOG.md")
    for plugin in PLUGIN_ORDER:
        assert plugin in text


def test_rules_doc_covers_every_rule(repo_root):
    from mcp_guard.core.registry import plugin_rule_catalogue

    text = _read(repo_root, "docs/en/rules.md")
    for rules in plugin_rule_catalogue().values():
        for rule_id in rules:
            assert rule_id in text, rule_id


def test_chinese_rules_doc_covers_every_rule(repo_root):
    from mcp_guard.core.registry import plugin_rule_catalogue

    text = _read(repo_root, "docs/zh-CN/rules.md")
    for rules in plugin_rule_catalogue().values():
        for rule_id in rules:
            assert rule_id in text, rule_id


def test_policy_doc_lists_every_lint_code(repo_root):
    from mcp_guard.core.lint import lint_text

    text = _read(repo_root, "docs/en/policy.md")
    for code in ("POL-000", "POL-005", "POL-007", "POL-013", "POL-017"):
        assert code in text


# --------------------------------------------------------------------------
# shipped artifacts
# --------------------------------------------------------------------------
def test_default_policy_file_matches_the_built_in_policy(repo_root):
    text = (repo_root / "src" / "mcp_guard" / "data" / "default_policy.toml").read_text(
        encoding="utf-8"
    )
    document = tomllib.loads(text)
    assert parse_policy(document)[0].to_dict() == default_policy().to_dict()


def test_example_policy_lints_clean(repo_root):
    from mcp_guard.core.lint import lint_text

    text = (repo_root / "examples" / "policy.toml").read_text(encoding="utf-8")
    issues = lint_text(text, "examples/policy.toml")
    blocking = [issue for issue in issues if issue.severity.value in ("HIGH", "CRITICAL")]
    assert blocking == [], [issue.to_text() for issue in blocking]


def test_example_policy_is_loadable(repo_root):
    from mcp_guard.core.policy import load_policy

    policy = load_policy(repo_root / "examples" / "policy.toml")
    assert policy.name == "strict-example"


def test_example_etdi_document_is_valid(repo_root):
    from mcp_guard.core.etdi import validate_etdi

    import json

    document = json.loads(
        (repo_root / "examples" / "etdi-tools.json").read_text(encoding="utf-8")
    )
    assert validate_etdi(document) == []


def test_example_transcript_is_valid_json(repo_root):
    import json

    document = json.loads(
        (repo_root / "examples" / "transcript.json").read_text(encoding="utf-8")
    )
    assert "calls" in document


def test_example_transcript_trips_the_guard(repo_root, engine):
    import json

    from mcp_guard.core.request import CheckRequest

    document = json.loads(
        (repo_root / "examples" / "transcript.json").read_text(encoding="utf-8")
    )
    report = engine.check(CheckRequest.from_dict(document))
    assert report.verdict.value == "FAIL"

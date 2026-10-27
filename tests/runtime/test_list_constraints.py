"""Tests for the per-element constraints of 0.5.

The weakness these cover: in 0.4 an argument that is a *list of paths* was
never descended into.  ``ArgumentConstraint.check()`` applied ``path_prefix``
and ``regex`` to strings only, so a list was checked for its type and its
length and its elements were never looked at -- ``git_add_many(files=
['../CANARY-ESCAPE-9f3a.txt'])`` was accepted by the policy.  That is the
list-form variant of the path-traversal advisory 0.2 fixed for scalars
(CVE-2026-27735, GHSA-vjqx-cfc4-9h6v).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_guard.policy import DENY, Policy, PolicyEngine, PolicyError, load_policy

PREFIX = "./workspace"
CANARY = "../CANARY-ESCAPE-9f3a.txt"


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """A workspace with one file inside it and one canary file outside it."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "ok.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "CANARY-ESCAPE-9f3a.txt").write_text("secret", encoding="utf-8")
    return tmp_path


def engine(sandbox: Path, **arguments: object) -> PolicyEngine:
    """An engine for a single tool whose arguments carry these constraints."""
    policy = Policy.model_validate(
        {"tools": {"git_add_many": {"action": "allow", "arguments": arguments}}}
    )
    return PolicyEngine(policy, session_id="s", base_dir=sandbox)


# ---------------------------------------------------------------- scalars


def test_a_scalar_path_inside_the_prefix_is_still_allowed(sandbox: Path) -> None:
    """The 0.4 behaviour of a scalar path argument is unchanged."""
    decision = engine(sandbox, path={"type": "string", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"path": "workspace/ok.txt"}
    )
    assert decision.allowed


def test_a_scalar_path_outside_the_prefix_is_still_refused(sandbox: Path) -> None:
    """The 0.4 behaviour of a scalar path argument is unchanged."""
    decision = engine(sandbox, path={"type": "string", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"path": CANARY}
    )
    assert decision.decision == DENY
    assert "path_prefix" in decision.reason


def test_a_scalar_argument_declared_as_string_still_refuses_a_list(sandbox: Path) -> None:
    """``type: string`` keeps its 0.4 meaning: one path, not a list of paths."""
    decision = engine(sandbox, path={"type": "string", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"path": ["workspace/ok.txt"]}
    )
    assert decision.decision == DENY
    assert "must be of type string" in decision.reason


# ------------------------------------------- the list: implicit per element


def test_a_list_with_a_traversal_element_is_refused(sandbox: Path) -> None:
    """The corpus payload: a traversal inside a list argument."""
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": [CANARY]}
    )
    assert decision.decision == DENY
    assert "files[0]" in decision.reason
    assert "path_prefix" in decision.reason


def test_a_list_of_safe_paths_is_allowed(sandbox: Path) -> None:
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": ["workspace/ok.txt", "workspace/other.txt"]}
    )
    assert decision.allowed


def test_every_element_of_a_list_is_checked(sandbox: Path) -> None:
    """The first element is safe, the second one escapes: the call is refused."""
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": ["workspace/ok.txt", CANARY]}
    )
    assert decision.decision == DENY
    assert "files[1]" in decision.reason


def test_a_list_with_a_non_string_element_is_refused(sandbox: Path) -> None:
    """A wrong type is a violation, never an element the check walks past."""
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": ["workspace/ok.txt", 42]}
    )
    assert decision.decision == DENY
    assert "files[1]" in decision.reason
    assert "must be a string path" in decision.reason


def test_an_empty_list_is_allowed(sandbox: Path) -> None:
    """There is no path in an empty list that can leave the prefix."""
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": []}
    )
    assert decision.allowed


def test_an_empty_list_is_refused_when_min_length_is_set(sandbox: Path) -> None:
    decision = engine(
        sandbox, files={"type": "array", "min_length": 1, "path_prefix": PREFIX}
    ).evaluate("git_add_many", {"files": []})
    assert decision.decision == DENY
    assert "min_length" in decision.reason


def test_an_absolute_path_inside_a_list_is_refused(sandbox: Path) -> None:
    """A relative prefix never accepts an absolute candidate, element or not."""
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": ["/etc/passwd"]}
    )
    assert decision.decision == DENY
    assert "absolute path" in decision.reason


def test_a_symlink_that_escapes_the_prefix_is_refused_inside_a_list(sandbox: Path) -> None:
    outside = sandbox / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = sandbox / "workspace" / "escape.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    decision = engine(sandbox, files={"type": "array", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": ["workspace/escape.txt"]}
    )
    assert decision.decision == DENY
    assert "outside the allowed prefix" in decision.reason


def test_a_regex_is_applied_to_every_element_of_a_list(sandbox: Path) -> None:
    decision = engine(sandbox, files={"type": "array", "regex": r"[\w./-]+"}).evaluate(
        "git_add_many", {"files": ["ok.txt", "not a path!"]}
    )
    assert decision.decision == DENY
    assert "files[1]" in decision.reason


# ------------------------------------------------ the list: explicit 'items'


def test_items_refuses_a_traversal_element(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={"type": "array", "items": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": [CANARY]})
    assert decision.decision == DENY
    assert "files[0]" in decision.reason


def test_items_allows_a_list_of_safe_paths(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={"type": "array", "items": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": ["workspace/ok.txt", "workspace/other.txt"]})
    assert decision.allowed


def test_items_refuses_an_element_of_the_wrong_type(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={"type": "array", "items": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": [42]})
    assert decision.decision == DENY
    assert "must be of type string" in decision.reason


def test_the_element_alias_is_accepted(sandbox: Path) -> None:
    """``element:`` is the same field as ``items:``."""
    decision = engine(
        sandbox,
        files={"type": "array", "element": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": [CANARY]})
    assert decision.decision == DENY
    assert "files[0]" in decision.reason


def test_items_max_length_is_the_length_of_the_element_string(sandbox: Path) -> None:
    """The length of an element is ``items.max_length``, not the length of the list."""
    decision = engine(
        sandbox,
        files={
            "type": "array",
            "items": {"type": "string", "max_length": 8, "path_prefix": PREFIX},
        },
    ).evaluate("git_add_many", {"files": ["workspace/a-very-long-name.txt"]})
    assert decision.decision == DENY
    assert "max_length 8" in decision.reason


def test_max_length_on_the_array_is_the_length_of_the_list(sandbox: Path) -> None:
    """The disambiguation: on an array, ``max_length`` counts the elements."""
    decision = engine(
        sandbox,
        files={
            "type": "array",
            "max_length": 2,
            "items": {"type": "string", "max_length": 256, "path_prefix": PREFIX},
        },
    ).evaluate("git_add_many", {"files": ["workspace/a.txt", "workspace/b.txt", "workspace/c.txt"]})
    assert decision.decision == DENY
    assert "max_length 2" in decision.reason


def test_items_enum_is_applied_to_every_element(sandbox: Path) -> None:
    decision = engine(
        sandbox, files={"type": "array", "items": {"enum": ["a.txt", "b.txt"]}}
    ).evaluate("git_add_many", {"files": ["a.txt", "c.txt"]})
    assert decision.decision == DENY
    assert "files[1]" in decision.reason
    assert "must be one of" in decision.reason


def test_enum_on_the_array_is_the_enum_of_the_whole_list(sandbox: Path) -> None:
    """The 0.4 meaning is kept: the enum describes the value, not its elements."""
    decision = engine(
        sandbox, files={"type": "array", "enum": [["a.txt", "b.txt"]]}
    ).evaluate("git_add_many", {"files": ["a.txt", "b.txt"]})
    assert decision.allowed
    refused = engine(
        sandbox, files={"type": "array", "enum": [["a.txt"]]}
    ).evaluate("git_add_many", {"files": ["a.txt", "b.txt"]})
    assert refused.decision == DENY


def test_items_declared_but_the_value_is_not_a_list_is_refused(sandbox: Path) -> None:
    """Without a declared type, the ``items`` constraint itself refuses a scalar."""
    decision = engine(sandbox, files={"items": {"type": "string"}}).evaluate(
        "git_add_many", {"files": "workspace/ok.txt"}
    )
    assert decision.decision == DENY
    assert "must be a list" in decision.reason


def test_a_declared_type_is_checked_before_the_items(sandbox: Path) -> None:
    decision = engine(sandbox, files={"type": "array", "items": {"type": "string"}}).evaluate(
        "git_add_many", {"files": "workspace/ok.txt"}
    )
    assert decision.decision == DENY
    assert "must be of type array" in decision.reason


# ------------------------------------------------------------ nested lists


def test_a_nested_list_is_checked_to_the_second_level(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={
            "type": "array",
            "items": {
                "type": "array",
                "items": {"type": "string", "path_prefix": PREFIX},
            },
        },
    ).evaluate("git_add_many", {"files": [["workspace/ok.txt"], [CANARY]]})
    assert decision.decision == DENY
    assert "files[1][0]" in decision.reason


def test_a_nested_list_of_safe_paths_is_allowed(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={
            "type": "array",
            "items": {
                "type": "array",
                "items": {"type": "string", "path_prefix": PREFIX},
            },
        },
    ).evaluate("git_add_many", {"files": [["workspace/ok.txt"], ["workspace/other.txt"]]})
    assert decision.allowed


def test_a_policy_may_not_nest_elements_more_than_four_levels_deep(
    write_policy, tmp_path: Path
) -> None:
    """Five levels of ``items:`` are one level too many."""
    document = (
        "tools:\n"
        "  git_add_many:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      files:\n"
        "        type: array\n"
        "        items:\n"
        "          type: array\n"
        "          items:\n"
        "            type: array\n"
        "            items:\n"
        "              type: array\n"
        "              items:\n"
        "                type: array\n"
        "                items:\n"
        "                  type: string\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(write_policy(document))
    assert "nested more than 4 levels deep" in str(error.value)


def test_a_policy_may_nest_elements_four_levels_deep(write_policy) -> None:
    document = (
        "tools:\n"
        "  git_add_many:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      files:\n"
        "        type: array\n"
        "        items:\n"
        "          type: array\n"
        "          items:\n"
        "            type: array\n"
        "            items:\n"
        "              type: array\n"
        "              items:\n"
        "                type: string\n"
    )
    policy = load_policy(write_policy(document))
    assert policy.tools["git_add_many"].arguments["files"].items is not None


# -------------------------------------------------------------- map shapes


def test_the_keys_of_a_map_are_checked(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={"type": "object", "keys": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": {CANARY: "content"}})
    assert decision.decision == DENY
    assert "path_prefix" in decision.reason


def test_the_values_of_a_map_are_checked(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={"type": "object", "values": {"type": "string", "path_prefix": PREFIX}},
    ).evaluate("git_add_many", {"files": {"a.txt": CANARY}})
    assert decision.decision == DENY
    assert "path_prefix" in decision.reason


def test_a_map_of_safe_paths_is_allowed(sandbox: Path) -> None:
    decision = engine(
        sandbox,
        files={
            "type": "object",
            "keys": {"type": "string", "path_prefix": PREFIX},
            "values": {"type": "string", "path_prefix": PREFIX},
        },
    ).evaluate("git_add_many", {"files": {"workspace/a.txt": "workspace/b.txt"}})
    assert decision.allowed


def test_a_map_with_a_path_prefix_but_no_keys_is_refused(sandbox: Path) -> None:
    """The policy has to say which side of the map holds the paths."""
    decision = engine(sandbox, files={"type": "object", "path_prefix": PREFIX}).evaluate(
        "git_add_many", {"files": {"workspace/a.txt": "content"}}
    )
    assert decision.decision == DENY
    assert "must be a string path" in decision.reason


# --------------------------------------------------------- policy sanity


def test_required_is_not_meaningful_inside_items(write_policy) -> None:
    document = (
        "tools:\n"
        "  git_add_many:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      files:\n"
        "        type: array\n"
        "        items:\n"
        "          type: string\n"
        "          required: true\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(write_policy(document))
    assert "required is not meaningful inside 'items'" in str(error.value)


def test_items_needs_the_array_type(write_policy) -> None:
    document = (
        "tools:\n"
        "  git_add_many:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      files:\n"
        "        type: string\n"
        "        items:\n"
        "          type: string\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(write_policy(document))
    assert "needs type 'array'" in str(error.value)


def test_keys_needs_the_object_type(write_policy) -> None:
    document = (
        "tools:\n"
        "  git_add_many:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      files:\n"
        "        type: array\n"
        "        keys:\n"
        "          type: string\n"
    )
    with pytest.raises(PolicyError) as error:
        load_policy(write_policy(document))
    assert "needs type 'object'" in str(error.value)

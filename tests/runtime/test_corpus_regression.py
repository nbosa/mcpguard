"""The regression corpus: the list-form traversal is refused.

The corpus in ``../corpus`` is a small, self-contained set of cases in the
shape of the upstream guard corpus (the upstream guard corpus,
which is read-only and is not modified by this work).  Every case is a list of
calls with an expected decision, and the expected decision is an assertion
about the reference policy in ``../corpus/reference-policy.yaml`` -- not a
wish.

The harness runs the cases **in process**, against :class:`PolicyEngine`, so
the corpus needs no MCP server and no network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp_guard import yamlmini as yaml

from mcp_guard.policy import ALLOW, DENY, PolicyEngine, load_policy

CORPUS_DIR = Path(__file__).resolve().parents[2] / "corpus"
CASES_DIR = CORPUS_DIR / "cases"
REFERENCE_POLICY = CORPUS_DIR / "reference-policy.yaml"

#: The workspace layout the cases refer to, relative to the base directory.
WORKSPACE_FILES = (
    "cases/workspace/repo-a/README.md",
    "cases/workspace/repo-a/src/app.py",
    "cases/workspace/repo-a/src/util.py",
)
#: The canary that lives *outside* the workspace, one level above it.
CANARY = "CANARY-ESCAPE-9f3a.txt"


def _load_case(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path.name} must contain a mapping"
    return document


def _all_cases() -> list[tuple[str, dict[str, Any]]]:
    cases = []
    for path in sorted(CASES_DIR.glob("*.yaml")):
        cases.append((path.stem, _load_case(path)))
    return cases


def _calls() -> list[tuple[str, str, dict[str, Any]]]:
    """Every call of every case, as (case id, call id, call)."""
    collected = []
    for case_id, case in _all_cases():
        for call in case["calls"]:
            collected.append((case_id, call["id"], call))
    return collected


def _tool_of(case_id: str) -> str:
    """The tool of the case with this id."""
    for name, case in _all_cases():
        if name == case_id:
            return case["tool"]["name"]
    raise KeyError(case_id)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """The fixture workspace: a repository inside ``cases/workspace``."""
    for relative in WORKSPACE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture\n", encoding="utf-8")
    (tmp_path / CANARY).write_text("secret\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("case_id", "call_id", "call"),
    _calls(),
    ids=[f"{case_id}-{call_id}" for case_id, call_id, _ in _calls()],
)
def test_the_corpus_case_produces_the_expected_decision(
    case_id: str, call_id: str, call: dict[str, Any], workspace: Path
) -> None:
    """Each call of the corpus produces the decision the case expects."""
    policy = load_policy(REFERENCE_POLICY)
    engine = PolicyEngine(policy, session_id="corpus", base_dir=workspace)

    tool = call.get("tool") or _tool_of(case_id)
    decision = engine.evaluate(tool, call["arguments"])

    expected = call["expected"]
    assert expected in ("allow", "block"), f"unknown expectation {expected!r}"
    if expected == "allow":
        assert decision.decision == ALLOW, (
            f"{case_id}/{call_id} was refused but should be allowed: {decision.reason}"
        )
    else:
        assert decision.decision == DENY, (
            f"{case_id}/{call_id} was allowed but should be blocked"
        )
        assert decision.reason, "a refusal must carry a reason"


def test_the_corpus_covers_the_three_shapes() -> None:
    """The corpus keeps its shape: a scalar traversal, a list traversal and a legitimate call."""
    cases = _all_cases()
    assert len(cases) >= 3, "the corpus must hold at least three cases"

    expectations = {
        (case_id, call["id"]): call["expected"]
        for case_id, _, call in _calls()
    }
    blocked = [key for key, value in expectations.items() if value == "block"]
    allowed = [key for key, value in expectations.items() if value == "allow"]

    assert any("01-git-add-scalar-traversal" in case for case, _ in blocked), (
        "the scalar traversal case must be blocked"
    )
    assert any("list-traversal" in case for case, _ in blocked), (
        "the list-form traversal case must be blocked"
    )
    assert any("legitimate" in case for case, _ in allowed), (
        "the legitimate multi-file case must be allowed"
    )


def test_the_list_form_traversal_case_is_blocked(workspace: Path) -> None:
    """The corpus payload of the upstream case 05b, refused by the 0.5 policy."""
    policy = load_policy(REFERENCE_POLICY)
    engine = PolicyEngine(policy, session_id="corpus", base_dir=workspace)

    decision = engine.evaluate(
        "git_add_many",
        {"files": ["../CANARY-ESCAPE-9f3a.txt"], "repo_path": "cases/workspace/repo-a"},
    )
    assert decision.decision == DENY
    assert "files[0]" in decision.reason


def test_the_legitimate_multi_file_add_is_allowed(workspace: Path) -> None:
    """The same tool, a list of workspace paths: still allowed."""
    policy = load_policy(REFERENCE_POLICY)
    engine = PolicyEngine(policy, session_id="corpus", base_dir=workspace)

    decision = engine.evaluate(
        "git_add_many",
        {
            "files": [
                "cases/workspace/repo-a/src/app.py",
                "cases/workspace/repo-a/README.md",
            ],
            "repo_path": "cases/workspace/repo-a",
        },
    )
    assert decision.decision == ALLOW

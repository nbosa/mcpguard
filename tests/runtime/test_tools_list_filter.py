"""Tests for the filtering of the ``tools/list`` response.

A tool that the policy denies must never be advertised to the client: the
client should not even learn that the tool exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import proxy_session, run_async
from mcp_guard.policy import Policy, PolicyEngine

POLICY = """
version: 1
default_action: deny
tools:
  read_file:
    action: allow
  run_shell:
    action: deny
  send_email:
    action: allow
    require_approval: true
"""


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return path


def test_the_engine_hides_the_denied_tools() -> None:
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {"action": "allow"},
                "run_shell": {"action": "deny"},
                "send_email": {"action": "allow", "require_approval": True},
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.visible_tools(["read_file", "run_shell", "send_email"]) == ["read_file", "send_email"]
    assert engine.advertises("read_file")
    assert not engine.advertises("run_shell")
    assert not engine.advertises("an_unknown_tool")


def test_the_client_only_sees_the_allowed_tools(policy: Path, tmp_path: Path) -> None:
    async def main():
        async with proxy_session(policy, base_dir=tmp_path) as session:
            result = await session.list_tools()
            return [tool.name for tool in result.tools]

    names = run_async(main)
    assert "read_file" in names
    assert "run_shell" not in names
    # A tool that needs an approval is still advertised: it is reachable, the
    # call is what needs the approval.
    assert "send_email" in names


def test_a_default_deny_policy_advertises_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("version: 1\n", encoding="utf-8")

    async def main():
        async with proxy_session(empty, base_dir=tmp_path) as session:
            result = await session.list_tools()
            return [tool.name for tool in result.tools]

    assert run_async(main) == []


def test_the_filtered_list_is_written_to_the_audit_log(policy: Path, tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"

    async def main():
        async with proxy_session(
            policy, audit=audit, extra=["--legacy-unkeyed"], base_dir=tmp_path
        ) as session:
            await session.list_tools()

    run_async(main)

    import json

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
    listing = [record for record in records if record["method"] == "tools/list"]
    assert len(listing) == 1
    assert listing[0]["arguments"]["hidden"] == ["run_shell"]
    assert "read_file" in listing[0]["arguments"]["advertised"]
    assert listing[0]["decision"] == "allow"

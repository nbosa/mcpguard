"""The fixes of 0.5.0rc2: RC-01, RC-02, the initialize deadline and R-01.

Every test here is about a *behaviour* that changed in 0.5.0rc2:

* **F1 / RC-01** -- an oversize upstream line is discarded, the request that
  was waiting for it is answered, and the proxy keeps serving.
* **F2 / RC-02** -- a mistyped option is refused instead of ignored, while
  the upstream command is still passed through untouched.
* **F3** -- the ``initialize`` handshake has a deadline, so a hung upstream
  cannot leave the client waiting.
* **F4 / R-01** -- a policy regex that could stall the proxy is refused when
  the policy is *loaded*, and the value a regex is applied to is capped.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Iterator

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from mcp_guard.audit import STATUS_OK, verify_log
from mcp_guard.cli import EXIT_USAGE, main
from mcp_guard.policy import PolicyError, load_policy
from mcp_guard.proxy import UPSTREAM_OVERSIZE_CODE, UPSTREAM_TIMEOUT_CODE
from mcp_guard.upstream import MAX_LINE_CHARS, LineSplitter, OversizeLine, split_lines

from .conftest import child_environment
from .test_rc_cross_feature import call_over_stdio

REPO_ROOT = Path(__file__).resolve().parents[2]

#: An upstream whose **first** answer is over the proxy's line bound and
#: whose later answers are ordinary.  It is the shape of a broken upstream
#: that answers one call with a huge blob and then carries on.
OVERSIZE_UPSTREAM = '''\
"""An upstream whose first answer is over the line bound of the proxy."""

import json
import sys

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

CALLS = {"n": 0}


async def on_list_tools(ctx, params):
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="git_add_many",
                description="echo the list back",
                input_schema={"type": "object"},
            )
        ]
    )


async def on_call_tool(ctx, params):
    CALLS["n"] += 1
    if CALLS["n"] == 1:
        # A response line that is over the bound the proxy puts on one line
        # of the upstream's stdout.
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="x" * 9_000_000)]
        )
    files = (params.arguments or {}).get("files", [])
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(files))]
    )


async def main():
    server = Server(
        "oversize-upstream",
        version="1.0.0",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    anyio.run(main)
'''

#: An upstream that reads its input and never answers.  The handshake with
#: it therefore never completes.
SILENT_UPSTREAM = '''\
"""An upstream that never answers anything."""

import sys

for _line in sys.stdin:
    pass
'''

LIST_POLICY = """
version: 1
default_action: deny
tools:
  git_add_many:
    action: allow
    arguments:
      files:
        type: array
        required: true
        items:
          type: string
          path_prefix: "./sandbox"
"""


def write_upstream(directory: Path, source: str, name: str = "upstream.py") -> Path:
    """Write an upstream script into ``directory`` and return its path."""
    path = directory / name
    path.write_text(source, encoding="utf-8")
    return path


def proxy_arguments(policy: Path, upstream: Path, *extra: str) -> list[str]:
    """The command line of the proxy, in front of ``upstream``."""
    return [
        sys.executable, "-m", "mcp_guard", "run",
        "--policy", str(policy),
        *extra,
        "--", sys.executable, str(upstream),
    ]


def read_records(path: Path) -> list[dict[str, Any]]:
    """The decision records of an audit log."""
    records = []
    for line in path.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record_type") == "record":
            records.append(record)
    return records


# ===========================================================================
# F1 / RC-01  the oversize upstream line
# ===========================================================================


def test_a_line_of_exactly_the_bound_is_accepted() -> None:
    """A line of exactly ``MAX_LINE_CHARS`` characters is not over the bound."""
    bound = 4096
    line = "x" * bound
    results = list(split_lines([line + "\n"], max_chars=bound))

    assert results == [line], "a line of exactly the bound must be passed on"


def test_a_line_of_the_bound_plus_one_is_discarded() -> None:
    """A line of one character more than the bound is discarded, not passed on."""
    bound = 4096
    results = list(split_lines(["x" * (bound + 1) + "\n"], max_chars=bound))

    assert results == [OversizeLine(bound + 1)], results


def test_the_oversize_line_is_drained_and_the_next_line_is_read() -> None:
    """The line after an oversize one is read normally.

    The oversize line is drained to its newline without being buffered, so
    the reader is back in sync for the line that follows it.
    """
    bound = 64
    chunks = ["x" * (bound + 1), "\n", "the next line\n"]
    results = list(split_lines(chunks, max_chars=bound))

    assert results == [OversizeLine(bound + 1), "the next line"], results


def test_the_buffer_does_not_grow_with_the_oversize_line() -> None:
    """The memory the reader needs does not depend on the size of the line.

    A 4 MiB line is fed in 64 KiB chunks with a bound of 4 KiB.  The peak
    memory has to stay near the bound -- if the whole line were buffered, the
    peak would be the size of the line.
    """
    chunk_size = 64 * 1024
    total = 4 * 1024 * 1024

    def chunks() -> Iterator[str]:
        sent = 0
        while sent < total:
            yield "y" * min(chunk_size, total - sent)
            sent += chunk_size

    tracemalloc.start()
    try:
        splitter = LineSplitter(max_chars=4096)
        results: list[str | OversizeLine] = []
        for chunk in chunks():
            results.extend(splitter.feed(chunk))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The overflow is reported once, as soon as it is noticed -- and the
    # buffer that holds the line is empty from then on.
    assert len(results) == 1, results
    assert isinstance(results[0], OversizeLine), results
    assert results[0].chars <= 4096 + chunk_size, results[0]
    assert splitter.buffer == "", splitter.buffer
    assert peak < 1024 * 1024, f"the reader buffered the whole line: {peak} bytes"


@pytest.mark.anyio
async def test_the_proxy_serves_the_next_request_after_an_oversize_line(
    tmp_path: Path,
) -> None:
    """The proxy survives an oversize line and answers the next request.

    This is the heart of RC-01: in 0.5.0rc1 the oversize line killed the
    whole proxy, so there was no "next request" at all.
    """
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(LIST_POLICY, encoding="utf-8")
    (tmp_path / "sandbox").mkdir()
    upstream = write_upstream(tmp_path, OVERSIZE_UPSTREAM)

    command = proxy_arguments(policy_path, upstream)
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(tmp_path),
        env=child_environment(),
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            with anyio.move_on_after(20) as scope:
                try:
                    await session.call_tool("git_add_many", {"files": ["sandbox/ok.txt"]})
                except MCPError as exc:
                    code = getattr(getattr(exc, "error", None), "code", None)
                    assert code == UPSTREAM_OVERSIZE_CODE, f"{code!r}"
                else:
                    pytest.fail("the oversize answer was accepted")
            assert not scope.cancelled_caught, "the client was left waiting"

            # The proxy is still there and still serving.
            result = await session.call_tool("git_add_many", {"files": ["sandbox/ok.txt"]})
            text = "".join(
                block.text for block in result.content if getattr(block, "type", None) == "text"
            )
            assert "sandbox/ok.txt" in text, text


@pytest.mark.anyio
async def test_the_audit_log_of_an_oversize_line_verifies(tmp_path: Path) -> None:
    """The oversize line leaves an audit record, and the log still verifies.

    The record carries the **size** of the line, the **tool** it was the
    answer of, and the **reason** -- and no payload content, because the
    payload is the very thing that was too large.
    """
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(LIST_POLICY, encoding="utf-8")
    (tmp_path / "sandbox").mkdir()
    upstream = write_upstream(tmp_path, OVERSIZE_UPSTREAM)
    audit = tmp_path / "audit.jsonl"
    key_file = tmp_path / "audit.key"

    keygen = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "keygen", "--out", str(key_file)],
        capture_output=True, env=child_environment(), cwd=str(tmp_path),
    )
    assert keygen.returncode == 0, keygen.stderr

    command = proxy_arguments(
        policy_path, upstream, "--audit", str(audit), "--audit-key-file", str(key_file)
    )
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(tmp_path),
        env=child_environment(),
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            with anyio.move_on_after(20):
                try:
                    await session.call_tool("git_add_many", {"files": ["sandbox/ok.txt"]})
                except MCPError:
                    pass

    result = verify_log(audit, key_file=key_file)
    assert result.status == STATUS_OK, result.reason

    records = read_records(audit)
    oversize = [
        record for record in records if "discarded" in record.get("reason", "")
    ]
    assert oversize, [record.get("reason") for record in records]
    record = oversize[0]
    assert record["tool_name"] == "git_add_many"
    assert record["arguments"] == {}, "the record must not carry the payload"
    # The record carries the *size* of the discarded line -- a lower bound on
    # it, because the report is made as soon as the overflow is noticed.
    assert "characters were discarded" in record["reason"], record["reason"]
    assert str(MAX_LINE_CHARS) in record["reason"], record["reason"]


# ===========================================================================
# F2 / RC-02  the mistyped option
# ===========================================================================


def test_a_mistyped_upstream_timeout_is_refused_and_names_the_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--upstream-timout 5`` is refused, and the message names the flag."""
    code = main(
        [
            "run",
            "--policy", "does-not-matter.yaml",
            "--upstream-timout", "5",
            "--",
            sys.executable, "-c", "pass",
        ]
    )

    assert code == EXIT_USAGE
    error = capsys.readouterr().err
    assert "--upstream-timout" in error, error
    # The closest known flag is offered, so the operator can see the typo.
    assert "--upstream-timeout" in error, error


def test_the_correct_upstream_timeout_is_accepted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--upstream-timeout 5`` is a known option and is not refused."""
    code = main(
        [
            "run",
            "--policy", "does-not-matter.yaml",
            "--upstream-timeout", "5",
            "--",
            sys.executable, "-c", "pass",
        ]
    )

    # The policy file does not exist, so the run stops with a usage error --
    # but *not* with "unrecognized argument".
    assert code == EXIT_USAGE
    error = capsys.readouterr().err
    assert "unrecognized" not in error, error


def test_the_upstream_arguments_after_the_separator_are_passed_through() -> None:
    """Whatever is after ``--`` is the upstream command, untouched.

    The upstream command keeps its own options, its own values and its own
    order: the separator is the only thing that is read.
    """
    seen: dict[str, Any] = {}

    def fake_run(options: Any, upstream: list[str]) -> int:
        seen["upstream"] = list(upstream)
        return 0

    import mcp_guard.cli as cli

    original = cli._run
    cli._run = fake_run  # type: ignore[assignment]
    try:
        code = main(
            [
                "run",
                "--policy", "p.yaml",
                "--upstream-timeout", "5",
                "--",
                sys.executable, "-m", "server",
                "--port", "8080",
                "--",  # a second separator is part of the command
                "trailing",
            ]
        )
    finally:
        cli._run = original  # type: ignore[assignment]

    assert code == 0
    assert seen["upstream"] == [
        sys.executable, "-m", "server", "--port", "8080", "--", "trailing"
    ], seen["upstream"]


def test_an_upstream_command_without_the_separator_is_still_accepted() -> None:
    """The convenience form -- the command without ``--`` -- still works."""
    seen: dict[str, Any] = {}

    def fake_run(options: Any, upstream: list[str]) -> int:
        seen["upstream"] = list(upstream)
        return 0

    import mcp_guard.cli as cli

    original = cli._run
    cli._run = fake_run  # type: ignore[assignment]
    try:
        code = main(["run", "--policy", "p.yaml", "my-server", "serve"])
    finally:
        cli._run = original  # type: ignore[assignment]

    assert code == 0
    assert seen["upstream"] == ["my-server", "serve"], seen["upstream"]


# ===========================================================================
# F3  the deadline of the initialize handshake
# ===========================================================================


def test_the_initialize_handshake_has_a_deadline(tmp_path: Path) -> None:
    """An upstream that never answers the handshake must not hang the client.

    The client is answered with a JSON-RPC error, the proxy leaves with the
    documented exit code, and nothing waits for ever.
    """
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(LIST_POLICY, encoding="utf-8")
    upstream = write_upstream(tmp_path, SILENT_UPSTREAM)

    command = proxy_arguments(
        policy_path, upstream, "--upstream-init-timeout", "0.5"
    )
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment(),
        cwd=str(tmp_path),
    )
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "rc68-test", "version": "1.0.0"},
            },
        }
    ).encode("utf-8")
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(request + b"\n")
    process.stdin.flush()

    line = process.stdout.readline()
    process.stdin.close()
    exit_code = process.wait(timeout=30)
    elapsed = time.perf_counter() - started

    assert line, "the client was left waiting for an answer"
    answer = json.loads(line.decode("utf-8"))
    assert answer.get("id") == 1, answer
    assert "error" in answer, answer
    assert answer["error"]["code"] == UPSTREAM_TIMEOUT_CODE, answer
    assert exit_code == 4, f"the proxy must leave with the documented code, got {exit_code}"
    assert elapsed < 20, f"the proxy took {elapsed:.1f}s"


@pytest.mark.anyio
async def test_the_client_of_a_hung_upstream_gets_an_error_not_a_hang(
    tmp_path: Path,
) -> None:
    """The real client gets a JSON-RPC error from the handshake."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(LIST_POLICY, encoding="utf-8")
    upstream = write_upstream(tmp_path, SILENT_UPSTREAM)

    command = proxy_arguments(policy_path, upstream, "--upstream-init-timeout", "0.5")
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(tmp_path),
        env=child_environment(),
    )
    with anyio.move_on_after(20) as scope:
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                with pytest.raises(MCPError) as caught:
                    await session.initialize()
                code = getattr(getattr(caught.value, "error", None), "code", None)
                assert code == UPSTREAM_TIMEOUT_CODE, f"{code!r}"

    assert not scope.cancelled_caught, "the client was left waiting"


def test_the_initialize_deadline_is_audited(tmp_path: Path) -> None:
    """The refused handshake is written to the audit log."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(LIST_POLICY, encoding="utf-8")
    upstream = write_upstream(tmp_path, SILENT_UPSTREAM)
    audit = tmp_path / "audit.jsonl"
    key_file = tmp_path / "audit.key"

    keygen = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "keygen", "--out", str(key_file)],
        capture_output=True, env=child_environment(), cwd=str(tmp_path),
    )
    assert keygen.returncode == 0, keygen.stderr

    command = proxy_arguments(
        policy_path,
        upstream,
        "--upstream-init-timeout",
        "0.5",
        "--audit",
        str(audit),
        "--audit-key-file",
        str(key_file),
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment(),
        cwd=str(tmp_path),
    )
    assert process.stdin is not None
    process.stdin.write(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "rc68-test", "version": "1.0.0"},
                },
            }
        ).encode("utf-8")
        + b"\n"
    )
    process.stdin.flush()
    process.stdout.readline()
    process.stdin.close()
    process.wait(timeout=30)

    result = verify_log(audit, key_file=key_file)
    assert result.status == STATUS_OK, result.reason
    records = read_records(audit)
    assert records, "the refused handshake was not audited"
    assert records[0]["method"] == "initialize", records[0]
    assert "handshake" in records[0]["reason"], records[0]


def test_the_initialize_deadline_is_documented() -> None:
    """The deadline has a name, a default and a help text."""
    from mcp_guard.proxy import DEFAULT_UPSTREAM_INIT_TIMEOUT

    assert DEFAULT_UPSTREAM_INIT_TIMEOUT > 0
    help_text = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "run", "--help"],
        capture_output=True,
        env=child_environment(),
        cwd=str(REPO_ROOT),
    ).stdout.decode("utf-8")
    assert "--upstream-init-timeout" in help_text, help_text
    assert f"{DEFAULT_UPSTREAM_INIT_TIMEOUT:g}" in help_text, help_text


# ===========================================================================
# F4 / R-01  the regular expression that could stall the proxy
# ===========================================================================


DANGEROUS_PATTERNS = [
    "(a+)+",
    "(a*)*",
    "(a|aa)+",
    "(.*a){10,}",
    r"(\w+\s?)*",
    "([a-z]+)*",
    "(a|a)+",
    "^(a?)+$",
]

SAFE_PATTERNS = [
    r"^[a-z0-9_-]{1,64}$",
    r"^/workspace/[A-Za-z0-9_./-]*$",
    r"^https://[a-z0-9.-]+\.example\.com/.*$",
    r"^\d{4}-\d{2}-\d{2}$",
    r"^[^/]+$",
    r"^user-[0-9]+$",
    r"^(\d{1,3}\.){3}\d{1,3}$",
    r"^(GET|POST|PUT)$",
]


def policy_with_regex(pattern: str, **extra: Any) -> str:
    """A policy with one tool whose argument is constrained by ``pattern``."""
    constraint = {"type": "string", "regex": pattern}
    constraint.update(extra)
    return json.dumps(
        {
            "version": 1,
            "default_action": "deny",
            "tools": {"tool_name": {"action": "allow", "arguments": {"arg": constraint}}},
        }
    )


@pytest.mark.parametrize("pattern", DANGEROUS_PATTERNS)
def test_a_dangerous_regex_is_refused_at_load_time(tmp_path: Path, pattern: str) -> None:
    """A regex with a nested quantifier is refused when the policy is loaded."""
    path = tmp_path / "policy.yaml"
    path.write_text(policy_with_regex(pattern), encoding="utf-8")

    with pytest.raises(PolicyError) as caught:
        load_policy(path)

    message = str(caught.value)
    assert "regex" in message, message
    assert "denial-of-service" in message, message


@pytest.mark.parametrize("pattern", SAFE_PATTERNS)
def test_a_common_regex_is_accepted(tmp_path: Path, pattern: str) -> None:
    """The patterns a policy really uses are not refused."""
    path = tmp_path / "policy.yaml"
    path.write_text(policy_with_regex(pattern), encoding="utf-8")

    policy = load_policy(path)

    constraint = policy.tools["tool_name"].arguments["arg"]
    assert constraint.regex == pattern


def test_the_escape_hatch_is_off_by_default(tmp_path: Path) -> None:
    """Without the escape hatch the dangerous pattern is refused."""
    path = tmp_path / "policy.yaml"
    path.write_text(policy_with_regex("(a+)+"), encoding="utf-8")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_the_escape_hatch_allows_a_dangerous_regex_and_is_announced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``allow_unsafe_regex: true`` works, and it is announced."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        policy_with_regex("(a+)+", allow_unsafe_regex=True), encoding="utf-8"
    )

    policy = load_policy(path)

    constraint = policy.tools["tool_name"].arguments["arg"]
    assert constraint.regex == "(a+)+"
    assert constraint.allow_unsafe_regex is True
    warning = capsys.readouterr().err
    assert "allow_unsafe_regex" in warning, warning
    assert "(a+)+" in warning, warning


def test_the_attack_string_does_not_stall_the_proxy(tmp_path: Path) -> None:
    """The 31-character attack string of R-01 does not stall anything.

    The string is thirty ``a`` followed by one character that does not match:
    the canonical payload of a nested ``a+`` quantifier, and the payload the
    0.5.0rc1 report measured as a 30-second stall.

    A policy with such a regex cannot even be loaded any more, and a policy
    with a *safe* regex answers the attack string in well under a second.
    """
    attack = "a" * 30 + "!"

    # 1. the dangerous policy is refused at load time, and fast.
    dangerous = tmp_path / "dangerous.yaml"
    dangerous.write_text(policy_with_regex("(a+)+"), encoding="utf-8")
    started = time.perf_counter()
    with pytest.raises(PolicyError):
        load_policy(dangerous)
    assert time.perf_counter() - started < 1.0

    # 2. a safe policy answers the attack string in well under a second.
    safe = tmp_path / "safe.yaml"
    safe.write_text(policy_with_regex(r"^[a-z0-9_-]{1,64}$"), encoding="utf-8")
    policy = load_policy(safe)
    from mcp_guard.policy import PolicyEngine

    engine = PolicyEngine(policy, session_id="rc68", base_dir=tmp_path)
    started = time.perf_counter()
    decision = engine.evaluate("tool_name", {"arg": attack})
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"the evaluation took {elapsed:.3f}s"
    assert decision.decision == "deny"


def test_every_shipped_policy_still_loads() -> None:
    """Every policy that ships with mcp-guard still loads.

    The guard must not break a policy that was fine: the two example
    policies, the reference policy of the corpus and the two policies of the
    end-to-end smoke are loaded here.
    """
    shipped = [
        REPO_ROOT / "examples" / "policy.list-paths.yaml",
        REPO_ROOT / "corpus" / "reference-policy.yaml",
        REPO_ROOT / "tools" / "e2e" / "policy-v4.yaml",
        REPO_ROOT / "tools" / "e2e" / "policy-v5.yaml",
    ]
    for path in shipped:
        assert path.exists(), path
        load_policy(path)


def test_a_value_longer_than_the_regex_input_cap_is_refused(tmp_path: Path) -> None:
    """A value that is longer than the cap is refused, not matched."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        policy_with_regex(r"^[a-z0-9_-]{1,64}$", max_regex_input=16), encoding="utf-8"
    )
    policy = load_policy(path)
    from mcp_guard.policy import PolicyEngine

    engine = PolicyEngine(policy, session_id="rc68", base_dir=tmp_path)
    decision = engine.evaluate("tool_name", {"arg": "a" * 17})

    assert decision.decision == "deny", decision.reason
    assert "16 characters" in decision.reason, decision.reason


def test_the_regex_input_cap_is_configurable(tmp_path: Path) -> None:
    """The cap is a policy setting, and it is honoured."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        policy_with_regex(r"^[a-z0-9_-]{1,64}$", max_regex_input=16), encoding="utf-8"
    )
    policy = load_policy(path)
    constraint = policy.tools["tool_name"].arguments["arg"]

    assert constraint.max_regex_input == 16
    # Without the setting the default is used.
    plain = tmp_path / "plain.yaml"
    plain.write_text(policy_with_regex(r"^[a-z0-9_-]{1,64}$"), encoding="utf-8")
    assert load_policy(plain).tools["tool_name"].arguments["arg"].max_regex_input is None

    from mcp_guard.redos import DEFAULT_MAX_REGEX_INPUT

    assert DEFAULT_MAX_REGEX_INPUT == 4096

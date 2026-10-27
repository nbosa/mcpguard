"""The cross-feature tests of the 0.5.0rc1 merge.

Every test in this file stands on a place where the **0.4.1 patch release** and
the **0.5 per-element constraints** meet.  Neither branch alone is enough for
any of them: the patch release is about the audit log, the budget and the
upstream, and the feature is about what a list or a map may contain.

The three interactions the merge had to get right are marked ``(a)``,
``(b)`` and ``(c)``:

``(a)``
    The R-02 budget charging must happen **exactly once** per call, even when
    a list element fails a constraint -- the constraint check may produce one
    violation per bad element, and the budget must not follow that count.
``(b)``
    The R-04 audit fix must survive a violation reason that quotes a list
    element containing U+2028, U+2029 or U+0085.  The record of such a refusal
    must still verify.
``(c)``
    The R-13 bounded upstream buffer must not turn a large but legal list
    argument into a silent truncation.  It either passes the argument whole
    or refuses it with ``-32005``.

Every test states in its docstring **which branch it fails on** and **which
branch it is impossible on**.  The compatibility shims at the top of this file
exist for exactly that reason: the file is meant to be dropped into either
branch unchanged to reproduce the evidence, so a symbol that only exists in
0.4.1 has to degrade into a clean assertion failure rather than a collection
error.

Run it against a branch with::

    cp tests/test_rc_cross_feature.py <branch>/tests/
    cd <branch> && python -m pytest -q tests/test_rc_cross_feature.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from mcp_guard import __version__
from mcp_guard.audit import STATUS_BROKEN, STATUS_OK, AuditLog, verify_log
from mcp_guard.cli import EXIT_BROKEN, EXIT_OK, EXIT_USAGE, main
from mcp_guard.keys import AuditKey, KeyRing, generate_key, write_key_file
from mcp_guard.policy import Policy, PolicyEngine
from mcp_guard.proxy import MCPGuardProxy, ProxyConfig

# -- compatibility shims (see the module docstring) -------------------------
try:  # 0.4.1 (R-04): the verifier splits on newlines only.
    from mcp_guard.audit import read_log_lines
except ImportError:  # pragma: no cover - the 0.5 branch alone
    read_log_lines = None  # type: ignore[assignment]

try:  # 0.4.1 (R-13): the JSON-RPC code of a request the upstream never answered.
    from mcp_guard.proxy import UPSTREAM_TIMEOUT_CODE
except ImportError:  # pragma: no cover - the 0.5 branch alone
    UPSTREAM_TIMEOUT_CODE = None  # type: ignore[assignment]

try:  # 0.4.1 (R-13): the bound on one line of the upstream's stdout.
    from mcp_guard.upstream import MAX_LINE_CHARS
except ImportError:  # pragma: no cover - the 0.5 branch alone
    MAX_LINE_CHARS = None  # type: ignore[assignment]

KEY = AuditKey.from_material("rc61" * 10)

#: The three characters that cut a record in half when the file is split with
#: ``str.splitlines()``.
SEPARATORS = [
    pytest.param(" ", id="U+2028 LINE SEPARATOR"),
    pytest.param(" ", id="U+2029 PARAGRAPH SEPARATOR"),
    pytest.param("", id="U+0085 NEXT LINE"),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"


# -- helpers ----------------------------------------------------------------


def list_policy(
    *,
    rate_limit_per_minute: int | None = None,
    max_calls: int | None = None,
    items: bool = True,
) -> Policy:
    """A policy with one tool that takes a list of paths.

    With ``items=True`` the constraint is declared the v5 way (a nested
    ``items`` block); with ``items=False`` it is the short form, where
    ``path_prefix`` is applied to every element of the list.
    """
    files: dict[str, Any] = {"type": "array", "required": True, "max_length": 64}
    if items:
        files["items"] = {"type": "string", "max_length": 256, "path_prefix": "./sandbox"}
    else:
        files["path_prefix"] = "./sandbox"
    rule: dict[str, Any] = {"action": "allow", "arguments": {"files": files}}
    if rate_limit_per_minute is not None:
        rule["rate_limit_per_minute"] = rate_limit_per_minute
    if max_calls is not None:
        rule["max_calls"] = max_calls
    return Policy.model_validate({"tools": {"git_add_many": rule}})


def map_policy() -> Policy:
    """A policy with one tool that takes a map of old paths to new paths."""
    return Policy.model_validate(
        {
            "tools": {
                "git_rename": {
                    "action": "allow",
                    "arguments": {
                        "renames": {
                            "type": "object",
                            "required": True,
                            "keys": {"type": "string", "path_prefix": "./sandbox"},
                            "values": {"type": "string", "path_prefix": "./sandbox"},
                        }
                    },
                }
            }
        }
    )


def engine_for(policy: Policy, base_dir: Path) -> PolicyEngine:
    """A policy engine rooted at ``base_dir``."""
    return PolicyEngine(policy, session_id="rc61-session", base_dir=base_dir)


def write_records(path: Path, records: list[dict[str, Any]], key: AuditKey = KEY) -> None:
    """Write ``records`` into a keyed audit log."""
    with AuditLog(path, "rc61-session", key=key, require_keyed=True, warn=False) as log:
        for record in records:
            log.append(
                method=record.get("method", "tools/call"),
                tool_name=record.get("tool_name", "git_add_many"),
                arguments=record.get("arguments", {}),
                decision=record.get("decision", "deny"),
                reason=record.get("reason", "denied"),
            )


def read_records(path: Path) -> list[dict[str, Any]]:
    """The *decision* records of an audit log (checkpoints are not decisions)."""
    records = []
    for line in path.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record_type") == "record":
            records.append(record)
    return records


def sandbox(base_dir: Path) -> Path:
    """Create and return the ``sandbox`` directory the policies point at."""
    directory = base_dir / "sandbox"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


ECHO_UPSTREAM = '''\
"""An upstream that echoes the list it was given, and can also never answer."""

import json
import sys

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

MODE = sys.argv[1] if len(sys.argv) > 1 else "echo"


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
    if MODE == "hang":
        await anyio.sleep_forever()
    if MODE == "huge":
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
        "echo-upstream",
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


def upstream_script(directory: Path) -> Path:
    """Write the echo upstream into ``directory`` and return its path."""
    path = directory / "echo_upstream.py"
    path.write_text(ECHO_UPSTREAM, encoding="utf-8")
    return path


def proxy_environment() -> dict[str, str]:
    """An environment in which ``mcp_guard`` is importable without an install."""
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{SOURCE_ROOT}{os.pathsep}{existing}" if existing else str(SOURCE_ROOT)
    )
    return environment


async def call_over_stdio(
    *,
    policy: Path,
    upstream: Path,
    cwd: Path,
    arguments: dict[str, Any],
    extra: tuple[str, ...] = (),
    mode: str | None = None,
) -> tuple[str, str, int | None]:
    """Run the real proxy as a subprocess and make one tool call.

    Returns ``(status, detail, code)`` where ``status`` is ``"ok"`` or
    ``"error"`` and ``code`` is the JSON-RPC error code of a refusal.
    """
    command = [
        sys.executable, "-m", "mcp_guard", "run",
        "--policy", str(policy),
        *extra,
        "--", sys.executable, str(upstream),
    ]
    if mode is not None:
        command.append(mode)
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(cwd),
        env=proxy_environment(),
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            try:
                result = await session.call_tool("git_add_many", arguments)
            except MCPError as exc:
                data: Any = exc.data if isinstance(exc.data, dict) else {}
                code = getattr(getattr(exc, "error", None), "code", None)
                return "error", f"{data.get('code', '')}: {exc.message}", code
            text = "".join(
                block.text for block in result.content if getattr(block, "type", None) == "text"
            )
            return "ok", text, None


# ---------------------------------------------------------------------------
# (a)  R-02  x  v5:  the budget is charged exactly once per call
# ---------------------------------------------------------------------------


def test_a_refused_list_call_is_charged_exactly_once(tmp_path: Path) -> None:
    """(a) One call, three bad elements, one charge.

    The v5 constraint check produces **one violation per bad element** -- that
    is the whole point of the feature.  The R-02 charging happens before the
    check, so the budget must not follow the number of violations: one call
    costs one attempt, whatever the list looked like.

    Fails on: **v5 alone** -- there the refused call costs no budget at all
    (``total_calls == 0`` instead of ``1``).
    Fails on: **v41 alone** -- the list is refused as a whole (``must be a
    string path to satisfy path_prefix``), so there is one violation instead
    of three and no ``files[0]`` to name.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)

    decision = engine.evaluate(
        "git_add_many", {"files": ["../escape-a", "../escape-b", "../escape-c"]}
    )

    assert decision.decision == "deny"
    assert len(decision.violations) == 3, decision.violations
    assert any("files[0]" in violation for violation in decision.violations)
    assert any("files[2]" in violation for violation in decision.violations)
    # The charge is once, not once per violation.
    assert engine.guard.total_calls == 1
    assert engine.guard.calls_for("git_add_many") == 1


def test_the_refused_list_calls_reach_the_rate_limit(tmp_path: Path) -> None:
    """(a) The refused list calls are throttled like any other use of the tool.

    R-02 says an attempt is an attempt.  The v5 feature says what the attempt
    looked like.  Together: a client that probes the per-element constraints
    in a loop runs into the rate limit of the tool, exactly like a client that
    probes the scalar ones.

    Fails on: **v5 alone** -- the probing is free, so the rate limit never
    engages and the fourth call is denied again instead of rate limited.
    Fails on: **v41 alone** -- the refusal names the argument, not the
    element, so ``files[0]`` is nowhere in the reason.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(rate_limit_per_minute=3), tmp_path)

    for attempt in range(3):
        decision = engine.evaluate("git_add_many", {"files": [f"../escape-{attempt}"]})
        assert decision.decision == "deny", decision.reason
        assert "files[0]" in decision.reason, decision.reason

    assert engine.guard.calls_for("git_add_many") == 3
    limited = engine.evaluate("git_add_many", {"files": ["../escape-3"]})
    assert limited.decision == "rate_limited", limited.reason


def test_the_session_cap_counts_a_refused_list_call(tmp_path: Path) -> None:
    """(a) The second form of the budget: ``max_calls`` counts it too.

    Fails on: **v5 alone** -- the cap is never reached, because a refused
    call costs nothing there.
    Fails on: **v41 alone** -- the refusal names the argument, not the
    element, so the per-element assertion cannot hold.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(max_calls=2), tmp_path)

    for attempt in range(2):
        decision = engine.evaluate("git_add_many", {"files": [f"../escape-{attempt}"]})
        assert decision.decision == "deny"
        assert "files[0]" in decision.reason, decision.reason

    limited = engine.evaluate("git_add_many", {"files": ["../escape-2"]})
    assert limited.decision == "rate_limited", limited.reason


# ---------------------------------------------------------------------------
# (b)  R-04  x  v5:  a refusal that quotes a list element with a separator
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("separator", SEPARATORS)
def test_a_list_violation_with_a_line_separator_still_verifies(
    tmp_path: Path, separator: str
) -> None:
    """(b) A ``files[0]`` violation that names an element with a line separator
    must still leave a verifiable audit log.

    The separator reaches the log **literally**: ``canonical_json`` writes with
    ``ensure_ascii=False``, and the record carries the arguments of the call
    as they were.  The verifier used to split the file with
    ``str.splitlines()``, which breaks on U+2028, U+2029 and U+0085 -- so the
    record was cut in half, the chain never verified again, and because a
    writer verifies the log before it adopts it, **no later session could
    write to that log either**.

    Fails on: **v5 alone** -- the log comes back ``BROKEN``
    (``invalid JSON: Unterminated string``) and no later session may write
    to it.
    Fails on: **v41 alone** -- there is no per-element constraint, so the
    refusal names the argument (``files``) and never ``files[0]``.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    element = f"safe{separator}../../etc/passwd"

    decision = engine.evaluate("git_add_many", {"files": [element]})
    assert decision.decision == "deny"
    assert "files[0]" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [{"arguments": {"files": [element]}, "reason": decision.reason, "decision": "deny"}],
    )

    # The separator really is in the file, in the raw form.
    assert separator.encode("utf-8") in log_path.read_bytes()

    result = verify_log(log_path, key=KEY)
    assert result.status == STATUS_OK, result.reason

    if read_log_lines is None:  # pragma: no cover - the 0.5 branch alone
        pytest.fail("mcp_guard.audit.read_log_lines is missing: this tree has no R-04 fix")
    # No record was cut in half: every non-empty line is still whole JSON.
    lines = [line for line in read_log_lines(log_path) if line.strip()]
    parsed = [json.loads(line) for line in lines]
    assert [record["record_type"] for record in parsed] == ["record", "checkpoint"]
    assert parsed[0]["arguments"]["files"] == [element], "the element was not written whole"


def test_a_map_key_with_a_line_separator_still_verifies(tmp_path: Path) -> None:
    """(b) The same for a map: the key of a refused rename carries the
    separator, and the log of the refusal still verifies.

    Fails on: **v5 alone** -- the log is ``BROKEN``.
    Fails on: **v41 alone** -- a map constraint does not exist there, so the
    refusal never names a key at all.
    """
    sandbox(tmp_path)
    engine = engine_for(map_policy(), tmp_path)
    key = "safe ../../etc/passwd"

    decision = engine.evaluate("git_rename", {"renames": {key: "sandbox/target.txt"}})
    assert decision.decision == "deny"
    assert "key" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [
            {
                "tool_name": "git_rename",
                "arguments": {"renames": {key: "sandbox/target.txt"}},
                "reason": decision.reason,
                "decision": "deny",
            }
        ],
    )

    assert " ".encode("utf-8") in log_path.read_bytes()
    result = verify_log(log_path, key=KEY)
    assert result.status == STATUS_OK, result.reason


def test_a_refused_list_call_can_still_be_appended_to(tmp_path: Path) -> None:
    """(b) A log that carries a separator stays appendable.

    The R-04 fix is not only about ``verify``: a writer *adopts* an existing
    log before it appends, so a broken log also stopped every later session
    from writing to it.

    Fails on: **v5 alone** -- the writer refuses to adopt the log.
    Fails on: **v41 alone** -- the reason never names ``files[0]``.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    element = "safe ../../etc/passwd"
    decision = engine.evaluate("git_add_many", {"files": [element]})
    assert "files[0]" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [{"arguments": {"files": [element]}, "reason": decision.reason, "decision": "deny"}],
    )

    with AuditLog(log_path, "rc61-session-2", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="git_add_many",
            arguments={"files": ["sandbox/ok.txt"]},
            decision="allow",
            reason="allowed by policy",
        )

    result = verify_log(log_path, key=KEY)
    assert result.status == STATUS_OK, result.reason
    assert len(read_records(log_path)) == 2


# ---------------------------------------------------------------------------
# (c)  R-13  x  v5:  a large but legal list is never truncated
# ---------------------------------------------------------------------------


def test_a_large_legal_list_is_forwarded_whole(tmp_path: Path) -> None:
    """(c) A large but legal list argument reaches the upstream **whole**.

    The R-13 bound is on the *line* the upstream writes, not on the argument.
    A list that is large but legal must not be cut short on the way through:
    either the whole list arrives, or the call is refused.  It must never
    arrive truncated, because a truncated path list is a list of paths that
    the policy never looked at.

    Passes on: **v5 alone** -- there is no bound there at all, so nothing can
    truncate the list; the test is the control that shows the bound is not
    what breaks the legal traffic.
    Impossible on: **v41 alone** -- the policy below cannot even be loaded,
    since ``items`` does not exist there, so the large list cannot be
    expressed at all.
    """
    sandbox(tmp_path)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: deny
tools:
  git_add_many:
    action: allow
    arguments:
      files:
        type: array
        required: true
        max_length: 100000
        items:
          type: string
          max_length: 256
          path_prefix: "./sandbox"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    upstream = upstream_script(tmp_path)
    files = [f"sandbox/file-{index:06d}.txt" for index in range(20_000)]

    status, detail, _code = anyio.run(
        lambda: call_over_stdio(
            policy=policy_path,
            upstream=upstream,
            cwd=tmp_path,
            arguments={"files": files},
            extra=("--upstream-timeout", "60"),
        )
    )

    assert status == "ok", detail
    assert len(detail) > 100_000, "the answer was too small to exercise the line buffer"
    assert json.loads(detail) == files, "the list was truncated on the way to the upstream"


def test_the_timeout_record_carries_the_whole_list(tmp_path: Path) -> None:
    """(c) The record of a timed out call carries the list it carried.

    A timeout is evidence, so it goes into the log like any other decision.
    The evidence has to be complete: the arguments of the abandoned call are
    written whole, and the log of a list that carries a separator still
    verifies.

    Fails on: **v5 alone** -- there is no deadline, so the call never ends.
    Fails on: **v41 alone** -- the policy below cannot be loaded, since
    ``items`` does not exist there.
    """
    if UPSTREAM_TIMEOUT_CODE is None:  # pragma: no cover - the 0.5 branch alone
        pytest.fail("mcp_guard.proxy.UPSTREAM_TIMEOUT_CODE is missing: no R-13 fix here")

    class _HangingUpstream:
        async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
            await anyio.sleep_forever()
            raise AssertionError("unreachable")  # pragma: no cover

    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    key_file = write_key_file(tmp_path / "audit.key", KEY.material)
    audit = tmp_path / "audit.jsonl"
    proxy = MCPGuardProxy(
        ProxyConfig(
            upstream_command=[sys.executable, "-c", "pass"],
            policy=engine.policy,
            audit_path=audit,
            audit_key_file=key_file,
            upstream_timeout=0.5,
        )
    )
    proxy._upstream = _HangingUpstream()
    files = [f"sandbox/file-{index}.txt" for index in range(5)]

    class _Params:
        name = "git_add_many"
        arguments = {"files": files}

    ctx = SimpleNamespace(session=None)
    try:
        with pytest.raises(MCPError) as caught:
            anyio.run(
                lambda: proxy._on_call_tool(ctx, _Params())  # type: ignore[arg-type]
            )
    finally:
        proxy.audit.close()  # type: ignore[union-attr]

    assert caught.value.error.code == UPSTREAM_TIMEOUT_CODE
    records = read_records(audit)
    assert records, "the timeout must be recorded"
    assert records[-1]["arguments"]["files"] == files, "the list was truncated in the log"
    assert verify_log(audit, key=KEY).status == STATUS_OK


# ---------------------------------------------------------------------------
# The other 0.4.1 fixes, in front of a v5 constraint
# ---------------------------------------------------------------------------


def test_an_explicit_key_file_beats_the_environment_for_a_list_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-10 x v5: the log of a refused list call is signed with the key the
    operator named, not with the one the environment happened to hold.

    Fails on: **v5 alone** -- the environment overrides the flag, so the log
    is signed with the wrong key and does not verify with the named one.
    Fails on: **v41 alone** -- the refusal never names ``files[0]``.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    decision = engine.evaluate("git_add_many", {"files": ["../escape"]})
    assert "files[0]" in decision.reason, decision.reason

    chosen = write_key_file(tmp_path / "chosen.key", KEY.material)
    other = AuditKey.from_material("other" * 10)
    monkeypatch.setenv("MCP_GUARD_AUDIT_KEY", other.material.hex())

    log_path = tmp_path / "audit.jsonl"
    with AuditLog(log_path, "rc61-session", key_file=chosen, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="git_add_many",
            arguments={"files": ["../escape"]},
            decision="deny",
            reason=decision.reason,
        )

    # The log is signed with the key the operator named, so it verifies with
    # that key -- and not with the one the environment happened to hold.
    result = verify_log(log_path, key=KEY)
    assert result.status == STATUS_OK, result.reason


def test_a_refused_rotation_leaves_a_list_denial_log_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R-06 x v5: a rotation that is refused must not touch the log -- not
    even the log of a refused list call.

    Fails on: **v5 alone** -- the rotation is committed *first* and the usage
    error is reported afterwards, so the log changed.
    Fails on: **v41 alone** -- the refusal never names ``files[0]``.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    decision = engine.evaluate("git_add_many", {"files": ["../escape"]})
    assert "files[0]" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [{"arguments": {"files": ["../escape"]}, "reason": decision.reason, "decision": "deny"}],
    )
    before = log_path.read_bytes()

    key_file = write_key_file(tmp_path / "audit.key", KEY.material)
    new_key = AuditKey.from_material("new" * 10)
    new_key_file = write_key_file(tmp_path / "new.key", new_key.material)
    # The key ring already holds the key the rotation wants to rotate onto,
    # so the rotation must be refused before the log is opened.
    ring = tmp_path / "ring.json"
    ring.write_text(
        json.dumps({KEY.key_id: KEY.material.hex(), new_key.key_id: new_key.material.hex()}),
        encoding="utf-8",
    )
    os.chmod(ring, 0o600)

    code = main(
        [
            "rotate-key",
            "--audit", str(log_path),
            "--new-key-file", str(new_key_file),
            "--audit-key-file", str(key_file),
            "--audit-keyring", str(ring),
        ]
    )

    assert code == EXIT_USAGE, capsys.readouterr().err
    assert log_path.read_bytes() == before, "a refused rotation must not touch the log"
    assert verify_log(log_path, key=KEY).status == STATUS_OK


def test_a_rewritten_separator_in_a_list_denial_log_is_broken(tmp_path: Path) -> None:
    """R-05 x v5: a rewritten record separator is detected -- in the log of a
    refused list call as well.

    Fails on: **v5 alone** -- ``splitlines()`` splits on ``\\r\\n`` just as
    well, so the file verifies ``OK`` and the rewrite is invisible.
    Fails on: **v41 alone** -- the refusal never names ``files[0]``.
    """
    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    decision = engine.evaluate("git_add_many", {"files": ["../escape"]})
    assert "files[0]" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [{"arguments": {"files": ["../escape"]}, "reason": decision.reason, "decision": "deny"}],
    )

    rewritten = log_path.read_bytes().replace(b"\n", b"\r\n")
    assert rewritten != log_path.read_bytes()
    log_path.write_bytes(rewritten)

    result = verify_log(log_path, key=KEY)
    assert result.status == STATUS_BROKEN, result.reason


def test_a_second_writer_is_refused_on_a_list_denial_log(tmp_path: Path) -> None:
    """R-09 x v5: one writer at a time, also for the log of a refused list
    call.  Two writers would both chain from the same tail.

    Fails on: **v5 alone** -- the second writer is accepted and the log is
    corrupted.
    Fails on: **v41 alone** -- the refusal never names ``files[0]``.
    """
    from mcp_guard.audit import AuditError

    sandbox(tmp_path)
    engine = engine_for(list_policy(), tmp_path)
    decision = engine.evaluate("git_add_many", {"files": ["../escape"]})
    assert "files[0]" in decision.reason, decision.reason

    log_path = tmp_path / "audit.jsonl"
    write_records(
        log_path,
        [{"arguments": {"files": ["../escape"]}, "reason": decision.reason, "decision": "deny"}],
    )

    with AuditLog(log_path, "rc61-session", key=KEY, require_keyed=True, warn=False):
        with pytest.raises(AuditError) as caught:
            AuditLog(log_path, "rc61-other", key=KEY, require_keyed=True, warn=False)
    assert "another writer" in str(caught.value), str(caught.value)
    assert verify_log(log_path, key=KEY).status == STATUS_OK


# ---------------------------------------------------------------------------
# positive control
# ---------------------------------------------------------------------------


def test_a_denied_list_call_never_reaches_the_upstream(tmp_path: Path) -> None:
    """Positive control: a call the policy refuses never reaches the upstream.

    The R-13 deadline must not turn a *policy* refusal into a timeout: the
    client is told ``deny`` at once, and the upstream is never asked.  This
    test passes on every branch -- it is the control that shows the timeout
    above is not just a slow path.
    """
    sandbox(tmp_path)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
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
""".strip()
        + "\n",
        encoding="utf-8",
    )
    upstream = upstream_script(tmp_path)

    status, detail, code = anyio.run(
        lambda: call_over_stdio(
            policy=policy_path,
            upstream=upstream,
            cwd=tmp_path,
            arguments={"files": ["../CANARY-ESCAPE-9f3a.txt"]},
            extra=("--upstream-timeout", "30"),
        )
    )

    assert status == "error", detail
    assert "files[0]" in detail, detail
    assert code == -32001, f"{code!r} / {detail}"


# ---------------------------------------------------------------------------
# the version
# ---------------------------------------------------------------------------


def test_the_version_is_one_number_everywhere(capsys: pytest.CaptureFixture[str]) -> None:
    """The version is one number, in the package, in the metadata and on the
    command line.

    Fails on: **v5 alone** -- the version there is ``0.5.0-dev``.
    Fails on: **v41 alone** -- the version there is ``0.4.1``.
    """
    import tomllib

    pyproject = REPO_ROOT / "pyproject.toml"
    document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert document["project"]["version"] == __version__

    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    printed = capsys.readouterr().out.strip()
    assert printed.startswith(f"mcp-guard {__version__}"), printed
    assert __version__ == "1.0.0", __version__

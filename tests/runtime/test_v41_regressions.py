"""The regression tests of the 0.4.1 patch.

Every test in this file reproduces a defect of the 0.4.0 release: it fails on
the unpatched tree and passes on the patched one.  The findings are the ones
of the independent review of v4:

``R-04`` / ``R-05``
    One client-supplied Unicode line separator (U+2028, U+2029, U+0085) inside
    a tool name or an argument value made the whole audit log unverifiable and
    unappendable, and a rewritten record separator still verified ``OK``.
``R-02``
    A call refused for a bad argument consumed no budget, so the argument
    constraints could be probed for free.
``R-06``
    ``rotate-key`` committed the rotation and *then* reported that it had done
    nothing.
``R-09``
    Two writers on one log corrupted it with no diagnostic.
``R-10``
    ``MCP_GUARD_AUDIT_KEY`` silently overrode an explicit ``--audit-key-file``.
``R-13``
    The upstream line buffer was unbounded and an upstream call had no deadline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import mcp_types as types
import pytest
from mcp.shared.exceptions import MCPError

from mcp_guard.audit import (
    STATUS_BROKEN,
    STATUS_OK,
    AuditError,
    AuditLog,
    read_log_lines,
    verify_log,
)
from mcp_guard.cli import EXIT_KEY, EXIT_OK, EXIT_USAGE, main
from mcp_guard.keys import AuditKey, KeyRing, generate_key, write_key_file
from mcp_guard.policy import Policy
from mcp_guard.proxy import UPSTREAM_TIMEOUT_CODE, MCPGuardProxy, ProxyConfig
from mcp_guard import upstream as upstream_module

KEY = AuditKey.from_material("v4" * 16)

#: The three characters that break a log when a record may contain them.
SEPARATORS = [
    pytest.param("\u2028", id="U+2028 LINE SEPARATOR"),
    pytest.param("\u2029", id="U+2029 PARAGRAPH SEPARATOR"),
    pytest.param("\u0085", id="U+0085 NEXT LINE"),
]


def read_records(path: Path) -> list[dict[str, Any]]:
    """The records of a log, read the way the log format says: one per line."""
    return [json.loads(line) for line in read_log_lines(path) if line.strip()]


def write_log(path: Path, key: AuditKey = KEY, count: int = 2) -> Path:
    """A keyed log with ``count`` decision records."""
    with AuditLog(path, "session-1", key=key, require_keyed=True, warn=False) as log:
        for index in range(count):
            log.append(
                method="tools/call",
                tool_name="read_file",
                arguments={"path": f"sandbox/hello-{index}.txt"},
                decision="allow",
                reason="allowed by policy",
                upstream_latency_ms=1.0,
            )
    return path


# ---------------------------------------------------------------------------
# R-04 / R-05  the separators of the record format
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("separator", SEPARATORS)
def test_a_separator_in_an_argument_does_not_break_the_log(
    tmp_path: Path, separator: str
) -> None:
    """R-04: one client-supplied character used to brick the whole log.

    ``canonical_json`` uses ``ensure_ascii=False`` and JSON only requires the
    characters below U+0020 to be escaped, so U+2028, U+2029 and U+0085 are
    written *literally* into the record.  The verifier used to split the file
    with ``str.splitlines()``, which honours all three, so it cut the record in
    half and the chain never verified again -- not even for the next session,
    because a writer verifies the log before it adopts it.
    """
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_file",
            arguments={"note": f"before{separator}after"},
            decision="allow",
            reason="allowed by policy",
        )

    result = verify_log(path, key=KEY)
    assert result.status == STATUS_OK, f"{result.reason}"
    assert result.records == 1


@pytest.mark.parametrize("separator", SEPARATORS)
def test_a_separator_in_the_tool_name_does_not_break_the_log(
    tmp_path: Path, separator: str
) -> None:
    """R-04: the tool name alone is enough, it is echoed into the reason."""
    path = tmp_path / "audit.jsonl"
    tool_name = f"evil{separator}tool"
    with AuditLog(path, "session-1", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name=tool_name,
            arguments={},
            decision="deny",
            reason=f"tool {tool_name!r} is not listed in the policy (default deny)",
        )

    assert verify_log(path, key=KEY).status == STATUS_OK


def test_a_log_with_a_separator_in_it_can_still_be_appended_to(tmp_path: Path) -> None:
    """R-04: the damage was permanent, because a writer verifies the log first."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_file",
            arguments={"note": "a\u2028b"},
            decision="allow",
            reason="allowed by policy",
        )

    with AuditLog(path, "session-2", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_file",
            arguments={},
            decision="allow",
            reason="allowed by policy",
        )

    result = verify_log(path, key=KEY)
    assert result.status == STATUS_OK
    assert result.records == 2


def test_the_verifier_splits_on_newline_only(tmp_path: Path) -> None:
    """R-04: the file is JSONL, so the only line break is ``\\n``."""
    path = tmp_path / "audit.jsonl"
    path.write_text('{"a": 1}\n{"b": "x\u2028y"}\n', encoding="utf-8")

    assert read_log_lines(path) == ['{"a": 1}', '{"b": "x\u2028y"}', ""]


@pytest.mark.parametrize(
    "name, old, new, expected",
    [
        ("LF -> CRLF", "\n", "\r\n", "canonical"),
        ("LF -> vertical tab", "\n", "\x0b", "invalid JSON"),
        ("LF -> form feed", "\n", "\x0c", "invalid JSON"),
        ("LF -> file separator", "\n", "\x1c", "invalid JSON"),
        ("LF -> U+2028", "\n", "\u2028", "invalid JSON"),
    ],
)
def test_a_rewritten_record_separator_is_broken(
    tmp_path: Path, name: str, old: str, new: str, expected: str
) -> None:
    """R-05: rewriting every separator used to verify ``OK`` all the same.

    The chain only covers the records, so a file whose separators were
    rewritten was indistinguishable from an untouched one.  A line that is not
    the canonical encoding of its own record is not a line this writer wrote,
    and a separator that is not a newline at all merges two records into one
    line, which is not valid JSON either.
    """
    path = write_log(tmp_path / "audit.jsonl", count=3)
    original = path.read_bytes()
    rewritten = original.replace(old.encode("utf-8"), new.encode("utf-8"))
    assert rewritten != original, f"{name}: the transform must change the file"
    path.write_bytes(rewritten)

    result = verify_log(path, key=KEY)
    assert result.status == STATUS_BROKEN, f"{name}: {result.reason}"
    assert expected in (result.reason or ""), f"{name}: {result.reason}"


def test_the_content_of_a_record_is_still_protected(tmp_path: Path) -> None:
    """The positive control: the chain does its job for the records themselves."""
    path = write_log(tmp_path / "audit.jsonl", count=1)
    records = read_records(path)
    records[0]["decision"] = "deny"
    path.write_text(
        json.dumps(records[0], sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    assert verify_log(path, key=KEY).status == STATUS_BROKEN


def test_a_control_character_is_still_escaped(tmp_path: Path) -> None:
    """Below U+0020 ``json.dumps`` escapes them, which is why only three bite."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY, require_keyed=True, warn=False) as log:
        log.append(
            method="tools/call",
            tool_name="read_file",
            arguments={"note": "a\x0bb\x0cc\x1cd"},
            decision="allow",
            reason="allowed by policy",
        )

    assert verify_log(path, key=KEY).status == STATUS_OK


# ---------------------------------------------------------------------------
# R-02  a refused call costs budget
# ---------------------------------------------------------------------------


def test_a_refused_call_consumes_the_budget(tmp_path: Path) -> None:
    """R-02: probing the argument constraints must not be free."""
    from mcp_guard.policy import PolicyEngine

    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {
                    "action": "allow",
                    "rate_limit_per_minute": 100,
                    "arguments": {"n": {"type": "integer", "max": 0}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="session-1")

    for _ in range(50):
        assert engine.evaluate("read_file", {"n": 999}).decision == "deny"

    assert engine.guard.total_calls == 50, "a refused attempt costs budget"

    # ...so the probing is throttled like any other use of the tool.
    for _ in range(50):
        assert engine.evaluate("read_file", {"n": 999}).decision == "deny"
    assert engine.evaluate("read_file", {"n": 0}).decision == "rate_limited"


def test_the_state_docstring_agrees_with_the_behaviour() -> None:
    """R-02: the docstring described a behaviour the code did not have.

    It said a refused call consumed budget "because the upstream saw an
    attempt", which is not what happens: the upstream never saw it.  The
    docstring now says what the code does.
    """
    import mcp_guard.state as state_module

    docstring = state_module.__doc__ or ""
    assert "the upstream saw an attempt" not in docstring
    assert "consumes budget" in docstring


# ---------------------------------------------------------------------------
# R-06  a refused rotation touches nothing
# ---------------------------------------------------------------------------


def test_a_refused_rotation_does_not_touch_the_log(tmp_path: Path, capsys) -> None:
    """R-06: the command reported a usage error *after* the rotation.

    An operator whose script treats exit 2 as "nothing happened" had already
    lost the old key, because the rotation record was already in the log.
    """
    audit = tmp_path / "audit.jsonl"
    ring = tmp_path / "ring.json"
    new_key_file = tmp_path / "new.key"
    old, new = generate_key(), generate_key()
    write_key_file(new_key_file, new.material)
    KeyRing().add(old).add(new).save(ring)
    write_log(audit, key=old, count=1)
    before = audit.read_bytes()

    code = main(
        [
            "rotate-key",
            "--audit",
            str(audit),
            "--new-key-file",
            str(new_key_file),
            "--audit-keyring",
            str(ring),
        ]
    )

    assert code == EXIT_USAGE
    assert "already in" in capsys.readouterr().err
    assert audit.read_bytes() == before, "a refused rotation must not write anything"
    assert not any(
        record.get("record_type") == "rotation" for record in read_records(audit)
    )


def test_a_forced_rotation_still_rotates(tmp_path: Path, capsys) -> None:
    """The positive control: ``--force`` is the documented way out."""
    audit = tmp_path / "audit.jsonl"
    ring = tmp_path / "ring.json"
    new_key_file = tmp_path / "new.key"
    old, new = generate_key(), generate_key()
    write_key_file(new_key_file, new.material)
    KeyRing().add(old).add(new).save(ring)
    write_log(audit, key=old, count=1)

    code = main(
        [
            "rotate-key",
            "--audit",
            str(audit),
            "--new-key-file",
            str(new_key_file),
            "--audit-keyring",
            str(ring),
            "--force",
        ]
    )

    assert code == EXIT_OK
    assert any(
        record.get("record_type") == "rotation" for record in read_records(audit)
    )


# ---------------------------------------------------------------------------
# R-09  one writer at a time
# ---------------------------------------------------------------------------


def test_a_second_writer_is_refused(tmp_path: Path) -> None:
    """R-09: two writers on one log corrupted it, with no diagnostic.

    Both writers adopted the same tail and both chained from it, so the second
    record of the file claimed a predecessor the first one had already moved
    past.  The second writer is now refused, cleanly.
    """
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path, "writer-1", key=KEY, require_keyed=True, warn=False)
    try:
        with pytest.raises(AuditError) as caught:
            AuditLog(path, "writer-2", key=KEY, require_keyed=True, warn=False)
        assert "another writer" in str(caught.value)
    finally:
        first.close()

    assert verify_log(path, key=KEY).status == STATUS_OK


def test_the_writer_lock_is_released_when_the_writer_closes(tmp_path: Path) -> None:
    """The lock is held for the writer's lifetime, not for ever."""
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path, "writer-1", key=KEY, require_keyed=True, warn=False)
    first.append(
        method="tools/call", tool_name="read_file", arguments={}, decision="allow", reason="r"
    )
    first.close()

    with AuditLog(path, "writer-2", key=KEY, require_keyed=True, warn=False) as second:
        second.append(
            method="tools/call", tool_name="read_file", arguments={}, decision="allow", reason="r"
        )

    result = verify_log(path, key=KEY)
    assert result.status == STATUS_OK
    assert result.records == 2


# ---------------------------------------------------------------------------
# R-10  an explicit key file beats the environment
# ---------------------------------------------------------------------------


def test_an_explicit_key_file_beats_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """R-10: the operator's explicit choice was ignored, without a word.

    The precedence is the one the README documents: the explicit key file
    first, the environment only as a fallback.
    """
    path = tmp_path / "audit.jsonl"
    key_file = write_key_file(tmp_path / "audit.key", KEY.material)
    write_log(path, key=KEY, count=1)
    monkeypatch.setenv("MCP_GUARD_AUDIT_KEY", generate_key().material.hex())

    code = main(["verify", str(path), "--audit-key-file", str(key_file)])

    assert code == EXIT_OK, capsys.readouterr().out
    assert "HMAC-SHA256 chain intact" in capsys.readouterr().out


def test_the_environment_is_still_the_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The positive control: with no explicit key file the environment is used."""
    path = tmp_path / "audit.jsonl"
    key = generate_key()
    write_log(path, key=key, count=1)
    monkeypatch.setenv("MCP_GUARD_AUDIT_KEY", key.material.hex())

    assert main(["verify", str(path)]) == EXIT_OK


def test_the_environment_alone_still_fails_on_the_wrong_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The positive control: the environment is not ignored, it is a fallback."""
    path = tmp_path / "audit.jsonl"
    write_log(path, key=KEY, count=1)
    monkeypatch.setenv("MCP_GUARD_AUDIT_KEY", generate_key().material.hex())

    assert main(["verify", str(path)]) == EXIT_KEY


# ---------------------------------------------------------------------------
# R-13  a bounded upstream
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_upstream_line_buffer_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """R-13: the buffer grew with every chunk and had no maximum.

    An upstream that never emits a newline could therefore exhaust the memory
    of the proxy.  The line is now capped.

    **The behaviour of the cap changed in 0.5.0rc2 (RC-01).**  In 0.5.0rc1 an
    over-long line raised a ``ValueError`` inside the reader, which cancelled
    the whole proxy and left the client waiting for an answer that never
    came.  The line is now **discarded**: the reader stays alive, the discard
    is counted, and the next line is read normally.  The bound still holds --
    the buffer never grows past it -- but it no longer terminates the proxy.
    """
    monkeypatch.setattr(upstream_module, "MAX_LINE_CHARS", 64)
    send, receive = anyio.create_memory_object_stream[bytes](4)
    upstream = upstream_module.Upstream([sys.executable, "-c", "pass"])
    upstream.process = SimpleNamespace(stdout=receive)
    writer, reader = anyio.create_memory_object_stream(4)

    async with anyio.create_task_group() as group:
        group.start_soon(upstream._stdout_reader, writer)
        await send.send(b"x" * 128)  # no newline at all
        await anyio.sleep(0.2)  # give the reader time to notice the bound
        # The line was discarded, not buffered and not fatal.
        assert upstream.discarded_lines == 1, upstream.discarded_lines
        assert upstream.last_discarded_chars == 128, upstream.last_discarded_chars

        # The reader is still alive: it ends the oversize line and reads the
        # next one as usual.
        await send.send(b"\n")
        await send.send(b'{"jsonrpc": "2.0", "id": 1, "result": {}}\n')
        await anyio.sleep(0.2)
        await send.aclose()

    messages = [item async for item in reader]
    assert len(messages) == 1, messages
    assert upstream.discarded_lines == 1, upstream.discarded_lines


@pytest.mark.anyio
async def test_a_normal_upstream_line_is_still_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive control: a line under the cap is read as before."""
    monkeypatch.setattr(upstream_module, "MAX_LINE_CHARS", 64)
    send, receive = anyio.create_memory_object_stream[bytes](4)
    upstream = upstream_module.Upstream([sys.executable, "-c", "pass"])
    upstream.process = SimpleNamespace(stdout=receive)
    writer, reader = anyio.create_memory_object_stream(4)

    async with anyio.create_task_group() as group:
        group.start_soon(upstream._stdout_reader, writer)
        await send.send(b'{"jsonrpc": "2.0", "id": 1, "result": {}}\n')
        await send.aclose()

    messages = [item async for item in reader]
    assert len(messages) == 1


class _HangingUpstream:
    """An upstream that accepts the call and never answers it."""

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        await anyio.sleep_forever()
        raise AssertionError("unreachable")  # pragma: no cover


@pytest.mark.anyio
async def test_an_upstream_call_has_a_deadline(tmp_path: Path) -> None:
    """R-13: a call without a deadline hangs the client for ever.

    The timeout is evidence, so it is written to the audit log like any other
    decision.
    """
    key_file = write_key_file(tmp_path / "audit.key", KEY.material)
    audit = tmp_path / "audit.jsonl"
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    proxy = MCPGuardProxy(
        ProxyConfig(
            upstream_command=[sys.executable, "-c", "pass"],
            policy=policy,
            audit_path=audit,
            audit_key_file=key_file,
            upstream_timeout=0.2,
        )
    )
    proxy._upstream = _HangingUpstream()
    params = types.CallToolRequestParams(name="read_file", arguments={})

    try:
        with pytest.raises(MCPError) as caught:
            await proxy._on_call_tool(SimpleNamespace(session=None), params)
    finally:
        proxy.audit.close()  # type: ignore[union-attr]

    assert caught.value.error.code == UPSTREAM_TIMEOUT_CODE
    reasons = [record["reason"] for record in read_records(audit)]
    assert any("did not answer" in reason for reason in reasons)


def test_the_upstream_timeout_flag_is_validated(capsys) -> None:
    """A timeout of zero seconds is a configuration mistake, not a request."""
    code = main(
        [
            "run",
            "--policy",
            "does-not-matter.yaml",
            "--upstream-timeout",
            "0",
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )

    assert code == EXIT_USAGE
    assert "upstream-timeout" in capsys.readouterr().err

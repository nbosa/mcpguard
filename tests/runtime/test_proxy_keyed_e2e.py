"""End to end test of the keyed audit log through the real proxy process.

Everything else exercises the audit chain in the library.  This one runs the
shipped ``mcp-guard run`` command, makes real MCP calls through it and checks
the log the process actually wrote.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from .conftest import child_environment, proxy_command
from mcp_guard.audit import verify_log
from mcp_guard.keys import AuditKey, write_key_file

KEY = AuditKey.from_material("d" * 64)
OTHER_KEY = AuditKey.from_material("e" * 64)

POLICY = """
version: 1
default_action: deny
tools:
  read_file:
    action: allow
    arguments:
      path:
        type: string
        required: true
        path_prefix: "./sandbox"
"""


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return path


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    directory = tmp_path / "sandbox"
    directory.mkdir()
    (directory / "hello.txt").write_text("hello from the mcp-guard sandbox", encoding="utf-8")
    return directory


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    return write_key_file(tmp_path / "audit.key", KEY.material)


def start(policy: Path, audit: Path, extra: list[str], cwd: Path) -> subprocess.Popen[str]:
    """Start the shipped proxy, in its own working directory."""
    command = proxy_command(policy, audit, extra)
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=child_environment(),
        cwd=str(cwd),
    )


def send(process: subprocess.Popen[str], message: dict) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen[str]) -> dict:
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, "the proxy closed the connection"
    return json.loads(line)


def initialize(process: subprocess.Popen[str]) -> None:
    send(
        process,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "raw", "version": "1.0"},
            },
        },
    )
    assert receive(process)["result"]["serverInfo"]["name"] == "mcp-guard"
    send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})


def call(process: subprocess.Popen[str], identifier: int, path: str) -> dict:
    send(
        process,
        {
            "jsonrpc": "2.0",
            "id": identifier,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": path}},
        },
    )
    return receive(process)


def test_the_proxy_writes_a_keyed_log_that_verifies(
    policy: Path, sandbox: Path, tmp_path: Path, key_file: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    process = start(
        policy,
        audit,
        ["--audit-key-file", str(key_file), "--audit-checkpoint-interval", "2"],
        tmp_path,
    )
    try:
        initialize(process)
        assert call(process, 2, "sandbox/hello.txt")["result"]["content"][0]["text"] == (
            "hello from the mcp-guard sandbox"
        )
        assert "error" in call(process, 3, "../../etc/passwd")
        # The proxy refuses the path before it is forwarded: the log must not
        # contain the upstream's answer for it.
        time.sleep(0.2)
    finally:
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=30) == 0

    result = verify_log(audit, key_file=key_file)
    assert result.status == "OK"
    assert result.records == 2
    assert result.keyed
    assert result.sealed
    assert result.checkpoints == 2  # one periodic, one for the clean shutdown
    assert result.key_id == KEY.key_id

    text = audit.read_text(encoding="utf-8")
    assert KEY.material.hex() not in text
    assert "d" * 64 not in text
    for record in (json.loads(line) for line in text.splitlines()):
        assert record["key_id"] == KEY.key_id


def test_the_proxy_refuses_to_start_on_a_keyed_log_it_cannot_key(
    policy: Path, tmp_path: Path, key_file: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"not": "a record"}\n', encoding="utf-8")
    process = start(policy, audit, ["--legacy-unkeyed"], tmp_path)
    try:
        _, stderr = process.communicate(timeout=60)
    finally:
        if process.poll() is None:  # pragma: no cover - defensive
            process.kill()
    assert process.returncode == 1
    assert "does not verify" in stderr


def test_the_proxy_refuses_the_wrong_key(
    policy: Path, sandbox: Path, tmp_path: Path, key_file: Path
) -> None:
    """A keyed log cannot be continued with a key the log was not written with."""
    audit = tmp_path / "audit.jsonl"
    first = start(policy, audit, ["--audit-key-file", str(key_file)], tmp_path)
    try:
        initialize(first)
        call(first, 2, "sandbox/hello.txt")
    finally:
        first.send_signal(signal.SIGTERM)
        assert first.wait(timeout=30) == 0

    wrong = write_key_file(tmp_path / "wrong.key", OTHER_KEY.material)
    second = start(policy, audit, ["--audit-key-file", str(wrong)], tmp_path)
    try:
        _, stderr = second.communicate(timeout=60)
    finally:
        if second.poll() is None:  # pragma: no cover - defensive
            second.kill()
    assert second.returncode == 3
    assert KEY.key_id in stderr
    assert OTHER_KEY.material.hex() not in stderr
"""End to end tests: a real client, a real proxy, a real upstream server.

Every test drives a real ``mcp-guard`` process in front of the real
``demo/danger_server.py`` over a stdio pipe, so what is tested is the shipped
behaviour and not a mock of it.
"""

from __future__ import annotations

import json
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest
from mcp.shared.exceptions import MCPError

from .conftest import DEMO_SERVER, child_environment, proxy_command, proxy_session, run_async

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
  run_shell:
    action: deny
    reason: "shell access is not permitted by policy"
  send_email:
    action: allow
    require_approval: true
"""


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    directory = tmp_path / "sandbox"
    directory.mkdir()
    (directory / "hello.txt").write_text("hello from the mcp-guard sandbox", encoding="utf-8")
    return directory


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return path


def test_an_allowed_call_returns_the_file_contents(policy: Path, sandbox: Path, tmp_path: Path) -> None:
    async def main():
        async with proxy_session(policy, base_dir=tmp_path) as session:
            return await session.call_tool("read_file", {"path": "sandbox/hello.txt"})

    result = run_async(main)
    assert result.content[0].text == "hello from the mcp-guard sandbox"
    assert not result.is_error


def test_the_refused_calls_carry_a_stable_error_code(policy: Path, sandbox: Path, tmp_path: Path) -> None:
    """Every refusal is a JSON-RPC error with a stable code and a reason."""

    async def main():
        refusals = {}
        async with proxy_session(policy, base_dir=tmp_path) as session:
            for name, arguments in (
                ("read_file", {"path": "../../etc/passwd"}),
                ("read_file", {"path": "/etc/passwd"}),
                ("read_file", {"path": "sandbox/../../etc/passwd"}),
                ("run_shell", {"cmd": "rm -rf /"}),
                ("send_email", {"to": "a@example.com", "body": "hi"}),
            ):
                with pytest.raises(MCPError) as error:
                    await session.call_tool(name, arguments)
                refusals[name + ":" + str(arguments)] = error.value
        return refusals

    refusals = run_async(main)

    traversal = refusals["read_file:{'path': '../../etc/passwd'}"]
    assert traversal.data["code"] == "deny"
    assert traversal.code == -32001
    assert "path_prefix" in traversal.data["reason"]

    absolute = refusals["read_file:{'path': '/etc/passwd'}"]
    assert absolute.data["code"] == "deny"
    assert "absolute path" in absolute.data["reason"]

    middle = refusals["read_file:{'path': 'sandbox/../../etc/passwd'}"]
    assert middle.data["code"] == "deny"

    shell = refusals["run_shell:{'cmd': 'rm -rf /'}"]
    assert shell.data["code"] == "deny"
    assert shell.data["reason"] == "shell access is not permitted by policy"

    mail = refusals["send_email:{'to': 'a@example.com', 'body': 'hi'}"]
    assert mail.data["code"] == "approval_required"
    assert mail.code == -32002


def test_a_default_deny_policy_refuses_everything(tmp_path: Path, sandbox: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("version: 1\n", encoding="utf-8")

    async def main():
        async with proxy_session(empty, base_dir=tmp_path) as session:
            with pytest.raises(MCPError) as error:
                await session.call_tool("read_file", {"path": "sandbox/hello.txt"})
            return error.value

    error = run_async(main)
    assert error.data["code"] == "deny"
    assert "default deny" in error.data["reason"]


def test_the_audit_log_records_the_allowed_and_the_refused_call(
    policy: Path, sandbox: Path, tmp_path: Path
) -> None:
    audit = tmp_path / "audit.jsonl"

    async def main():
        async with proxy_session(
            policy, audit=audit, extra=["--legacy-unkeyed"], base_dir=tmp_path
        ) as session:
            await session.call_tool("read_file", {"path": "sandbox/hello.txt"})
            with pytest.raises(MCPError):
                await session.call_tool("read_file", {"path": "../../etc/passwd"})

    run_async(main)

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
    calls = [record for record in records if record["method"] == "tools/call"]
    assert len(calls) == 2

    allowed, refused = calls
    assert allowed["tool_name"] == "read_file"
    assert allowed["decision"] == "allow"
    assert allowed["upstream_latency_ms"] is not None
    assert allowed["session_id"]
    assert allowed["arguments"] == {"path": "sandbox/hello.txt"}

    assert refused["decision"] == "deny"
    assert refused["upstream_latency_ms"] is None

    # The whole file is one chain: every record points at its predecessor.
    from mcp_guard.audit import ZERO_HASH, verify_log

    assert verify_log(audit, allow_legacy=True).ok
    previous = ZERO_HASH
    for record in records:
        assert record["prev_hash"] == previous
        previous = record["hash"]


def test_the_session_token_expires(policy: Path, sandbox: Path, tmp_path: Path) -> None:
    async def main():
        async with proxy_session(policy, extra=["--ttl", "1"], base_dir=tmp_path) as session:
            first = await session.call_tool("read_file", {"path": "sandbox/hello.txt"})
            time.sleep(1.2)
            with pytest.raises(MCPError) as error:
                await session.call_tool("read_file", {"path": "sandbox/hello.txt"})
            return first, error.value

    first, error = run_async(main)
    assert first.content[0].text == "hello from the mcp-guard sandbox"
    assert error.data["code"] == "ttl_expired"
    assert error.code == -32004


def test_the_proxy_does_not_open_a_network_connection(
    policy: Path, sandbox: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The proxy may only talk to the upstream over a stdio pipe."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the proxy must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)

    async def main():
        async with proxy_session(policy, base_dir=tmp_path) as session:
            return await session.call_tool("read_file", {"path": "sandbox/hello.txt"})

    result = run_async(main)
    assert result.content[0].text == "hello from the mcp-guard sandbox"


def raw_proxy(policy: Path, tmp_path: Path, audit: Path | None = None) -> subprocess.Popen[str]:
    """Start the proxy as a plain process and talk JSON-RPC to it over stdin."""
    command = proxy_command(policy, audit)
    environment = child_environment()
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        cwd=str(tmp_path),
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


def test_the_proxy_speaks_plain_json_rpc(policy: Path, sandbox: Path, tmp_path: Path) -> None:
    """The proxy is an ordinary stdio JSON-RPC server, not an SDK artefact."""
    process = raw_proxy(policy, tmp_path)
    try:
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
        initialize = receive(process)
        assert initialize["result"]["serverInfo"]["name"] == "mcp-guard"

        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listing = receive(process)
        # run_shell is denied by the policy, so it is not advertised.
        assert [tool["name"] for tool in listing["result"]["tools"]] == ["read_file", "send_email"]

        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "sandbox/hello.txt"},
                },
            },
        )
        call = receive(process)
        assert call["result"]["content"][0]["text"] == "hello from the mcp-guard sandbox"

        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
            },
        )
        refused = receive(process)
        assert refused["error"]["code"] == -32001
        assert refused["error"]["data"]["code"] == "deny"
    finally:
        process.kill()
        process.wait(timeout=10)


def test_the_proxy_terminates_the_upstream_on_sigterm(
    policy: Path, sandbox: Path, tmp_path: Path
) -> None:
    """SIGTERM stops the proxy and reaps the upstream server."""
    if shutil.which("pgrep") is None:  # pragma: no cover - platform dependent
        pytest.skip("pgrep is not available")

    def upstream_processes() -> int:
        result = subprocess.run(
            ["pgrep", "-f", str(DEMO_SERVER)], capture_output=True, text=True, check=False
        )
        return len([line for line in result.stdout.split() if line.strip()])

    process = raw_proxy(policy, tmp_path)
    try:
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
        receive(process)
        assert upstream_processes() >= 1

        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=20) == 0

        deadline = time.time() + 10
        while upstream_processes() and time.time() < deadline:
            time.sleep(0.1)
        assert upstream_processes() == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)

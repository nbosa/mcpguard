#!/usr/bin/env python3
"""The end-to-end smoke test of 0.5.0rc1, through the real proxy.

Every behaviour below is exercised through a **real** ``mcp-guard run``
subprocess over stdio, with a real MCP upstream and a real audit log on disk
that is afterwards verified with the real ``mcp-guard verify-log``.

The five behaviours of the release-candidate checklist:

1. a list-form traversal is **denied** (and the upstream never sees it),
2. a safe list is **allowed**,
3. a tool argument that contains **U+2028** is logged, and the log
   **verifies**,
4. a **refused call is charged to the budget**,
5. an upstream that does not answer is answered with **-32005**.

Usage::

    python rc_smoke.py <source-root> [<work-dir>]

``<source-root>`` is the tree whose ``src/`` holds the ``mcp_guard`` package
under test; ``<work-dir>`` is a scratch directory (default: a temporary one).
Nothing is written outside it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

HERE = Path(__file__).resolve().parent

POLICY = """\
version: 1
default_action: deny

session:
  max_calls: 500

tools:
  git_add_many:
    action: allow
    reason: "list-form staging is confined to the workspace"
    rate_limit_per_minute: 2
    arguments:
      files:
        type: array
        required: true
        max_length: 64
        items:
          type: string
          max_length: 4096
          path_prefix: "./workspace"
  write_note:
    action: allow
    reason: "a free-text note is allowed"
    arguments:
      note:
        type: string
        required: true
        max_length: 4096
"""

UPSTREAM = '''\
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
            types.Tool(name="git_add_many", description="echo the list back",
                       input_schema={"type": "object"}),
            types.Tool(name="write_note", description="echo the note back",
                       input_schema={"type": "object"}),
        ]
    )


async def on_call_tool(ctx, params):
    if MODE == "hang":
        await anyio.sleep_forever()
    name = params.name
    arguments = params.arguments or {}
    if name == "git_add_many":
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(arguments.get("files", [])))]
        )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=str(arguments.get("note", "")))]
    )


async def main():
    server = Server(
        "smoke-upstream", version="1.0.0",
        on_list_tools=on_list_tools, on_call_tool=on_call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
'''

RESULTS: list[tuple[str, str, str]] = []


def record(name: str, expected: str, detail: str) -> None:
    RESULTS.append((name, expected, detail))
    print(f"  {name:<52} {detail}")


def environment(source_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{source_root / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return env


async def call(
    source_root: Path,
    policy: Path,
    upstream: Path,
    work: Path,
    audit: Path | None,
    key_file: Path | None,
    arguments: dict[str, Any],
    tool: str = "git_add_many",
    mode: str | None = None,
    timeout: float = 20.0,
    calls: list[dict[str, Any]] | None = None,
) -> list[tuple[str, str, int | None]]:
    """Run the real proxy and make one call (or several, in ONE session).

    The budget of a tool is per *session*, so a test of the budget needs
    every call in the same proxy run: that is what the ``calls`` argument is
    for.
    """
    command = [
        sys.executable, "-m", "mcp_guard", "run",
        "--policy", str(policy),
        "--upstream-timeout", str(timeout),
    ]
    if audit is not None:
        command += ["--audit", str(audit)]
    if key_file is not None:
        command += ["--audit-key-file", str(key_file)]
    command += ["--", sys.executable, str(upstream)]
    if mode is not None:
        command.append(mode)
    parameters = StdioServerParameters(
        command=command[0], args=command[1:], cwd=str(work), env=environment(source_root)
    )
    out: list[tuple[str, str, int | None]] = []
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            for one in (calls if calls is not None else [arguments]):
                try:
                    result = await session.call_tool(tool, one)
                except MCPError as exc:
                    data: Any = exc.data if isinstance(exc.data, dict) else {}
                    code = getattr(getattr(exc, "error", None), "code", None)
                    out.append(("error", f"{data.get('code', '')}: {exc.message}", code))
                    continue
                text = "".join(
                    block.text for block in result.content if getattr(block, "type", None) == "text"
                )
                out.append(("ok", text, None))
    return out


def verify(source_root: Path, audit: Path, key_file: Path) -> tuple[int, str]:
    result = subprocess.run(
        [
            sys.executable, "-m", "mcp_guard", "verify-log",
            str(audit), "--audit-key-file", str(key_file),
        ],
        capture_output=True, text=True, env=environment(source_root), cwd=str(audit.parent),
    )
    return result.returncode, (result.stdout + result.stderr).strip()


async def main() -> int:
    source_root = Path(sys.argv[1]).resolve()
    work = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(tempfile.mkdtemp(prefix="rc61-smoke-"))
    work.mkdir(parents=True, exist_ok=True)
    (work / "workspace").mkdir(exist_ok=True)
    (work / "workspace" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (work / "policy.yaml").write_text(POLICY, encoding="utf-8")
    upstream = work / "smoke_upstream.py"
    upstream.write_text(UPSTREAM, encoding="utf-8")
    policy = work / "policy.yaml"

    # 0.4 and later require a keyed audit log: the key never leaves this
    # directory and is never printed.
    key_file = work / "audit.key"
    subprocess.run(
        [sys.executable, "-m", "mcp_guard", "keygen", "--out", str(key_file)],
        check=True, capture_output=True, env=environment(source_root), cwd=str(work),
    )

    print(f"mcp-guard under test : {source_root}")
    print(f"work directory        : {work}")
    print(f"python                : {sys.executable}")
    print()

    # -- 1. a list-form traversal is denied -------------------------------
    (status, detail, code) = (await call(
        source_root, policy, upstream, work, None, None,
        {"files": ["workspace/app.py", "../CANARY-ESCAPE-9f3a.txt"]},
    ))[0]
    ok = status == "error" and code == -32001 and "files[1]" in detail
    record(
        "1. list-form traversal denied",
        "error / -32001 / names files[1]",
        ("OK  " if ok else "FAIL") + f"  status={status} code={code} :: {detail[:150]}",
    )

    # -- 2. a safe list is allowed ----------------------------------------
    (status, detail, code) = (await call(
        source_root, policy, upstream, work, None, None,
        {"files": ["workspace/app.py"]},
    ))[0]
    ok = status == "ok" and json.loads(detail) == ["workspace/app.py"]
    record(
        "2. safe list allowed",
        "ok / the upstream receives the list",
        ("OK  " if ok else "FAIL") + f"  status={status} :: {detail[:150]}",
    )

    # -- 3. a U+2028 argument is logged, and the log verifies --------------
    audit = work / "audit.jsonl"
    separator = " "
    note = f"before{separator}after"
    (status, detail, code) = (await call(
        source_root, policy, upstream, work, audit, key_file,
        {"note": note}, tool="write_note",
    ))[0]
    raw = audit.read_bytes() if audit.exists() else b""
    has_separator = separator.encode("utf-8") in raw
    exit_code, verdict = verify(source_root, audit, key_file)
    ok = status == "ok" and has_separator and exit_code == 0
    record(
        "3. U+2028 argument logged, verify-log OK",
        "ok / the separator is in the log / verify exit 0",
        ("OK  " if ok else "FAIL")
        + f"  status={status} separator_in_log={has_separator} verify_exit={exit_code} :: {verdict[:110]}",
    )

    # -- 4. a refused call is charged to the budget ------------------------
    budget_audit = work / "budget.jsonl"
    policy_budget = work / "policy-budget.yaml"
    policy_budget.write_text(
        POLICY.replace("rate_limit_per_minute: 2", "rate_limit_per_minute: 1"),
        encoding="utf-8",
    )
    # Both calls in ONE proxy run: the budget of a tool is per session, and
    # the point of the test is that the *refused* call is the one that spends
    # it.
    outcomes = await call(
        source_root, policy_budget, upstream, work, budget_audit, key_file,
        {},
        calls=[
            {"files": ["../CANARY-ESCAPE-9f3a.txt"]},
            {"files": ["workspace/app.py"]},
        ],
    )
    (_s1, _d1, refused_code) = outcomes[0]
    (_s2, detail2, code2) = outcomes[1]
    ok = refused_code == -32001 and code2 == -32003
    record(
        "4. a refused call is charged to the budget",
        "the refusal is -32001, the next call is -32003 (rate limited)",
        ("OK  " if ok else "FAIL")
        + f"  refusal={refused_code} next={code2} :: {detail2[:110]}",
    )

    # -- 5. an upstream that does not answer -> -32005 --------------------
    (status, detail, code) = (await call(
        source_root, policy, upstream, work, None, None,
        {"files": ["workspace/app.py"]}, mode="hang", timeout=5.0,
    ))[0]
    ok = status == "error" and code == -32005
    record(
        "5. an upstream that never answers -> -32005",
        "error / -32005",
        ("OK  " if ok else "FAIL") + f"  status={status} code={code} :: {detail[:150]}",
    )

    print()
    failed = [name for name, _expected, detail in RESULTS if detail.startswith("FAIL")]
    print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} behaviours behaved as documented")
    if failed:
        for name in failed:
            print(f"  FAILED: {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(anyio.run(main))

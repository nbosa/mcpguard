#!/usr/bin/env python3
"""The end-to-end proof of TASK #55, through the real proxy.

The same call, the same upstream server, two guards:

* the **0.4** guard (the pristine v4 tree in /tmp/mg55-baseline) with the
  constraint v4 can express -- the type and the length of the list -- allows
  the traversal through to the server;
* the **0.5** guard (src-copy) with the per-element constraint refuses it.

Usage:  python e2e.py <src-root> <policy-file> <label>
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

SERVER = Path(__file__).resolve().parent / "git_server.py"


async def call(source_root: Path, policy: Path, arguments: dict[str, Any]) -> tuple[str, str]:
    command = [
        sys.executable, "-m", "mcp_guard", "run", "--policy", str(policy),
        "--", sys.executable, str(SERVER),
    ]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{source_root / 'src'}{os.pathsep}{environment.get('PYTHONPATH', '')}"
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(Path(__file__).resolve().parent),
        env=environment,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            try:
                result = await session.call_tool("git_add_many", arguments)
            except MCPError as exc:
                data: Any = exc.data if isinstance(exc.data, dict) else {}
                return "error", f"{data.get('code', '')}: {exc.message}"
            text = "".join(
                block.text for block in result.content if getattr(block, "type", None) == "text"
            )
            return "ok", text


async def main() -> int:
    source_root = Path(sys.argv[1])
    policy = Path(sys.argv[2])
    label = sys.argv[3]
    print(f"--- {label} (guard: {source_root}) ---")
    cases = [
        ("traversal in a list", {"files": ["../CANARY-ESCAPE-9f3a.txt"]}),
        ("safe list", {"files": ["cases/workspace/repo-a/src/app.py", "cases/workspace/repo-a/README.md"]}),
        ("traversal as the second element", {"files": ["cases/workspace/repo-a/src/app.py", "../CANARY-ESCAPE-9f3a.txt"]}),
        ("wrong type in a list", {"files": ["cases/workspace/repo-a/src/app.py", 42]}),
    ]
    for title, arguments in cases:
        status, detail = await call(source_root, policy, arguments)
        print(f"  {title:<32} {status:<6} {detail}")
    return 0


if __name__ == "__main__":
    anyio.run(main)

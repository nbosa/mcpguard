#!/usr/bin/env python3
"""A tiny MCP client that drives the mcp-guard demo.

It starts the proxy in front of ``demo/danger_server.py``, performs one
MCP operation against it and prints the result in a stable, greppable format::

    STATUS: ok
    CONTENT: hello from the mcp-guard sandbox

    STATUS: error
    ERROR_CODE: deny
    ERROR_MESSAGE: deny: argument 'path' violates path_prefix ...

Run it from the root of the repository.  An audit log needs a key, or the
explicit ``--legacy-unkeyed`` that asks for the old unkeyed chain -- the demo
asks for it so its output stays reproducible::

    python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl \
        --legacy-unkeyed --tool read_file --args '{"path": "demo/sandbox/hello.txt"}'

    # what a real deployment does instead:
    python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl \
        --audit-key-file /tmp/demo-audit.key \
        --tool read_file --args '{"path": "demo/sandbox/hello.txt"}'
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = REPO_ROOT / "src"
DANGER_SERVER = REPO_ROOT / "demo" / "danger_server.py"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Drive the mcp-guard demo.")
    parser.add_argument("--policy", default="demo/policy.yaml", help="policy file handed to the proxy")
    parser.add_argument("--audit", default="demo/audit.jsonl", help="audit log written by the proxy")
    parser.add_argument(
        "--audit-key-file",
        default=None,
        help="audit chain key for the proxy; without it the proxy refuses to write an audit log",
    )
    parser.add_argument(
        "--legacy-unkeyed",
        action="store_true",
        help="write the legacy unkeyed chain: it detects an edited file, not a rewritten one",
    )
    parser.add_argument("--tool", default=None, help="name of the tool to call")
    parser.add_argument("--args", default="{}", help="JSON object with the arguments of the tool call")
    parser.add_argument("--list", action="store_true", help="list the tools the client is allowed to see")
    return parser


def proxy_command(
    policy: str, audit: str | None, key_file: str | None = None, legacy: bool = False
) -> list[str]:
    """The command line of the proxy, including the upstream server."""
    command = [sys.executable, "-m", "mcp_guard", "run", "--policy", policy]
    if audit:
        command += ["--audit", audit]
    if key_file:
        command += ["--audit-key-file", key_file]
    if legacy:
        command += ["--legacy-unkeyed"]
    command += ["--", sys.executable, str(DANGER_SERVER)]
    return command


def child_environment() -> dict[str, str]:
    """The environment of the proxy: the source tree is importable without an install."""
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{SOURCE_ROOT}{os.pathsep}{existing}" if existing else str(SOURCE_ROOT)
    )
    return environment


async def run(options: argparse.Namespace) -> int:
    command = proxy_command(options.policy, options.audit, options.audit_key_file, options.legacy_unkeyed)
    parameters = StdioServerParameters(
        command=command[0],
        args=command[1:],
        cwd=str(REPO_ROOT),
        env=child_environment(),
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            if options.list:
                result = await session.list_tools()
                print("TOOLS: " + ", ".join(tool.name for tool in result.tools))
                return 0
            arguments = json.loads(options.args)
            try:
                result = await session.call_tool(options.tool, arguments)
            except MCPError as exc:
                data: Any = exc.data if isinstance(exc.data, dict) else {}
                print("STATUS: error")
                print("ERROR_CODE: " + str(data.get("code", "")))
                print("ERROR_MESSAGE: " + exc.message)
                return 0
            print("STATUS: ok")
            for block in result.content:
                if getattr(block, "type", None) == "text":
                    print("CONTENT: " + block.text)
            return 0


def main() -> int:
    options = build_parser().parse_args()
    return anyio.run(run, options)


if __name__ == "__main__":
    sys.exit(main())

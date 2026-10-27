#!/usr/bin/env python3
"""A list-taking MCP server for the end-to-end proof of TASK #55.

It exposes one tool, ``git_add_many(files=[...])``, and echoes the files it
was given.  It is the upstream of the end-to-end run: if the proxy allows the
call, the traversal reaches this server, which is the whole point.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

TOOLS: list[types.Tool] = [
    types.Tool(
        name="git_add_many",
        description="Stage several files into the repository index.",
        input_schema={
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The files to stage.",
                }
            },
            "required": ["files"],
        },
    ),
]


async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    files = (params.arguments or {}).get("files", [])
    return types.CallToolResult(
        content=[types.TextContent(type="text", text="staged: " + json.dumps(files))]
    )


async def main() -> int:
    server = Server(
        "git-server",
        version="1.0.0",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(anyio.run(main))
    except (KeyboardInterrupt, BrokenPipeError):
        sys.exit(0)

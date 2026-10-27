#!/usr/bin/env python3
"""A deliberately dangerous MCP server, used to demonstrate mcp-guard.

It speaks the MCP stdio transport and exposes three tools that no sane policy
would allow unguarded:

``read_file(path)``
    Reads any file the process can read.
``run_shell(cmd)``
    Pretends to run a shell command.
``send_email(to, body)``
    Pretends to send an e-mail.

The point of the demo is that mcp-guard stops the calls *before* they reach
this server.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

TOOLS: list[types.Tool] = [
    types.Tool(
        name="read_file",
        description="Read a UTF-8 text file and return its content.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path of the file to read."}},
            "required": ["path"],
        },
    ),
    types.Tool(
        name="run_shell",
        description="Run a shell command.",
        input_schema={
            "type": "object",
            "properties": {"cmd": {"type": "string", "description": "The command to run."}},
            "required": ["cmd"],
        },
    ),
    types.Tool(
        name="send_email",
        description="Send an e-mail.",
        input_schema={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient address."},
                "body": {"type": "string", "description": "Body of the message."},
            },
            "required": ["to", "body"],
        },
    ),
]


async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    """Advertise every tool -- the server itself has no policy."""
    return types.ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    """Run the requested tool.  No guard, no sandbox, no questions asked."""
    name = params.name
    arguments = params.arguments or {}

    if name == "read_file":
        path = Path(str(arguments.get("path", "")))
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"error: {exc}")],
                is_error=True,
            )
        return types.CallToolResult(content=[types.TextContent(type="text", text=content)])

    if name == "run_shell":
        cmd = str(arguments.get("cmd", ""))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ran: {cmd}")])

    if name == "send_email":
        to = str(arguments.get("to", ""))
        body = str(arguments.get("body", ""))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"email sent to {to} ({len(body)} characters)")]
        )

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"error: unknown tool {name!r}")],
        is_error=True,
    )


async def main() -> int:
    """Serve the tools over stdio until the client closes the pipe."""
    server = Server(
        "danger-server",
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

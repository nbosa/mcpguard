"""Normalised representation of "what is being checked".

The CLI accepts several transcript shapes; :meth:`CheckRequest.from_dict` accepts
all of them and normalises into the three canonical buckets:

* ``calls``   - agent -> tool invocations (arguments are the interesting part)
* ``results`` - tool -> agent payloads (the injection surface)
* ``transcript`` - free-form conversational text
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ToolCall", "ToolResult", "CheckRequest", "LOCAL_PATH_METADATA_KEYS"]

#: Metadata keys that name a local file.
#:
#: These are honoured only when they arrive through the operator channel
#: (:attr:`CheckRequest.trusted`), never when they come out of a transcript
#: document.  A transcript is untrusted input; letting it name a path would
#: turn "scan this transcript" into "read this file and print it back"
#: (AUD-14).
LOCAL_PATH_METADATA_KEYS: tuple[str, ...] = ("etdi_path", "pins_path")


@dataclass
class ToolCall:
    """A single tool invocation requested by the agent."""

    server: str = ""
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    raw_arguments: str = ""

    @property
    def qualified(self) -> str:
        """``server.tool`` identifier (falls back to the bare tool name)."""
        if self.server and self.tool:
            return f"{self.server}.{self.tool}"
        return self.tool or self.server

    def arguments_text(self) -> str:
        """Serialised arguments, used for text scanning."""
        if self.raw_arguments:
            return self.raw_arguments
        if isinstance(self.arguments, dict):
            try:
                return json.dumps(self.arguments, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                return str(self.arguments)
        return str(self.arguments)

    def argument_items(self) -> list[tuple[str, str]]:
        """Flatten arguments into ``(key, value)`` pairs of string values."""
        items: list[tuple[str, str]] = []

        def walk(node: Any, path: str) -> None:
            if isinstance(node, str):
                items.append((path, node))
            elif isinstance(node, dict):
                for key, item in node.items():
                    walk(item, str(key) if not path else f"{path}.{key}")
            elif isinstance(node, (list, tuple)):
                for index, item in enumerate(node):
                    walk(item, f"{path}[{index}]" if path else f"[{index}]")
            elif node is not None and not isinstance(node, (bool, int, float)):
                items.append((path, str(node)))

        walk(self.arguments, "")
        return items

    def argument_strings(self) -> list[str]:
        """Flatten arguments into the individual string values they contain."""
        return [value for _key, value in self.argument_items()]


@dataclass
class ToolResult:
    """A payload returned by a tool server to the agent."""

    server: str = ""
    tool: str = ""
    content: str = ""
    call_id: str = ""
    is_error: bool = False

    @property
    def qualified(self) -> str:
        if self.server and self.tool:
            return f"{self.server}.{self.tool}"
        return self.tool or self.server


@dataclass
class CheckRequest:
    """Everything a guard run may inspect."""

    agent: str = ""
    calls: list[ToolCall] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)
    transcript: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    trusted: dict[str, Any] = field(default_factory=dict)
    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "CheckRequest":
        """Build a request from a transcript document.

        Accepted document shapes::

            {"agent": "...", "calls": [...], "results": [...], "transcript": "..."}
            {"agent": "...", "tool_calls": [...], "tool_results": [...], "messages": [...]}

        The document is **untrusted input**.  Keys that name a local file are
        quarantined: a transcript is allowed to carry data, but it is never
        allowed to name a path that the scanner will open (AUD-14).
        """
        if not isinstance(doc, dict):
            raise ValueError("transcript document must be a JSON object")

        request = cls(
            agent=str(doc.get("agent", "") or ""),
            transcript=str(doc.get("transcript", "") or ""),
        )

        raw_calls = doc.get("calls") or doc.get("tool_calls") or []
        if isinstance(raw_calls, dict):
            raw_calls = [raw_calls]
        for item in raw_calls or []:
            if not isinstance(item, dict):
                continue
            arguments = item.get("arguments")
            if arguments is None:
                arguments = item.get("input") or item.get("params") or {}
            raw_arg_str = str(item.get("raw_arguments", "") or "")
            if not arguments and raw_arg_str:
                try:
                    parsed = json.loads(raw_arg_str)
                    if isinstance(parsed, dict):
                        arguments = parsed
                    else:
                        arguments = {"raw": raw_arg_str}
                except Exception:
                    arguments = {"raw": raw_arg_str}
            request.calls.append(
                ToolCall(
                    server=str(item.get("server", "") or ""),
                    tool=str(item.get("tool", item.get("name", "")) or ""),
                    arguments=arguments if isinstance(arguments, dict) else {"value": arguments},
                    call_id=str(item.get("id", item.get("call_id", "")) or ""),
                    raw_arguments=str(item.get("raw_arguments", "") or ""),
                )
            )

        raw_results = doc.get("results") or doc.get("tool_results") or []
        if isinstance(raw_results, dict):
            raw_results = [raw_results]
        for item in raw_results or []:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if content is None:
                content = item.get("text", item.get("output", ""))
            if isinstance(content, (dict, list)):
                content = json.dumps(content, ensure_ascii=False, sort_keys=True)
            request.results.append(
                ToolResult(
                    server=str(item.get("server", "") or ""),
                    tool=str(item.get("tool", item.get("name", "")) or ""),
                    content=str(content or ""),
                    call_id=str(item.get("id", item.get("call_id", "")) or ""),
                    is_error=bool(item.get("is_error", False)),
                )
            )

        messages = doc.get("messages") or []
        if isinstance(messages, list) and not request.transcript:
            chunks: list[str] = []
            for message in messages:
                if isinstance(message, dict):
                    role = message.get("role", "")
                    content = message.get("content", "")
                    if isinstance(content, (dict, list)):
                        content = json.dumps(content, ensure_ascii=False)
                    chunks.append(f"[{role}] {content}")
                else:
                    chunks.append(str(message))
            request.transcript = "\n".join(chunks)

        metadata = doc.get("metadata") or {}
        if isinstance(metadata, dict):
            request.metadata.update(metadata)

        for key in ("etdi", "etdi_path", "pins", "pins_path", "egress_tools"):
            if key in doc and key not in request.metadata:
                request.metadata[key] = doc[key]

        # Quarantine the keys that name a local file.  A transcript is data,
        # not configuration: if it could name a path, scanning an untrusted
        # transcript would read whatever that path points at and report the
        # contents back to whoever supplied the transcript (AUD-14).  The
        # operator channel -- ``CheckRequest.trusted`` -- is the only place a
        # path may come from.
        for key in LOCAL_PATH_METADATA_KEYS:
            if key in request.metadata:
                request.metadata.pop(key)

        return request

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "calls": [
                {
                    "server": call.server,
                    "tool": call.tool,
                    "arguments": call.arguments,
                    "call_id": call.call_id,
                }
                for call in self.calls
            ],
            "results": [
                {
                    "server": result.server,
                    "tool": result.tool,
                    "content": result.content,
                    "call_id": result.call_id,
                    "is_error": result.is_error,
                }
                for result in self.results
            ],
            "transcript": self.transcript,
            "metadata": dict(self.metadata),
        }

"""ETDI (Extended Tool Description & Integrity) document handling.

ETDI is the tool-description format mcp-guard pins. A document looks like::

    {
      "etdi": "1.0",
      "server": {"name": "fs", "version": "1.4.0"},
      "tools": [
        {
          "name": "read_file",
          "description": "Read a file from the workspace",
          "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
          }
        }
      ]
    }

The module validates the document and derives the digests used by the pin
manifest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .textutil import canonical_json, sha256_hex

__all__ = [
    "ETDI_VERSION",
    "EtdiTool",
    "EtdiDocument",
    "parse_etdi",
    "validate_etdi",
    "tool_digests",
    "tool_parameters",
]

#: Supported ETDI document version.
ETDI_VERSION = "1.0"

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")
_MAX_DESCRIPTION = 4096


@dataclass(frozen=True)
class EtdiTool:
    """A single tool descriptor inside an ETDI document."""

    name: str
    description: str = ""
    title: str = ""
    version: str = ""
    server: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def qualified(self) -> str:
        if self.server and self.name:
            return f"{self.server}.{self.name}"
        return self.name


@dataclass(frozen=True)
class EtdiDocument:
    """A validated ETDI document."""

    version: str
    server: Mapping[str, Any]
    tools: tuple[EtdiTool, ...]
    raw: Mapping[str, Any] = field(default_factory=dict)

    def tool_names(self) -> tuple[str, ...]:
        return tuple(tool.qualified for tool in self.tools)


def tool_parameters(schema: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Flatten a JSON-Schema-ish input schema into parameter descriptors."""
    parameters: list[dict[str, Any]] = []
    if not isinstance(schema, Mapping):
        return parameters
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return parameters
    required = schema.get("required")
    required_set = set(required) if isinstance(required, (list, tuple)) else set()
    for name, spec in properties.items():
        entry: dict[str, Any] = {"name": str(name), "type": "any", "required": name in required_set}
        if isinstance(spec, Mapping):
            raw_type = spec.get("type", "any")
            if isinstance(raw_type, list):
                entry["type"] = "|".join(str(item) for item in raw_type)
            else:
                entry["type"] = str(raw_type)
            if "enum" in spec:
                entry["enum"] = list(spec.get("enum") or [])
            if "default" in spec:
                entry["default"] = spec.get("default")
            entry["description"] = str(spec.get("description", "") or "")
        parameters.append(entry)
    parameters.sort(key=lambda item: item["name"])
    return parameters


def tool_digests(tool: EtdiTool) -> dict[str, str]:
    """Compute the digest set used for pinning a tool."""
    description = tool.description or ""
    schema = dict(tool.input_schema or {})
    return {
        "description_sha256": sha256_hex(description),
        "schema_sha256": sha256_hex(canonical_json(schema)),
        "tool_sha256": sha256_hex(
            canonical_json(
                {
                    "name": tool.name,
                    "description": description,
                    "inputSchema": schema,
                }
            )
        ),
    }


def validate_etdi(doc: Any) -> list[str]:
    """Validate an ETDI document, returning a list of human readable errors."""
    errors: list[str] = []
    if not isinstance(doc, Mapping):
        return ["ETDI document must be a JSON object"]

    version = doc.get("etdi")
    if version is None:
        errors.append("missing required field 'etdi'")
    elif not isinstance(version, str) or not _VERSION_RE.match(version):
        errors.append(f"'etdi' must be a dotted version string, got {version!r}")
    elif version != ETDI_VERSION:
        errors.append(f"unsupported ETDI version {version!r} (supported: {ETDI_VERSION})")

    server = doc.get("server")
    if server is not None and not isinstance(server, Mapping):
        errors.append("'server' must be an object when present")
    elif isinstance(server, Mapping):
        server_name = server.get("name")
        if server_name is not None and not isinstance(server_name, str):
            errors.append("'server.name' must be a string")
        server_version = server.get("version")
        if server_version is not None and not isinstance(server_version, str):
            errors.append("'server.version' must be a string")

    tools = doc.get("tools")
    if tools is None:
        errors.append("missing required field 'tools'")
    elif not isinstance(tools, list):
        errors.append("'tools' must be an array")
    else:
        if not tools:
            errors.append("'tools' must not be empty")
        seen: set[str] = set()
        for index, tool in enumerate(tools):
            label = f"tools[{index}]"
            if not isinstance(tool, Mapping):
                errors.append(f"{label} must be an object")
                continue
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                errors.append(f"{label}.name is required and must be a string")
            elif not _TOOL_NAME_RE.match(name):
                errors.append(f"{label}.name '{name}' contains illegal characters")
            elif name in seen:
                errors.append(f"{label}.name '{name}' is duplicated")
            else:
                seen.add(name)
            description = tool.get("description", "")
            if description is None:
                description = ""
            if not isinstance(description, str):
                errors.append(f"{label}.description must be a string")
            elif len(description) > _MAX_DESCRIPTION:
                errors.append(
                    f"{label}.description exceeds {_MAX_DESCRIPTION} characters"
                )
            schema = tool.get("inputSchema")
            if schema is not None:
                if not isinstance(schema, Mapping):
                    errors.append(f"{label}.inputSchema must be an object")
                else:
                    schema_type = schema.get("type", "object")
                    if schema_type != "object":
                        errors.append(f"{label}.inputSchema.type must be 'object'")
                    properties = schema.get("properties")
                    if properties is not None and not isinstance(properties, Mapping):
                        errors.append(f"{label}.inputSchema.properties must be an object")
                    required = schema.get("required")
                    if required is not None:
                        if not isinstance(required, list):
                            errors.append(f"{label}.inputSchema.required must be an array")
                        else:
                            if isinstance(properties, Mapping):
                                for item in required:
                                    if not isinstance(item, str):
                                        errors.append(
                                            f"{label}.inputSchema.required entries must be strings"
                                        )
                                        break
                                    if item not in properties:
                                        errors.append(
                                            f"{label}.inputSchema.required references unknown "
                                            f"property '{item}'"
                                        )
    return errors


def parse_etdi(doc: Any) -> tuple[EtdiDocument | None, list[str]]:
    """Parse and validate an ETDI document.

    Returns:
        ``(document, errors)``. ``document`` is ``None`` when the document is
        unusable; ``errors`` is empty on success.
    """
    errors = validate_etdi(doc)
    if errors or not isinstance(doc, Mapping):
        return None, errors

    server_block = doc.get("server") or {}
    server_name = str(server_block.get("name", "") or "") if isinstance(server_block, Mapping) else ""

    tools: list[EtdiTool] = []
    for raw_tool in doc.get("tools") or []:
        schema = raw_tool.get("inputSchema") or {}
        required = schema.get("required") if isinstance(schema, Mapping) else None
        tools.append(
            EtdiTool(
                name=str(raw_tool.get("name", "")),
                description=str(raw_tool.get("description", "") or ""),
                title=str(raw_tool.get("title", "") or ""),
                version=str(raw_tool.get("version", "") or ""),
                server=server_name,
                input_schema=dict(schema) if isinstance(schema, Mapping) else {},
                required=tuple(required) if isinstance(required, list) else (),
                raw=dict(raw_tool),
            )
        )

    document = EtdiDocument(
        version=str(doc.get("etdi", ETDI_VERSION)),
        server=dict(server_block) if isinstance(server_block, Mapping) else {},
        tools=tuple(tools),
        raw=dict(doc),
    )
    return document, []

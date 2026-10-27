"""ETDI pin manifest: build, load, save and verify.

The pin manifest is the frozen fingerprint of a tool surface. It is what makes
"the tool description changed under us" a detectable, auditable event instead of
a silent trust downgrade.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .etdi import ETDI_VERSION, EtdiDocument, parse_etdi, tool_digests, tool_parameters
from .textutil import canonical_json, sha256_hex

__all__ = [
    "PIN_MANIFEST_VERSION",
    "build_pin_manifest",
    "verify_pin_manifest",
    "load_pin_manifest",
    "save_pin_manifest",
    "manifest_digest",
]

#: Version of the pin manifest container format.
PIN_MANIFEST_VERSION = "1.0"


def _tool_entry(document: EtdiDocument, tool) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "server": tool.server,
        "tool": tool.name,
        "name": tool.name,
        "description": tool.description,
        "required": list(tool.required),
        "parameters": tool_parameters(tool.input_schema),
        "schema": dict(tool.input_schema),
    }
    entry.update(tool_digests(tool))
    return entry


def build_pin_manifest(
    etdi_doc: Any,
    *,
    generated_at: str = "",
    generator: str = "mcp-guard",
) -> dict[str, Any]:
    """Build a pin manifest from an ETDI document.

    Raises:
        ValueError: when the ETDI document is invalid.
    """
    document, errors = parse_etdi(etdi_doc)
    if document is None or errors:
        raise ValueError("invalid ETDI document: " + "; ".join(errors))

    tools = sorted(
        (_tool_entry(document, tool) for tool in document.tools),
        key=lambda item: (item.get("server", ""), item.get("tool", "")),
    )
    manifest: dict[str, Any] = {
        "manifest_version": PIN_MANIFEST_VERSION,
        "etdi_version": document.version or ETDI_VERSION,
        "generator": generator,
        "generated_at": generated_at,
        "server": dict(document.server),
        "tools": tools,
    }
    manifest["manifest_sha256"] = manifest_digest(manifest)
    return manifest


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Digest over the pinned surface of a manifest.

    The digest covers the *whole* pinned surface, not just the tool list: the
    server block, the ETDI version and the manifest format version are all
    part of what was pinned.  A digest that only covered the tools would let
    an attacker swap the server identity -- or the ETDI version the tools are
    interpreted under -- without invalidating the pin (AUD-16).

    The tool entries are sorted by their canonical serialisation, so the
    digest is stable when the entries are reordered (AUD-17).
    """
    tools = sorted(
        (dict(entry) for entry in (manifest.get("tools") or [])),
        key=canonical_json,
    )
    payload = {
        "manifest_version": str(manifest.get("manifest_version", "") or ""),
        "etdi_version": str(manifest.get("etdi_version", "") or ""),
        "server": dict(manifest.get("server") or {}),
        "tools": tools,
    }
    return sha256_hex(canonical_json(payload))


def load_pin_manifest(path: str | Path) -> dict[str, Any]:
    """Load a pin manifest from disk."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"pin manifest {file_path} must contain a JSON object")
    return data


def save_pin_manifest(manifest: Mapping[str, Any], path: str | Path) -> Path:
    """Write a pin manifest to disk (deterministic, sorted keys)."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return file_path


def _index_manifest(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("tools") or []:
        if not isinstance(entry, Mapping):
            continue
        server = str(entry.get("server", "") or "")
        tool = str(entry.get("tool", entry.get("name", "")) or "")
        key = f"{server}.{tool}" if server else tool
        index[key] = dict(entry)
    return index


def _index_document(document: EtdiDocument) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for tool in document.tools:
        entry = _tool_entry(document, tool)
        index[tool.qualified] = entry
    return index


def _server_changes(manifest: Mapping[str, Any], document: EtdiDocument) -> list[dict[str, Any]]:
    """Describe the drift between the pinned server block and the live one."""
    pinned = manifest.get("server")
    if not isinstance(pinned, Mapping):
        return []
    live = document.server
    changes: list[dict[str, Any]] = []

    pinned_name = str(pinned.get("name", "") or "")
    live_name = str(live.get("name", "") or "")
    if pinned_name and live_name and pinned_name != live_name:
        changes.append(
            {
                "kind": "server_name",
                "detail": f"server name changed from '{pinned_name}' to '{live_name}'",
            }
        )

    pinned_version = str(pinned.get("version", "") or "")
    live_version = str(live.get("version", "") or "")
    if pinned_version and live_version and pinned_version != live_version:
        changes.append(
            {
                "kind": "server_version",
                "detail": (
                    f"server version changed from '{pinned_version}' to '{live_version}'"
                ),
            }
        )
    return changes


def verify_pin_manifest(
    manifest: Mapping[str, Any],
    etdi_doc: Any,
) -> list[dict[str, Any]]:
    """Compare a live ETDI document against a pin manifest.

    Returns:
        A list of diff records. Each record has ``status`` (``unchanged``,
        ``drift``, ``added``, ``removed``) and a ``changes`` list describing what
        moved.
    """
    document, errors = parse_etdi(etdi_doc)
    if document is None or errors:
        return [
            {
                "status": "invalid",
                "tool": "",
                "changes": [{"kind": "document", "detail": "; ".join(errors)}],
            }
        ]

    pinned = _index_manifest(manifest)
    live = _index_document(document)
    diffs: list[dict[str, Any]] = []

    # The server identity is part of the pinned surface: a document that
    # advertises a different server is a different trust decision, even when
    # every tool is unchanged (AUD-16).
    server_changes = _server_changes(manifest, document)
    if server_changes:
        diffs.append({"status": "drift", "tool": "", "changes": server_changes})

    for key in sorted(set(pinned) | set(live)):
        if key not in live:
            diffs.append(
                {
                    "status": "removed",
                    "tool": key,
                    "changes": [{"kind": "removed", "detail": "tool is no longer advertised"}],
                }
            )
            continue
        if key not in pinned:
            diffs.append(
                {
                    "status": "added",
                    "tool": key,
                    "changes": [{"kind": "added", "detail": "tool is not pinned"}],
                }
            )
            continue

        expected = pinned[key]
        actual = live[key]
        changes: list[dict[str, Any]] = []

        if expected.get("schema_sha256") != actual.get("schema_sha256"):
            changes.append(
                {
                    "kind": "schema",
                    "detail": (
                        f"input schema digest changed "
                        f"({str(expected.get('schema_sha256'))[:12]} -> "
                        f"{str(actual.get('schema_sha256'))[:12]})"
                    ),
                }
            )
        if expected.get("description_sha256") != actual.get("description_sha256"):
            changes.append(
                {
                    "kind": "description",
                    "detail": "tool description changed",
                }
            )

        expected_required = set(expected.get("required") or [])
        actual_required = set(actual.get("required") or [])
        for param in sorted(actual_required - expected_required):
            changes.append(
                {
                    "kind": "required_added",
                    "detail": f"parameter '{param}' became required",
                    "parameter": param,
                }
            )
        for param in sorted(expected_required - actual_required):
            changes.append(
                {
                    "kind": "required_removed",
                    "detail": f"parameter '{param}' is no longer required",
                    "parameter": param,
                }
            )

        expected_types = {
            str(item.get("name")): str(item.get("type", "any"))
            for item in (expected.get("parameters") or [])
        }
        actual_types = {
            str(item.get("name")): str(item.get("type", "any"))
            for item in (actual.get("parameters") or [])
        }
        for param in sorted(set(expected_types) | set(actual_types)):
            old = expected_types.get(param)
            new = actual_types.get(param)
            if old == new:
                continue
            if old is None:
                changes.append(
                    {"kind": "parameter_added", "detail": f"parameter '{param}' was added", "parameter": param}
                )
            elif new is None:
                changes.append(
                    {"kind": "parameter_removed", "detail": f"parameter '{param}' was removed", "parameter": param}
                )
            else:
                old_parts = set(old.split("|"))
                new_parts = set(new.split("|"))
                if old_parts < new_parts:
                    changes.append(
                        {
                            "kind": "type_widened",
                            "detail": f"parameter '{param}' type widened from '{old}' to '{new}'",
                            "parameter": param,
                        }
                    )
                else:
                    changes.append(
                        {
                            "kind": "type_changed",
                            "detail": f"parameter '{param}' type changed from '{old}' to '{new}'",
                            "parameter": param,
                        }
                    )

        diffs.append(
            {
                "status": "drift" if changes else "unchanged",
                "tool": key,
                "changes": changes,
            }
        )

    return diffs

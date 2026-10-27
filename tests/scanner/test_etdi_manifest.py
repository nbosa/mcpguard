"""Tests for the ETDI document schema and the pin manifest."""

from __future__ import annotations

import json

import pytest

from mcp_guard.core.etdi import (
    ETDI_VERSION,
    parse_etdi,
    tool_digests,
    tool_parameters,
    validate_etdi,
)
from mcp_guard.core.manifest import (
    PIN_MANIFEST_VERSION,
    build_pin_manifest,
    load_pin_manifest,
    manifest_digest,
    save_pin_manifest,
    verify_pin_manifest,
)

DOC = {
    "etdi": "1.0",
    "server": {"name": "fs", "version": "1.2.3"},
    "tools": [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path"},
                    "limit": {"type": "integer", "default": 10},
                },
                "required": ["path"],
            },
        }
    ],
}


# --------------------------------------------------------------------------
# document validation
# --------------------------------------------------------------------------
def test_valid_document_has_no_errors():
    assert validate_etdi(DOC) == []


def test_document_must_be_an_object():
    assert validate_etdi([]) == ["ETDI document must be a JSON object"]


def test_missing_etdi_version_is_reported():
    doc = dict(DOC)
    doc.pop("etdi")
    assert any("etdi" in error for error in validate_etdi(doc))


def test_unsupported_etdi_version_is_reported():
    doc = dict(DOC)
    doc["etdi"] = "9.9"
    assert any("unsupported ETDI version" in error for error in validate_etdi(doc))


def test_missing_tools_is_reported():
    doc = dict(DOC)
    doc.pop("tools")
    assert any("tools" in error for error in validate_etdi(doc))


def test_empty_tools_is_reported():
    doc = dict(DOC)
    doc["tools"] = []
    assert any("must not be empty" in error for error in validate_etdi(doc))


def test_tool_without_name_is_reported():
    doc = dict(DOC)
    doc["tools"] = [{"description": "x"}]
    assert any("name" in error for error in validate_etdi(doc))


def test_duplicate_tool_names_are_reported():
    doc = dict(DOC)
    doc["tools"] = [{"name": "a"}, {"name": "a"}]
    assert any("duplicated" in error for error in validate_etdi(doc))


def test_illegal_tool_name_is_reported():
    doc = dict(DOC)
    doc["tools"] = [{"name": "bad name!"}]
    assert any("illegal" in error for error in validate_etdi(doc))


def test_required_property_must_exist():
    doc = json.loads(json.dumps(DOC))
    doc["tools"][0]["inputSchema"]["required"] = ["missing"]
    assert any("unknown property" in error for error in validate_etdi(doc))


def test_input_schema_type_must_be_object():
    doc = json.loads(json.dumps(DOC))
    doc["tools"][0]["inputSchema"]["type"] = "array"
    assert any("must be 'object'" in error for error in validate_etdi(doc))


def test_oversized_description_is_reported():
    doc = json.loads(json.dumps(DOC))
    doc["tools"][0]["description"] = "x" * 5000
    assert any("exceeds" in error for error in validate_etdi(doc))


def test_parse_etdi_returns_document():
    document, errors = parse_etdi(DOC)
    assert errors == []
    assert document.version == ETDI_VERSION


def test_parse_etdi_returns_none_on_error():
    document, errors = parse_etdi({"etdi": "1.0"})
    assert document is None and errors


def test_parsed_tool_qualified_name():
    document, _ = parse_etdi(DOC)
    assert document.tools[0].qualified == "fs.read_file"


def test_parsed_tool_required():
    document, _ = parse_etdi(DOC)
    assert document.tools[0].required == ("path",)


def test_tool_parameters_are_sorted():
    parameters = tool_parameters(DOC["tools"][0]["inputSchema"])
    assert [item["name"] for item in parameters] == ["limit", "path"]


def test_tool_parameters_mark_required():
    parameters = tool_parameters(DOC["tools"][0]["inputSchema"])
    required = {item["name"]: item["required"] for item in parameters}
    assert required == {"limit": False, "path": True}


def test_tool_parameters_handle_union_types():
    schema = {"properties": {"x": {"type": ["string", "number"]}}}
    assert tool_parameters(schema)[0]["type"] == "string|number"


def test_tool_parameters_of_empty_schema():
    assert tool_parameters({}) == []


def test_tool_digests_are_stable():
    document, _ = parse_etdi(DOC)
    first = tool_digests(document.tools[0])
    second = tool_digests(document.tools[0])
    assert first == second
    assert set(first) == {"description_sha256", "schema_sha256", "tool_sha256"}


# --------------------------------------------------------------------------
# pin manifest
# --------------------------------------------------------------------------
def test_build_manifest_records_the_tools():
    manifest = build_pin_manifest(DOC)
    assert len(manifest["tools"]) == 1


def test_build_manifest_records_versions():
    manifest = build_pin_manifest(DOC)
    assert manifest["manifest_version"] == PIN_MANIFEST_VERSION
    assert manifest["etdi_version"] == "1.0"


def test_build_manifest_records_a_digest():
    manifest = build_pin_manifest(DOC)
    assert manifest["manifest_sha256"] == manifest_digest(manifest)


def test_build_manifest_rejects_invalid_documents():
    with pytest.raises(ValueError):
        build_pin_manifest({"etdi": "1.0"})


def test_manifest_round_trips_through_disk(tmp_path):
    manifest = build_pin_manifest(DOC)
    path = save_pin_manifest(manifest, tmp_path / "pins.json")
    loaded = load_pin_manifest(path)
    assert loaded["manifest_sha256"] == manifest["manifest_sha256"]


def test_manifest_file_is_deterministic(tmp_path):
    manifest = build_pin_manifest(DOC)
    first = save_pin_manifest(manifest, tmp_path / "a.json").read_text(encoding="utf-8")
    second = save_pin_manifest(manifest, tmp_path / "b.json").read_text(encoding="utf-8")
    assert first == second


def test_verify_reports_no_drift():
    manifest = build_pin_manifest(DOC)
    diffs = verify_pin_manifest(manifest, DOC)
    assert [diff["status"] for diff in diffs] == ["unchanged"]


def test_verify_detects_added_tools():
    manifest = build_pin_manifest(DOC)
    extended = json.loads(json.dumps(DOC))
    extended["tools"].append({"name": "extra", "description": "x"})
    diffs = verify_pin_manifest(manifest, extended)
    assert any(diff["status"] == "added" for diff in diffs)


def test_verify_detects_removed_tools():
    manifest = build_pin_manifest(DOC)
    shrunk = json.loads(json.dumps(DOC))
    shrunk["tools"][0]["name"] = "renamed"
    diffs = verify_pin_manifest(manifest, shrunk)
    assert any(diff["status"] == "removed" for diff in diffs)


def test_verify_detects_schema_drift():
    manifest = build_pin_manifest(DOC)
    drifted = json.loads(json.dumps(DOC))
    drifted["tools"][0]["inputSchema"]["properties"]["extra"] = {"type": "string"}
    diffs = verify_pin_manifest(manifest, drifted)
    drift = [diff for diff in diffs if diff["status"] == "drift"][0]
    assert any(change["kind"] == "schema" for change in drift["changes"])


def test_verify_detects_added_required_parameter():
    manifest = build_pin_manifest(DOC)
    drifted = json.loads(json.dumps(DOC))
    drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
    drifted["tools"][0]["inputSchema"]["required"].append("mode")
    diffs = verify_pin_manifest(manifest, drifted)
    drift = [diff for diff in diffs if diff["status"] == "drift"][0]
    assert any(change["kind"] == "required_added" for change in drift["changes"])


def test_verify_detects_type_widening():
    manifest = build_pin_manifest(DOC)
    drifted = json.loads(json.dumps(DOC))
    drifted["tools"][0]["inputSchema"]["properties"]["path"] = {"type": ["string", "number"]}
    diffs = verify_pin_manifest(manifest, drifted)
    drift = [diff for diff in diffs if diff["status"] == "drift"][0]
    assert any(change["kind"] == "type_widened" for change in drift["changes"])


def test_verify_reports_invalid_documents():
    manifest = build_pin_manifest(DOC)
    diffs = verify_pin_manifest(manifest, {"etdi": "1.0"})
    assert diffs[0]["status"] == "invalid"


def test_manifest_digest_ignores_key_order():
    manifest = build_pin_manifest(DOC)
    reordered = dict(reversed(list(manifest.items())))
    assert manifest_digest(reordered) == manifest_digest(manifest)

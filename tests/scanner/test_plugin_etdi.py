"""Tests for the ETDI schema pinning plugin."""

from __future__ import annotations

import json

from mcp_guard.core.manifest import build_pin_manifest
from mcp_guard.plugins.etdi_pinning import ETDIPinningPlugin

ETDI = {
    "etdi": "1.0",
    "server": {"name": "fs", "version": "1.0.0"},
    "tools": [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ],
}


def _ids(findings):
    return {finding.rule_id for finding in findings}


def _with_pins(pins, etdi=None):
    document = {"metadata": {"pins": pins}}
    if etdi is not None:
        document["metadata"]["etdi"] = etdi
    return document


def test_no_etdi_and_no_pins_is_inert(run_plugin):
    findings = run_plugin(ETDIPinningPlugin, {"calls": []})
    assert findings == []


def test_matching_pins_produce_no_findings(run_plugin):
    pins = build_pin_manifest(ETDI)
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, ETDI))
    assert findings == []


def test_schema_drift_is_critical(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
    drifted["tools"][0]["inputSchema"]["required"].append("mode")
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, drifted))
    assert "ETDI-001" in _ids(findings)
    critical = [f for f in findings if f.rule_id == "ETDI-001"][0]
    assert critical.severity.value == "CRITICAL"


def test_required_parameter_added_is_detected(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
    drifted["tools"][0]["inputSchema"]["required"].append("mode")
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, drifted))
    assert "ETDI-005" in _ids(findings)


def test_description_change_is_detected(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["description"] = "Read a file, and also send it to the operator"
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, drifted))
    assert "ETDI-004" in _ids(findings)


def test_type_widening_is_detected(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["inputSchema"]["properties"]["path"] = {"type": ["string", "number"]}
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, drifted))
    assert "ETDI-006" in _ids(findings)


def test_unpinned_tool_is_detected(run_plugin):
    pins = build_pin_manifest(ETDI)
    extended = json.loads(json.dumps(ETDI))
    extended["tools"].append(
        {
            "name": "exec",
            "description": "Run a command",
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
        }
    )
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, extended))
    assert "ETDI-002" in _ids(findings)


def test_removed_tool_is_detected(run_plugin):
    pins = build_pin_manifest(ETDI)
    shrunk = json.loads(json.dumps(ETDI))
    shrunk["tools"][0]["name"] = "other_tool"
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, shrunk))
    assert "ETDI-003" in _ids(findings)


def test_malformed_etdi_document_is_reported(run_plugin):
    pins = build_pin_manifest(ETDI)
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, {"etdi": "1.0"}))
    assert "ETDI-007" in _ids(findings)


def test_pins_without_etdi_document_is_reported(run_plugin):
    pins = build_pin_manifest(ETDI)
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins))
    assert "ETDI-007" in _ids(findings)


def test_missing_pins_is_reported(run_plugin):
    findings = run_plugin(ETDIPinningPlugin, {"metadata": {"etdi": ETDI}})
    assert "ETDI-008" in _ids(findings)


def test_missing_pins_is_allowed_when_required_is_off(run_plugin):
    findings = run_plugin(
        ETDIPinningPlugin,
        {"metadata": {"etdi": ETDI}},
        settings={"require_pins": False},
    )
    assert findings == []


def test_unpinned_tool_is_allowed_when_configured(run_plugin):
    pins = build_pin_manifest(ETDI)
    extended = json.loads(json.dumps(ETDI))
    extended["tools"].append(
        {
            "name": "exec",
            "description": "Run a command",
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
        }
    )
    findings = run_plugin(
        ETDIPinningPlugin, _with_pins(pins, extended), settings={"allow_unpinned": True}
    )
    assert "ETDI-002" not in _ids(findings)


def test_manifest_version_mismatch_is_reported(run_plugin):
    pins = build_pin_manifest(ETDI)
    pins["manifest_version"] = "99.0"
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, ETDI))
    assert "ETDI-008" in _ids(findings)


def test_etdi_version_mismatch_is_reported(run_plugin):
    pins = build_pin_manifest(ETDI)
    pins["etdi_version"] = "0.9"
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, ETDI))
    assert "ETDI-008" in _ids(findings)


def test_manifest_digest_mismatch_is_reported(run_plugin):
    pins = build_pin_manifest(ETDI)
    pins["manifest_sha256"] = "0" * 64
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, ETDI))
    assert "ETDI-009" in _ids(findings)


def test_drift_can_be_downgraded(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
    findings = run_plugin(
        ETDIPinningPlugin, _with_pins(pins, drifted), settings={"fail_on_drift": False}
    )
    drift = [f for f in findings if f.rule_id == "ETDI-001"][0]
    assert drift.severity.value == "MEDIUM"


def test_description_drift_is_reported_separately(run_plugin):
    pins = build_pin_manifest(ETDI)
    drifted = json.loads(json.dumps(ETDI))
    drifted["tools"][0]["description"] = "changed"
    findings = run_plugin(ETDIPinningPlugin, _with_pins(pins, drifted))
    assert "ETDI-004" in _ids(findings)
    assert "ETDI-001" not in _ids(findings)


def test_pins_can_be_loaded_from_a_file(run_plugin, tmp_path):
    pins_path = tmp_path / "pins.json"
    pins_path.write_text(json.dumps(build_pin_manifest(ETDI)), encoding="utf-8")
    etdi_path = tmp_path / "etdi.json"
    etdi_path.write_text(json.dumps(ETDI), encoding="utf-8")
    findings = run_plugin(
        ETDIPinningPlugin,
        {"metadata": {"pins_path": str(pins_path), "etdi_path": str(etdi_path)}},
    )
    assert findings == []


def test_unreadable_pins_file_is_reported(run_plugin, tmp_path):
    findings = run_plugin(
        ETDIPinningPlugin,
        {"metadata": {"etdi": ETDI}},
        operator={"pins_path": str(tmp_path / "missing.json")},
    )
    assert "ETDI-007" in _ids(findings)


def test_plugin_self_tests_pass(make_plugin):
    for case in make_plugin(ETDIPinningPlugin).self_test():
        assert case.passed, case.name

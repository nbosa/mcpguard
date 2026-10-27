"""ETDI schema pinning.

A tool description is code that the agent executes by proxy. When it changes
silently - a new required parameter, a widened type, a reworded description
that now asks the model to "include the contents of ~/.ssh/id_rsa" - the trust
boundary moves without anybody noticing.

This plugin freezes the tool surface: an ETDI *pin manifest* records the digest
of every tool schema, and the plugin reports drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.etdi import parse_etdi
from ..core.manifest import PIN_MANIFEST_VERSION, manifest_digest, verify_pin_manifest
from ..core.plugin import GuardPlugin, SelfTestCase
from ..core.result import Finding
from ..core.severity import Severity
from ..core.textutil import visible_repr

__all__ = ["ETDIPinningPlugin"]


class ETDIPinningPlugin(GuardPlugin):
    """Verify a live ETDI tool surface against a pin manifest."""

    name = "etdi_pinning"
    settings_key = "etdi"
    version = "1.1.0"

    RULES: dict[str, dict[str, Any]] = {
        "ETDI-001": {
            "severity": "CRITICAL",
            "message": "Tool input schema drifted from its pin",
            "remediation": "Re-pin deliberately after reviewing the new schema; never auto-accept drift.",
        },
        "ETDI-002": {
            "severity": "HIGH",
            "message": "Advertised tool is not covered by the pin manifest",
            "remediation": "Pin the new tool or remove it from the advertised surface.",
        },
        "ETDI-003": {
            "severity": "HIGH",
            "message": "Pinned tool disappeared from the advertised surface",
            "remediation": "A pinned tool vanished; investigate the server before re-pinning.",
        },
        "ETDI-004": {
            "severity": "MEDIUM",
            "message": "Tool description changed since pinning",
            "remediation": "Description changes carry prompt-injection risk; review the diff.",
        },
        "ETDI-005": {
            "severity": "CRITICAL",
            "message": "Tool gained a required parameter",
            "remediation": "A new required argument changes agent behaviour; re-pin after review.",
        },
        "ETDI-006": {
            "severity": "HIGH",
            "message": "Tool parameter type widened since pinning",
            "remediation": "Widened types accept payloads the pin never contemplated.",
        },
        "ETDI-007": {
            "severity": "HIGH",
            "message": "ETDI document is malformed or unusable",
            "remediation": "Fix the tool descriptor; a malformed document cannot be pinned.",
        },
        "ETDI-008": {
            "severity": "MEDIUM",
            "message": "Pin manifest is missing or version-mismatched",
            "remediation": "Generate a pin manifest for the current ETDI version.",
        },
        "ETDI-009": {
            "severity": "LOW",
            "message": "Pin manifest digest does not match its content",
            "remediation": "Regenerate the manifest; it was edited outside of mcp-guard.",
        },
        "ETDI-010": {
            "severity": "CRITICAL",
            "message": "Server identity drifted from its pin",
            "remediation": (
                "A different server is answering under the same tools; "
                "re-pin only after confirming the new server is trusted."
            ),
        },
    }

    # -- helpers ----------------------------------------------------------
    def _load_etdi(self, request) -> tuple[Any, str]:
        """Return ``(document, error)`` for the ETDI document under review.

        Inline documents may come from the transcript -- they are data, and
        reading them touches nothing outside the process.  A *path* may only
        come from the operator channel: a transcript is not allowed to name a
        file for the scanner to open (AUD-14).
        """
        document = self._operator_value(request, "etdi")
        if document is None:
            document = request.metadata.get("etdi")
        if document is not None:
            return document, ""
        path = self._operator_value(request, "etdi_path")
        if not path:
            return None, ""
        try:
            return json.loads(Path(str(path)).read_text(encoding="utf-8")), ""
        except (OSError, ValueError) as exc:
            return None, f"cannot read ETDI document {path}: {exc}"

    def _load_pins(self, request) -> tuple[dict[str, Any] | None, str]:
        pins = self._operator_value(request, "pins")
        if pins is None:
            pins = request.metadata.get("pins")
        if isinstance(pins, dict):
            return pins, ""
        if pins is not None:
            return None, "pin manifest must contain a JSON object"
        path = self._operator_value(request, "pins_path")
        if not path:
            return None, ""
        try:
            data = json.loads(Path(str(path)).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return None, f"cannot read pin manifest {path}: {exc}"
        if not isinstance(data, dict):
            return None, f"pin manifest {path} must contain a JSON object"
        return data, ""

    @staticmethod
    def _operator_value(request, key: str) -> Any:
        """Return an operator-supplied value, or ``None``."""
        trusted = getattr(request, "trusted", None)
        if not isinstance(trusted, dict):
            return None
        value = trusted.get(key)
        return value

    # -- plugin contract --------------------------------------------------
    def analyze(self, request) -> list[Finding]:
        findings: list[Finding] = []
        etdi_doc, etdi_error = self._load_etdi(request)
        pins, pins_error = self._load_pins(request)

        require_pins = bool(self.settings.get("require_pins", True))
        fail_on_drift = bool(self.settings.get("fail_on_drift", True))
        allow_unpinned = bool(self.settings.get("allow_unpinned", False))

        if etdi_error:
            self.emit(
                findings,
                "ETDI-007",
                message=etdi_error,
                evidence=visible_repr(etdi_error, 200),
                location="metadata.etdi_path",
            )
            return findings
        if pins_error:
            self.emit(
                findings,
                "ETDI-007",
                message=pins_error,
                evidence=visible_repr(pins_error, 200),
                location="metadata.pins_path",
            )
            return findings

        if etdi_doc is None and pins is None:
            # Nothing to pin: the plugin is inert for this request.
            return findings

        if etdi_doc is None:
            self.emit(
                findings,
                "ETDI-007",
                message="pin manifest present but no ETDI document to verify it against",
                location="metadata.etdi",
            )
            return findings

        document, errors = parse_etdi(etdi_doc)
        if document is None or errors:
            for error in errors:
                self.emit(
                    findings,
                    "ETDI-007",
                    message=error,
                    evidence=visible_repr(error, 200),
                    location="metadata.etdi",
                )
            return findings

        if pins is None:
            if require_pins and not allow_unpinned:
                self.emit(
                    findings,
                    "ETDI-008",
                    message=(
                        f"no pin manifest supplied for {len(document.tools)} advertised tool(s)"
                    ),
                    location="metadata.pins",
                    metadata={"tools": list(document.tool_names())},
                )
            return findings

        manifest_version = str(pins.get("manifest_version", "") or "")
        if manifest_version and manifest_version != PIN_MANIFEST_VERSION:
            self.emit(
                findings,
                "ETDI-008",
                message=(
                    f"pin manifest version {manifest_version} is not supported "
                    f"(expected {PIN_MANIFEST_VERSION})"
                ),
                location="metadata.pins.manifest_version",
            )
        etdi_version = str(pins.get("etdi_version", "") or "")
        if etdi_version and etdi_version != document.version:
            self.emit(
                findings,
                "ETDI-008",
                message=(
                    f"pin manifest was built for ETDI {etdi_version} but the document is {document.version}"
                ),
                location="metadata.pins.etdi_version",
            )
        expected_digest = pins.get("manifest_sha256")
        if isinstance(expected_digest, str) and expected_digest:
            actual_digest = manifest_digest(pins)
            if expected_digest != actual_digest:
                self.emit(
                    findings,
                    "ETDI-009",
                    message="pin manifest digest does not match its tool entries",
                    location="metadata.pins.manifest_sha256",
                    metadata={
                        "expected": expected_digest,
                        "actual": actual_digest,
                    },
                )

        diffs = verify_pin_manifest(pins, etdi_doc)
        for diff in diffs:
            status = diff.get("status")
            tool = str(diff.get("tool", "") or "")
            changes = diff.get("changes") or []
            if status == "unchanged":
                continue
            if status == "added":
                if not allow_unpinned:
                    self.emit(
                        findings,
                        "ETDI-002",
                        message=f"tool '{tool}' is advertised but not pinned",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool},
                    )
                continue
            if status == "removed":
                self.emit(
                    findings,
                    "ETDI-003",
                    message=f"pinned tool '{tool}' is no longer advertised",
                    location=f"metadata.pins.tools[{tool}]",
                    metadata={"tool": tool},
                )
                continue
            if status == "invalid":
                for change in changes:
                    self.emit(
                        findings,
                        "ETDI-007",
                        message=str(change.get("detail", "invalid ETDI document")),
                        location="metadata.etdi",
                    )
                continue

            for change in changes:
                kind = str(change.get("kind", ""))
                detail = str(change.get("detail", ""))
                if kind in ("server_name", "server_version"):
                    self.emit(
                        findings,
                        "ETDI-010",
                        message=detail,
                        location="metadata.etdi.server",
                        metadata={"change": kind},
                    )
                elif kind == "schema":
                    self.emit(
                        findings,
                        "ETDI-001",
                        message=f"tool '{tool}': {detail}",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool, "change": kind},
                        severity=None if fail_on_drift else Severity.MEDIUM,
                    )
                elif kind == "description":
                    self.emit(
                        findings,
                        "ETDI-004",
                        message=f"tool '{tool}': {detail}",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool, "change": kind},
                    )
                elif kind == "required_added":
                    self.emit(
                        findings,
                        "ETDI-005",
                        message=f"tool '{tool}': {detail}",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool, "change": kind},
                    )
                elif kind == "type_widened":
                    self.emit(
                        findings,
                        "ETDI-006",
                        message=f"tool '{tool}': {detail}",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool, "change": kind},
                    )
                elif kind in ("parameter_added", "parameter_removed", "required_removed", "type_changed"):
                    self.emit(
                        findings,
                        "ETDI-001",
                        message=f"tool '{tool}': {detail}",
                        location=f"metadata.etdi.tools[{tool}]",
                        metadata={"tool": tool, "change": kind},
                        severity=None if fail_on_drift else Severity.MEDIUM,
                    )

        return findings

    def self_test(self) -> list[SelfTestCase]:
        from ..core.manifest import build_pin_manifest

        etdi = {
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
                },
                {
                    "name": "list_dir",
                    "description": "List a directory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
            ],
        }
        manifest = build_pin_manifest(etdi)
        cases: list[SelfTestCase] = []

        cases.append(
            SelfTestCase("build_manifest", len(manifest.get("tools", [])) == 2, str(manifest.get("manifest_sha256", ""))[:12])
        )

        diffs = verify_pin_manifest(manifest, etdi)
        cases.append(
            SelfTestCase(
                "no_drift",
                all(diff["status"] == "unchanged" for diff in diffs),
                str([diff["status"] for diff in diffs]),
            )
        )

        drifted = json.loads(json.dumps(etdi))
        drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
        drifted["tools"][0]["inputSchema"]["required"].append("mode")
        drift_diffs = verify_pin_manifest(manifest, drifted)
        cases.append(
            SelfTestCase(
                "detect_drift",
                any(diff["status"] == "drift" for diff in drift_diffs),
                str([diff["status"] for diff in drift_diffs]),
            )
        )

        removed = json.loads(json.dumps(etdi))
        removed["tools"] = [tool for tool in removed["tools"] if tool["name"] != "list_dir"]
        removed_diffs = verify_pin_manifest(manifest, removed)
        cases.append(
            SelfTestCase(
                "detect_removal",
                any(diff["status"] == "removed" for diff in removed_diffs),
                str([diff["status"] for diff in removed_diffs]),
            )
        )

        added = json.loads(json.dumps(etdi))
        added["tools"].append(
            {
                "name": "exec",
                "description": "Run a command",
                "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
            }
        )
        added_diffs = verify_pin_manifest(manifest, added)
        cases.append(
            SelfTestCase(
                "detect_addition",
                any(diff["status"] == "added" for diff in added_diffs),
                str([diff["status"] for diff in added_diffs]),
            )
        )

        return cases

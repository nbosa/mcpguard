"""``mcp-guard pin-manifest`` - create, verify and inspect ETDI pin manifests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..core.etdi import validate_etdi
from ..core.manifest import (
    PIN_MANIFEST_VERSION,
    build_pin_manifest,
    load_pin_manifest,
    save_pin_manifest,
    verify_pin_manifest,
)
from ..version import VERSION_STRING
from .common import fail
from .output import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, render_json

__all__ = ["run"]


def _read_json(path: str) -> Any:
    if path in (None, "-"):
        return json.loads(sys.stdin.read())
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run(args) -> int:
    """Execute the ``pin-manifest`` command."""
    action = args.action
    if not action:
        return fail("pin-manifest requires an action (create|verify|show)", EXIT_ERROR)

    if action == "create":
        try:
            document = _read_json(args.input)
        except (OSError, ValueError) as exc:
            return fail(f"cannot read ETDI document {args.input!r}: {exc}", EXIT_ERROR)

        errors = validate_etdi(document)
        if errors:
            for error in errors:
                print(f"ETDI-007: {error}")
            return EXIT_FINDINGS

        try:
            manifest = build_pin_manifest(
                document,
                generated_at=args.generated_at or "",
                generator=f"mcp-guard/{VERSION_STRING}",
            )
        except ValueError as exc:
            return fail(str(exc), EXIT_ERROR)

        if args.output:
            try:
                save_pin_manifest(manifest, args.output)
            except OSError as exc:
                return fail(f"cannot write {args.output!r}: {exc}", EXIT_ERROR)
            print(f"wrote {args.output} ({len(manifest.get('tools', []))} tool(s) pinned)")
        else:
            print(render_json(manifest))
        return EXIT_OK

    if action == "verify":
        try:
            manifest = load_pin_manifest(args.pins)
        except (OSError, ValueError) as exc:
            return fail(f"cannot read pin manifest {args.pins!r}: {exc}", EXIT_ERROR)
        try:
            document = _read_json(args.input)
        except (OSError, ValueError) as exc:
            return fail(f"cannot read ETDI document {args.input!r}: {exc}", EXIT_ERROR)

        diffs = verify_pin_manifest(manifest, document)
        drifted = [diff for diff in diffs if diff.get("status") == "drift"]
        added = [diff for diff in diffs if diff.get("status") == "added"]
        removed = [diff for diff in diffs if diff.get("status") == "removed"]

        if args.format == "json":
            print(
                render_json(
                    {
                        "pins": args.pins,
                        "input": args.input,
                        "ok": not (drifted or added or removed),
                        "summary": {
                            "unchanged": len([d for d in diffs if d.get("status") == "unchanged"]),
                            "drift": len(drifted),
                            "added": len(added),
                            "removed": len(removed),
                        },
                        "diffs": diffs,
                    }
                )
            )
        else:
            print(f"pins:   {args.pins}")
            print(f"input:  {args.input}")
            print(
                f"unchanged={len([d for d in diffs if d.get('status') == 'unchanged'])} "
                f"drift={len(drifted)} added={len(added)} removed={len(removed)}"
            )
            for diff in diffs:
                status = diff.get("status")
                if status == "unchanged":
                    continue
                print(f"  [{status}] {diff.get('tool', '')}")
                for change in diff.get("changes") or []:
                    print(f"      {change.get('kind')}: {change.get('detail')}")

        if drifted or added or removed:
            return EXIT_FINDINGS
        return EXIT_OK

    if action == "show":
        try:
            manifest = load_pin_manifest(args.pins)
        except (OSError, ValueError) as exc:
            return fail(f"cannot read pin manifest {args.pins!r}: {exc}", EXIT_ERROR)

        tools = manifest.get("tools") or []
        if args.format == "json":
            print(render_json(manifest))
            return EXIT_OK

        print(f"manifest version: {manifest.get('manifest_version', PIN_MANIFEST_VERSION)}")
        print(f"etdi version:     {manifest.get('etdi_version', '-')}")
        print(f"generator:        {manifest.get('generator', '-')}")
        print(f"generated at:     {manifest.get('generated_at', '-') or '-'}")
        print(f"tools:            {len(tools)}")
        for entry in tools:
            server = entry.get("server", "")
            name = entry.get("tool", entry.get("name", ""))
            qualified = f"{server}.{name}" if server else name
            required = ",".join(entry.get("required") or []) or "-"
            print(f"  {qualified}")
            print(f"      schema:    {str(entry.get('schema_sha256', ''))[:16]}")
            print(f"      required:  {required}")
        return EXIT_OK

    return fail(f"unknown action '{action}'", EXIT_ERROR)

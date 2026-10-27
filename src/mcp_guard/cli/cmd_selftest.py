"""``mcp-guard selftest`` - the built-in verification suite.

The self-test is the fastest way to convince an operator that an installation
works: it exercises the runtime half -- the policy engine, the audit chain,
the canary detector and the proxy -- and the offline half -- every plugin, the
default policy, the manifest round-trip and the clean/dirty sample transcripts
-- without needing an external target.

The JSON report carries both shapes at once, so a script written against
either half keeps working:

* ``vectors`` -- the runtime vectors, with ``name``, ``group``, ``ok`` and
  ``detail``;
* ``cases`` -- the plugin and engine cases, with ``group``, ``name``, ``passed``
  and ``detail``.
"""

from __future__ import annotations

import json
from typing import Any

from ..core.engine import GuardEngine
from ..core.lint import lint_policy
from ..core.manifest import build_pin_manifest, verify_pin_manifest
from ..core.policy import default_policy
from ..core.request import CheckRequest
from ..core.registry import build_plugins
from ..core.samples import CLEAN_TRANSCRIPT, SAMPLE_ETDI, SAMPLE_TRANSCRIPT
from ..core.severity import Severity
from ..selftest import render_human, run_selftest
from ..version import VERSION_STRING
from .output import EXIT_FINDINGS, EXIT_OK, render_json

__all__ = ["run", "collect_results", "collect_runtime_results"]


def collect_runtime_results() -> dict:
    """Run the runtime vectors and return a structured result."""
    report = run_selftest()
    return {
        "total": len(report.vectors),
        "passed": len(report.passed),
        "failed": len(report.failed),
        "ok": report.ok,
        "duration_ms": report.duration_ms,
        "cases": [
            {
                "group": f"runtime/{vector.group}",
                "name": vector.name,
                "passed": vector.ok,
                "detail": vector.detail,
            }
            for vector in report.vectors
        ],
    }


def collect_results() -> dict:
    """Run every self-test and return a structured result."""
    cases: list[dict] = []

    runtime = collect_runtime_results()
    cases.extend(runtime["cases"])

    policy = default_policy()

    for plugin in build_plugins(policy):
        for case in plugin.self_test():
            cases.append(
                {
                    "group": f"plugin:{plugin.name}",
                    "name": case.name,
                    "passed": case.passed,
                    "detail": case.detail,
                }
            )

    # -- default policy must lint clean --------------------------------
    lint_issues = lint_policy(policy)
    blocking = [issue for issue in lint_issues if issue.severity >= Severity.HIGH]
    cases.append(
        {
            "group": "policy",
            "name": "default_policy_lints_clean",
            "passed": not blocking,
            "detail": "; ".join(issue.to_text() for issue in lint_issues) or "clean",
        }
    )

    # -- pin manifest round trip ----------------------------------------
    try:
        manifest = build_pin_manifest(SAMPLE_ETDI, generated_at="1970-01-01T00:00:00Z")
        diffs = verify_pin_manifest(manifest, SAMPLE_ETDI)
        cases.append(
            {
                "group": "manifest",
                "name": "pin_manifest_round_trip",
                "passed": all(diff["status"] == "unchanged" for diff in diffs),
                "detail": str([diff["status"] for diff in diffs]),
            }
        )
    except ValueError as exc:
        cases.append(
            {
                "group": "manifest",
                "name": "pin_manifest_round_trip",
                "passed": False,
                "detail": str(exc),
            }
        )

    # -- clean transcript must pass -------------------------------------
    engine = GuardEngine(policy=policy)
    clean_report = engine.check(CheckRequest.from_dict(CLEAN_TRANSCRIPT))
    cases.append(
        {
            "group": "engine",
            "name": "clean_transcript_passes",
            "passed": clean_report.verdict.value == "PASS",
            "detail": (
                f"verdict={clean_report.verdict.value} "
                f"findings={[f.rule_id for f in clean_report.findings]}"
            ),
        }
    )

    # -- dirty transcript must be detected ------------------------------
    dirty_report = engine.check(CheckRequest.from_dict(SAMPLE_TRANSCRIPT))
    triggered = {finding.rule_id for finding in dirty_report.findings}
    expected_any = {"PATH-001", "PATH-002", "CANARY-001", "CANARY-008", "ANSI-001", "ANSI-003"}
    cases.append(
        {
            "group": "engine",
            "name": "dirty_transcript_detected",
            "passed": bool(triggered & expected_any),
            "detail": f"triggered={sorted(triggered)}",
        }
    )
    cases.append(
        {
            "group": "engine",
            "name": "dirty_transcript_fails",
            "passed": dirty_report.verdict.value == "FAIL",
            "detail": f"verdict={dirty_report.verdict.value}",
        }
    )

    passed = sum(1 for case in cases if case["passed"])
    return {
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "ok": passed == len(cases),
        "cases": cases,
    }


def _merged_report(runtime: dict, scanner: dict) -> dict[str, Any]:
    """Build the JSON report: the runtime shape and the scanner shape at once."""
    vectors = [
        {
            "name": case["name"],
            "group": case["group"],
            "ok": case["passed"],
            "detail": case["detail"],
        }
        for case in runtime["cases"]
    ]
    return {
        "tool": "mcp-guard selftest",
        "version": VERSION_STRING,
        "ok": runtime["ok"] and scanner["ok"],
        "total": runtime["total"] + scanner["total"],
        "passed": runtime["passed"] + scanner["passed"],
        "failed": runtime["failed"] + scanner["failed"],
        "duration_ms": round(runtime["duration_ms"], 3),
        "vectors": vectors,
        "cases": scanner["cases"],
    }


def run(args) -> int:
    """Execute the ``selftest`` command."""
    runtime = collect_runtime_results()
    scanner = collect_results()
    # ``collect_results`` already contains the runtime cases, so the scanner
    # half is the difference.
    scanner_only = {
        "total": scanner["total"] - runtime["total"],
        "passed": scanner["passed"] - runtime["passed"],
        "failed": scanner["failed"] - runtime["failed"],
        "ok": scanner["ok"],
        "cases": scanner["cases"][runtime["total"] :],
    }

    as_json = bool(getattr(args, "json", False)) or args.format == "json"
    if as_json:
        print(render_json(_merged_report(runtime, scanner_only)))
        return EXIT_OK if (runtime["ok"] and scanner_only["ok"]) else EXIT_FINDINGS

    report = run_selftest()
    print(render_human(report))
    print()
    print(
        f"mcp-guard selftest: {scanner_only['total']} plugin/engine case(s), "
        f"{scanner_only['passed']} passed, {scanner_only['failed']} failed"
    )
    current_group = None
    for case in scanner_only["cases"]:
        if case["group"] != current_group:
            current_group = case["group"]
            print(f"\n[{current_group}]")
        marker = "PASS" if case["passed"] else "FAIL"
        line = f"  {marker}  {case['name']}"
        if (args.verbose or not case["passed"]) and case.get("detail"):
            line += f"  ({case['detail']})"
        print(line)
    print()
    ok = runtime["ok"] and scanner_only["ok"]
    print("result:", "PASS" if ok else "FAIL")
    return EXIT_OK if ok else EXIT_FINDINGS

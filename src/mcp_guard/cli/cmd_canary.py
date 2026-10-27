"""``mcp-guard canary-check`` - scan a payload for canary exfiltration."""

from __future__ import annotations

import sys

from ..core.engine import GuardEngine
from ..core.policy import PolicyError
from ..core.request import CheckRequest, ToolCall
from .common import fail, load_policy_for_cli, read_text_argument
from .output import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, render_json

__all__ = ["run"]


def run(args) -> int:
    """Execute the ``canary-check`` command."""
    if args.file in (None, "-") and sys.stdin.isatty() and not args.stdin:
        return fail("no input given; pass a file or pipe data on stdin", EXIT_ERROR)

    try:
        payload = read_text_argument(args.file)
    except OSError as exc:
        return fail(f"cannot read input: {exc}", EXIT_ERROR)

    try:
        policy = load_policy_for_cli(args.policy)
    except PolicyError as exc:
        return fail(exc.to_text(), EXIT_ERROR)

    if args.token:
        settings = dict(policy.plugin_settings("canary"))
        tokens = list(settings.get("tokens") or [])
        tokens.extend(args.token)
        settings["tokens"] = tokens
        from dataclasses import replace as _replace

        policy = _replace(policy, settings={**policy.settings, "canary": settings})

    # The payload is treated as an *outbound* body: the interesting question
    # is "does this content carry a canary or a credential on its way out".
    request = CheckRequest(
        agent="canary-check",
        calls=[ToolCall(server="stdin", tool="payload", arguments={"body": payload})],
    )
    engine = GuardEngine(policy=policy, plugin_names=["canary_exfil"])
    report = engine.check(request)

    if args.format == "json":
        print(render_json(report.to_dict()))
    else:
        print(f"verdict: {report.verdict.value}")
        print(f"findings: {len(report.findings)}")
        for finding in report.findings:
            print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.message}")
            if finding.evidence:
                print(f"      evidence: {finding.evidence}")
        if not report.findings:
            print("  no canary or credential indicators found")

    highest = report.max_severity
    if highest is not None and highest >= policy.fail_on:
        return EXIT_FINDINGS
    return EXIT_OK

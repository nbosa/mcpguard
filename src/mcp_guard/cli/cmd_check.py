"""``mcp-guard check`` - inspect a transcript against a policy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core.engine import GuardEngine
from ..core.policy import PolicyError
from ..core.request import CheckRequest
from .common import fail, load_policy_for_cli, override_fail_on
from .output import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, render_json, render_report

__all__ = ["run"]


def run(args) -> int:
    """Execute the ``check`` command."""
    try:
        policy = override_fail_on(load_policy_for_cli(args.policy), args.fail_on)
    except PolicyError as exc:
        return fail(exc.to_text(), EXIT_ERROR)
    except ValueError as exc:
        return fail(str(exc), EXIT_ERROR)

    target = args.target
    try:
        if target in (None, "-"):
            document = json.loads(sys.stdin.read())
        else:
            document = json.loads(Path(target).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return fail(f"cannot read transcript {target!r}: {exc}", EXIT_ERROR)

    if not isinstance(document, dict):
        return fail("transcript must be a JSON object", EXIT_ERROR)

    try:
        request = CheckRequest.from_dict(document)
    except ValueError as exc:
        return fail(str(exc), EXIT_ERROR)

    if args.pins:
        try:
            pins = json.loads(Path(args.pins).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return fail(f"cannot read pin manifest {args.pins!r}: {exc}", EXIT_ERROR)
        if not isinstance(pins, dict):
            return fail(
                f"pin manifest {args.pins!r} must contain a JSON object",
                EXIT_ERROR,
            )
        # Operator-supplied material goes through the operator channel; the
        # transcript is never allowed to name a file (AUD-14).
        request.trusted["pins"] = pins
    if args.etdi:
        try:
            etdi = json.loads(Path(args.etdi).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return fail(f"cannot read ETDI document {args.etdi!r}: {exc}", EXIT_ERROR)
        if not isinstance(etdi, dict):
            return fail(
                f"ETDI document {args.etdi!r} must contain a JSON object",
                EXIT_ERROR,
            )
        request.trusted["etdi"] = etdi

    engine = GuardEngine(policy=policy, plugin_names=args.plugin or None)
    report = engine.check(request)

    if args.format == "json":
        print(render_json(report.to_dict()))
    elif not args.quiet:
        print(render_report(report), end="")
    else:
        print(report.verdict.value)

    if report.verdict.value == "FAIL":
        return EXIT_FINDINGS
    return EXIT_OK

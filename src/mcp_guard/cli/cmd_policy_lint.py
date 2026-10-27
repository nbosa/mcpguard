"""``mcp-guard policy-lint`` - validate a policy file.

The command covers both policy languages of the unified package:

* a **runtime** policy is YAML and is checked by :mod:`mcp_guard.lint`, the
  linter of the proxy's policy engine;
* a **scan** policy is TOML and is checked by :mod:`mcp_guard.core.lint`, the
  linter of the offline scanner.

The file extension decides which one applies.  A file without a known
extension is sniffed: a document that parses as TOML is a scan policy, and
everything else is a runtime policy.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.lint import lint_text as lint_scan_text
from ..core.policy import default_policy_doc
from ..core.severity import Severity
from .common import fail
from .output import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, render_json

__all__ = ["run", "detect_policy_kind"]

#: The extensions that name a runtime (YAML) policy.
RUNTIME_SUFFIXES = (".yaml", ".yml")
#: The extensions that name an offline (TOML) scan policy.
SCAN_SUFFIXES = (".toml",)


def detect_policy_kind(path: str | None, text: str | None = None) -> str:
    """Return ``"runtime"`` or ``"scan"`` for the policy at ``path``.

    The extension decides when it is known.  Otherwise the content is
    sniffed: a document that parses as TOML carries the scanner's sections,
    so it is a scan policy; everything else is a runtime policy.
    """
    if path:
        suffix = Path(path).suffix.lower()
        if suffix in RUNTIME_SUFFIXES:
            return "runtime"
        if suffix in SCAN_SUFFIXES:
            return "scan"
    if text is not None:
        import tomllib

        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return "runtime"
        if isinstance(document, dict) and (
            "meta" in document or "settings" in document or "rule" in document
        ):
            return "scan"
    return "runtime"


def _lint_runtime(path: str | None, args) -> int:
    """Lint a runtime (YAML) policy with the runtime linter."""
    from ..lint import lint_policy, render_human, to_sarif

    try:
        report = lint_policy(
            path,
            base_dir=Path(args.base_dir) if getattr(args, "base_dir", None) else None,
        )
    except FileNotFoundError:
        return fail(f"policy file not found: {path}", EXIT_ERROR)
    except IsADirectoryError:
        return fail(f"policy file is a directory: {path}", EXIT_ERROR)
    except OSError as exc:
        return fail(f"policy file {path} could not be read: {exc}", EXIT_ERROR)

    if args.json or args.format == "json":
        print(json.dumps(to_sarif(report), indent=2, ensure_ascii=False))
    else:
        print(render_human(report))
    return report.exit_code(strict=bool(args.strict))


def _lint_scan(path: str | None, args) -> int:
    """Lint an offline (TOML) policy with the scanner linter."""
    from ..core.lint import lint_policy

    if path is None:
        from ..core.policy import parse_policy

        policy, issues = parse_policy(default_policy_doc(), "<built-in default>")
        issues.extend(lint_policy(policy))
        source = "<built-in default>"
    else:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            return fail(f"cannot read policy file {path!r}: {exc}", EXIT_ERROR)
        issues = lint_scan_text(text, path)
        source = path

    errors = [issue for issue in issues if issue.severity >= Severity.HIGH]
    warnings = [issue for issue in issues if issue.severity < Severity.HIGH]

    if args.json or args.format == "json":
        print(
            render_json(
                {
                    "source": source,
                    "ok": not errors and not (args.strict and warnings),
                    "errors": len(errors),
                    "warnings": len(warnings),
                    "issues": [issue.to_dict() for issue in issues],
                }
            )
        )
    else:
        print(f"policy: {source}")
        print(f"errors: {len(errors)}  warnings: {len(warnings)}")
        for issue in issues:
            print(f"  {issue.to_text()}")

    if errors:
        return EXIT_FINDINGS
    if args.strict and warnings:
        return EXIT_FINDINGS
    return EXIT_OK


def run(args) -> int:
    """Execute the ``policy-lint`` command."""
    path = args.policy_file
    if path is None:
        # Without a file there is only the built-in default policy, which is a
        # scan policy.
        return _lint_scan(None, args)
    text: str | None = None
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        text = None
    kind = detect_policy_kind(path, text)
    if kind == "scan":
        return _lint_scan(path, args)
    return _lint_runtime(path, args)

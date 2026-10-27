"""``mcp-guard sanitize-output`` - strip terminal escape sequences."""

from __future__ import annotations

import sys

from ..plugins.ansi_sanitize import sanitize_text
from .common import fail, read_text_argument
from .output import EXIT_ERROR, EXIT_OK, render_json

__all__ = ["run"]


def run(args) -> int:
    """Execute the ``sanitize-output`` command."""
    if args.file in (None, "-") and sys.stdin.isatty() and not args.stdin:
        return fail("no input given; pass a file or pipe data on stdin", EXIT_ERROR)

    try:
        payload = read_text_argument(args.file)
    except OSError as exc:
        return fail(f"cannot read input: {exc}", EXIT_ERROR)

    result = sanitize_text(
        payload,
        allow_ansi=args.keep_ansi,
        max_chars=args.max_chars or 0,
        strip_control=not args.keep_control,
        strip_bidi=not args.keep_bidi,
    )

    if args.format == "json":
        payload_dict = result.to_dict()
        payload_dict["text"] = result.text
        print(render_json(payload_dict))
    else:
        sys.stdout.write(result.text)
        if result.text and not result.text.endswith("\n"):
            sys.stdout.write("\n")

    if args.fail_on_change and result.changed:
        return 1
    return EXIT_OK

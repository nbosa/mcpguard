"""The unified ``mcp-guard`` command line interface.

The interface is one executable with nine commands; see
:func:`mcp_guard.cli.main.main` for the list.  The sub-modules hold one
command each, so that a command can be imported and called on its own.
"""

from .main import build_parser, main
from .cmd_runtime import EXIT_BROKEN, EXIT_CONFLICT, EXIT_KEY, EXIT_OK, EXIT_USAGE, run_proxy


def _run(options, upstream):
    options.upstream = upstream
    return run_proxy(options)


__all__ = [
    "main",
    "build_parser",
    "_run",
    "EXIT_OK",
    "EXIT_BROKEN",
    "EXIT_USAGE",
    "EXIT_KEY",
    "EXIT_CONFLICT",
    "cmd_check",
    "cmd_policy_lint",
    "cmd_selftest",
    "cmd_pin_manifest",
    "cmd_sanitize_output",
    "cmd_canary_check",
    "cmd_runtime",
]

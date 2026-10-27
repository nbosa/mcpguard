"""The unified ``mcp-guard`` command line interface.

One executable, nine commands, two halves:

**The runtime half**

``proxy``
    run the policy-enforcing proxy in front of an upstream MCP server;
``verify-audit``
    verify the hash chain and the keyed HMAC chain of an audit log;
``rotate-key``
    rotate the key of an audit log onto a new key file;
``keygen``
    create a new audit chain key file;

**The offline half**

``check``
    run the four guard plugins over a recorded transcript;
``policy-lint``
    statically check a runtime (YAML) or scan (TOML) policy;
``selftest``
    run the embedded verification suite of both halves;
``pin-manifest``
    create, verify or show an ETDI pin manifest;
``sanitize-output``
    strip terminal escape sequences from a payload;
``canary-check``
    look for canary tokens and honeypot URIs in a payload.

The old names ``run``, ``verify`` and ``verify-log`` still work; they are
aliases of ``proxy`` and ``verify-audit``.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from typing import Sequence

from ..version import RELEASE_CODENAME, VERSION_STRING
from . import (
    cmd_canary,
    cmd_check,
    cmd_pin_manifest,
    cmd_policy_lint,
    cmd_runtime,
    cmd_sanitize,
    cmd_selftest,
)

__all__ = ["main", "build_parser"]

_DESCRIPTION = (
    "A policy-enforcing proxy and offline scanner for Model Context Protocol agents."
)

_EPILOG = """\
examples:
  mcp-guard proxy --policy policy.yaml --audit audit.jsonl -- server-command
  mcp-guard verify-audit audit.jsonl --audit-key-file key.bin
  mcp-guard check transcript.json --format json
  mcp-guard policy-lint policy.yaml
  mcp-guard selftest
"""

#: Every option the command line interface knows, so that a mistyped one can
#: be answered with a suggestion instead of a bare complaint.
KNOWN_OPTIONS = [
    "--version",
    "--help",
    "--policy",
    "--audit",
    "--upstream-timeout",
    "--upstream-init-timeout",
    "--out",
    "--new-key-file",
    "--json",
    "--strict",
    "--base-dir",
    "--format",
    "--fail-on",
    "--pins",
    "--etdi",
    "--plugin",
    "--quiet",
    "--verbose",
    "--stdin",
    "--keep-ansi",
    "--keep-control",
    "--input",
    "--output",
    "--generated-at",
    "--audit-key-file",
    "--audit-keyring",
    "--audit-checkpoint-interval",
    "--ttl",
    "--legacy-unkeyed",
    "--session-id",
    "--allow-legacy",
    "--require-keyed",
    "--force",
    "--canary-tokens",
]


# ---------------------------------------------------------------------------
# the runtime options
# ---------------------------------------------------------------------------

FLAG = "--%s"

KEY_OPTIONS = [
    (
        FLAG % "audit-key-file",
        "file holding the audit chain key (mode 0600); MCP_GUARD_AUDIT_KEY_FILE and "
        "MCP_GUARD_AUDIT_KEY are the fallbacks",
    ),
    (
        FLAG % "audit-keyring",
        "key ring (JSON, mode 0600) holding every key the log has been signed with; needed to "
        "verify a rotated log, or MCP_GUARD_AUDIT_KEYRING",
    ),
    (
        FLAG % "audit-checkpoint-interval",
        "how many records between two checkpoints of the keyed chain (default 100, or "
        "MCP_GUARD_AUDIT_CHECKPOINT_INTERVAL)",
    ),
    (FLAG % "ttl", "number of seconds after which the session refuses every further call"),
]
FLAG_OPTIONS = [
    (
        FLAG % "legacy-unkeyed",
        "write the legacy unkeyed hash chain even when a key is configured; it cannot detect a "
        "full rewrite",
    ),
    (FLAG % "session-id", "override the generated session id (used by the tests)"),
    (FLAG % "base-dir", "directory relative paths are resolved against (default: the working directory)"),
    (
        FLAG % "allow-legacy",
        "accept a legacy unkeyed log (exit 0) instead of refusing it (exit 3); such a log "
        "authenticates nothing, so only pass this on purpose",
    ),
    (FLAG % "require-keyed", "deprecated no-op: a keyed log is what verify requires by default now"),
    (FLAG % "force", "replace an existing key file / rotate even if the key ring holds the new key id"),
]
VALUE_OPTIONS = {
    FLAG % "audit-key-file",
    FLAG % "audit-keyring",
    FLAG % "audit-checkpoint-interval",
    FLAG % "ttl",
    FLAG % "base-dir",
    FLAG % "session-id",
}
INT_OPTIONS = {FLAG % "audit-checkpoint-interval", FLAG % "ttl"}


def _add(parser: argparse.ArgumentParser, options: list[tuple[str, str]]) -> None:
    """Add a table of ``(flag, help)`` rows to a subcommand."""
    for flag, text in options:
        if flag not in VALUE_OPTIONS:
            parser.add_argument(flag, action="store_true", help=text)
        elif flag in INT_OPTIONS:
            parser.add_argument(flag, type=int, default=None, help=text)
        else:
            parser.add_argument(flag, default=None, help=text)


# ---------------------------------------------------------------------------
# the parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser of the command line interface."""
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcp-guard {VERSION_STRING} ({RELEASE_CODENAME})",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    _add_proxy(subparsers)
    _add_verify_audit(subparsers)
    _add_rotate_key(subparsers)
    _add_keygen(subparsers)
    _add_check(subparsers)
    _add_policy_lint(subparsers)
    _add_selftest(subparsers)
    _add_pin_manifest(subparsers)
    _add_sanitize_output(subparsers)
    _add_canary_check(subparsers)
    return parser


def _add_proxy(subparsers) -> None:
    proxy = subparsers.add_parser(
        "proxy",
        aliases=["run"],
        help="run the proxy in front of an upstream MCP server",
        description=(
            "Run the policy-enforcing proxy.  Everything after '--' is the upstream command."
        ),
    )
    proxy.add_argument("--policy", required=True, help="path of the YAML policy file")
    proxy.add_argument("--audit", default=None, help="path of the JSONL audit log to append to")
    proxy.add_argument(
        "--upstream-timeout",
        type=float,
        default=120.0,
        help="how many seconds the upstream may take to answer one request (default 120)",
    )
    proxy.add_argument(
        "--upstream-init-timeout",
        type=float,
        default=30.0,
        help="how many seconds the upstream may take to complete the initialize handshake (default 30)",
    )
    proxy.add_argument(
        "--canary-tokens",
        default=None,
        help="path of an mcp-canary bundle JSON file to block outbound token exfiltration",
    )
    _add(proxy, KEY_OPTIONS + FLAG_OPTIONS)
    proxy.set_defaults(func=cmd_runtime.run_proxy)


def _add_verify_audit(subparsers) -> None:
    verify = subparsers.add_parser(
        "verify-audit",
        aliases=["verify", "verify-log"],
        help="verify the hash chain and the HMAC chain of an audit log",
    )
    verify.add_argument("path", help="path of the JSONL audit log")
    _add(verify, KEY_OPTIONS + FLAG_OPTIONS)
    verify.set_defaults(func=cmd_runtime.run_verify_audit)


def _add_rotate_key(subparsers) -> None:
    rotate = subparsers.add_parser(
        "rotate-key", help="rotate the key of an audit log onto a new key file"
    )
    rotate.add_argument("--audit", required=True, help="path of the JSONL audit log to rotate")
    rotate.add_argument("--new-key-file", required=True, help="the key file to rotate onto")
    _add(rotate, KEY_OPTIONS + [FLAG_OPTIONS[-1]])
    rotate.set_defaults(func=cmd_runtime.run_rotate_key)


def _add_keygen(subparsers) -> None:
    keygen = subparsers.add_parser("keygen", help="create a new audit chain key file")
    keygen.add_argument("--out", required=True, help="path of the key file to create (mode 0600)")
    keygen.add_argument("--force", action="store_true", help="overwrite an existing key file")
    keygen.set_defaults(func=cmd_runtime.run_keygen)


def _add_check(subparsers) -> None:
    check = subparsers.add_parser(
        "check",
        help="check a transcript for policy violations",
        description="Run every enabled plugin over a transcript document.",
    )
    check.add_argument(
        "target",
        nargs="?",
        default="-",
        help="path to a JSON transcript document ('-' for stdin, the default)",
    )
    check.add_argument("--policy", help="policy file to apply (default: built-in)")
    check.add_argument(
        "--fail-on",
        metavar="LEVEL",
        help="override the policy failure threshold (INFO|LOW|MEDIUM|HIGH|CRITICAL)",
    )
    check.add_argument("--pins", help="ETDI pin manifest to verify the tool surface against")
    check.add_argument("--etdi", help="ETDI document describing the live tool surface")
    check.add_argument(
        "--plugin",
        action="append",
        metavar="NAME",
        help="restrict the run to the given plugin (repeatable)",
    )
    check.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    check.add_argument("--quiet", action="store_true", help="print only the verdict")
    check.set_defaults(func=cmd_check.run)


def _add_policy_lint(subparsers) -> None:
    lint = subparsers.add_parser(
        "policy-lint",
        help="validate a policy file",
        description=(
            "Report structural and semantic problems in a policy.  A YAML file is checked as a "
            "runtime policy, a TOML file as an offline scan policy."
        ),
    )
    lint.add_argument(
        "policy_file",
        nargs="?",
        default=None,
        help="policy file to lint (default: the built-in policy)",
    )
    lint.add_argument(
        "--json",
        action="store_true",
        help="write the report as JSON (SARIF-lite for a runtime policy)",
    )
    lint.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    lint.add_argument("--strict", action="store_true", help="treat warnings as errors")
    lint.add_argument(
        "--base-dir",
        default=None,
        help="directory the relative path prefixes are resolved against",
    )
    lint.set_defaults(func=cmd_policy_lint.run)


def _add_selftest(subparsers) -> None:
    selftest = subparsers.add_parser(
        "selftest",
        help="run the built-in verification suite",
        description=(
            "Exercise the proxy, the audit chain, the canary detector, every plugin, the default "
            "policy and the sample transcripts."
        ),
    )
    selftest.add_argument(
        "--verbose", action="store_true", help="print detail for passing cases too"
    )
    selftest.add_argument(
        "--json", action="store_true", help="write the report as JSON"
    )
    selftest.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    selftest.set_defaults(func=cmd_selftest.run)


def _add_pin_manifest(subparsers) -> None:
    pin = subparsers.add_parser(
        "pin-manifest",
        help="create, verify or show ETDI pin manifests",
        description="Manage the frozen fingerprint of a tool surface.",
    )
    pin_sub = pin.add_subparsers(dest="action", metavar="<action>")

    create = pin_sub.add_parser("create", help="pin an ETDI document")
    create.add_argument("--input", required=True, help="ETDI document ('-' for stdin)")
    create.add_argument("--output", help="write the manifest here (default: stdout)")
    create.add_argument("--generated-at", help="timestamp recorded in the manifest")

    verify = pin_sub.add_parser("verify", help="verify an ETDI document against pins")
    verify.add_argument("--pins", required=True, help="pin manifest")
    verify.add_argument("--input", required=True, help="ETDI document ('-' for stdin)")
    verify.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )

    show = pin_sub.add_parser("show", help="show the contents of a pin manifest")
    show.add_argument("--pins", required=True, help="pin manifest")
    show.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    pin.set_defaults(func=cmd_pin_manifest.run)


def _add_sanitize_output(subparsers) -> None:
    sanitize = subparsers.add_parser(
        "sanitize-output",
        help="strip terminal escape sequences from a payload",
        description="Remove ANSI escape sequences, overwrite tricks and bidi overrides.",
    )
    sanitize.add_argument(
        "file", nargs="?", default="-", help="payload file ('-' for stdin, the default)"
    )
    sanitize.add_argument("--stdin", action="store_true", help="read from stdin explicitly")
    sanitize.add_argument("--keep-ansi", action="store_true", help="keep ANSI escape sequences")
    sanitize.add_argument(
        "--keep-control", action="store_true", help="keep other control characters"
    )
    sanitize.add_argument(
        "--keep-bidi", action="store_true", help="keep bidirectional override characters"
    )
    sanitize.add_argument(
        "--max-chars", type=int, default=0, help="truncate the sanitized output"
    )
    sanitize.add_argument(
        "--fail-on-change",
        action="store_true",
        help="exit with code 1 when the payload was modified",
    )
    sanitize.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    sanitize.add_argument("--output", help="write the result here (default: stdout)")
    sanitize.set_defaults(func=cmd_sanitize.run)


def _add_canary_check(subparsers) -> None:
    canary = subparsers.add_parser(
        "canary-check",
        help="look for canary tokens in a payload",
        description="Scan a payload for registered canary tokens and honeypot URIs.",
    )
    canary.add_argument(
        "file", nargs="?", default="-", help="payload file ('-' for stdin, the default)"
    )
    canary.add_argument("--stdin", action="store_true", help="read from stdin explicitly")
    canary.add_argument("--policy", help="policy file to apply (default: built-in)")
    canary.add_argument(
        "--token",
        action="append",
        metavar="TOKEN",
        help="register a canary token to look for (repeatable)",
    )
    canary.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    canary.set_defaults(func=cmd_canary.run)


# ---------------------------------------------------------------------------
# argument handling
# ---------------------------------------------------------------------------


def _split_upstream(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split ``argv`` at the first ``--`` into (own arguments, upstream command)."""
    arguments = list(argv)
    if "--" in arguments:
        index = arguments.index("--")
        return arguments[:index], arguments[index + 1 :]
    return arguments, []


def _suggest(argument: str) -> str | None:
    """The known option that looks most like ``argument`` (if there is one)."""
    matches = difflib.get_close_matches(argument, KNOWN_OPTIONS, n=1, cutoff=0.6)
    return matches[0] if matches else None


def _refuse_unknown(extra: Sequence[str]) -> int:
    """Refuse an option mcp-guard does not know, the way argparse refuses one.

    A flag that is spelled wrong used to be accepted and did nothing, which is
    the worst of both worlds: the operator believes a safety property is on
    (``--upstream-timout 5`` leaves the upstream without its deadline) and it
    is not.  The name of the offending flag is printed, and so is the closest
    known flag, if there is one.
    """
    for argument in extra:
        print(f"mcp-guard: error: unrecognized argument: {argument}", file=sys.stderr)
        suggestion = _suggest(argument)
        if suggestion is not None:
            print(f"mcp-guard: error: did you mean {suggestion}?", file=sys.stderr)
    print(
        "mcp-guard: error: if the argument belongs to the upstream command, "
        'put it after "--"',
        file=sys.stderr,
    )
    return cmd_runtime.EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``mcp-guard`` executable."""
    raw = list(sys.argv[1:] if argv is None else argv)
    own, upstream = _split_upstream(raw)

    parser = build_parser()
    options, extra = parser.parse_known_args(own)
    if extra:
        # An option mcp-guard does not know is a usage error, never a silent
        # no-op.  The only exception is a command that is meant for the
        # upstream: it has to come after "--", because without it there is no
        # way to tell our mistyped flag from the upstream's own options.
        if upstream:
            return _refuse_unknown(extra)
        options_only = [
            argument for argument in extra if argument.startswith("-") and argument != "-"
        ]
        if options_only:
            return _refuse_unknown(options_only)
        if options.command in ("policy-lint", "selftest"):
            # Neither of them runs an upstream, so a second positional argument
            # is a mistake and not the beginning of a command line.
            return cmd_runtime.fail(
                f"{options.command} takes no further arguments (got {extra[0]!r})",
                cmd_runtime.EXIT_USAGE,
            )
        upstream = extra

    if options.command in ("proxy", "run"):
        cli_mod = sys.modules.get("mcp_guard.cli")
        runner = getattr(cli_mod, "_run", None) if cli_mod else None
        if runner is not None:
            return runner(options, upstream)
        options.upstream = upstream
        return cmd_runtime.run_proxy(options)
    if options.command in ("verify-audit", "verify", "verify-log"):
        return cmd_runtime.run_verify_audit(options)
    if options.command == "rotate-key":
        return cmd_runtime.run_rotate_key(options)
    if options.command == "keygen":
        return cmd_runtime.run_keygen(options)

    handler = getattr(options, "func", None)
    if handler is None:
        if not getattr(options, "command", None):
            parser.print_help(sys.stdout)
        else:
            parser.print_usage(sys.stderr)
        return cmd_runtime.EXIT_USAGE
    return handler(options)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

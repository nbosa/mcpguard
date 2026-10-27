"""The runtime half of the command line interface.

Four commands live here:

``proxy``
    run the policy-enforcing proxy in front of an upstream MCP server;
``verify-audit``
    verify the hash chain and the keyed HMAC chain of an audit log;
``rotate-key``
    rotate the key of an audit log onto a new key file;
``keygen``
    create a new audit chain key file.

The exit codes are the ones the runtime half has always used: ``0`` ``OK``,
``1`` ``BROKEN``, ``2`` ``WARN`` or a usage error, ``3`` ``REFUSED`` (an
unaccepted legacy log) or ``KEY`` (no usable key), and ``64`` for two
contradictory flags.  ``3`` always means "I could not authenticate this",
never "this was tampered with".
"""

from __future__ import annotations

import json
import math
import secrets
import sys
from pathlib import Path

from ..audit import (
    STATUS_BROKEN,
    STATUS_KEY,
    STATUS_OK,
    STATUS_REFUSED,
    STATUS_WARN,
    AuditError,
    AuditLog,
    VerifyResult,
    verify_log,
)
from ..keys import (
    AuditKey,
    AuditKeyError,
    KeyRing,
    generate_key,
    read_key_file,
    resolve_checkpoint_interval,
    write_key_file,
)
from ..policy import PolicyError, load_policy

__all__ = [
    "EXIT_OK",
    "EXIT_BROKEN",
    "EXIT_USAGE",
    "EXIT_KEY",
    "EXIT_CONFLICT",
    "fail",
    "run_proxy",
    "run_verify_audit",
    "run_rotate_key",
    "run_keygen",
]

EXIT_OK = 0
EXIT_BROKEN = 1
EXIT_USAGE = 2
EXIT_KEY = 3

#: ``sysexits.h``'s EX_USAGE, used only where the operator asked for two things
#: that contradict each other.  Every other usage error stays at 2.
EXIT_CONFLICT = 64

#: The five outcomes of ``verify-audit`` and the exit code each one maps onto.
EXIT_CODES = {
    STATUS_OK: EXIT_OK,
    STATUS_BROKEN: EXIT_BROKEN,
    STATUS_WARN: EXIT_USAGE,
    STATUS_REFUSED: EXIT_KEY,
    STATUS_KEY: EXIT_KEY,
}


def fail(message: object, code: int = EXIT_USAGE) -> int:
    """Print one operator-facing error on stderr and return its exit code."""
    print(f"mcp-guard: {message}", file=sys.stderr)
    return code


# ---------------------------------------------------------------------------
# proxy
# ---------------------------------------------------------------------------


def run_proxy(args) -> int:
    """Execute the ``proxy`` command."""
    from ..proxy import (  # imported late: only the proxy needs the MCP SDK
        DEFAULT_UPSTREAM_INIT_TIMEOUT,
        DEFAULT_UPSTREAM_TIMEOUT,
        EXIT_UPSTREAM_INIT,
        MCPGuardProxy,
        ProxyConfig,
    )

    # G-19: the numbers are checked first.  A timeout that is not a number is
    # a mistake in the option the operator wrote, and saying so is more useful
    # than saying that the upstream command is missing.
    for name, value in (
        ("--ttl", args.ttl),
        ("--upstream-timeout", args.upstream_timeout),
        ("--upstream-init-timeout", args.upstream_init_timeout),
    ):
        if value is not None and (math.isnan(value) or not math.isfinite(value) or value <= 0):
            return fail(f"{name} must be a positive number of seconds", EXIT_USAGE)

    upstream = list(getattr(args, "upstream", None) or [])
    if not upstream:
        return fail(
            "no upstream command given (use: mcp-guard proxy ... -- <server command>)",
            EXIT_USAGE,
        )

    try:
        policy = load_policy(args.policy)
        checkpoint_interval = resolve_checkpoint_interval(args.audit_checkpoint_interval)
    except (PolicyError, ValueError) as exc:
        return fail(exc, EXIT_USAGE)

    def optional(value: str | None) -> Path | None:
        return Path(value) if value else None

    config = ProxyConfig(
        upstream_command=upstream,
        policy=policy,
        audit_path=optional(args.audit),
        ttl_seconds=args.ttl,
        session_id=args.session_id or secrets.token_hex(16),
        base_dir=Path(args.base_dir).resolve() if args.base_dir else Path.cwd(),
        audit_key_file=optional(args.audit_key_file),
        audit_keyring=optional(args.audit_keyring),
        audit_legacy=bool(args.legacy_unkeyed),
        checkpoint_interval=checkpoint_interval,
        upstream_timeout=args.upstream_timeout,
        upstream_init_timeout=args.upstream_init_timeout,
        canary_bundle=optional(getattr(args, "canary_tokens", None)),
    )
    try:
        proxy = MCPGuardProxy(config)
    except (AuditKeyError, AuditError) as exc:
        return fail(exc, EXIT_KEY if isinstance(exc, AuditKeyError) else EXIT_BROKEN)
    except FileNotFoundError as exc:
        return fail(f"file not found: {exc.filename}", EXIT_USAGE)
    except (OSError, ValueError) as exc:
        return fail(str(exc), EXIT_USAGE)

    try:
        import anyio
    except ImportError:
        return fail(
            "the MCP SDK is not installed; run 'pip install mcp-guard[proxy]' to use the proxy "
            "command.  The offline commands (check, policy-lint, selftest, ...) need no SDK.",
            EXIT_USAGE,
        )

    try:
        return anyio.run(proxy.run)
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        return EXIT_OK
    except (AuditKeyError, AuditError) as exc:
        return fail(exc, EXIT_KEY if isinstance(exc, AuditKeyError) else EXIT_BROKEN)


# ---------------------------------------------------------------------------
# verify-audit
# ---------------------------------------------------------------------------


def _report(result: VerifyResult) -> None:
    """Print the outcome of :func:`verify_log`."""
    if result.status == STATUS_BROKEN:
        print(f"BROKEN: line {result.broken_line}: {result.reason}")
        return
    if result.status == STATUS_REFUSED:
        print(f"REFUSED: {result.reason}")
        return
    if result.status == STATUS_KEY:
        print(f"KEY ERROR: {result.reason}")
        return
    if result.status == STATUS_WARN:
        print(
            f"WARN: {result.records} record(s) verified, HMAC-SHA256 chain intact, {result.reason}"
        )
        print(
            f"     {result.checkpoints} checkpoint(s), {result.rotations} rotation(s), "
            f"key {result.key_id}"
        )
        return

    if result.keyed:
        detail = f"HMAC-SHA256 chain intact, key {result.key_id}"
        if result.rotations:
            detail += f" (first written with key {result.first_key_id})"
        print(
            f"OK: {result.records} record(s) verified, {detail}, {result.checkpoints} checkpoint(s), "
            f"{result.rotations} rotation(s)"
        )
        return

    print(f"OK: {result.records} record(s) verified, hash chain intact")
    print(
        "     this is a LEGACY unkeyed chain: it has no MAC, so a full rewrite with recomputed "
        "hashes is not detectable. mcp-guard refuses such a log by default (exit 3); --allow-legacy "
        "is what accepted it.",
        file=sys.stderr,
    )


def run_verify_audit(args) -> int:
    """Execute the ``verify-audit`` command."""
    if args.require_keyed and args.allow_legacy:
        return fail(
            "--require-keyed and --allow-legacy contradict each other: one asks for a keyed log, the "
            "other accepts an unkeyed one. Drop --require-keyed (it is the default and deprecated).",
            EXIT_CONFLICT,
        )
    if args.require_keyed:
        print(
            "mcp-guard: --require-keyed is deprecated and now does nothing: mcp-guard verify-audit "
            "refuses an unkeyed log by default. It is kept so old scripts keep running.",
            file=sys.stderr,
        )
    try:
        result = verify_log(
            args.path,
            key_file=args.audit_key_file,
            keyring=args.audit_keyring,
            allow_legacy=bool(args.allow_legacy),
            checkpoint_interval=args.audit_checkpoint_interval,
        )
    except AuditKeyError as exc:
        # The verdict always goes to stdout, so a caller reads one line whatever
        # went wrong.
        print(f"KEY ERROR: {exc}")
        return EXIT_KEY
    _report(result)
    return EXIT_CODES[result.status]


# ---------------------------------------------------------------------------
# rotate-key / keygen
# ---------------------------------------------------------------------------


def run_rotate_key(args) -> int:
    """Execute the ``rotate-key`` command."""
    ring_path = Path(args.audit_keyring) if args.audit_keyring else None
    try:
        new_key = AuditKey.from_material(read_key_file(args.new_key_file))
        # The precondition is checked *before* the writer is opened: a refused
        # rotation must not touch the log at all, and opening the writer would
        # seal it with a checkpoint even when nothing is rotated.
        if ring_path is not None and ring_path.exists() and not args.force:
            if new_key.key_id in KeyRing.load(ring_path):
                return fail(f"key {new_key.key_id} is already in {ring_path}", EXIT_USAGE)
        with AuditLog(
            args.audit,
            "mcp-guard-rotate-key",
            key_file=args.audit_key_file,
            # An existing ring is needed to continue an already rotated log; one
            # that does not exist yet is created below.
            keyring=ring_path if ring_path is not None and ring_path.exists() else None,
        ) as log:
            if not log.keyed:
                return fail(
                    f"{args.audit} is an unkeyed legacy chain; there is no key to rotate",
                    EXIT_BROKEN,
                )
            previous_key = log.key
            record = log.rotate(new_key)
            if ring_path is not None:
                keyring = KeyRing.load(ring_path) if ring_path.exists() else KeyRing(path=ring_path)
                # The ring must hold every key the log is signed with, the one it
                # rotates away from included, or the log cannot be verified.
                if previous_key is not None:
                    keyring.add(previous_key)
                try:
                    keyring.add(new_key).save()
                except AuditKeyError as exc:
                    # The rotation is committed, so the log needs the new key to
                    # be verifiable at all: this is not a usage error.
                    return fail(
                        f"the log was rotated onto key {new_key.key_id} but the key ring "
                        f"{ring_path} was not updated: {exc}",
                        EXIT_BROKEN,
                    )
    except (AuditKeyError, AuditError) as exc:
        return fail(exc, EXIT_KEY if isinstance(exc, AuditKeyError) else EXIT_BROKEN)
    print(
        f"rotated {args.audit} from key {record['rotation']['previous_key_id']} onto key "
        f"{record['rotation']['key_id']} (rotation at record {record['rotation']['records'] + 1})"
    )
    if ring_path is not None:
        print(f"added the new key to {ring_path}")
    return EXIT_OK


def run_keygen(args) -> int:
    """Execute the ``keygen`` command."""
    try:
        key = generate_key()
        path = write_key_file(args.out, key.material, force=args.force)
    except AuditKeyError as exc:
        return fail(exc, EXIT_KEY)
    print(f"wrote a new audit key to {path} (mode 0600, key id {key.key_id})")
    print("the key itself is never printed and never written to the audit log")
    return EXIT_OK

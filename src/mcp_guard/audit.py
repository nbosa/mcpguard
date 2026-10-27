"""The append-only, keyed audit log: one JSON object per line, two chains.

Every record carries the plain SHA-256 ``hash`` chain of 0.1 and, on a keyed log,
an HMAC-SHA256 ``mac`` chain over it.  The plain chain detects a local edit, the
keyed one a whole file rewrite; checkpoint and rotation records live in the same
chain.  Deleting the keyed fields defeats the MAC and leaves something
indistinguishable from a pre-0.2 log, so a chain that verifies without a MAC
anywhere is refused unless ``allow_legacy`` is set.

``docs/DESIGN.md`` section 1 has the format and the full argument.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:  # pragma: no cover - the POSIX branch is the one that is exercised
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - the Windows branch is the one that is exercised
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]

from .keys import (
    DEFAULT_CHECKPOINT_INTERVAL,
    AuditKey,
    AuditKeyError,
    KeyResolver,
    resolve_checkpoint_interval,
    write_private_file,
)
from .redact import redact_arguments, scrub_reason

#: The ``chain`` field of a keyed record, and the domain separator of the MAC.
CHAIN_HMAC = "hmac-sha256-v1"
MAC_DOMAIN = b"mcp-guard-audit-mac-v1"

#: Not part of the MAC input: a MAC cannot cover itself, and it covers
#: ``prev_mac`` separately, by concatenation.
MAC_EXCLUDED_FIELDS = ("hash", "mac", "prev_mac")

#: The kind of a record that is not a checkpoint or a rotation.
DECISION = "record"
CHECKPOINT = "checkpoint"
ROTATION = "rotation"
RECORD_TYPES = (DECISION, CHECKPOINT, ROTATION)

#: Record types that only a keyed log has: any of them proves it was keyed.
KEYED_RECORD_TYPES = (CHECKPOINT, ROTATION)

#: The all-zero first link of both chains: a log that lost its head is detected.
ZERO_HASH = "0" * 64
ZERO_MAC = "0" * 64

#: Fields every audit record carries.
REQUIRED_FIELDS = ( "timestamp", "session_id", "method", "tool_name", "arguments",
                    "decision", "reason", "upstream_latency_ms", "prev_hash", "hash",
)

#: The fields only a keyed record carries, and the ones a downgrade deletes.
KEYED_FIELDS = ("chain", "record_type", "key_id", "prev_mac", "mac")
KEYED_MARKER_FIELDS = ("mac", "prev_mac", "key_id", "chain")

#: The sidecar of a keyed log: ``audit.jsonl`` -> ``audit.jsonl.keyed``.
SENTINEL_SUFFIX = ".keyed"

# Verification outcomes; the command line maps them onto its exit codes.  REFUSED
# is a chain that verified but carries no MAC at all, and was not accepted.
STATUS_OK = "OK"
STATUS_BROKEN = "BROKEN"
STATUS_WARN = "WARN"
STATUS_KEY = "KEY"
STATUS_REFUSED = "REFUSED"

class AuditError(Exception):
    """An audit log cannot be written, appended to or trusted."""

class _WriterLock:
    """An exclusive advisory lock on one audit log, held for the writer's life.

    Two writers on one log would both adopt the same tail and both chain from
    it, so the file ends up with two records claiming the same predecessor: the
    chain is broken and there is no diagnostic that says why.  The lock turns
    that into a clean refusal instead -- the second writer is told that another
    writer holds the log, and nothing is written.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: Any = None

    def acquire(self) -> None:
        """Take the lock, or raise :class:`AuditError`."""
        try:
            self._handle = self.path.open("a+")
        except OSError as exc:
            raise AuditError(
                f"refusing to append to {self.path}: the log could not be opened ({exc.strerror})"
            ) from None
        try:
            if fcntl is not None:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif msvcrt is not None:  # pragma: no cover - Windows
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            self._release_handle()
            raise AuditError(
                f"refusing to append to {self.path}: another writer holds it ({exc.strerror})"
            ) from None

    def release(self) -> None:
        """Give the lock back; safe to call more than once."""
        if self._handle is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - Windows
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:  # pragma: no cover - the handle is closed anyway
            pass
        self._release_handle()

    def _release_handle(self) -> None:
        """Close the lock handle, if there is one."""
        handle, self._handle = self._handle, None
        if handle is not None:
            handle.close()

def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


#: The outcomes an audit record can carry, as distinct from the decision the
#: policy reached (G-15).
OUTCOME_ALLOWED = "allowed"
OUTCOME_BLOCKED = "blocked"
OUTCOME_UPSTREAM_ERROR = "upstream_error"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_CHECKPOINT = "checkpoint"
OUTCOMES = (
    OUTCOME_ALLOWED,
    OUTCOME_BLOCKED,
    OUTCOME_UPSTREAM_ERROR,
    OUTCOME_TIMEOUT,
    OUTCOME_CHECKPOINT,
)


def default_outcome(decision: str) -> str:
    """The outcome that belongs to a decision when nothing else is known."""
    if decision == "allow":
        return OUTCOME_ALLOWED
    return OUTCOME_BLOCKED

def _canonical_default(obj: Any) -> str:
    """Stable placeholder for unserializable types to ensure reproducibility (G-10)."""
    return f"<unserialisable argument of type {type(obj).__name__}>"

def canonical_json(payload: Any) -> str:
    """Serialise ``payload`` to the canonical form used for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_canonical_default)

def compute_hash(record: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of ``record`` without its ``hash`` field."""
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

def mac_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    """The part of ``record`` the MAC is computed over."""
    return {key: value for key, value in record.items() if key not in MAC_EXCLUDED_FIELDS}

def compute_mac(record: Mapping[str, Any], key: bytes, prev_mac: str = ZERO_MAC) -> str:
    """HMAC-SHA256 over the canonical JSON, chained with the predecessor's MAC."""
    payload = canonical_json(mac_payload(record)).encode("utf-8")
    message = MAC_DOMAIN + b"|" + prev_mac.encode("ascii") + b"|" + payload
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def record_type_of(record: Mapping[str, Any]) -> str:
    """The kind of a record: a decision, a checkpoint or a rotation."""
    value = record.get("record_type")
    return value if isinstance(value, str) and value else DECISION

def is_keyed(record: Mapping[str, Any]) -> bool:
    """Whether the record belongs to a keyed (MAC chained) chain."""
    return isinstance(record.get("mac"), str)

def carries_keyed_marker(record: Mapping[str, Any]) -> bool:
    """Whether the record claims the chain is keyed, MAC or not."""
    return is_keyed(record) or record_type_of(record) in KEYED_RECORD_TYPES or any(
        field in record for field in KEYED_MARKER_FIELDS
    )

def sentinel_path(path: str | Path) -> Path:
    """The sidecar that records that a log was created keyed: ``PATH.keyed``."""
    return Path(f"{path}{SENTINEL_SUFFIX}")

def write_sentinel(path: str | Path, key_id: str) -> Path:
    """Write the keyed sentinel: key id and time, never key material."""
    document = {"version": 1, "path": str(path), "key_id": key_id, "created": utc_timestamp()}
    return write_private_file(sentinel_path(path), (canonical_json(document) + "\n").encode("utf-8"))

#: Emitted at most once per process: the log has no integrity guarantee beyond an
#: unkeyed hash chain, and saying it once is enough.
_LEGACY_WARNING_EMITTED = False

def warn_about_legacy_chain() -> None:
    """Say, on stderr, that the log being written authenticates nothing."""
    global _LEGACY_WARNING_EMITTED
    if _LEGACY_WARNING_EMITTED:
        return
    _LEGACY_WARNING_EMITTED = True
    print(
        "mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a "
        "full rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file "
        "(or MCP_GUARD_AUDIT_KEY) for an HMAC chained log.",
        file=sys.stderr,
    )

@dataclass(frozen=True)
class VerifyResult:
    """The outcome of verifying one audit log."""

    ok: bool
    records: int
    broken_line: int | None = None
    reason: str | None = None
    #: ``OK``, ``BROKEN``, ``WARN`` (possible truncation), ``REFUSED`` (an
    #: unaccepted legacy log) or ``KEY``.
    status: str = STATUS_OK

    # The state of the chain when the walk stopped, so a caller can continue it.
    lines: int = 0
    checkpoints: int = 0
    rotations: int = 0
    keyed: bool = False
    key_id: str | None = None
    first_key_id: str | None = None
    tail: int = 0
    last_checkpoint_line: int | None = None
    sealed: bool = False
    last_mac: str = ZERO_MAC
    last_hash: str = ZERO_HASH

    @property
    def truncated(self) -> bool:
        """Whether the log may have lost its tail (the chain is still intact)."""
        return self.status == STATUS_WARN

    def __bool__(self) -> bool:
        return self.ok and not self.truncated

    @property
    def exit_code(self) -> int:
        """The exit code of ``mcp-guard verify``; REFUSED is a key class failure."""
        return {STATUS_OK: 0, STATUS_BROKEN: 1, STATUS_WARN: 2, STATUS_REFUSED: 3, STATUS_KEY: 3}[
            self.status
        ]

def _failure(status: str, reason: str, line: int | None = None, **fields: Any) -> VerifyResult:
    """A verification that did not pass, with its status and first bad line."""
    return VerifyResult(ok=False, records=0, reason=reason, status=status, broken_line=line, **fields)

def _broken(reason: str, line: int | None = None, **fields: Any) -> VerifyResult:
    return _failure(STATUS_BROKEN, reason, line, **fields)

def _key_error(reason: str, line: int | None = None, **fields: Any) -> VerifyResult:
    return _failure(STATUS_KEY, reason, line, **fields)

class _Walk:
    """The running state of one verification pass over a log."""

    def __init__(
        self, resolver: KeyResolver, default_interval: int, *, path: Path | None = None,
        allow_legacy: bool = False, sentinel: bool = False,
    ) -> None:
        self.resolver = resolver
        self.previous_hash = ZERO_HASH
        self.previous_mac = ZERO_MAC
        self.active_key_id: str | None = resolver.key_id
        self.count = 0  # decision records
        self.seen = 0  # every record, checkpoints and rotations included
        self.checkpoints = 0
        self.rotations = 0
        self.keyed = False
        self.path = path
        self.allow_legacy = allow_legacy
        self.sentinel = sentinel
        self.key_id: str | None = None
        self.first_key_id: str | None = None
        self.tail = 0
        self.last_checkpoint_line: int | None = None
        self.sealed = False
        self.interval = default_interval

    def fail(self, result: VerifyResult) -> VerifyResult:
        """Attach the running counts to a failure and return it."""
        return replace(
            result,
            records=self.count,
            lines=self.seen,
            keyed=self.keyed,
            key_id=self.key_id or self.first_key_id,
            first_key_id=self.first_key_id,
        )

    def result(self) -> VerifyResult:
        status = STATUS_OK
        reason: str | None = None
        broken_line: int | None = None
        # Complete means "ends with the clean-shutdown checkpoint of its last
        # writer": a live log, a killed writer and a removed tail look alike.
        if self.keyed and not self.sealed:
            where = (
                f"after the last checkpoint at line {self.last_checkpoint_line}"
                if self.last_checkpoint_line is not None
                else "the log has no checkpoint at all"
            )
            status = STATUS_WARN
            reason = ( f"the log does not end with a clean-shutdown checkpoint ({self.tail} record(s) "
                                   f"{where}, the checkpoint interval is {self.interval}); the writer may still be "
                                   "running, or the tail after the last checkpoint may have been removed"
            )
        elif not self.keyed:
            # The chain is intact but nothing in it is authenticated, and a log
            # whose keyed fields were stripped lands in exactly this place.
            status, reason, broken_line = self._legacy_verdict()
        return VerifyResult(
            ok=status != STATUS_BROKEN,
            records=self.count,
            reason=reason,
            status=status,
            broken_line=broken_line,
            lines=self.seen,
            checkpoints=self.checkpoints,
            rotations=self.rotations,
            keyed=self.keyed,
            key_id=self.key_id or self.first_key_id,
            first_key_id=self.first_key_id,
            tail=self.tail,
            last_checkpoint_line=self.last_checkpoint_line,
            sealed=self.sealed,
            last_mac=self.previous_mac,
            last_hash=self.previous_hash,
        )

    def _legacy_verdict(self) -> tuple[str, str | None, int | None]:
        """What to do with a chain that verified but carries no MAC at all."""
        common = (
            f"{self.count} record(s) verified, hash chain intact, but not one record carries a MAC "
            "or a key id: a keyed log whose mac, prev_mac, key_id and chain fields were stripped is "
            "indistinguishable from this one, so an unkeyed log authenticates nothing"
        )
        if self.sentinel:
            # The sidecar says it was created keyed, so the MACs are gone on purpose.
            return (
                STATUS_BROKEN,
                f"{common}; the keyed sentinel {sentinel_path(self.path)!s} is still there, so this "
                "log was created keyed and its MACs have been removed",
                1,
            )
        if not self.allow_legacy:
            return (
                STATUS_REFUSED,
                f"legacy unkeyed chain: {common}. Pass --allow-legacy to accept an unkeyed log, or "
                "configure the key that signed it",
                None,
            )
        return STATUS_OK, None, None

def read_log_lines(path: str | Path) -> list[str]:
    """The lines of a log, split on newlines and on nothing else.

    ``str.splitlines()`` breaks on nine separators -- ``\\n``, ``\\r``, ``\\r\\n``,
    ``\\v``, ``\\f``, ``\\x1c``, ``\\x1d``, ``\\x1e`` and ``\\x85`` -- plus U+2028
    and U+2029, while a record may legally contain any of them: JSON only
    requires the characters below U+0020 to be escaped, and this writer uses
    ``ensure_ascii=False``, so U+2028, U+2029 and U+0085 are written literally.
    One of them from a client would cut a record in half and make the whole
    chain unverifiable.  The log is JSONL, so the only line break is ``\\n``.

    The file is read with ``newline=""`` so that a CR is not translated away
    before the line is compared with the canonical encoding: a rewritten
    separator has to stay visible.
    """
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        return handle.read().split("\n")

def verify_log(
    path: str | Path,
    *,
    key: bytes | str | AuditKey | None = None,
    key_file: str | Path | None = None,
    keyring: Any = None,
    resolver: KeyResolver | None = None,
    allow_legacy: bool = False,
    require_keyed: bool = False,
    checkpoint_interval: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> VerifyResult:
    """Recompute the chain of an audit log.

    On a keyed log every record must carry a valid MAC under the key that signed
    it, that MAC must chain to its predecessor's, and the first must chain to the
    zero MAC -- so a log that lost its *head* is detected too.  Every checkpoint
    must agree with the running MAC, hash and count.

    A chain that verifies but carries no MAC anywhere is a legacy (pre-0.2) log,
    and since 0.4 that is **refused** (``REFUSED``, exit 3) unless
    ``allow_legacy`` is set: stripping the keyed fields leaves exactly such a
    file.  ``require_keyed`` is a deprecated no-op; ``checkpoint_interval`` is the
    interval assumed for a log that has written no checkpoint yet.

    Returns a :class:`VerifyResult`: ``ok`` is ``True`` when the whole chain
    verifies, else ``broken_line`` is the 1-based number of the *first* bad
    record and ``reason`` says why.  ``docs/DESIGN.md`` section 1 has the rest.
    """
    log_path = Path(path)
    if not log_path.exists():
        return _broken(f"audit log not found: {log_path}", 1)

    try:
        lines = read_log_lines(log_path)
    except UnicodeDecodeError as exc:
        return _broken(f"audit log is not valid UTF-8: {exc}", 1)
    except OSError as exc:
        return _broken(f"audit log could not be read: {exc}", 1)

    if resolver is None:
        resolver = KeyResolver.load(
            material=None if isinstance(key, AuditKey) else key,
            key_file=key_file,
            keyring=keyring,
            environ=environ,
        )
        if isinstance(key, AuditKey):
            resolver.primary = key

    interval = (
        resolve_checkpoint_interval(checkpoint_interval)
        if checkpoint_interval is not None
        else DEFAULT_CHECKPOINT_INTERVAL
    )
    return _verify_lines(
        lines,
        resolver,
        allow_legacy=allow_legacy,
        interval=interval,
        path=log_path,
        sentinel=sentinel_path(log_path).exists(),
    )

def _verify_lines(
    lines: list[str], resolver: KeyResolver, *, allow_legacy: bool, interval: int,
    path: Path | None = None, sentinel: bool = False,
) -> VerifyResult:
    """Walk the records of a log, verifying the hash chain and the MAC chain."""
    walk = _Walk(resolver, interval, path=path, allow_legacy=allow_legacy, sentinel=sentinel)

    def broken(reason: str) -> VerifyResult:
        """The first bad record is always the one the walk stopped on."""
        return walk.fail(_broken(reason, number))

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return broken(f"invalid JSON: {exc}")
        if not isinstance(record, dict):
            return broken("record is not a JSON object")

        missing = [field for field in REQUIRED_FIELDS if field not in record]
        if missing:
            return broken(f"record is missing the field(s) {', '.join(missing)}")

        kind = record_type_of(record)
        if kind not in RECORD_TYPES:
            return broken(f"unknown record type {kind!r}")

        keyed_record = is_keyed(record)
        if not keyed_record:
            # An earlier record proved the chain was keyed, or this one still
            # carries a keyed-only field: a MAC was removed, whatever the flags.
            if walk.keyed or carries_keyed_marker(record):
                return broken("the mac field is gone: an unkeyed record was spliced into a keyed chain")
        else:
            walk.keyed = True

        if record["prev_hash"] != walk.previous_hash:
            return broken(
                f"prev_hash {record['prev_hash']!r} does not match the hash of the previous record "
                f"({walk.previous_hash!r})"
            )

        if keyed_record:
            failure = _verify_mac(walk, record, number, kind)
            if failure is not None:
                return walk.fail(failure)

        expected = compute_hash(record)
        if record["hash"] != expected:
            return broken(f"hash {record['hash']!r} does not match the recomputed hash {expected!r}")

        # The line has to be exactly what this writer produces: the same bytes,
        # the same key order, the same escaping.  A rewritten separator (CRLF,
        # U+2028, a form feed) leaves the record itself intact, so the chain
        # still verifies and only this check sees the change.
        if canonical_json(record) != line:
            return broken("the line is not the canonical encoding this writer produces")

        # A checkpoint commits to the state *before* itself: the record count, the
        # running hash and the running MAC of its predecessor.
        if kind == CHECKPOINT:
            problem = _check_checkpoint(record, walk)
            if problem is not None:
                return walk.fail(_broken(problem, number))
            walk.checkpoints += 1
            walk.last_checkpoint_line = number
            walk.tail = 0
            walk.sealed = bool(record["checkpoint"]["final"])
            walk.interval = _interval_of(record, walk.interval)
        elif kind == ROTATION:
            walk.rotations += 1
            walk.tail += 1
            walk.sealed = False
        else:
            walk.count += 1
            walk.tail += 1
            walk.sealed = False

        walk.seen += 1
        walk.previous_hash = record["hash"]
        if keyed_record:
            walk.previous_mac = record["mac"]

    return walk.result()

def _verify_mac(walk: _Walk, record: Mapping[str, Any], number: int, kind: str) -> VerifyResult | None:
    """Verify the MAC of one keyed record; return a failure or ``None``."""
    for field in KEYED_FIELDS:
        if field not in record:
            return _broken(f"the keyed record is missing the field {field!r}", number)
    if record["chain"] != CHAIN_HMAC:
        return _broken(f"unknown chain {record['chain']!r}", number)
    mac, key_id, prev_mac = record["mac"], record["key_id"], record["prev_mac"]
    if not all(isinstance(value, str) for value in (mac, key_id, prev_mac)):
        return _broken("mac, key_id and prev_mac must be strings", number)

    rotation = record.get("rotation") if kind == ROTATION else None
    if kind == ROTATION:
        if not isinstance(rotation, Mapping) or not isinstance(rotation.get("previous_key_id"), str):
            return _broken(
                "a rotation record must carry rotation.previous_key_id (the key it was signed with)",
                number,
            )
    # A rotation is signed with the key it rotates away from; every other record
    # is signed with the key it names.
    signing_key_id = rotation["previous_key_id"] if kind == ROTATION else key_id

    if prev_mac != walk.previous_mac:
        return _broken(
            f"prev_mac {prev_mac!r} does not match the mac of the previous record "
            f"({walk.previous_mac!r})",
            number,
        )

    key = walk.resolver.key_for(signing_key_id)
    if key is None:
        available = ", ".join(sorted(walk.resolver.ids())) or "none"
        return _key_error(
            f"the record is signed with key {signing_key_id!r}, which is not available "
            f"(available: {available}); pass the matching --audit-key-file, or a --audit-keyring "
            "for a log that has been rotated",
            number,
            key_id=key_id,
        )

    if walk.first_key_id is None:
        walk.first_key_id = key_id
        walk.active_key_id = key_id
    elif kind != ROTATION and walk.active_key_id is not None and key_id != walk.active_key_id:
        return _key_error(
            f"the record is signed with key {key_id!r} but the chain is signed with key "
            f"{walk.active_key_id!r}: a key may only change through a rotation record",
            number,
            key_id=key_id,
        )

    expected = compute_mac(record, key.material, prev_mac)
    if not hmac.compare_digest(expected, mac):
        return _broken(
            f"mac {mac!r} does not match the recomputed mac {expected!r} under key {key_id!r}: "
            "the record was modified, or the log was rebuilt without the key",
            number,
            key_id=key_id,
        )

    if walk.first_key_id is None:
        walk.first_key_id = key_id
    walk.key_id = key_id
    walk.active_key_id = key_id
    return None

def _check_checkpoint(record: Mapping[str, Any], walk: _Walk) -> str | None:
    """Check a checkpoint against the running MAC, hash and record count."""
    checkpoint = record.get("checkpoint")
    if not isinstance(checkpoint, Mapping):
        return "a checkpoint record must carry a 'checkpoint' object"

    committed_records = checkpoint.get("records")
    if not isinstance(committed_records, int) or isinstance(committed_records, bool):
        return "the checkpoint record count must be an integer"
    if committed_records != walk.seen:
        return ( f"the checkpoint commits to record {committed_records} but sits at position "
                         f"{walk.seen}: records were inserted or removed before it"
        )

    committed_hash = checkpoint.get("hash")
    if committed_hash != walk.previous_hash:
        return ( f"the checkpoint commits to hash {committed_hash!r} but the running hash is "
                         f"{walk.previous_hash!r}"
        )

    if not is_keyed(record):
        return None

    committed_mac = checkpoint.get("mac")
    if committed_mac != walk.previous_mac:
        return ( f"the checkpoint commits to mac {committed_mac!r} but the running mac is "
                         f"{walk.previous_mac!r}: the chain was rebuilt, or the checkpoint was forged"
        )
    if checkpoint.get("key_id") not in (None, walk.active_key_id):
        return "the checkpoint key id does not match the key that signed it"
    if not isinstance(checkpoint.get("final"), bool):
        return "the checkpoint 'final' flag must be a boolean"
    return None

def _interval_of(record: Mapping[str, Any], default: int) -> int:
    """The checkpoint interval a record announces, or the default."""
    checkpoint = record.get("checkpoint")
    if isinstance(checkpoint, Mapping):
        value = checkpoint.get("interval")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            return value
    return default

class AuditLog:
    """Append-only writer, verified on open, keyed whenever a key is available."""

    def __init__(
        self,
        path: str | Path,
        session_id: str,
        *,
        key: bytes | str | AuditKey | None = None,
        key_file: str | Path | None = None,
        keyring: Any = None,
        resolver: KeyResolver | None = None,
        legacy: bool = False,
        require_keyed: bool = False,
        checkpoint_interval: int | str | None = None,
        fsync: bool = False,
        warn: bool = True,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.path = Path(path)
        self.session_id = session_id
        self.fsync = fsync
        self.checkpoint_interval = resolve_checkpoint_interval(checkpoint_interval)
        self._closed = False
        self._lines = 0
        self._since_checkpoint = 0
        self._sealed = False
        self._last_hash = ZERO_HASH
        self._last_mac = ZERO_MAC
        self._lock: _WriterLock | None = None

        if resolver is None:
            resolver = KeyResolver.load(
                material=None if isinstance(key, AuditKey) else key,
                key_file=key_file,
                keyring=keyring,
                environ=environ,
            )
            if isinstance(key, AuditKey):
                resolver.primary = key
        self._resolver = resolver
        self._key: AuditKey | None = None if legacy else resolver.primary
        self._key_id: str | None = None if legacy else resolver.key_id

        # Since 0.4 the unkeyed chain has to be asked for, not defaulted to.
        if require_keyed and self._key is None:
            raise AuditKeyError(
                f"refusing to write {self.path}: no audit key is configured, so the log would be an "
                "unkeyed legacy chain that cannot detect a full rewrite. Configure --audit-key-file "
                "(or MCP_GUARD_AUDIT_KEY), or pass --legacy-unkeyed to accept an unkeyed log"
            )

        # The lock comes before the chain is adopted: two writers must not both
        # adopt the same tail, or the second one chains from a predecessor the
        # first one has already moved past.
        # F-09: Acquire lock before checking file existence and size.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = _WriterLock(self.path)
        try:
            self._lock.acquire()
            existing = self.path.exists() and bool(self.path.stat().st_size)
            if existing:
                # A writer accepts the format it writes itself; `_adopt` decides
                # whether the existing log and this writer agree.
                self._adopt(
                    verify_log(self.path, resolver=resolver, allow_legacy=True), legacy=legacy
                )

            # A key may still have arrived with the existing chain, so the legacy
            # warning waits until the log has been adopted.
            if self._key is None:
                if warn:
                    warn_about_legacy_chain()
            else:
                # `verify` reports BROKEN when this sidecar is here but no MAC is.
                write_sentinel(self.path, self._key_id or "")

            self._handle = self.path.open("a", encoding="utf-8")
        except BaseException:
            if self._lock is not None:
                self._lock.release()
            raise

    @property
    def keyed(self) -> bool:
        """Whether this log is authenticated with HMAC-SHA256."""
        return self._key is not None

    @property
    def key_id(self) -> str | None:
        """The public key id, or ``None`` in legacy mode."""
        return self._key_id

    @property
    def key(self) -> AuditKey | None:
        """The key this writer signs with; never printed, never logged."""
        return self._key

    def _adopt(self, result: VerifyResult, *, legacy: bool = False) -> None:
        """Continue an existing, verified chain."""
        # Checked before the status, so an unkeyed writer aimed at a keyed log is
        # told what it is about to do, not only that it lacks a key.
        if result.keyed and legacy:
            raise AuditError(
                f"refusing to append to {self.path}: it is an HMAC chain and an unkeyed writer "
                "would silently downgrade it"
            )
        if result.status in (STATUS_BROKEN, STATUS_KEY):
            error = AuditKeyError if result.status == STATUS_KEY else AuditError
            raise error( f"refusing to append to {self.path}: the existing audit log does not verify "
                                     f"(line {result.broken_line}: {result.reason})"
            )
        if result.keyed and not legacy:
            # Continue with the key the log is signed with: reopening a rotated
            # log must not break it, and a key ring alone must be enough.
            active = self._resolver.key_for(result.key_id or "")
            if active is None:
                raise AuditKeyError(
                    f"refusing to append to {self.path}: the existing audit log is an HMAC chain "
                    f"written with key {result.key_id!r}, but no audit key is configured; pass "
                    "--audit-key-file, or --audit-keyring for a log that has been rotated"
                )
            self._key = active
            self._key_id = result.key_id
        elif not result.keyed and self.keyed:
            raise AuditError(
                f"refusing to append to {self.path}: the existing audit log is an unkeyed legacy "
                "chain; starting a keyed chain on top of it is refused, because the result would not "
                "be distinguishable from a downgrade. Verify it as legacy and start a new log."
            )

        self._lines = result.lines
        self._last_hash = result.last_hash
        self._last_mac = result.last_mac
        self._since_checkpoint = result.tail
        # Even when the previous writer sealed the log, *this* one has not shut
        # down yet, so it owes the log its own final checkpoint.
        self._sealed = False

    def _base_record(
        self, method: str, *, tool_name: str | None, arguments: Any, decision: str,
        reason: str, upstream_latency_ms: float | None, outcome: str | None = None,
    ) -> dict[str, Any]:
        return {
            "timestamp": utc_timestamp(),
            "session_id": self.session_id,
            "method": method,
            "tool_name": tool_name,
            "arguments": arguments,
            "decision": decision,
            # G-15: ``decision`` is what the *policy* said; ``outcome`` is
            # what happened end to end.  A call the policy allowed and the
            # upstream then failed is not the same event as a call the policy
            # denied, and a reader of the log needs to tell them apart without
            # parsing the reason text.
            "outcome": outcome if outcome is not None else default_outcome(decision),
            "reason": reason,
            "upstream_latency_ms": upstream_latency_ms,
            "prev_hash": self._last_hash,
        }

    def _seal(self, record: dict[str, Any]) -> dict[str, Any]:
        """Finish a record: the MAC first, then the hash over everything."""
        if self.keyed:
            record["chain"] = CHAIN_HMAC
            record["key_id"] = self._key_id
            record["prev_mac"] = self._last_mac
            record["mac"] = compute_mac(record, self._key.material, self._last_mac)
        record["hash"] = compute_hash(record)
        return record

    def _write(self, record: dict[str, Any]) -> None:
        self._handle.write(canonical_json(record) + "\n")
        self._handle.flush()
        if self.fsync:
            os.fsync(self._handle.fileno())
        self._lines += 1
        self._last_hash = record["hash"]
        self._last_mac = record.get("mac", ZERO_MAC)

    def append(
        self, *, method: str, tool_name: str | None, arguments: Any, decision: str,
        reason: str, upstream_latency_ms: float | None = None,
        outcome: str | None = None,
    ) -> dict[str, Any]:
        """Append one decision record to the log and return it."""
        if self._closed:
            raise AuditError("audit log is closed")
        try:
            redacted_arguments = redact_arguments(arguments)
        except RecursionError:
            redacted_arguments = {"<error>": "<arguments nested too deeply to redact>"}

        # G-02: the reason is scrubbed before it is written, so a value that
        # reached the message from anywhere at all -- the policy, a caller,
        # a future constraint -- still does not reach the log.
        clean_reason = scrub_reason(reason)

        record = self._base_record(
            method,
            tool_name=tool_name,
            arguments=redacted_arguments,
            decision=decision,
            reason=clean_reason,
            upstream_latency_ms=None
            if upstream_latency_ms is None
            else round(float(upstream_latency_ms), 3),
            outcome=outcome,
        )
        if self.keyed:
            record["record_type"] = DECISION
        self._seal(record)
        self._write(record)

        self._since_checkpoint += 1
        if self.keyed and self._since_checkpoint >= self.checkpoint_interval:
            self.checkpoint(final=False)
        return record

    def checkpoint(self, *, final: bool = False) -> dict[str, Any]:
        """Commit the running MAC, hash and record count; ``final`` marks shutdown."""
        if self._closed:
            raise AuditError("audit log is closed")
        if not self.keyed:
            raise AuditError(
                "a checkpoint commits to the running MAC, so it needs a keyed audit log; the "
                "legacy unkeyed chain has no MAC to commit to"
            )
        record = self._base_record(
            "audit/checkpoint",
            tool_name=None,
            arguments={},
            decision=CHECKPOINT,
            reason=(
                "clean shutdown"
                if final
                else f"every {self.checkpoint_interval} record(s) the running mac is committed"
            ),
            upstream_latency_ms=None,
            outcome=OUTCOME_CHECKPOINT,
        )
        record["record_type"] = CHECKPOINT
        record["checkpoint"] = {
            "records": self._lines,
            "mac": self._last_mac,
            "hash": self._last_hash,
            "interval": self.checkpoint_interval,
            "final": bool(final),
            "key_id": self._key_id,
        }
        self._seal(record)
        self._write(record)
        self._since_checkpoint = 0
        self._sealed = bool(final)
        return record

    def rotate(self, new_key: bytes | str | AuditKey, *, reason: str | None = None) -> dict[str, Any]:
        """Rotate onto a new key: signed with the old one, committing to the new."""
        if self._closed:
            raise AuditError("audit log is closed")
        if not self.keyed:
            raise AuditError(
                "cannot rotate an unkeyed legacy chain; start a keyed log to be able to rotate it"
            )
        new = new_key if isinstance(new_key, AuditKey) else AuditKey.from_material(new_key)
        if new.key_id == self._key_id:
            raise AuditError(f"the log is already signed with key {new.key_id!r}")

        record = self._base_record(
            "audit/rotate",
            tool_name=None,
            arguments={"key_id": new.key_id},
            decision=ROTATION,
            reason=reason or f"the audit chain key was rotated to {new.key_id}",
            upstream_latency_ms=None,
            outcome=OUTCOME_CHECKPOINT,
        )
        record["record_type"] = ROTATION
        record["rotation"] = {
            "previous_key_id": self._key_id,
            "key_id": new.key_id,
            "records": self._lines,
        }
        # Sealed with the old key, so only a holder of the old key can forge it.
        record["chain"] = CHAIN_HMAC
        record["key_id"] = new.key_id
        record["prev_mac"] = self._last_mac
        record["mac"] = compute_mac(record, self._key.material, self._last_mac)
        record["hash"] = compute_hash(record)
        self._write(record)

        self._key = new
        self._key_id = new.key_id
        self._resolver.primary = new
        self._since_checkpoint += 1
        self._sealed = False
        return record

    def close(self) -> None:
        """Seal the log with a final checkpoint (keyed mode) and close the file."""
        if self._closed:
            return
        if self.keyed and not self._sealed:
            try:
                self.checkpoint(final=True)
            except (AuditError, OSError):  # pragma: no cover - never block a clean exit
                pass
        self._closed = True
        self._handle.close()
        if self._lock is not None:
            self._lock.release()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

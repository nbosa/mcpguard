"""Tests for the downgrade attack: stripping the MACs off a keyed log.

The weakness these tests pin down is the one the keyed chain could not close on
its own: the ``mac``, ``prev_mac``, ``key_id`` and ``chain`` fields can simply be
*deleted*, and what is left is a structurally perfect legacy log that an unkeyed
chain cannot tell apart from an honest one written before 0.2.

In 0.3 that log verified ``OK`` and only printed a warning, unless the operator
remembered ``--require-keyed``.  Since 0.4 it is refused with exit ``3`` by
default, a log that is keyed at the head and unkeyed at the tail is ``BROKEN``
whatever the flags say, and the keyed writer will not produce such a log by
accident.

Every test asserts the real command line exit code *and* the library result, so
a change in either layer is caught.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

import pytest

from .conftest import REPO_ROOT, child_environment
from mcp_guard.audit import (
    STATUS_BROKEN,
    STATUS_OK,
    STATUS_REFUSED,
    ZERO_HASH,
    ZERO_MAC,
    AuditLog,
    canonical_json,
    compute_hash,
    sentinel_path,
    verify_log,
)
from mcp_guard.cli import EXIT_CONFLICT, EXIT_KEY, EXIT_OK, main
from mcp_guard.keys import AuditKey, write_key_file

#: A fixed key, so a failing test is reproducible and no real secret is involved.
KEY = AuditKey.from_material("7" * 64)

#: The fields a downgrade attack deletes.
KEYED_FIELDS = ("mac", "prev_mac", "key_id", "chain")

POLICY = "version: 1\ndefault_action: deny\n"


# -- helpers ---------------------------------------------------------------


def run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run the real command line in a subprocess, the way an operator would."""
    return subprocess.run(
        [sys.executable, "-m", "mcp_guard", *argv],
        capture_output=True,
        text=True,
        env=child_environment(),
        cwd=str(REPO_ROOT),
        timeout=60,
    )


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_records(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(canonical_json(record) for record in records) + "\n", encoding="utf-8")


def keyed_log(directory: Path, name: str = "audit.jsonl", count: int = 4) -> Path:
    """A clean, keyed, cleanly closed audit log."""
    path = directory / name
    with AuditLog(path, "session-1", key=KEY, checkpoint_interval=2) as log:
        for index in range(count):
            log.append(
                method="tools/call",
                tool_name="read_file",
                arguments={"path": f"sandbox/hello-{index}.txt"},
                decision="allow",
                reason="allowed by policy",
                upstream_latency_ms=1.5,
            )
    return path


def strip_everything(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip every keyed field and drop every checkpoint/rotation record.

    What the attacker can do without the key: delete the keyed fields, drop the
    record types that only exist in a keyed log, and recompute the whole plain
    SHA-256 chain.  The result is a perfect legacy log.
    """
    stripped: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for record in records:
        legacy = {
            field: value
            for field, value in record.items()
            if field not in KEYED_FIELDS + ("record_type", "checkpoint", "rotation")
        }
        legacy["prev_hash"] = previous
        legacy["hash"] = compute_hash(legacy)
        previous = legacy["hash"]
        stripped.append(legacy)
    return stripped


def strip_the_tail(records: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    """Strip the keyed fields of the *last* ``count`` records only."""
    mixed = [dict(record) for record in records]
    previous = ZERO_HASH
    for index, record in enumerate(mixed):
        if index >= len(mixed) - count:
            for field in KEYED_FIELDS:
                record.pop(field, None)
            checkpoint = record.get("checkpoint")
            if isinstance(checkpoint, dict):
                # The checkpoint cannot commit to a MAC that is no longer there.
                checkpoint["mac"] = ZERO_MAC
                checkpoint["key_id"] = None
        record["prev_hash"] = previous
        checkpoint = record.get("checkpoint")
        if isinstance(checkpoint, dict):
            checkpoint["hash"] = previous
        record["hash"] = compute_hash(record)
        previous = record["hash"]
    return mixed


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    return write_key_file(tmp_path / "audit.key", KEY.material)


@pytest.fixture
def downgraded(tmp_path: Path) -> Path:
    """The attack log of T1: a keyed log, fully downgraded and re-chained."""
    original = keyed_log(tmp_path)
    attack = tmp_path / "downgraded.jsonl"
    write_records(attack, strip_everything(read_records(original)))
    return attack


# -- T1: the whole downgrade, by default -----------------------------------


def test_a_mac_stripped_log_is_refused_by_default(
    tmp_path: Path, key_file: Path, downgraded: Path
) -> None:
    """T1: every MAC gone, every unkeyed hash recomputed -> exit 3, REFUSED."""
    attack = downgraded
    assert not any("mac" in record for record in read_records(attack))

    result = verify_log(attack, key_file=key_file)
    assert result.status == STATUS_REFUSED
    assert result.exit_code == 3
    assert result.reason is not None and result.reason.startswith("legacy unkeyed chain")

    completed = run(["verify", str(attack), "--audit-key-file", str(key_file)])
    assert completed.returncode == 3
    assert completed.stdout.startswith("REFUSED: legacy unkeyed chain")
    assert completed.stderr == ""


def test_only_allow_legacy_accepts_a_stripped_log(
    key_file: Path, downgraded: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """T1b: the refusal is about the default, not about the log being unreadable."""
    attack = downgraded
    assert main(["verify", str(attack), "--audit-key-file", str(key_file), "--allow-legacy"]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.startswith("OK:")
    assert "LEGACY unkeyed chain" in captured.err
    assert "not detectable" in captured.err


# -- T2/T3: the keyed sentinel ---------------------------------------------


def test_editing_the_log_in_place_is_broken_without_any_flag(tmp_path: Path, key_file: Path) -> None:
    """The realistic downgrade: the attacker edits the log and forgets the sidecar.

    Here the downgraded file keeps the *name* of the keyed log, so its
    ``PATH.keyed`` is still on disk.  That is why the sentinel check comes first:
    it turns what would be a ``REFUSED`` into a ``BROKEN``, which is a stronger
    answer, and it needs no flag at all.
    """
    log = keyed_log(tmp_path, name="in-place.jsonl")
    write_records(log, strip_everything(read_records(log)))

    result = verify_log(log, key_file=key_file)
    assert result.status == STATUS_BROKEN
    assert result.exit_code == 1
    assert "sentinel" in (result.reason or "")

    completed = run(["verify", str(log), "--audit-key-file", str(key_file)])
    assert completed.returncode == 1
    assert completed.stdout.startswith("BROKEN")


def test_the_sentinel_turns_a_stripped_log_into_broken(key_file: Path, downgraded: Path) -> None:
    """T2: the sidecar is still there, so the log was keyed -- that is tampering."""
    attack = downgraded
    sentinel_path(attack).write_text(
        canonical_json({"version": 1, "key_id": KEY.key_id, "created": "2026-10-19T00:00:00.000000Z"})
    )

    result = verify_log(attack, key_file=key_file, allow_legacy=True)
    assert result.status == STATUS_BROKEN
    assert result.exit_code == 1

    completed = run(["verify", str(attack), "--audit-key-file", str(key_file), "--allow-legacy"])
    assert completed.returncode == 1
    assert completed.stdout.startswith("BROKEN")
    assert "sentinel" in completed.stdout


def test_deleting_the_sentinel_defeats_it_and_that_is_documented(key_file: Path, downgraded: Path) -> None:
    """T3: the documented residual risk -- remove the sidecar and it reads legacy."""
    attack = downgraded
    sentinel = sentinel_path(attack)
    sentinel.write_text(canonical_json({"version": 1, "key_id": KEY.key_id}))
    sentinel.unlink()

    assert verify_log(attack, key_file=key_file, allow_legacy=True).status == STATUS_OK

    completed = run(["verify", str(attack), "--audit-key-file", str(key_file), "--allow-legacy"])
    assert completed.returncode == 0
    assert completed.stdout.startswith("OK:")
    assert "LEGACY unkeyed chain" in completed.stderr


def test_the_sentinel_holds_only_public_metadata(tmp_path: Path, key_file: Path) -> None:
    """The sidecar is written for every keyed log, and it never holds the key."""
    log = keyed_log(tmp_path, name="written.jsonl")
    sentinel = sentinel_path(log)

    assert sentinel.exists()
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600
    document = json.loads(sentinel.read_text(encoding="utf-8"))
    assert document["key_id"] == KEY.key_id
    assert set(document) == {"version", "path", "key_id", "created"}
    # G-18: the key file carries an explicit encoding tag.
    assert key_file.read_text(encoding="utf-8").strip() == "hex:" + KEY.material.hex()


# -- T4: a partially stripped log ------------------------------------------


@pytest.mark.parametrize("extra", [[], ["--allow-legacy"]])
def test_a_partially_stripped_log_is_broken(tmp_path: Path, key_file: Path, extra: list[str]) -> None:
    """T4: keyed at the head and unkeyed at the tail is never "legacy"."""
    original = keyed_log(tmp_path, name="tail.jsonl", count=6)
    attack = tmp_path / "half-stripped.jsonl"
    write_records(attack, strip_the_tail(read_records(original), 2))

    result = verify_log(attack, key_file=key_file, allow_legacy="--allow-legacy" in extra)
    assert result.status == STATUS_BROKEN
    assert result.exit_code == 1

    completed = run(["verify", str(attack), "--audit-key-file", str(key_file), *extra])
    assert completed.returncode == 1
    assert completed.stdout.startswith("BROKEN")
    assert "mac" in completed.stdout


def test_a_log_whose_checkpoint_kept_its_fields_is_broken(tmp_path: Path, key_file: Path) -> None:
    """Half stripping the *mac* only, leaving key_id behind, is not a legacy log."""
    original = keyed_log(tmp_path, name="keep.jsonl")
    records = [dict(record) for record in read_records(original)]
    previous = ZERO_HASH
    for record in records:
        record.pop("mac", None)
        record["prev_mac"] = ZERO_MAC
        checkpoint = record.get("checkpoint")
        if isinstance(checkpoint, dict):
            checkpoint["mac"] = ZERO_MAC
        record["prev_hash"] = previous
        record["hash"] = compute_hash(record)
        previous = record["hash"]
    attack = tmp_path / "macs-only.jsonl"
    write_records(attack, records)

    assert verify_log(attack, key_file=key_file).status == STATUS_BROKEN
    assert run(["verify", str(attack), "--audit-key-file", str(key_file)]).returncode == 1


# -- T5: an honest legacy log ----------------------------------------------


def test_an_honest_legacy_log_is_refused_until_it_is_asked_for(tmp_path: Path) -> None:
    """T5: old logs stay readable, but only on an explicit --allow-legacy."""
    log = tmp_path / "legacy.jsonl"
    with AuditLog(log, "session-1", legacy=True) as writer:  # what --legacy-unkeyed does
        writer.append(
            method="tools/call",
            tool_name="read_file",
            arguments={"path": "sandbox/hello.txt"},
            decision="allow",
            reason="allowed by policy",
        )
    assert not sentinel_path(log).exists()

    assert verify_log(log).status == STATUS_REFUSED
    assert verify_log(log, allow_legacy=True).status == STATUS_OK

    assert run(["verify", str(log)]).returncode == 3
    accepted = run(["verify", str(log), "--allow-legacy"])
    assert accepted.returncode == 0
    assert accepted.stdout.startswith("OK: 1 record(s) verified, hash chain intact")


# -- T6: the deprecated flag ------------------------------------------------


def test_require_keyed_is_a_deprecated_no_op(tmp_path: Path) -> None:
    """T6a: the old flag keeps working and does exactly what the default does."""
    log = tmp_path / "legacy.jsonl"
    with AuditLog(log, "session-1", legacy=True) as writer:
        writer.append(method="tools/list", tool_name=None, arguments={}, decision="allow", reason="listed")

    plain = run(["verify", str(log)])
    deprecated = run(["verify", str(log), "--require-keyed"])

    assert deprecated.returncode == plain.returncode == 3
    assert deprecated.stdout == plain.stdout
    assert "deprecated" in deprecated.stderr
    assert plain.stderr == ""


def test_require_keyed_with_allow_legacy_is_a_usage_error(tmp_path: Path) -> None:
    """T6b: the two flags ask for opposite things, so neither is honoured."""
    log = tmp_path / "legacy.jsonl"
    with AuditLog(log, "session-1", legacy=True) as writer:
        writer.append(method="tools/list", tool_name=None, arguments={}, decision="allow", reason="listed")

    completed = run(["verify", str(log), "--require-keyed", "--allow-legacy"])
    assert completed.returncode == EXIT_CONFLICT == 64
    assert "contradict each other" in completed.stderr
    assert completed.stdout == ""


# -- T7: the write side ----------------------------------------------------


def test_the_proxy_refuses_to_write_an_unkeyed_log_without_being_asked(tmp_path: Path) -> None:
    """T7: `run` will not quietly fall back to a chain that detects nothing."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    audit = tmp_path / "audit.jsonl"

    refused = run(
        ["run", "--policy", str(policy), "--audit", str(audit), "--", sys.executable, "-c", "pass"]
    )
    assert refused.returncode == 3
    assert "no audit key is configured" in refused.stderr
    assert "--legacy-unkeyed" in refused.stderr
    assert not audit.exists()

    # ... and the explicit opt-in works.
    accepted = run(
        [
            "run",
            "--policy",
            str(policy),
            "--audit",
            str(audit),
            "--legacy-unkeyed",
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )
    assert "no audit key is configured" in accepted.stderr
    assert "UNKEYED legacy chain" in accepted.stderr


def test_the_proxy_refuses_to_continue_a_log_it_cannot_key(tmp_path: Path, key_file: Path) -> None:
    """A keyed log cannot be opened by a writer that has no key at all."""
    log = keyed_log(tmp_path, name="existing.jsonl")
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    before = log.read_text(encoding="utf-8")

    refused = run(
        [
            "run",
            "--policy",
            str(policy),
            "--audit",
            str(log),
            "--legacy-unkeyed",
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )
    assert refused.returncode == 1
    assert "downgrade" in refused.stderr
    assert log.read_text(encoding="utf-8") == before


# -- T8: the key never leaks -----------------------------------------------


def test_the_key_material_never_appears_anywhere(
    tmp_path: Path, key_file: Path, downgraded: Path
) -> None:
    """T8: not in stdout, stderr, the sidecar or the log -- for any verdict."""
    attack = downgraded
    sentinel_path(attack).write_text(canonical_json({"version": 1, "key_id": KEY.key_id}))
    original = keyed_log(tmp_path, name="original.jsonl")

    rendered = [original.read_text(encoding="utf-8"), sentinel_path(original).read_text(encoding="utf-8")]
    for argv in (
        ["verify", str(attack), "--audit-key-file", str(key_file)],
        ["verify", str(attack), "--audit-key-file", str(key_file), "--allow-legacy"],
        ["verify", str(attack), "--audit-key-file", str(key_file), "--require-keyed"],
        ["verify", str(original), "--audit-key-file", str(key_file)],
        ["verify", str(original), "--audit-key-file", str(key_file), "--audit-keyring", "nope.json"],
    ):
        completed = run(argv)
        rendered.append(completed.stdout + completed.stderr)

    material = KEY.material.hex()
    for text in rendered:
        assert material not in text
        assert "7" * 64 not in text
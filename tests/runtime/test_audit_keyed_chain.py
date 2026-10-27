"""Tests for the keyed audit chain: HMAC, checkpoints, rotation, key hygiene.

The chain under test is the one that closes the weakness a plain hash chain
has: an attacker who can rewrite the whole log can recompute every unkeyed
hash, so every attack below is run against a *fully rebuilt* log, not just a
byte that was flipped in place.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Callable

import pytest

from mcp_guard.audit import (
    CHAIN_HMAC,
    STATUS_BROKEN,
    STATUS_KEY,
    STATUS_OK,
    STATUS_REFUSED,
    STATUS_WARN,
    ZERO_HASH,
    ZERO_MAC,
    AuditError,
    AuditLog,
    canonical_json,
    compute_hash,
    compute_mac,
    is_keyed,
    verify_log,
)
from mcp_guard.keys import (
    KEY_ENV,
    KEY_FILE_ENV,
    KEYRING_ENV,
    MIN_KEY_BYTES,
    AuditKey,
    AuditKeyError,
    KeyResolver,
    KeyRing,
    key_id_for,
    read_key_file,
    write_key_file,
)

KEY_A = AuditKey.from_material("a" * 64)
KEY_B = AuditKey.from_material("b" * 64)
KEY_C = AuditKey.from_material("c" * 64)


# -- helpers ---------------------------------------------------------------


def append_record(log: AuditLog, index: int = 0, **overrides: Any) -> dict[str, Any]:
    payload = {
        "method": "tools/call",
        "tool_name": "read_file",
        "arguments": {"path": f"sandbox/hello-{index}.txt"},
        "decision": "allow",
        "reason": "allowed by policy",
        "upstream_latency_ms": 1.5,
    }
    payload.update(overrides)
    return log.append(**payload)


def write_log(path: Path, key: AuditKey = KEY_A, count: int = 5, interval: int = 100) -> Path:
    """A keyed log with ``count`` decision records, cleanly closed."""
    with AuditLog(path, "session-1", key=key, checkpoint_interval=interval) as log:
        for index in range(count):
            append_record(log, index)
    return path


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_records(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(canonical_json(record) for record in records) + "\n", encoding="utf-8")


def rebuild_with_unkeyed_hashes(records: list[dict[str, Any]], mutate: Callable[[dict], None]) -> list[dict]:
    """An attacker who rewrites everything and recomputes every *unkeyed* hash.

    The result is a perfect hash chain: every ``prev_hash`` points at its
    predecessor, every ``hash`` is the SHA-256 of its own record, every
    checkpoint commits to the running hash and the right count.  The only thing
    the attacker cannot do is compute an HMAC, because the HMAC key is not in
    the log.
    """
    forged = [dict(record) for record in records]
    previous = ZERO_HASH
    for record in forged:
        mutate(record)
        record["prev_hash"] = previous
        record["mac"] = record.get("mac", ZERO_MAC)  # kept: the attacker cannot forge it
        checkpoint = record.get("checkpoint")
        if isinstance(checkpoint, dict):
            checkpoint["hash"] = previous
            checkpoint["mac"] = record["prev_mac"]
        record["hash"] = compute_hash(record)
        previous = record["hash"]
    return forged


# -- the keyed chain -------------------------------------------------------


def downgrade_to_legacy(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The downgrade attack: strip the keyed fields, fix up everything unkeyed.

    The checkpoint and rotation records are dropped too, because those record
    types only exist in a keyed log and leaving them behind would give the
    downgrade away.  What is left is a structurally perfect legacy log.
    """
    forged: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for record in records:
        stripped = {
            field: value
            for field, value in record.items()
            if field not in ("mac", "prev_mac", "key_id", "chain", "record_type", "checkpoint", "rotation")
        }
        stripped["prev_hash"] = previous
        stripped["hash"] = compute_hash(stripped)
        previous = stripped["hash"]
        forged.append(stripped)
    return forged


def test_a_keyed_record_carries_a_mac_that_chains(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        first = append_record(log, 0)
        second = append_record(log, 1)

    assert first["chain"] == CHAIN_HMAC
    assert first["key_id"] == KEY_A.key_id
    assert first["prev_mac"] == ZERO_MAC
    assert second["prev_mac"] == first["mac"]
    assert first["mac"] == compute_mac(first, KEY_A.material, ZERO_MAC)
    assert second["mac"] == compute_mac(second, KEY_A.material, first["mac"])
    assert len(first["mac"]) == 64


def test_the_mac_covers_the_previous_mac_so_records_cannot_be_moved(tmp_path: Path) -> None:
    record = {
        "record_type": "record",
        "chain": CHAIN_HMAC,
        "key_id": KEY_A.key_id,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "session_id": "s",
        "method": "tools/call",
        "tool_name": "t",
        "arguments": {},
        "decision": "allow",
        "reason": "because",
        "upstream_latency_ms": None,
        "prev_hash": ZERO_HASH,
    }
    chained = compute_mac(record, KEY_A.material, "a" * 64)
    assert chained != compute_mac(record, KEY_A.material, "b" * 64)


def test_the_hash_covers_the_mac(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        record = append_record(log)
    without_mac = {key: value for key, value in record.items() if key != "mac"}
    assert compute_hash(record) != compute_hash(without_mac)


def test_a_clean_keyed_log_verifies(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=5)
    result = verify_log(path, key=KEY_A)
    assert result.status == STATUS_OK
    assert result.ok
    assert result.keyed
    assert result.records == 5
    assert result.sealed
    assert result.tail == 0
    assert result.exit_code == 0


def test_the_key_can_come_from_the_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(KEY_ENV, KEY_A.material.hex())
    with AuditLog(path, "session-1") as log:
        append_record(log)
    result = verify_log(path, environ={KEY_ENV: KEY_A.material.hex()})
    assert result.status == STATUS_OK


def test_the_key_can_come_from_a_key_file(tmp_path: Path) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key_file=key_file) as log:
        append_record(log)
    assert verify_log(path, key_file=key_file).status == STATUS_OK
    assert KEY_ENV not in os.environ or KEY_A.material.hex() not in os.environ.get(KEY_ENV, "")


def test_the_key_file_environment_variable_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        assert log.keyed
        append_record(log)
    assert verify_log(path, environ={KEY_FILE_ENV: str(key_file)}).status == STATUS_OK


# -- attacks ---------------------------------------------------------------


def test_a_full_rewrite_with_recomputed_unkeyed_hashes_is_detected(tmp_path: Path) -> None:
    """The weakness this feature exists for.

    The attacker is handed the original log and rewrites *every* record: the
    payload, the prev_hash chain and the hashes -- including the hash a
    checkpoint commits to.  What they cannot recompute is one single HMAC.
    """
    path = write_log(tmp_path / "audit.jsonl", count=4)
    original = read_records(path)

    forged = rebuild_with_unkeyed_hashes(
        original,
        lambda record: record.update(
            decision="deny", reason="refused: /etc/passwd", arguments={"path": "/etc/passwd"}
        ),
    )

    # The unkeyed chain is perfect: an unkeyed verifier cannot tell the difference.
    assert [record["hash"] for record in forged] != [record["hash"] for record in original]
    assert all(record["hash"] == compute_hash(record) for record in forged)
    assert all(
        forged[index]["prev_hash"] == (ZERO_HASH if index == 0 else forged[index - 1]["hash"])
        for index in range(len(forged))
    )
    for record in forged:  # every single decision was rewritten
        if record["record_type"] == "record":
            assert record["decision"] == "deny"

    attack = tmp_path / "rewritten.jsonl"
    write_records(attack, forged)
    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 1
    assert "mac" in (result.reason or "")
    assert result.exit_code == 1


def test_a_rewrite_that_rewrites_the_mac_field_as_text_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=3)
    forged = [
        dict(record, reason="allowed by policy", mac="0" * 64)
        for record in read_records(path)
    ]
    forged[0]["mac"] = "1" * 64
    attack = tmp_path / "rewritten.jsonl"
    write_records(attack, forged)
    assert verify_log(attack, key=KEY_A).status == STATUS_BROKEN


def test_stripping_the_mac_is_a_downgrade_that_verify_refuses_by_default(tmp_path: Path) -> None:
    """The residual weakness, stated out loud: the MAC fields can be removed.

    Since 0.4 ``verify`` refuses such a log (exit 3) unless the operator passes
    ``--allow-legacy``, so a downgrade is no longer something a script has to
    remember to opt out of.  The writer refuses the same downgrade in the other
    direction.
    """
    path = write_log(tmp_path / "audit.jsonl", count=3)
    attack = tmp_path / "downgraded.jsonl"
    write_records(attack, downgrade_to_legacy(read_records(path)))

    assert verify_log(attack, key=KEY_A).status == STATUS_REFUSED
    assert verify_log(attack, key=KEY_A).exit_code == 3
    assert verify_log(attack, key=KEY_A, allow_legacy=True).status == STATUS_OK

    with pytest.raises(AuditError):
        AuditLog(attack, "session-2", key=KEY_A)


def test_a_single_modified_byte_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=3)
    original = path.read_text(encoding="utf-8")
    index = original.index("hello-1.txt")
    path.write_text(original[:index] + "H" + original[index + 1 :], encoding="utf-8")

    result = verify_log(path, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 2  # the byte is in the second record
    assert result.exit_code == 1


def test_a_modified_mac_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=3)
    records = read_records(path)
    records[1]["mac"] = "f" * 64
    attack = tmp_path / "audit.jsonl"
    write_records(attack, records)

    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 2


def test_a_deleted_record_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=4)
    records = read_records(path)
    del records[1]
    attack = tmp_path / "deleted.jsonl"
    write_records(attack, records)

    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 2


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=4)
    records = read_records(path)
    records[1], records[2] = records[2], records[1]
    attack = tmp_path / "reordered.jsonl"
    write_records(attack, records)

    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 2


def test_a_removed_head_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=4)
    records = read_records(path)[1:]
    attack = tmp_path / "head.jsonl"
    write_records(attack, records)

    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 1
    # The head is gone, so the new first record no longer links to the zero hash/mac.
    assert "prev_hash" in (result.reason or "") or "prev_mac" in (result.reason or "")


def test_a_truncated_tail_is_a_warning_not_a_silent_ok(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=6, interval=2)
    records = read_records(path)
    assert sum(1 for record in records if record["record_type"] == "checkpoint") == 4

    for drop in (1, 2, 3, 4, 5, len(records) - 1):
        attack = tmp_path / f"truncated-{drop}.jsonl"
        write_records(attack, records[:-drop])
        result = verify_log(attack, key=KEY_A)
        assert result.status == STATUS_WARN, f"dropping {drop} record(s) was not a warning"
        assert result.ok  # the chain itself is intact
        assert result.exit_code == 2
        assert result.truncated
        assert not result  # an incomplete log is not truthy


def test_a_tampered_checkpoint_is_detected(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=4, interval=2)
    records = read_records(path)
    checkpoint = next(record for record in records if record["record_type"] == "checkpoint")
    checkpoint["checkpoint"]["records"] = 99
    attack = tmp_path / "checkpoint.jsonl"
    write_records(attack, records)

    # The MAC covers the checkpoint payload, so editing it is caught there first.
    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == records.index(checkpoint) + 1


def test_a_checkpoint_that_disagrees_with_the_chain_is_broken(tmp_path: Path) -> None:
    """Even a correctly *re-signed* checkpoint is rejected when it lies.

    This is the case the MAC alone cannot catch: a checkpoint that was signed
    with the key but commits to the wrong record count, hash or MAC.
    """
    path = write_log(tmp_path / "audit.jsonl", count=4, interval=2)
    records = read_records(path)
    index = next(i for i, record in enumerate(records) if record["record_type"] == "checkpoint")
    previous_mac = records[index - 1]["mac"] if index else ZERO_MAC

    for field, value in (
        ("records", 99),
        ("hash", "0" * 64),
        ("mac", "0" * 64),
    ):
        record = dict(records[index])
        record["checkpoint"] = dict(record["checkpoint"], **{field: value})
        record["mac"] = compute_mac(record, KEY_A.material, previous_mac)
        record["hash"] = compute_hash(record)
        resigned = list(records)
        resigned[index] = record
        attack = tmp_path / f"resigned-{field}.jsonl"
        write_records(attack, resigned)

        result = verify_log(attack, key=KEY_A)
        assert result.status == STATUS_BROKEN, field
        assert "checkpoint" in (result.reason or ""), field


def test_a_forged_checkpoint_mac_is_broken(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=4, interval=2)
    records = read_records(path)
    for record in records:
        checkpoint = record.get("checkpoint")
        if isinstance(checkpoint, dict):
            checkpoint["mac"] = "0" * 64
    attack = tmp_path / "forged-checkpoint.jsonl"
    write_records(attack, records)

    result = verify_log(attack, key=KEY_A)
    assert result.status == STATUS_BROKEN


# -- keys ------------------------------------------------------------------


def test_a_missing_key_is_a_key_error_not_tampering(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl")
    result = verify_log(path)
    assert result.status == STATUS_KEY
    assert KEY_A.key_id in (result.reason or "")
    assert result.exit_code == 3


def test_the_wrong_key_is_a_key_error_not_tampering(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", key=KEY_A)
    result = verify_log(path, key=KEY_B)
    assert result.status == STATUS_KEY
    assert result.exit_code == 3
    assert "not available" in (result.reason or "")


def test_a_key_with_the_right_id_but_the_wrong_material_is_tampering(tmp_path: Path) -> None:
    """A hand edited key id cannot downgrade a key error into a false BROKEN."""
    path = write_log(tmp_path / "audit.jsonl", key=KEY_A)
    impostor = AuditKey(key_id=KEY_A.key_id, material=KEY_B.material)
    assert verify_log(path, key=impostor).status == STATUS_BROKEN


def test_a_world_readable_key_file_is_refused(tmp_path: Path) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    os.chmod(key_file, 0o644)
    assert stat.S_IMODE(key_file.stat().st_mode) & 0o077

    with pytest.raises(AuditKeyError) as error:
        read_key_file(key_file)
    assert "readable by group or other" in str(error.value)
    assert "chmod 600" in str(error.value)
    assert KEY_A.material.hex() not in str(error.value)


def test_a_group_readable_key_file_is_refused(tmp_path: Path) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    os.chmod(key_file, 0o640)
    with pytest.raises(AuditKeyError):
        read_key_file(key_file)
    os.chmod(key_file, 0o600)
    assert read_key_file(key_file) == KEY_A.material


def test_a_key_file_is_created_with_mode_0600(tmp_path: Path) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # G-18: the key file states how it is encoded instead of leaving the
    # reader to guess.
    assert key_file.read_text().strip() == "hex:" + KEY_A.material.hex()


def test_keygen_does_not_overwrite_a_key_file_by_accident(tmp_path: Path) -> None:
    key_file = write_key_file(tmp_path / "audit.key", KEY_A.material)
    with pytest.raises(AuditKeyError):
        write_key_file(key_file, KEY_B.material)
    assert read_key_file(key_file) == KEY_A.material
    write_key_file(key_file, KEY_B.material, force=True)
    assert read_key_file(key_file) == KEY_B.material


def test_a_short_key_is_refused() -> None:
    with pytest.raises(AuditKeyError) as error:
        AuditKey.from_material("too short")
    assert "too short" in str(error.value)


def test_the_key_id_is_a_one_way_fingerprint() -> None:
    assert key_id_for(KEY_A.material) == KEY_A.key_id
    assert key_id_for(KEY_A.material) != key_id_for(KEY_B.material)
    assert len(KEY_A.key_id) == 16
    assert KEY_A.material.hex()[:16] not in KEY_A.key_id


# -- the key never leaks ---------------------------------------------------


def test_the_key_is_never_written_to_the_log(tmp_path: Path) -> None:
    key = AuditKey.from_material("f" * 64)
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=key, checkpoint_interval=2) as log:
        for index in range(4):
            append_record(log, index)
        log.rotate(KEY_B)
        append_record(log, 9)

    text = path.read_text(encoding="utf-8")
    assert key.material.hex() not in text
    assert "f" * 64 not in text
    assert key.material.hex(":") not in text


def test_repr_of_a_key_never_shows_the_material() -> None:
    for rendering in (repr(KEY_A), str(KEY_A), f"{KEY_A}"):
        assert KEY_A.material.hex() not in rendering
        assert "f" * 64 not in rendering
        assert KEY_A.key_id in rendering


def test_error_messages_never_contain_the_key(tmp_path: Path) -> None:
    key = AuditKey.from_material("e" * 64)
    key_file = write_key_file(tmp_path / "audit.key", key.material)
    path = write_log(tmp_path / "audit.jsonl", key=key)

    os.chmod(key_file, 0o666)
    failures = []
    for call in (
        lambda: verify_log(path, key_file=key_file),
        lambda: verify_log(path, key=AuditKey.from_material("e" * 63 + "d")),
        lambda: read_key_file(key_file),
    ):
        try:
            call()
        except AuditKeyError as exc:
            failures.append(str(exc))
    os.chmod(key_file, 0o600)

    assert failures
    for message in failures:
        assert key.material.hex() not in message
        assert "e" * 64 not in message


def test_a_keyed_log_cannot_be_appended_to_without_the_key(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl")
    with pytest.raises(AuditKeyError) as error:
        AuditLog(path, "session-2")
    assert KEY_A.key_id in str(error.value)
    assert "not available" in str(error.value)


# -- checkpoints -----------------------------------------------------------


def test_a_checkpoint_is_written_every_n_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A, checkpoint_interval=3) as log:
        for index in range(7):
            append_record(log, index)

    records = read_records(path)
    periodic = [
        record
        for record in records
        if record["record_type"] == "checkpoint" and not record["checkpoint"]["final"]
    ]
    assert len(periodic) == 2
    # The count is the position in the log: every record written before it.
    assert [record["checkpoint"]["records"] for record in periodic] == [3, 7]
    assert all(record["checkpoint"]["interval"] == 3 for record in periodic)
    assert records[-1]["checkpoint"]["final"] is True  # ... and one on shutdown


def test_a_clean_shutdown_writes_a_final_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "session-1", key=KEY_A, checkpoint_interval=1000)
    append_record(log)
    log.close()
    log.close()  # idempotent: a second close must not add a second checkpoint

    records = read_records(path)
    assert records[-1]["record_type"] == "checkpoint"
    assert records[-1]["checkpoint"]["final"] is True
    assert records[-1]["checkpoint"]["records"] == 1
    assert verify_log(path, key=KEY_A).status == STATUS_OK


def test_the_checkpoint_commits_to_the_running_mac(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A, checkpoint_interval=2) as log:
        append_record(log, 0)
        append_record(log, 1)

    records = read_records(path)
    checkpoint = records[2]
    assert checkpoint["checkpoint"]["mac"] == records[1]["mac"]
    assert checkpoint["checkpoint"]["hash"] == records[1]["hash"]
    assert checkpoint["prev_mac"] == records[1]["mac"]


def test_the_checkpoint_interval_is_configurable(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A, checkpoint_interval=1) as log:
        append_record(log, 0)
        append_record(log, 1)
    assert sum(1 for r in read_records(path) if r["record_type"] == "checkpoint") == 3


def test_the_checkpoint_interval_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MCP_GUARD_AUDIT_CHECKPOINT_INTERVAL", "2")
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        for index in range(4):
            append_record(log, index)
    assert sum(1 for r in read_records(path) if r["record_type"] == "checkpoint") == 3


def test_a_crash_leaves_a_log_without_a_final_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "session-1", key=KEY_A, checkpoint_interval=100)
    append_record(log)
    log._handle.close()  # the process dies: no close(), no final checkpoint

    result = verify_log(path, key=KEY_A)
    assert result.status == STATUS_WARN
    assert "clean-shutdown checkpoint" in (result.reason or "")


def test_a_checkpoint_needs_a_key(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.jsonl", "s") as log:
        with pytest.raises(AuditError) as error:
            log.checkpoint()
        assert "keyed" in str(error.value)


# -- rotation --------------------------------------------------------------


def test_a_rotation_record_commits_to_the_new_key_id(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        append_record(log)
        record = log.rotate(KEY_B)

    assert record["record_type"] == "rotation"
    assert record["key_id"] == KEY_B.key_id
    assert record["rotation"]["previous_key_id"] == KEY_A.key_id
    assert record["rotation"]["key_id"] == KEY_B.key_id
    # Signed with the old key: somebody holding only the new key cannot forge it.
    assert record["mac"] == compute_mac(record, KEY_A.material, record["prev_mac"])


def test_a_rotated_log_verifies_with_a_keyring(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    ring = KeyRing().add(KEY_A).add(KEY_B)
    ring.path = tmp_path / "ring.json"
    ring.save()

    with AuditLog(path, "session-1", key=KEY_A) as log:
        append_record(log, 0)
        log.rotate(KEY_B)
        append_record(log, 1)

    result = verify_log(path, keyring=ring.path)
    assert result.status == STATUS_OK
    assert result.rotations == 1
    assert result.key_id == KEY_B.key_id
    assert result.first_key_id == KEY_A.key_id
    assert verify_log(path, key=KEY_A).status == STATUS_KEY
    assert verify_log(path, key=KEY_B).status == STATUS_KEY


def test_a_rotated_log_can_be_continued_through_a_rotation(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    ring = KeyRing().add(KEY_A).add(KEY_B)
    ring.path = tmp_path / "ring.json"
    ring.save()

    with AuditLog(path, "session-1", key=KEY_A) as log:
        append_record(log, 0)
        log.rotate(KEY_B)
    with AuditLog(path, "session-2", keyring=ring.path) as log:
        assert log.keyed and log.key_id == KEY_B.key_id
        append_record(log, 1)
    with AuditLog(path, "session-3", keyring=ring.path) as log:
        append_record(log, 2)

    result = verify_log(path, keyring=ring.path)
    assert result.status == STATUS_OK
    assert result.records == 3
    assert result.rotations == 1


def test_a_forged_rotation_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        append_record(log)
        log.rotate(KEY_B)
        append_record(log, 1)

    records = read_records(path)
    records[1]["rotation"]["key_id"] = KEY_C.key_id
    attack = tmp_path / "forged.jsonl"
    write_records(attack, records)

    ring = KeyRing().add(KEY_A).add(KEY_B).add(KEY_C)
    ring.path = tmp_path / "ring.json"
    ring.save()
    result = verify_log(attack, keyring=ring.path)
    assert result.status == STATUS_BROKEN
    assert result.broken_line == 2


def test_a_rotation_onto_the_same_key_is_refused(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.jsonl", "session-1", key=KEY_A) as log:
        with pytest.raises(AuditError):
            log.rotate(KEY_A)


def test_an_unkeyed_writer_cannot_downgrade_a_keyed_log(tmp_path: Path) -> None:
    path = write_log(tmp_path / "audit.jsonl", count=2)
    before = len(read_records(path))
    with pytest.raises(AuditError) as error:
        AuditLog(path, "session-2", legacy=True)
    assert "downgrade" in str(error.value)
    assert len(read_records(path)) == before


def test_a_legacy_chain_cannot_be_rotated(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        with pytest.raises(AuditError) as error:
            log.rotate(KEY_B)
        assert "unkeyed" in str(error.value)


def test_the_keyring_file_is_checked_too(tmp_path: Path) -> None:
    ring = KeyRing().add(KEY_A)
    ring.path = tmp_path / "ring.json"
    ring.save()
    os.chmod(ring.path, 0o644)
    with pytest.raises(AuditKeyError) as error:
        KeyRing.load(ring.path)
    assert "readable by group or other" in str(error.value)


def test_a_keyring_that_mislabels_a_key_is_refused(tmp_path: Path) -> None:
    ring_path = tmp_path / "ring.json"
    ring_path.write_text(
        json.dumps({"version": 1, "keys": {"0" * 16: KEY_A.material.hex()}}), encoding="utf-8"
    )
    os.chmod(ring_path, 0o600)
    with pytest.raises(AuditKeyError) as error:
        KeyRing.load(ring_path)
    assert "key id" in str(error.value)


# -- legacy mode -----------------------------------------------------------


def test_a_legacy_log_still_verifies_and_is_readable(tmp_path: Path) -> None:
    """Old logs stay readable: an upgrade must not be a data loss event."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:  # no key: the legacy format
        append_record(log, 0)
        append_record(log, 1)

    records = read_records(path)
    assert not any(is_keyed(record) for record in records)
    assert records[0]["prev_hash"] == ZERO_HASH
    assert "mac" not in records[0]
    # Byte for byte the pre-0.2 record format, plus the ``outcome`` field that
    # G-15 added in 0.6.0: ``decision`` is what the policy said and
    # ``outcome`` is what happened end to end.  The old fields are all still
    # there, and a record written by 0.6.0 still verifies under an older
    # mcp-guard, because the hash covers the fields the record carries.
    assert sorted(records[0]) == sorted(
        [
            "timestamp",
            "session_id",
            "method",
            "tool_name",
            "arguments",
            "decision",
            "outcome",
            "reason",
            "upstream_latency_ms",
            "prev_hash",
            "hash",
        ]
    )
    assert records[0]["outcome"] == "allowed"

    result = verify_log(path, allow_legacy=True)
    assert result.status == STATUS_OK
    assert result.records == 2
    assert not result.keyed
    assert result.exit_code == 0
    # ... but the default refuses it, which is the point of 0.4.
    assert verify_log(path).status == STATUS_REFUSED


def test_a_legacy_log_is_never_reported_as_truncated(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)
    assert verify_log(path, allow_legacy=True).status == STATUS_OK


def test_legacy_mode_can_be_forced_even_with_a_key(tmp_path: Path) -> None:
    """The legacy writer is explicit, and it really is legacy."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A, legacy=True) as log:
        assert not log.keyed
        append_record(log)
    assert not is_keyed(read_records(path)[0])
    assert verify_log(path, allow_legacy=True).status == STATUS_OK
    with pytest.raises(AuditError):
        AuditLog(path, "session-2", key=KEY_A)  # a keyed chain may not continue a legacy one


def test_the_committed_demo_sample_is_still_a_valid_legacy_log(repo_root: Path) -> None:
    result = verify_log(repo_root / "demo" / "audit-sample.jsonl", allow_legacy=True)
    assert result.status == STATUS_OK
    assert result.records == 2
    assert not result.keyed


def test_g09_key_in_keyring_verifies_when_primary_differs(tmp_path: Path) -> None:
    """G-09: A key present in the keyring verifies even if resolver primary key is different."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1", key=KEY_A) as log:
        append_record(log)
    resolver = KeyResolver(key=KEY_B, keyring=KeyRing().add(KEY_A))
    result = verify_log(path, resolver=resolver)
    assert result.status == STATUS_OK
    assert result.records == 1
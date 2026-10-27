"""Tests for the append-only, hash chained audit log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_guard.audit import (
    REQUIRED_FIELDS,
    ZERO_HASH,
    AuditError,
    AuditLog,
    canonical_json,
    compute_hash,
    verify_log,
)


def append_record(log: AuditLog, **overrides: object) -> dict:
    payload = {
        "method": "tools/call",
        "tool_name": "read_file",
        "arguments": {"path": "sandbox/hello.txt"},
        "decision": "allow",
        "reason": "allowed by policy",
        "upstream_latency_ms": 1.5,
    }
    payload.update(overrides)
    return log.append(**payload)  # type: ignore[arg-type]


def test_a_fresh_log_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)
        append_record(log)

    result = verify_log(path)
    assert result.ok
    assert result.records == 2
    assert result.broken_line is None


def test_the_first_record_links_to_the_zero_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        first = append_record(log)
        second = append_record(log)

    assert first["prev_hash"] == ZERO_HASH
    assert len(ZERO_HASH) == 64
    assert second["prev_hash"] == first["hash"]


def test_every_required_field_is_present(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        record = append_record(log)

    for field in REQUIRED_FIELDS:
        assert field in record

    assert record["session_id"] == "session-1"
    assert record["timestamp"].endswith("Z")
    assert record["decision"] == "allow"
    assert record["upstream_latency_ms"] == 1.5


def test_the_latency_is_null_when_the_call_was_not_forwarded(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        record = append_record(log, decision="deny", upstream_latency_ms=None)
    assert record["upstream_latency_ms"] is None


def test_a_single_modified_byte_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)
        append_record(log)

    original = path.read_text(encoding="utf-8")
    # Change exactly one byte in the middle of the file.
    index = original.index("hello.txt")
    tampered = original[:index] + "H" + original[index + 1 :]
    assert len(tampered) == len(original)
    path.write_text(tampered, encoding="utf-8")

    result = verify_log(path)
    assert not result.ok
    assert result.broken_line == 1
    assert "hash" in (result.reason or "")


def test_a_modified_hash_field_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)

    record = json.loads(path.read_text(encoding="utf-8").strip())
    record["hash"] = "0" * 64
    path.write_text(canonical_json(record) + "\n", encoding="utf-8")

    result = verify_log(path)
    assert not result.ok
    assert result.broken_line == 1


def test_a_removed_record_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)
        append_record(log)
        append_record(log)

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_log(path)
    assert not result.ok
    assert result.broken_line == 2
    assert "prev_hash" in (result.reason or "")


def test_a_missing_log_is_reported(tmp_path: Path) -> None:
    result = verify_log(tmp_path / "nope.jsonl")
    assert not result.ok
    assert "not found" in (result.reason or "")


def test_a_missing_field_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps({"session_id": "x"}) + "\n", encoding="utf-8")
    result = verify_log(path)
    assert not result.ok
    assert result.broken_line == 1
    assert "missing" in (result.reason or "")


def test_the_proxy_refuses_to_extend_a_broken_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"not": "a record"}\n', encoding="utf-8")
    with pytest.raises(AuditError) as error:
        AuditLog(path, "session-1")
    assert "does not verify" in str(error.value)


def test_the_log_continues_an_existing_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        first = append_record(log)
    with AuditLog(path, "session-2") as log:
        second = append_record(log)

    assert second["prev_hash"] == first["hash"]
    assert verify_log(path).ok


def test_the_hash_covers_every_field(tmp_path: Path) -> None:
    record = {
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
    digest = compute_hash(record)
    assert len(digest) == 64

    changed = dict(record, reason="because!")
    assert compute_hash(changed) != digest


def test_the_hash_ignores_the_hash_field_itself() -> None:
    record = {"a": 1}
    with_hash = dict(record, hash="whatever")
    assert compute_hash(with_hash) == compute_hash(record)


def test_the_arguments_are_redacted_in_the_audit_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        record = append_record(log, arguments={"path": "a.txt", "api_key": "hunter2"})
    assert record["arguments"]["api_key"] == "***"
    assert record["arguments"]["path"] == "a.txt"
    assert verify_log(path).ok


def test_the_file_is_append_only(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        append_record(log)
        first_size = path.stat().st_size
        append_record(log)
        assert path.stat().st_size > first_size
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_canonical_json_stable_on_opaque_objects() -> None:
    """G-10: canonical_json produces stable strings for unhandled object types."""
    class Opaque:
        pass

    assert canonical_json({"a": Opaque()}) == canonical_json({"a": Opaque()})
    assert compute_hash({"a": Opaque()}) == compute_hash({"a": Opaque()})


def test_canonical_json_preserves_unicode_line_separators() -> None:
    """U+2028 and U+2029 are preserved in canonical_json (handled by read_log_lines)."""
    encoded = canonical_json({"text": "line\u2028sep\u2029para"})
    assert "\u2028" in encoded
    assert "\u2029" in encoded

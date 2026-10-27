"""Tests for the ``verify`` exit codes and the key commands.

The four exit codes are the contract an operator scripts against:

==== ==========================================================
   0 ``OK``      the chain verifies and the log is sealed
   1 ``BROKEN``  the chain does not verify
   2 ``WARN``    the chain verifies but the log is missing its tail
   3 ``KEY``     no usable key: none, the wrong one, or an unsafe key file
==== ==========================================================
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

import pytest

from .conftest import REPO_ROOT, child_environment
from mcp_guard.audit import AuditLog, canonical_json, compute_hash
from mcp_guard.cli import EXIT_BROKEN, EXIT_KEY, EXIT_OK, EXIT_USAGE, main
from mcp_guard.keys import AuditKey, KeyRing, key_id_for, read_key_file, write_key_file

KEY_A = AuditKey.from_material("a" * 64)
KEY_B = AuditKey.from_material("b" * 64)


# -- helpers ---------------------------------------------------------------


def append_record(log: AuditLog, index: int = 0) -> dict[str, Any]:
    return log.append(
        method="tools/call",
        tool_name="read_file",
        arguments={"path": f"sandbox/hello-{index}.txt"},
        decision="allow",
        reason="allowed by policy",
        upstream_latency_ms=1.0,
    )


def write_log(
    tmp_path: Path, key: AuditKey | None = KEY_A, count: int = 4, interval: int = 100, name: str = "audit.jsonl"
) -> Path:
    path = tmp_path / name
    with AuditLog(path, "session-1", key=key, checkpoint_interval=interval) as log:
        for index in range(count):
            append_record(log, index)
    return path


def run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run the command line in a subprocess, the way an operator would."""
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


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    return write_key_file(tmp_path / "audit.key", KEY_A.material)


# -- exit code 0 -----------------------------------------------------------


def test_a_clean_keyed_log_exits_zero(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path)
    assert main(["verify", str(path), "--audit-key-file", str(key_file)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("OK:")
    assert "HMAC-SHA256 chain intact" in out
    assert "4 record(s)" in out
    assert key_id_for(KEY_A.material) in out


def test_verify_log_is_still_a_valid_command(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The old command name keeps working: scripts must not break."""
    path = write_log(tmp_path)
    assert main(["verify-log", str(path), "--audit-key-file", str(key_file)]) == EXIT_OK
    assert capsys.readouterr().out.startswith("OK:")


def test_the_key_can_be_given_in_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path)
    monkeypatch.setenv("MCP_GUARD_AUDIT_KEY", KEY_A.material.hex())
    assert main(["verify", str(path)]) == EXIT_OK
    assert capsys.readouterr().out.startswith("OK:")


# -- exit code 1 -----------------------------------------------------------


def test_a_tampered_record_exits_one(
    tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path)
    records = read_records(path)
    records[1]["decision"] = "allow"
    records[1]["reason"] = "allowed by policy  "  # two bytes the attacker likes to have
    records[1]["mac"] = records[0]["mac"]  # a plausible-looking MAC
    records[1]["hash"] = compute_hash(records[1])
    tampered = tmp_path / "tampered.jsonl"
    write_records(tampered, records)

    assert main(["verify", str(tampered), "--audit-key-file", str(key_file)]) == EXIT_BROKEN
    out = capsys.readouterr().out
    assert "BROKEN: line 2" in out
    assert "mac" in out


def test_a_full_rewrite_exits_one(tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Rewrite everything, recompute every unkeyed hash, get caught."""
    path = write_log(tmp_path, count=3)
    records = read_records(path)
    previous = "0" * 64
    for record in records:
        record["reason"] = "everything is fine"
        record["prev_hash"] = previous
        record["hash"] = compute_hash(record)
        previous = record["hash"]
    rewritten = tmp_path / "rewritten.jsonl"
    write_records(rewritten, records)

    assert main(["verify", str(rewritten), "--audit-key-file", str(key_file)]) == EXIT_BROKEN
    assert "BROKEN: line 1" in capsys.readouterr().out


# -- exit code 2 -----------------------------------------------------------


def test_a_truncated_tail_exits_two(tmp_path: Path, key_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_log(tmp_path, count=6, interval=2)
    records = read_records(path)
    truncated = tmp_path / "truncated.jsonl"
    write_records(truncated, records[:-2])

    assert main(["verify", str(truncated), "--audit-key-file", str(key_file)]) == EXIT_USAGE
    out = capsys.readouterr().out
    assert out.startswith("WARN:")
    assert "may have been removed" in out


# -- exit code 3 -----------------------------------------------------------


def test_the_wrong_key_exits_three(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_log(tmp_path)
    other = write_key_file(tmp_path / "other.key", KEY_B.material)
    assert main(["verify", str(path), "--audit-key-file", str(other)]) == EXIT_KEY
    out = capsys.readouterr().out
    assert out.startswith("KEY ERROR:")
    assert key_id_for(KEY_A.material) in out


def test_no_key_at_all_exits_three(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_log(tmp_path)
    assert main(["verify", str(path)]) == EXIT_KEY
    assert capsys.readouterr().out.startswith("KEY ERROR:")


def test_a_world_readable_key_file_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path)
    key = write_key_file(tmp_path / "loose.key", KEY_A.material)
    os.chmod(key, 0o644)
    assert main(["verify", str(path), "--audit-key-file", str(key)]) == EXIT_KEY
    assert "readable by group or other" in capsys.readouterr().out
    assert KEY_A.material.hex() not in capsys.readouterr().out


def test_an_unkeyed_log_can_be_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--require-keyed is a deprecated no-op: refusing is what verify now does."""
    path = write_log(tmp_path, key=None, name="legacy.jsonl")
    assert main(["verify", str(path), "--require-keyed"]) == EXIT_KEY
    assert "REFUSED" in capsys.readouterr().out


def test_run_refuses_an_unsafe_key_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    key = write_key_file(tmp_path / "loose.key", KEY_A.material)
    os.chmod(key, 0o644)

    code = main(
        [
            "run",
            "--policy",
            str(policy),
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--audit-key-file",
            str(key),
            "--",
            "echo",
            "hi",
        ]
    )
    assert code == EXIT_KEY
    assert "readable by group or other" in capsys.readouterr().err
    assert not (tmp_path / "audit.jsonl").exists()


# -- legacy ----------------------------------------------------------------


def test_a_legacy_log_verifies_with_a_warning_only_when_asked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reading an old log still works -- with --allow-legacy, and loudly."""
    path = write_log(tmp_path, key=None, name="legacy.jsonl")
    assert main(["verify", str(path)]) == EXIT_KEY
    assert capsys.readouterr().out.startswith("REFUSED: legacy unkeyed chain")

    assert main(["verify", str(path), "--allow-legacy"]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.startswith("OK: 4 record(s) verified, hash chain intact")
    assert "LEGACY unkeyed chain" in captured.err
    assert "full rewrite" in captured.err


# -- keygen ----------------------------------------------------------------


def test_keygen_writes_a_private_file_and_never_prints_the_key(tmp_path: Path) -> None:
    target = tmp_path / "audit.key"
    result = run(["keygen", "--out", str(target)])
    assert result.returncode == EXIT_OK
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    material = read_key_file(target)
    assert len(material) >= 32

    rendered = result.stdout + result.stderr
    assert material.hex() not in rendered
    assert material.hex()[:32] not in rendered
    assert "key id" in result.stdout
    # ... and the key it wrote verifies a log written with it.
    log = write_log(tmp_path, key=AuditKey.from_material(material), name="with-new-key.jsonl")
    assert run(["verify", str(log), "--audit-key-file", str(target)]).returncode == EXIT_OK


def test_keygen_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "audit.key"
    assert run(["keygen", "--out", str(target)]).returncode == EXIT_OK
    before = target.read_text()
    again = run(["keygen", "--out", str(target)])
    assert again.returncode == EXIT_KEY
    assert "--force" in again.stderr
    assert target.read_text() == before
    assert run(["keygen", "--out", str(target), "--force"]).returncode == EXIT_OK


# -- rotation --------------------------------------------------------------


def test_rotate_key_then_verify_with_the_keyring(tmp_path: Path, key_file: Path) -> None:
    path = write_log(tmp_path, count=3)
    new_key = write_key_file(tmp_path / "new.key", KEY_B.material)
    ring = tmp_path / "ring.json"

    rotated = run(
        [
            "rotate-key",
            "--audit",
            str(path),
            "--audit-key-file",
            str(key_file),
            "--new-key-file",
            str(new_key),
            "--audit-keyring",
            str(ring),
        ]
    )
    assert rotated.returncode == EXIT_OK, rotated.stderr
    assert key_id_for(KEY_A.material) in rotated.stdout
    assert key_id_for(KEY_B.material) in rotated.stdout
    assert KEY_B.material.hex() not in rotated.stdout + rotated.stderr

    records = read_records(path)
    rotation = [record for record in records if record["record_type"] == "rotation"]
    assert len(rotation) == 1
    assert rotation[0]["key_id"] == key_id_for(KEY_B.material)

    verified = run(["verify", str(path), "--audit-keyring", str(ring)])
    assert verified.returncode == EXIT_OK, verified.stdout + verified.stderr
    assert "1 rotation(s)" in verified.stdout

    # One key alone is not enough any more: the log spans two of them.
    assert run(["verify", str(path), "--audit-key-file", str(key_file)]).returncode == EXIT_KEY


def test_rotate_key_adds_the_new_key_to_the_keyring(tmp_path: Path, key_file: Path) -> None:
    path = write_log(tmp_path, count=1)
    new_key = write_key_file(tmp_path / "new.key", KEY_B.material)
    ring = tmp_path / "ring.json"
    assert stat.S_IMODE(ring.stat().st_mode) == 0o600 if ring.exists() else True

    assert (
        run(
            [
                "rotate-key",
                "--audit",
                str(path),
                "--audit-key-file",
                str(key_file),
                "--new-key-file",
                str(new_key),
                "--audit-keyring",
                str(ring),
            ]
        ).returncode
        == EXIT_OK
    )
    assert KEY_B.material.hex() in ring.read_text()  # the ring is a key store, not a log
    assert stat.S_IMODE(ring.stat().st_mode) == 0o600
    assert set(KeyRing.load(ring).ids()) == {
        key_id_for(KEY_A.material),
        key_id_for(KEY_B.material),
    }


def test_rotate_key_refuses_a_world_readable_new_key(tmp_path: Path, key_file: Path) -> None:
    path = write_log(tmp_path, count=1)
    new_key = write_key_file(tmp_path / "new.key", KEY_B.material)
    os.chmod(new_key, 0o644)
    result = run(
        [
            "rotate-key",
            "--audit",
            str(path),
            "--audit-key-file",
            str(key_file),
            "--new-key-file",
            str(new_key),
        ]
    )
    assert result.returncode == EXIT_KEY
    assert "readable by group or other" in result.stderr
    assert all(record["record_type"] != "rotation" for record in read_records(path))


def test_rotate_key_refuses_an_unkeyed_log(tmp_path: Path) -> None:
    path = write_log(tmp_path, key=None, name="legacy.jsonl")
    new_key = write_key_file(tmp_path / "new.key", KEY_B.material)
    result = run(
        [
            "rotate-key",
            "--audit",
            str(path),
            "--audit-key-file",
            str(new_key),
            "--new-key-file",
            str(new_key),
        ]
    )
    assert result.returncode == EXIT_BROKEN
    assert "unkeyed legacy chain" in result.stderr


def test_rotate_key_refuses_a_log_that_does_not_verify(tmp_path: Path, key_file: Path) -> None:
    path = write_log(tmp_path, count=3)
    records = read_records(path)
    records[0]["reason"] = "rewritten"
    records[0]["hash"] = compute_hash(records[0])
    write_records(path, records)
    new_key = write_key_file(tmp_path / "new.key", KEY_B.material)

    result = run(
        [
            "rotate-key",
            "--audit",
            str(path),
            "--audit-key-file",
            str(key_file),
            "--new-key-file",
            str(new_key),
        ]
    )
    assert result.returncode == EXIT_BROKEN
    assert "does not verify" in result.stderr
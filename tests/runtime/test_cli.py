"""Tests for the command line interface.

(The reference layout lists seven test modules; this one is added because the
``verify-log`` command and the argument handling are part of the deliverable
and deserve their own tests.)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import REPO_ROOT, SOURCE_ROOT, child_environment
from mcp_guard.audit import AuditLog, compute_hash
from mcp_guard.cli import main


def test_verify_log_reports_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        log.append(
            method="tools/call",
            tool_name="read_file",
            arguments={"path": "a.txt"},
            decision="allow",
            reason="allowed by policy",
            upstream_latency_ms=1.0,
        )

    assert main(["verify-log", str(path), "--allow-legacy"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("OK:")
    assert "1 record" in captured.out
    assert "LEGACY unkeyed chain" in captured.err


def test_verify_log_reports_the_first_broken_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "session-1") as log:
        for index in range(3):
            log.append(
                method="tools/call",
                tool_name="read_file",
                arguments={"path": f"file-{index}.txt"},
                decision="allow",
                reason="allowed by policy",
                upstream_latency_ms=1.0,
            )

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["arguments"]["path"] = "tampered.txt"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["verify-log", str(path)]) == 1
    out = capsys.readouterr().out
    assert "BROKEN: line 2" in out
    assert "hash" in out


def test_verify_log_reports_a_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify-log", str(tmp_path / "nope.jsonl")]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_run_without_an_upstream_command_exits_with_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    assert main(["run", "--policy", str(policy)]) == 2
    assert "no upstream command" in capsys.readouterr().err


def test_run_with_a_missing_policy_file_exits_with_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["run", "--policy", str(tmp_path / "nope.yaml"), "--", "echo", "hi"]) == 2
    assert "not found" in capsys.readouterr().err


def test_run_with_an_invalid_policy_file_reports_the_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("tools:\n  read_file:\n    action: maybe\n", encoding="utf-8")
    assert main(["run", "--policy", str(policy), "--", "echo", "hi"]) == 2
    error = capsys.readouterr().err
    assert "is invalid" in error
    assert "tools.read_file.action" in error


def test_run_rejects_a_ttl_of_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    assert main(["run", "--policy", str(policy), "--ttl", "0", "--", "echo", "hi"]) == 2
    assert "--ttl" in capsys.readouterr().err


def test_run_rejects_nan_and_inf_timeouts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """G-19: NaN and inf timeouts must be rejected cleanly as usage errors."""
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    for bad_arg in (["--upstream-timeout", "nan"], ["--upstream-timeout", "inf"], ["--upstream-timeout=-inf"]):
        assert main(["run", "--policy", str(policy)] + bad_arg + ["--", "echo", "hi"]) == 2
        assert "--upstream-timeout" in capsys.readouterr().err


def test_the_version_is_printed() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "--version"],
        capture_output=True,
        text=True,
        env=child_environment(),
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0
    assert result.stdout.startswith("mcp-guard ")


def test_the_hash_of_a_record_is_stable() -> None:
    record = {
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "session_id": "s",
        "method": "tools/call",
        "tool_name": "t",
        "arguments": {},
        "decision": "allow",
        "reason": "because",
        "upstream_latency_ms": None,
        "prev_hash": "0" * 64,
    }
    assert compute_hash(record) == compute_hash(dict(record))
    assert SOURCE_ROOT.is_dir()

"""Tests for the filesystem path guards."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_guard.paths import (
    ABSOLUTE_PATH,
    INVALID_PATH,
    OUTSIDE_PREFIX,
    PathViolation,
    check_path,
)
from mcp_guard.policy import DENY, Policy, PolicyEngine


def test_a_relative_path_inside_the_prefix_is_accepted(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("hi", encoding="utf-8")

    resolved = check_path("sandbox/hello.txt", "./sandbox", tmp_path)
    assert resolved == (sandbox / "hello.txt").resolve()


def test_a_dot_dot_traversal_is_denied(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(PathViolation) as error:
        check_path("../../etc/passwd", "./sandbox", tmp_path)
    assert error.value.code == OUTSIDE_PREFIX


def test_a_dot_dot_that_stays_inside_is_accepted(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("hi", encoding="utf-8")
    resolved = check_path("sandbox/../sandbox/hello.txt", "./sandbox", tmp_path)
    assert resolved == (sandbox / "hello.txt").resolve()


def test_an_absolute_path_is_denied_when_the_prefix_is_relative(tmp_path: Path) -> None:
    with pytest.raises(PathViolation) as error:
        check_path("/etc/passwd", "./sandbox", tmp_path)
    assert error.value.code == ABSOLUTE_PATH


def test_an_absolute_path_inside_an_absolute_prefix_is_accepted(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    target = sandbox / "hello.txt"
    target.write_text("hi", encoding="utf-8")
    resolved = check_path(str(target), str(sandbox), tmp_path)
    assert resolved == target.resolve()


def test_an_absolute_path_outside_an_absolute_prefix_is_denied(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(PathViolation) as error:
        check_path("/etc/passwd", str(sandbox), tmp_path)
    assert error.value.code == OUTSIDE_PREFIX


def test_a_symlink_that_escapes_the_prefix_is_denied(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = sandbox / "escape.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    with pytest.raises(PathViolation) as error:
        check_path("sandbox/escape.txt", "./sandbox", tmp_path)
    assert error.value.code == OUTSIDE_PREFIX


def test_a_symlink_that_stays_inside_the_prefix_is_accepted(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    target = sandbox / "hello.txt"
    target.write_text("hi", encoding="utf-8")
    link = sandbox / "alias.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    resolved = check_path("sandbox/alias.txt", "./sandbox", tmp_path)
    assert resolved == target.resolve()


def test_a_symlinked_directory_that_escapes_is_denied(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = sandbox / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    with pytest.raises(PathViolation) as error:
        check_path("sandbox/link/secret.txt", "./sandbox", tmp_path)
    assert error.value.code == OUTSIDE_PREFIX


def test_a_path_with_a_nul_byte_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathViolation) as error:
        check_path("sandbox/\x00.txt", "./sandbox", tmp_path)
    assert error.value.code == INVALID_PATH


def test_an_empty_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathViolation) as error:
        check_path("   ", "./sandbox", tmp_path)
    assert error.value.code == INVALID_PATH


def test_a_non_string_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathViolation) as error:
        check_path(42, "./sandbox", tmp_path)  # type: ignore[arg-type]
    assert error.value.code == INVALID_PATH


def test_the_policy_reports_a_path_violation(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "arguments": {"path": {"path_prefix": "./sandbox"}}}}}
    )
    engine = PolicyEngine(policy, session_id="s", base_dir=tmp_path)

    inside = engine.evaluate("read_file", {"path": "sandbox/ok.txt"})
    assert inside.allowed

    outside = engine.evaluate("read_file", {"path": "../../etc/passwd"})
    assert outside.decision == DENY
    assert outside.violations
    assert "path_prefix" in outside.violations[0]


def test_a_path_prefix_also_refuses_absolute_paths(tmp_path: Path) -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "arguments": {"path": {"path_prefix": "./sandbox"}}}}}
    )
    engine = PolicyEngine(policy, session_id="s", base_dir=tmp_path)
    decision = engine.evaluate("read_file", {"path": "/etc/passwd"})
    assert decision.decision == DENY
    assert "absolute path" in decision.reason


def test_the_prefix_is_resolved_symlinks(tmp_path: Path) -> None:
    """A prefix that is itself reached through a symlink still matches."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "hello.txt").write_text("hi", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    resolved = check_path("link/hello.txt", "./link", tmp_path)
    assert resolved == (real / "hello.txt").resolve()
    assert os.path.commonpath([str(resolved), str(real.resolve())]) == str(real.resolve())


def test_url_schemes_are_rejected_in_check_path(tmp_path: Path) -> None:
    """OPUS-03: URL schemes like http:// or file:// are rejected by check_path."""
    (tmp_path / "sandbox").mkdir()
    with pytest.raises(PathViolation) as exc:
        check_path("http://[::ffff:127.0.0.1]/admin", "./sandbox", tmp_path)
    assert "URL scheme" in str(exc.value)


def test_unicode_nfc_and_nfd_spellings_match_same_directory(tmp_path: Path) -> None:
    """G-12: Composed (NFC) and decomposed (NFD) spellings match the same directory."""
    import unicodedata

    prefix_nfc = unicodedata.normalize("NFC", "café")
    candidate_nfd = unicodedata.normalize("NFD", "café")
    (tmp_path / prefix_nfc).mkdir()
    (tmp_path / prefix_nfc / "hello.txt").write_text("ok", encoding="utf-8")

    resolved = check_path(f"{candidate_nfd}/hello.txt", f"./{prefix_nfc}", tmp_path)
    assert resolved.exists()
    assert resolved.is_relative_to(tmp_path.resolve())

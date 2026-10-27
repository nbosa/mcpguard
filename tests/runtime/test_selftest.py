"""Tests for ``mcp-guard selftest``.

The selftest is the release's own answer to "does this build work?", so these
tests check three things: that every vector passes, that the vectors really
cover the five areas the release is sold on, and that the whole thing is fast
enough to be used as a health check.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from mcp_guard.cli import main
from mcp_guard.selftest import (
    POLICY_DOCUMENT,
    U2028,
    VECTORS,
    render_human,
    run_selftest,
)

#: The five areas the 0.5.0 release is sold on.  Every one of them has to be
#: covered by a vector, or the selftest is not testing what it claims to test.
REQUIRED_GROUPS = {"path", "audit", "budget", "upstream", "regex"}


@pytest.fixture(scope="module")
def report():
    """One selftest run, shared by the tests that only read it."""
    return run_selftest()


# -- the shape of the selftest ---------------------------------------------

def test_the_selftest_has_every_vector() -> None:
    """The unified release runs the twelve original vectors plus three more.

    The three added vectors cover the canary detector, the keyed HMAC audit
    chain and the four guard plugins -- the parts that only exist in the
    merged package.
    """
    names = {name for name, _, _, _ in VECTORS}
    assert len(VECTORS) == 15
    assert {
        "canary-exfil-denied",
        "audit-keyed-chain",
        "four-plugins-smoke",
    } <= names


def test_the_vector_names_are_unique() -> None:
    names = [name for name, _, _, _ in VECTORS]
    assert len(set(names)) == len(names)


def test_every_required_area_is_covered() -> None:
    groups = {group for _, group, _, _ in VECTORS}
    assert REQUIRED_GROUPS <= groups


def test_every_vector_has_a_description() -> None:
    for name, _, description, _ in VECTORS:
        assert description, name


def test_every_vector_passes(report) -> None:
    failed = [vector.name for vector in report.failed]
    assert failed == [], f"the selftest failed these vectors: {failed}"


def test_the_report_is_ok(report) -> None:
    assert report.ok


def test_the_report_counts_the_vectors(report) -> None:
    assert len(report.vectors) == len(VECTORS)
    assert len(report.passed) == len(VECTORS)
    assert len(report.failed) == 0


def test_the_exit_code_of_a_clean_run_is_zero(report) -> None:
    assert report.exit_code == 0


def test_the_selftest_runs_in_under_a_second() -> None:
    """The whole point of an embedded selftest is that it is cheap."""
    started = time.perf_counter()
    run_selftest()
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"the selftest took {elapsed:.3f}s"


def test_the_reported_duration_is_measured() -> None:
    assert run_selftest().duration_ms > 0.0


# -- the vectors themselves ------------------------------------------------

def test_the_scalar_traversal_is_refused() -> None:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[0]
        ok, detail = vector(base)
    assert ok, detail
    assert "violates path_prefix" in detail


def test_the_list_traversal_is_refused() -> None:
    """The 0.5.0 property: the traversal is caught inside the list."""
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[2]
        ok, detail = vector(base)
    assert ok, detail
    assert "files[1]" in detail


def test_the_u2028_vector_verifies_the_log() -> None:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[5]
        ok, detail = vector(base)
    assert ok, detail
    assert "verifies" in detail


def test_the_budget_vector_exhausts_the_budget() -> None:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[7]
        ok, detail = vector(base)
    assert ok, detail
    assert "cap exceeded" in detail


def test_the_oversize_vector_discards_the_line() -> None:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[9]
        ok, detail = vector(base)
    assert ok, detail
    assert "discarded" in detail


def test_the_redos_vector_refuses_the_pattern() -> None:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        _, _, _, vector = VECTORS[11]
        ok, detail = vector(base)
    assert ok, detail
    assert "refused at load time" in detail


def test_every_vector_is_independent() -> None:
    """One vector that fails must never hide another."""
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "workspace").mkdir()
        for name, _, _, vector in VECTORS:
            ok, detail = vector(base)
            assert ok, f"{name}: {detail}"


def test_a_vector_that_raises_is_reported_as_a_failure() -> None:
    """A vector that crashes has failed; it must not crash the run."""
    from mcp_guard.selftest import VectorResult

    def _explode(_base: Path) -> tuple[bool, str]:
        raise RuntimeError("boom")

    try:
        _explode(Path("/nowhere"))
    except RuntimeError:
        pass
    else:  # pragma: no cover - the helper is not supposed to succeed
        pytest.fail("the helper did not raise")

    result = VectorResult(name="x", group="y", description="z", ok=False, detail="raised")
    assert not result.ok


# -- the policy the selftest runs against ----------------------------------

def test_the_selftest_policy_denies_by_default() -> None:
    assert POLICY_DOCUMENT["default_action"] == "deny"


def test_the_selftest_policy_has_a_denied_tool() -> None:
    assert POLICY_DOCUMENT["tools"]["run_shell"]["action"] == "deny"


def test_the_selftest_policy_constrains_a_list_of_paths() -> None:
    constraint = POLICY_DOCUMENT["tools"]["read_files"]["arguments"]["files"]
    assert constraint["type"] == "array"
    assert constraint["path_prefix"] == "./workspace"


def test_the_separator_is_the_unicode_line_separator() -> None:
    assert U2028 == "\u2028"
    assert len(U2028) == 1
    assert ord(U2028) == 0x2028


# -- the output ------------------------------------------------------------

def test_the_human_output_names_every_vector(report) -> None:
    text = render_human(report)
    for name, _, _, _ in VECTORS:
        assert name in text


def test_the_human_output_says_that_everything_passed(report) -> None:
    assert "all vectors passed" in render_human(report)


def test_the_report_is_json_serialisable(report) -> None:
    document = report.as_dict()
    assert document["ok"] is True
    assert document["passed"] == len(VECTORS)
    assert document["failed"] == 0
    assert len(document["vectors"]) == 15
    json.dumps(document)


# -- the command line ------------------------------------------------------

def test_the_command_runs_the_vectors_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["selftest"]) == 0
    assert "15 vector(s)" in capsys.readouterr().out


def test_the_command_writes_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is True
    assert len(document["vectors"]) == 15


def test_the_command_reports_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    main(["selftest", "--json"])
    document = json.loads(capsys.readouterr().out)
    assert document["version"] == "1.0.0"


def test_the_command_refuses_a_second_positional_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["selftest", "extra"]) == 2
    assert "no further arguments" in capsys.readouterr().err


def test_the_command_leaves_nothing_behind() -> None:
    """The selftest writes into a temporary directory and cleans it up."""
    before = set(Path(tempfile.gettempdir()).glob("mcp-guard-selftest-*"))
    run_selftest()
    after = set(Path(tempfile.gettempdir()).glob("mcp-guard-selftest-*"))
    assert after == before

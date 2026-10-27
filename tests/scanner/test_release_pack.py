"""Tests for the release artifacts: REPORT.md, MANIFEST.md, VERIFY.md and the zip.

These tests validate the shipped release pack itself. When the artifacts have
not been built yet they are skipped, so the suite stays runnable on a clean
checkout; after ``tools/build_release.py`` has run they all execute.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

import pytest

MANIFEST_NAME = "MANIFEST.md"
VERIFY_NAME = "VERIFY.md"
REPORT_NAME = "REPORT.md"
ZIP_NAME = "mcp-guard-v1.0.0-oss.zip"

#: `| `path/to/file` | 123 | `sha256` |`
ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*`([0-9a-f]{64})`\s*\|\s*$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_artifacts(repo_root: Path) -> None:
    missing = [
        name
        for name in (REPORT_NAME, MANIFEST_NAME, VERIFY_NAME, ZIP_NAME)
        if not (repo_root / name).is_file()
    ]
    if missing:
        pytest.skip(
            "release artifacts not built yet (missing: " + ", ".join(missing) + ")"
        )


@pytest.fixture
def artifacts(repo_root):
    _require_artifacts(repo_root)
    return repo_root


def _manifest_rows(repo_root: Path) -> list[tuple[str, int, str]]:
    text = (repo_root / MANIFEST_NAME).read_text(encoding="utf-8")
    rows = []
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if match:
            rows.append((match.group(1), int(match.group(2)), match.group(3)))
    return rows


# --------------------------------------------------------------------------
# presence and shape
# --------------------------------------------------------------------------
def test_report_exists_and_is_substantial(artifacts):
    text = (artifacts / REPORT_NAME).read_text(encoding="utf-8")
    assert len(text) > 5000
    assert text.startswith("# ")


def test_report_covers_every_requirement(artifacts):
    text = (artifacts / REPORT_NAME).read_text(encoding="utf-8")
    for token in (
        "etdi_pinning",
        "ansi_sanitize",
        "path_shape",
        "canary_exfil",
        "policy-lint",
        "pin-manifest",
        "sanitize-output",
        "canary-check",
    ):
        assert token in text, token


def test_verify_exists_and_has_a_pass_verdict(artifacts):
    text = (artifacts / VERIFY_NAME).read_text(encoding="utf-8")
    assert "VERDICT: PASS" in text
    assert "VERDICT: FAIL" not in text


def test_verify_records_the_test_suite(artifacts):
    text = (artifacts / VERIFY_NAME).read_text(encoding="utf-8")
    assert "pytest" in text
    assert "mcp-guard selftest" in text
    assert "mcp-guard policy-lint" in text


def test_manifest_exists_and_lists_files(artifacts):
    rows = _manifest_rows(artifacts)
    assert len(rows) > 40


# --------------------------------------------------------------------------
# manifest integrity
# --------------------------------------------------------------------------
def test_manifest_files_all_exist(artifacts):
    for path, _size, _digest in _manifest_rows(artifacts):
        assert (artifacts / path).is_file(), path


def test_manifest_sizes_match(artifacts):
    for path, size, _digest in _manifest_rows(artifacts):
        assert (artifacts / path).stat().st_size == size, path


def test_manifest_digests_match(artifacts):
    for path, _size, digest in _manifest_rows(artifacts):
        assert _sha256(artifacts / path) == digest, path


def test_manifest_covers_the_source_tree(artifacts):
    paths = {path for path, _size, _digest in _manifest_rows(artifacts)}
    assert "src/mcp_guard/__init__.py" in paths
    assert "src/mcp_guard/plugins/path_shape.py" in paths
    assert "src/mcp_guard/cli/main.py" in paths
    assert "src/mcp_guard/data/default_policy.toml" in paths


def test_manifest_covers_the_tests_and_docs(artifacts):
    paths = {path for path, _size, _digest in _manifest_rows(artifacts)}
    assert any(path.startswith("tests/") for path in paths)
    assert "docs/en/rules.md" in paths


def test_manifest_excludes_itself_and_the_zip(artifacts):
    paths = {path for path, _size, _digest in _manifest_rows(artifacts)}
    assert MANIFEST_NAME not in paths
    assert ZIP_NAME not in paths


def test_manifest_states_the_exclusions(artifacts):
    text = (artifacts / MANIFEST_NAME).read_text(encoding="utf-8")
    assert MANIFEST_NAME in text
    assert ZIP_NAME in text


# --------------------------------------------------------------------------
# the release zip
# --------------------------------------------------------------------------
def test_zip_is_a_valid_archive(artifacts):
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        assert archive.testzip() is None


def test_zip_contains_the_entry_points(artifacts):
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        names = {name.split("/", 1)[1] for name in archive.namelist() if "/" in name}
    for expected in (
        "README.md",
        "REPORT.md",
        "MANIFEST.md",
        "VERIFY.md",
        "LICENSE",
        "CHANGELOG.md",
        "pyproject.toml",
        "src/mcp_guard/__init__.py",
        "src/mcp_guard/core/engine.py",
        "src/mcp_guard/plugins/path_shape.py",
        "src/mcp_guard/cli/main.py",
        "src/mcp_guard/data/default_policy.toml",
        "docs/en/rules.md",
        "examples/policy.toml",
        "examples/transcript.json",
        "tests/test_adversarial_runtime.py",
        "tests/test_adversarial_scanner.py",
    ):
        assert expected in names, expected


def test_zip_excludes_caches(artifacts):
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        names = archive.namelist()
    assert not [name for name in names if "__pycache__" in name]
    assert not [name for name in names if name.endswith(".pyc")]


def test_zip_has_a_single_top_level_directory(artifacts):
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        roots = {name.split("/", 1)[0] for name in archive.namelist()}
    assert roots == {"mcp-guard-v1.0.0-oss"}


def test_zip_content_matches_the_working_tree(artifacts):
    prefix = "mcp-guard-v1.0.0-oss/"
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        for name in ("README.md", "src/mcp_guard/core/engine.py"):
            assert archive.read(prefix + name) == (artifacts / name).read_bytes(), name


def test_zip_contains_every_shipped_python_module(artifacts):
    with zipfile.ZipFile(artifacts / ZIP_NAME) as archive:
        names = {name.split("/", 1)[1] for name in archive.namelist() if "/" in name}
    for module in (
        "core/severity.py",
        "core/result.py",
        "core/request.py",
        "core/textutil.py",
        "core/redact.py",
        "core/policy.py",
        "core/lint.py",
        "core/plugin.py",
        "core/registry.py",
        "core/engine.py",
        "core/etdi.py",
        "core/manifest.py",
        "core/samples.py",
        "plugins/etdi_pinning.py",
        "plugins/ansi_sanitize.py",
        "plugins/path_shape.py",
        "plugins/canary_exfil.py",
        "cli/main.py",
        "cli/common.py",
        "cli/output.py",
        "cli/cmd_check.py",
        "cli/cmd_policy_lint.py",
        "cli/cmd_selftest.py",
        "cli/cmd_pin_manifest.py",
        "cli/cmd_sanitize.py",
        "cli/cmd_canary.py",
    ):
        assert f"src/mcp_guard/{module}" in names, module

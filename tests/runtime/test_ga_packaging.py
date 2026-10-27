"""Tests for the 0.5.0 GA packaging.

The release is a package, and a package that cannot be installed is not a
release.  These tests pin down the things that break most often at the very
end of a release: a version that says one thing in the metadata and another
in the code, a module that is in the source tree but not in the wheel, a
changelog that was never written, and a benchmark whose numbers were never
produced.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

import mcp_guard
from mcp_guard import __version__
from mcp_guard.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"


def bundle_root() -> Path | None:
    """The root of the release bundle, if this tree is part of one."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "src-ga").is_dir() and (candidate / "benchmarks").is_dir():
            return candidate
    return None


BUNDLE = bundle_root()
needs_bundle = pytest.mark.skipif(
    BUNDLE is None, reason="this tree is not part of a release bundle"
)


def pyproject() -> dict:
    """The parsed ``pyproject.toml`` of the release."""
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


# -- the version -----------------------------------------------------------

def test_the_version_is_the_release_version() -> None:
    assert __version__ == "1.0.0"


def test_the_version_is_one_number_in_the_metadata() -> None:
    assert pyproject()["project"]["version"] == __version__


def test_the_version_is_one_number_on_the_command_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip().startswith(f"mcp-guard {__version__}")


def test_the_release_is_marked_as_production() -> None:
    classifiers = pyproject()["project"]["classifiers"]
    assert "Development Status :: 5 - Production/Stable" in classifiers


def test_the_release_is_not_marked_as_a_beta() -> None:
    classifiers = pyproject()["project"]["classifiers"]
    assert "Development Status :: 4 - Beta" not in classifiers


def test_the_package_metadata_names_the_project() -> None:
    assert pyproject()["project"]["name"] == "mcp-guard"


# -- the new commands ------------------------------------------------------

def test_the_console_script_is_declared() -> None:
    assert pyproject()["project"]["scripts"]["mcp-guard"] == "mcp_guard.cli:main"


def test_the_new_modules_are_part_of_the_package() -> None:
    from mcp_guard import lint, selftest

    assert lint.__name__ == "mcp_guard.lint"
    assert selftest.__name__ == "mcp_guard.selftest"


def test_the_new_modules_are_in_the_source_tree() -> None:
    assert (SOURCE_ROOT / "mcp_guard" / "lint.py").is_file()
    assert (SOURCE_ROOT / "mcp_guard" / "selftest.py").is_file()


def test_both_new_commands_are_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    text = capsys.readouterr().out
    assert "policy-lint" in text
    assert "selftest" in text


def test_the_old_commands_still_work(capsys: pytest.CaptureFixture[str]) -> None:
    """The new commands are added, not substituted."""
    with pytest.raises(SystemExit):
        main(["--help"])
    text = capsys.readouterr().out
    for command in ("run", "verify", "keygen", "rotate-key"):
        assert command in text


def test_the_package_ships_the_new_modules() -> None:
    """Both new modules have to be inside the installed package."""
    package = Path(mcp_guard.__file__).resolve().parent
    assert (package / "lint.py").is_file()
    assert (package / "selftest.py").is_file()


# -- the artifacts ---------------------------------------------------------

def test_the_wheel_can_be_built(tmp_path: Path) -> None:
    """The wheel is built from this tree, and it builds."""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    wheels = list(tmp_path.glob(f"mcp_guard-{__version__}*-*.whl"))
    assert len(wheels) == 1, wheels


def test_the_wheel_carries_the_new_modules(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    wheel = list(tmp_path.glob(f"mcp_guard-{__version__}*-*.whl"))[0]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "mcp_guard/lint.py" in names
    assert "mcp_guard/selftest.py" in names
    assert "mcp_guard/canary.py" in names
    assert "mcp_guard/cli.py" in names or "mcp_guard/cli/__init__.py" in names


def test_the_sdist_carries_the_tests_and_the_examples(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    sdist = list(tmp_path.glob(f"mcp_guard-{__version__}*.tar.gz"))[0]
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    assert any(name.endswith("test_policy_lint.py") for name in names)
    assert any(name.endswith("test_selftest.py") for name in names)
    assert any(name.endswith("examples/policy.list-paths.yaml") for name in names)
    assert any(name.endswith("README.md") for name in names)
    assert any(name.endswith("LICENSE") for name in names)


def test_the_built_artifacts_are_in_the_dist_directory() -> None:
    """After the release build, ``dist/`` holds the wheel and the sdist."""
    dist = REPO_ROOT / "dist"
    if not dist.is_dir():
        pytest.skip("the release has not been built in this tree yet")
    names = {path.name for path in dist.iterdir()}
    assert any(name.startswith("mcp_guard-0.6.0") and name.endswith(".whl") for name in names)
    assert any(name.startswith("mcp_guard-0.6.0") and name.endswith(".tar.gz") for name in names)


# -- the release documents -------------------------------------------------

@needs_bundle
def test_the_changes_document_is_at_the_root_of_the_bundle() -> None:
    changes = BUNDLE / "CHANGES.md"
    assert changes.is_file()
    assert "0.5.0" in changes.read_text(encoding="utf-8")


@needs_bundle
def test_the_changes_document_names_the_new_commands() -> None:
    text = (BUNDLE / "CHANGES.md").read_text(encoding="utf-8")
    assert "policy-lint" in text
    assert "selftest" in text


@needs_bundle
def test_the_manifest_lists_the_shipped_files() -> None:
    manifest = BUNDLE / "MANIFEST.md"
    assert manifest.is_file()
    text = manifest.read_text(encoding="utf-8")
    for name in ("src-ga", "benchmarks", "dist"):
        assert name in text


@needs_bundle
def test_the_report_describes_the_release() -> None:
    report = BUNDLE / "REPORT.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "0.5.0" in text


@needs_bundle
def test_the_verification_document_says_pass() -> None:
    verify = BUNDLE / "VERIFY.md"
    assert verify.is_file()
    text = verify.read_text(encoding="utf-8")
    assert "PASS" in text


@needs_bundle
def test_the_bundle_carries_the_benchmark() -> None:
    results = BUNDLE / "benchmarks" / "results.json"
    assert results.is_file()
    document = json.loads(results.read_text(encoding="utf-8"))
    assert document["method"]["requests_per_version"] == 1000
    assert "0.4.0" in document["versions"]
    # The candidate of this release is 0.6.0-rc1, measured against the
    # shipped 0.4.0 baseline.
    assert "0.6.0-rc1" in document["versions"]


@needs_bundle
def test_the_release_documents_are_the_same_in_both_places() -> None:
    """The copies in the bundle root and in the source tree are the same bytes.

    The root copies are what the operator receives; the ones in ``src-ga/``
    are what ships in the source distribution.  A difference between them
    means one of the two is stale.
    """
    for name in ("CHANGES.md", "MANIFEST.md", "REPORT.md", "VERIFY.md"):
        at_root = BUNDLE / name
        in_source = BUNDLE / "src-ga" / name
        assert at_root.is_file(), f"{name} is not at the root of the bundle"
        assert in_source.is_file(), f"{name} is not in the source tree"
        assert at_root.read_bytes() == in_source.read_bytes(), (
            f"{name} has drifted between the copy in the bundle and the copy in the source tree"
        )


@needs_bundle
def test_the_benchmark_markdown_quotes_the_numbers() -> None:
    markdown = (BUNDLE / "benchmarks" / "BENCHMARK.md").read_text(encoding="utf-8")
    assert "p50" in markdown
    assert "p95" in markdown
    assert "p99" in markdown


# -- the release bundle ----------------------------------------------------

@needs_bundle
def test_the_release_zip_carries_the_whole_bundle() -> None:
    archive = BUNDLE / "mcp-guard-v0.6.0-rc1.zip"
    if not archive.is_file():
        pytest.skip("the release zip has not been built in this bundle yet")
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
    for expected in (
        "src-ga/src/mcp_guard/lint.py",
        "src-ga/src/mcp_guard/selftest.py",
        "src-ga/pyproject.toml",
        "benchmarks/results.json",
        "benchmarks/BENCHMARK.md",
        "CHANGES.md",
        "MANIFEST.md",
        "REPORT.md",
        "VERIFY.md",
    ):
        assert expected in names, f"{expected} is not in the release zip"

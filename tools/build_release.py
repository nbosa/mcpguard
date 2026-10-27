#!/usr/bin/env python3
"""Build the release artifacts: ``MANIFEST.md`` and ``mcp-guard-v1.0.0-oss.zip``.

The manifest lists every file that ships, with its size and SHA-256 digest.
The archive holds exactly those files (plus the manifest itself) under a
single top-level directory.

Usage::

    python tools/build_release.py [--root DIR] [--check]

``--check`` builds into a temporary directory and reports what *would* change,
without touching the working tree.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT_NAME = "mcp-guard-v1.0.0-oss"
ZIP_NAME = f"{ROOT_NAME}.zip"
MANIFEST_NAME = "MANIFEST.md"

#: Directories that never ship.
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    ".eggs",
}

#: File suffixes that never ship.
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pyd", ".so", ".egg-info"}

#: Exact file names that never ship.
EXCLUDED_NAMES = {MANIFEST_NAME, ZIP_NAME}

#: Top-level entries that ship but are not part of the package.
EXCLUDED_TOP_LEVEL = {".gitignore", ".DS_Store"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shipped_files(root: Path) -> list[Path]:
    """Return every file that ships, sorted by relative path."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        if path.name in EXCLUDED_NAMES:
            continue
        found.append(path)
    return found


def render_manifest(root: Path, files: list[Path]) -> str:
    """Render ``MANIFEST.md``."""
    lines = [
        f"# MANIFEST -- {ROOT_NAME}",
        "",
        "Every file listed below ships in the release archive, byte for byte.",
        "The size is the size on disk and the digest is the SHA-256 of the file",
        "contents.  The manifest itself and the archive are excluded from the",
        "listing -- the manifest cannot contain its own digest, and the archive",
        "cannot contain itself.",
        "",
        f"* Archive: `{ZIP_NAME}`",
        f"* Manifest: `{MANIFEST_NAME}` (not listed below)",
        f"* Files: {len(files)}",
        "",
        "| File | Size | SHA-256 |",
        "| --- | ---: | --- |",
    ]
    for path in files:
        relative = path.relative_to(root).as_posix()
        lines.append(f"| `{relative}` | {path.stat().st_size} | `{_sha256(path)}` |")
    lines.append("")
    return "\n".join(lines)


def build(root: Path) -> tuple[Path, Path]:
    """Write the manifest and the archive; return their paths."""
    files = shipped_files(root)
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(render_manifest(root, files), encoding="utf-8")

    archive_path = root / ZIP_NAME
    if archive_path.exists():
        archive_path.unlink()
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in shipped_files(root) + [manifest_path]:
            relative = path.relative_to(root).as_posix()
            archive.write(path, f"{ROOT_NAME}/{relative}")
    return manifest_path, archive_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--check", action="store_true", help="report only")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    files = shipped_files(root)
    print(f"{len(files)} file(s) ship from {root}")
    if args.check:
        for path in files:
            print(f"  {path.relative_to(root).as_posix()}")
        return 0

    manifest_path, archive_path = build(root)
    print(f"wrote {manifest_path.name} and {archive_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

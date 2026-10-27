"""Filesystem path guards: where every path constraint in a policy is decided.

The check is *resolve-then-compare*, not lexical -- ``..`` is collapsed and
symlinks are followed, so it runs on the location the operating system would
really open and a symlink that escapes the prefix is rejected.  A relative
policy prefix also rejects an absolute candidate outright: "everything under
``./sandbox``" must not accept ``/etc/passwd``.

Two properties are worth stating plainly, because both were defects in an
earlier release:

* **Unicode normalisation is decided before the filesystem is consulted**
  (G-12).  A path spelled with a decomposed ``e`` + combining acute accent
  and a path spelled with a composed ``é`` name the same directory on the
  filesystems that normalise, and different directories on the ones that do
  not.  If the comparison is made on the raw spelling, a prefix written in
  one form silently stops matching a candidate written in the other.  The
  check therefore decides the question on the normalised spelling and reports
  the two spellings separately when they disagree.
* **The rejected value is never echoed** (G-02).  The message carries a
  fingerprint -- a short, non-reversible digest -- so an operator can
  correlate two rejections of the same value without the value itself
  reaching the audit log.
"""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

from .redact import fingerprint

#: Error codes raised by :func:`check_path`.
INVALID_PATH = "invalid_path"
ABSOLUTE_PATH = "absolute_path"
OUTSIDE_PREFIX = "outside_prefix"
NORMALISATION_MISMATCH = "normalisation_mismatch"

#: The URL schemes that are not filesystem paths.  A value carrying one of
#: them is a URL that happens to have been written where a path was
#: expected, and a path guard is the wrong instrument for it (OPUS-03).
_URL_SCHEME_PREFIXES = ("file:", "http:", "https:", "ftp:", "data:", "javascript:")
_URL_MARKERS = ("://", "file:", "http:", "https:", "ftp:", "data:", "javascript:")


class PathViolation(Exception):
    """Raised when a candidate path is not acceptable under a prefix."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _resolve(path: Path) -> Path:
    """Resolve ``path`` to its real location; ``strict=False`` for missing paths."""
    return path.resolve()


def _nfc(text: str) -> str:
    """The composed (NFC) spelling of ``text``."""
    return unicodedata.normalize("NFC", text)


def _comparable(path: Path) -> str:
    """A spelling of ``path`` that can be compared with another path.

    The spelling is composed (NFC) and case-folded on the platforms where the
    filesystem is case-insensitive, so that the comparison answers the
    question the operator meant to ask rather than the question the byte
    sequence happens to pose.
    """
    return os.path.normcase(_nfc(str(path)))


def _is_inside(resolved: Path, prefix: Path) -> bool:
    """Is ``resolved`` the prefix itself, or under it?"""
    if resolved == prefix:
        return True
    comparable = _comparable(resolved)
    base = _comparable(prefix).rstrip(os.sep)
    return comparable == base or comparable.startswith(base + os.sep)


def check_path(candidate: str, prefix: str, base_dir: Path | str) -> Path:
    """Return the resolved path of ``candidate`` if it stays inside ``prefix``.

    Raises :class:`PathViolation` if the candidate is malformed, absolute while
    the prefix is relative, resolves outside the prefix, or is spelled in a
    way that makes the answer ambiguous.
    """
    if not isinstance(candidate, str) or not candidate.strip():
        raise PathViolation(INVALID_PATH, "path must be a non-empty string")
    if "\x00" in candidate:
        raise PathViolation(INVALID_PATH, "path contains a NUL byte")

    # OPUS-03: Reject values that look like URLs -- path_prefix is for
    # filesystem paths, and a URL that reaches the path guard is a value the
    # operator did not expect to be a path at all.
    lowered = candidate.strip().lower()
    if "://" in lowered or lowered.startswith(_URL_SCHEME_PREFIXES):
        raise PathViolation(
            INVALID_PATH,
            "path contains a URL scheme - use a regex constraint for URLs",
        )

    base = Path(base_dir)
    prefix_is_relative = not Path(prefix).is_absolute()

    if prefix_is_relative:
        if Path(candidate).is_absolute():
            raise PathViolation(
                ABSOLUTE_PATH,
                f"absolute path {fingerprint(candidate)} is not allowed: the prefix {prefix!r} is relative",
            )

    # G-12: the comparison is made on the composed spelling.  The *lookup*
    # still prefers whichever spelling exists on disk, because a filesystem
    # that stores the decomposed form must keep working.
    prefix_abs = _resolve(base / Path(_nfc(prefix))) if prefix_is_relative else _resolve(Path(_nfc(prefix)))
    raw_prefix_abs = _resolve(base / Path(prefix)) if prefix_is_relative else _resolve(Path(prefix))
    if not prefix_abs.exists() and raw_prefix_abs.exists():
        prefix_abs = raw_prefix_abs

    normalised_target = base / Path(_nfc(candidate)) if prefix_is_relative else Path(_nfc(candidate))
    raw_target = base / Path(candidate) if prefix_is_relative else Path(candidate)

    if normalised_target.exists() or not raw_target.exists():
        resolved = _resolve(normalised_target)
    else:
        resolved = _resolve(raw_target)

    raw_resolved = _resolve(raw_target)

    inside = _is_inside(resolved, prefix_abs)
    raw_inside = _is_inside(raw_resolved, prefix_abs)

    if inside != raw_inside:
        # The two spellings of the same name disagree about where it is.  That
        # is not a decision this function may make on the operator's behalf
        # (G-12).
        raise PathViolation(
            NORMALISATION_MISMATCH,
            f"path {fingerprint(candidate)} is inside the prefix {prefix!r} in one Unicode "
            "spelling and outside it in another; write the path in the composed (NFC) form",
        )

    if not inside:
        raise PathViolation(
            OUTSIDE_PREFIX,
            f"path {fingerprint(candidate)} resolves outside the allowed prefix {prefix!r}",
        )
    return resolved

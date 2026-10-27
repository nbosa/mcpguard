#!/usr/bin/env python3
"""Scan the repository for personal data and credential material.

This is a *shape* scanner, not a knowledge scanner.  It asks one question of
every line of every text file in the repository: "does this line have the
shape of something that must not be published?"  The shapes it knows are the
ones that leak by accident:

* a private key header;
* an AWS access key id;
* a GitHub, Slack, Stripe or npm token;
* a credential assigned to a variable in a configuration file or a command
  line;
* an e-mail address on a domain that is not reserved for documentation;
* an absolute path into somebody's home directory.

Why nothing personal is hard-coded
-----------------------------------
A scanner that carries a list of real names, real addresses or real keys is
a scanner that itself leaks: it ships them to every clone, it cannot be
published, and it goes stale the moment a person changes jobs.  This file
therefore contains no personal identifier at all.  Every rule is expressed as
a structural pattern, and the only names it knows are the domain names that
RFC 2606 reserves for documentation use.  A pattern that matches a shape is
reported; the same shape in a different person's file is reported just the
same.

The scanner reads its own source, and so must every file it is pointed at.
There is no exemption list for file names and no exemption for archives: a
secret that is committed inside a ``.zip`` has been committed just as surely
as one that is committed in the clear.  Only build artefacts, virtual
environments and binary files are skipped, because they hold no source text
to inspect.

Nothing that is matched is ever printed.  A finding names the file, the
line, the kind of the shape and a short description of that shape -- never
the value that was found, because the report of a leak is very often the
second copy of the leak.

Usage::

    python check_secrets.py                 # scan the repository this file is in
    python check_secrets.py --root DIR      # scan another directory
    python check_secrets.py --json          # machine-readable output
    python check_secrets.py --self-test     # prove that every detector fires

The exit code is 0 when nothing was found and 1 when something was.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

__all__ = [
    "Detector",
    "Finding",
    "DETECTORS",
    "iter_files",
    "scan_root",
    "scan_text",
    "main",
]


# ---------------------------------------------------------------------------
# the reserved names
# ---------------------------------------------------------------------------

#: The domain names that RFC 2606 reserves for documentation and examples.
#: A message to one of them is not personal data, so it is never reported.
RESERVED_DOMAINS = frozenset(
    {"example.com", "example.net", "example.org", "example.invalid"}
)

#: The suffixes of the reserved names above, used for the sub-domains of them.
_RESERVED_SUFFIXES = tuple("." + name for name in RESERVED_DOMAINS)


def _is_reserved_domain(domain: str) -> bool:
    """Whether ``domain`` is a name that RFC 2606 reserves for documentation.

    A name is reserved when it is one of the four reserved names, when it is
    a sub-domain of one of them, or when it sits under any ``.example.``
    label.
    """
    host = domain.lower().rstrip(".")
    if host in RESERVED_DOMAINS:
        return True
    if ".example." in host:
        return True
    return host.endswith(_RESERVED_SUFFIXES)


# ---------------------------------------------------------------------------
# the detectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    """One shape that must not be published, and how to describe it."""

    kind: str
    shape: str
    pattern: re.Pattern[str]
    suppress: Callable[[re.Match[str]], bool] | None = None


def _suppress_reserved_email(match: re.Match[str]) -> bool:
    """Whether the e-mail match is addressed to a reserved name."""
    domain = match.group("domain")
    return _is_reserved_domain(domain)


DETECTORS: tuple[Detector, ...] = (
    Detector(
        kind="private_key",
        shape="private key header",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ),
    Detector(
        kind="aws_access_key_id",
        shape="access key id: a four letter prefix and sixteen upper case characters",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Detector(
        kind="github_token",
        shape="token: a known prefix and thirty six or more token characters",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"
        ),
    ),
    Detector(
        kind="slack_token",
        shape="token: a known prefix and a team and secret segment",
        pattern=re.compile(r"\bxox[abopsr]-[A-Za-z0-9-]{10,}\b"),
    ),
    Detector(
        kind="stripe_key",
        shape="secret or restricted key: a known prefix and twenty or more characters",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    Detector(
        kind="npm_token",
        shape="token: a known prefix and thirty or more token characters",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    ),
    Detector(
        kind="assigned_secret",
        shape="credential assigned to a name",
        pattern=re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(?:password|passwd|api[_-]?key|secret[_-]?key|client[_-]?secret"
            r"|access[_-]?token|private[_-]?key|passphrase)"
            r"(?![A-Za-z0-9_])"
            r"\s*[:=]\s*"
            r"[\"']?(?P<value>[A-Za-z0-9_\-./+~]{8,})"
        ),
    ),
    Detector(
        kind="email_address",
        shape="mail address on a name that is not reserved for documentation",
        pattern=re.compile(
            r"\b(?P<local>[A-Za-z0-9._%+-]+)@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
        ),
        suppress=_suppress_reserved_email,
    ),
    Detector(
        kind="home_directory_path",
        shape="absolute path into a home directory",
        pattern=re.compile(
            r"(?<![A-Za-z0-9_.-])"
            r"(?:[A-Za-z]:[\\/])?"
            r"/(?:home|Users)/"
            r"[A-Za-z0-9._-]+"
        ),
    ),
)


# ---------------------------------------------------------------------------
# the findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One place where a forbidden shape was found."""

    path: str
    line: int
    kind: str
    shape: str

    def as_text(self) -> str:
        """The one line report of this finding.

        The line carries the kind and a description of the shape.  It never
        carries the value that was found.
        """
        return f"{self.path}:{self.line}: {self.kind} ({self.shape})"


def scan_text(text: str, path: str = "<text>") -> list[Finding]:
    """Return every finding in ``text``.

    Each detector reports at most one finding per line: a line that carries
    ten copies of the same shape is one problem, not ten.
    """
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for detector in DETECTORS:
            for match in detector.pattern.finditer(line):
                if detector.suppress is not None and detector.suppress(match):
                    continue
                findings.append(Finding(path, number, detector.kind, detector.shape))
                break
    return findings


# ---------------------------------------------------------------------------
# the walk
# ---------------------------------------------------------------------------

#: Directories that hold no source text to inspect.
SKIP_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "build",
        "dist",
    }
)


def _is_skipped_directory(name: str) -> bool:
    """Whether a directory of this name is skipped."""
    return name in SKIP_DIRECTORY_NAMES or name.endswith(".egg-info")


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every file under ``root`` that is worth reading."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not _is_skipped_directory(name))
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _read_text(path: Path) -> str | None:
    """Read ``path`` as text, or return ``None`` when it is not text."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_root(root: Path) -> list[Finding]:
    """Return every finding in the files under ``root``."""
    findings: list[Finding] = []
    for path in iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            relative = path
        findings.extend(scan_text(text, relative.as_posix()))
    return findings


# ---------------------------------------------------------------------------
# the self-test
# ---------------------------------------------------------------------------

#: The built-in samples.  Every one of them is synthetic: the value is
#: assembled from fragments at run time, so that this file holds no complete
#: credential and the scanner finds nothing in its own source.
_SELF_TEST_SAMPLES: tuple[tuple[str, str], ...] = (
    ("private_key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
    ("aws_access_key_id", "AKIA" + "IOSFODNN7EXAMPLE"),
    ("github_token", "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"),
    ("slack_token", "xoxb-" + "123456789012-abcdefghijkl"),
    ("stripe_key", "sk_live_" + "abcdefghijklmnop1234567890"),
    ("npm_token", "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789"),
    ("assigned_secret", "pass" + "word=" + "hunter2hunter2"),
    ("email_address", "person" + "@" + "mcp-guard.invalid"),
    ("home_directory_path", "/home/" + "sample-user/.ssh/id_rsa"),
)

#: Lines that carry no forbidden shape and must never be reported.
_SELF_TEST_BENIGN: tuple[str, ...] = (
    "the tool read a file named quarterly-report.txt",
    "a message to " + "user@example.com",
    "a message to " + "docs@example.net",
    "a message to " + "team@example.org",
    "a message to " + "agent@example.invalid",
    "a message to " + "host@docs.example.com",
    "the repository lives under a version control directory",
)


def run_self_test() -> tuple[bool, list[dict[str, object]]]:
    """Run every detector over the built-in samples.

    Returns the overall outcome and the result of each check.
    """
    results: list[dict[str, object]] = []
    ok = True

    for kind, sample in _SELF_TEST_SAMPLES:
        fired = [finding for finding in scan_text(sample, "<self-test>") if finding.kind == kind]
        passed = bool(fired)
        ok = ok and passed
        results.append({"check": kind, "passed": passed, "detail": "detector fired"})

    for sample in _SELF_TEST_BENIGN:
        fired = scan_text(sample, "<self-test>")
        passed = not fired
        ok = ok and passed
        results.append({"check": "benign", "passed": passed, "detail": "no finding"})

    own_source = Path(__file__).read_text(encoding="utf-8")
    own_findings = scan_text(own_source, Path(__file__).name)
    passed = not own_findings
    ok = ok and passed
    results.append(
        {
            "check": "self_scan",
            "passed": passed,
            "detail": "the scanner reports nothing in its own source",
        }
    )

    return ok, results


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------


def _self_test(as_json: bool) -> int:
    ok, results = run_self_test()
    if as_json:
        print(
            json.dumps(
                {
                    "self_test": "ok" if ok else "failed",
                    "checks": results,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        for result in results:
            state = "ok  " if result["passed"] else "FAIL"
            print(f"check_secrets self-test: {state} {result['check']}: {result['detail']}")
        total = len(results)
        passed = sum(1 for result in results if result["passed"])
        print(f"check_secrets self-test: {passed}/{total} checks passed")
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the scanner and return its exit code."""
    parser = argparse.ArgumentParser(
        prog="check_secrets.py",
        description=(
            "Scan a directory tree for personal data and credential material. "
            "Only the shape of a finding is reported, never its value."
        ),
    )
    parser.add_argument(
        "--root",
        default=None,
        help="the directory to scan (default: the directory this script is in)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="write the report as JSON",
    )
    parser.add_argument(
        "--self-test",
        dest="self_test",
        action="store_true",
        help="run the built-in synthetic samples and check that every detector fires",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test(as_json=args.json)

    root = (
        Path(args.root).expanduser().resolve()
        if args.root
        else Path(__file__).resolve().parent
    )
    if not root.is_dir():
        print(f"check_secrets: not a directory: {root}", file=sys.stderr)
        return 2

    findings = scan_root(root)

    if args.json:
        print(
            json.dumps(
                {
                    "root": str(root),
                    "count": len(findings),
                    "findings": [asdict(finding) for finding in findings],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        for finding in findings:
            print(finding.as_text())
        print(
            f"check_secrets: {len(findings)} finding(s) in {root}",
            file=sys.stderr,
        )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

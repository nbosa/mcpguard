"""Path-shape canonicalization.

Guard rules must not be defeated by the *shape* of a path. ``~/.ssh/id_rsa``,
``%2e%2e%2f%2e%2e%2fetc%2fpasswd``, ``..\\..\\Windows\\System32`` and
``C:Users\\bob\\.aws\\credentials`` all denote different-looking strings but
identical intent.

:func:`canonicalize` reduces a path to a machine-independent *shape* plus a set
of flags (escapes home, obfuscated traversal, alternate data stream, reserved
device name, ...) that policies can match on.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from ..core.plugin import GuardPlugin, SelfTestCase
from ..core.result import Finding
from ..core.textutil import visible_repr

__all__ = [
    "PathShape",
    "canonicalize",
    "WINDOWS_RESERVED_NAMES",
    "PathShapePlugin",
]

#: Windows device names that resolve to a device, not a file.
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)

_PERCENT_RE = re.compile(r"%([0-9a-fA-F]{2})")
# Overlong UTF-8 encodings of '.' and '/': %c0%ae, %c1%9c, %e0%80%ae ...
_OVERLONG_RE = re.compile(
    r"%c[01]%[89a-fA-F][0-9a-fA-F]"
    r"|%e0%[89a-fA-F][0-9a-fA-F]%[89a-fA-F][0-9a-fA-F]",
    re.IGNORECASE,
)
_DRIVE_RE = re.compile(r"^([A-Za-z]):(.*)$")
_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
#: Schemes that are always URLs, even without the "//" authority marker.
KNOWN_URL_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "mailto",
        "data",
        "ws",
        "wss",
        "ssh",
        "git",
        "s3",
        "gs",
        "blob",
        "azure",
    }
)
_ENV_WIN_RE = re.compile(r"^%([A-Za-z_][A-Za-z0-9_]*)%(?:/(.*))?$")
_ENV_SH_RE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(?:/(.*))?$")

#: Argument names that are treated as paths even without a separator.
PATH_LIKE_KEYS = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "filepath",
        "file_path",
        "dir",
        "dirs",
        "directory",
        "folder",
        "target",
        "target_path",
        "src",
        "source",
        "source_path",
        "dest",
        "destination",
        "destination_path",
        "location",
        "root",
        "cwd",
        "output_path",
        "output_file",
        "input_file",
    }
)


@dataclass(frozen=True)
class PathShape:
    """Canonical description of a path."""

    raw: str
    decoded: str = ""
    normalized: str = ""
    literal: str = ""
    shape: str = ""
    segments: tuple[str, ...] = ()
    anchor: str = "rel"
    drive: str = ""
    env_name: str = ""
    absolute: bool = False
    home_relative: bool = False
    escapes_home: bool = False
    escapes_root: bool = False
    upward: int = 0
    encoded_layers: int = 0
    encoded_traversal: bool = False
    overlong_encoding: bool = False
    ads: bool = False
    unc: bool = False
    device: bool = False
    url: bool = False
    url_scheme: str = ""
    drive_relative: bool = False
    reserved: str = ""
    trailing_dot: bool = False
    null_byte: bool = False
    controls: tuple[str, ...] = ()
    flags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_sensitive_candidate(self) -> bool:
        return bool(self.segments)


def _percent_decode(text: str, max_layers: int = 5) -> tuple[str, int]:
    """Percent-decode ``text`` up to ``max_layers`` times."""
    layers = 0
    current = text
    for _ in range(max_layers):
        if "%" not in current:
            break
        updated = _PERCENT_RE.sub(lambda match: chr(int(match.group(1), 16)), current)
        if updated == current:
            break
        current = updated
        layers += 1
    return current, layers


def canonicalize(raw: Any, home: str | None = None) -> PathShape:
    """Canonicalize ``raw`` into a :class:`PathShape`.

    The canonicalization is purely lexical: no filesystem access, no ``stat``,
    no symlink resolution. That keeps the guard deterministic and side-effect
    free, and makes it safe to run on attacker-controlled strings.
    """
    original = "" if raw is None else str(raw)
    unquoted = original
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in "\"'`":
        unquoted = unquoted[1:-1]
    stripped = unquoted.strip()

    decoded, layers = _percent_decode(stripped)
    encoded_traversal = layers > 0 and ".." in decoded

    null_byte = ("\x00" in stripped) or ("\x00" in decoded)
    controls = tuple(sorted({char for char in (stripped + decoded) if ord(char) < 32 and char != "\t"}))
    overlong = bool(_OVERLONG_RE.search(stripped))

    work = decoded.replace("\\", "/")
    home_dir = (home or os.path.expanduser("~") or "/").rstrip("/") or "/"

    anchor = "rel"
    drive = ""
    env_name = ""
    drive_relative = False
    unc = work.startswith("//")
    device = work.startswith("//./") or work.startswith("//?/")

    if device:
        anchor = "device"
        work = work[3:]
    elif unc:
        anchor = "unc"
        work = work[2:]
    else:
        drive_match = _DRIVE_RE.match(work)
        if drive_match:
            drive = drive_match.group(1).upper()
            rest = drive_match.group(2)
            if rest.startswith("/"):
                anchor = "abs"
                work = rest
            else:
                anchor = "drive_rel"
                drive_relative = True
                work = rest
        elif work.startswith("/"):
            anchor = "root"

    home_relative = False
    is_url = False
    url_scheme = ""
    if anchor == "rel":
        scheme_match = _URL_SCHEME_RE.match(work)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            remainder = work[scheme_match.end():]
            is_authority_form = remainder.startswith("//")
            if scheme == "file":
                if is_authority_form:
                    remainder = remainder[2:]
                work = remainder
                anchor = "root" if remainder.startswith("/") else "rel"
            elif is_authority_form or scheme in KNOWN_URL_SCHEMES:
                anchor = "url"
                is_url = True
                url_scheme = scheme

    if anchor == "rel":
        if work == "~" or work.startswith("~/"):
            anchor = "home"
            home_relative = True
            work = work[1:]
        else:
            env_match = _ENV_WIN_RE.match(work) or _ENV_SH_RE.match(work)
            if env_match:
                anchor = "env"
                env_name = env_match.group(1).upper()
                work = env_match.group(2) or ""

    segments: list[str] = []
    upward = 0
    escapes_home = False
    escapes_root = False

    for segment in work.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments and segments[-1] != "..":
                segments.pop()
                continue
            if anchor == "home":
                escapes_home = True
                continue
            if anchor in ("root", "abs"):
                escapes_root = True
                continue
            upward += 1
            segments.append("..")
            continue
        segments.append(segment)

    if anchor == "rel" and upward > 0:
        # A relative path that walks up leaves the base directory; with the
        # default base (the home directory) that is an escape.
        escapes_home = True

    literal, shape, normalized = _render(anchor, drive, env_name, segments, home_dir)

    ads = (not is_url) and any(":" in segment for segment in segments)
    reserved = ""
    trailing_dot = False
    for segment in segments:
        if segment in (".", ".."):
            continue
        if segment.endswith(".") or segment.endswith(" "):
            trailing_dot = True
        base = segment.split(".")[0].upper()
        if base in WINDOWS_RESERVED_NAMES:
            reserved = base
            break

    # Windows ignores trailing dots and spaces in a file name, so "report.txt."
    # and "report.txt" address the same file. The trailing whitespace has to be
    # read from the untrimmed value, otherwise the obfuscation is invisible.
    raw_tail = unquoted.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if raw_tail and raw_tail not in (".", ".."):
        if raw_tail.endswith(".") or raw_tail.endswith(" "):
            trailing_dot = True

    flags: list[str] = []
    if home_relative:
        flags.append("home_relative")
    if absolute_flag(anchor):
        flags.append("absolute")
    if escapes_home:
        flags.append("escapes_home")
    if escapes_root:
        flags.append("escapes_root")
    if encoded_traversal:
        flags.append("encoded_traversal")
    if overlong:
        flags.append("overlong_encoding")
    if ads:
        flags.append("alternate_data_stream")
    if unc:
        flags.append("unc")
    if device:
        flags.append("device_namespace")
    if drive_relative:
        flags.append("drive_relative")
    if reserved:
        flags.append("reserved_device_name")
    if trailing_dot:
        flags.append("trailing_dot")
    if null_byte:
        flags.append("null_byte")
    if upward:
        flags.append("upward_traversal")
    if is_url:
        flags.append("url")

    return PathShape(
        raw=original,
        decoded=decoded,
        normalized=normalized,
        literal=literal,
        shape=shape,
        segments=tuple(segments),
        anchor=anchor,
        drive=drive,
        env_name=env_name,
        url=is_url,
        url_scheme=url_scheme,
        absolute=absolute_flag(anchor),
        home_relative=home_relative,
        escapes_home=escapes_home,
        escapes_root=escapes_root,
        upward=upward,
        encoded_layers=layers,
        encoded_traversal=encoded_traversal,
        overlong_encoding=overlong,
        ads=ads,
        unc=unc,
        device=device,
        drive_relative=drive_relative,
        reserved=reserved,
        trailing_dot=trailing_dot,
        null_byte=null_byte,
        controls=controls,
        flags=tuple(flags),
    )


def absolute_flag(anchor: str) -> bool:
    return anchor in ("root", "abs", "unc", "device")


def _render(
    anchor: str,
    drive: str,
    env_name: str,
    segments: list[str],
    home_dir: str,
) -> tuple[str, str, str]:
    """Return ``(literal, shape, normalized)`` for the resolved segments."""
    tail = "/".join(segments)
    if anchor == "home":
        literal = "<HOME>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = (f"{home_dir}/{tail}" if tail else home_dir)
    elif anchor == "root":
        literal = "/" + tail
        shape = literal
        normalized = literal
    elif anchor == "abs":
        literal = "<ABS>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = f"{drive}/{tail}" if tail else f"{drive}/"
    elif anchor == "unc":
        literal = "<UNC>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = "//" + tail
    elif anchor == "device":
        literal = "<DEVICE>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = "//./" + tail
    elif anchor == "drive_rel":
        literal = f"<DRIVE:{drive}>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = f"{drive}:{tail}"
    elif anchor == "env":
        literal = f"<ENV:{env_name}>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = f"${env_name}/{tail}"
    elif anchor == "url":
        literal = "<URL>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = tail
    else:
        literal = "<REL>" + (f"/{tail}" if tail else "")
        shape = literal
        normalized = tail
    return literal, shape, normalized


def looks_like_path(value: str) -> bool:
    """Heuristic: does ``value`` look like a filesystem path at all?"""
    if not value:
        return False
    text = value.strip()
    if not text:
        return False
    if "/" in text or "\\" in text:
        return True
    if text.startswith("~") or text.startswith("%") or text.startswith("$"):
        return True
    if text.startswith("//"):
        return True
    return False


class PathShapePlugin(GuardPlugin):
    """Detect dangerous path shapes in tool call arguments."""

    name = "path_shape"
    settings_key = "path"
    version = "1.3.0"

    RULES: dict[str, dict[str, Any]] = {
        "PATH-001": {
            "severity": "CRITICAL",
            "message": "Path escapes the home/base directory",
            "remediation": "Confine filesystem access to the working tree; reject upward traversal.",
        },
        "PATH-002": {
            "severity": "CRITICAL",
            "message": "Path targets a sensitive credential location",
            "remediation": "Deny reads of private keys, cloud credentials and dotfile secrets.",
        },
        "PATH-003": {
            "severity": "HIGH",
            "message": "Path uses a device or UNC namespace",
            "remediation": "Reject device paths (\\\\.\\, \\\\?\\) and UNC shares.",
        },
        "PATH-004": {
            "severity": "HIGH",
            "message": "Path hides traversal behind percent-encoding",
            "remediation": "Decode and re-validate the path after canonicalization.",
        },
        "PATH-005": {
            "severity": "HIGH",
            "message": "Path uses an NTFS alternate data stream",
            "remediation": "Reject ':stream' suffixes; they bypass extension based policy.",
        },
        "PATH-006": {
            "severity": "HIGH",
            "message": "Path uses a Windows reserved device name",
            "remediation": "Reject reserved device names such as CON, NUL, COM1.",
        },
        "PATH-007": {
            "severity": "MEDIUM",
            "message": "Path targets a system location",
            "remediation": "System paths usually indicate host reconnaissance.",
        },
        "PATH-008": {
            "severity": "MEDIUM",
            "message": "Path contains control characters or a NUL byte",
            "remediation": "Reject paths containing control characters (truncation attacks).",
        },
        "PATH-009": {
            "severity": "MEDIUM",
            "message": "Path is drive-relative and resolves against the per-drive cwd",
            "remediation": "Reject 'C:foo' style paths; they bypass drive-root assumptions.",
        },
        "PATH-010": {
            "severity": "LOW",
            "message": "Path uses trailing dot or space obfuscation",
            "remediation": "Strip trailing dots/spaces before policy evaluation.",
        },
        "PATH-011": {
            "severity": "HIGH",
            "message": "Path is outside the configured allowed roots",
            "remediation": "Add the root to settings.path.allowed_roots or deny the access.",
        },
    }

    # -- helpers ----------------------------------------------------------
    def _sensitive_names(self) -> set[str]:
        values = self.settings.get("sensitive_names") or []
        return {str(item).lower() for item in values if isinstance(item, str)}

    def _sensitive_files(self) -> list[str]:
        values = self.settings.get("sensitive_files") or []
        return [str(item) for item in values if isinstance(item, str)]

    def _system_prefixes(self) -> list[str]:
        values = self.settings.get("system_prefixes") or []
        return [str(item) for item in values if isinstance(item, str)]

    def _allowed_roots(self) -> list[str]:
        values = self.settings.get("allowed_roots") or []
        return [str(item) for item in values if isinstance(item, str)]

    def _is_sensitive(self, shape: PathShape) -> tuple[bool, str]:
        names = self._sensitive_names()
        for segment in shape.segments:
            if segment in (".", ".."):
                continue
            if segment.lower() in names:
                return True, segment
        for segment in shape.segments:
            if segment in (".", ".."):
                continue
            for pattern in self._sensitive_files():
                if fnmatch.fnmatch(segment, pattern):
                    return True, segment
        return False, ""

    def _is_system_path(self, shape: PathShape) -> bool:
        literal = shape.literal
        for prefix in self._system_prefixes():
            if literal == prefix or literal.startswith(prefix.rstrip("/") + "/"):
                return True
            if shape.normalized == prefix or shape.normalized.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    def _outside_allowed_roots(self, shape: PathShape) -> bool:
        roots = self._allowed_roots()
        if not roots:
            return False
        if shape.anchor == "rel":
            base_dir = self.context.settings.get("base_dir") or os.getcwd()
            if not base_dir:
                return False
            resolved = os.path.normpath(os.path.join(base_dir, shape.normalized))
            base_in_roots = False
            for root in roots:
                root_clean = os.path.normpath(root)
                try:
                    if os.path.commonpath([base_dir, root_clean]) == root_clean:
                        base_in_roots = True
                        break
                except ValueError:
                    continue
            if not base_in_roots:
                return False
        else:
            resolved = os.path.normpath(shape.normalized)

        for root in roots:
            root_clean = os.path.normpath(root)
            try:
                if os.path.commonpath([resolved, root_clean]) == root_clean:
                    return False
            except ValueError:
                continue
        return True

    def _candidates(self, call) -> Iterator[tuple[str, str]]:
        """Yield ``(key, value)`` pairs from a call that look like paths."""
        for key, value in _iter_strings(call.arguments):
            if looks_like_path(value) or key.lower() in PATH_LIKE_KEYS:
                yield key, value

    # -- plugin contract --------------------------------------------------
    def analyze(self, request) -> list[Finding]:
        findings: list[Finding] = []
        home = self.context.home_dir or os.path.expanduser("~")

        for index, call in enumerate(request.calls):
            for key, value in self._candidates(call):
                shape = canonicalize(value, home=home)
                if shape.anchor == "url":
                    # URLs are not filesystem paths; the canary plugin still
                    # inspects them, but path-shape rules do not apply.
                    continue
                location = f"calls[{index}].arguments.{key}"
                evidence = visible_repr(value, 160)

                if shape.escapes_home or shape.escapes_root:
                    self.emit(
                        findings,
                        "PATH-001",
                        evidence=evidence,
                        location=location,
                        metadata={
                            "shape": shape.shape,
                            "flags": list(shape.flags),
                            "upward": shape.upward,
                        },
                    )
                sensitive, matched = self._is_sensitive(shape)
                if sensitive:
                    self.emit(
                        findings,
                        "PATH-002",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape, "matched": matched},
                    )
                if shape.device or shape.unc:
                    self.emit(
                        findings,
                        "PATH-003",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape},
                    )
                if shape.encoded_traversal or shape.overlong_encoding:
                    self.emit(
                        findings,
                        "PATH-004",
                        evidence=evidence,
                        location=location,
                        metadata={
                            "encoded_layers": shape.encoded_layers,
                            "overlong": shape.overlong_encoding,
                            "shape": shape.shape,
                        },
                    )
                if shape.ads:
                    self.emit(
                        findings,
                        "PATH-005",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape},
                    )
                if shape.reserved:
                    self.emit(
                        findings,
                        "PATH-006",
                        evidence=evidence,
                        location=location,
                        metadata={"reserved": shape.reserved},
                    )
                if self._is_system_path(shape):
                    self.emit(
                        findings,
                        "PATH-007",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape},
                    )
                if shape.null_byte or shape.controls:
                    self.emit(
                        findings,
                        "PATH-008",
                        evidence=evidence,
                        location=location,
                        metadata={"controls": list(shape.controls)},
                    )
                if shape.drive_relative:
                    self.emit(
                        findings,
                        "PATH-009",
                        evidence=evidence,
                        location=location,
                        metadata={"drive": shape.drive},
                    )
                if shape.trailing_dot:
                    self.emit(
                        findings,
                        "PATH-010",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape},
                    )
                if self._outside_allowed_roots(shape):
                    self.emit(
                        findings,
                        "PATH-011",
                        evidence=evidence,
                        location=location,
                        metadata={"shape": shape.shape},
                    )

        return findings

    def self_test(self) -> list[SelfTestCase]:
        cases: list[SelfTestCase] = []
        home = "/" "home/bob"

        traversal = canonicalize("../../etc/passwd", home=home)
        cases.append(
            SelfTestCase("relative_traversal", traversal.escapes_home, traversal.shape)
        )

        home_escape = canonicalize("~/.ssh/../../etc/passwd", home=home)
        cases.append(
            SelfTestCase("home_escape", home_escape.escapes_home, home_escape.shape)
        )

        encoded = canonicalize("%2e%2e%2f%2e%2e%2fetc%2fpasswd", home=home)
        cases.append(
            SelfTestCase(
                "encoded_traversal",
                encoded.encoded_traversal and encoded.escapes_home,
                encoded.shape,
            )
        )

        sensitive = canonicalize("~/.aws/credentials", home=home)
        cases.append(
            SelfTestCase(
                "sensitive_shape",
                sensitive.shape == "<HOME>/.aws/credentials",
                sensitive.shape,
            )
        )

        ads = canonicalize("report.txt:hidden", home=home)
        cases.append(SelfTestCase("ads", ads.ads, ads.shape))

        reserved = canonicalize("\\\\.\\NUL", home=home)
        cases.append(
            SelfTestCase("reserved_device", reserved.device and reserved.reserved == "NUL", reserved.shape)
        )

        unc = canonicalize("\\\\server\\share\\file.txt", home=home)
        cases.append(SelfTestCase("unc", unc.unc, unc.shape))

        drive_rel = canonicalize("C:Users\\bob\\file.txt", home=home)
        cases.append(
            SelfTestCase("drive_relative", drive_rel.drive_relative, drive_rel.shape)
        )

        system = canonicalize("/etc/shadow", home=home)
        cases.append(SelfTestCase("system_path", system.literal.startswith("/etc"), system.literal))

        benign = canonicalize("src/main.py", home=home)
        cases.append(
            SelfTestCase(
                "benign_path",
                not benign.escapes_home and not benign.ads and not benign.reserved,
                benign.shape,
            )
        )

        return cases


def _iter_strings(node: Any, key: str = "") -> Iterator[tuple[str, str]]:
    """Flatten nested argument structures into ``(key, string)`` pairs."""
    if isinstance(node, dict):
        for child_key, child in node.items():
            yield from _iter_strings(child, str(child_key))
    elif isinstance(node, (list, tuple)):
        for index, child in enumerate(node):
            yield from _iter_strings(child, f"{key}[{index}]" if key else f"[{index}]")
    elif isinstance(node, str):
        yield key, node

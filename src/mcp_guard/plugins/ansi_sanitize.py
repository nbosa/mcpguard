"""ANSI terminal escape sanitization.

Tool output is frequently pasted into a terminal. Raw ANSI escape sequences in
that output are an injection vector: they can rewrite the screen, hide text,
rewrite scrollback and (via OSC 52) reach the clipboard.

This module provides both detection (as a guard plugin) and a hard sanitizer
(used by ``mcp-guard sanitize-output``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..core.plugin import GuardPlugin, SelfTestCase
from ..core.result import Finding
from ..core.textutil import truncate, visible_repr

__all__ = [
    "ANSI_SEQUENCE_RE",
    "SanitizeResult",
    "strip_ansi",
    "sanitize_text",
    "detect_ansi_categories",
    "ANSISanitizePlugin",
]

#: Matches the escape sequences a terminal actually interprets.
#:
#: The 7-bit ``ESC`` branch is the generic ECMA-48 escape sequence: ``ESC``,
#: zero or more intermediate bytes (``0x20``-``0x2F``) and one final byte
#: (``0x30``-``0x7E``).  It is what covers ``ESC c`` (reset the terminal),
#: ``ESC 7`` / ``ESC 8`` (save and restore the cursor), ``ESC d`` / ``ESC e``
#: (index and next line) and the keypad-mode sequences ``ESC =`` / ``ESC >``.
#: An earlier revision only recognised ``ESC`` followed by a byte in
#: ``0x40``-``0x5F``, so ``ESC c`` -- which clears the screen and moves the
#: cursor home, and is exactly what a prompt-injection payload wants -- passed
#: straight through the sanitizer (AUD-11).
ANSI_SEQUENCE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"      # OSC terminated by ST or BEL
    r"|\x1b\][^\x1b]*\x07"                      # OSC terminated by BEL
    r"|\x1b[P^_X][^\x1b]*(?:\x1b\\|\x07)"       # DCS / SOS / PM / APC
    r"|\x1b\[[0-?]*[ -/]*[@-~]"                 # CSI
    r"|\x1b[()*+][0-9A-B]"                      # charset selection
    r"|\x1b[ -/]*[0-~]"                         # any other 7-bit escape sequence
    r"|\x9d[^\x07\x9c]*[\x07\x9c]"              # 8-bit OSC
    r"|\x9b[0-?]*[ -/]*[@-~]"                   # 8-bit CSI
    r"|\x90[^\x9c]*\x9c"                        # 8-bit DCS
    r"|\x9e[^\x9c]*\x9c|\x9f[^\x9c]*\x9c"       # 8-bit PM / APC
    r"|\x9c"                                    # 8-bit ST
)

_OSC_52_RE = re.compile(r"(?:\x1b\]|\x9d)52;")
_OSC_TITLE_RE = re.compile(r"(?:\x1b\]|\x9d)[02];")
_OSC_HYPERLINK_RE = re.compile(r"(?:\x1b\]|\x9d)8;")
_CSI_CURSOR_RE = re.compile(r"\x1b\[[0-9;?]*[HfABCDG]|\x9b[0-9;?]*[HfABCDG]")
_CSI_CONCEAL_RE = re.compile(r"\x1b\[8;?[0-9;]*m|\x1b\[\?25[lh]|\x9b[8;?[0-9;]*m")
_BACKSPACE_RE = re.compile(r"\x08")
_CARRIAGE_RE = re.compile(r"\r")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Same as above but keeps ESC (0x1b) so that an explicit allow_ansi opt-in
# survives the control-character sweep.
_CONTROL_RE_NO_ESC = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")
_BIDI_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069]")


#: ``ESC c`` -- reset the terminal, clear the screen and home the cursor.
_ESC_RESET_RE = re.compile(r"\x1bc")


@dataclass
class SanitizeResult:
    """Outcome of a sanitization pass."""

    text: str
    original_length: int
    removed_sequences: int = 0
    removed_controls: int = 0
    removed_bidi: int = 0
    truncated: bool = False
    categories: dict[str, int] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return (
            self.removed_sequences
            or self.removed_controls
            or self.removed_bidi
            or self.truncated
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_length": self.original_length,
            "sanitized_length": len(self.text),
            "removed_sequences": self.removed_sequences,
            "removed_controls": self.removed_controls,
            "removed_bidi": self.removed_bidi,
            "truncated": self.truncated,
            "categories": dict(self.categories),
        }


def strip_ansi(text: str, rounds: int = 8) -> tuple[str, int]:
    """Remove ANSI escape sequences from ``text``.

    Returns:
        ``(clean_text, removed_count)``. Several passes are performed because
        nested sequences (``ESC] ... ESC \\``) hide inside one another.
    """
    if not text:
        return "", 0
    removed = 0
    current = text
    for _ in range(max(rounds, 1)):
        updated, count = ANSI_SEQUENCE_RE.subn("", current)
        removed += count
        if not count or updated == current:
            break
        current = updated
    return current, removed


def _apply_overwrites(text: str) -> str:
    """Resolve backspace / carriage-return text overwrite tricks."""
    if "\x08" in text:
        buffer: list[str] = []
        for char in text:
            if char == "\x08":
                if buffer:
                    buffer.pop()
                continue
            buffer.append(char)
        text = "".join(buffer)
    if "\r" in text:
        lines = []
        for line in text.split("\n"):
            if "\r" in line:
                line = line.rsplit("\r", 1)[-1]
            lines.append(line)
        text = "\n".join(lines)
    return text


def detect_ansi_categories(text: str) -> dict[str, int]:
    """Count the dangerous escape categories present in ``text``."""
    if not text:
        return {}
    categories: dict[str, int] = {}

    def bump(name: str, amount: int = 1) -> None:
        if amount:
            categories[name] = categories.get(name, 0) + amount

    sequences = len(ANSI_SEQUENCE_RE.findall(text))
    bump("ansi_sequence", sequences)
    bump("osc", len(_OSC_TITLE_RE.findall(text)) + len(_OSC_HYPERLINK_RE.findall(text)))
    bump("osc52", len(_OSC_52_RE.findall(text)))
    bump("cursor", len(_CSI_CURSOR_RE.findall(text)))
    bump("conceal", len(_CSI_CONCEAL_RE.findall(text)))
    bump("backspace", len(_BACKSPACE_RE.findall(text)))
    bump("carriage_return", len(_CARRIAGE_RE.findall(text)))
    bump("bidi", len(_BIDI_RE.findall(text)))
    bump("control", len(_CONTROL_RE.findall(text)))
    bump("reset", len(_ESC_RESET_RE.findall(text)))
    return categories


def sanitize_text(
    text: str,
    *,
    allow_ansi: bool = False,
    max_chars: int = 0,
    strip_control: bool = True,
    strip_bidi: bool = True,
) -> SanitizeResult:
    """Sanitize ``text`` for safe terminal rendering.

    Args:
        text: the raw payload.
        allow_ansi: keep escape sequences (used when the consumer explicitly
            opts in, e.g. a TUI that renders markdown itself).
        max_chars: truncate the result to this many characters (0 = no limit).
        strip_control: remove residual C0 control characters.
        strip_bidi: remove bidirectional override characters.
    """
    original = text or ""
    if allow_ansi:
        clean, removed = original, 0
    else:
        clean, removed = strip_ansi(original)

    clean = _apply_overwrites(clean)

    removed_bidi = 0
    if strip_bidi:
        clean, removed_bidi = _BIDI_RE.subn("", clean)

    removed_controls = 0
    if strip_control:
        pattern = _CONTROL_RE_NO_ESC if allow_ansi else _CONTROL_RE
        clean, removed_controls = pattern.subn("", clean)

    truncated = False
    if max_chars and len(clean) > max_chars:
        clean = truncate(clean, max_chars, suffix="...[truncated]")
        truncated = True

    categories = detect_ansi_categories(original)
    return SanitizeResult(
        text=clean,
        original_length=len(original),
        removed_sequences=removed,
        removed_controls=removed_controls,
        removed_bidi=removed_bidi,
        truncated=truncated,
        categories=categories,
    )


class ANSISanitizePlugin(GuardPlugin):
    """Detect terminal control sequences smuggled through tool output."""

    name = "ansi_sanitize"
    settings_key = "ansi"
    version = "1.2.0"

    RULES: dict[str, dict[str, Any]] = {
        "ANSI-001": {
            "severity": "MEDIUM",
            "message": "ANSI escape sequence detected in tool output",
            "remediation": "Strip escape sequences before rendering tool output in a terminal.",
        },
        "ANSI-002": {
            "severity": "HIGH",
            "message": "OSC terminal sequence detected (title or hyperlink spoofing)",
            "remediation": "Reject OSC sequences; they can rewrite the terminal title or fake hyperlinks.",
        },
        "ANSI-003": {
            "severity": "CRITICAL",
            "message": "OSC 52 clipboard write sequence detected",
            "remediation": "Block OSC 52 outright; it can silently replace the operator clipboard.",
        },
        "ANSI-004": {
            "severity": "MEDIUM",
            "message": "Cursor / screen control sequence detected",
            "remediation": "Strip CSI cursor sequences from untrusted output.",
        },
        "ANSI-005": {
            "severity": "HIGH",
            "message": "Concealed or overwritten text detected (backspace, carriage return or CSI 8)",
            "remediation": "Resolve overwrite tricks so hidden text cannot be spoofed.",
        },
        "ANSI-006": {
            "severity": "HIGH",
            "message": "Bidirectional text control characters detected (Trojan Source)",
            "remediation": "Remove Unicode bidi override characters from untrusted text.",
        },
        "ANSI-007": {
            "severity": "MEDIUM",
            "message": "Raw control characters detected in output",
            "remediation": "Strip control characters that have no rendering purpose.",
        },
        "ANSI-008": {
            "severity": "LOW",
            "message": "Output exceeds the configured maximum length and will be truncated",
            "remediation": "Raise settings.ansi.max_output_chars or split the payload.",
        },
    }

    def analyze(self, request) -> list[Finding]:
        findings: list[Finding] = []
        allow_ansi = bool(self.settings.get("allow_ansi", False))
        max_chars = int(self.settings.get("max_output_chars", 100000) or 0)
        detect_bidi = bool(self.settings.get("detect_bidi", True))

        targets: list[tuple[str, str]] = []
        for index, result in enumerate(request.results):
            targets.append((f"results[{index}].content", result.content))
        if request.transcript:
            targets.append(("transcript", request.transcript))
        for index, call in enumerate(request.calls):
            # Scan the raw argument values: the JSON serialisation of an
            # argument escapes ESC as \\u001b, which would hide the payload.
            for key, value in call.argument_items():
                targets.append((f"calls[{index}].arguments.{key}", value))

        for location, payload in targets:
            if not payload:
                continue
            categories = detect_ansi_categories(payload)

            evidence = visible_repr(payload, 160)
            if categories.get("ansi_sequence") and not allow_ansi:
                self.emit(
                    findings,
                    "ANSI-001",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["ansi_sequence"]},
                )
            if categories.get("osc52"):
                self.emit(
                    findings,
                    "ANSI-003",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["osc52"]},
                )
            elif categories.get("osc"):
                self.emit(
                    findings,
                    "ANSI-002",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["osc"]},
                )
            if categories.get("cursor"):
                self.emit(
                    findings,
                    "ANSI-004",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["cursor"]},
                )
            if categories.get("conceal") or categories.get("backspace") or categories.get("carriage_return"):
                self.emit(
                    findings,
                    "ANSI-005",
                    evidence=evidence,
                    location=location,
                    metadata={
                        "conceal": categories.get("conceal", 0),
                        "backspace": categories.get("backspace", 0),
                        "carriage_return": categories.get("carriage_return", 0),
                    },
                )
            if detect_bidi and categories.get("bidi"):
                self.emit(
                    findings,
                    "ANSI-006",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["bidi"]},
                )
            if categories.get("control"):
                self.emit(
                    findings,
                    "ANSI-007",
                    evidence=evidence,
                    location=location,
                    metadata={"count": categories["control"]},
                )
            if max_chars and len(payload) > max_chars:
                self.emit(
                    findings,
                    "ANSI-008",
                    evidence=visible_repr(payload[:120], 120),
                    location=location,
                    metadata={"length": len(payload), "max_output_chars": max_chars},
                )

        return findings

    def self_test(self) -> list[SelfTestCase]:
        cases: list[SelfTestCase] = []

        clean, removed = strip_ansi("plain \x1b[31mred\x1b[0m text")
        cases.append(
            SelfTestCase("strip_csi", removed == 2 and "red" in clean, f"removed={removed}")
        )

        clipboard = "before\x1b]52;c;cGF5bG9hZA==\x07after"
        categories = detect_ansi_categories(clipboard)
        cases.append(
            SelfTestCase(
                "detect_osc52",
                categories.get("osc52", 0) == 1,
                str(categories),
            )
        )

        hidden = "visible\x08\x08\x08hidden"
        result = sanitize_text(hidden)
        cases.append(
            SelfTestCase(
                "resolve_backspace",
                "hidden" in result.text and "visible" not in result.text,
                result.text,
            )
        )

        bidi = "invoice\u202erexe"
        bidi_categories = detect_ansi_categories(bidi)
        cases.append(
            SelfTestCase("detect_bidi", bidi_categories.get("bidi", 0) == 1, str(bidi_categories))
        )

        spoof = "harmless\r\x1b[2K\rreal command"
        spoof_result = sanitize_text(spoof)
        cases.append(
            SelfTestCase(
                "resolve_carriage_return",
                "harmless" not in spoof_result.text,
                spoof_result.text,
            )
        )

        allowed = sanitize_text("\x1b[31mred\x1b[0m", allow_ansi=True)
        cases.append(
            SelfTestCase("allow_ansi_opt_in", allowed.removed_sequences == 0, allowed.text)
        )

        return cases

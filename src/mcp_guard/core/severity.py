"""Ordered severity model shared by every mcp-guard rule.

Severity levels are ordered so that policy authors can express thresholds such as
``fail_on = "HIGH"`` without the ordering depending on lexical comparison of the
level names (``"CRITICAL" < "HIGH" < "INFO"`` lexicographically, which is useless).
"""

from __future__ import annotations

from enum import Enum

__all__ = ["Severity", "SEVERITY_ORDER", "parse_severity", "max_severity", "severity_rank"]

#: Canonical severity order, lowest first.
SEVERITY_ORDER: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class Severity(Enum):
    """Severity of a single guard finding.

    Ordering is defined explicitly through :attr:`rank` rather than by mixing in
    :class:`str`: a ``str`` mixin would make ``Severity.HIGH > "LOW"`` fall back
    to a *lexical* comparison and silently produce a wrong answer.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value

    def __format__(self, format_spec: str) -> str:
        return format(self.value, format_spec)

    @property
    def rank(self) -> int:
        """Numeric rank of this severity; larger means more severe."""
        return SEVERITY_ORDER.index(self.value)

    # -- explicit ordering ------------------------------------------------
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


def parse_severity(value: object, default: Severity | None = None) -> Severity:
    """Coerce ``value`` into a :class:`Severity`.

    Raises:
        ValueError: when the value is not a known severity and no default is given.
    """
    if isinstance(value, Severity):
        return value
    if value is None:
        if default is not None:
            return default
        raise ValueError("severity is required")
    text = str(value).strip().upper()
    if text in SEVERITY_ORDER:
        return Severity[text]
    if default is not None:
        return default
    raise ValueError(f"unknown severity: {value!r}")


def severity_rank(value: object) -> int:
    """Return the numeric rank of ``value`` (raises for unknown severities)."""
    return parse_severity(value).rank


def max_severity(values) -> Severity | None:
    """Return the most severe entry of ``values`` or ``None`` when empty."""
    best: Severity | None = None
    for value in values:
        severity = parse_severity(value)
        if best is None or severity > best:
            best = severity
    return best

"""Evidence redaction.

Guard findings frequently quote the offending payload. Printing that payload
verbatim would leak the very secret the guard is protecting, so evidence is
redacted before it reaches a report, a log file or a terminal.

Two tables live here, and the split between them is deliberate:

:data:`CREDENTIAL_PATTERNS`
    the *detection* table.  It is the single source of truth for "what counts
    as credential material" and is consumed by
    :mod:`mcp_guard.plugins.canary_exfil`.  A pattern belongs here only when it
    is specific enough to fire on a secret and not on ordinary traffic.

:data:`REDACTION_PATTERNS`
    the *masking* table.  It contains every detection pattern plus the extra
    shapes that are needed to mask a secret that appears **without** the
    context that gave it away -- the bare 40-character value of an AWS secret
    access key, for instance, which looks like any other base64 run.

The two tables drifted apart in an earlier release: the canary detector found
``npm_`` and ``sk_live_`` material that the redactor did not mask, so the
guard announced the secret and then printed it (AUD-05).  Deriving the masking
table from the detection table -- and keeping the extra shapes in the same
module -- is what stops that from happening again.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

__all__ = [
    "CREDENTIAL_PATTERNS",
    "REDACTION_PATTERNS",
    "redact",
    "mask_value",
    "fingerprint",
]


#: ``(kind, compiled pattern)`` pairs that identify credential material.
#:
#: This is the single source of truth for credential *detection*.  Every entry
#: must also be masked by :func:`redact`; ``tests/audit`` pins that property
#: for every kind, so a new detection pattern cannot be added without a
#: matching redaction.
CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)?"
    )),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(
        r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{8,}['\"]?"
    )),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abopsr]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("assigned_secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key|"
        r"client[_-]?secret|private[_-]?key)\b\s*[:=]\s*"
        r"(['\"]?)([A-Za-z0-9_\-./+=]{8,})\2"
    )),
)

#: Patterns that only matter for *masking*, not for detection.
#:
#: ``aws_secret_value`` catches the bare 40-character value of an AWS secret
#: access key.  Without the ``aws_secret_access_key =`` prefix it is
#: indistinguishable from any other base64 run, so it cannot be used to
#: *detect* a secret -- but once the detector has decided that a payload
#: contains one, the value must not be printed.
#:
#: ``jwt`` and ``url_credentials`` complete the families the detection table
#: already knows about.
_REDACTION_ONLY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_secret_value", re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*)://[^\s/@:]+:[^\s/@]+@")),
)

#: ``(kind, compiled pattern)`` pairs applied in order when masking evidence.
#:
#: The detection patterns come first so that a secret is masked *with* its
#: context (``api_key=`` stays readable, only the value is replaced); the
#: redaction-only shapes then catch the values that are left over.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    CREDENTIAL_PATTERNS + _REDACTION_ONLY_PATTERNS
)


def mask_value(value: str, keep: int = 2) -> str:
    """Return a masked representation of ``value`` keeping ``keep`` characters."""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def fingerprint(value: Any) -> str:
    """A short, non-reversible digest of ``value``.

    A rejected value must not reach a report, but an operator still needs to
    correlate two rejections of the same value -- "the same secret was refused
    at 10:04 and at 10:07" -- without learning what it was.  The fingerprint
    gives them that and nothing more.
    """
    try:
        encoded = json.dumps(value, sort_keys=True, default=repr).encode("utf-8")
    except (TypeError, ValueError):  # pragma: no cover - defensive
        encoded = repr(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()[:16]


def redact(text: str, extra_patterns: tuple[tuple[str, re.Pattern[str]], ...] = ()) -> str:
    """Redact credential-looking material from ``text``.

    Args:
        text: the raw evidence string.
        extra_patterns: additional ``(kind, pattern)`` pairs applied after the
            built-in ones.

    Returns:
        The redacted text. Known secret material is replaced by
        ``<redacted:kind>`` markers.
    """
    if not text:
        return ""
    result = text
    for kind, pattern in REDACTION_PATTERNS:
        if kind == "assigned_secret":
            result = pattern.sub(
                lambda match: f"{match.group(1)}=<redacted:assigned_secret>",
                result,
            )
        elif kind == "url_credentials":
            result = pattern.sub(
                lambda match: f"{match.group(1)}://<redacted:url_credentials>@",
                result,
            )
        elif kind == "aws_secret":
            # Keep the variable name readable; only the value is a secret.
            result = pattern.sub(
                lambda match: "aws_secret_access_key=<redacted:aws_secret>",
                result,
            )
        else:
            result = pattern.sub(f"<redacted:{kind}>", result)
    for kind, pattern in extra_patterns:
        result = pattern.sub(f"<redacted:{kind}>", result)
    return result

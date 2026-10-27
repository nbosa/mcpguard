"""Small text helpers shared by the plugins.

Everything in here is dependency free and deterministic so that results can be
reproduced across machines (important for pin manifests and audit trails).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections import Counter

__all__ = [
    "canonical_json",
    "sha256_hex",
    "sha256_bytes",
    "shannon_entropy",
    "looks_like_base64",
    "decode_base64_loose",
    "printable_ratio",
    "collapse_whitespace",
    "truncate",
    "visible_repr",
    "iter_words",
]

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_WORD_RE = re.compile(r"[A-Za-z0-9_./\\:-]{4,}")


def canonical_json(obj) -> str:
    """Serialise ``obj`` deterministically (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    """SHA-256 hex digest of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits per character) of ``text``."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def looks_like_base64(text: str) -> bool:
    """Heuristic: does ``text`` look like a base64 blob?"""
    candidate = text.strip()
    if not candidate or len(candidate) < 16:
        return False
    if len(candidate) % 4 != 0:
        return False
    return bool(_BASE64_RE.match(candidate))


def looks_like_hex(text: str) -> bool:
    """Heuristic: does ``text`` look like a hex blob?"""
    candidate = text.strip()
    if len(candidate) < 16 or len(candidate) % 2 != 0:
        return False
    return bool(_HEX_RE.match(candidate))


def decode_base64_loose(text: str) -> bytes | None:
    """Best-effort base64 decode; returns ``None`` when the payload is not decodable."""
    candidate = "".join(text.split())
    if not candidate:
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    return decoded or None


def printable_ratio(data: bytes) -> float:
    """Fraction of ``data`` made of printable ASCII/UTF-8 safe bytes."""
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(data)


def collapse_whitespace(text: str) -> str:
    """Collapse runs of whitespace into single spaces."""
    return re.sub(r"\s+", " ", text).strip()


def truncate(text: str, limit: int, suffix: str = "...") -> str:
    """Truncate ``text`` to ``limit`` characters, appending ``suffix`` when cut."""
    if limit is None or limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= len(suffix):
        return text[:limit]
    return text[: limit - len(suffix)] + suffix


def visible_repr(text: str, limit: int = 240) -> str:
    """Escape control characters so evidence is safe to print in a terminal."""
    escaped = "".join(
        chr(byte) if 32 <= byte < 127 else f"\\x{byte:02x}"
        for byte in text.encode("utf-8", errors="replace")
    )
    return truncate(escaped, limit)


def iter_words(text: str):
    """Yield word-ish tokens of at least four characters."""
    for match in _WORD_RE.finditer(text or ""):
        yield match.group(0)

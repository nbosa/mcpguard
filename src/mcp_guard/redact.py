"""Redaction of sensitive values before they reach the audit log.

An argument key matching :data:`SENSITIVE_KEY_PATTERN` has its value replaced
wholesale with ``"***"`` -- never truncated or masked in place, so a partially
redacted secret cannot leak a prefix or a suffix.  Nested objects and arrays are
walked recursively with depth bounding to prevent recursion attacks.

Two properties are load-bearing and are both pinned by the test suite:

* **The match is word-bounded.**  A key is sensitive when one of its *words* is
  a sensitive word, not when the key merely *contains* the letters of one.
  ``api_key``, ``apiKey`` and ``API-KEY`` are sensitive; ``monkey``,
  ``donkey``, ``turkey``, ``keyboard``, ``hotkey_config`` and ``keynote`` are
  not.  An earlier release matched on the raw substring and redacted the
  innocent words as well, which destroyed audit forensics without protecting
  anything (OPUS-01).
* **The walk is total and bounded.**  A value nested deeper than
  :data:`MAX_REDACTION_DEPTH` levels is replaced by a stable placeholder
  instead of being walked, so a hostile client cannot make the audit writer
  recurse until the stack overflows -- and cannot make it lose the record
  entirely (G-05).
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any

from .core.redact import redact

#: Keys whose values are replaced with :data:`REDACTED` in audit records.
#:
#: The pattern has two halves, because a sensitive word can be separated from
#: the rest of the key in two different ways:
#:
#: * the *separated* half -- ``token``, ``api_key``, ``API-KEY``,
#:   ``client_secret``: the sensitive word starts the key or follows a ``_`` or
#:   ``-``, and ends the key or is followed by another ``_`` or ``-``;
#: * the *camelCase* half -- ``apiKey``, ``refreshToken``: the sensitive word
#:   starts with a capital letter and is preceded by a letter or a digit.
#:
#: A capital is what separates ``apiKey`` from ``apikey``'s neighbours, and it
#: is also what keeps ``keyboard`` out: the second half needs ``Key``, not
#: ``key``.
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|[_\-])(?i:token|secret|password|key|authorization|api[_\-]key)(?:$|[_\-])|"
    r"(?<=[A-Za-z0-9])(?:Token|Secret|Password|Key|Authorization|ApiKey)(?:$|[_\-]|(?=[A-Z]))"
)

#: Placeholder written in place of a sensitive value.
REDACTED = "***"

#: The deepest nesting the redactor walks (G-05).  A client value nested
#: deeper than this is replaced by a placeholder rather than walked, so the
#: redactor is total: it cannot raise, and it cannot lose the record.
MAX_REDACTION_DEPTH = 32

#: The largest redacted payload the redactor will produce, in bytes of its
#: canonical JSON form.  A client that sends a huge argument tree must not be
#: able to make the audit log enormous (G-05).  The cap is reported in the
#: record itself, so a reader can see that it was hit.
MAX_REDACTED_PAYLOAD_BYTES = 64 * 1024

#: The placeholder written in place of a payload that was too large.
TRUNCATED = "<argument payload truncated>"


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when ``key`` matches :data:`SENSITIVE_KEY_PATTERN`."""
    return bool(SENSITIVE_KEY_PATTERN.search(key))


def fingerprint(value: Any) -> str:
    """A short, non-reversible digest of ``value``.

    A rejected value must not reach the audit log (G-02), but an operator
    still needs to correlate two rejections of the same value -- "the same
    secret was refused at 10:04 and at 10:07" -- without learning what it
    was.  The fingerprint gives them that and nothing more.
    """
    import hashlib
    import json

    try:
        encoded = json.dumps(value, sort_keys=True, default=repr).encode("utf-8")
    except (TypeError, ValueError):  # pragma: no cover - defensive
        encoded = repr(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()[:16]


def get_known_canaries() -> set[str]:
    try:
        from .canary import get_registered_canary_tokens

        return set(get_registered_canary_tokens())
    except (ImportError, AttributeError):
        return set()


def get_known_decoy_uris() -> set[str]:
    try:
        from .canary import get_registered_decoy_uris

        return set(get_registered_decoy_uris())
    except (ImportError, AttributeError):
        return set()


def scrub_canary_text(text: str) -> str:
    """Scrub raw and encoded canary tokens and decoy URIs from text."""
    if not isinstance(text, str) or not text:
        return text
    scrubbed = text
    # 1. Decoy URIs
    for uri in get_known_decoy_uris():
        if uri and uri in scrubbed:
            scrubbed = scrubbed.replace(uri, f"[REDACTED-CANARY:{fingerprint(uri)}]")
    # 2. Registered canary tokens and their variants
    for token in get_known_canaries():
        if not token:
            continue
        fp = fingerprint(token)
        marker = f"[REDACTED-CANARY:{fp}]"
        # raw token
        if token in scrubbed:
            scrubbed = scrubbed.replace(token, marker)
        # url-encoded
        quoted = urllib.parse.quote(token)
        if quoted and quoted in scrubbed:
            scrubbed = scrubbed.replace(quoted, marker)
        # hex variants
        try:
            hex_l = token.encode("utf-8").hex()
            if hex_l and hex_l in scrubbed:
                scrubbed = scrubbed.replace(hex_l, marker)
            hex_u = hex_l.upper()
            if hex_u and hex_u in scrubbed:
                scrubbed = scrubbed.replace(hex_u, marker)
        except Exception:
            pass
        # base64 variants
        try:
            raw_bytes = token.encode("utf-8")
            b64_std = base64.b64encode(raw_bytes).decode("ascii")
            if b64_std and b64_std in scrubbed:
                scrubbed = scrubbed.replace(b64_std, marker)
            b64_strip = b64_std.rstrip("=")
            if b64_strip and b64_strip in scrubbed:
                scrubbed = scrubbed.replace(b64_strip, marker)
            b64_url = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
            if b64_url and b64_url in scrubbed:
                scrubbed = scrubbed.replace(b64_url, marker)
            b64_url_strip = b64_url.rstrip("=")
            if b64_url_strip and b64_url_strip in scrubbed:
                scrubbed = scrubbed.replace(b64_url_strip, marker)
        except Exception:
            pass
    return scrubbed


def redact_value(value: Any, *, max_depth: int = MAX_REDACTION_DEPTH, _current_depth: int = 0) -> Any:
    """Recursively redact sensitive values: mappings, lists, tuples, scalars.

    G-05: Depth is strictly bounded to prevent stack exhaustion on deeply nested
    inputs.  The value is never modified in place; a new structure is returned.
    """
    if _current_depth >= max_depth:
        return f"<value nested deeper than {max_depth} levels>"

    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            scrubbed_key = scrub_canary_text(key) if isinstance(key, str) else key
            if isinstance(scrubbed_key, str) and is_sensitive_key(scrubbed_key):
                redacted[scrubbed_key] = REDACTED
            else:
                redacted[scrubbed_key] = redact_value(
                    item, max_depth=max_depth, _current_depth=_current_depth + 1
                )
        return redacted
    if isinstance(value, str):
        return scrub_canary_text(value)
    if isinstance(value, list):
        return [redact_value(item, max_depth=max_depth, _current_depth=_current_depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, max_depth=max_depth, _current_depth=_current_depth + 1) for item in value)
    return value


def redact_arguments(
    arguments: Any,
    *,
    max_depth: int = MAX_REDACTION_DEPTH,
    max_bytes: int = MAX_REDACTED_PAYLOAD_BYTES,
) -> Any:
    """Redact the arguments of a tool call.

    The result is capped at ``max_bytes`` bytes of canonical JSON.  When the cap
    is hit the payload is replaced by :data:`TRUNCATED`, so the record says
    that it was truncated rather than silently holding a partial argument dump
    (G-05).
    """
    redacted = redact_value(arguments, max_depth=max_depth)
    if max_bytes <= 0:
        return redacted
    try:
        encoded = json_bytes(redacted)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return redacted
    if len(encoded) <= max_bytes:
        return redacted
    return TRUNCATED


def json_bytes(value: Any) -> bytes:
    """The UTF-8 encoded canonical JSON of ``value``, for size accounting."""
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr).encode("utf-8")


#: The shapes of a credential that are masked wherever they appear in a
#: reason.  The policy no longer renders a rejected value into a violation
#: message, but a reason can also be written by other code, and the audit
#: log is the last place a secret should die.
_CREDENTIAL_PATTERNS = (
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{10,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{15,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?"),
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}"),
)

#: The wording that introduces a value a policy has just rejected.
_REJECTED_VALUE_RE = re.compile(r"(?i)\b(got|received)\s+(['\"])(?:\\.|(?!\2).)*\2")


def scrub_reason(reason: str) -> str:
    """Mask anything in ``reason`` that must not reach the audit log.

    Two passes, in order of how much they would cost if they were wrong:

    * a credential-shaped run is masked wherever it appears;
    * a quoted literal that follows the word that introduces a rejected value
      is masked, because that is where a policy that renders the value would
      put it.

    Neither pass can mask the *policy* half of a message, so an operator
    reading the log still sees which argument failed and what it was
    compared against.
    """
    if not reason:
        return reason
    scrubbed = scrub_canary_text(reason)
    for pattern in _CREDENTIAL_PATTERNS:
        scrubbed = pattern.sub(REDACTED, scrubbed)
    scrubbed = _REJECTED_VALUE_RE.sub(
        lambda match: f"{match.group(1)} {match.group(2)}{REDACTED}{match.group(2)}", scrubbed
    )
    return scrubbed

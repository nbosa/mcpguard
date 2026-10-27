"""Native outbound canary-token exfiltration blocking for mcp-guard.

A canary token is a value that is planted in an agent's environment, in a
tool's output or behind a decoy endpoint, so that the moment it shows up in
an *outbound* call the defender knows the agent has been talked into
exfiltrating.  mcp-guard sits exactly where that can be seen: it is the
process that decides whether a tool call leaves the machine.

This module provides the guard natively, with no dependency on #89
(``mcp-canary``), and it is *interface compatible* with it: a hook built here
can be swapped for :class:`mcp_canary.integrations.mcpguard.CanaryGuardHook`
and the policy engine does not notice.  Both are asked the same question --
:meth:`CanaryGuardHook.evaluate_call` -- and both answer with the same pair
of a decision and a detection result.

Two properties are the point of the whole exercise:

* **No false positives.**  A canary is only reported when a *registered* token
  value is found in the outbound call, either literally or after a decoding
  step.  Nothing is flagged because it "looks like" a credential: a SHA-256
  digest, a base64 blob and a UUID are all ordinary traffic and are all left
  alone.  The detector has no heuristic mode.
* **The token does not reach the audit log.**  The matched value is the very
  thing the guard exists to keep off the wire, so the decision text carries a
  fingerprint of it (see :func:`mcp_guard.redact.fingerprint`) and the token's
  identity -- never the token itself (G-02).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from .policy import ALLOW, DENY, Decision
from .redact import fingerprint

#: The token categories of #89 (``mcp_canary.tokens.CanaryType``).
CANARY_TYPE_ENV_VAR = "env_var"
CANARY_TYPE_TOOL_OUTPUT = "tool_output"
CANARY_TYPE_DECOY_URI = "decoy_uri"
CANARY_TYPE_DECOY_TOOL = "decoy_tool"

#: The exfiltration methods of #89 (``mcp_canary.detector.ExfiltrationMethod``).
METHOD_RAW_STRING = "raw_string"
METHOD_BASE64 = "base64"
METHOD_HEX = "hex"
METHOD_URL_ENCODED = "url_encode"
METHOD_MIXED_URL_BASE64 = "url_base64_mixed"
METHOD_DECOY_TOOL_INVOCATION = "decoy_tool_invocation"
METHOD_DECOY_URI_ACCESS = "decoy_uri_access"

#: The namespace #89 derives its deterministic identifiers from.
MCP_CANARY_NAMESPACE = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


class CanaryViolationSeverity(str, Enum):
    """The severity of a canary violation; the same values as #89."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class CanaryViolation:
    """One detected canary leak.

    The field names match #89's ``CanaryViolation`` so that a caller written
    against #89 keeps working; ``token_name`` and ``exfiltration_method`` are
    kept as aliases for the names this module used first.
    """

    token_id: str
    token_type: str
    method: str
    location: str
    matched_value: str
    severity: CanaryViolationSeverity
    description: str
    decoding_chain: tuple[str, ...] = ()
    #: The name of the token, when it has one.
    token_name: str = ""
    #: The matched value, digested.  Never the value itself.
    matched_fingerprint: str = ""

    @property
    def exfiltration_method(self) -> str:
        """The name #89 gives this field."""
        return self.method

    def to_dict(self) -> dict[str, Any]:
        fp = self.matched_fingerprint or (fingerprint(self.matched_value) if self.matched_value else "")
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "method": self.method,
            "location": self.location,
            "matched_value": fp,
            "matched_fingerprint": fp,
            "severity": self.severity.value,
            "description": self.description,
            "decoding_chain": list(self.decoding_chain),
        }


@dataclass
class DetectionResult:
    """The outcome of inspecting one tool call.

    The field names match #89's ``DetectionResult``.
    """

    clean: bool
    tool_name: str = ""
    violations: list[CanaryViolation] = field(default_factory=list)
    inspected_arguments_count: int = 0
    scan_duration_ms: float = 0.0

    @property
    def has_violations(self) -> bool:
        """Whether anything was detected."""
        return not self.clean or len(self.violations) > 0

    @property
    def duration_ms(self) -> float:
        """The name this module used first for :attr:`scan_duration_ms`."""
        return self.scan_duration_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean": self.clean,
            "tool_name": self.tool_name,
            "violations_count": len(self.violations),
            "violations": [violation.to_dict() for violation in self.violations],
            "inspected_arguments_count": self.inspected_arguments_count,
            "scan_duration_ms": round(self.scan_duration_ms, 3),
        }


#: The base64 shape #89 looks for: a run of base64 characters, at least
#: sixteen of them, with optional padding.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

#: The hex shape #89 looks for: a run of hex digits, at least sixteen of
#: them, optionally prefixed with ``0x`` and bounded by word edges.
_HEX_RE = re.compile(r"\b(?:0x)?([0-9a-fA-F]{16,})\b")

#: The colon- or space-separated hex shape: ``41:4b:49:41`` and friends.
_HEX_DELIMITED_RE = re.compile(r"\b([0-9a-fA-F]{2}(?:[:\s-][0-9a-fA-F]{2}){7,})\b")

#: The watermark shape #89 derives from its seed.
_WATERMARK_RE = re.compile(r"CNR[0-9A-F]{4}[0-9a-f]{8}")

#: How deep the detector walks an argument structure.
MAX_SCAN_DEPTH = 32

#: The longest argument string the detector will scan.  A longer value is
#: scanned only for the literal token values, not for encoded candidates.
MAX_SCAN_LENGTH = 1_048_576


_GLOBAL_CANARY_TOKENS: set[str] = set()
_GLOBAL_DECOY_URIS: set[str] = set()


def get_registered_canary_tokens() -> set[str]:
    """Return the global set of registered canary tokens."""
    return set(_GLOBAL_CANARY_TOKENS)


def get_registered_decoy_uris() -> set[str]:
    """Return the global set of registered decoy URIs."""
    return set(_GLOBAL_DECOY_URIS)


class NativeCanaryDetector:
    """Detects canary tokens and honeypot invocations in an outbound call.

    The detector is *token driven*: it reports a violation only when a
    registered token value, a registered decoy URI or a registered decoy tool
    name is actually present.  There is no heuristic that could fire on
    ordinary traffic, which is what makes the zero-false-positive claim
    checkable rather than aspirational.
    """

    def __init__(
        self,
        registered_tokens: Iterable[str] | None = None,
        decoy_tools: Iterable[str] | None = None,
        decoy_uris: Iterable[str] | None = None,
        seed: str | None = None,
        *,
        token_ids: Mapping[str, str] | None = None,
        token_types: Mapping[str, str] | None = None,
    ) -> None:
        self.tokens: set[str] = set(registered_tokens or ())
        self.decoy_tools: set[str] = set(decoy_tools or ())
        self.decoy_uris: set[str] = set(decoy_uris or ())
        self.seed = seed
        _GLOBAL_CANARY_TOKENS.update(self.tokens)
        _GLOBAL_DECOY_URIS.update(self.decoy_uris)
        #: The id of each token value, so a violation can name the token.
        self.token_ids: dict[str, str] = dict(token_ids or {})
        #: The category of each token value.
        self.token_types: dict[str, str] = dict(token_types or {})
        #: The watermark of each token value.
        self.token_watermarks: dict[str, str] = {}
        #: The values that are non-empty to search for (enforce all tokens regardless of length).
        self._searchable: tuple[str, ...] = tuple(
            sorted((token for token in self.tokens if token), key=len, reverse=True)
        )

    # -- construction ----------------------------------------------------

    @classmethod
    def from_bundle(cls, bundle_path_or_dict: str | Path | Mapping[str, Any]) -> "NativeCanaryDetector":
        """Build a detector from an #89 canary bundle.

        The bundle is the JSON that ``mcp_canary.tokens.CanaryBundle`` writes:
        a ``seed_fingerprint``, a ``created_at`` and a list of tokens, each
        with a ``token_id``, a ``token_type``, a ``name``, a ``value`` and a
        ``watermark``.
        """
        if isinstance(bundle_path_or_dict, (str, Path)):
            raw = Path(bundle_path_or_dict).read_text(encoding="utf-8")
            data = json.loads(raw)
        else:
            data = dict(bundle_path_or_dict)

        tokens: set[str] = set()
        decoy_tools: set[str] = set()
        decoy_uris: set[str] = set()
        token_ids: dict[str, str] = {}
        token_types: dict[str, str] = {}
        watermarks: dict[str, str] = {}

        for item in data.get("tokens", []) or ():
            if not isinstance(item, Mapping):
                continue
            value = item.get("value")
            # #89 writes "token_type"; earlier drafts wrote "type".
            kind = str(item.get("token_type") or item.get("type") or "")
            name = str(item.get("name") or "")
            token_id = str(item.get("token_id") or item.get("id") or name or "")

            if kind == CANARY_TYPE_DECOY_TOOL:
                if name:
                    decoy_tools.add(name)
                if isinstance(value, str) and value:
                    decoy_tools.add(value)
                continue
            if kind == CANARY_TYPE_DECOY_URI:
                if isinstance(value, str) and value:
                    decoy_uris.add(value)
                    token_ids[value] = token_id
                    token_types[value] = kind
                continue
            if isinstance(value, str) and value:
                tokens.add(value)
                token_ids[value] = token_id
                token_types[value] = kind or CANARY_TYPE_TOOL_OUTPUT
                watermark = item.get("watermark")
                if isinstance(watermark, str) and watermark:
                    watermarks[value] = watermark

        detector = cls(
            registered_tokens=tokens,
            decoy_tools=decoy_tools,
            decoy_uris=decoy_uris,
            seed=data.get("seed"),
            token_ids=token_ids,
            token_types=token_types,
        )
        detector.token_watermarks = watermarks
        return detector

    def add_token(self, token: str, token_id: str = "", token_type: str = CANARY_TYPE_TOOL_OUTPUT) -> None:
        """Register a token value to watch for."""
        self.tokens.add(token)
        _GLOBAL_CANARY_TOKENS.add(token)
        if token_id:
            self.token_ids[token] = token_id
        self.token_types[token] = token_type
        self._searchable = tuple(
            sorted((item for item in self.tokens if item), key=len, reverse=True)
        )

    def add_decoy_tool(self, tool_name: str) -> None:
        """Register a honeypot tool name."""
        self.decoy_tools.add(tool_name)

    def add_decoy_uri(self, uri: str) -> None:
        """Register a honeypot URI."""
        self.decoy_uris.add(uri)
        _GLOBAL_DECOY_URIS.add(uri)

    # -- inspection ------------------------------------------------------

    def inspect_tool_call(
        self, tool_name: str, arguments: Mapping[str, Any] | None = None
    ) -> DetectionResult:
        """Inspect an outbound tool call for a canary leak."""
        violations: list[CanaryViolation] = []
        arguments = arguments or {}

        if tool_name in self.decoy_tools:
            violations.append(
                CanaryViolation(
                    token_id=f"decoy_tool_{tool_name}",
                    token_type=CANARY_TYPE_DECOY_TOOL,
                    method=METHOD_DECOY_TOOL_INVOCATION,
                    location="tool_name",
                    matched_value=tool_name,
                    severity=CanaryViolationSeverity.CRITICAL,
                    description=(
                        f"CRITICAL HONEYPOT TRIGGER: unauthorized decoy MCP tool {tool_name!r} was "
                        "invoked.  This is a direct indicator of prompt injection or model subversion."
                    ),
                    decoding_chain=("tool_dispatch",),
                    token_name=tool_name,
                    matched_fingerprint=fingerprint(tool_name),
                )
            )

        inspected = self._scan_structure(arguments, location="arguments", violations=violations)

        return DetectionResult(
            clean=not violations,
            tool_name=tool_name,
            violations=violations,
            inspected_arguments_count=inspected,
        )

    def _scan_structure(
        self, value: Any, location: str, violations: list[CanaryViolation], depth: int = 0
    ) -> int:
        """Walk an argument structure, scanning every string it contains."""
        if depth > MAX_SCAN_DEPTH:
            return 0
        count = 1
        if isinstance(value, str):
            self._scan_string(value, location, violations)
        elif isinstance(value, Mapping):
            for key, item in value.items():
                child = f"{location}.{key}" if location else str(key)
                if isinstance(key, str):
                    # A key can carry a token too, not only a value.
                    self._scan_string(key, f"{child}(key)", violations)
                count += self._scan_structure(item, child, violations, depth + 1)
        elif isinstance(value, (list, tuple, set)):
            for index, item in enumerate(value):
                count += self._scan_structure(item, f"{location}[{index}]", violations, depth + 1)
        return count

    def _scan_string(self, text: str, location: str, violations: list[CanaryViolation]) -> None:
        """Look for every registered token in one string."""
        if not text:
            return

        for decoy_uri in self.decoy_uris:
            if decoy_uri and decoy_uri in text:
                uri_fp = fingerprint(decoy_uri)
                violations.append(
                    self._violation(
                        token_id=self.token_ids.get(decoy_uri, f"decoy_uri_{uri_fp}"),
                        token_type=CANARY_TYPE_DECOY_URI,
                        method=METHOD_DECOY_URI_ACCESS,
                        location=location,
                        matched=decoy_uri,
                        description=f"Canary honeypot URI accessed [matched {uri_fp}]",
                        chain=("decoy_uri",),
                    )
                )

        for token in self._searchable:
            if token in text:
                violations.append(
                    self._violation(
                        token_id=self.token_ids.get(token, ""),
                        token_type=self.token_types.get(token, CANARY_TYPE_TOOL_OUTPUT),
                        method=METHOD_RAW_STRING,
                        location=location,
                        matched=token,
                        description="Canary token found in an outbound call",
                        chain=("raw",),
                    )
                )

        # F-04: Chunk oversized strings with sliding overlap so encoded tokens are detected
        # even past 1 MiB instead of silently skipping them.
        if len(text) > MAX_SCAN_LENGTH:
            chunk_size = MAX_SCAN_LENGTH
            overlap = 8192
            step = chunk_size - overlap
            chunks = [text[i : i + chunk_size] for i in range(0, len(text), step)]
        else:
            chunks = [text]

        for chunk in chunks:
            for decoded, method, chain in self._decoded_candidates(chunk):
                for token in self._searchable:
                    if token in decoded:
                        violations.append(
                            self._violation(
                                token_id=self.token_ids.get(token, ""),
                                token_type=self.token_types.get(token, CANARY_TYPE_TOOL_OUTPUT),
                                method=method,
                                location=location,
                                matched=token,
                                description=(
                                    f"Canary token found in an outbound call after {method} decoding"
                                ),
                                chain=chain,
                            )
                        )

    def _violation(
        self,
        *,
        token_id: str,
        token_type: str,
        method: str,
        location: str,
        matched: str,
        description: str,
        chain: tuple[str, ...],
    ) -> CanaryViolation:
        return CanaryViolation(
            token_id=token_id,
            token_type=token_type,
            method=method,
            location=location,
            matched_value=matched,
            severity=CanaryViolationSeverity.CRITICAL,
            description=description,
            decoding_chain=chain,
            token_name=self.token_ids.get(matched, ""),
            matched_fingerprint=fingerprint(matched),
        )

    def _decoded_candidates(self, text: str) -> list[tuple[str, str, tuple[str, ...]]]:
        """Every decoding of ``text`` that might hide a token.

        The candidates are the URL-decoded form and the base64- and
        hex-decoded runs inside it.  Each candidate carries the chain that
        produced it, so a violation can say *how* the token was hidden.
        """
        candidates: list[tuple[str, str, tuple[str, ...]]] = []

        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            candidates.append((unquoted, METHOD_URL_ENCODED, ("url_decode",)))
            double_unquoted = urllib.parse.unquote(unquoted)
            if double_unquoted != unquoted:
                candidates.append(
                    (double_unquoted, METHOD_URL_ENCODED, ("url_decode", "url_decode"))
                )

        sources: list[tuple[str, tuple[str, ...]]] = [(text, ())]
        sources.extend((value, chain) for value, _method, chain in candidates)

        for source, chain in sources:
            for match in _BASE64_RE.finditer(source):
                raw = match.group(0)
                for decoded, method, extra in self._decode_base64(raw, source):
                    candidates.append((decoded, method, chain + extra))
            for match in _HEX_RE.finditer(source):
                decoded = self._decode_hex(match.group(1))
                if decoded is not None:
                    candidates.append((decoded, METHOD_HEX, chain + ("hex_decode",)))
            for match in _HEX_DELIMITED_RE.finditer(source):
                cleaned = re.sub(r"[:\s-]", "", match.group(1))
                decoded = self._decode_hex(cleaned)
                if decoded is not None:
                    candidates.append((decoded, METHOD_HEX, chain + ("hex_decode",)))

        return candidates

    def _decode_base64(self, raw: str, source: str) -> list[tuple[str, str, tuple[str, ...]]]:
        """The base64 decodings of ``raw`` that produce readable text."""
        results: list[tuple[str, str, tuple[str, ...]]] = []
        variants = [(raw, "base64", ("base64_decode",))]
        url_safe = raw.replace("-", "+").replace("_", "/")
        if url_safe != raw:
            method = METHOD_MIXED_URL_BASE64 if "%" in source else METHOD_BASE64
            variants.append((url_safe, method, ("url_safe_base64_decode",)))
        for variant, method, chain in variants:
            padded = variant + "=" * ((4 - len(variant) % 4) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False)
            except (binascii.Error, ValueError):
                continue
            try:
                text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if text:
                results.append((text, method, chain))
        return results

    def _decode_hex(self, text: str) -> str | None:
        """The UTF-8 text of a hex run, or ``None`` when it is not text."""
        if len(text) % 2 or len(text) < 4:
            return None
        try:
            decoded = bytes.fromhex(text)
        except ValueError:
            return None
        try:
            value = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return value if len(value) >= 8 else None


class CanaryGuardHook:
    """The pre-call interception hook, compatible with #89.

    The hook answers the question the policy engine asks -- "may this call
    leave the machine?" -- and it is asked it *before* the policy rules are
    applied, so a canary leak is refused even for a tool the policy would
    otherwise allow.

    The interface is the one #89 uses: :meth:`evaluate_call` returns the pair
    of an mcp-guard decision and a detection result.
    """

    def __init__(
        self,
        detector: Any,
        auto_block: bool = True,
        lang: str = "en",
    ) -> None:
        self.detector = detector
        self.auto_block = auto_block
        self.lang = lang

    def evaluate_call(
        self, tool_name: str, arguments: Mapping[str, Any] | None = None
    ) -> tuple[Decision, DetectionResult]:
        """Inspect a tool call and return ``(decision, detection_result)``."""
        args = dict(arguments or {})

        if hasattr(self.detector, "inspect_tool_call"):
            result = self.detector.inspect_tool_call(tool_name, args)
        else:  # pragma: no cover - defensive
            result = DetectionResult(clean=True, tool_name=tool_name)

        if not result.clean and self.auto_block:
            # G-02: the matched value is the thing the guard exists to keep
            # off the wire, so the decision carries its fingerprint and the
            # identity of the token, never the token.
            violations = tuple(
                f"{violation.severity.value.upper()}: {violation.description} "
                f"[token {violation.token_id or 'unknown'}; "
                f"matched {violation.matched_fingerprint or fingerprint(violation.matched_value)}]"
                for violation in result.violations
            )
            # A detector from another implementation may report that it found
            # something without saying what.  The call is still refused: the
            # finding is the finding, and a reason that names nothing is
            # better than an exception in the middle of the request path.
            primary = result.violations[0] if result.violations else None
            reason = (
                f"Canary policy violation: {primary.description}"
                if primary is not None
                else "Canary policy violation: the detector reported a canary leak it did not describe"
            )
            decision = Decision(
                decision=DENY,
                code=DENY,
                reason=reason,
                violations=violations,
            )
            return decision, result

        decision = Decision(
            decision=ALLOW,
            code=ALLOW,
            reason=f"Canary inspection clean for tool {tool_name!r}",
            violations=(),
        )
        return decision, result


#: The name this module used first for :class:`CanaryGuardHook`.
CanaryHook = CanaryGuardHook


def decoy_tool_policy_rules(bundle: str | Path | Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """The policy rules that deny every decoy tool in an #89 bundle.

    This is the native equivalent of #89's ``CanaryPolicyGenerator``: a
    mapping of tool name to a deny rule, ready to be merged into a policy
    document.
    """
    detector = NativeCanaryDetector.from_bundle(bundle)
    rules: dict[str, dict[str, str]] = {}
    for name in sorted(detector.decoy_tools):
        rules[name] = {
            "action": "deny",
            "reason": (
                f"CRITICAL HONEYPOT TRIGGER: {name!r} is an indirect prompt-injection decoy "
                "tool.  Access is strictly denied and recorded in the audit log."
            ),
        }
    return rules

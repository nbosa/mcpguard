"""Canary exfiltration detection.

A *canary* is a distinctive, worthless-but-unique marker planted in the agent's
environment, context window or tool configuration. If a canary shows up in an
outbound payload (a tool call that leaves the machine), the agent has been
manipulated into leaking context.

This plugin detects:

* configured canary tokens (exact and shape-normalised),
* generic ``CANARY-...`` shaped markers,
* credential material and high entropy blobs headed for egress tools,
* environment / credential dump indicators.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.plugin import GuardPlugin, SelfTestCase
from ..core.redact import CREDENTIAL_PATTERNS, fingerprint
from ..core.result import Finding
from ..core.severity import Severity
from ..core.textutil import (
    decode_base64_loose,
    looks_like_base64,
    printable_ratio,
    shannon_entropy,
    visible_repr,
)

__all__ = [
    "CANARY_SHAPE_RE",
    "CREDENTIAL_PATTERNS",
    "normalize_token",
    "CanaryExfilPlugin",
]

#: Generic marker shape, e.g. ``CANARY-AB12-CD34``.
CANARY_SHAPE_RE = re.compile(r"\bCANARY-[A-Za-z0-9]{2,}(?:-[A-Za-z0-9]{2,})+\b")

#: A *candidate* token: a run of alphanumerics, optionally joined by single
#: ``-``, ``_`` or ``.`` separators.
#:
#: Shape-normalised matching compares a candidate against a candidate, never
#: against a whole blob of text.  Comparing against the whole text meant that
#: the letters of ``SECRET`` scattered through unrelated prose -- "my sec ret
#: value" -- normalised into a single ``SECRET`` and tripped the detector
#: (AUD-10).
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*")

#: JWT-like tokens.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")

#: URLs carrying inline credentials.
URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*)://[^\s/@:]+:[^\s/@]+@")

#: Indicators of an environment or credential dump.
ENV_DUMP_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("proc_environ", re.compile(r"/proc/(?:self|\d+)/environ")),
    ("printenv", re.compile(r"(?i)\bprintenv\b")),
    ("env_pipe", re.compile(r"(?i)\benv\s*\|\s*(?:grep|cat|base64|curl|nc)\b")),
    ("os_environ", re.compile(r"(?i)\bos\.environ\b|\bprocess\.env\b")),
    ("env_var_name", re.compile(
        r"(?i)\b(?:AWS_SECRET_ACCESS_KEY|DATABASE_URL|GITHUB_TOKEN|SLACK_TOKEN|"
        r"OPENAI_API_KEY|ANTHROPIC_API_KEY|PRIVATE_KEY|PASSWORD)\b"
    )),
)

_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_BLOB_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")


def normalize_token(token: str) -> str:
    """Normalise a canary token for shape-insensitive comparison."""
    return re.sub(r"[^A-Za-z0-9]", "", token or "").upper()


#: The smallest reassembled blob worth decoding.
_MIN_REJOINED_BLOB = 16

#: The smallest fragment that may take part in a reassembly.
#
#: Eight characters is well above the length of an ordinary English word, so
#: prose is not reassembled into a blob by accident.
_MIN_REJOINED_FRAGMENT = 8

#: A single base64 fragment.
#:
#: A fragment of a split blob is *not* a multiple of four characters, so it
#: cannot be tested with :func:`looks_like_base64`; only its alphabet and its
#: length can be checked.
_BASE64_FRAGMENT_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")

#: Separators between the fragments of a split blob.
#:
#: The text under inspection is usually the JSON serialisation of the
#: arguments, so the newline that splits the blob is the two-character escape
#: ``\n`` rather than a newline, and the fragments are wrapped in JSON
#: punctuation.  All of those are separators; none of them is part of the
#: base64 alphabet, so splitting on them cannot cut a blob in half.
_BLOB_SEPARATOR_RE = re.compile(r"(\\n|\\r|\\t|\\u00[0-9a-fA-F]{2}|\s+|[{}\[\]\",:;])")


def _rejoined_base64(text: str) -> list[str]:
    """Return base64 blobs that were split across whitespace.

    The fragments of one blob are adjacent whitespace-separated runs of
    base64 characters.  A group is offered to the caller only when it decodes
    to printable text, so a sentence is never mistaken for an encoded payload.
    """
    groups: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if len(current) >= 2:
            joined = "".join(current)
            if len(joined) >= _MIN_REJOINED_BLOB:
                groups.append(joined)
        current.clear()

    for word in _BLOB_SEPARATOR_RE.split(text or ""):
        if not word:
            continue
        if _BLOB_SEPARATOR_RE.fullmatch(word):
            # A separator inside a blob splits it into fragments; a separator
            # after a non-blob word ends the group.
            continue
        if len(word) >= _MIN_REJOINED_FRAGMENT and _BASE64_FRAGMENT_RE.match(word):
            current.append(word)
            continue
        flush()
    flush()

    confirmed: list[str] = []
    for group in groups:
        decoded = decode_base64_loose(group)
        if not decoded or printable_ratio(decoded) < 0.8:
            continue
        try:
            decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        confirmed.append(group)
    return confirmed


class CanaryExfilPlugin(GuardPlugin):
    """Detect canary leakage and credential-shaped exfiltration."""

    name = "canary_exfil"
    settings_key = "canary"
    version = "1.4.0"

    RULES: dict[str, dict[str, Any]] = {
        "CANARY-001": {
            "severity": "CRITICAL",
            "message": "Configured canary token detected in payload",
            "remediation": "Treat as confirmed context leakage; revoke the canary and inspect the tool call.",
        },
        "CANARY-002": {
            "severity": "CRITICAL",
            "message": "Canary-shaped marker detected in payload",
            "remediation": "An unrecognised canary marker reached the payload; treat as leakage.",
        },
        "CANARY-003": {
            "severity": "CRITICAL",
            "message": "Credential material detected in payload",
            "remediation": "Never let raw credentials travel through tool arguments.",
        },
        "CANARY-004": {
            "severity": "HIGH",
            "message": "High-entropy blob detected in payload",
            "remediation": "Verify that high-entropy data is not an encoded secret.",
        },
        "CANARY-005": {
            "severity": "MEDIUM",
            "message": "JWT-like token detected in payload",
            "remediation": "Confirm the token is not a session credential bound for egress.",
        },
        "CANARY-006": {
            "severity": "HIGH",
            "message": "URL with embedded credentials detected",
            "remediation": "Move credentials out of URLs and into a secret store.",
        },
        "CANARY-007": {
            "severity": "HIGH",
            "message": "Environment or credential dump indicator detected",
            "remediation": "Block environment dumping and re-evaluate the tool's permissions.",
        },
        "CANARY-008": {
            "severity": "CRITICAL",
            "message": "Canary marker sent to an egress-capable tool",
            "remediation": "Egress tools must never carry context markers; block the call.",
        },
        "CANARY-009": {
            "severity": "HIGH",
            "message": "Base64 blob decodes to credential material",
            "remediation": "Encoded credentials are still credentials; strip them before egress.",
        },
        "CANARY-010": {
            "severity": "HIGH",
            "message": "Canary token returned by a tool",
            "remediation": "A tool returned a canary; the server may already be compromised.",
        },
    }

    # -- helpers ----------------------------------------------------------
    def _tokens(self) -> list[str]:
        values = self.settings.get("tokens") or []
        return [str(item) for item in values if isinstance(item, str) and item.strip()]

    def _egress_tools(self, request) -> set[str]:
        tools = set()
        for item in self.settings.get("egress_tools") or []:
            if isinstance(item, str):
                tools.add(item)
                tools.add(item.lower())
        for item in (request.metadata.get("egress_tools") or []):
            if isinstance(item, str):
                tools.add(item)
        return tools

    def _entropy_threshold(self) -> float:
        try:
            return float(self.settings.get("entropy_threshold", 4.2))
        except (TypeError, ValueError):
            return 4.2

    def _min_blob_len(self) -> int:
        try:
            value = int(self.settings.get("min_blob_len", 40))
        except (TypeError, ValueError):
            return 40
        return max(value, 8)

    def _block_on_match(self) -> bool:
        return bool(self.settings.get("block_on_match", True))

    def _configured_match(self, text: str) -> str | None:
        """Return the configured token matching ``text`` (exact or normalised)."""
        if not text:
            return None
        upper = text.upper()
        for token in self._tokens():
            if token in text or token.upper() in upper:
                return token
        # Shape-normalised fallback.  The token is compared against *candidate
        # tokens* extracted from the text, and the comparison is an equality:
        # the normalised candidate must be exactly the normalised token.  A
        # substring comparison against the whole text normalised unrelated
        # prose into a false match (AUD-10).
        for token in self._tokens():
            needle = normalize_token(token)
            if not needle:
                continue
            for match in _CANDIDATE_RE.finditer(text):
                if normalize_token(match.group(0)) == needle:
                    return token
        return None

    def _generic_match(self, text: str) -> str:
        """Return a canary-shaped marker found in ``text`` (if any)."""
        match = CANARY_SHAPE_RE.search(text or "")
        return match.group(0) if match else ""

    def _entropy_blobs(self, text: str) -> list[str]:
        threshold = self._entropy_threshold()
        minimum = self._min_blob_len()
        blobs: list[str] = []
        for match in _BLOB_RE.finditer(text or ""):
            candidate = match.group(0)
            if len(candidate) < minimum:
                continue
            if shannon_entropy(candidate) >= threshold:
                blobs.append(candidate)
        for match in _HEX_BLOB_RE.finditer(text or ""):
            candidate = match.group(0)
            if len(candidate) >= minimum and shannon_entropy(candidate) >= threshold:
                blobs.append(candidate)
        # A blob that was split across lines is still a blob (AUD-09).
        for candidate in _rejoined_base64(text):
            if len(candidate) >= minimum and shannon_entropy(candidate) >= threshold:
                blobs.append(candidate)
        return blobs

    def _decode_credential_blob(self, text: str) -> str:
        """Return the first base64 blob in ``text`` that decodes to credentials."""
        candidates = [
            match.group(0)
            for match in _BLOB_RE.finditer(text or "")
            if looks_like_base64(match.group(0))
        ]
        # A blob that was split across lines is still a blob (AUD-09).
        candidates.extend(_rejoined_base64(text))
        for candidate in candidates:
            decoded = decode_base64_loose(candidate)
            if not decoded:
                continue
            if printable_ratio(decoded) < 0.8:
                continue
            try:
                decoded_text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for _kind, pattern in CREDENTIAL_PATTERNS:
                if pattern.search(decoded_text):
                    return candidate
        return ""

    # -- plugin contract --------------------------------------------------
    def analyze(self, request) -> list[Finding]:
        findings: list[Finding] = []
        egress_tools = self._egress_tools(request)
        scan_results = bool(self.settings.get("scan_results", True))

        for index, call in enumerate(request.calls):
            location = f"calls[{index}].arguments"
            text = call.arguments_text()
            in_egress = bool(
                (call.qualified and call.qualified in egress_tools)
                or (call.tool and call.tool in egress_tools)
                or (call.tool and call.tool.lower() in egress_tools)
            )
            self._scan(
                findings,
                text,
                location,
                in_egress=in_egress,
                in_result=False,
            )

        if scan_results:
            for index, result in enumerate(request.results):
                self._scan(
                    findings,
                    result.content,
                    f"results[{index}].content",
                    in_egress=False,
                    in_result=True,
                )

        if request.transcript:
            self._scan(
                findings,
                request.transcript,
                "transcript",
                in_egress=False,
                in_result=False,
            )

        return findings

    def _scan(
        self,
        findings: list[Finding],
        text: str,
        location: str,
        *,
        in_egress: bool,
        in_result: bool,
    ) -> None:
        if not text:
            return
        evidence = visible_repr(text, 200)
        block = self._block_on_match()

        configured = self._configured_match(text)
        generic = self._generic_match(text)

        if configured:
            rule_id = "CANARY-008" if in_egress else ("CANARY-010" if in_result else "CANARY-001")
            # The token itself is the secret.  Report a fingerprint so an
            # operator can correlate two rejections without the report
            # becoming a copy of the canary (AUD-06).
            self._emit(
                findings,
                rule_id,
                evidence,
                location,
                block,
                {"token_fingerprint": fingerprint(configured)},
            )
        elif generic:
            self._emit(
                findings,
                "CANARY-002",
                evidence,
                location,
                block,
                {"token_fingerprint": fingerprint(generic)},
            )

        for kind, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                self._emit(findings, "CANARY-003", evidence, location, block, {"kind": kind})
                break

        if JWT_RE.search(text):
            self._emit(findings, "CANARY-005", evidence, location, block, {})
            if in_egress:
                self._emit(findings, "CANARY-003", evidence, location, block, {"kind": "jwt"})

        if URL_CREDENTIALS_RE.search(text):
            self._emit(findings, "CANARY-006", evidence, location, block, {})

        for kind, pattern in ENV_DUMP_PATTERNS:
            if pattern.search(text):
                self._emit(findings, "CANARY-007", evidence, location, block, {"kind": kind})
                break

        blobs = self._entropy_blobs(text)
        if blobs:
            self._emit(
                findings,
                "CANARY-004",
                visible_repr(blobs[0], 120),
                location,
                block,
                {"count": len(blobs)},
            )

        encoded = self._decode_credential_blob(text)
        if encoded:
            self._emit(
                findings,
                "CANARY-009",
                visible_repr(encoded, 120),
                location,
                block,
                {"blob_length": len(encoded)},
            )

    def _emit(
        self,
        findings: list[Finding],
        rule_id: str,
        evidence: str,
        location: str,
        block: bool,
        metadata: dict[str, Any],
    ) -> None:
        finding = self.finding(
            rule_id,
            evidence=evidence,
            location=location,
            metadata=metadata,
        )
        if finding is None:
            return
        if not block and finding.severity == Severity.CRITICAL:
            finding.severity = Severity.HIGH
        findings.append(finding)

    def self_test(self) -> list[SelfTestCase]:
        cases: list[SelfTestCase] = []
        configured = normalize_token("CANARY-AB12-CD34")
        cases.append(
            SelfTestCase(
                "normalize_token",
                configured == "CANARYAB12CD34",
                configured,
            )
        )

        match = CANARY_SHAPE_RE.search("value CANARY-ZZ99-QQ11 end")
        cases.append(
            SelfTestCase("canary_shape", bool(match), match.group(0) if match else "")
        )

        blob = "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FybGFnaW5xdWlvcHFycw=="
        cases.append(
            SelfTestCase(
                "base64_blob_entropy",
                shannon_entropy(blob) >= 4.2,
                f"{shannon_entropy(blob):.2f}",
            )
        )

        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        cases.append(
            SelfTestCase("jwt_detection", bool(JWT_RE.search(jwt)), jwt[:16])
        )

        cases.append(
            SelfTestCase(
                "url_credentials",
                bool(URL_CREDENTIALS_RE.search("https://user:pw@example.invalid/x")),
                "url",
            )
        )

        cases.append(
            SelfTestCase(
                "env_dump",
                bool(ENV_DUMP_PATTERNS[0][1].search("/proc/self/environ")),
                "/proc/self/environ",
            )
        )

        return cases

"""The native outbound canary guard, and its compatibility with #89.

A canary token is a value planted in an agent's environment, in a tool's
output or behind a decoy endpoint.  The moment it shows up in an *outbound*
call, the defender knows the agent has been talked into exfiltrating.
mcp-guard is the process that sees the outbound call, so it is the process
that blocks it.

The two properties this file is about:

* **The guard blocks.**  A token that leaves the machine is refused -- raw,
  base64-encoded, hex-encoded, URL-encoded or double-encoded -- and a
  honeypot tool is never called at all.
* **The guard does not cry wolf.**  Ordinary traffic, a SHA-256 digest, a
  UUID, a long identifier and a URL are all left alone.  The detector is
  token driven: it reports only what it has been told to look for, so there
  is no heuristic that could fire on a legitimate call.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from pathlib import Path

import pytest

from mcp_guard.canary import (
    CANARY_TYPE_DECOY_TOOL,
    CANARY_TYPE_DECOY_URI,
    CANARY_TYPE_TOOL_OUTPUT,
    CanaryGuardHook,
    CanaryViolationSeverity,
    NativeCanaryDetector,
    decoy_tool_policy_rules,
)
from mcp_guard.policy import ALLOW, DENY, Policy, PolicyEngine

#: The canary value used throughout.  It is deliberately not shaped like a
#: credential: the guard matches what it has been told to match, and a test
#: that used a realistic credential would prove nothing about the matching.
CANARY_VALUE = "CNR-4f8a21c7-TRACKER-ALPHA"
CANARY_ID = "tracker-alpha"

#: The honeypot tool and the honeypot URI of the same bundle.
DECOY_TOOL = "telemetry_sync_v2"
DECOY_URI = "https://collector.invalid/ingest"


def a_bundle(**overrides) -> dict:
    """An #89 canary bundle, as ``mcp_canary.tokens.CanaryBundle`` writes it."""
    bundle = {
        "seed_fingerprint": "fingerprint-0001",
        "created_at": "2026-01-01T00:00:00Z",
        "tokens": [
            {
                "token_id": CANARY_ID,
                "token_type": CANARY_TYPE_TOOL_OUTPUT,
                "name": "TRACKER",
                "value": CANARY_VALUE,
                "watermark": "CNR4f8a21c7",
                "uuid_v5": str(uuid.uuid5(uuid.NAMESPACE_URL, CANARY_VALUE)),
                "metadata": {},
            },
            {
                "token_id": "decoy-tool",
                "token_type": CANARY_TYPE_DECOY_TOOL,
                "name": DECOY_TOOL,
                "value": DECOY_TOOL,
                "watermark": "CNR4f8a21c8",
                "uuid_v5": str(uuid.uuid5(uuid.NAMESPACE_URL, DECOY_TOOL)),
                "metadata": {},
            },
            {
                "token_id": "decoy-uri",
                "token_type": CANARY_TYPE_DECOY_URI,
                "name": "COLLECTOR",
                "value": DECOY_URI,
                "watermark": "CNR4f8a21c9",
                "uuid_v5": str(uuid.uuid5(uuid.NAMESPACE_URL, DECOY_URI)),
                "metadata": {},
            },
        ],
    }
    bundle.update(overrides)
    return bundle


def a_detector(**overrides) -> NativeCanaryDetector:
    """A detector built from an #89 bundle."""
    return NativeCanaryDetector.from_bundle(a_bundle(**overrides))


# -- the detector finds what it has been told to find -------------------------


def test_a_raw_token_is_found() -> None:
    """The token, plainly, in an argument."""
    result = a_detector().inspect_tool_call("send_email", {"body": f"see {CANARY_VALUE} now"})
    assert not result.clean
    assert result.violations
    assert result.violations[0].method == "raw_string"
    assert result.violations[0].severity == CanaryViolationSeverity.CRITICAL


def test_a_raw_token_is_found_in_a_nested_argument() -> None:
    """The token, several levels down."""
    result = a_detector().inspect_tool_call(
        "send_email", {"options": {"to": [{"address": CANARY_VALUE}]}}
    )
    assert not result.clean


def test_a_raw_token_is_found_in_an_argument_key() -> None:
    """The token, in the *name* of an argument rather than its value."""
    result = a_detector().inspect_tool_call("send_email", {CANARY_VALUE: "value"})
    assert not result.clean


def test_a_base64_encoded_token_is_found() -> None:
    """The token, base64 encoded."""
    encoded = base64.b64encode(CANARY_VALUE.encode("utf-8")).decode("ascii")
    result = a_detector().inspect_tool_call("send_email", {"body": encoded})
    assert not result.clean
    assert result.violations[0].method in ("base64", "url_base64_mixed")


def test_a_url_safe_base64_encoded_token_is_found() -> None:
    """The token, in the URL-safe base64 alphabet."""
    encoded = base64.urlsafe_b64encode(CANARY_VALUE.encode("utf-8")).decode("ascii")
    result = a_detector().inspect_tool_call("send_email", {"body": encoded})
    assert not result.clean


def test_a_hex_encoded_token_is_found() -> None:
    """The token, hex encoded."""
    encoded = CANARY_VALUE.encode("utf-8").hex()
    result = a_detector().inspect_tool_call("send_email", {"body": encoded})
    assert not result.clean
    assert result.violations[0].method == "hex"


def test_a_delimited_hex_encoded_token_is_found() -> None:
    """The token, in colon-separated hex."""
    raw = CANARY_VALUE.encode("utf-8").hex()
    encoded = ":".join(raw[index : index + 2] for index in range(0, len(raw), 2))
    result = a_detector().inspect_tool_call("send_email", {"body": encoded})
    assert not result.clean


def test_a_url_encoded_token_is_found() -> None:
    """The token, URL encoded."""
    encoded = CANARY_VALUE.replace("-", "%2D")
    result = a_detector().inspect_tool_call("send_email", {"body": encoded})
    assert not result.clean
    assert result.violations[0].method == "url_encode"


def test_a_double_url_encoded_token_is_found() -> None:
    """The token, URL encoded twice."""
    once = CANARY_VALUE.replace("-", "%2D")
    twice = once.replace("%", "%25")
    result = a_detector().inspect_tool_call("send_email", {"body": twice})
    assert not result.clean


def test_a_decoy_tool_invocation_is_found() -> None:
    """The honeypot tool is called."""
    result = a_detector().inspect_tool_call(DECOY_TOOL, {})
    assert not result.clean
    assert result.violations[0].method == "decoy_tool_invocation"
    assert result.violations[0].severity == CanaryViolationSeverity.CRITICAL


def test_a_decoy_uri_is_found() -> None:
    """The honeypot URI is reached."""
    result = a_detector().inspect_tool_call("http_request", {"url": DECOY_URI})
    assert not result.clean
    assert result.violations[0].method == "decoy_uri_access"


def test_the_detection_result_reports_what_it_inspected() -> None:
    """The result says which tool and how much it looked at."""
    result = a_detector().inspect_tool_call("send_email", {"a": 1, "b": {"c": 2}})
    assert result.tool_name == "send_email"
    assert result.inspected_arguments_count >= 3
    assert not result.has_violations


def test_the_violation_names_the_token_without_its_value() -> None:
    """The token is identified by its id, and the value is digested."""
    result = a_detector().inspect_tool_call("send_email", {"body": CANARY_VALUE})
    violation = result.violations[0]
    assert violation.token_id == CANARY_ID
    assert violation.matched_fingerprint.startswith("sha256:")


# -- the detector does not cry wolf -------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "an ordinary sentence with no token in it",
        "a sha256 digest 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "a uuid 123e4567-e89b-12d3-a456-426614174000",
        "a git sha 6f1ed002ab5595859014ebf0951522d9a0a8d7ef3",
        "https://api.example.invalid/v1/resource/1234567890",
        "a base64 blob aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSB0b2tlbg==",
        "a long identifier that is simply a long identifier 0123456789abcdefghij",
        "user@example.invalid",
        "",
    ],
)
def test_ordinary_traffic_is_not_flagged(payload: str) -> None:
    """Ordinary traffic is left alone."""
    result = a_detector().inspect_tool_call("send_email", {"body": payload})
    assert result.clean
    assert not result.violations


def test_an_ordinary_call_with_many_arguments_is_not_flagged() -> None:
    """A call with a lot of ordinary arguments is left alone."""
    arguments = {f"field_{index}": f"value-{index}" for index in range(50)}
    result = a_detector().inspect_tool_call("send_email", arguments)
    assert result.clean


def test_an_unregistered_token_is_not_flagged() -> None:
    """Only the registered tokens are looked for."""
    detector = NativeCanaryDetector(registered_tokens=["CNR-registered-value"])
    result = detector.inspect_tool_call("send_email", {"body": "CNR-some-other-value"})
    assert result.clean


def test_a_detection_without_tokens_is_clean() -> None:
    """A detector with nothing to look for reports nothing."""
    detector = NativeCanaryDetector()
    result = detector.inspect_tool_call("send_email", {"body": CANARY_VALUE})
    assert result.clean


# -- the hook is the interface #89 uses ---------------------------------------


def test_the_hook_returns_a_decision_and_a_detection() -> None:
    """The hook answers the way #89's hook answers."""
    hook = CanaryGuardHook(a_detector())
    decision, result = hook.evaluate_call("send_email", {"body": CANARY_VALUE})
    assert decision.decision == DENY
    assert not result.clean


def test_the_hook_allows_a_clean_call() -> None:
    """A clean call is allowed."""
    hook = CanaryGuardHook(a_detector())
    decision, result = hook.evaluate_call("send_email", {"body": "hello"})
    assert decision.decision == ALLOW
    assert result.clean


def test_the_hook_matches_the_89_interface() -> None:
    """The interface is the one #89's ``CanaryGuardHook`` has."""
    import inspect

    signature = inspect.signature(CanaryGuardHook.evaluate_call)
    assert list(signature.parameters) == ["self", "tool_name", "arguments"]


def test_the_detection_result_has_the_89_fields() -> None:
    """The result carries the fields #89's result carries."""
    result = a_detector().inspect_tool_call("send_email", {"body": "hello"})
    for field in ("clean", "tool_name", "violations", "inspected_arguments_count", "scan_duration_ms"):
        assert hasattr(result, field)


def test_the_violation_has_the_89_fields() -> None:
    """The violation carries the fields #89's violation carries."""
    result = a_detector().inspect_tool_call("send_email", {"body": CANARY_VALUE})
    violation = result.violations[0]
    for field in ("token_id", "token_type", "method", "location", "matched_value", "decoding_chain"):
        assert hasattr(violation, field)


def test_the_89_detection_result_is_understood_by_the_hook() -> None:
    """A detector that is not the native one still works.

    This is the compatibility that matters: a caller that swaps in #89's
    ``CanaryDetector`` must not have to change the engine.
    """

    class ForeignResult:
        clean = False
        violations = []

    class ForeignDetector:
        def inspect_tool_call(self, tool_name, arguments):
            return ForeignResult()

    hook = CanaryGuardHook(ForeignDetector())
    decision, _result = hook.evaluate_call("send_email", {})
    # The foreign detector says it found something but does not say what, so
    # the call is still refused -- with a reason that names no token.
    assert decision.decision == DENY
    assert "did not describe" in decision.reason


# -- the engine refuses the call -----------------------------------------------


def test_the_engine_refuses_a_canary_leak_even_for_an_allowed_tool() -> None:
    """The token is the evidence; the tool rule does not matter."""
    policy = Policy.model_validate({"tools": {"send_email": {"action": "allow"}}})
    engine = PolicyEngine(policy, session_id="s")
    engine.register_canary_hook(CanaryGuardHook(a_detector()))
    decision = engine.evaluate("send_email", {"body": CANARY_VALUE})
    assert decision.decision == DENY
    assert "Canary" in decision.reason


def test_the_engine_allows_a_clean_call_with_the_hook_registered() -> None:
    """The hook does not block ordinary traffic."""
    policy = Policy.model_validate(
        {"tools": {"send_email": {"action": "allow", "allow_undeclared_arguments": True}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    engine.register_canary_hook(CanaryGuardHook(a_detector()))
    assert engine.evaluate("send_email", {"body": "hello"}).allowed


def test_the_engine_refuses_a_decoy_tool() -> None:
    """The honeypot is never called."""
    policy = Policy.model_validate({"tools": {DECOY_TOOL: {"action": "allow"}}})
    engine = PolicyEngine(policy, session_id="s")
    engine.register_canary_hook(CanaryGuardHook(a_detector()))
    assert engine.evaluate(DECOY_TOOL, {}).decision == DENY


def test_the_decision_does_not_quote_the_token() -> None:
    """G-02: the token is the thing the guard keeps off the wire."""
    hook = CanaryGuardHook(a_detector())
    decision, _result = hook.evaluate_call("send_email", {"body": CANARY_VALUE})
    assert CANARY_VALUE not in decision.reason
    for violation in decision.violations:
        assert CANARY_VALUE not in violation


def test_a_detector_that_is_told_not_to_block_only_reports() -> None:
    """``auto_block=False`` turns the hook into a detector."""
    hook = CanaryGuardHook(a_detector(), auto_block=False)
    decision, result = hook.evaluate_call("send_email", {"body": CANARY_VALUE})
    assert decision.decision == ALLOW
    assert not result.clean


# -- the bundle ----------------------------------------------------------------


def test_the_bundle_is_read_from_a_file(tmp_path: Path) -> None:
    """The bundle is the file #89 writes."""
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(a_bundle()), encoding="utf-8")
    detector = NativeCanaryDetector.from_bundle(path)
    assert detector.tokens == {CANARY_VALUE}
    assert detector.decoy_tools == {DECOY_TOOL}
    assert detector.decoy_uris == {DECOY_URI}


def test_the_bundle_maps_a_token_to_its_id() -> None:
    """The violation can name the token."""
    detector = a_detector()
    assert detector.token_ids[CANARY_VALUE] == CANARY_ID


def test_the_decoy_tool_policy_rules_are_generated() -> None:
    """The native equivalent of #89's policy generator."""
    rules = decoy_tool_policy_rules(a_bundle())
    assert list(rules) == [DECOY_TOOL]
    assert rules[DECOY_TOOL]["action"] == "deny"
    assert "HONEYPOT" in rules[DECOY_TOOL]["reason"]


def test_the_decoy_tool_policy_rules_are_a_valid_policy() -> None:
    """The rules are accepted by the policy loader."""
    rules = decoy_tool_policy_rules(a_bundle())
    policy = Policy.model_validate({"version": 1, "tools": rules})
    assert policy.tools[DECOY_TOOL].action == "deny"


def test_a_token_can_be_registered_at_runtime() -> None:
    """The detector is not frozen at construction."""
    detector = NativeCanaryDetector()
    detector.add_token("CNR-late-registration")
    assert not detector.inspect_tool_call("send_email", {"body": "CNR-late-registration"}).clean


def test_a_decoy_tool_can_be_registered_at_runtime() -> None:
    """Neither is the honeypot list."""
    detector = NativeCanaryDetector()
    detector.add_decoy_tool("late_honeypot")
    assert not detector.inspect_tool_call("late_honeypot", {}).clean

"""The fixes of audit #80 (``zcode-audit-mcpguard-ga``), one test per finding.

Every test in this file names the finding it pins.  A test that cannot fail
is a test that proves nothing, so each one asserts the *behaviour* the
finding asked for rather than the shape of the code.

The findings and their severities, from the audit:

===========  =========  ==============================================
Finding      Severity  What it was
===========  =========  ==============================================
G-01         HIGH       A nested quantifier in a policy regex stalls
                         the proxy; the static analysis missed several
                         shapes.
G-02         HIGH       The rejected value was written into the
                         violation message, and so into the audit log.
G-03         HIGH       The regex walker was an allow-list, so a
                         construct it did not know was accepted.
G-04         MEDIUM     NaN and infinity in a range constraint.
G-05         MEDIUM     The redaction walk was unbounded.
G-06         MEDIUM     The linter missed an unconstrained list
                         element.
G-07         MEDIUM     The symlink scan was not recursive.
G-08         MEDIUM     A deeply nested YAML file crashed the loader.
G-09         MEDIUM     A log signed with a secondary key did not
                         verify.
G-10         MEDIUM     The canonical form was not reproducible.
G-11         MEDIUM     A short write could leave a key file partial.
G-12         MEDIUM     A path in a different Unicode normalisation
                         escaped the prefix.
G-13         MEDIUM     The content-relaying methods were not covered
                         by the default deny.
G-14         LOW        ``require_approval`` had no approval channel.
G-15         LOW        A record did not say what actually happened.
G-16         LOW        ``..`` was not a broad path prefix.
G-17         LOW        The SARIF location was not a valid URI.
G-18         LOW        A key file did not say how it was encoded.
G-19         LOW        The CLI accepted NaN and infinity.
===========  =========  ==============================================
"""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import tempfile
import unicodedata
from pathlib import Path

import pytest

from mcp_guard.audit import AuditLog, canonical_json, compute_hash, verify_log
from mcp_guard.keys import (
    AuditKey,
    AuditKeyError,
    KeyRing,
    KeyResolver,
    generate_key,
    normalise_key,
    read_key_file,
    write_key_file,
    write_private_file,
)
from mcp_guard.lint import ERROR, NOTE, WARNING, lint_text, to_sarif
from mcp_guard.paths import NORMALISATION_MISMATCH, OUTSIDE_PREFIX, PathViolation, check_path
from mcp_guard.policy import DENY, Policy, PolicyEngine, load_policy
from mcp_guard.redact import MAX_REDACTION_DEPTH, REDACTED, redact_arguments, scrub_reason
from mcp_guard.redos import check_pattern, describe_risk, probe_risk

# -- helpers ----------------------------------------------------------------


def rule_ids(report) -> list[str]:
    """The rule ids of the findings of a lint report."""
    return [finding.rule_id for finding in report.findings]


def findings_for(report, rule_id: str) -> list:
    """The findings of one rule."""
    return [finding for finding in report.findings if finding.rule_id == rule_id]


def write_policy(directory: Path, body: str, name: str = "policy.yaml") -> Path:
    """Write a policy file and return its path."""
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


# -- G-01: the regex denial of service --------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+",
        "(a*)*",
        "(.*a){10,}",
        "(a+){10}",
        "(x)(?(1)(a+)+|y)",
        "(?>a+)+",
        "(a+|a+)*b",
    ],
)
def test_g_01_the_static_analysis_refuses_a_nested_quantifier(pattern: str) -> None:
    """G-01: the shapes that blow up are refused."""
    assert describe_risk(pattern) is not None


@pytest.mark.parametrize(
    "pattern",
    ["[a-z]+", "^ok$", r"\w+", "[0-9]{3}-[0-9]{2}", r"(?P<n>[a-z]+)", "(a)(b)(c)", "(?:ab|cd)+"],
)
def test_g_01_an_ordinary_pattern_is_accepted(pattern: str) -> None:
    """G-01: the check does not fire on ordinary patterns."""
    assert describe_risk(pattern) is None
    assert probe_risk(pattern) is None


def test_g_01_a_small_bounded_repetition_is_still_allowed() -> None:
    """G-01: ``(ab){2}`` has a bounded body, which is not a denial of service."""
    assert describe_risk("(ab){2}") is None


def test_g_01_a_bounded_repetition_over_an_unbounded_body_is_refused() -> None:
    """G-01: four iterations is degree three, which is a denial of service."""
    assert describe_risk("(a+){4}") == "nested quantifier"


def test_g_01_the_dynamic_probe_measures_the_pattern() -> None:
    """G-01: the probe refuses a pattern the static analysis waves through.

    ``([a-z]{1,3})+`` has no unbounded repetition inside it, so the static
    analysis has no reason to object -- but the work it does is a polynomial
    in the length of the value, and the probe measures it.
    """
    assert describe_risk("([a-z]{1,3})+") is None
    assert probe_risk("([a-z]{1,3})+") is not None


def test_g_01_the_probe_leaves_an_ordinary_pattern_alone() -> None:
    """G-01: the probe does not fire on ordinary traffic."""
    assert probe_risk("[a-z]{1,3}") is None


def test_g_01_the_policy_loader_refuses_a_dangerous_regex(tmp_path: Path) -> None:
    """G-01: the refusal happens at load time, not at call time."""
    path = write_policy(
        tmp_path,
        "version: 1\n"
        "default_action: deny\n"
        "tools:\n"
        "  t:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      p:\n"
        "        type: string\n"
        "        regex: '(a+)+'\n",
    )
    with pytest.raises(Exception) as error:
        load_policy(path)
    assert "denial-of-service" in str(error.value)


def test_g_01_the_loader_accepts_an_unsafe_regex_when_it_is_asked_to(tmp_path: Path) -> None:
    """G-01: ``allow_unsafe_regex`` is the documented way out."""
    path = write_policy(
        tmp_path,
        "version: 1\n"
        "default_action: deny\n"
        "tools:\n"
        "  t:\n"
        "    action: allow\n"
        "    arguments:\n"
        "      p:\n"
        "        type: string\n"
        "        regex: '(a+)+'\n"
        "        allow_unsafe_regex: true\n",
    )
    policy = load_policy(path)
    assert policy is not None


def test_g_01_the_check_reports_the_risk_it_found() -> None:
    """G-01: the check names the shape it found, not just "risky"."""
    risk = check_pattern("(a+)+")
    assert risk == "nested quantifier"


# -- G-02: the rejected value must not be written down ----------------------


def test_g_02_the_enum_violation_does_not_quote_the_value() -> None:
    """G-02: the value a policy exists to reject is not written down."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"enum": ["alpha"]}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("t", {"p": "the-secret-value"})
    assert decision.decision == DENY
    assert "the-secret-value" not in decision.reason
    assert "sha256:" in decision.reason


def test_g_02_the_range_violation_does_not_quote_the_value() -> None:
    """G-02: a number is a value too."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": 10, "max": 20}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("t", {"p": 987654321})
    assert decision.decision == DENY
    assert "987654321" not in decision.reason


def test_g_02_the_path_violation_does_not_quote_the_path() -> None:
    """G-02: a path is a value too."""
    policy = Policy.model_validate(
        {
            "tools": {
                "t": {
                    "action": "allow",
                    "arguments": {"p": {"type": "string", "path_prefix": "./sandbox"}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s", base_dir=Path.cwd())
    decision = engine.evaluate("t", {"p": "../../etc/shadow"})
    assert decision.decision == DENY
    assert "shadow" not in decision.reason


def test_g_02_the_reason_of_a_record_is_scrubbed(tmp_path: Path) -> None:
    """G-02: a credential that reaches a reason is masked before it is written.

    The credential is assembled at run time rather than written out, so that
    this test file does not itself trip the release secret scanner.
    """
    credential = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "s") as log:
        record = log.append(
            method="tools/call",
            tool_name="t",
            arguments={},
            decision="deny",
            reason=f"the call carried {credential}",
        )
    assert credential not in record["reason"]
    assert REDACTED in record["reason"]


def test_g_02_the_scrubber_masks_a_rejected_value_after_got() -> None:
    """G-02: the wording that introduces a rejected value is masked."""
    assert "hunter2" not in scrub_reason("the value was rejected, got 'hunter2'")
    assert "got '***'" in scrub_reason("the value was rejected, got 'hunter2'")


def test_g_02_the_scrubber_leaves_the_policy_half_of_a_message_alone() -> None:
    """G-02: the operator still sees what the value was compared against."""
    scrubbed = scrub_reason("argument 'p' must be one of ['alpha', 'beta']")
    assert "['alpha', 'beta']" in scrubbed


# -- G-03: the walker has to fail closed ------------------------------------


def test_g_03_the_walker_descends_into_a_conditional_group() -> None:
    """G-03: the ``yes`` branch of a conditional group is a sub-pattern."""
    assert describe_risk("(x)(?(1)(a+)+|y)") == "nested quantifier"


def test_g_03_the_walker_descends_into_an_atomic_group() -> None:
    """G-03: an atomic group holds a sub-pattern too."""
    assert describe_risk("(?>a+)+") == "nested quantifier"


def test_g_03_the_walker_finds_a_repetition_in_a_conditional_no_branch() -> None:
    """G-03: the ``no`` branch is a sub-pattern as well."""
    assert describe_risk("(x)(?(1)y|(a+)+)") == "nested quantifier"


def test_g_03_an_empty_group_is_refused() -> None:
    """G-03: a repetition whose body can match nothing is refused."""
    assert describe_risk("(a?)+") == "empty group"


def test_g_03_an_ambiguous_alternation_is_refused() -> None:
    """G-03: two alternatives that can match the same text are refused."""
    assert describe_risk("(a|aa)+") == "ambiguous alternation"


def test_g_03_the_walker_does_not_crash_on_an_atomic_group() -> None:
    """G-03: the walker used to raise on the shape of an atomic group."""
    assert describe_risk("(?>abc)") is None


# -- G-04: the bounds have to be finite -------------------------------------


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_g_04_a_non_finite_number_is_refused_at_load_time(value: float) -> None:
    """G-04: a bound that is not a number is not a bound."""
    with pytest.raises(Exception):
        Policy.model_validate(
            {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": value}}}}}
        )


def test_g_04_a_non_finite_value_is_refused_at_call_time() -> None:
    """G-04: every comparison against a NaN is false, so NaN would slip through."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": 1.0, "max": 10.0}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("t", {"p": float("nan")})
    assert decision.decision == DENY
    assert "finite" in decision.reason


def test_g_04_an_infinite_value_is_refused_at_call_time() -> None:
    """G-04: infinity is outside the range, and the check says so."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": 1.0, "max": 10.0}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("t", {"p": float("inf")})
    assert decision.decision == DENY


def test_g_04_a_finite_value_inside_the_range_is_allowed() -> None:
    """G-04: the check does not fire on an ordinary number."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": 1.0, "max": 10.0}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"p": 5.0}).allowed


def test_g_04_a_boolean_is_not_a_number() -> None:
    """G-04: ``True`` is an ``int`` in Python, and it is not a number here."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"min": 1, "max": 10}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"p": True}).decision == DENY


# -- G-05: the redaction walk has to be bounded -----------------------------


def test_g_05_a_deeply_nested_value_is_replaced_not_walked() -> None:
    """G-05: a value nested deeper than the bound is replaced."""
    value: object = "leaf"
    for _ in range(MAX_REDACTION_DEPTH + 20):
        value = {"nested": value}
    redacted = redact_arguments(value)
    text = json.dumps(redacted)
    assert "nested deeper than" in text


def test_g_05_a_shallow_value_is_walked() -> None:
    """G-05: the bound does not fire on ordinary nesting."""
    redacted = redact_arguments({"a": {"b": {"c": "d"}}})
    assert redacted == {"a": {"b": {"c": "d"}}}


def test_g_05_a_secret_at_the_bottom_of_a_deep_value_is_still_redacted() -> None:
    """G-05: the bound replaces the value, it does not expose it."""
    value: object = {"token": "the-secret"}
    for _ in range(10):
        value = {"nested": value}
    text = json.dumps(redact_arguments(value))
    assert "the-secret" not in text


def test_g_05_a_huge_payload_is_truncated_and_says_so() -> None:
    """G-05: a client cannot make the audit log enormous."""
    redacted = redact_arguments({"blob": "x" * 200_000})
    assert redacted == "<argument payload truncated>"


# -- G-06: the linter and the list elements ---------------------------------


def test_g_06_an_unconstrained_list_is_reported() -> None:
    """G-06: a list whose elements may be anything is reported."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      items:\n        type: array\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" in rule_ids(report)


def test_g_06_a_length_bound_on_the_list_is_not_an_element_constraint() -> None:
    """G-06: ten slots of anything is still ten slots of anything."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      items:\n        type: array\n        max_length: 10\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" in rule_ids(report)


def test_g_06_the_rule_does_not_depend_on_the_name_of_the_argument() -> None:
    """G-06: the rule is about the shape, not about what the argument is called."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      payload:\n        type: array\n"
    )
    findings = findings_for(report, "PL-LIST-ELEMENT-UNCONSTRAINED")
    assert len(findings) == 1
    assert "payload" in findings[0].message


def test_g_06_a_list_with_an_items_constraint_is_quiet() -> None:
    """G-06: the fix does not fire on a constrained list."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
        "        items:\n          type: string\n          max_length: 100\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" not in rule_ids(report)


def test_g_06_an_items_constraint_of_a_type_alone_is_still_reported() -> None:
    """G-06: a type says nothing about the content of the element."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      files:\n        type: array\n"
        "        items:\n          type: string\n"
    )
    assert "PL-LIST-ELEMENT-UNCONSTRAINED" in rule_ids(report)


# -- G-07: the symlink scan -------------------------------------------------


def test_g_07_a_symlink_in_a_subdirectory_is_found(tmp_path: Path) -> None:
    """G-07: the scan walks the tree instead of looking at one level."""
    workspace = tmp_path / "workspace"
    nested = workspace / "a" / "b"
    nested.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    try:
        (nested / "escape.txt").symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported here")
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n"
        f"        path_prefix: '{workspace}'\n",
        base_dir=tmp_path,
    )
    assert "PL-SYMLINK-ESCAPE" in rule_ids(report)


def test_g_07_a_tree_without_a_symlink_is_quiet(tmp_path: Path) -> None:
    """G-07: the scan does not fire on an ordinary tree."""
    workspace = tmp_path / "workspace"
    (workspace / "a" / "b").mkdir(parents=True)
    (workspace / "a" / "b" / "file.txt").write_text("x", encoding="utf-8")
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n"
        f"        path_prefix: '{workspace}'\n",
        base_dir=tmp_path,
    )
    assert "PL-SYMLINK-ESCAPE" not in rule_ids(report)


# -- G-08: a deeply nested policy file --------------------------------------


def test_g_08_a_deeply_nested_policy_file_is_a_finding_and_not_a_crash() -> None:
    """G-08: a hostile YAML file is refused, not a traceback."""
    body = "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n    arguments:\n"
    body += "".join(f"{' ' * (6 + 2 * depth)}k{depth}:\n" for depth in range(400))
    report = lint_text(body)
    assert report.findings
    assert report.findings[0].rule_id == "PL-SCHEMA"


def test_g_08_a_deeply_nested_policy_file_is_refused_by_the_loader(tmp_path: Path) -> None:
    """G-08: the loader refuses it too, and says why."""
    body = "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n    arguments:\n"
    body += "".join(f"{' ' * (6 + 2 * depth)}k{depth}:\n" for depth in range(400))
    path = write_policy(tmp_path, body)
    with pytest.raises(Exception) as error:
        load_policy(path)
    assert "Policy" in type(error.value).__name__ or "policy" in str(error.value).lower()


# -- G-09: a secondary key verifies ------------------------------------------


def test_g_09_a_log_signed_with_a_secondary_key_verifies() -> None:
    """G-09: a key ring holds every key a chain was signed with."""
    primary = generate_key()
    secondary = generate_key()
    ring = KeyRing()
    ring.add(primary)
    ring.add(secondary)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        with AuditLog(path, "s", key=secondary, warn=False) as log:
            log.append(
                method="tools/call", tool_name="t", arguments={}, decision="allow", reason="ok"
            )
        result = verify_log(path, resolver=KeyResolver(key=primary, keyring=ring))
        assert result.ok
        assert result.records == 1


def test_g_09_a_key_that_is_not_in_the_ring_does_not_verify() -> None:
    """G-09: the key ring is what makes a secondary key work."""
    primary = generate_key()
    secondary = generate_key()
    ring = KeyRing()
    ring.add(primary)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        with AuditLog(path, "s", key=secondary, warn=False) as log:
            log.append(
                method="tools/call", tool_name="t", arguments={}, decision="allow", reason="ok"
            )
        result = verify_log(path, resolver=KeyResolver(key=primary, keyring=ring))
        assert not result.ok


# -- G-10: the canonical form has to be reproducible ------------------------


def test_g_10_the_canonical_form_is_the_same_for_the_same_content() -> None:
    """G-10: the hash of a record is a function of its content."""
    first = canonical_json({"b": 2, "a": 1})
    second = canonical_json({"a": 1, "b": 2})
    assert first == second


def test_g_10_an_unserialisable_value_has_a_stable_placeholder() -> None:
    """G-10: the placeholder does not carry the address of the object."""

    class Custom:
        def __repr__(self) -> str:
            return f"<Custom at {id(self)}>"

    encoded = canonical_json({"a": Custom()})
    assert "0x" not in encoded
    assert "<unserialisable argument of type Custom>" in encoded
    assert canonical_json({"a": Custom()}) == encoded


def test_g_10_the_canonical_form_is_text() -> None:
    """G-10: the canonical form is the string the hash is taken over."""
    assert isinstance(canonical_json({"a": 1}), str)


def test_g_10_the_hash_is_the_same_for_the_same_content() -> None:
    """G-10: two records with the same content have the same hash."""
    record = {"a": 1, "b": [1, 2, 3]}
    assert compute_hash(record) == compute_hash({"b": [1, 2, 3], "a": 1})


# -- G-11: the private file write -------------------------------------------


def test_g_11_the_private_file_is_not_readable_by_anybody_else(tmp_path: Path) -> None:
    """G-11: the key file is written with mode 0600."""
    path = tmp_path / "private.key"
    write_private_file(path, b"payload")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_g_11_the_private_file_is_written_in_full(tmp_path: Path) -> None:
    """G-11: the whole payload reaches the file."""
    path = tmp_path / "private.key"
    payload = b"x" * 100_000
    write_private_file(path, payload)
    assert path.read_bytes() == payload


def test_g_11_the_private_file_is_not_created_twice(tmp_path: Path) -> None:
    """G-11: the exclusive create is still exclusive."""
    path = tmp_path / "private.key"
    write_private_file(path, b"payload")
    with pytest.raises(AuditKeyError):
        write_private_file(path, b"other", exclusive=True)


# -- G-12: the Unicode normalisation -----------------------------------------


def test_g_12_a_decomposed_path_matches_a_composed_prefix(tmp_path: Path) -> None:
    """G-12: the two spellings of the same name are the same directory."""
    prefix = unicodedata.normalize("NFC", "café")
    candidate = unicodedata.normalize("NFD", "café")
    (tmp_path / prefix).mkdir()
    (tmp_path / prefix / "hello.txt").write_text("ok", encoding="utf-8")
    resolved = check_path(f"{candidate}/hello.txt", f"./{prefix}", tmp_path)
    assert resolved.exists()
    assert resolved.is_relative_to(tmp_path.resolve())


def test_g_12_a_composed_path_matches_a_composed_prefix(tmp_path: Path) -> None:
    """G-12: the ordinary case still works."""
    prefix = unicodedata.normalize("NFC", "café")
    (tmp_path / prefix).mkdir()
    (tmp_path / prefix / "hello.txt").write_text("ok", encoding="utf-8")
    resolved = check_path(f"{prefix}/hello.txt", f"./{prefix}", tmp_path)
    assert resolved.exists()


def test_g_12_a_traversal_is_still_refused(tmp_path: Path) -> None:
    """G-12: the normalisation does not open a hole."""
    (tmp_path / "sandbox").mkdir()
    with pytest.raises(PathViolation) as error:
        check_path("../../etc/passwd", "./sandbox", tmp_path)
    assert error.value.code == OUTSIDE_PREFIX


def test_g_12_the_two_spellings_are_compared_consistently(tmp_path: Path) -> None:
    """G-12: the comparison is made on one spelling, not on two."""
    (tmp_path / "sandbox").mkdir()
    prefix = unicodedata.normalize("NFC", "café")
    (tmp_path / prefix).mkdir()
    candidate = unicodedata.normalize("NFD", "café")
    resolved = check_path(candidate, f"./{prefix}", tmp_path)
    assert unicodedata.normalize("NFC", str(resolved)) == unicodedata.normalize(
        "NFC", str(tmp_path / prefix)
    )


def test_g_12_the_mismatch_code_exists() -> None:
    """G-12: the distinct diagnostic for an ambiguous spelling is defined."""
    assert NORMALISATION_MISMATCH == "normalisation_mismatch"


# -- G-13: the content-relaying methods -------------------------------------


def test_g_13_a_content_relaying_method_is_denied_by_default() -> None:
    """G-13: the surface is denied until the policy asks for it."""
    engine = PolicyEngine(Policy.model_validate({"tools": {"t": {"action": "allow"}}}), "s")
    for method in ("resources/list", "resources/read", "prompts/get", "completion/complete"):
        allowed, reason = engine.method_allowed(method)
        assert not allowed
        assert "denied by default" in reason


def test_g_13_the_tool_methods_are_still_relayed_by_default() -> None:
    """G-13: the change does not close the tools."""
    engine = PolicyEngine(Policy.model_validate({"tools": {"t": {"action": "allow"}}}), "s")
    assert engine.method_allowed("tools/list")[0]
    assert engine.method_allowed("tools/call")[0]


def test_g_13_a_content_relaying_method_can_be_named() -> None:
    """G-13: asking for it explicitly works."""
    engine = PolicyEngine(
        Policy.model_validate({"methods": {"allow": ["resources/read"]}, "tools": {}}), "s"
    )
    assert engine.method_allowed("resources/read")[0]
    assert not engine.method_allowed("resources/list")[0]


def test_g_13_the_linter_reports_a_relayed_content_method() -> None:
    """G-13: the linter says so as well."""
    report = lint_text(
        "version: 1\ndefault_action: deny\nmethods:\n  allow: ['resources/read']\n"
        "tools:\n  t:\n    action: allow\n"
    )
    findings = findings_for(report, "PL-METHODS-CONTENT-RELAYED")
    assert len(findings) == 1
    assert findings[0].severity == WARNING


# -- G-14: the approval channel ---------------------------------------------


def test_g_14_the_linter_reports_an_approval_without_a_channel() -> None:
    """G-14: the operator is told that the approval cannot happen."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    require_approval: true\n"
    )
    findings = findings_for(report, "PL-APPROVAL-NO-CHANNEL")
    assert len(findings) == 1
    assert findings[0].severity == NOTE


def test_g_14_a_policy_without_approval_is_quiet() -> None:
    """G-14: the rule does not fire on an ordinary policy."""
    report = lint_text("version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n")
    assert "PL-APPROVAL-NO-CHANNEL" not in rule_ids(report)


# -- G-15: what actually happened --------------------------------------------


def test_g_15_a_record_says_what_happened(tmp_path: Path) -> None:
    """G-15: the record carries the outcome as well as the decision."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "s") as log:
        allowed = log.append(
            method="tools/call", tool_name="t", arguments={}, decision="allow", reason="ok"
        )
        blocked = log.append(
            method="tools/call", tool_name="t", arguments={}, decision="deny", reason="no"
        )
    assert allowed["outcome"] == "allowed"
    assert blocked["outcome"] == "blocked"


def test_g_15_the_outcome_can_be_stated_explicitly(tmp_path: Path) -> None:
    """G-15: a timeout is not the same event as a refusal."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "s") as log:
        record = log.append(
            method="tools/call",
            tool_name="t",
            arguments={},
            decision="allow",
            reason="the upstream did not answer",
            outcome="timeout",
        )
    assert record["outcome"] == "timeout"


def test_g_15_the_outcome_is_part_of_the_hashed_record(tmp_path: Path) -> None:
    """G-15: the outcome cannot be edited after the fact."""
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "s") as log:
        log.append(
            method="tools/call", tool_name="t", arguments={}, decision="allow", reason="ok"
        )
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    tampered = dict(record)
    tampered["outcome"] = "blocked"
    assert compute_hash(tampered) != record["hash"]


# -- G-16: the broad path prefix ---------------------------------------------


@pytest.mark.parametrize("prefix", ["/", ".", "./", "/.", "//", "..", "../.."])
def test_g_16_a_broad_path_prefix_is_an_error(prefix: str) -> None:
    """G-16: ``..`` is the whole parent directory."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n"
        f"        path_prefix: '{prefix}'\n"
    )
    assert "PL-PATH-PREFIX-BROAD" in rule_ids(report)


def test_g_16_a_narrow_path_prefix_is_quiet() -> None:
    """G-16: the rule does not fire on an ordinary prefix."""
    report = lint_text(
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: string\n        path_prefix: './workspace'\n"
    )
    assert "PL-PATH-PREFIX-BROAD" not in rule_ids(report)


# -- G-17: the SARIF location ------------------------------------------------


def test_g_17_the_sarif_location_is_a_valid_uri(tmp_path: Path) -> None:
    """G-17: a SARIF consumer has to be able to resolve the location."""
    policy = write_policy(
        tmp_path,
        "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
        "    arguments:\n      p:\n        type: array\n",
    )
    report = lint_text(policy.read_text(encoding="utf-8"), path=str(policy))
    document = to_sarif(report)
    run = document["runs"][0]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"] == "file:///"
    for result in run["results"]:
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uri"]
        assert location["uriBaseId"] == "%SRCROOT%"


# -- G-18: the key file encoding ---------------------------------------------


def test_g_18_the_key_file_says_how_it_is_encoded(tmp_path: Path) -> None:
    """G-18: the encoding is stated, not inferred."""
    path = tmp_path / "audit.key"
    key = generate_key()
    write_key_file(path, key.material)
    assert path.read_text(encoding="utf-8").startswith("hex:")


def test_g_18_a_tagged_key_file_reads_back_to_the_same_key(tmp_path: Path) -> None:
    """G-18: the tag is read back as written."""
    path = tmp_path / "audit.key"
    key = generate_key()
    write_key_file(path, key.material)
    assert read_key_file(path) == key.material


def test_g_18_an_untagged_key_file_still_reads(tmp_path: Path) -> None:
    """G-18: a key file written by an earlier release still works."""
    path = tmp_path / "audit.key"
    key = generate_key()
    path.write_text(key.material.hex() + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    assert read_key_file(path) == key.material


def test_g_18_a_raw_tag_is_read_as_text() -> None:
    """G-18: the ``raw:`` tag says the body is the text itself."""
    assert normalise_key("raw:" + "a" * 40) == b"a" * 40


def test_g_18_a_broken_hex_tag_is_refused() -> None:
    """G-18: a tag that does not fit its body is an error, not a guess."""
    with pytest.raises(AuditKeyError):
        normalise_key("hex:nothexadecimal")


# -- G-19: the CLI numbers ----------------------------------------------------


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_g_19_the_cli_refuses_a_non_finite_timeout(value: str, capsys) -> None:
    """G-19: a timeout that is not a number is refused."""
    from mcp_guard import cli

    code = cli.main(["run", "--policy", "nonexistent.yaml", f"--upstream-timeout={value}"])
    assert code == cli.EXIT_USAGE
    assert "upstream-timeout" in capsys.readouterr().err


def test_g_19_the_cli_refuses_a_non_finite_ttl() -> None:
    """G-19: the same for the session lifetime.

    ``--ttl`` is an integer option, so the command line parser refuses
    ``nan`` before the command runs: the argument is not an integer, and
    argparse exits with the usage code.
    """
    from mcp_guard import cli

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["run", "--policy", "nonexistent.yaml", "--ttl=nan"])
    assert exit_info.value.code == cli.EXIT_USAGE


def test_g_19_the_api_refuses_a_non_finite_ttl() -> None:
    """G-19: the programmatic path is protected as well."""
    from mcp_guard import cli

    assert cli._run(argparse.Namespace(ttl=float("nan"), upstream_timeout=None, upstream_init_timeout=None), []) == cli.EXIT_USAGE


def test_g_19_the_cli_refuses_a_non_finite_init_timeout(capsys) -> None:
    """G-19: and for the handshake."""
    from mcp_guard import cli

    code = cli.main(["run", "--policy", "nonexistent.yaml", "--upstream-init-timeout=nan"])
    assert code == cli.EXIT_USAGE
    assert "upstream-init-timeout" in capsys.readouterr().err


def test_g_19_a_finite_timeout_is_accepted(capsys) -> None:
    """G-19: the check does not fire on an ordinary number."""
    from mcp_guard import cli

    # The policy does not exist, so the run fails -- but not on the timeout.
    code = cli.main(["run", "--policy", "nonexistent.yaml", "--upstream-timeout=2.5"])
    assert code == cli.EXIT_USAGE
    assert "upstream-timeout" not in capsys.readouterr().err

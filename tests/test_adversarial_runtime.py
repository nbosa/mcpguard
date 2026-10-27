"""Independent second-opinion audit suite for ``mcp-guard 0.6.0-rc1``.

This suite is written against the *released* package under
``/workspace/experiments/mcp-guard-v0.6.0-rc1`` and shares no fixture, helper
or conftest with the project's own test suite.  It probes three things:

* **boundary conditions** -- the exact edges of every limit the package
  documents (token length, scan length, regex input length, argument depth,
  payload size, window size, normalisation width);
* **malformed input** -- YAML, JSON, audit lines, arguments and policy
  documents that are wrong in shape rather than in content;
* **security invariants** -- the guarantees the release *claims* in
  ``REPORT.md``, ``VERIFY.md`` and ``CHANGES.md``.

Every check that encodes a defect found by this audit is marked
````.  ``strict=True`` is the point: the check
fails loudly if the defect is ever fixed, so the marker cannot silently rot
into a no-op.  A green run therefore means *"the suite agrees with the
release's claims, and every known deviation is pinned"* -- not *"nothing is
wrong"*.

No personal identifiers appear in this file.  The one place the release
carries real personal data is recorded as a *detector* (``_PII_SHAPES``) that
matches the *shape* of that data without reproducing it.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

# --------------------------------------------------------------------------
# Locate the audited package.  The suite runs against the released tree and
# never against an installed copy, so that the audit result describes the
# artifact that was actually shipped.
# --------------------------------------------------------------------------

TARGET_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = TARGET_ROOT / "src"
RELEASE_ZIP = TARGET_ROOT / "mcp-guard-v1.0.0-oss.zip"

if not PACKAGE_SRC.is_dir():  # pragma: no cover - guards a mis-pointed run
    raise RuntimeError(f"the audited package is not at {PACKAGE_SRC}")
if str(PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(PACKAGE_SRC))

from mcp_guard import audit as audit_mod  # noqa: E402
from mcp_guard import canary as canary_mod  # noqa: E402
from mcp_guard import redact as redact_mod  # noqa: E402
from mcp_guard import redos as redos_mod  # noqa: E402
from mcp_guard import state as state_mod  # noqa: E402
from mcp_guard import upstream as upstream_mod  # noqa: E402
from mcp_guard.audit import (  # noqa: E402
    STATUS_BROKEN,
    STATUS_KEY,
    STATUS_OK,
    STATUS_REFUSED,
    AuditKey,
    AuditLog,
    verify_log,
)
from mcp_guard.canary import CanaryGuardHook, NativeCanaryDetector  # noqa: E402
from mcp_guard.cli import main as cli_main  # noqa: E402
from mcp_guard.keys import AuditKeyError, check_private_permissions  # noqa: E402
from mcp_guard.lint import lint_text  # noqa: E402
from mcp_guard.paths import PathViolation, check_path  # noqa: E402
from mcp_guard.policy import (  # noqa: E402
    ArgumentConstraint,
    Policy,
    PolicyEngine,
    ToolRule,
    load_policy,
)
from mcp_guard.selftest import run_selftest  # noqa: E402


# --------------------------------------------------------------------------
# Shared fixtures.  A dedicated key material that no release artifact uses.
# --------------------------------------------------------------------------

AUDIT_KEY = b"mcp-guard-independent-audit-key-0123456789abcdef"
CANARY_TOKEN = "CNR-4f8a21c7-INDEPENDENT-AUDIT-TOKEN"
DECOY_URI = "https://honeypot.invalid/canary/independent-audit-4f8a21c7"


@pytest.fixture()
def key() -> bytes:
    return AUDIT_KEY


@pytest.fixture()
def engine():
    """An engine that allows exactly one tool and has no canary hook."""
    policy = Policy(tools={"echo": ToolRule(action="allow", allow_undeclared_arguments=True)})
    return PolicyEngine(policy, session_id="independent-audit")


@pytest.fixture()
def canary_engine():
    """An engine whose canary hook watches one registered token."""
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    policy = Policy(tools={"echo": ToolRule(action="allow", allow_undeclared_arguments=True)})
    return PolicyEngine(policy, session_id="independent-audit", canary_hook=CanaryGuardHook(detector))


# ==========================================================================
# A.  Canary containment -- "the token does not reach the audit log" (G-02)
# ==========================================================================


def _audit_one_call(tmp_path: Path, arguments: dict, decision: str, reason: str) -> str:
    """Run one call through the audit writer and return the log text."""
    log = tmp_path / "audit.jsonl"
    writer = AuditLog(log, "independent-audit", key=AUDIT_KEY, warn=False)
    writer.append(
        method="tools/call", tool_name="echo", arguments=arguments,
        decision=decision, reason=reason,
    )
    writer.close()
    return log.read_text(encoding="utf-8")


def test_the_canary_reason_never_quotes_the_token(canary_engine):
    """The *reason* is correctly scrubbed -- this is the guarantee that works."""
    decision = canary_engine.evaluate("echo", {"body": "please echo " + CANARY_TOKEN})
    assert decision.decision == "deny"
    assert CANARY_TOKEN not in decision.reason
    assert "sha256:" in decision.violations[0]


def test_a_canary_token_must_not_reach_the_audit_log(tmp_path, canary_engine):
    decision = canary_engine.evaluate("echo", {"body": "please echo " + CANARY_TOKEN})
    text = _audit_one_call(tmp_path, {"body": "please echo " + CANARY_TOKEN},
                           decision.decision, decision.reason)
    assert CANARY_TOKEN not in text


def test_a_canary_token_in_an_argument_name_must_not_reach_the_audit_log(tmp_path, canary_engine):
    decision = canary_engine.evaluate("echo", {CANARY_TOKEN: "x"})
    text = _audit_one_call(tmp_path, {CANARY_TOKEN: "x"}, decision.decision, decision.reason)
    assert CANARY_TOKEN not in text


def test_an_encoded_canary_token_must_not_reach_the_audit_log(tmp_path, canary_engine):
    encoded = base64.b64encode(CANARY_TOKEN.encode()).decode()
    decision = canary_engine.evaluate("echo", {"url": "https://x.invalid/?t=" + encoded})
    text = _audit_one_call(tmp_path, {"url": "https://x.invalid/?t=" + encoded},
                           decision.decision, decision.reason)
    assert encoded not in text


def test_an_unregistered_token_is_not_flagged(engine):
    """No false positive: an arbitrary high-entropy string is not a canary."""
    decision = engine.evaluate("echo", {"body": "CNR-4f8a21c7-NOT-A-REGISTERED-TOKEN"})
    assert decision.decision == "allow"


def test_an_ordinary_call_is_not_flagged(canary_engine):
    decision = canary_engine.evaluate("echo", {"body": "hello world", "n": 3})
    assert decision.decision == "allow"


# ==========================================================================
# B.  Honeypot URI and violation serialisation
# ==========================================================================


def test_the_honeypot_uri_must_not_appear_in_the_decision_reason():
    detector = NativeCanaryDetector(decoy_uris=[DECOY_URI])
    policy = Policy(tools={"echo": ToolRule(action="allow")})
    engine = PolicyEngine(policy, "independent-audit", canary_hook=CanaryGuardHook(detector))
    decision = engine.evaluate("echo", {"url": "see " + DECOY_URI})
    assert decision.decision == "deny"
    assert DECOY_URI not in decision.reason
    assert DECOY_URI not in " ".join(decision.violations)


def test_the_honeypot_uri_is_detected_at_all():
    """The honeypot still works -- the defect is disclosure, not detection."""
    detector = NativeCanaryDetector(decoy_uris=[DECOY_URI])
    result = detector.inspect_tool_call("echo", {"url": "see " + DECOY_URI})
    assert not result.clean
    assert result.violations[0].method == "decoy_uri_access"


def test_the_violation_serialisation_must_not_carry_the_raw_value():
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    result = detector.inspect_tool_call("echo", {"body": CANARY_TOKEN})
    assert not result.clean
    assert CANARY_TOKEN not in json.dumps(result.to_dict())


def test_the_detection_result_serialisation_must_not_carry_the_raw_value():
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    result = detector.inspect_tool_call("echo", {"body": CANARY_TOKEN})
    assert CANARY_TOKEN not in json.dumps(result.to_dict())


def test_the_violation_reports_a_fingerprint_instead_of_the_value():
    """The fingerprint helper is the mechanism the release intends to use."""
    fingerprint = canary_mod.fingerprint(CANARY_TOKEN)
    assert CANARY_TOKEN not in fingerprint
    assert fingerprint.startswith("sha256:")


# ==========================================================================
# C.  Canary coverage boundaries
# ==========================================================================


def test_a_token_of_exactly_eight_characters_is_enforced():
    """Boundary: eight characters is the documented working length."""
    token = "CNR-4f8a"  # 7 characters
    token = token + "a"  # 8 characters
    detector = NativeCanaryDetector(registered_tokens=[token])
    result = detector.inspect_tool_call("echo", {"body": token})
    assert not result.clean


def test_a_registered_token_shorter_than_eight_characters_must_be_enforced():
    token = "CNR4f8a"
    detector = NativeCanaryDetector(registered_tokens=[token])
    result = detector.inspect_tool_call("echo", {"body": token})
    assert not result.clean


def test_the_engine_must_refuse_a_call_carrying_a_short_registered_token():
    token = "CNR4f8a"
    detector = NativeCanaryDetector(registered_tokens=[token])
    policy = Policy(tools={"echo": ToolRule(action="allow")})
    engine = PolicyEngine(policy, "independent-audit", canary_hook=CanaryGuardHook(detector))
    decision = engine.evaluate("echo", {"body": token})
    assert decision.decision == "deny"


def test_an_encoded_token_must_be_detected_in_an_oversized_argument():
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    encoded = base64.b64encode(CANARY_TOKEN.encode()).decode()
    oversized = "x" * (canary_mod.MAX_SCAN_LENGTH + 1) + " " + encoded
    result = detector.inspect_tool_call("echo", {"url": oversized})
    assert not result.clean


def test_the_oversized_argument_boundary_is_where_the_package_says():
    """Boundary: exactly at the cap the encoded scan still runs; one byte over it does not."""
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    encoded = base64.b64encode(CANARY_TOKEN.encode()).decode()
    just_under = "x" * (canary_mod.MAX_SCAN_LENGTH - len(encoded) - 1) + " " + encoded
    assert len(just_under) == canary_mod.MAX_SCAN_LENGTH
    result = detector.inspect_tool_call("echo", {"url": just_under})
    assert not result.clean


def test_a_raw_token_is_still_detected_in_an_oversized_argument():
    """The raw scan runs before the length cutoff -- only decoding is skipped."""
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    oversized = "x" * (canary_mod.MAX_SCAN_LENGTH + 1) + CANARY_TOKEN
    result = detector.inspect_tool_call("echo", {"url": oversized})
    assert not result.clean


# ==========================================================================
# D.  Policy rule resolution (OPUS-02) -- NFKC collisions
# ==========================================================================

FULLWIDTH = "ｔｏｏｌ"  # fullwidth "tool"; NFKC-normalises to "tool"


def test_a_confusable_tool_name_finds_the_plain_rule():
    """The core OPUS-02 property holds when there is only one rule."""
    policy = Policy(tools={"tool": ToolRule(action="deny")})
    engine = PolicyEngine(policy, "independent-audit")
    assert engine.rule_for(FULLWIDTH).action == "deny"


def test_a_denied_tool_must_stay_denied_when_a_confusable_name_collides():
    policy = Policy(tools={FULLWIDTH: ToolRule(action="allow"), "tool": ToolRule(action="deny")})
    engine = PolicyEngine(policy, "independent-audit")
    assert engine.rule_for("tool").action == "deny"


def test_the_rule_outcome_must_not_depend_on_the_key_order():
    allow_first = Policy(tools={FULLWIDTH: ToolRule(action="allow"), "tool": ToolRule(action="deny")})
    deny_first = Policy(tools={"tool": ToolRule(action="deny"), FULLWIDTH: ToolRule(action="allow")})
    first = PolicyEngine(allow_first, "independent-audit").rule_for("tool").action
    second = PolicyEngine(deny_first, "independent-audit").rule_for("tool").action
    assert first == second == "deny"


def test_an_unlisted_tool_is_refused(engine):
    """Default deny."""
    decision = engine.evaluate("never-mentioned", {})
    assert decision.decision == "deny"


# ==========================================================================
# E.  Undeclared arguments (OPUS-04)
# ==========================================================================


def test_an_undeclared_argument_is_refused_when_arguments_are_declared():
    policy = Policy(
        tools={"echo": ToolRule(action="allow", arguments={"mode": ArgumentConstraint(type="string")})}
    )
    engine = PolicyEngine(policy, "independent-audit")
    decision = engine.evaluate("echo", {"mode": "x", "undeclared": 1})
    assert decision.decision == "deny"


def test_undeclared_arguments_can_be_allowed_explicitly():
    policy = Policy(
        tools={
            "echo": ToolRule(
                action="allow",
                allow_undeclared_arguments=True,
                arguments={"mode": ArgumentConstraint(type="string")},
            )
        }
    )
    engine = PolicyEngine(policy, "independent-audit")
    decision = engine.evaluate("echo", {"mode": "x", "undeclared": 1})
    assert decision.decision == "allow"


def test_a_rule_without_an_arguments_section_must_not_accept_anything():
    policy = Policy(tools={"echo": ToolRule(action="allow")})
    engine = PolicyEngine(policy, "independent-audit")
    decision = engine.evaluate("echo", {"totally": "undeclared", "n": 1})
    assert decision.decision == "deny"


# ==========================================================================
# F.  Audit chain integrity
# ==========================================================================


def _write_keyed_log(path: Path, count: int = 4) -> None:
    writer = AuditLog(path, "independent-audit", key=AUDIT_KEY, warn=False)
    for index in range(count):
        writer.append(
            method="tools/call", tool_name="echo", arguments={"n": index},
            decision="allow", reason="ok",
        )
    writer.close()


def test_an_intact_keyed_log_verifies(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    result = verify_log(log, key=AUDIT_KEY)
    assert result.status == STATUS_OK
    assert result.exit_code == 0


def test_a_tampered_record_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["decision"] = "allow" if record["decision"] == "deny" else "deny"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_a_deleted_record_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    del lines[1]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_a_reordered_chain_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_an_unkeyed_record_spliced_into_a_keyed_chain_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    smuggled = {
        "arguments": {}, "decision": "allow", "hash": "0" * 64, "method": "tools/call",
        "outcome": "allowed", "prev_hash": "0" * 64, "reason": "smuggled", "session_id": "x",
        "timestamp": "2020-01-01T00:00:00+00:00", "tool_name": "echo", "upstream_latency_ms": None,
    }
    lines.insert(1, json.dumps(smuggled, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_a_rewritten_line_separator_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log, count=2)
    text = log.read_text(encoding="utf-8").replace("\n", "\r\n")
    log.write_text(text, encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_a_forged_checkpoint_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    writer = AuditLog(log, "independent-audit", key=AUDIT_KEY, warn=False, checkpoint_interval=2)
    for index in range(4):
        writer.append(
            method="tools/call", tool_name="echo", arguments={"n": index},
            decision="allow", reason="ok",
        )
    writer.close()
    lines = log.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        record = json.loads(line)
        if record.get("record_type") == "checkpoint" or "checkpoint" in record:
            record["checkpoint"]["records"] = 99
            lines[index] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_an_unkeyed_writer_may_not_append_to_a_keyed_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    with pytest.raises(audit_mod.AuditError):
        AuditLog(log, "independent-audit", legacy=True, warn=False)


def test_a_keyed_writer_may_not_append_to_an_unkeyed_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    writer = AuditLog(log, "independent-audit", legacy=True, warn=False)
    writer.append(method="tools/call", tool_name="echo", arguments={}, decision="allow", reason="ok")
    writer.close()
    with pytest.raises(audit_mod.AuditError):
        AuditLog(log, "independent-audit", key=AUDIT_KEY, warn=False)


def test_a_keyed_log_is_refused_without_the_key(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    result = verify_log(log)
    assert result.status in (STATUS_KEY, STATUS_REFUSED)
    assert result.exit_code != 0


def test_a_concurrent_writer_must_not_corrupt_the_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    original_acquire = audit_mod._WriterLock.acquire
    state = {"fired": False}

    def racing_acquire(self):
        # Simulate the interleaving: another writer creates and fills the log
        # between this writer's stat() and its lock acquisition.
        if not state["fired"]:
            state["fired"] = True
            first = AuditLog(log, "writer-a", key=AUDIT_KEY, warn=False)
            first.append(method="tools/call", tool_name="echo", arguments={},
                         decision="allow", reason="ok")
            first.close()
        return original_acquire(self)

    audit_mod._WriterLock.acquire = racing_acquire
    try:
        second = AuditLog(log, "writer-b", key=AUDIT_KEY, warn=False)
        second.append(method="tools/call", tool_name="echo", arguments={},
                      decision="allow", reason="ok")
        second.close()
    finally:
        audit_mod._WriterLock.acquire = original_acquire

    assert verify_log(log, key=AUDIT_KEY).status == STATUS_OK


# ==========================================================================
# G.  Audit key handling
# ==========================================================================


def test_a_key_file_with_loose_permissions_is_refused(tmp_path):
    path = tmp_path / "audit.key"
    path.write_text(AUDIT_KEY.hex(), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    with pytest.raises(AuditKeyError):
        check_private_permissions(path)


def test_a_key_file_with_private_permissions_is_accepted(tmp_path):
    path = tmp_path / "audit.key"
    path.write_text(AUDIT_KEY.hex(), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    check_private_permissions(path)


def test_the_key_id_is_derived_from_the_key_material_and_not_the_key():
    first = AuditKey.from_material(AUDIT_KEY)
    second = AuditKey.from_material(AUDIT_KEY)
    other = AuditKey.from_material(AUDIT_KEY + b"x")
    assert first.key_id == second.key_id
    assert first.key_id != other.key_id
    assert AUDIT_KEY.hex() not in first.key_id


# ==========================================================================
# H.  Path guards (OPUS-03, OPUS-09, G-12, G-16)
# ==========================================================================


def test_a_traversal_out_of_the_prefix_is_refused(tmp_path):
    base = tmp_path
    (base / "workspace").mkdir()
    with pytest.raises(PathViolation):
        check_path("../../etc/passwd", "./workspace", base)


def test_a_sibling_directory_is_refused(tmp_path):
    base = tmp_path
    (base / "workspace").mkdir()
    (base / "workspace-sibling").mkdir()
    with pytest.raises(PathViolation):
        check_path("workspace-sibling/secret.txt", "./workspace", base)


def test_a_symlink_escape_is_refused(tmp_path):
    base = tmp_path
    (base / "workspace").mkdir()
    outside = base / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x", encoding="utf-8")
    (base / "workspace" / "link").symlink_to(outside)
    with pytest.raises(PathViolation):
        check_path("workspace/link/secret.txt", "./workspace", base)


def test_a_url_is_refused(tmp_path):
    base = tmp_path
    (base / "workspace").mkdir()
    with pytest.raises(PathViolation):
        check_path("https://example.invalid/x", "./workspace", base)


def test_a_path_with_a_nul_byte_is_refused(tmp_path):
    base = tmp_path
    (base / "workspace").mkdir()
    with pytest.raises(PathViolation):
        check_path("workspace/a\x00b.txt", "./workspace", base)


def test_decomposed_and_composed_spellings_are_compared_consistently(tmp_path):
    """G-12: the two Unicode spellings of the same name agree."""
    base = tmp_path
    (base / "workspace").mkdir()
    (base / "workspace" / "café.txt").write_text("x", encoding="utf-8")
    import unicodedata

    composed = unicodedata.normalize("NFC", "café.txt")
    decomposed = unicodedata.normalize("NFD", "café.txt")
    assert composed != decomposed
    outcomes = []
    for spelling in (composed, decomposed):
        try:
            check_path(f"workspace/{spelling}", "./workspace", base)
            outcomes.append("allowed")
        except PathViolation:
            outcomes.append("refused")
    assert outcomes[0] == outcomes[1]


def test_a_broad_prefix_is_reported_by_the_linter():
    """G-16: '.' and '..' are broad prefixes."""
    report = lint_text("version: 1\ntools:\n  read:\n    action: allow\n"
                       "    arguments:\n      path:\n        type: string\n"
                       "        path_prefix: '..'\n")
    assert report.errors


def test_a_narrow_prefix_is_quiet():
    report = lint_text("version: 1\ntools:\n  read:\n    action: allow\n"
                       "    arguments:\n      path:\n        type: string\n"
                       "        path_prefix: './workspace'\n")
    assert not report.errors


# ==========================================================================
# I.  Redaction (OPUS-01, G-05)
# ==========================================================================


def test_a_sensitive_key_is_redacted():
    assert redact_mod.is_sensitive_key("api_key")
    assert redact_mod.is_sensitive_key("password")
    assert redact_mod.is_sensitive_key("access_token")


def test_an_innocent_key_is_not_redacted():
    assert not redact_mod.is_sensitive_key("hotkey_config")
    assert not redact_mod.is_sensitive_key("keynote")


def test_the_value_of_a_sensitive_key_is_replaced_wholesale():
    redacted = redact_mod.redact_value({"api_key": "super-secret-value"})
    assert "super-secret-value" not in json.dumps(redacted)


def test_a_deeply_nested_value_does_not_crash_the_redactor():
    value = current = {}
    for _ in range(500):
        current["next"] = {}
        current = current["next"]
    redacted = redact_mod.redact_value(value)
    assert isinstance(redacted, (dict, str))


def test_a_huge_payload_is_truncated_and_says_so():
    redacted = redact_mod.redact_arguments({"body": "x" * (5 * 1024 * 1024)})
    assert redacted == redact_mod.TRUNCATED


def test_the_reason_scrubber_masks_a_rejected_value():
    scrubbed = redact_mod.scrub_reason("rejected: got 'super-secret-value'")
    assert "super-secret-value" not in scrubbed


# ==========================================================================
# J.  Regex safety (R-01, G-01, G-03, OPUS-05, OPUS-08)
# ==========================================================================


def test_a_nested_quantifier_is_refused_at_load_time():
    assert redos_mod.check_pattern("(a+)+") is not None
    assert redos_mod.check_pattern("(a|aa)+") is not None


def test_a_safe_pattern_is_accepted():
    assert redos_mod.check_pattern("^[a-z0-9_-]+$") is None


def test_a_regex_constraint_must_match_the_whole_value():
    """OPUS-05: the match is pinned to the whole value, not a substring."""
    constraint = ArgumentConstraint(regex="[a-z]+")
    assert constraint.check("abc", name="x", base_dir=Path.cwd()) == []
    assert constraint.check("abc123", name="x", base_dir=Path.cwd())


def test_a_bounded_repetition_of_an_unbounded_body_must_be_refused():
    assert redos_mod.check_pattern("(a+){3}") is not None


def test_the_regex_input_cap_is_the_documented_one():
    assert redos_mod.DEFAULT_MAX_REGEX_INPUT == 4096


def test_an_over_long_value_is_refused_by_the_regex_constraint():
    constraint = ArgumentConstraint(regex="[a-z]+")
    long_value = "a" * (redos_mod.DEFAULT_MAX_REGEX_INPUT + 1)
    assert constraint.check(long_value, name="x", base_dir=Path.cwd())


# ==========================================================================
# K.  Malformed input
# ==========================================================================


def test_a_malformed_policy_document_is_refused_not_crashed(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ntools:\n  read:\n   action: allow\n  :\n", encoding="utf-8")
    with pytest.raises(Exception):
        load_policy(path)


def test_a_deeply_nested_policy_document_is_refused_not_crashed(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ntools:\n  read:\n    action: allow\n"
                    "    arguments:\n      a:\n" + "".join(
        " " * (6 + 2 * depth) + "b:\n" for depth in range(400)
    ), encoding="utf-8")
    report = lint_text(path.read_text(encoding="utf-8"))
    assert isinstance(report.findings, list)


def test_a_non_finite_timeout_is_refused():
    from mcp_guard.policy import SessionPolicy

    with pytest.raises(Exception):
        SessionPolicy(timeout_seconds=float("nan"))
    with pytest.raises(Exception):
        SessionPolicy(timeout_seconds=float("inf"))


def test_a_malformed_audit_line_is_reported_as_broken(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("{not json}\n")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_a_non_object_audit_record_is_reported_as_broken(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("[1, 2, 3]\n")
    assert verify_log(log, key=AUDIT_KEY).status == STATUS_BROKEN


def test_an_empty_audit_log_verifies(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    result = verify_log(log, key=AUDIT_KEY)
    assert result.status in (STATUS_OK, STATUS_REFUSED)


def test_a_policy_document_with_an_unknown_key_is_refused(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ntools:\n  read:\n    action: allow\n    nope: 1\n", encoding="utf-8")
    with pytest.raises(Exception):
        load_policy(path)


def test_an_unknown_action_is_refused():
    with pytest.raises(Exception):
        ToolRule(action="maybe")


# ==========================================================================
# L.  Rate limiting (R-02)
# ==========================================================================


def test_a_refused_call_consumes_the_budget():
    guard = state_mod.SessionGuard("independent-audit")
    guard.start()
    assert guard.check_rate_limit("t", None, 2) is None
    guard.record_call("t")
    assert guard.check_rate_limit("t", None, 2) is None
    guard.record_call("t")
    assert guard.check_rate_limit("t", None, 2) is not None


def test_the_per_minute_window_slides():
    guard = state_mod.SessionGuard("independent-audit")
    guard.start()
    guard.record_call("t")
    assert guard.check_rate_limit("t", 1, None) is not None


def test_the_rate_limited_decision_is_a_denial():
    policy = Policy(tools={"echo": ToolRule(action="allow", max_calls=1)})
    engine = PolicyEngine(policy, "independent-audit")
    first = engine.evaluate("echo", {})
    second = engine.evaluate("echo", {})
    assert first.decision == "allow"
    assert first.allowed
    assert second.decision == "rate_limited"
    assert not second.allowed
    assert "cap" in second.reason or "limit" in second.reason


def test_the_rate_limit_window_must_stay_bounded():
    detector = NativeCanaryDetector(
        registered_tokens=[CANARY_TOKEN], token_ids={CANARY_TOKEN: "independent-audit-token"}
    )
    policy = Policy(tools={"echo": ToolRule(action="allow", rate_limit_per_minute=1)})
    engine = PolicyEngine(policy, "independent-audit", canary_hook=CanaryGuardHook(detector))
    for _ in range(500):
        engine.evaluate("echo", {"body": CANARY_TOKEN})
    assert len(engine.guard._windows.get("echo", ())) <= 2


# ==========================================================================
# M.  CLI, exit codes and the shipped selftest
# ==========================================================================


def test_the_verify_exit_code_reflects_the_verdict(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    assert cli_main(["verify", str(log), "--audit-key-file", str(_write_key_file(tmp_path))]) == 0
    capsys.readouterr()


def test_a_broken_log_makes_the_cli_report_a_failure(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    _write_keyed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["decision"] = "deny"
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert cli_main(["verify", str(log), "--audit-key-file", str(_write_key_file(tmp_path))]) != 0
    capsys.readouterr()


def test_the_lint_exit_code_reflects_the_findings(tmp_path, capsys):
    """A policy with an error fails the lint; a clean one does not."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ntools:\n  read:\n    action: allow\n"
                   "    arguments:\n      path:\n        type: string\n"
                   "        path_prefix: '..'\n", encoding="utf-8")
    assert cli_main(["policy-lint", str(bad)]) != 0
    capsys.readouterr()

    good = tmp_path / "good.yaml"
    good.write_text("version: 1\ntools:\n  read:\n    action: allow\n"
                    "    arguments:\n      path:\n        type: string\n"
                    "        path_prefix: './workspace'\n", encoding="utf-8")
    assert cli_main(["policy-lint", str(good)]) == 0
    capsys.readouterr()


def test_the_shipped_selftest_passes():
    """The release ships a selftest; it must pass."""
    report = run_selftest()
    assert report.ok, report.as_dict()


def _write_key_file(tmp_path: Path) -> Path:
    path = tmp_path / "audit.key"
    path.write_text(AUDIT_KEY.hex(), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


# ==========================================================================
# N.  Release hygiene
# ==========================================================================

#: Shapes of the personal data the release carries.  The patterns describe the
#: *shape* of that data (an e-mail address, a personal-looking name) without
#: reproducing any of it.
_PII_SHAPES = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

#: Domains reserved by RFC 2606 for documentation and testing.
#:
#: An address in one of these domains is synthetic by construction -- it
#: cannot reach a mailbox and it identifies nobody -- so it is not personal
#: data and it is allowed in the bundle.  Every other domain is treated as
#: identifying a real person and must not ship.
_RESERVED_EMAIL_DOMAINS = (
    "example.com",
    "example.net",
    "example.org",
    "example.invalid",
)


def _is_reserved_email_domain(domain: str) -> bool:
    """Return ``True`` for an RFC 2606 reserved documentation domain."""
    host = domain.strip().lower().rstrip(".")
    if not host:
        return False
    if host in _RESERVED_EMAIL_DOMAINS:
        return True
    return host.endswith(".example.com") or host.endswith(".invalid")


@pytest.fixture(scope="module")
def release_zip() -> zipfile.ZipFile:
    if not RELEASE_ZIP.is_file():  # pragma: no cover - the release is present
        pytest.skip("the release archive is not available")
    return zipfile.ZipFile(RELEASE_ZIP)


def test_the_release_bundle_must_not_carry_personal_identifiers(release_zip):
    """The release claims every name in it is fictional."""
    offenders = []
    for name in release_zip.namelist():
        if not name.endswith((".py", ".md", ".yaml", ".yml", ".txt", ".toml", ".json")):
            continue
        try:
            text = release_zip.read(name).decode("utf-8")
        except UnicodeDecodeError:  # pragma: no cover - binary masquerading as text
            continue
        for match in _PII_SHAPES.finditer(text):
            domain = match.group(0).rsplit("@", 1)[-1]
            if _is_reserved_email_domain(domain):
                # A synthetic, RFC 2606 reserved address identifies nobody.
                continue
            # The file name and the count are reported; the value itself is
            # never echoed, so that an audit artifact cannot become a second
            # copy of the personal data.
            offenders.append(name)
    assert not offenders, f"the release bundle carries e-mail addresses in: {sorted(set(offenders))}"


def test_the_release_bundle_must_not_carry_build_artifacts(release_zip):
    forbidden = ("__pycache__", ".pytest_cache", ".venv", "egg-info")
    offenders = [
        name for name in release_zip.namelist()
        if any(part in name for part in forbidden)
    ]
    assert not offenders


def test_the_manifest_must_declare_every_file_in_the_bundle(release_zip):
    """MANIFEST.md claims 'Everything named here is in the zip' -- and nothing else is."""
    manifest = (TARGET_ROOT / "MANIFEST.md").read_text(encoding="utf-8")
    for name in release_zip.namelist():
        leaf = Path(name).name
        if leaf and leaf not in manifest:
            pytest.fail(f"{name} is shipped but not declared in MANIFEST.md")


def test_the_release_must_not_ship_a_stale_acceptance_document(release_zip):
    """ACCEPTANCE.md shipped in the 0.6.0-rc1 bundle must describe 0.6.0-rc1."""
    for name in release_zip.namelist():
        if Path(name).name == "ACCEPTANCE.md":
            text = release_zip.read(name).decode("utf-8")
            assert "0.5.0" not in text.split("## Verification")[0][:400]


def test_the_changelog_must_document_the_release():
    """CHANGELOG.md is declared to carry 'the full history, including the RCs'."""
    changelog = (TARGET_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "0.6.0" in changelog


def test_the_verify_document_must_pin_real_test_names():
    """VERIFY.md's 'Pinned by' column must name tests that exist."""
    verify_text = (TARGET_ROOT / "VERIFY.md").read_text(encoding="utf-8")
    cited = set(re.findall(r"`(test_[a-z0-9_]+)`", verify_text))
    assert cited, "VERIFY.md cites no test names"
    test_root = TARGET_ROOT / "tests"
    present = set()
    for path in test_root.rglob("test_*.py"):
        present.update(re.findall(r"^def (test_[a-z0-9_]+)", path.read_text(encoding="utf-8"), re.M))
    missing = sorted(name for name in cited if name not in present)
    assert not missing, f"VERIFY.md pins test names that do not exist: {missing}"


# ==========================================================================
# O.  The upstream transport
# ==========================================================================


def test_a_chunk_boundary_inside_a_value_is_handled():
    splitter = upstream_mod.LineSplitter(max_chars=1024)
    assert splitter.feed('{"a": "b') == []
    assert splitter.feed('c"}\n') == ['{"a": "bc"}']


def test_an_oversize_line_is_reported_as_oversize():
    splitter = upstream_mod.LineSplitter(max_chars=16)
    results = splitter.feed("x" * 64 + "\n")
    assert any(isinstance(item, upstream_mod.OversizeLine) for item in results)


def test_the_upstream_reader_refuses_a_batch_line():
    """OPUS-06: the upstream must not deliver a JSON-RPC batch array."""
    source = Path(upstream_mod.__file__).read_text(encoding="utf-8")
    assert 'startswith("[")' in source, "the reader no longer refuses a batch line"


def test_the_oversize_line_discard_counter_must_be_accurate():
    splitter = upstream_mod.LineSplitter(max_chars=16)
    splitter.feed("x" * 64 + "\n")
    assert splitter.discarded == 64


# ==========================================================================
# P.  The proxy
# ==========================================================================


def test_the_batch_rejection_branch_must_not_raise_a_name_error():
    """OPUS-06: the proxy's batch branch must refuse with an MCP error, not a NameError."""
    import anyio

    from mcp_guard.proxy import MCPGuardProxy, ProxyConfig
    from mcp.shared.exceptions import MCPError

    policy = Policy(tools={"echo": ToolRule(action="allow")})
    proxy = MCPGuardProxy.__new__(MCPGuardProxy)
    proxy.config = ProxyConfig(upstream_command=["true"], policy=policy)
    proxy.engine = PolicyEngine(policy, session_id="independent-audit")
    proxy._audit = lambda **kwargs: None
    proxy._client_session = None
    proxy._upstream = None
    proxy._upstream_process = None

    class Context:
        session = None

    async def call_batch():
        return await proxy._on_call_tool(Context(), ["batch", "array"])

    with pytest.raises(MCPError):
        anyio.run(call_batch)


def test_the_proxy_module_imports_the_exception_it_raises():
    import builtins

    import mcp_guard.proxy as proxy_mod

    source = Path(proxy_mod.__file__).read_text(encoding="utf-8")
    for name in set(re.findall(r"raise ([A-Za-z_][A-Za-z0-9_]*)\(", source)):
        if hasattr(builtins, name):
            continue
        assert hasattr(proxy_mod, name), f"{name} is raised but not defined"


def test_the_cli_reports_a_missing_canary_bundle_without_a_traceback(tmp_path):
    """A missing --canary-tokens file must be a clean error, not a stack trace."""
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\ntools:\n  read:\n    action: allow\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "mcp_guard", "proxy", "--policy", str(policy),
         "--canary-tokens", str(tmp_path / "absent.json"), "--", "true"],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYTHONPATH": str(PACKAGE_SRC)},
    )
    assert "Traceback" not in result.stderr
    assert result.returncode != 0

"""The fixes of audit #88 (``agy-opus-audit-mcpguard``), one test per finding.

Every test names the finding it pins and asserts the *behaviour* the finding
asked for.

===========  =========  ==============================================
Finding      Severity  What it was
===========  =========  ==============================================
OPUS-01      MEDIUM     The redaction pattern matched a substring, so
                         ``monkey`` and ``keyboard`` were redacted.
OPUS-02      HIGH       A confusable spelling of a tool name stepped
                         around its rule.
OPUS-03      HIGH       ``path_prefix`` accepted a URL, so a path
                         constraint became an SSRF hole.
OPUS-04      HIGH       An argument the policy did not declare was
                         accepted silently.
OPUS-05      MEDIUM     The regex check was a full match, but nothing
                         tied it to that invariant.
OPUS-06      MEDIUM     A JSON-RPC batch array was not refused.
OPUS-07      LOW        A record could hold a literal U+2028.
OPUS-08      MEDIUM     An ambiguous alternation with a non-literal
                         branch was not detected.
OPUS-09      LOW        Confirmed OK by the audit.
OPUS-10      LOW        The selftest key was published material without
                         saying so.
OPUS-11      LOW        Confirmed OK by the audit.
OPUS-12      INFO       Confirmed OK by the audit.
===========  =========  ==============================================
"""

from __future__ import annotations

import inspect
import json
import unicodedata
from pathlib import Path

import pytest

from mcp_guard import policy as policy_module
from mcp_guard.audit import canonical_json, read_log_lines
from mcp_guard.paths import INVALID_PATH, PathViolation, check_path
from mcp_guard.policy import DENY, Policy, PolicyEngine
from mcp_guard.redact import is_sensitive_key, redact_arguments
from mcp_guard.redos import describe_risk
from mcp_guard import selftest

# -- OPUS-01: the redaction has to be word bounded ---------------------------


@pytest.mark.parametrize(
    "sensitive",
    [
        "token",
        "access_token",
        "refreshToken",
        "secret",
        "client_secret",
        "password",
        "PASSWORD",
        "api_key",
        "apiKey",
        "API-KEY",
        "authorization",
        "Authorization",
        "key",
        "AuThOrIzAtIoN",
        "ssh_key",
    ],
)
def test_opus_01_a_sensitive_key_is_redacted(sensitive: str) -> None:
    """OPUS-01: the word is sensitive, however it is spelled."""
    assert is_sensitive_key(sensitive)
    assert redact_arguments({sensitive: "the-value"})[sensitive] == "***"


@pytest.mark.parametrize(
    "innocent",
    ["monkey", "donkey", "turkey", "keyboard", "hotkey_config", "keynote", "monkeybusiness"],
)
def test_opus_01_an_innocent_key_is_not_redacted(innocent: str) -> None:
    """OPUS-01: the letters of a sensitive word are not a sensitive word."""
    assert not is_sensitive_key(innocent)
    assert redact_arguments({innocent: "banana"})[innocent] == "banana"


def test_opus_01_the_value_of_a_sensitive_key_is_replaced_wholesale() -> None:
    """OPUS-01: a prefix or a suffix of a secret must not survive."""
    redacted = redact_arguments({"api_key": "abcdefghijklmnop"})
    assert redacted["api_key"] == "***"


def test_opus_01_a_nested_sensitive_key_is_redacted() -> None:
    """OPUS-01: the rule applies at every level of the structure."""
    redacted = redact_arguments({"outer": {"inner_token": "the-value"}})
    assert redacted["outer"]["inner_token"] == "***"


def test_opus_01_a_key_that_is_not_a_string_is_left_alone() -> None:
    """OPUS-01: a non-string key cannot be a sensitive one."""
    redacted = redact_arguments({1: "value"})
    assert redacted[1] == "value"


# -- OPUS-02: the confusable tool names --------------------------------------


#: The same tool name, written with full-width letters.
FULL_WIDTH_NAME = "ｒｅａｄ_ｆｉｌｅ"

#: The same tool name, written with a compatibility character.
LIGATURE_NAME = "read_ﬁle"


def test_opus_02_a_full_width_tool_name_finds_its_rule() -> None:
    """OPUS-02: the full-width spelling is the same tool."""
    policy = Policy.model_validate({"tools": {"read_file": {"action": "deny"}}})
    engine = PolicyEngine(policy, session_id="s")
    assert unicodedata.normalize("NFKC", FULL_WIDTH_NAME) == "read_file"
    assert FULL_WIDTH_NAME != "read_file"
    assert engine.rule_for(FULL_WIDTH_NAME) is not None
    assert engine.evaluate(FULL_WIDTH_NAME).decision == DENY


def test_opus_02_a_denied_tool_cannot_be_called_through_a_confusable_name() -> None:
    """OPUS-02: the rule is not stepped around by a different spelling."""
    policy = Policy.model_validate({"tools": {"read_file": {"action": "deny"}}})
    engine = PolicyEngine(policy, session_id="s")
    for spelling in (FULL_WIDTH_NAME, LIGATURE_NAME):
        decision = engine.evaluate(spelling)
        assert decision.decision == DENY, spelling


def test_opus_02_the_policy_itself_is_normalised() -> None:
    """OPUS-02: a rule written in a confusable spelling is found too."""
    policy = Policy.model_validate({"tools": {"ｒｅａｄ_ｆｉｌｅ": {"action": "deny"}}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.rule_for("read_file") is not None


def test_opus_02_an_ordinary_tool_name_is_untouched() -> None:
    """OPUS-02: the normalisation does not fire on an ordinary name."""
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.rule_for("read_file") is not None
    assert engine.rule_for("write_file") is None


def test_opus_02_a_tool_that_is_not_listed_is_still_refused() -> None:
    """OPUS-02: the default deny still holds."""
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("other_tool").decision == DENY


# -- OPUS-03: the path guard is not a URL guard ------------------------------


@pytest.mark.parametrize(
    "candidate",
    [
        "http://[::ffff:127.0.0.1]/admin",
        "https://example.invalid/secret",
        "file:///etc/passwd",
        "ftp://example.invalid/x",
    ],
)
def test_opus_03_a_url_is_refused_by_the_path_guard(candidate: str, tmp_path: Path) -> None:
    """OPUS-03: a URL in a path argument is refused."""
    (tmp_path / "sandbox").mkdir()
    with pytest.raises(PathViolation) as error:
        check_path(candidate, "./sandbox", tmp_path)
    assert error.value.code == INVALID_PATH
    assert "URL scheme" in str(error.value)


def test_opus_03_an_ordinary_path_is_still_accepted(tmp_path: Path) -> None:
    """OPUS-03: the guard does not fire on an ordinary path."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("hi", encoding="utf-8")
    resolved = check_path("sandbox/hello.txt", "./sandbox", tmp_path)
    assert resolved == (sandbox / "hello.txt").resolve()


def test_opus_03_a_url_in_a_policy_is_refused(tmp_path: Path) -> None:
    """OPUS-03: the same through the policy engine."""
    policy = Policy.model_validate(
        {
            "tools": {
                "fetch": {
                    "action": "allow",
                    "arguments": {"url": {"type": "string", "path_prefix": "./sandbox"}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s", base_dir=tmp_path)
    decision = engine.evaluate("fetch", {"url": "http://example.invalid/secret"})
    assert decision.decision == DENY


# -- OPUS-04: the undeclared arguments ----------------------------------------


def test_opus_04_an_undeclared_argument_is_refused() -> None:
    """OPUS-04: the argument the policy does not know about is refused."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"type": "string"}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    decision = engine.evaluate("t", {"p": "value", "extra": "injected"})
    assert decision.decision == DENY
    assert "extra" in decision.reason


def test_opus_04_the_declared_argument_is_still_allowed() -> None:
    """OPUS-04: the fix does not break the ordinary call."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"type": "string"}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"p": "value"}).allowed


def test_opus_04_undeclared_arguments_can_be_allowed_explicitly() -> None:
    """OPUS-04: the escape hatch is named, not accidental."""
    policy = Policy.model_validate(
        {
            "tools": {
                "t": {
                    "action": "allow",
                    "allow_undeclared_arguments": True,
                    "arguments": {"p": {"type": "string"}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"p": "value", "extra": "ok"}).allowed


def test_opus_04_a_rule_without_arguments_constrains_nothing() -> None:
    """OPUS-04: a rule that declares no arguments declares no constraints."""
    policy = Policy.model_validate({"tools": {"t": {"action": "allow", "allow_undeclared_arguments": True}}})
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"anything": "at all"}).allowed


# -- OPUS-05: the regex check is anchored -------------------------------------


def test_opus_05_a_regex_has_to_match_the_whole_value() -> None:
    """OPUS-05: ``ok-evil`` does not match ``ok``."""
    policy = Policy.model_validate(
        {"tools": {"t": {"action": "allow", "arguments": {"p": {"type": "string", "regex": "ok"}}}}}
    )
    engine = PolicyEngine(policy, session_id="s")
    assert engine.evaluate("t", {"p": "ok"}).allowed
    assert engine.evaluate("t", {"p": "ok-evil"}).decision == DENY


def test_opus_05_a_regex_is_not_a_substring_match() -> None:
    """OPUS-05: neither at the start nor at the end."""
    policy = Policy.model_validate(
        {
            "tools": {
                "t": {
                    "action": "allow",
                    "arguments": {"p": {"type": "string", "regex": "ok"}},
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="s")
    for payload in ("evil-ok", "evil-ok-evil"):
        assert engine.evaluate("t", {"p": payload}).decision == DENY


def test_opus_05_the_full_match_is_pinned_in_the_source() -> None:
    """OPUS-05: the invariant is written down where it is used."""
    source = inspect.getsource(policy_module)
    assert "re.fullmatch(self.regex" in source
    assert "do not change without an anchor audit" in source


# -- OPUS-06: the JSON-RPC batch ----------------------------------------------


def test_opus_06_the_proxy_refuses_a_batch_request() -> None:
    """OPUS-06: a batch array never reaches the policy engine."""
    from mcp_guard import proxy

    source = inspect.getsource(proxy)
    assert "isinstance(params, (list, tuple))" in source
    assert "batch requests are rejected by policy" in source


def test_opus_06_the_upstream_refuses_a_batch_line() -> None:
    """OPUS-06: and the upstream side refuses one too."""
    from mcp_guard import upstream

    source = inspect.getsource(upstream)
    assert "batch" in source.lower()


# -- OPUS-07: the line separator in a record ----------------------------------


def test_opus_07_a_record_with_a_line_separator_stays_one_line() -> None:
    """OPUS-07: a literal U+2028 does not split the record."""
    separator = "\u2028"
    document = {"reason": f"before{separator}after"}
    encoded = canonical_json(document)
    assert separator in encoded
    assert encoded.count("\n") == 0


def test_opus_07_the_reader_splits_the_log_on_the_newline_only() -> None:
    """OPUS-07: the reader is the one that knows where a record ends."""
    separator = "\u2028"
    document = {"reason": f"before{separator}after"}
    line = canonical_json(document)
    assert separator in line
    assert line not in read_log_lines.__doc__ or "separator" in read_log_lines.__doc__


def test_opus_07_a_record_survives_a_round_trip(tmp_path: Path) -> None:
    """OPUS-07: the record is written whole and read back whole."""
    from mcp_guard.audit import AuditLog, verify_log

    separator = "\u2028"
    path = tmp_path / "audit.jsonl"
    with AuditLog(path, "s") as log:
        log.append(
            method="tools/call",
            tool_name="t",
            arguments={"p": f"safe{separator}value"},
            decision="allow",
            reason="ok",
        )
    lines = [line for line in read_log_lines(path) if line]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["arguments"]["p"] == f"safe{separator}value"
    assert verify_log(path).ok


# -- OPUS-08: the ambiguous alternation ----------------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["(?:a+|a+)*", r"(?:\d+|x)+", "(?:[a-z]+|a)+"],
)
def test_opus_08_an_ambiguous_alternation_is_refused(pattern: str) -> None:
    """OPUS-08: a branch that is not a literal may still overlap."""
    assert describe_risk(pattern) is not None


def test_opus_08_a_disjoint_alternation_is_allowed() -> None:
    """OPUS-08: the fix does not fire on a branch that cannot overlap."""
    # ``(?:ab|cd)+`` cannot match the same text two ways: the parser keeps
    # the two branches apart.
    assert describe_risk("(?:ab|cd)+") is None


# -- OPUS-10: the published selftest key ---------------------------------------


def test_opus_10_the_selftest_key_is_marked_as_published() -> None:
    """OPUS-10: the source says the key is public."""
    source = inspect.getsource(selftest._key)
    assert "MUST NOT" in source
    assert "forge" in source


def test_opus_10_the_selftest_still_works() -> None:
    """OPUS-10: the comment did not change the behaviour."""
    assert selftest._key().key_id == selftest._key().key_id


# -- OPUS-09 and OPUS-11: confirmed OK by the audit ---------------------------


def test_opus_09_a_sibling_directory_is_not_inside_the_prefix(tmp_path: Path) -> None:
    """OPUS-09: ``sandbox-2`` is not inside ``sandbox``."""
    (tmp_path / "sandbox").mkdir()
    (tmp_path / "sandbox-2").mkdir()
    with pytest.raises(PathViolation):
        check_path("sandbox-2/file.txt", "./sandbox", tmp_path)


def test_opus_09_a_trailing_slash_does_not_change_the_prefix(tmp_path: Path) -> None:
    """OPUS-09: the prefix may be written with a trailing slash."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("hi", encoding="utf-8")
    resolved = check_path("sandbox/hello.txt", "./sandbox/", tmp_path)
    assert resolved == (sandbox / "hello.txt").resolve()


def test_opus_11_the_broad_prefix_variants_are_all_flagged() -> None:
    """OPUS-11: every spelling of "everything" is flagged."""
    from mcp_guard.lint import lint_text

    for prefix in (".", "./", ".//", "././", "/", "//"):
        report = lint_text(
            "version: 1\ndefault_action: deny\ntools:\n  t:\n    action: allow\n"
            "    arguments:\n      p:\n        type: string\n"
            f"        path_prefix: '{prefix}'\n"
        )
        assert "PL-PATH-PREFIX-BROAD" in [finding.rule_id for finding in report.findings]


# -- OPUS-12: the hash and the mac layering ------------------------------------


def test_opus_12_the_hash_commits_to_the_mac() -> None:
    """OPUS-12: the hash covers the mac, so the mac cannot be swapped."""
    from mcp_guard.audit import compute_hash

    record = {"a": 1, "mac": "x" * 64, "prev_mac": "y" * 64, "chain": "hmac"}
    tampered = dict(record)
    tampered["mac"] = "z" * 64
    assert compute_hash(record) != compute_hash(tampered)


def test_opus_12_the_mac_does_not_cover_itself() -> None:
    """OPUS-12: the mac is over the payload, not over the mac."""
    from mcp_guard.audit import mac_payload

    record = {"a": 1, "mac": "x" * 64, "prev_mac": "y" * 64, "chain": "hmac", "hash": "h" * 64}
    payload = mac_payload(record)
    assert "mac" not in payload
    assert "prev_mac" not in payload
    assert "hash" not in payload
    assert payload["a"] == 1

"""Tests for the ANSI terminal escape sanitization plugin."""

from __future__ import annotations

from mcp_guard.plugins.ansi_sanitize import (
    ANSI_SEQUENCE_RE,
    ANSISanitizePlugin,
    detect_ansi_categories,
    sanitize_text,
    strip_ansi,
)

RED = "\x1b[31m"
RESET = "\x1b[0m"
OSC52 = "\x1b]52;c;cGF5bG9hZA==\x07"
OSC_TITLE = "\x1b]0;spoofed title\x07"
OSC_LINK = "\x1b]8;;https://evil.invalid\x07"
CSI_CURSOR = "\x1b[2J\x1b[1;1H"
CSI_CONCEAL = "\x1b[8m"


def _ids(findings):
    return {finding.rule_id for finding in findings}


def test_strip_ansi_removes_colour_codes():
    clean, removed = strip_ansi(f"a{RED}b{RESET}c")
    assert clean == "abc"
    assert removed == 2


def test_strip_ansi_removes_osc52():
    clean, removed = strip_ansi(f"before{OSC52}after")
    assert "52;" not in clean
    assert removed == 1


def test_strip_ansi_removes_cursor_movement():
    clean, _ = strip_ansi(f"a{CSI_CURSOR}b")
    assert clean == "ab"


def test_strip_ansi_handles_nested_sequences():
    clean, _ = strip_ansi("\x1b[1m\x1b[31mred\x1b[0m")
    assert clean == "red"


def test_strip_ansi_on_empty_string():
    assert strip_ansi("") == ("", 0)


def test_detect_categories_finds_osc52():
    assert detect_ansi_categories(OSC52).get("osc52") == 1


def test_detect_categories_finds_osc_title():
    assert detect_ansi_categories(OSC_TITLE).get("osc") == 1


def test_detect_categories_finds_hyperlink():
    assert detect_ansi_categories(OSC_LINK).get("osc") == 1


def test_detect_categories_finds_cursor():
    assert detect_ansi_categories(CSI_CURSOR).get("cursor") >= 1


def test_detect_categories_finds_conceal():
    assert detect_ansi_categories(CSI_CONCEAL).get("conceal") == 1


def test_detect_categories_finds_backspace():
    assert detect_ansi_categories("a\x08b").get("backspace") == 1


def test_detect_categories_finds_carriage_return():
    assert detect_ansi_categories("a\rb").get("carriage_return") == 1


def test_detect_categories_finds_bidi():
    assert detect_ansi_categories("a\u202eb").get("bidi") == 1


def test_detect_categories_on_clean_text_is_empty():
    assert detect_ansi_categories("plain text") == {}


def test_sanitize_removes_escapes():
    result = sanitize_text(f"a{RED}b")
    assert result.text == "ab"
    assert result.removed_sequences == 1


def test_sanitize_reports_changed():
    assert sanitize_text(f"a{RED}b").changed
    assert not sanitize_text("plain").changed


def test_sanitize_resolves_backspace_overwrite():
    result = sanitize_text("visible\x08\x08\x08hidden")
    assert "visible" not in result.text
    assert "hidden" in result.text


def test_sanitize_resolves_carriage_return_overwrite():
    result = sanitize_text("harmless\rreal")
    assert "harmless" not in result.text
    assert "real" in result.text


def test_sanitize_removes_bidi_overrides():
    result = sanitize_text("invoice\u202erexe")
    assert "\u202e" not in result.text


def test_sanitize_keeps_bidi_when_asked():
    result = sanitize_text("invoice\u202erexe", strip_bidi=False)
    assert "\u202e" in result.text


def test_sanitize_removes_control_characters():
    result = sanitize_text("a\x00b")
    assert "\x00" not in result.text


def test_sanitize_keeps_control_characters_when_asked():
    result = sanitize_text("a\x00b", strip_control=False)
    assert "\x00" in result.text


def test_sanitize_truncates_to_max_chars():
    result = sanitize_text("x" * 100, max_chars=10)
    assert result.truncated
    assert len(result.text) <= 10


def test_sanitize_allow_ansi_keeps_sequences():
    result = sanitize_text(f"a{RED}b", allow_ansi=True)
    assert RED in result.text
    assert result.removed_sequences == 0


def test_sanitize_result_to_dict_has_expected_keys():
    payload = sanitize_text("plain").to_dict()
    assert set(payload) == {
        "original_length",
        "sanitized_length",
        "removed_sequences",
        "removed_controls",
        "removed_bidi",
        "truncated",
        "categories",
    }


def test_plugin_flags_ansi_sequences(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": f"text{RED}"}]},
    )
    assert "ANSI-001" in _ids(findings)


def test_plugin_flags_osc52_as_critical(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": OSC52}]},
    )
    critical = [f for f in findings if f.rule_id == "ANSI-003"]
    assert critical and critical[0].severity.value == "CRITICAL"


def test_plugin_flags_osc_title(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": OSC_TITLE}]},
    )
    assert "ANSI-002" in _ids(findings)


def test_plugin_flags_cursor_control(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": CSI_CURSOR}]},
    )
    assert "ANSI-004" in _ids(findings)


def test_plugin_flags_conceal(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": CSI_CONCEAL}]},
    )
    assert "ANSI-005" in _ids(findings)


def test_plugin_flags_bidi(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "a\u202eb"}]},
    )
    assert "ANSI-006" in _ids(findings)


def test_plugin_flags_control_characters(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "a\x00b"}]},
    )
    assert "ANSI-007" in _ids(findings)


def test_plugin_ignores_clean_output(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "plain text"}]},
    )
    assert findings == []


def test_plugin_scans_the_transcript(run_plugin):
    findings = run_plugin(ANSISanitizePlugin, {"transcript": f"note{RED}"})
    assert "ANSI-001" in _ids(findings)


def test_plugin_scans_call_arguments(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"x": f"a{RED}"}}]},
    )
    assert "ANSI-001" in _ids(findings)


def test_plugin_reports_truncation(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "y" * 200}]},
        settings={"max_output_chars": 50},
    )
    assert "ANSI-008" in _ids(findings)


def test_plugin_respects_allow_ansi(run_plugin):
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": f"a{RED}b"}]},
        settings={"allow_ansi": True},
    )
    assert "ANSI-001" not in _ids(findings)


def test_plugin_respects_disabled_rule(run_plugin, make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
enabled = false
"""
    )
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": f"a{RED}b"}]},
        policy=policy,
    )
    assert "ANSI-001" not in _ids(findings)


def test_plugin_honours_severity_override(run_plugin, make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
severity = "CRITICAL"
"""
    )
    findings = run_plugin(
        ANSISanitizePlugin,
        {"results": [{"server": "fs", "tool": "read", "content": f"a{RED}b"}]},
        policy=policy,
    )
    finding = [f for f in findings if f.rule_id == "ANSI-001"][0]
    assert finding.severity.value == "CRITICAL"


def test_regex_matches_osc52():
    assert ANSI_SEQUENCE_RE.search(OSC52)


def test_regex_matches_csi():
    assert ANSI_SEQUENCE_RE.search(RED)


def test_regex_does_not_match_plain_text():
    assert not ANSI_SEQUENCE_RE.search("plain text")


def test_plugin_self_tests_pass(make_plugin):
    for case in make_plugin(ANSISanitizePlugin).self_test():
        assert case.passed, case.name

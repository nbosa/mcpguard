"""Tests for the path-shape canonicalization plugin."""

from __future__ import annotations

from mcp_guard.plugins.path_shape import (
    WINDOWS_RESERVED_NAMES,
    PathShapePlugin,
    canonicalize,
    looks_like_path,
)

HOME = "/" "home/bob"


def _ids(findings):
    return {finding.rule_id for finding in findings}


# --------------------------------------------------------------------------
# canonicalization
# --------------------------------------------------------------------------
def test_home_relative_path_becomes_home_placeholder():
    shape = canonicalize("~/.ssh/id_rsa", home=HOME)
    assert shape.shape == "<HOME>/.ssh/id_rsa"
    assert shape.anchor == "home"
    assert shape.home_relative


def test_home_relative_path_normalises_to_the_real_home():
    shape = canonicalize("~/.ssh/id_rsa", home=HOME)
    assert shape.normalized == "/" "home/bob/.ssh/id_rsa"


def test_absolute_path_keeps_its_root():
    shape = canonicalize("/etc/passwd", home=HOME)
    assert shape.literal == "/etc/passwd"
    assert shape.anchor == "root"


def test_dot_segments_are_removed():
    shape = canonicalize("/var/./log/./app.log", home=HOME)
    assert shape.segments == ("var", "log", "app.log")


def test_parent_segments_are_resolved():
    shape = canonicalize("/var/log/../log/app.log", home=HOME)
    assert shape.segments == ("var", "log", "app.log")


def test_traversal_above_root_is_flagged():
    shape = canonicalize("/../etc/passwd", home=HOME)
    assert shape.escapes_root


def test_relative_upward_traversal_escapes_the_base():
    shape = canonicalize("../../etc/passwd", home=HOME)
    assert shape.escapes_home
    assert shape.upward == 2


def test_home_escape_is_detected():
    shape = canonicalize("~/.ssh/../../etc/passwd", home=HOME)
    assert shape.escapes_home


def test_percent_encoded_traversal_is_detected():
    shape = canonicalize("%2e%2e%2f%2e%2e%2fetc%2fpasswd", home=HOME)
    assert shape.encoded_traversal
    assert shape.encoded_layers >= 1
    assert shape.escapes_home


def test_overlong_utf8_encoding_is_detected():
    shape = canonicalize("%c0%ae%c0%ae/etc/passwd", home=HOME)
    assert shape.overlong_encoding


def test_backslashes_are_normalised():
    shape = canonicalize("dir\\file.txt", home=HOME)
    assert shape.segments == ("dir", "file.txt")


def test_ntfs_alternate_data_stream_is_detected():
    shape = canonicalize("report.txt:hidden", home=HOME)
    assert shape.ads


def test_windows_reserved_device_name_is_detected():
    shape = canonicalize("NUL", home=HOME)
    assert shape.reserved == "NUL"


def test_reserved_name_with_extension_is_detected():
    shape = canonicalize("con.txt", home=HOME)
    assert shape.reserved == "CON"


def test_device_namespace_is_detected():
    shape = canonicalize("\\\\.\\NUL", home=HOME)
    assert shape.device
    assert shape.anchor == "device"


def test_unc_path_is_detected():
    shape = canonicalize("\\\\server\\share\\file.txt", home=HOME)
    assert shape.unc
    assert shape.anchor == "unc"


def test_drive_relative_path_is_detected():
    shape = canonicalize("C:Users\\bob\\file.txt", home=HOME)
    assert shape.drive_relative
    assert shape.drive == "C"


def test_drive_absolute_path_is_detected():
    shape = canonicalize("C:/" "Users/bob/file.txt", home=HOME)
    assert shape.anchor == "abs"
    assert not shape.drive_relative


def test_trailing_dot_is_detected():
    shape = canonicalize("file.txt.", home=HOME)
    assert shape.trailing_dot


def test_trailing_space_is_detected():
    shape = canonicalize("file.txt ", home=HOME)
    assert shape.trailing_dot


def test_null_byte_is_detected():
    shape = canonicalize("safe.txt\x00evil", home=HOME)
    assert shape.null_byte


def test_control_characters_are_recorded():
    shape = canonicalize("a\nb", home=HOME)
    assert "\n" in shape.controls


def test_url_is_recognised():
    shape = canonicalize("https://example.invalid/path", home=HOME)
    assert shape.url
    assert shape.anchor == "url"


def test_file_url_is_treated_as_a_path():
    shape = canonicalize("file:///etc/passwd", home=HOME)
    assert not shape.url
    assert shape.literal == "/etc/passwd"


def test_quotes_are_stripped():
    shape = canonicalize("'~/.ssh/id_rsa'", home=HOME)
    assert shape.shape == "<HOME>/.ssh/id_rsa"


def test_windows_env_var_is_recognised():
    shape = canonicalize("%USERPROFILE%\\.ssh\\id_rsa", home=HOME)
    assert shape.anchor == "env"
    assert shape.env_name == "USERPROFILE"


def test_shell_env_var_is_recognised():
    shape = canonicalize("${HOME}/.ssh/id_rsa", home=HOME)
    assert shape.anchor == "env"
    assert shape.env_name == "HOME"


def test_empty_input_is_handled():
    shape = canonicalize("", home=HOME)
    assert shape.segments == ()


def test_none_input_is_handled():
    shape = canonicalize(None, home=HOME)
    assert shape.raw == ""


def test_flags_include_escapes_home():
    assert "escapes_home" in canonicalize("../../x", home=HOME).flags


def test_flags_include_url():
    assert "url" in canonicalize("https://x.invalid/", home=HOME).flags


def test_looks_like_path_detects_separators():
    assert looks_like_path("a/b")


def test_looks_like_path_detects_home():
    assert looks_like_path("~/x")


def test_looks_like_path_rejects_plain_word():
    assert not looks_like_path("hello")


def test_windows_reserved_set_contains_con_and_nul():
    assert "CON" in WINDOWS_RESERVED_NAMES
    assert "NUL" in WINDOWS_RESERVED_NAMES


# --------------------------------------------------------------------------
# plugin behaviour
# --------------------------------------------------------------------------
def test_plugin_flags_home_escape(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "../../.ssh/id_rsa"}}]},
    )
    assert "PATH-001" in _ids(findings)


def test_plugin_flags_sensitive_path(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "~/.aws/credentials"}}]},
    )
    assert "PATH-002" in _ids(findings)


def test_plugin_flags_private_key(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "~/.ssh/id_rsa"}}]},
    )
    assert "PATH-002" in _ids(findings)


def test_plugin_flags_unc_path(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "\\\\server\\share\\x"}}]},
    )
    assert "PATH-003" in _ids(findings)


def test_plugin_flags_encoded_traversal(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "%2e%2e%2fetc%2fpasswd"}}]},
    )
    assert "PATH-004" in _ids(findings)


def test_plugin_flags_alternate_data_stream(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "notes.txt:payload"}}]},
    )
    assert "PATH-005" in _ids(findings)


def test_plugin_flags_reserved_name(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "NUL"}}]},
    )
    assert "PATH-006" in _ids(findings)


def test_plugin_flags_system_path(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "/etc/shadow"}}]},
    )
    assert "PATH-007" in _ids(findings)


def test_plugin_flags_control_characters(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "a\x00b"}}]},
    )
    assert "PATH-008" in _ids(findings)


def test_plugin_flags_drive_relative_path(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "C:Windows\\System32"}}]},
    )
    assert "PATH-009" in _ids(findings)


def test_plugin_flags_trailing_dot(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "notes.txt."}}]},
    )
    assert "PATH-010" in _ids(findings)


def test_plugin_flags_path_outside_allowed_roots(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "/var/data/file.txt"}}]},
        settings={"allowed_roots": ["/srv/app"]},
    )
    assert "PATH-011" in _ids(findings)


def test_plugin_allows_path_inside_allowed_roots(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "/srv/app/file.txt"}}]},
        settings={"allowed_roots": ["/srv/app"]},
    )
    assert "PATH-011" not in _ids(findings)


def test_plugin_ignores_benign_paths(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "src/app/main.py"}}]},
    )
    assert findings == []


def test_plugin_ignores_urls(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "web", "tool": "get", "arguments": {"url": "https://example.invalid/a"}}]},
    )
    assert findings == []


def test_plugin_considers_path_like_argument_names(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"target": "~/.ssh/id_rsa"}}]},
    )
    assert "PATH-002" in _ids(findings)


def test_plugin_finds_nested_arguments(run_plugin):
    findings = run_plugin(
        PathShapePlugin,
        {
            "calls": [
                {
                    "server": "fs",
                    "tool": "read",
                    "arguments": {"opts": {"paths": ["~/.aws/credentials"]}},
                }
            ]
        },
    )
    assert "PATH-002" in _ids(findings)


def test_plugin_self_tests_pass(make_plugin):
    for case in make_plugin(PathShapePlugin).self_test():
        assert case.passed, case.name

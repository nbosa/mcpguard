"""Tests for the canary exfiltration detection plugin."""

from __future__ import annotations

from mcp_guard.plugins.canary_exfil import (
    CANARY_SHAPE_RE,
    CanaryExfilPlugin,
    normalize_token,
)


def _ids(findings):
    return {finding.rule_id for finding in findings}


def _call(arguments, tool="read_file", server="fs"):
    return {"calls": [{"server": server, "tool": tool, "arguments": arguments}]}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def test_normalize_token_removes_separators():
    assert normalize_token("CANARY-AB12-CD34") == "CANARYAB12CD34"


def test_normalize_token_is_case_insensitive():
    assert normalize_token("canary-ab12") == normalize_token("CANARY-AB12")


def test_normalize_token_of_empty_string():
    assert normalize_token("") == ""


def test_canary_shape_regex_matches():
    assert CANARY_SHAPE_RE.search("value CANARY-AB12-CD34 end")


def test_canary_shape_regex_ignores_plain_words():
    assert not CANARY_SHAPE_RE.search("CANARY without parts")


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------
def test_configured_canary_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "context=CANARY-AB12-CD34"}),
        settings={"tokens": ["CANARY-AB12-CD34"]},
    )
    assert "CANARY-001" in _ids(findings)


def test_configured_canary_is_detected_case_insensitively(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "context=canary-ab12-cd34"}),
        settings={"tokens": ["CANARY-AB12-CD34"]},
    )
    assert "CANARY-001" in _ids(findings)


def test_configured_canary_is_detected_through_normalisation(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "context=CANARY_AB12_CD34"}),
        settings={"tokens": ["CANARY-AB12-CD34"]},
    )
    assert "CANARY-001" in _ids(findings)


def test_unconfigured_canary_shape_is_detected(run_plugin):
    findings = run_plugin(CanaryExfilPlugin, _call({"body": "context=CANARY-ZZ99-QQ11"}))
    assert "CANARY-002" in _ids(findings)


def test_canary_in_egress_tool_is_critical(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "context=CANARY-AB12-CD34"}, tool="http_post"),
        settings={"tokens": ["CANARY-AB12-CD34"], "egress_tools": ["http_post"]},
    )
    assert "CANARY-008" in _ids(findings)


def test_canary_in_non_egress_tool_is_not_egress_rule(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "context=CANARY-AB12-CD34"}, tool="read_file"),
        settings={"tokens": ["CANARY-AB12-CD34"], "egress_tools": ["http_post"]},
    )
    assert "CANARY-008" not in _ids(findings)


def test_canary_returned_by_a_tool_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "CANARY-AB12-CD34"}]},
        settings={"tokens": ["CANARY-AB12-CD34"]},
    )
    assert "CANARY-010" in _ids(findings)


def test_credential_material_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"token": "AKIA" "IOSFODNN7EXAMPLE"})
    )
    assert "CANARY-003" in _ids(findings)


def test_private_key_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"key": "-----BEGIN " "RSA PRIVATE KEY-----\nabc\n"}),
    )
    assert "CANARY-003" in _ids(findings)


def test_github_token_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"t": "ghp_abcdefghijklmnopqrstuvwxyz0123"})
    )
    assert "CANARY-003" in _ids(findings)


def test_assigned_password_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"creds": "pass" "word=hunter2hunter2"})
    )
    assert "CANARY-003" in _ids(findings)


def test_jwt_is_detected(run_plugin):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    findings = run_plugin(CanaryExfilPlugin, _call({"t": jwt}))
    assert "CANARY-005" in _ids(findings)


def test_url_with_credentials_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"u": "https://user:hunter2@example.invalid/x"})
    )
    assert "CANARY-006" in _ids(findings)


def test_environment_dump_indicator_is_detected(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"cmd": "cat /proc/self/environ"})
    )
    assert "CANARY-007" in _ids(findings)


def test_high_entropy_blob_is_detected(run_plugin):
    blob = "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FybGFnaW5xdWlvcHFycw=="
    findings = run_plugin(CanaryExfilPlugin, _call({"blob": blob}))
    assert "CANARY-004" in _ids(findings)


def test_base64_blob_with_credentials_is_detected(run_plugin):
    import base64

    encoded = base64.b64encode(b"pass" b"word=hunter2hunter2").decode("ascii")
    findings = run_plugin(CanaryExfilPlugin, _call({"blob": encoded}))
    assert "CANARY-009" in _ids(findings)


def test_clean_payload_produces_no_findings(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, _call({"path": "docs/README.md", "n": 3})
    )
    assert findings == []


def test_transcript_is_scanned(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin, {"transcript": "leaking CANARY-ZZ99-QQ11 now"}
    )
    assert "CANARY-002" in _ids(findings)


def test_result_scanning_can_be_disabled(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        {"results": [{"server": "fs", "tool": "read", "content": "CANARY-ZZ99-QQ11"}]},
        settings={"scan_results": False},
    )
    assert findings == []


def test_block_on_match_can_be_disabled(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        _call({"body": "CANARY-AB12-CD34"}),
        settings={"tokens": ["CANARY-AB12-CD34"], "block_on_match": False},
    )
    critical = [f for f in findings if f.rule_id in ("CANARY-001", "CANARY-002")]
    assert critical and critical[0].severity.value == "HIGH"


def test_egress_tools_from_metadata_are_honoured(run_plugin):
    findings = run_plugin(
        CanaryExfilPlugin,
        {
            "calls": [{"server": "net", "tool": "post", "arguments": {"b": "CANARY-AB12-CD34"}}],
            "metadata": {"egress_tools": ["net.post"]},
        },
        settings={"tokens": ["CANARY-AB12-CD34"]},
    )
    assert "CANARY-008" in _ids(findings)


def test_plugin_self_tests_pass(make_plugin):
    for case in make_plugin(CanaryExfilPlugin).self_test():
        assert case.passed, case.name

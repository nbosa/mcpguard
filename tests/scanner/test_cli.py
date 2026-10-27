"""Tests for the unified command line interface."""

from __future__ import annotations

import io
import json

import pytest

from mcp_guard.cli.main import build_parser, main
from mcp_guard.cli.output import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from mcp_guard.core.manifest import build_pin_manifest
from mcp_guard.core.samples import SAMPLE_ETDI, SAMPLE_TRANSCRIPT


def _stdin(monkeypatch, payload: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def test_parser_exposes_every_command():
    parser = build_parser()
    actions = [a for a in parser._actions if a.dest == "command"]
    assert set(actions[0].choices) == {
        "proxy",
        "run",
        "verify-audit",
        "verify",
        "verify-log",
        "rotate-key",
        "keygen",
        "check",
        "policy-lint",
        "selftest",
        "pin-manifest",
        "sanitize-output",
        "canary-check",
    }


def test_parser_has_a_version_flag(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--version"])
    assert "mcp-guard" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_ERROR
    assert "usage" in capsys.readouterr().out.lower()


def test_pin_manifest_without_action_is_an_error(capsys):
    assert main(["pin-manifest"]) == EXIT_ERROR
    assert "requires an action" in capsys.readouterr().err


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------
def test_check_passes_on_a_clean_transcript(tmp_path, capsys):
    path = tmp_path / "clean.json"
    path.write_text(
        json.dumps(
            {
                "calls": [{"server": "fs", "tool": "read", "arguments": {"path": "README.md"}}],
                "results": [{"server": "fs", "tool": "read", "content": "hello"}],
            }
        ),
        encoding="utf-8",
    )
    assert main(["check", str(path)]) == EXIT_OK
    assert "PASS" in capsys.readouterr().out


def test_check_fails_on_a_dirty_transcript(tmp_path, capsys):
    path = tmp_path / "dirty.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    assert main(["check", str(path)]) == EXIT_FINDINGS
    assert "FAIL" in capsys.readouterr().out


def test_check_json_output_is_valid_json(tmp_path, capsys):
    path = tmp_path / "dirty.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    main(["check", str(path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["findings"]


def test_check_reads_stdin(monkeypatch, capsys):
    _stdin(monkeypatch, json.dumps(SAMPLE_TRANSCRIPT))
    assert main(["check"]) == EXIT_FINDINGS


def test_check_rejects_a_missing_file(tmp_path, capsys):
    assert main(["check", str(tmp_path / "nope.json")]) == EXIT_ERROR
    assert "cannot read transcript" in capsys.readouterr().err


def test_check_rejects_invalid_json(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["check", str(path)]) == EXIT_ERROR


def test_check_rejects_a_non_object_document(tmp_path, capsys):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert main(["check", str(path)]) == EXIT_ERROR


def test_check_quiet_prints_only_the_verdict(tmp_path, capsys):
    path = tmp_path / "dirty.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    main(["check", str(path), "--quiet"])
    assert capsys.readouterr().out.strip() == "FAIL"


def test_check_accepts_a_policy(tmp_path, capsys):
    policy = tmp_path / "policy.toml"
    policy.write_text(
        '[meta]\nname = "unit"\nversion = "1.0.0"\n[settings]\nfail_on = "CRITICAL"\n',
        encoding="utf-8",
    )
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    assert main(["check", str(path), "--policy", str(policy)]) == EXIT_FINDINGS


def test_check_rejects_a_broken_policy(tmp_path, capsys):
    policy = tmp_path / "policy.toml"
    policy.write_text("[meta]\nname = 1\n[settings]\nfail_on = 'NOPE'\n", encoding="utf-8")
    assert main(["check", "-", "--policy", str(policy)]) == EXIT_ERROR


def test_check_fail_on_override(tmp_path, capsys):
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    assert main(["check", str(path), "--fail-on", "CRITICAL"]) == EXIT_FINDINGS


def test_check_can_restrict_plugins(tmp_path, capsys):
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    main(["check", str(path), "--plugin", "path_shape", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert set(payload["summary"]["by_plugin"]) <= {"path_shape"}


def test_check_accepts_pins_and_etdi(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps(build_pin_manifest(SAMPLE_ETDI)), encoding="utf-8")
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    assert main(
        ["check", str(path), "--etdi", str(etdi), "--pins", str(pins)]
    ) == EXIT_FINDINGS


def test_check_reports_a_missing_pin_manifest(tmp_path, capsys):
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(SAMPLE_TRANSCRIPT), encoding="utf-8")
    assert main(["check", str(path), "--pins", str(tmp_path / "nope.json")]) == EXIT_ERROR


# --------------------------------------------------------------------------
# policy-lint
# --------------------------------------------------------------------------
def test_policy_lint_passes_on_the_built_in_policy(capsys):
    assert main(["policy-lint"]) == EXIT_OK
    assert "errors: 0" in capsys.readouterr().out


def test_policy_lint_reports_errors(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text('[meta]\nname = "x"\n[settings]\nfail_on = "NOPE"\n', encoding="utf-8")
    assert main(["policy-lint", str(path)]) == EXIT_FINDINGS
    assert "POL-004" in capsys.readouterr().out


def test_policy_lint_reports_unknown_plugins(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text(
        '[meta]\nname = "x"\n[[rule]]\nid = "X-001"\nplugin = "nope"\n', encoding="utf-8"
    )
    assert main(["policy-lint", str(path)]) == EXIT_FINDINGS
    assert "POL-007" in capsys.readouterr().out


def test_policy_lint_json_output(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text('[meta]\nname = "x"\n[settings]\nfail_on = "NOPE"\n', encoding="utf-8")
    main(["policy-lint", str(path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] >= 1
    assert payload["issues"]


def test_policy_lint_strict_turns_warnings_into_failures(tmp_path, capsys):
    path = tmp_path / "warn.toml"
    path.write_text(
        '[meta]\nname = "x"\n[settings]\nfail_on = "HIGH"\nbogus_key = 1\n', encoding="utf-8"
    )
    assert main(["policy-lint", str(path)]) == EXIT_OK
    assert main(["policy-lint", str(path), "--strict"]) == EXIT_FINDINGS


def test_policy_lint_rejects_a_missing_file(tmp_path, capsys):
    assert main(["policy-lint", str(tmp_path / "nope.toml")]) == EXIT_ERROR


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------
def test_selftest_passes(capsys):
    assert main(["selftest"]) == EXIT_OK
    assert "result: PASS" in capsys.readouterr().out


def test_selftest_json_output(capsys):
    main(["selftest", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["failed"] == 0


def test_selftest_verbose_shows_details(capsys):
    main(["selftest", "--verbose"])
    assert "plugin:path_shape" in capsys.readouterr().out


# --------------------------------------------------------------------------
# pin-manifest
# --------------------------------------------------------------------------
def test_pin_manifest_create_writes_a_file(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    assert main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)]) == EXIT_OK
    assert json.loads(out.read_text(encoding="utf-8"))["tools"]


def test_pin_manifest_create_prints_json(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    main(["pin-manifest", "create", "--input", str(etdi)])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["tools"]) == 2


def test_pin_manifest_create_rejects_invalid_documents(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text('{"etdi": "1.0"}', encoding="utf-8")
    assert main(["pin-manifest", "create", "--input", str(etdi)]) == EXIT_FINDINGS
    assert "ETDI-007" in capsys.readouterr().out


def test_pin_manifest_verify_accepts_matching_documents(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)])
    capsys.readouterr()
    assert main(
        ["pin-manifest", "verify", "--pins", str(out), "--input", str(etdi)]
    ) == EXIT_OK


def test_pin_manifest_verify_detects_drift(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)])
    changed = json.loads(etdi.read_text(encoding="utf-8"))
    changed["tools"][0]["description"] = "tampered"
    etdi.write_text(json.dumps(changed), encoding="utf-8")
    capsys.readouterr()
    assert main(
        ["pin-manifest", "verify", "--pins", str(out), "--input", str(etdi)]
    ) == EXIT_FINDINGS
    assert "drift" in capsys.readouterr().out


def test_pin_manifest_verify_json_output(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)])
    capsys.readouterr()
    main(
        [
            "pin-manifest",
            "verify",
            "--pins",
            str(out),
            "--input",
            str(etdi),
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True


def test_pin_manifest_show(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)])
    capsys.readouterr()
    assert main(["pin-manifest", "show", "--pins", str(out)]) == EXIT_OK
    assert "workspace.read_file" in capsys.readouterr().out


def test_pin_manifest_show_json(tmp_path, capsys):
    etdi = tmp_path / "etdi.json"
    etdi.write_text(json.dumps(SAMPLE_ETDI), encoding="utf-8")
    out = tmp_path / "pins.json"
    main(["pin-manifest", "create", "--input", str(etdi), "--output", str(out)])
    capsys.readouterr()
    main(["pin-manifest", "show", "--pins", str(out), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["tools"]


def test_pin_manifest_rejects_a_missing_manifest(tmp_path, capsys):
    assert main(["pin-manifest", "show", "--pins", str(tmp_path / "nope.json")]) == EXIT_ERROR


# --------------------------------------------------------------------------
# sanitize-output
# --------------------------------------------------------------------------
def test_sanitize_output_strips_escapes(monkeypatch, capsys):
    _stdin(monkeypatch, "before\x1b[31mred\x1b[0mafter")
    assert main(["sanitize-output"]) == EXIT_OK
    assert capsys.readouterr().out.strip() == "beforeredafter"


def test_sanitize_output_reads_a_file(tmp_path, capsys):
    path = tmp_path / "payload.txt"
    path.write_text("hello\x1b[31mworld", encoding="utf-8")
    main(["sanitize-output", str(path)])
    assert capsys.readouterr().out.strip() == "helloworld"


def test_sanitize_output_json_report(monkeypatch, capsys):
    _stdin(monkeypatch, "a\x1b[31mb")
    main(["sanitize-output", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["removed_sequences"] == 1
    assert payload["text"] == "ab"


def test_sanitize_output_keep_ansi(monkeypatch, capsys):
    _stdin(monkeypatch, "a\x1b[31mb")
    main(["sanitize-output", "--keep-ansi"])
    assert "\x1b[31m" in capsys.readouterr().out


def test_sanitize_output_max_chars(monkeypatch, capsys):
    _stdin(monkeypatch, "x" * 100)
    main(["sanitize-output", "--max-chars", "10"])
    assert len(capsys.readouterr().out.strip()) <= 10


def test_sanitize_output_fail_on_change(monkeypatch, capsys):
    _stdin(monkeypatch, "a\x1b[31mb")
    assert main(["sanitize-output", "--fail-on-change"]) == EXIT_FINDINGS


def test_sanitize_output_fail_on_change_is_quiet_for_clean_input(monkeypatch, capsys):
    _stdin(monkeypatch, "clean")
    assert main(["sanitize-output", "--fail-on-change"]) == EXIT_OK


# --------------------------------------------------------------------------
# canary-check
# --------------------------------------------------------------------------
def test_canary_check_detects_a_canary(monkeypatch, capsys):
    _stdin(monkeypatch, "leaking CANARY-AB12-CD34 now")
    assert main(["canary-check"]) == EXIT_FINDINGS
    assert "CANARY-002" in capsys.readouterr().out


def test_canary_check_passes_on_clean_input(monkeypatch, capsys):
    _stdin(monkeypatch, "nothing to see here")
    assert main(["canary-check"]) == EXIT_OK


def test_canary_check_uses_a_configured_token(monkeypatch, capsys):
    _stdin(monkeypatch, "the value is SECRET-XYZ")
    assert main(["canary-check", "--token", "SECRET-XYZ"]) == EXIT_FINDINGS
    assert "CANARY-001" in capsys.readouterr().out


def test_canary_check_json_output(monkeypatch, capsys):
    _stdin(monkeypatch, "CANARY-AB12-CD34")
    main(["canary-check", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["findings"]


def test_canary_check_reports_credentials(monkeypatch, capsys):
    _stdin(monkeypatch, "AKIA" "IOSFODNN7EXAMPLE")
    assert main(["canary-check"]) == EXIT_FINDINGS
    assert "CANARY-003" in capsys.readouterr().out


def test_canary_check_rejects_a_broken_policy(tmp_path, monkeypatch, capsys):
    policy = tmp_path / "policy.toml"
    policy.write_text("[meta]\nname = 'x'\n[settings]\nfail_on = 'NOPE'\n", encoding="utf-8")
    _stdin(monkeypatch, "text")
    assert main(["canary-check", "--policy", str(policy)]) == EXIT_ERROR

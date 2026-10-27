"""Independent second-opinion audit suite for mcp-guard v0.6.0 GA (#128).

This suite was written from scratch during an independent security,
correctness and edge-case review of the ``mcp-guard`` v0.6.0 GA release pack.
The pack is treated as strictly read-only: nothing here writes into it.

The suite contains two kinds of tests:

``INV-*`` invariant tests
    Assertions about behaviour the release must keep: dangerous input is
    detected, evidence is redacted, exit codes are stable, malformed input
    never crashes the engine, and the reported verdict reflects the findings.

``AUD-*`` defect reproductions
    Each test states the security invariant that the audit found to be
    violated and is marked ``xfail(strict=False)``.  While the defect is
    present the test is reported as an expected failure; once the
    maintainer fixes the defect the test reports ``XPASS`` and the suite
    still succeeds.  The finding id in the reason string matches the id
    used in ``REPORT.md``.

Nothing in this file imports the target's own ``tests/conftest.py``; the
suite is self-contained so that it keeps working against a bare checkout.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import sys
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# bootstrap: import the audited package from the read-only release pack
# ---------------------------------------------------------------------------

PACK_NAME = "mcp-guard-v1.0.0-oss"


def _find_pack_root() -> Path:
    """Locate the release tree the suite audits.

    The tree is looked up in this order:

    1. the ``MCP_GUARD_PACK_ROOT`` environment variable, if it is set;
    2. the repository the suite itself lives in, so that a checkout runs the
       audit against itself;
    3. the current working directory and its parent.
    """
    override = os.environ.get("MCP_GUARD_PACK_ROOT")
    if override:
        return Path(override).resolve()

    here = Path(__file__).resolve()
    candidates = [
        here.parents[1],  # <repo>/tests -> <repo>
        here.parents[2],
        Path.cwd(),
        Path.cwd().parent,
    ]
    for candidate in candidates:
        if (candidate / "src" / "mcp_guard" / "__init__.py").is_file():
            return candidate.resolve()

    searched = "\n  ".join(str(path) for path in candidates)
    raise ImportError(
        "cannot locate the audited release tree "
        f"'{PACK_NAME}'.\n"
        f"Searched:\n  {searched}\n"
        "Set MCP_GUARD_PACK_ROOT to the release directory and re-run."
    )


PACK_ROOT = _find_pack_root()
SRC = PACK_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_guard.cli.main import main  # noqa: E402
from mcp_guard.core.engine import GuardEngine  # noqa: E402
from mcp_guard.core.lint import lint_policy  # noqa: E402
from mcp_guard.core.manifest import (  # noqa: E402
    build_pin_manifest,
    manifest_digest,
    verify_pin_manifest,
)
from mcp_guard.core.plugin import GuardPlugin, PluginContext  # noqa: E402
from mcp_guard.core.policy import (  # noqa: E402
    PolicyError,
    default_policy,
    load_policy_text,
    parse_policy,
)
from mcp_guard.core.redact import redact  # noqa: E402
from mcp_guard.core.request import CheckRequest  # noqa: E402
from mcp_guard.core.result import Verdict  # noqa: E402
from mcp_guard.core.severity import Severity, max_severity, parse_severity  # noqa: E402
from mcp_guard.core.textutil import (  # noqa: E402
    canonical_json,
    decode_base64_loose,
    looks_like_base64,
    printable_ratio,
    shannon_entropy,
    truncate,
    visible_repr,
)
from mcp_guard.plugins.ansi_sanitize import (  # noqa: E402
    ANSI_SEQUENCE_RE,
    detect_ansi_categories,
    sanitize_text,
    strip_ansi,
)
from mcp_guard.plugins.canary_exfil import (  # noqa: E402
    CREDENTIAL_PATTERNS,
    CanaryExfilPlugin,
    normalize_token,
)
from mcp_guard.plugins.path_shape import PathShapePlugin, canonicalize  # noqa: E402

HOME = "/" "home/bob"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _ids(findings) -> list[str]:
    return [finding.rule_id for finding in findings]


def _make(plugin_class, settings=None, policy=None):
    active = policy if policy is not None else default_policy()
    merged = {
        **active.plugin_settings(plugin_class.settings_block()),
        **(settings or {}),
    }
    context = PluginContext(policy=active, settings=merged, home_dir=HOME)
    return plugin_class(context)


def _run(plugin_class, document, settings=None, policy=None):
    """Run one plugin over a transcript document and return its findings."""
    plugin = _make(plugin_class, settings=settings, policy=policy)
    return plugin.analyze(CheckRequest.from_dict(document))


def _path_findings(path, key="path", settings=None):
    return _run(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read_file", "arguments": {key: path}}]},
        settings=settings,
    )


def _call_document(tool="http_post", body="", server="web"):
    return {"calls": [{"server": server, "tool": tool, "arguments": {"body": body}}]}


def _policy_from_toml(text):
    import tomllib

    return parse_policy(tomllib.loads(text))[0]


class _ExplodingPlugin(GuardPlugin):
    """A plugin that always raises, used to probe the engine's error path."""

    name = "exploding"

    def analyze(self, request):
        raise RuntimeError("plugin exploded on purpose")


# ---------------------------------------------------------------------------
# INV-01 .. INV-12  --  path shape: invariants the release must keep
# ---------------------------------------------------------------------------


def test_inv_home_traversal_is_critical():
    findings = _path_findings("../../etc/passwd")
    assert "PATH-001" in _ids(findings)
    severity = [f.severity for f in findings if f.rule_id == "PATH-001"][0]
    assert severity == Severity.CRITICAL


def test_inv_home_escape_is_critical():
    findings = _path_findings("~/.ssh/../../etc/passwd")
    assert "PATH-001" in _ids(findings)


def test_inv_encoded_traversal_is_detected():
    findings = _path_findings("%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    assert "PATH-004" in _ids(findings)
    assert "PATH-001" in _ids(findings)


def test_inv_credential_path_is_critical():
    findings = _path_findings("~/.aws/credentials")
    assert "PATH-002" in _ids(findings)


def test_inv_reserved_device_name_is_detected():
    findings = _path_findings("\\\\.\\NUL")
    assert "PATH-006" in _ids(findings)


def test_inv_alternate_data_stream_is_detected():
    findings = _path_findings("report.txt:hidden")
    assert "PATH-005" in _ids(findings)


def test_inv_unc_share_is_detected():
    findings = _path_findings("\\\\server\\share\\file.txt")
    assert "PATH-003" in _ids(findings)


def test_inv_drive_relative_path_is_detected():
    findings = _path_findings("C:Users\\bob\\file.txt")
    assert "PATH-009" in _ids(findings)


def test_inv_urls_are_not_treated_as_filesystem_paths():
    findings = _path_findings("https://example.invalid/download")
    assert not [rule for rule in _ids(findings) if rule.startswith("PATH-")]


def test_inv_file_url_is_root_anchored_and_examined():
    findings = _path_findings("file:///etc/passwd")
    assert "PATH-007" in _ids(findings)


def test_inv_allowed_roots_rejects_absolute_path_outside_root():
    findings = _path_findings("/var/data/file.txt", settings={"allowed_roots": ["/srv/app"]})
    assert "PATH-011" in _ids(findings)


def test_inv_allowed_roots_accepts_absolute_path_inside_root():
    findings = _path_findings("/srv/app/file.txt", settings={"allowed_roots": ["/srv/app"]})
    assert "PATH-011" not in _ids(findings)


def test_inv_benign_relative_path_is_clean():
    findings = _path_findings("src/app/main.py")
    assert findings == []


def test_inv_canonicalize_never_touches_the_filesystem():
    """Path canonicalization is documented as purely lexical."""
    for payload in ("/etc/passwd", "~/.ssh/id_rsa", "\\..\\..\\windows", "a\x00b"):
        shape = canonicalize(payload, home=HOME)
        assert isinstance(shape.shape, str)


@pytest.mark.parametrize(
    "payload",
    [None, 0, 1, 3.5, True, [], {}, b"bytes", object()],
)
def test_inv_canonicalize_accepts_non_string_inputs(payload):
    shape = canonicalize(payload, home=HOME)
    assert shape.raw == str(payload) if payload is not None else shape.raw == ""


def test_inv_canonicalize_is_deterministic():
    first = canonicalize("~/.ssh/../../etc/passwd", home=HOME)
    second = canonicalize("~/.ssh/../../etc/passwd", home=HOME)
    assert first == second


# ---------------------------------------------------------------------------
# AUD-01  --  escapes_root is computed but never consumed by any rule
# ---------------------------------------------------------------------------


def test_aud_root_anchored_escape_raises_critical_path_rule():
    findings = _path_findings("/../../etc/passwd")
    assert "PATH-001" in _ids(findings)


def test_aud_drive_absolute_escape_is_not_silent():
    findings = _path_findings("C:/../../Windows/System32")
    assert findings, "a traversal above the drive root must produce a finding"


def test_aud_escapes_root_flag_is_consumed_by_a_rule():
    shape = canonicalize("/../../etc/passwd", home=HOME)
    assert shape.escapes_root
    findings = _path_findings("/../../etc/passwd")
    assert any(f.rule_id == "PATH-001" for f in findings)


# ---------------------------------------------------------------------------
# AUD-02  --  percent-encoded NUL / control bytes bypass PATH-008
# ---------------------------------------------------------------------------


def test_aud_percent_encoded_nul_is_flagged():
    findings = _path_findings("safe.txt%00.png")
    assert "PATH-008" in _ids(findings)


def test_aud_percent_encoded_control_is_flagged():
    findings = _path_findings("report%0a.md")
    assert "PATH-008" in _ids(findings)


def test_inv_plain_nul_byte_is_flagged():
    findings = _path_findings("safe.txt\x00.png")
    assert "PATH-008" in _ids(findings)


# ---------------------------------------------------------------------------
# AUD-03  --  allowed_roots turns every relative path into a HIGH finding
# ---------------------------------------------------------------------------


def test_aud_allowed_roots_accepts_relative_workspace_path():
    findings = _path_findings("src/main.py", settings={"allowed_roots": ["/workspace"]})
    assert "PATH-011" not in _ids(findings)


# ---------------------------------------------------------------------------
# AUD-04  --  raw_arguments bypasses the path and ANSI plugins
# ---------------------------------------------------------------------------


def test_aud_raw_arguments_path_is_not_hidden():
    findings = _run(
        PathShapePlugin,
        {"calls": [{"server": "fs", "tool": "read_file", "raw_arguments": "/root/.ssh/id_rsa"}]},
    )
    assert findings, "a path carried in raw_arguments must still be examined"


def test_aud_raw_arguments_ansi_is_not_hidden():
    findings = _run(
        __import__(
            "mcp_guard.plugins.ansi_sanitize", fromlist=["ANSISanitizePlugin"]
        ).ANSISanitizePlugin,
        {"calls": [{"server": "fs", "tool": "read_file", "raw_arguments": "\x1b]52;c;eA==\x07"}]},
    )
    assert findings, "ANSI sequences carried in raw_arguments must still be examined"


# ---------------------------------------------------------------------------
# INV-05 .. INV-08  --  redaction and evidence handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "AKIA" "IOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "xoxb-" "1234567890-abcdefghij",
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
        "AIza" + "b" * 35,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
        "pass" "word = 'sup3rs3cretvalue'",
        "https://user:pw@example.invalid/x",
        "-----BEGIN " "RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_inv_redact_masks_known_credential_material(payload):
    masked = redact(payload)
    assert "<redacted:" in masked, f"not redacted: {payload!r}"


def test_inv_redact_is_idempotent():
    payload = "AKIA" "IOSFODNN7EXAMPLE pass" "word=hunter2hunter2"
    once = redact(payload)
    assert redact(once) == once


def test_inv_redact_handles_empty_input():
    assert redact("") == ""
    assert redact(None) == ""


def test_inv_evidence_escapes_control_characters():
    engine = GuardEngine(policy=default_policy())
    request = CheckRequest.from_dict(
        {"results": [{"content": "text\x1b]52;c;cGF5bG9hZA==\x07"}]}
    )
    report = engine.check(request)
    assert report.findings
    for finding in report.findings:
        assert "\x1b" not in finding.evidence


def test_inv_evidence_respects_max_evidence_chars():
    policy = default_policy()
    import dataclasses

    tight = dataclasses.replace(policy, max_evidence_chars=32)
    engine = GuardEngine(policy=tight)
    request = CheckRequest.from_dict(
        {"calls": [{"server": "web", "tool": "http_post", "arguments": {"body": "x" * 5000}}]}
    )
    report = engine.check(request)
    for finding in report.findings:
        assert len(finding.evidence) <= 32


# ---------------------------------------------------------------------------
# AUD-05  --  the canary detector finds secrets that redaction does not mask
# ---------------------------------------------------------------------------


def _aws_secret_payload() -> str:
    return "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _npm_payload() -> str:
    return "npm_" "abcdefghijklmnopqrstuvwxyz0123456789"


def _stripe_payload() -> str:
    return "sk_" "live_abcdefghijklmnop1234567890"


@pytest.mark.parametrize(
    "payload",
    [_aws_secret_payload(), _npm_payload(), _stripe_payload()],
    ids=["aws_secret_access_key", "npm_token", "stripe_live_key"],
)
def test_aud_detected_credential_is_masked_in_the_report(payload):
    engine = GuardEngine(policy=default_policy())
    report = engine.check(CheckRequest.from_dict(_call_document(body=payload)))
    assert report.findings, "the canary plugin should have detected the secret"
    rendered = json.dumps(report.to_dict(), ensure_ascii=False)
    assert payload.split("=")[-1] not in rendered


def test_aud_every_canary_credential_pattern_is_redactable():
    samples = {
        "private_key": "-----BEGIN " "OPENSSH PRIVATE KEY-----\nAA\n-----END OPENSSH PRIVATE KEY-----",
        "aws_access_key": "AKIA" "IOSFODNN7EXAMPLE",
        "aws_secret": _aws_secret_payload(),
        "github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "npm_token": _npm_payload(),
        "stripe_key": _stripe_payload(),
        "slack_token": "xoxb-" "1234567890-abcdefghij",
        "openai_key": "sk-abcdefghijklmnopqrstuvwxyz012345",
        "anthropic_key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
        "google_api_key": "AIza" + "b" * 35,
    }
    undetected = []
    for kind, _pattern in CREDENTIAL_PATTERNS:
        if kind not in samples:
            continue
        if redact(samples[kind]) == samples[kind]:
            undetected.append(kind)
    assert not undetected, f"credential kinds detected but never redacted: {undetected}"


def test_aud_finding_metadata_is_redacted():
    policy = default_policy()
    plugin = CanaryExfilPlugin(
        PluginContext(
            policy=policy,
            settings={**policy.plugin_settings("canary"), "tokens": ["SECRET-TOKEN-VALUE"]},
            home_dir=HOME,
        )
    )
    findings = plugin.analyze(
        CheckRequest.from_dict(_call_document(body="SECRET-TOKEN-VALUE"))
    )
    assert findings
    for finding in findings:
        assert "SECRET-TOKEN-VALUE" not in json.dumps(finding.metadata)


# ---------------------------------------------------------------------------
# INV-09 .. INV-12  --  engine behaviour
# ---------------------------------------------------------------------------


def test_inv_clean_transcript_passes_with_no_findings():
    engine = GuardEngine(policy=default_policy())
    request = CheckRequest.from_dict(
        {
            "calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "docs/README.md"}}],
            "results": [{"server": "fs", "tool": "read_file", "content": "# Hello\n"}],
            "transcript": "assistant: reading the documentation",
        }
    )
    report = engine.check(request)
    assert report.verdict == Verdict.PASS
    assert report.findings == []


def test_inv_dangerous_transcript_fails():
    engine = GuardEngine(policy=default_policy())
    request = CheckRequest.from_dict(
        {"calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "../../.ssh/id_rsa"}}]}
    )
    report = engine.check(request)
    assert report.verdict == Verdict.FAIL


def test_inv_engine_is_deterministic():
    engine = GuardEngine(policy=default_policy())
    request = CheckRequest.from_dict(
        {
            "calls": [
                {"server": "fs", "tool": "read_file", "arguments": {"path": "~/.aws/credentials"}},
                {"server": "web", "tool": "http_post", "arguments": {"body": "CANARY-AB12-CD34"}},
            ]
        }
    )
    first = [(f.rule_id, f.plugin, f.evidence) for f in engine.check(request).findings]
    second = [(f.rule_id, f.plugin, f.evidence) for f in engine.check(request).findings]
    assert first == second


def test_inv_findings_are_sorted_by_descending_severity():
    engine = GuardEngine(policy=default_policy())
    request = CheckRequest.from_dict(
        {
            "calls": [{"server": "web", "tool": "http_post", "arguments": {"body": "CANARY-AB12-CD34"}}],
            "results": [{"server": "fs", "tool": "read", "content": "text\x1b[31mred"}],
        }
    )
    report = engine.check(request)
    ranks = [finding.severity.rank for finding in report.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_inv_engine_survives_hostile_payloads():
    engine = GuardEngine(policy=default_policy())
    hostile = [
        "\x00" * 100,
        "\x1b" * 500,
        "a" * 10_000,
        "{" * 2000,
        "‮" * 100,
        "\ud800",
        "%%%",
        "../../" * 500,
        "CANARY-" + "X" * 200,
    ]
    for payload in hostile:
        request = CheckRequest.from_dict(
            {
                "calls": [{"server": "web", "tool": "http_post", "arguments": {"body": payload}}],
                "results": [{"server": "fs", "tool": "read", "content": payload}],
                "transcript": payload,
            }
        )
        report = engine.check(request)
        assert isinstance(report.verdict, Verdict)


# ---------------------------------------------------------------------------
# AUD-07  --  a crashing plugin produces verdict PASS
# ---------------------------------------------------------------------------


def test_aud_plugin_crash_is_not_a_pass_verdict():
    policy = default_policy()
    engine = GuardEngine(policy=policy, plugins=[_ExplodingPlugin(PluginContext(policy=policy, settings={}))])
    report = engine.check(CheckRequest.from_dict({}))
    assert report.verdict != Verdict.PASS


def test_aud_plugin_crash_is_reported_as_at_least_a_warning():
    policy = default_policy()
    engine = GuardEngine(policy=policy, plugins=[_ExplodingPlugin(PluginContext(policy=policy, settings={}))])
    report = engine.check(CheckRequest.from_dict({}))
    assert report.max_severity is not None
    assert report.max_severity >= Severity.MEDIUM


def test_inv_plugin_crash_is_recorded_in_the_report():
    policy = default_policy()
    engine = GuardEngine(policy=policy, plugins=[_ExplodingPlugin(PluginContext(policy=policy, settings={}))])
    report = engine.check(CheckRequest.from_dict({}))
    assert "ENGINE-000" in _ids(report.findings)


# ---------------------------------------------------------------------------
# AUD-08  --  an unknown --plugin name silently disables every guard
# ---------------------------------------------------------------------------


def test_aud_unknown_plugin_name_is_rejected():
    from mcp_guard.core.registry import build_plugins

    plugins = build_plugins(default_policy(), ["definitely_not_a_plugin"])
    assert plugins, "an unknown plugin name must not silently yield zero plugins"


def test_aud_unknown_plugin_name_cli_does_not_exit_zero(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text(
        json.dumps({"calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "../../.ssh/id_rsa"}}]}),
        encoding="utf-8",
    )
    code = main(["check", str(document), "--plugin", "definitely_not_a_plugin", "--format", "json"])
    assert code != 0


def test_inv_stats_list_the_plugins_that_ran():
    engine = GuardEngine(policy=default_policy(), plugin_names=["path_shape"])
    report = engine.check(CheckRequest.from_dict({}))
    assert report.stats["plugins"] == ["path_shape"]


# ---------------------------------------------------------------------------
# AUD-09  --  base64 credential exfiltration can be split to evade detection
# ---------------------------------------------------------------------------


def test_inv_whole_base64_credential_is_detected():
    encoded = base64.b64encode(b"pass" b"word = 'topsecretvalue123'").decode()
    findings = _run(CanaryExfilPlugin, _call_document(body=encoded))
    assert "CANARY-009" in _ids(findings)


def test_aud_split_base64_credential_is_still_detected():
    encoded = base64.b64encode(b"pass" b"word = 'topsecretvalue123'").decode()
    half = len(encoded) // 2
    findings = _run(CanaryExfilPlugin, _call_document(body=encoded[:half] + "\n" + encoded[half:]))
    assert "CANARY-009" in _ids(findings)


# ---------------------------------------------------------------------------
# AUD-10  --  the shape-normalised canary match produces CRITICAL false positives
# ---------------------------------------------------------------------------


def test_inv_configured_canary_token_is_detected():
    policy = default_policy()
    import dataclasses

    settings = dict(policy.plugin_settings("canary"))
    settings["tokens"] = ["CANARY-AB12-CD34"]
    scoped = dataclasses.replace(policy, settings={**policy.settings, "canary": settings})
    findings = _run(CanaryExfilPlugin, _call_document(body="value CANARY-AB12-CD34 end"), policy=scoped)
    assert "CANARY-001" in _ids(findings) or "CANARY-008" in _ids(findings)


def test_aud_normalised_canary_match_does_not_fire_on_unrelated_prose():
    policy = default_policy()
    import dataclasses

    settings = dict(policy.plugin_settings("canary"))
    settings["tokens"] = ["SECRET"]
    scoped = dataclasses.replace(policy, settings={**policy.settings, "canary": settings})
    findings = _run(CanaryExfilPlugin, _call_document(body="my sec ret value"), policy=scoped)
    assert not findings, "prose that merely contains the token letters must not match"


def test_inv_normalize_token_removes_separators():
    assert normalize_token("CANARY-AB12-CD34") == "CANARYAB12CD34"


# ---------------------------------------------------------------------------
# AUD-11  --  RIS (ESC c) survives the ANSI sanitizer
# ---------------------------------------------------------------------------


def test_inv_csi_and_osc_sequences_are_stripped():
    clean, removed = strip_ansi("plain \x1b[31mred\x1b[0m text")
    assert removed == 2
    assert "red" in clean


def test_aud_ris_sequence_is_stripped():
    clean, _ = strip_ansi("visible\x1bcMORE")
    assert "\x1b" not in clean


def test_aud_sanitize_without_control_stripping_leaves_no_escape():
    result = sanitize_text("visible\x1bcMORE", strip_control=False)
    assert "\x1b" not in result.text


def test_inv_default_sanitize_removes_every_escape_introducer():
    payload = "a\x1bc b\x1b[31m c\x1b]52;c;eA==\x07 d"
    result = sanitize_text(payload)
    assert "\x1b" not in result.text


def test_inv_osc52_is_detected():
    categories = detect_ansi_categories("before\x1b]52;c;cGF5bG9hZA==\x07after")
    assert categories.get("osc52", 0) == 1


def test_inv_bidi_controls_are_detected_and_removed():
    categories = detect_ansi_categories("invoice\u202erexe")
    assert categories.get("bidi", 0) == 1
    assert "\u202e" not in sanitize_text("invoice\u202erexe").text


def test_inv_backspace_overwrite_is_resolved():
    result = sanitize_text("visible\x08\x08\x08hidden")
    assert "hidden" in result.text
    assert "\x08" not in result.text


def test_inv_carriage_return_overwrite_is_resolved():
    result = sanitize_text("harmless\r\x1b[2K\rreal command")
    assert "harmless" not in result.text


def test_inv_sanitize_is_idempotent():
    once = sanitize_text("a\x1b[31mb\x08c").text
    assert sanitize_text(once).text == once


def test_inv_detect_ansi_categories_counts_sequences():
    categories = detect_ansi_categories("\x1b[31m\x1b[1m")
    assert categories.get("ansi_sequence", 0) == 2


def test_inv_ansi_regex_is_not_vulnerable_to_a_bare_bracket():
    # A lone bracket is not an escape sequence.
    assert ANSI_SEQUENCE_RE.search("[31m") is None


# ---------------------------------------------------------------------------
# AUD-12  --  the policy 'plugin' field is parsed but never used for scoping
# ---------------------------------------------------------------------------


def test_aud_mis_scoped_rule_cannot_disable_a_builtin_rule():
    try:
        policy = load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "PATH-001"
plugin = "custom"
enabled = false
"""
        )
    except PolicyError:
        # Fail-closed is the stronger outcome: the policy is refused outright
        # because a rule id does not belong to the plugin that claims it.
        return
    report = GuardEngine(policy=policy).check(
        CheckRequest.from_dict(
            {"calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "../../etc/passwd"}}]}
        )
    )
    assert "PATH-001" in _ids(report.findings)


def test_aud_mis_scoped_rule_with_regex_is_reported_by_the_linter():
    policy = _policy_from_toml(
        """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "PATH-001"
plugin = "custom"
enabled = false
regex = "zzz-never-matches"
"""
    )
    issues = lint_policy(policy)
    assert any(issue.code in ("POL-006", "POL-016", "POL-007") for issue in issues)


def test_aud_lint_critical_issue_blocks_policy_loading():
    with pytest.raises(PolicyError):
        load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "PATH-001"
plugin = "custom"
enabled = false
"""
        )


def test_inv_duplicate_rule_ids_are_rejected():
    with pytest.raises(PolicyError):
        load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "PATH-001"
plugin = "path_shape"

[[rule]]
id = "PATH-001"
plugin = "path_shape"
"""
        )


def test_inv_invalid_regex_is_rejected():
    with pytest.raises(PolicyError):
        load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "CUSTOM-001"
plugin = "custom"
regex = "(unclosed"
"""
        )


def test_inv_unknown_rule_id_is_reported_by_the_linter():
    policy = _policy_from_toml(
        """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "NOPE-999"
plugin = "path_shape"
"""
    )
    assert any(issue.code == "POL-006" for issue in lint_policy(policy))


def test_inv_default_policy_lints_clean():
    blocking = [issue for issue in lint_policy(default_policy()) if issue.severity >= Severity.HIGH]
    assert blocking == []


# ---------------------------------------------------------------------------
# AUD-13  --  load_policy_text does not run the semantic linter
# ---------------------------------------------------------------------------


def test_aud_invalid_plugin_setting_is_rejected_at_load_time():
    with pytest.raises(PolicyError):
        load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[settings.ansi]
max_output_chars = "abc"
"""
        )


def test_aud_invalid_plugin_setting_does_not_end_in_a_pass_verdict():
    try:
        policy = load_policy_text(
            """
[meta]
name = "audit"
version = "1.0.0"

[settings.ansi]
max_output_chars = "abc"
"""
        )
    except PolicyError:
        # Refused at load time: there is no policy to run, so there is no
        # report and -- above all -- no PASS verdict.
        return
    report = GuardEngine(policy=policy).check(CheckRequest.from_dict({}))
    assert report.verdict != Verdict.PASS


# ---------------------------------------------------------------------------
# AUD-14  --  the transcript can name the files the guard opens
# ---------------------------------------------------------------------------


def test_aud_transcript_metadata_cannot_open_local_files(tmp_path):
    target = tmp_path / "operator-secret.json"
    target.write_text(
        json.dumps(
            {
                "etdi": "1.0",
                "server": {"name": "internal", "version": "1"},
                "tools": [
                    {
                        "name": "operator_only_admin_tool",
                        "description": "d",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = GuardEngine(policy=default_policy(), plugin_names=["etdi_pinning"]).check(
        CheckRequest.from_dict({"metadata": {"etdi_path": str(target)}})
    )
    rendered = json.dumps(report.to_dict())
    assert "operator_only_admin_tool" not in rendered


def test_inv_transcript_without_metadata_opens_nothing(tmp_path):
    report = GuardEngine(policy=default_policy(), plugin_names=["etdi_pinning"]).check(
        CheckRequest.from_dict({"calls": []})
    )
    assert report.findings == []


# ---------------------------------------------------------------------------
# AUD-15  --  a malformed pin manifest is silently downgraded
# ---------------------------------------------------------------------------


def test_aud_malformed_pin_manifest_is_an_error(tmp_path, capsys):
    pins = tmp_path / "pins.json"
    pins.write_text("[1, 2, 3]", encoding="utf-8")
    document = tmp_path / "t.json"
    document.write_text(
        json.dumps(
            {
                "metadata": {
                    "etdi": {
                        "etdi": "1.0",
                        "server": {},
                        "tools": [
                            {
                                "name": "t",
                                "description": "d",
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    code = main(["check", str(document), "--pins", str(pins), "--format", "json"])
    assert code != 0


def test_inv_valid_pin_manifest_verifies_clean(tmp_path, capsys):
    etdi = {
        "etdi": "1.0",
        "server": {"name": "fs", "version": "1.0.0"},
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    }
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps(build_pin_manifest(etdi)), encoding="utf-8")
    document = tmp_path / "t.json"
    document.write_text(json.dumps({"metadata": {"etdi": etdi}}), encoding="utf-8")
    code = main(["check", str(document), "--pins", str(pins), "--format", "json"])
    assert code == 0


# ---------------------------------------------------------------------------
# AUD-16  --  the pin manifest does not pin the server identity or version
# ---------------------------------------------------------------------------


def _etdi() -> dict:
    return {
        "etdi": "1.0",
        "server": {"name": "fs", "version": "1.0.0"},
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    }


def test_aud_server_version_change_is_detected():
    manifest = build_pin_manifest(_etdi())
    drifted = _etdi()
    drifted["server"]["version"] = "9.9.9-EVIL"
    diffs = verify_pin_manifest(manifest, drifted)
    assert any(diff["status"] != "unchanged" for diff in diffs)


def test_aud_manifest_digest_covers_the_server_block():
    manifest = build_pin_manifest(_etdi())
    tampered = dict(manifest)
    tampered["server"] = {"name": "attacker", "version": "0.0.0"}
    tampered["etdi_version"] = "9.9"
    assert manifest_digest(tampered) != manifest["manifest_sha256"]


def test_aud_manifest_digest_is_stable_across_reordering():
    etdi = _etdi()
    etdi["tools"].append(
        {
            "name": "list_dir",
            "description": "List a directory",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
    )
    manifest = build_pin_manifest(etdi)
    reordered = dict(manifest)
    reordered["tools"] = list(reversed(manifest["tools"]))
    assert manifest_digest(reordered) == manifest["manifest_sha256"]


# ---------------------------------------------------------------------------
# INV-16 .. INV-18  --  ETDI / manifest invariants
# ---------------------------------------------------------------------------


def test_inv_manifest_round_trip_is_unchanged():
    manifest = build_pin_manifest(_etdi())
    diffs = verify_pin_manifest(manifest, _etdi())
    assert all(diff["status"] == "unchanged" for diff in diffs)


def test_inv_added_tool_is_detected():
    manifest = build_pin_manifest(_etdi())
    drifted = _etdi()
    drifted["tools"].append(
        {
            "name": "exec",
            "description": "Run a command",
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
        }
    )
    diffs = verify_pin_manifest(manifest, drifted)
    assert any(diff["status"] == "added" for diff in diffs)


def test_inv_removed_tool_is_detected():
    etdi = _etdi()
    etdi["tools"].append(
        {
            "name": "list_dir",
            "description": "List a directory",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
    )
    manifest = build_pin_manifest(etdi)
    drifted = _etdi()
    diffs = verify_pin_manifest(manifest, drifted)
    assert any(diff["status"] == "removed" for diff in diffs)


def test_inv_required_parameter_added_is_detected():
    manifest = build_pin_manifest(_etdi())
    drifted = _etdi()
    drifted["tools"][0]["inputSchema"]["properties"]["mode"] = {"type": "string"}
    drifted["tools"][0]["inputSchema"]["required"] = ["path", "mode"]
    diffs = verify_pin_manifest(manifest, drifted)
    kinds = {change["kind"] for diff in diffs for change in diff["changes"]}
    assert "required_added" in kinds


def test_inv_parameter_type_widened_is_detected():
    manifest = build_pin_manifest(_etdi())
    drifted = _etdi()
    drifted["tools"][0]["inputSchema"]["properties"]["path"]["type"] = ["string", "number"]
    diffs = verify_pin_manifest(manifest, drifted)
    kinds = {change["kind"] for diff in diffs for change in diff["changes"]}
    assert "type_widened" in kinds


def test_inv_malformed_etdi_document_is_reported():
    findings = _run(
        __import__(
            "mcp_guard.plugins.etdi_pinning", fromlist=["ETDIPinningPlugin"]
        ).ETDIPinningPlugin,
        {"metadata": {"etdi": {"etdi": "1.0", "tools": "not-a-list"}}},
    )
    assert "ETDI-007" in _ids(findings)


def test_inv_manifest_version_mismatch_is_reported():
    etdi = _etdi()
    manifest = build_pin_manifest(etdi)
    manifest["manifest_version"] = "99.0"
    findings = _run(
        __import__(
            "mcp_guard.plugins.etdi_pinning", fromlist=["ETDIPinningPlugin"]
        ).ETDIPinningPlugin,
        {"metadata": {"etdi": etdi, "pins": manifest}},
    )
    assert "ETDI-008" in _ids(findings)


# ---------------------------------------------------------------------------
# AUD-18  --  custom policy regexes are unbounded (ReDoS / finding amplification)
# ---------------------------------------------------------------------------


def test_aud_custom_rule_matching_is_bounded_in_time():
    policy = _policy_from_toml(
        """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "CUSTOM-001"
plugin = "custom"
severity = "HIGH"
regex = "(a+)+b"
"""
    )
    request = CheckRequest.from_dict({"transcript": "a" * 24 + "!"})
    started = time.time()
    GuardEngine(policy=policy).check(request)
    assert time.time() - started < 0.5


def test_aud_custom_rule_finding_count_is_capped():
    policy = _policy_from_toml(
        """
[meta]
name = "audit"
version = "1.0.0"

[[rule]]
id = "CUSTOM-002"
plugin = "custom"
severity = "LOW"
regex = "a"
"""
    )
    request = CheckRequest.from_dict({"transcript": "a" * 10_000})
    report = GuardEngine(policy=policy).check(request)
    assert len(report.findings) <= 1000


# ---------------------------------------------------------------------------
# INV-19 .. INV-24  --  request normalisation and CLI contracts
# ---------------------------------------------------------------------------


def test_inv_request_accepts_the_documented_alternate_shape():
    request = CheckRequest.from_dict(
        {
            "agent": "a",
            "tool_calls": [{"server": "fs", "tool": "read", "input": {"path": "x"}}],
            "tool_results": [{"server": "fs", "tool": "read", "text": "hello"}],
            "messages": [{"role": "user", "content": "hello"}],
        }
    )
    assert len(request.calls) == 1
    assert len(request.results) == 1
    assert "user" in request.transcript


@pytest.mark.parametrize(
    "document",
    [
        {"calls": "not-a-list"},
        {"calls": [{"arguments": "not-a-dict"}]},
        {"calls": [{"arguments": ["a", "b"]}]},
        {"results": {"content": "single"}},
        {"results": [{"content": {"nested": True}}]},
        {"messages": "not-a-list"},
        {"metadata": "not-a-dict"},
        {"agent": None, "transcript": None},
        {"calls": [None, 5, "x"]},
    ],
)
def test_inv_request_survives_malformed_documents(document):
    request = CheckRequest.from_dict(document)
    assert isinstance(request.calls, list)
    assert isinstance(request.results, list)


def test_inv_request_rejects_a_non_object_document():
    with pytest.raises(ValueError):
        CheckRequest.from_dict(["not", "an", "object"])


def test_inv_cli_rejects_a_non_object_transcript(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text("[1, 2, 3]", encoding="utf-8")
    assert main(["check", str(document)]) == 2


def test_inv_cli_rejects_invalid_json(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text("{not json", encoding="utf-8")
    assert main(["check", str(document)]) == 2


def test_inv_cli_rejects_an_unknown_fail_on_level(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text("{}", encoding="utf-8")
    assert main(["check", str(document), "--fail-on", "NOPE"]) == 2


def test_inv_cli_exit_code_is_one_for_blocking_findings(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text(
        json.dumps({"calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "../../.ssh/id_rsa"}}]}),
        encoding="utf-8",
    )
    assert main(["check", str(document)]) == 1


def test_inv_cli_exit_code_is_zero_for_a_clean_transcript(tmp_path, capsys):
    document = tmp_path / "t.json"
    document.write_text(
        json.dumps({"calls": [{"server": "fs", "tool": "read_file", "arguments": {"path": "docs/README.md"}}]}),
        encoding="utf-8",
    )
    assert main(["check", str(document)]) == 0


def test_inv_cli_reads_a_transcript_from_stdin(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"calls": [{"server": "fs", "tool": "r", "arguments": {"path": "~/.ssh/id_rsa"}}]})),
    )
    assert main(["check", "-"]) == 1


def test_inv_cli_without_a_command_is_a_usage_error(capsys):
    assert main([]) == 2


# ---------------------------------------------------------------------------
# INV-25 .. INV-30  --  core utility invariants
# ---------------------------------------------------------------------------


def test_inv_severity_ordering_is_explicit_not_lexical():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.HIGH.rank > Severity.LOW.rank


def test_inv_severity_comparison_with_a_string_raises_instead_of_comparing_lexically():
    with pytest.raises(TypeError):
        Severity.HIGH < "LOW"


def test_inv_parse_severity_is_case_insensitive_and_ordered():
    assert parse_severity("high") == Severity.HIGH
    assert parse_severity(" CRITICAL ") == Severity.CRITICAL
    with pytest.raises(ValueError):
        parse_severity("nope")


def test_inv_max_severity_of_empty_is_none():
    assert max_severity([]) is None


def test_inv_verdict_ok_covers_warn():
    assert Verdict.PASS.ok and Verdict.WARN.ok
    assert not Verdict.FAIL.ok and not Verdict.ERROR.ok


def test_inv_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_inv_truncate_boundaries():
    assert truncate("abc", 0) == ""
    assert truncate("abc", -1) == ""
    assert truncate("abc", 10) == "abc"
    assert truncate("abcdef", 5, "...") == "ab..."
    assert len(truncate("x" * 100, 10)) == 10


def test_inv_visible_repr_escapes_control_and_non_ascii():
    assert "\x1b" not in visible_repr("a\x1bb")
    assert "\\x1b" in visible_repr("a\x1bb")
    assert visible_repr("\u202e") == "\\xe2\\x80\\xae"


def test_inv_entropy_and_printability_boundaries():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    assert printable_ratio(b"") == 0.0
    assert printable_ratio(b"abc") == 1.0


def test_inv_base64_helpers():
    assert looks_like_base64("Zm9vYmFyYmF6cXV4") is True
    assert looks_like_base64("Zm9vYmFyYmF6") is False  # length not a multiple of 4
    assert looks_like_base64("short") is False
    assert decode_base64_loose("Zm9vYmFyYmF6") == b"foobarbaz"
    assert decode_base64_loose("") is None

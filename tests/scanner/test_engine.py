"""Tests for the guard engine and the plugin framework."""

from __future__ import annotations

from dataclasses import replace

from mcp_guard.core.engine import GuardEngine
from mcp_guard.core.plugin import GuardPlugin, PluginContext, SelfTestCase
from mcp_guard.core.policy import default_policy, parse_policy
from mcp_guard.core.registry import (
    PLUGIN_CLASSES,
    PLUGIN_ORDER,
    build_plugins,
    known_plugin_names,
    plugin_metadata,
    plugin_rule_catalogue,
)
from mcp_guard.core.request import CheckRequest
from mcp_guard.core.severity import Severity


def _ids(findings):
    return {finding.rule_id for finding in findings}


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------
def test_four_plugins_are_registered():
    assert len(PLUGIN_CLASSES) == 4


def test_plugin_order_is_stable():
    assert PLUGIN_ORDER == ("etdi_pinning", "ansi_sanitize", "path_shape", "canary_exfil")


def test_known_plugin_names_matches_the_order():
    assert known_plugin_names() == PLUGIN_ORDER


def test_every_plugin_declares_a_rule_catalogue():
    catalogue = plugin_rule_catalogue()
    for name in PLUGIN_ORDER:
        assert catalogue[name], name


def test_every_plugin_has_a_version():
    for meta in plugin_metadata():
        assert meta["version"]


def test_build_plugins_returns_all_plugins(policy):
    assert len(build_plugins(policy)) == 4


def test_build_plugins_can_be_restricted(policy):
    assert len(build_plugins(policy, ["path_shape"])) == 1


def test_plugin_settings_are_taken_from_the_policy_block(policy):
    plugins = {plugin.name: plugin for plugin in build_plugins(policy)}
    assert plugins["path_shape"].settings["sensitive_names"]
    assert plugins["canary_exfil"].settings["egress_tools"]


def test_plugin_settings_key_is_resolved(policy):
    assert policy.plugin_settings("path_shape") == policy.plugin_settings("path")


# --------------------------------------------------------------------------
# plugin base class
# --------------------------------------------------------------------------
def test_plugin_resolves_default_severity(policy):
    plugin = build_plugins(policy, ["path_shape"])[0]
    assert plugin.rule("PATH-001").severity is Severity.CRITICAL


def test_plugin_rule_override_changes_severity(make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "PATH-001"
plugin = "path_shape"
severity = "LOW"
"""
    )
    plugin = build_plugins(policy, ["path_shape"])[0]
    assert plugin.rule("PATH-001").severity is Severity.LOW


def test_plugin_rule_override_can_disable(make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "PATH-001"
plugin = "path_shape"
enabled = false
"""
    )
    plugin = build_plugins(policy, ["path_shape"])[0]
    assert plugin.rule("PATH-001").enabled is False


def test_plugin_rule_override_can_change_the_message(make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "PATH-001"
plugin = "path_shape"
message = "custom wording"
"""
    )
    plugin = build_plugins(policy, ["path_shape"])[0]
    assert plugin.rule("PATH-001").message == "custom wording"


def test_disabled_rule_produces_no_finding(make_policy):
    policy = make_policy(
        """
[meta]
name = "unit"
version = "1.0.0"
[[rule]]
id = "PATH-001"
plugin = "path_shape"
enabled = false
"""
    )
    plugin = build_plugins(policy, ["path_shape"])[0]
    assert plugin.finding("PATH-001") is None
    assert plugin.finding("PATH-002") is not None


def test_plugin_context_option_falls_back(policy):
    context = PluginContext(policy=policy, settings={"a": 1})
    assert context.option("a") == 1
    assert context.option("missing", "fallback") == "fallback"


def test_plugin_context_option_of_none_returns_default(policy):
    context = PluginContext(policy=policy, settings={"a": None})
    assert context.option("a", "fallback") == "fallback"


def test_base_plugin_analyze_returns_nothing(policy):
    plugin = GuardPlugin(PluginContext(policy=policy, settings={}))
    assert plugin.analyze(CheckRequest()) == []


def test_base_plugin_self_test_returns_nothing(policy):
    plugin = GuardPlugin(PluginContext(policy=policy, settings={}))
    assert plugin.self_test() == []


def test_self_test_case_to_dict():
    case = SelfTestCase(name="x", passed=True, detail="d")
    assert case.to_dict() == {"name": "x", "passed": True, "detail": "d"}


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------
def test_engine_reports_a_clean_transcript_as_pass(engine, clean_transcript):
    report = engine.check(CheckRequest.from_dict(clean_transcript))
    assert report.verdict.value == "PASS"
    assert report.findings == []


def test_engine_reports_a_dirty_transcript_as_fail(engine, sample_transcript):
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert report.verdict.value == "FAIL"


def test_engine_collects_findings_from_several_plugins(engine, sample_transcript):
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert len(report.count_by_plugin()) >= 2


def test_engine_sorts_findings_by_severity(engine, sample_transcript):
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    ranks = [finding.severity.rank for finding in report.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_engine_records_the_policy(engine):
    report = engine.check(CheckRequest())
    assert report.policy_name == "mcp-guard-default"


def test_engine_records_stats(engine, sample_transcript):
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert report.stats["calls"] == 2
    assert report.stats["results"] == 1


def test_engine_redacts_evidence(policy, sample_transcript):
    engine = GuardEngine(policy=policy)
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert all("ghp_abcdefghijklmnopqrstuvwxyz0123" not in f.evidence for f in report.findings)


def test_engine_can_disable_redaction(policy, sample_transcript):
    engine = GuardEngine(policy=replace(policy, redact_evidence=False))
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert any("ghp_" in f.evidence for f in report.findings)


def test_engine_truncates_long_evidence(policy):
    engine = GuardEngine(policy=replace(policy, max_evidence_chars=32))
    document = {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "x" * 4000}}]}
    report = engine.check(CheckRequest.from_dict(document))
    assert all(len(f.evidence) <= 32 for f in report.findings)


def test_engine_fail_on_override(policy, sample_transcript):
    engine = GuardEngine(policy=replace(policy, fail_on=Severity.CRITICAL))
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert report.verdict.value == "FAIL"


def test_engine_warn_on_creates_a_warning(policy, sample_transcript):
    engine = GuardEngine(policy=replace(policy, fail_on=Severity.CRITICAL, warn_on=Severity.HIGH))
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert report.verdict.value in ("WARN", "FAIL")


def test_engine_survives_a_crashing_plugin(policy):
    class Boom(GuardPlugin):
        name = "boom"

        def analyze(self, request):
            raise RuntimeError("boom")

    engine = GuardEngine(
        policy=policy,
        plugins=[Boom(PluginContext(policy=policy, settings={}))],
    )
    report = engine.check(CheckRequest())
    assert report.findings[0].rule_id == "ENGINE-000"


def test_engine_restricts_plugins(policy, sample_transcript):
    engine = GuardEngine(policy=policy, plugin_names=["path_shape"])
    report = engine.check(CheckRequest.from_dict(sample_transcript))
    assert set(report.count_by_plugin()) == {"path_shape"}


def test_check_dict_is_equivalent_to_check(engine, clean_transcript):
    assert engine.check_dict(clean_transcript).verdict.value == "PASS"


def test_custom_rule_matches_content(policy, clean_transcript):
    custom = parse_policy(
        {
            "meta": {"name": "unit", "version": "1.0.0"},
            "rule": [
                {
                    "id": "X-001",
                    "plugin": "custom",
                    "severity": "HIGH",
                    "regex": "Hello",
                    "message": "greeting detected",
                }
            ],
        }
    )[0]
    engine = GuardEngine(policy=custom)
    report = engine.check(CheckRequest.from_dict(clean_transcript))
    assert "X-001" in _ids(report.findings)


def test_custom_rule_can_target_arguments_only(policy, clean_transcript):
    custom = parse_policy(
        {
            "meta": {"name": "unit", "version": "1.0.0"},
            "rule": [
                {
                    "id": "X-001",
                    "plugin": "custom",
                    "severity": "HIGH",
                    "regex": "Hello",
                    "target": "arguments",
                }
            ],
        }
    )[0]
    engine = GuardEngine(policy=custom)
    report = engine.check(CheckRequest.from_dict(clean_transcript))
    assert report.findings == []


def test_custom_rule_can_be_disabled(policy, clean_transcript):
    custom = parse_policy(
        {
            "meta": {"name": "unit", "version": "1.0.0"},
            "rule": [
                {
                    "id": "X-001",
                    "plugin": "custom",
                    "severity": "HIGH",
                    "regex": "Hello",
                    "enabled": False,
                }
            ],
        }
    )[0]
    engine = GuardEngine(policy=custom)
    report = engine.check(CheckRequest.from_dict(clean_transcript))
    assert report.findings == []


def test_engine_default_policy_is_used_when_none_is_given():
    engine = GuardEngine()
    assert engine.policy.name == default_policy().name

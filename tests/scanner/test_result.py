"""Tests for the finding / verdict / report data model."""

from __future__ import annotations

from mcp_guard.core.result import CheckReport, Finding, Verdict
from mcp_guard.core.severity import Severity


def _finding(rule_id: str, severity: Severity, plugin: str = "test") -> Finding:
    return Finding(
        rule_id=rule_id,
        plugin=plugin,
        severity=severity,
        message=f"{rule_id} happened",
    )


def test_verdict_values():
    assert {verdict.value for verdict in Verdict} == {"PASS", "WARN", "FAIL", "ERROR"}


def test_pass_is_ok():
    assert Verdict.PASS.ok


def test_warn_is_ok():
    assert Verdict.WARN.ok


def test_fail_is_not_ok():
    assert not Verdict.FAIL.ok


def test_error_is_not_ok():
    assert not Verdict.ERROR.ok


def test_finding_to_dict_has_expected_keys():
    payload = _finding("X-001", Severity.HIGH).to_dict()
    assert set(payload) == {
        "rule_id",
        "plugin",
        "severity",
        "message",
        "evidence",
        "location",
        "remediation",
        "metadata",
    }


def test_finding_to_dict_uses_severity_value():
    payload = _finding("X-001", Severity.CRITICAL).to_dict()
    assert payload["severity"] == "CRITICAL"


def test_finding_to_text_includes_severity_and_rule():
    text = _finding("X-001", Severity.HIGH).to_text()
    assert "[HIGH]" in text and "X-001" in text


def test_finding_to_text_includes_location():
    finding = _finding("X-001", Severity.HIGH)
    finding.location = "calls[0]"
    assert "calls[0]" in finding.to_text()


def test_report_max_severity_is_none_when_empty():
    assert CheckReport().max_severity is None


def test_report_max_severity_finds_the_worst():
    report = CheckReport(
        findings=[_finding("A-001", Severity.LOW), _finding("B-001", Severity.CRITICAL)]
    )
    assert report.max_severity is Severity.CRITICAL


def test_report_by_severity_orders_highest_first():
    report = CheckReport(
        findings=[
            _finding("A-001", Severity.LOW),
            _finding("B-001", Severity.CRITICAL),
            _finding("C-001", Severity.MEDIUM),
        ]
    )
    assert list(report.by_severity()) == ["CRITICAL", "MEDIUM", "LOW"]


def test_report_count_by_plugin():
    report = CheckReport(
        findings=[
            _finding("A-001", Severity.LOW, plugin="alpha"),
            _finding("B-001", Severity.HIGH, plugin="alpha"),
            _finding("C-001", Severity.LOW, plugin="beta"),
        ]
    )
    assert report.count_by_plugin() == {"alpha": 2, "beta": 1}


def test_report_to_dict_contains_summary():
    report = CheckReport(findings=[_finding("A-001", Severity.HIGH)])
    payload = report.to_dict()
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["max_severity"] == "HIGH"
    assert payload["verdict"] == "PASS"


def test_report_ok_follows_verdict():
    assert CheckReport(verdict=Verdict.PASS).ok
    assert not CheckReport(verdict=Verdict.FAIL).ok

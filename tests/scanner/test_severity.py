"""Tests for the severity model."""

from __future__ import annotations

import pytest

from mcp_guard.core.severity import (
    SEVERITY_ORDER,
    Severity,
    max_severity,
    parse_severity,
    severity_rank,
)


def test_severity_levels_are_ordered():
    assert SEVERITY_ORDER == ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_critical_is_greater_than_high():
    assert Severity.CRITICAL > Severity.HIGH


def test_high_is_greater_than_medium():
    assert Severity.HIGH > Severity.MEDIUM


def test_medium_is_greater_than_low():
    assert Severity.MEDIUM > Severity.LOW


def test_low_is_greater_than_info():
    assert Severity.LOW > Severity.INFO


def test_equal_severities_are_not_greater():
    assert not (Severity.HIGH > Severity.HIGH)
    assert Severity.HIGH >= Severity.HIGH


def test_rank_matches_order():
    assert Severity.INFO.rank == 0
    assert Severity.CRITICAL.rank == len(SEVERITY_ORDER) - 1


def test_parse_severity_accepts_lowercase():
    assert parse_severity("high") is Severity.HIGH


def test_parse_severity_strips_whitespace():
    assert parse_severity("  critical  ") is Severity.CRITICAL


def test_parse_severity_passes_through_enum():
    assert parse_severity(Severity.LOW) is Severity.LOW


def test_parse_severity_rejects_unknown():
    with pytest.raises(ValueError):
        parse_severity("SEVERE")


def test_parse_severity_uses_default():
    assert parse_severity("nope", Severity.LOW) is Severity.LOW


def test_parse_severity_none_without_default_raises():
    with pytest.raises(ValueError):
        parse_severity(None)


def test_severity_rank_helper():
    assert severity_rank("MEDIUM") == 2


def test_max_severity_picks_the_highest():
    assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_max_severity_of_empty_is_none():
    assert max_severity([]) is None


def test_severity_value_is_the_plain_string():
    assert Severity.HIGH.value == "HIGH"


def test_severity_format_uses_the_value():
    assert f"{Severity.HIGH}" == "HIGH"


def test_severity_comparison_with_other_types_is_not_implemented():
    with pytest.raises(TypeError):
        Severity.HIGH < "LOW"

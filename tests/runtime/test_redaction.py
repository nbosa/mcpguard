"""Tests for the redaction of sensitive values."""

from __future__ import annotations

import pytest

from mcp_guard.redact import (
    REDACTED,
    SENSITIVE_KEY_PATTERN,
    is_sensitive_key,
    redact_arguments,
    redact_value,
)


@pytest.mark.parametrize(
    "key",
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
    ],
)
def test_sensitive_keys_are_redacted(key: str) -> None:
    assert is_sensitive_key(key)
    redacted = redact_arguments({key: "super-secret-value"})
    assert redacted[key] == REDACTED
    assert "super-secret-value" not in str(redacted)


@pytest.mark.parametrize("key", ["path", "command", "body", "to", "count", "filename"])
def test_harmless_keys_are_kept(key: str) -> None:
    assert not is_sensitive_key(key)
    assert redact_arguments({key: "value"})[key] == "value"


def test_the_matching_is_case_insensitive() -> None:
    redacted = redact_arguments({"AuThOrIzAtIoN": "Bearer abc"})
    assert redacted["AuThOrIzAtIoN"] == REDACTED


def test_the_whole_value_is_replaced() -> None:
    redacted = redact_arguments({"token": "prefix-secret-suffix"})
    assert redacted["token"] == REDACTED
    assert "prefix" not in redacted["token"]
    assert "suffix" not in redacted["token"]


def test_nested_objects_are_redacted() -> None:
    redacted = redact_arguments(
        {"outer": {"password": "hunter2", "safe": "value"}, "token": "abc"}
    )
    assert redacted["outer"]["password"] == REDACTED
    assert redacted["outer"]["safe"] == "value"
    assert redacted["token"] == REDACTED


def test_values_inside_lists_are_redacted() -> None:
    redacted = redact_arguments({"items": [{"secret": "x"}, {"safe": "y"}]})
    assert redacted["items"][0]["secret"] == REDACTED
    assert redacted["items"][1]["safe"] == "y"


def test_a_list_of_secrets_is_redacted() -> None:
    redacted = redact_value(["a", "b"])
    assert redacted == ["a", "b"]


def test_scalars_pass_through() -> None:
    assert redact_value(42) == 42
    assert redact_value(None) is None
    assert redact_value("plain") == "plain"


def test_the_original_arguments_are_not_modified() -> None:
    arguments = {"token": "hunter2", "path": "a.txt"}
    redact_arguments(arguments)
    assert arguments["token"] == "hunter2"


@pytest.mark.parametrize(
    "innocent_key",
    ["monkey", "donkey", "turkey", "keyboard", "hotkey_config", "keynote"],
)
def test_innocent_subword_keys_are_not_redacted(innocent_key: str) -> None:
    """OPUS-01: Innocent fields containing 'key' as sub-word must not be redacted."""
    assert not is_sensitive_key(innocent_key)
    result = redact_arguments({innocent_key: "banana"})
    assert result[innocent_key] == "banana"


def test_the_pattern_is_the_documented_one() -> None:
    assert SENSITIVE_KEY_PATTERN.pattern == (
        r"(?:^|[_\-])(?i:token|secret|password|key|authorization|api[_\-]key)(?:$|[_\-])|"
        r"(?<=[A-Za-z0-9])(?:Token|Secret|Password|Key|Authorization|ApiKey)(?:$|[_\-]|(?=[A-Z]))"
    )

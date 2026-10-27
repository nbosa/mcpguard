"""Tests for evidence redaction."""

from __future__ import annotations

import re

from mcp_guard.core.redact import REDACTION_PATTERNS, mask_value, redact


def test_redact_masks_aws_access_key():
    out = redact("key AKIA" "IOSFODNN7EXAMPLE here")
    assert "AKIA" "IOSFODNN7EXAMPLE" not in out
    assert "<redacted:aws_access_key>" in out


def test_redact_masks_github_token():
    out = redact("token ghp_abcdefghijklmnopqrstuvwxyz0123")
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123" not in out


def test_redact_masks_private_key_block():
    payload = "-----BEGIN " "RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    out = redact(payload)
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_redact_masks_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    out = redact(jwt)
    assert jwt not in out


def test_redact_masks_assigned_secret_but_keeps_the_key():
    out = redact("pass" "word = supersecretvalue")
    assert "supersecretvalue" not in out
    assert "password" in out


def test_redact_masks_url_credentials():
    out = redact("https://user:hunter2@example.invalid/path")
    assert "hunter2" not in out


def test_redact_masks_slack_token():
    out = redact("xoxb-" "123456789012-abcdefghijkl")
    assert "xoxb-" not in out


def test_redact_masks_anthropic_key():
    out = redact("sk-ant-abcdefghijklmnopqrstuvwxyz012345")
    assert "sk-ant-" not in out


def test_redact_leaves_clean_text_untouched():
    assert redact("just a normal sentence") == "just a normal sentence"


def test_redact_handles_empty_string():
    assert redact("") == ""


def test_redact_applies_extra_patterns():
    out = redact("value-1234", extra_patterns=(("custom", re.compile(r"value-\d+")),))
    assert "value-1234" not in out
    assert "<redacted:custom>" in out


def test_mask_value_keeps_two_characters():
    assert mask_value("abcdefgh") == "ab****gh"


def test_mask_value_of_short_value_is_all_stars():
    assert mask_value("ab") == "**"


def test_mask_value_of_empty_string():
    assert mask_value("") == ""


def test_redaction_patterns_are_unique():
    kinds = [kind for kind, _ in REDACTION_PATTERNS]
    assert len(kinds) == len(set(kinds))

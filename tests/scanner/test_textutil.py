"""Tests for the shared text utilities."""

from __future__ import annotations

import math

from mcp_guard.core.textutil import (
    canonical_json,
    collapse_whitespace,
    decode_base64_loose,
    looks_like_base64,
    printable_ratio,
    sha256_bytes,
    sha256_hex,
    shannon_entropy,
    truncate,
    visible_repr,
)


def test_canonical_json_sorts_keys():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_is_stable():
    assert canonical_json({"a": [1, {"z": 1, "y": 2}]}) == canonical_json(
        {"a": [1, {"y": 2, "z": 1}]}
    )


def test_canonical_json_keeps_unicode():
    assert canonical_json({"k": "值"}) == '{"k":"值"}'


def test_sha256_hex_matches_hashlib_vector():
    assert sha256_hex("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_hex_is_deterministic():
    assert sha256_hex("mcp-guard") == sha256_hex("mcp-guard")


def test_sha256_bytes_matches_sha256_hex():
    assert sha256_bytes(b"mcp-guard") == sha256_hex("mcp-guard")


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_uniform_string_is_zero():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_of_binary_string_is_one():
    assert math.isclose(shannon_entropy("ab"), 1.0, rel_tol=1e-9)


def test_entropy_of_base64_blob_is_high():
    blob = "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FybGFnaW5xdWlvcHFycw=="
    assert shannon_entropy(blob) > 4.0


def test_looks_like_base64_accepts_valid_blob():
    assert looks_like_base64("Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2Fy")


def test_looks_like_base64_rejects_short_text():
    assert not looks_like_base64("short")


def test_looks_like_base64_rejects_bad_length():
    assert not looks_like_base64("Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FyYQ")


def test_looks_like_base64_rejects_underscores():
    assert not looks_like_base64("Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2F_")


def test_decode_base64_loose_decodes():
    assert decode_base64_loose("aGVsbG8=") == b"hello"


def test_decode_base64_loose_pads_input():
    assert decode_base64_loose("aGVsbG8") == b"hello"


def test_decode_base64_loose_returns_none_for_garbage():
    assert decode_base64_loose("!!!!") is None


def test_printable_ratio_of_text_is_one():
    assert printable_ratio(b"hello") == 1.0


def test_printable_ratio_of_binary_is_low():
    assert printable_ratio(bytes([0, 1, 2, 3])) < 0.2


def test_collapse_whitespace():
    assert collapse_whitespace("a   b\n\nc") == "a b c"


def test_truncate_leaves_short_text_untouched():
    assert truncate("abc", 10) == "abc"


def test_truncate_cuts_long_text():
    assert truncate("abcdefghij", 5) == "ab..."


def test_truncate_with_zero_limit_returns_empty():
    assert truncate("abc", 0) == ""


def test_visible_repr_escapes_control_characters():
    assert "\\x1b" in visible_repr("\x1b[31m")


def test_visible_repr_keeps_printable_text():
    assert visible_repr("hello") == "hello"

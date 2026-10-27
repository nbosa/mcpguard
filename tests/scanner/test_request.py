"""Tests for the normalised check-request model."""

from __future__ import annotations

from mcp_guard.core.request import CheckRequest, ToolCall, ToolResult


def test_from_dict_reads_calls():
    request = CheckRequest.from_dict(
        {"calls": [{"server": "fs", "tool": "read", "arguments": {"path": "a.txt"}}]}
    )
    assert len(request.calls) == 1
    assert request.calls[0].qualified == "fs.read"


def test_from_dict_reads_results():
    request = CheckRequest.from_dict(
        {"results": [{"server": "fs", "tool": "read", "content": "hello"}]}
    )
    assert request.results[0].content == "hello"


def test_from_dict_accepts_tool_calls_alias():
    request = CheckRequest.from_dict({"tool_calls": [{"tool": "x", "input": {"a": 1}}]})
    assert request.calls[0].arguments == {"a": 1}


def test_from_dict_accepts_tool_results_alias():
    request = CheckRequest.from_dict({"tool_results": [{"tool": "x", "text": "hi"}]})
    assert request.results[0].content == "hi"


def test_from_dict_builds_transcript_from_messages():
    request = CheckRequest.from_dict(
        {"messages": [{"role": "user", "content": "hi"}, {"role": "bot", "content": "yo"}]}
    )
    assert "hi" in request.transcript and "yo" in request.transcript


def test_from_dict_reads_agent():
    request = CheckRequest.from_dict({"agent": "runner"})
    assert request.agent == "runner"


def test_from_dict_rejects_non_mapping():
    try:
        CheckRequest.from_dict([1, 2, 3])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_from_dict_ignores_non_dict_call_entries():
    request = CheckRequest.from_dict({"calls": ["nope", {"tool": "x"}]})
    assert len(request.calls) == 1


def test_from_dict_copies_etdi_metadata():
    request = CheckRequest.from_dict({"etdi": {"etdi": "1.0"}})
    assert request.metadata["etdi"] == {"etdi": "1.0"}


def test_from_dict_copies_metadata_block():
    request = CheckRequest.from_dict({"metadata": {"custom": 1}})
    assert request.metadata["custom"] == 1


def test_qualified_name_without_server():
    call = ToolCall(tool="read")
    assert call.qualified == "read"


def test_qualified_name_without_tool():
    call = ToolCall(server="fs")
    assert call.qualified == "fs"


def test_arguments_text_is_json():
    call = ToolCall(arguments={"b": 1, "a": 2})
    assert call.arguments_text() == '{"a": 2, "b": 1}'


def test_arguments_text_uses_raw_when_present():
    call = ToolCall(arguments={"a": 1}, raw_arguments="raw")
    assert call.arguments_text() == "raw"


def test_argument_strings_flattens_nested_values():
    call = ToolCall(arguments={"path": "a", "opts": {"deep": ["b", 3]}})
    values = call.argument_strings()
    assert "a" in values and "b" in values


def test_result_qualified_name():
    assert ToolResult(server="fs", tool="read").qualified == "fs.read"


def test_to_dict_round_trips_calls():
    request = CheckRequest.from_dict({"calls": [{"server": "fs", "tool": "read"}]})
    payload = request.to_dict()
    assert payload["calls"][0]["tool"] == "read"


def test_empty_document_yields_empty_request():
    request = CheckRequest.from_dict({})
    assert request.calls == [] and request.results == [] and request.transcript == ""

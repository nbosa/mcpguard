"""Tests for the rate limits and for the lifetime of the session token."""

from __future__ import annotations

import pytest

from mcp_guard.policy import (
    ALLOW,
    APPROVAL_REQUIRED,
    DENY,
    RATE_LIMITED,
    TTL_EXPIRED,
    Policy,
    PolicyEngine,
)


class FakeClock:
    """A monotonic clock that only moves when the test tells it to."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def engine_for(policy: Policy, clock: FakeClock | None = None, ttl: int | None = None) -> PolicyEngine:
    return PolicyEngine(policy, session_id="session", clock=clock or FakeClock(), ttl_seconds=ttl)


def test_the_n_plus_first_call_in_the_window_is_rate_limited() -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "rate_limit_per_minute": 2}}}
    )
    engine = engine_for(policy)

    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == ALLOW

    decision = engine.evaluate("read_file")
    assert decision.decision == RATE_LIMITED
    assert decision.code == RATE_LIMITED
    assert "rate limit exceeded" in decision.reason


def test_the_window_slides() -> None:
    clock = FakeClock()
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "rate_limit_per_minute": 2}}}
    )
    engine = engine_for(policy, clock)

    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == RATE_LIMITED

    clock.advance(61.0)
    assert engine.evaluate("read_file").decision == ALLOW


def test_a_call_inside_the_window_keeps_the_budget_full() -> None:
    clock = FakeClock()
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "rate_limit_per_minute": 2}}}
    )
    engine = engine_for(policy, clock)

    engine.evaluate("read_file")
    clock.advance(30.0)
    engine.evaluate("read_file")
    assert engine.evaluate("read_file").decision == RATE_LIMITED


def test_the_rate_limit_is_per_tool() -> None:
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {"action": "allow", "rate_limit_per_minute": 1},
                "write_file": {"action": "allow"},
            }
        }
    )
    engine = engine_for(policy)
    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == RATE_LIMITED
    assert engine.evaluate("write_file").decision == ALLOW


def test_max_calls_caps_the_whole_session() -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "max_calls": 3}}}
    )
    engine = engine_for(policy)
    for _ in range(3):
        assert engine.evaluate("read_file").decision == ALLOW
    decision = engine.evaluate("read_file")
    assert decision.decision == RATE_LIMITED
    assert "session call cap" in decision.reason


def test_the_session_wide_cap_counts_every_tool() -> None:
    policy = Policy.model_validate(
        {
            "session": {"max_calls": 2},
            "tools": {"read_file": {"action": "allow"}, "write_file": {"action": "allow"}},
        }
    )
    engine = engine_for(policy)
    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("write_file").decision == ALLOW
    decision = engine.evaluate("read_file")
    assert decision.decision == RATE_LIMITED
    assert "in total" in decision.reason


def test_only_forwarded_calls_consume_the_budget() -> None:
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {"action": "allow", "rate_limit_per_minute": 1},
                "run_shell": {"action": "deny"},
            }
        }
    )
    engine = engine_for(policy)

    # A denied tool is never forwarded, so it does not use the budget of another tool.
    assert engine.evaluate("run_shell").decision == DENY
    assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == RATE_LIMITED


def test_a_refused_call_consumes_the_budget() -> None:
    """A refused call costs budget: an attempt is an attempt.

    Since 0.4.1 a call that reaches the argument check consumes the budget of
    its tool even when the arguments are refused, so a client cannot probe the
    argument constraints for free.  The calls refused *before* that check (an
    expired token, an unlisted or denied tool, a tool that needs an approval, or
    the rate limit itself) still cost nothing.
    """
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {
                    "action": "allow",
                    "rate_limit_per_minute": 1,
                    "arguments": {"path": {"max_length": 3}},
                }
            }
        }
    )
    engine = engine_for(policy)
    assert engine.evaluate("read_file", {"path": "far too long"}).decision == DENY
    assert engine.guard.calls_for("read_file") == 1
    assert engine.evaluate("read_file", {"path": "ok"}).decision == RATE_LIMITED


def test_a_call_refused_by_the_rate_limit_costs_nothing() -> None:
    """The limit is checked before the budget is spent, so a client that keeps
    hammering a limited tool does not keep its own window full."""
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "rate_limit_per_minute": 1}}}
    )
    engine = engine_for(policy)
    assert engine.evaluate("read_file").decision == ALLOW
    for _ in range(5):
        assert engine.evaluate("read_file").decision == RATE_LIMITED
    assert engine.guard.calls_for("read_file") == 1


def test_a_tool_refused_by_the_policy_costs_nothing() -> None:
    """A tool that is denied or needs an approval never reaches the argument
    check, so it costs no budget."""
    policy = Policy.model_validate(
        {
            "tools": {
                "read_file": {"action": "allow", "rate_limit_per_minute": 1},
                "run_shell": {"action": "deny"},
                "write_file": {"action": "allow", "require_approval": True},
            }
        }
    )
    engine = engine_for(policy)
    assert engine.evaluate("run_shell").decision == DENY
    assert engine.evaluate("write_file").decision == APPROVAL_REQUIRED
    assert engine.guard.total_calls == 0


def test_the_session_token_expires() -> None:
    clock = FakeClock()
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = engine_for(policy, clock, ttl=60)

    assert engine.evaluate("read_file").decision == ALLOW

    clock.advance(59.0)
    assert engine.evaluate("read_file").decision == ALLOW

    clock.advance(2.0)
    decision = engine.evaluate("read_file")
    assert decision.decision == TTL_EXPIRED
    assert decision.code == TTL_EXPIRED
    assert "expired" in decision.reason


def test_the_ttl_can_come_from_the_policy() -> None:
    clock = FakeClock()
    policy = Policy.model_validate(
        {"session": {"ttl_seconds": 30}, "tools": {"read_file": {"action": "allow"}}}
    )
    engine = engine_for(policy, clock)
    clock.advance(31.0)
    assert engine.evaluate("read_file").decision == TTL_EXPIRED


def test_without_a_ttl_the_session_never_expires() -> None:
    clock = FakeClock()
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = engine_for(policy, clock)
    clock.advance(10_000.0)
    assert engine.evaluate("read_file").decision == ALLOW


def test_the_expiry_is_checked_before_everything_else() -> None:
    clock = FakeClock()
    policy = Policy.model_validate({"tools": {"read_file": {"action": "allow"}}})
    engine = engine_for(policy, clock, ttl=1)
    clock.advance(5.0)
    decision = engine.evaluate("read_file")
    assert decision.decision == TTL_EXPIRED


def test_the_session_guard_counts_the_calls_it_recorded() -> None:
    from mcp_guard.state import SessionGuard

    guard = SessionGuard("s")
    guard.record_call("read_file")
    guard.record_call("read_file")
    assert guard.calls_for("read_file") == 2
    assert guard.total_calls == 2


@pytest.mark.parametrize("limit", [1, 2, 5])
def test_the_limit_is_honoured_for_every_limit(limit: int) -> None:
    policy = Policy.model_validate(
        {"tools": {"read_file": {"action": "allow", "rate_limit_per_minute": limit}}}
    )
    engine = engine_for(policy)
    for _ in range(limit):
        assert engine.evaluate("read_file").decision == ALLOW
    assert engine.evaluate("read_file").decision == RATE_LIMITED

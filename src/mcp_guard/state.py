"""Per-session state: the token lifetime and the call budgets.

One session id per proxy run, two independent budgets per tool:
``rate_limit_per_minute`` (a sliding 60 second window, the N-th call inside it
allowed and the N+1-th refused) and ``max_calls`` (a hard cap for the session).
Both count *attempts*: a call that reaches the argument check consumes budget
even when it is refused for a bad argument, because the client spent the
attempt.  A call refused before that -- an expired token, an unlisted or denied
tool, a tool that needs an approval, or a call the rate limit itself refused --
costs nothing, so a client can never lock itself out by retrying.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Callable

#: Length of the sliding window used by ``rate_limit_per_minute``.
RATE_LIMIT_WINDOW_SECONDS = 60.0

class SessionGuard:
    """Tracks the lifetime and the call budgets of one proxy session."""

    def __init__(
        self,
        session_id: str,
        ttl_seconds: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        session_max_calls: int | None = None,
    ) -> None:
        self.session_id = session_id
        self.ttl_seconds = ttl_seconds
        self.session_max_calls = session_max_calls
        self._clock = clock
        self.started_at = clock()
        self._windows: dict[str, deque[float]] = {}
        self._counts: dict[str, int] = {}
        self._total_calls = 0

    def start(self) -> None:
        """(Re)start the lifetime: the TTL runs while the client holds the token."""
        self.started_at = self._clock()

    @property
    def expires_at(self) -> float | None:
        """Monotonic timestamp at which the session expires, if a TTL is set."""
        if self.ttl_seconds is None:
            return None
        return self.started_at + self.ttl_seconds

    def elapsed(self) -> float:
        """Seconds since the session was created."""
        return self._clock() - self.started_at

    def expired(self) -> bool:
        """``True`` once the TTL has elapsed."""
        if self.ttl_seconds is None:
            return False
        return self.elapsed() >= self.ttl_seconds

    def expiry_reason(self) -> str | None:
        """Human readable reason when the session expired, else ``None``."""
        if not self.expired():
            return None
        return ( f"session token expired after {self.ttl_seconds}s "
                         f"(elapsed {self.elapsed():.1f}s, session {self.session_id})"
        )

    # -- budgets ----------------------------------------------------------
    def check_rate_limit(self, tool: str, per_minute: int | None, max_calls: int | None) -> str | None:
        """Return a refusal reason when a budget is exhausted, else ``None``."""
        if per_minute is not None:
            window = self._windows.setdefault(tool, deque())
            now = self._clock()
            while window and now - window[0] >= RATE_LIMIT_WINDOW_SECONDS:
                window.popleft()
            if len(window) >= per_minute:
                return ( f"rate limit exceeded: tool {tool!r} allows {per_minute} call(s) per minute, "
                                         f"{len(window)} already used in the last 60s"
                )
        if max_calls is not None:
            used = self._counts.get(tool, 0)
            if used >= max_calls:
                return ( f"session call cap exceeded: tool {tool!r} allows {max_calls} call(s) "
                                         f"per session, {used} already used"
                )
        if self.session_max_calls is not None and self._total_calls >= self.session_max_calls:
            return ( f"session call cap exceeded: the session allows {self.session_max_calls} call(s) "
                                 f"in total, {self._total_calls} already used"
            )
        return None

    def record_call(self, tool: str) -> None:
        """Record an attempt at calling ``tool``."""
        self._windows.setdefault(tool, deque()).append(self._clock())
        self._counts[tool] = self._counts.get(tool, 0) + 1
        self._total_calls += 1

    def calls_for(self, tool: str) -> int:
        """Number of recorded attempts for ``tool`` in this session."""
        return self._counts.get(tool, 0)

    @property
    def total_calls(self) -> int:
        """Number of recorded attempts in this session, across all tools."""
        return self._total_calls
